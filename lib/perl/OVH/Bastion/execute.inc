# vim: set filetype=perl ts=4 sw=4 sts=4 et:
package OVH::Bastion;

use common::sense;

use Config;
use Fcntl qw{ :DEFAULT :seek };
use IO::Handle;
use IO::Select;
use IPC::Open3;
use JSON;
use POSIX ":sys_wait_h";
use Symbol 'gensym';

# Get signal names, i.e. signal 9 is SIGKILL, etc.
my %signum2string;
@signum2string{split ' ', $Config{sig_num}} = map { "SIG$_" } split ' ', $Config{sig_name};

sub sysret2human {
    my $sysret = shift;
    if ($sysret == -1) {
        return R('OK', msg => "error: failed to execute ($!)");
    }
    elsif ($sysret & 127) {
        my $signal   = $sysret & 127;
        my $coredump = $sysret & 128;
        return R(
            'OK',
            value => {
                coredump => $coredump ? \1 : \0,
                signal   => $signum2string{$signal} || $signal,
                status   => undef,
            },
            msg => sprintf("signal %d (%s)%s", $signal, $signum2string{$signal}, $coredump ? ' and coredump' : '')
        );
    }
    else {
        return R(
            'OK',
            value => {coredump => \0, signal => undef, status => $sysret >> 8},
            msg   => sprintf("status %d", $sysret >> 8)
        );
    }
}

# utility function to set a filehandle to non-blocking
sub _set_non_blocking {
    my $handle = shift;

    my $flags = fcntl($handle, F_GETFL, 0);
    if (!$flags) {
        return R('ERR_SYSCALL_FAILED', msg => "Couldn't set filehandle to non-blocking (F_GETFL failed)");
    }

    $flags |= O_NONBLOCK;
    if (!fcntl($handle, F_SETFL, $flags)) {
        return R('ERR_SYSCALL_FAILED', msg => "Couldn't set filehandle to non-blocking (F_SETFL failed)");
    }
    return R('OK');
}

## no critic(ControlStructures::ProhibitDeepNests)
sub execute {
    my %params           = @_;
    my $cmd              = $params{'cmd'};                 # command to execute, must be an array ref (with possible parameters)
    my $expects_stdin    = $params{'expects_stdin'};       # the command called expects stdin, pipe caller stdin to it
    my $noisy_stdout     = $params{'noisy_stdout'};        # capture stdout but print it too
    my $noisy_stderr     = $params{'noisy_stderr'};        # capture stderr but print it too
    my $is_helper        = $params{'is_helper'};           # hide JSON returns from stdout even if noisy_stdout
    my $is_binary        = $params{'is_binary'};           # used for e.g. scp, don't bother mimicking readline(), we lose debug and stdout/stderr are NOT returned to caller
    my $stdin_str        = $params{'stdin_str'};           # string to push to the STDIN of the command
    my $must_succeed     = $params{'must_succeed'};        # if the executed command returns a non-zero exit value, turn OK_NON_ZERO_EXIT to ERR_NON_ZERO_EXIT
    my $max_stdout_bytes = $params{'max_stdout_bytes'};    # if the amount of stored stdout bytes exceeds this, halt the command and return to caller
    my $system           = $params{'system'};              # if set to 1, will use system() instead of open3(), needed for some plugins

    $noisy_stderr = $noisy_stdout = 1 if ($ENV{'PLUGIN_DEBUG'} or $is_binary);
    my $fnret;

    # taint check
    require Scalar::Util;
    foreach (@$cmd) {
        if (Scalar::Util::tainted($_) && /(.+)/) {
            # to be able to warn under -T; untaint it. we're going to crash right after anyway.
            require Carp;
            warn(Carp::longmess("would exec <" . join('^', @$cmd) . "> but param '$1' is tainted!"));
        }
    }

    # if caller want us to use system(), just do it here and call it a day
    if ($system) {
        my $child_exit_status = system(@$cmd);
        $fnret = sysret2human($child_exit_status);
        return R(
            $child_exit_status == 0 ? 'OK' : ($must_succeed ? 'ERR_NON_ZERO_EXIT' : 'OK_NON_ZERO_EXIT'),
            value => {
                sysret   => $child_exit_status + 0,
                status   => $fnret->value->{'status'},
                coredump => $fnret->value->{'coredump'},
                signal   => $fnret->value->{'signal'},
            },
            msg => "Command exited with " . sysret2human($child_exit_status)->msg,
        );
    }

    # otherwise, launch the command under open3()
    my ($child_stdin, $child_stdout, $child_stderr);
    $child_stderr = gensym;
    osh_debug("about to run_cmd ['" . join("','", @$cmd) . "']");
    my $pid;
    eval { $pid = open3($child_stdin, $child_stdout, $child_stderr, @$cmd); };
    if ($@) {
        chomp $@;
        return R('ERR_EXEC_FAILED', msg => "Couldn't exec requested command ($@)");
    }

    # if some filehandles are already closed, binmode may fail, which is why we use eval{} here
    eval { binmode $child_stdin; };
    eval { binmode $child_stdout; };
    eval { binmode $child_stderr; };
    eval { binmode STDIN; };
    eval { binmode STDOUT; };
    eval { binmode STDERR; };

    # set our child's stdin to non-blocking, so that a syswrite to it is guaranteed to never block,
    # otherwise we could get in an deadlock, where our child can't accept more data on its stdin
    # before we read pending data from its stdout/stderr, which we will never do because we're busy
    # waiting for the syswrite to its stdin to complete.
    $fnret = _set_non_blocking($child_stdin);
    $fnret or return $fnret;

    osh_debug("waiting for child PID $pid to complete...");

    # declare vars we'll use below
    my %output = ();
    my $stderr_output;
    my $stdout_output;
    my $stdout_buffer;
    my $child_stdin_to_write;
    my $child_stdin_closing;
    my $current_fh;
    my $currently_in_json_block;
    my %bytesnb;

    # maximum number of code_info() to call, to avoid flooding the logs
    my $info_limit = 5;

    # maximum intermediate buffer size we want in $child_stdin_to_write, before we stop
    # reading data from our own STDIN and wait our child to digest the data we send it,
    # otherwise if we get a possibly infinite amount of data from our STDIN without ever
    # being able to write it to our child, we'll end up in OOM
    my $max_stdin_buf_size = 8 * 1024 * 1024;

    # define our own version of syswrite to handle auto-retry if interrupted by a signal,
    # return the number of bytes actually written
    my $syswrite_ensure = sub {
        my ($_bufsiz, $_FH, $_name, $_noisy_ref, $_buffer) = @_;
        return 0 if (!$_bufsiz || !$_buffer);

        my $offset       = 0;
        my $totalwritten = 0;
        while ($offset < $_bufsiz) {
            my $written = eval { syswrite $_FH, $_buffer, 65535, $offset; };
            if ($@) {
                if ($@ =~ m{on closed filehandle}) {
                    $child_stdin_to_write = '';
                    return $totalwritten;
                }
                # don't ignore other errors
                die($@);
            }

            if (not defined $written) {
                if ($!{'EAGAIN'} && $_name eq 'child_stdin') {
                    osh_debug("in syswrite_ensure, got EAGAIN on our child stdin, our caller will retry on next loop");
                    return $totalwritten;
                }
                else {
                    # is the fd still open? (maybe we got a SIGPIPE or a SIGHUP)
                    # don't use tell() here, we use syseek() for unbuffered i/o,
                    # note that if we're at the position "0", it's still true (see doc).
                    my $previousError = $!;
                    if (!sysseek($_FH, 0, SEEK_CUR)) {
                        osh_debug("in syswrite_ensure, sysseek failed");
                        info_syslog("execute(): error while syswriting($previousError/$!) on $_name, "
                              . "the filehandle is closed, will no longer attempt to write to it")
                          if $info_limit-- > 0;
                        $$_noisy_ref = 0 if $_noisy_ref;
                    }
                    else {
                        # oww, abort writing for this cycle. as this might be user-induced, use info instead of warn
                        info_syslog(
                            "execute(): error while syswriting($previousError) on $_name, " . "aborting this cycle")
                          if $info_limit-- > 0;
                    }
                }
                last;
            }
            $offset       += $written;
            $totalwritten += $written;
        }
        return $totalwritten;
    };

    # as we'll always monitor our child stdout and stderr, add those to our IO::Select
    my $select = IO::Select->new($child_stdout, $child_stderr);

    if (length($stdin_str) > 0) {
        # we have some stdin data to push to our child, so preinit our intermediate buffer with that data
        $child_stdin_to_write = $stdin_str;
    }
    elsif ($expects_stdin) {
        # monitor our own stdin only if we expect it (we'll pipe it to our child's stdin)
        $select->add(\*STDIN);
    }

    # then, while we still have at least two filehandles to monitor OR we have only one which is not our own STDIN:
    while ($select->count() > 1 || ($select->count() == 1 && !$select->exists(\*STDIN))) {

        # first, if we have data to push to our child's stdin that comes from our own stdin,
        # try to do that before checking if we have pending data to read, as to ensure we don't get deadlocked
        if (length($child_stdin_to_write) > 0) {
            my $written2child = $syswrite_ensure->(
                length($child_stdin_to_write),
                $child_stdin, 'child_stdin', undef, $child_stdin_to_write
            );

            if ($written2child) {
                # remove the data we've written from the intermediate buffer
                $child_stdin_to_write = substr($child_stdin_to_write, $written2child);

                if (length($child_stdin_to_write) == 0) {
                    if (length($stdin_str) > 0) {
                        # we pushed all the data we wanted to push to our child stdin, we can close it now:
                        osh_debug("execute: closing child stdin as we wrote everything we wanted to it (stdin_str)");
                        close($child_stdin);
                    }
                    elsif ($child_stdin_closing) {
                        # our own STDIN was already closed, and we just finished flushing the data to our child,
                        # so we can close it as well
                        osh_debug("execute: closing child stdin as we wrote everything we wanted to it");
                        close($child_stdin);
                    }
                }
            }
        }

        # then, wait until we have something to read.
        # block only for 10ms, if there's nothing to read anywhere for this amount of time,
        # it'll be when we want to check if our child is dead
        my @ready = $select->can_read(0.01);

        # yep, we have something to read on at least one fh
        if (@ready) {

            # guarantee we're still reading this fh while it has something to say, this helps avoiding
            # mangling stdout/stderr on the console when noisy_* vars are set
            $current_fh = $ready[0];

            # ...unless we have piled up a big buffer from our stdin, and child is still blocking on its own stdin,
            # in which case we'll stop reading from our stdin and prioritize other filehandles
            # in an attempt to unblock our child
            if ($current_fh->fileno == STDIN->fileno && length($child_stdin_to_write) > $max_stdin_buf_size) {
                osh_debug("main loop, changing current fh to avoid deadlocking");
                if (@ready > 1) {
                    $current_fh = $ready[1];
                }
                else {
                    warn_syslog("possible deadlock while running ['" . join("','", @$cmd) . "']") if $info_limit-- > 0;
                    osh_debug("main loop, can't change current fh to avoid deadlock, refusing to read from it");
                    # we have nothing to read/write from/to, except from our own STDIN but our buffer is already full,
                    # so let's sleep for a tiny bit to help ensuring our child is not CPU-starved which could make
                    # it incapable of accepting new data to its STDIN, hence deadlocking us in return
                    require Time::HiRes;
                    Time::HiRes::usleep(1000 * 15);
                    next;
                }
            }

            my $sub_select = IO::Select->new($current_fh);

            # can_read(0) because we don't need a timeout: we KNOW there's something to read on this fh,
            # otherwise we wouldn't be here
            while ($sub_select->can_read(0)) {
                my $buffer;
                my $nbread = sysread $current_fh, $buffer, 65535;

                # undef==error, we log to syslog and close. as this might be user-induced, use info instead of warn
                if (not defined $nbread) {
                    info_syslog("execute(): error while sysreading($!), closing fh!");
                }

                # if size 0, it means it's an EOF
                elsif ($nbread == 0) {
                    # we got an EOF on this fh, remove it from the monitor list
                    osh_debug("main loop: removing current fh from select list");
                    $select->remove($current_fh);

                    # if this is an EOF on our own STDIN, we need to close our child's STDIN,
                    # but do this only if our intermediate buffer is empty, otherwise just mark it
                    # for close, we'll do it as soon as we empty the buffer
                    if ($current_fh->fileno == STDIN->fileno) {
                        close(STDIN);    # we got EOF on it, so close it
                        if (length($child_stdin_to_write) == 0) {
                            close($child_stdin);
                        }
                        else {
                            $child_stdin_closing = 1;    # defer close to when our intermediate buffer is empty
                        }
                    }
                    else {
                        ;                                # EOF on our child's stdout or stderr, nothing to do
                    }
                    last;
                }

                # we got data, is this our child's stderr?
                elsif ($current_fh->fileno == $child_stderr->fileno) {
                    $bytesnb{'stderr'} += $nbread;
                    $stderr_output .= $buffer if !$is_binary;

                    # syswrite on our own STDERR what we received
                    if ($noisy_stderr) {
                        $syswrite_ensure->($nbread, *STDERR, 'stderr', \$noisy_stderr, $buffer);
                    }
                }

                # we got data, is this our child's stdout ?
                elsif ($current_fh->fileno == $child_stdout->fileno) {
                    $bytesnb{'stdout'} += $nbread;
                    $stdout_output .= $buffer if !$is_binary;

                    # syswrite on our own STDOUT what we received, if asked to do so
                    # is $is_helper, then we need to filter out the HELPER_RESULT before printing,
                    # so handle that further below
                    if ($noisy_stdout) {
                        if (!$is_helper) {
                            $syswrite_ensure->($nbread, *STDOUT, 'stdout', \$noisy_stdout, $buffer);
                        }
                        else {
                            # if this is a helper, hide the HELPER_RESULT from noisy_stdout
                            foreach my $char (split //, $buffer) {
                                if ($char eq $/) {
                                    # in that case, we didn't noisy print each char, we wait for $/
                                    # then print it IF this is not the result_from_helper (json)
                                    if ($stdout_buffer eq 'JSON_START') {
                                        $currently_in_json_block = 1;
                                    }
                                    if (not $currently_in_json_block) {
                                        $stdout_buffer .= $/;
                                        $syswrite_ensure->(
                                            length($stdout_buffer), *STDOUT, 'stdout', \$noisy_stdout, $stdout_buffer
                                        );
                                    }
                                    if ($currently_in_json_block and $stdout_buffer eq 'JSON_END') {
                                        $currently_in_json_block = 0;
                                    }
                                    $stdout_buffer = '';
                                }
                                else {
                                    $stdout_buffer .= $char;
                                }
                            }
                            # if we still have data in our local buffer, flush it
                            $syswrite_ensure->(
                                length($stdout_buffer), *STDOUT, 'stdout', \$noisy_stdout, $stdout_buffer
                            ) if $stdout_buffer;
                        }
                    }

                    if ($max_stdout_bytes && $bytesnb{'stdout'} >= $max_stdout_bytes) {
                        # caller got enough data, close all our child channels
                        $select->remove($child_stdout);
                        $select->remove($child_stderr);
                        close($child_stdin);
                        close($child_stdout);
                        close($child_stderr);

                        # and also our own STDIN if we're listening for it
                        if ($select->exists(\*STDIN)) {
                            $select->remove(\*STDIN);
                            close(STDIN);
                        }
                    }
                }

                # we got data, is this our stdin?
                elsif ($current_fh->fileno == STDIN->fileno) {
                    $bytesnb{'stdin'} += $nbread;
                    # save this data for the next loop
                    $child_stdin_to_write .= $buffer;
                }

                # wow, we got data from an unknown fh ... it's not possible ... theoretically
                else {
                    warn_syslog("Got data from an unknown fh ($current_fh) with $nbread bytes of data");
                    last;
                }
            }

            # /guarantee
        }
    }

    # here, all fd went EOF (except maybe STDIN but we don't care)
    # so we need to waitpid
    # (might be blocking, but we have nothing to read/write anyway)
    osh_debug("all fds are EOF, waiting for pid $pid indefinitely");
    waitpid($pid, 0);
    my $child_exit_status = $?;

    $fnret = sysret2human($child_exit_status);
    osh_debug("cmd returned with " . $fnret->msg);
    return R(
        $fnret->value->{'status'} == 0 ? 'OK' : ($must_succeed ? 'ERR_NON_ZERO_EXIT' : 'OK_NON_ZERO_EXIT'),
        value => {
            sysret     => $child_exit_status >> 8,
            sysret_raw => $child_exit_status,
            stdout     => [split($/, $stdout_output)],
            stderr     => [split($/, $stderr_output)],
            bytesnb    => \%bytesnb,
            status     => $fnret->value->{'status'},
            coredump   => $fnret->value->{'coredump'},
            signal     => $fnret->value->{'signal'},
        },
        msg => "Command exited with " . sysret2human($child_exit_status)->msg,
    );
}

# This is a simplified version of execute(), only supporting to launch a command,
# closing STDIN immediately, and merging STDERR/STDOUT into a global output that can
# then be returned to the caller. It removes a lot of complicated locking problems
# execute() has to work with at the expense of efficiency.
# Most notably, execute() reads STDOUT and STDERR one byte at a time in some cases,
# while execute_simple() uses a buffer of 16K instead, which is several orders of
# magnitude faster for commands outputting large amounts of data (several megabytes) for example.
sub execute_simple {
    my %params       = @_;
    my $cmd          = $params{'cmd'};             # command to execute, must be an array ref (with possible parameters)
    my $must_succeed = $params{'must_succeed'};    # if the executed command returns a non-zero exit value, turn OK_NON_ZERO_EXIT to ERR_NON_ZERO_EXIT
    my $fnret;

    require Scalar::Util;
    foreach (@$cmd) {
        if (Scalar::Util::tainted($_) && /(.+)/) {
            # to be able to warn under -T; untaint it. we're going to crash right after anyway.
            require Carp;
            warn(Carp::longmess("would exec <" . join('^', @$cmd) . "> but param '$1' is tainted!"));
        }
    }

    my $child_in;
    my $child_out = gensym;
    osh_debug("about to run_cmd_simple ['" . join("','", @$cmd) . "']");
    my $pid;
    eval { $pid = open3($child_in, $child_out, undef, @$cmd); };
    if ($@) {
        chomp $@;
        return R('ERR_EXEC_FAILED', msg => "Couldn't exec requested command ($@)");
    }
    close($child_in);
    osh_debug("waiting for child PID $pid to complete...");

    my $output;
    while (1) {
        my $buffer;
        my $nbread = read $child_out, $buffer, 65535;
        if (not defined $nbread) {
            # oww, abort reading
            warn("execute_simple(): error while reading from command ($!), aborting");
            last;
        }
        last if ($nbread == 0);    # EOF
        $output .= $buffer;
    }
    close($child_out);

    osh_debug("all fds are EOF, waiting for pid $pid indefinitely");
    waitpid($pid, 0);
    my $child_exit_status = $?;

    $fnret = sysret2human($child_exit_status);
    osh_debug("cmd returned with " . $fnret->msg);
    return R(
        $fnret->value->{'status'} == 0 ? 'OK' : ($must_succeed ? 'ERR_NON_ZERO_EXIT' : 'OK_NON_ZERO_EXIT'),
        value => {
            sysret     => $child_exit_status >> 8,
            sysret_raw => $child_exit_status,
            output     => $output,
            status     => $fnret->value->{'status'},
            coredump   => $fnret->value->{'coredump'},
            signal     => $fnret->value->{'signal'},
        },
        msg => "Command exited with " . sysret2human($child_exit_status)->msg,
    );
}

sub result_from_helper {
    my $input = shift;

    if (ref $input ne 'ARRAY') {
        $input = [$input];
    }

    my $state = 1;
    my @json;
    foreach my $line (@$input) {
        chomp;
        if ($state == 1) {
            if ($line eq 'JSON_START') {
                # will now capture data
                @json  = ();
                $state = 2;
            }
        }
        elsif ($state == 2) {
            if ($line eq 'JSON_END') {
                # done capturing data, might still see a new JSON_START however
                $state = 1;
            }
            else {
                # capturing data
                push @json, $line;
            }
        }
    }

    if (not @json) {
        return R('ERR_HELPER_RETURN_EMPTY',
            msg => "The helper didn't return any data, maybe it crashed, please report to your sysadmin!");
    }

    my $json_decoded;
    eval { $json_decoded = decode_json(join("\n", @json)); };
    if ($@) {
        return R('ERR_HELPER_RETURN_INVALID', msg => $@);
    }
    return R('OK', value => $json_decoded);
}

sub helper_decapsulate {
    my $value = shift;
    return R($value->{'error_code'}, value => $value->{'value'}, msg => $value->{'error_message'});
}

sub helper {
    my %params        = @_;
    my @command       = @{$params{'cmd'} || []};
    my $expects_stdin = $params{'expects_stdin'};
    my $stdin_str     = $params{'stdin_str'};

    my $fnret = OVH::Bastion::execute(
        cmd           => \@command,
        noisy_stdout  => 1,
        noisy_stderr  => 1,
        is_helper     => 1,
        expects_stdin => $expects_stdin,
        stdin_str     => $stdin_str
    );
    $fnret or return R('ERR_HELPER_FAILED', "something went wrong in helper script (" . $fnret->msg . ")");

    $fnret = OVH::Bastion::result_from_helper($fnret->value->{'stdout'});
    $fnret or return $fnret;

    return OVH::Bastion::helper_decapsulate($fnret->value);
}

1;
