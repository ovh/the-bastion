# vim: set filetype=perl ts=4 sw=4 sts=4 et:
package OVH::Bastion;

use common::sense;

use Config;
use Fcntl 'SEEK_CUR';
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

## no critic(ControlStructures::ProhibitDeepNests)
sub execute {
    my %params        = @_;
    my $cmd           = $params{'cmd'};            # command to execute, must be an array ref (with possible parameters)
    my $expects_stdin = $params{'expects_stdin'};  # the command called expects stdin, pipe caller stdin to it
    my $noisy_stdout  = $params{'noisy_stdout'};   # capture stdout but print it too
    my $noisy_stderr  = $params{'noisy_stderr'};   # capture stderr but print it too
    my $is_helper     = $params{'is_helper'};      # hide JSON returns from stdout even if noisy_stdout
    my $is_binary = $params{'is_binary'}; # used for e.g. scp, don't bother mimicking readline(), we lose debug and stdout/stderr are NOT returned to caller
    my $stdin_str = $params{'stdin_str'}; # string to push to the STDIN of the command
    my $must_succeed = $params{'must_succeed'}; # if the executed command returns a non-zero exit value, turn OK_NON_ZERO_EXIT to ERR_NON_ZERO_EXIT
    my $max_stdout_bytes = $params{'max_stdout_bytes'}; # if the amount of stored stdout bytes exceeds this, halt the command and return to caller
    my $system           = $params{'system'};           # if set to 1, will use system() instead of open3(), needed for some plugins

    $noisy_stderr = $noisy_stdout = 1 if ($ENV{'PLUGIN_DEBUG'} or $is_binary);
    my $fnret;

    require Scalar::Util;
    foreach (@$cmd) {
        if (Scalar::Util::tainted($_) && /(.+)/) {
            # to be able to warn under -T; untaint it. we're going to crash right after anyway.
            require Carp;
            warn(Carp::longmess("would exec <" . join('^', @$cmd) . "> but param '$1' is tainted!"));
        }
    }

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

    my ($child_stdin, $child_stdout, $child_stderr);
    $child_stderr = gensym;
    osh_debug("about to run_cmd ['" . join("','", @$cmd) . "']");
    my $pid;
    eval { $pid = open3($child_stdin, $child_stdout, $child_stderr, @$cmd); };
    if ($@) {
        chomp $@;
        return R('ERR_EXEC_FAILED', msg => "Couldn't exec requested command ($@)");
    }
    osh_debug("waiting for child PID $pid to complete...");

    my %output = ();
    my $stderr_output;
    my $stdout_output;
    my $stdout_buffer;
    my $current_fh;
    my $currently_in_json_block;
    my %bytesnb;

    # maximum number of code_info() to call, to avoid flooding the logs
    my $info_limit = 5;

    # always monitor our child stdout and stderr
    my $select = IO::Select->new($child_stdout, $child_stderr);
    binmode $child_stdin;
    binmode $child_stdout;
    binmode $child_stderr;

    # if some fd are closed, binmode may fail
    eval { binmode STDIN; };
    eval { binmode STDOUT; };
    eval { binmode STDERR; };

    if ($stdin_str) {

        # we have some stdin data to push, do it now
        syswrite $child_stdin, $stdin_str;
        close($child_stdin);
    }
    elsif ($expects_stdin) {

        # ... and also monitor our own stdin only if we expect it (we'll pipe it to our child's stdin)
        $select->add(\*STDIN);
    }

    # our own version of syswrite to handle auto-retry if interrupted by a signal
    my $syswrite_ensure = sub {
        my ($_nbread, $_FH, $_name, $_noisy_ref, $_buffer, $_info_limit) = @_;
        return if (!$_nbread || !$_buffer);

        my $offset = 0;
        while ($offset < $_nbread) {
            my $written = syswrite $_FH, $_buffer, 65535, $offset;
            if (not defined $written) {
                # is the fd still open? (maybe we got a SIGPIPE or a SIGHUP)
                # don't use tell() here, we use syseek() for unbuffered i/o,
                # note that if we're at the position "0", it's still true (see doc).
                my $previousError = $!;
                if (!sysseek($_FH, 0, SEEK_CUR)) {
                    info_syslog("execute(): error while syswriting($previousError/$!) on $_name, "
                          . "the filehandle is closed, will no longer attempt to write to it")
                      if $$_info_limit-- > 0;
                    $$_noisy_ref = 0 if $_noisy_ref;
                }
                else {
                    # oww, abort writing for this cycle. as this might be user-induced, use info instead of warn
                    info_syslog("execute(): error while syswriting($previousError) on $_name, " . "aborting this cycle")
                      if $$_info_limit-- > 0;
                }
                last;
            }
            $offset += $written;
        }
    };

    # then, while we still have fh to monitor
    while ($select->count() > 1 || ($select->count() == 1 && !$select->exists(\*STDIN))) {

        # block only for 50ms, before checking if child is dead
        my @ready = $select->can_read(0.05);

        # yep, we have something to read on at least one fh
        if (@ready) {

            # guarantee we're still reading this fh while it has something to say
            $current_fh = $ready[0];
            my $sub_select = IO::Select->new($current_fh);

            # can_read(0) because we don't need a timeout: we KNOW there's something to read on this fh
            while ($sub_select->can_read(0)) {
                my $buffer;
                my $nbread = sysread $current_fh, $buffer, 65535;

                # undef mears error, we'll log to syslog and close. as this might be user-induced, use info instead of warn
                if (not defined $nbread) {
                    # awwww, not cool at all
                    info_syslog("execute(): error while sysreading($!), closing fh!");
                }

                # if size 0, it means it's an EOF
                elsif ($nbread == 0) {
                    # we got an EOF on this fh, remove it from the monitor list
                    $select->remove($current_fh);

                    # if this is an EOF on our own STDIN, we need to close our child's STDIN
                    if ($current_fh->fileno == STDIN->fileno) {
                        close(STDIN);           # we got eof on it, so close it
                        close($child_stdin);    # and close our child stdin
                    }
                    else {
                        ;                       # eof on our child's stdout or stderr, nothing to do
                    }
                    last;
                }

                # we got data, is this our child's stderr ?
                elsif ($current_fh->fileno == $child_stderr->fileno) {
                    $bytesnb{'stderr'} += $nbread;
                    $stderr_output .= $buffer if !$is_binary;

                    # syswrite on our own STDERR what we received
                    if ($noisy_stderr) {
                        $syswrite_ensure->($nbread, *STDERR, 'stderr', \$noisy_stderr, $buffer, \$info_limit);
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
                            $syswrite_ensure->($nbread, *STDOUT, 'stdout', \$noisy_stdout, $buffer, \$info_limit);
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
                                            length($stdout_buffer), *STDOUT, 'stdout', \$noisy_stdout, $stdout_buffer,
                                            \$info_limit
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
                                length($stdout_buffer), *STDOUT, 'stdout', \$noisy_stdout, $stdout_buffer, \$info_limit
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

                # we got data, is this our stdin ?
                elsif ($current_fh->fileno == STDIN->fileno) {
                    $bytesnb{'stdin'} += $nbread;

                    # we just write the data to our child's own stdin
                    $syswrite_ensure->($nbread, $child_stdin, 'child_stdin', undef, $buffer, \$info_limit);
                }

                # wow, we got data from an unknown fh ... it's not possible
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
    my %params = @_;
    my $cmd    = $params{'cmd'};    # command to execute, must be an array ref (with possible parameters)
    my $must_succeed = $params{'must_succeed'}; # if the executed command returns a non-zero exit value, turn OK_NON_ZERO_EXIT to ERR_NON_ZERO_EXIT
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
