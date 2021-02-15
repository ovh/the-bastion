# vim: set filetype=perl ts=4 sw=4 sts=4 et:
package OVH::Bastion;

use common::sense;

use IO::Handle;
use IPC::Open3;
use Symbol 'gensym';
use IO::Select;
use POSIX ":sys_wait_h";
use JSON;
use Config;

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
        return R('OK', value => {coredump => \0, signal => undef, status => $sysret >> 8}, msg => sprintf("status %d", $sysret >> 8));
    }
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

    my $readsize = $is_binary ? 16384 : 1;                 # XXX needs to be enhanced to be > 1 even for non-binary
    my $fnret;

=cut only to debug slow calls
    if (not $is_binary)
    {
        require Carp;
        open(SLOW, '>>', '/dev/shm/slowexecute');
        print SLOW Carp::longmess(join('^',@$cmd))."\n\n";
        close(SLOW);
    }
=cut

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
    my %lineBuffer;
    my $currentActive           = undef;
    my $currently_in_json_block = 0;
    my %bytesnb;

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

    # then, while we still have fh to monitor
    while ($select->count() > 1 || ($select->count() == 1 && !$select->exists(\*STDIN))) {

        # block only for 50ms, before checking if child is dead
        my @ready = $select->can_read(0.05);

        # yep, we have something to read on at least one fh
        if (@ready) {

            # guarantee we're still reading this fh while it has something to say
            $currentActive = $ready[0];
            my $subSelect = IO::Select->new($currentActive);

            # can_read(0) because we don't need a timeout: we KNOW there's something to read on this fh
            while ($subSelect->can_read(0)) {
                my $buffer;
                my $nbread = sysread $currentActive, $buffer, $readsize;

                # if size 0, it means it's an EOF, if undef, it's an error
                if (not $nbread) {

                    # error, we'll warn and close
                    if (not defined $nbread) {

                        # awwww, not cool at all
                        warn("execute(): error while sysreading($!), closing fh!");
                    }

                    # we got an EOF on this fh, remove it from the monitor list
                    $select->remove($currentActive);

                    # if this is an EOF on our own STDIN, we need to close our child's STDIN
                    if ($currentActive->fileno == STDIN->fileno) {
                        close(STDIN);           # we got eof on it, so close it
                        close($child_stdin);    # and close our child stdin
                    }
                    else {
                        ;                       # eof on our child's stdout or stderr, nothing to do
                    }
                    last;
                }

                # we got data, is this our child's stderr ?
                if ($currentActive->fileno == $child_stderr->fileno) {
                    $bytesnb{'stderr'} += $nbread;

                    # syswrite on our own STDERR what we received
                    if ($noisy_stderr) {
                        my $offset = 0;
                        while ($offset < $nbread) {
                            my $written = syswrite STDERR, $buffer, $readsize, $offset;
                            if (not defined $written) {

                                # oww, abort writing for this cycle
                                warn("execute(): error while syswriting($!) on stderr, aborting this cycle");
                                last;
                            }
                            $offset += $written;
                        }
                    }

                    # mimic line-based reading (for debug, and also data will be returned to caller)
                    if (not $is_binary) {

                        # if this is a newline, push it to our output array
                        if ($buffer eq $/) {
                            osh_debug("stderr($pid): " . $lineBuffer{'stderr'}) unless $noisy_stderr;    # avoid double print
                            push @{$output{'stderr'}}, $lineBuffer{'stderr'};
                            $lineBuffer{'stderr'} = '';
                        }

                        # or push it to our temp line buffer
                        else {
                            $lineBuffer{'stderr'} .= $buffer;
                        }
                    }
                }

                # we got data, is this our child's stdout ?
                elsif ($currentActive->fileno == $child_stdout->fileno) {
                    $bytesnb{'stdout'} += $nbread;

                    # syswrite on our own STDOUT what we received
                    if ($noisy_stdout and not $is_helper) {

                        # the "if is_helper" case is handled below per-line
                        my $offset = 0;
                        while ($offset < $nbread) {
                            my $written = syswrite STDOUT, $buffer, $readsize, $offset;
                            if (not defined $written) {

                                # oww, abort writing for this cycle
                                warn("execute(): error while syswriting($!) on stdout, aborting this cycle");
                                last;
                            }
                            $offset += $written;
                        }
                    }

                    # mimic line-based reading (for debug, and also data will be returned to caller)
                    if (not $is_binary) {
                        if ($buffer eq $/) {
                            osh_debug("stdout($pid): " . $lineBuffer{'stdout'}) unless $noisy_stdout;    # avoid double print
                            push @{$output{'stdout'}}, $lineBuffer{'stdout'};
                            if ($noisy_stdout and $is_helper) {

                                # in that case, we didn't noisy print each char, we wait for $/
                                # then print it IF this is not the result_from_helper (json)
                                if ($lineBuffer{'stdout'} eq 'JSON_START') {
                                    $currently_in_json_block = 1;
                                }
                                if (not $currently_in_json_block) {
                                    print $lineBuffer{'stdout'} . $/;
                                }
                                if ($currently_in_json_block and $lineBuffer{'stdout'} eq 'JSON_END') {
                                    $currently_in_json_block = 0;
                                }
                            }
                            $lineBuffer{'stdout'} = '';
                        }
                        else {
                            $lineBuffer{'stdout'} .= $buffer;
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

                        # don't forget to push any pending data to our output buffer
                        push @{$output{'stdout'}}, $lineBuffer{'stdout'};
                    }
                }

                # we got data, is this our stdin ?
                elsif ($currentActive->fileno == STDIN->fileno) {
                    $bytesnb{'stdin'} += $nbread;

                    # we just write the data to our child's own stdin
                    syswrite $child_stdin, $buffer;
                }

                # wow, we got data from an unknown fh ... it's not possible
                else {
                    # ... but just in case:
                    require Data::Dumper;
                    osh_warn("unknown fh: " . Data::Dumper::Dumper($currentActive) . " with char <$buffer>");
                    osh_warn(Data::Dumper::Dumper($child_stdout));
                    osh_warn(Data::Dumper::Dumper($child_stderr));
                    osh_warn(Data::Dumper::Dumper(\*STDIN));
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
            stdout     => $output{stdout},
            stderr     => $output{stderr},
            bytesnb    => \%bytesnb,
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
        return R('ERR_HELPER_RETURN_EMPTY', msg => "The helper didn't return any data, maybe it crashed, please report to your sysadmin!");
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

    my $fnret = OVH::Bastion::execute(cmd => \@command, noisy_stdout => 1, noisy_stderr => 1, is_helper => 1, expects_stdin => $expects_stdin, stdin_str => $stdin_str);
    $fnret or return R('ERR_HELPER_FAILED', "something went wrong in helper script (" . $fnret->msg . ")");

    $fnret = OVH::Bastion::result_from_helper($fnret->value->{'stdout'});
    $fnret or return $fnret;

    return OVH::Bastion::helper_decapsulate($fnret->value);
}

1;
