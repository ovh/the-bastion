# vim: set filetype=perl ts=4 sw=4 sts=4 et:
package OVH::Bastion;

use common::sense;

use Config;
use Fcntl qw{ F_GETFL F_SETFL O_NONBLOCK };
use IPC::Open3;
use JSON;
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

sub execute {
    my %params            = @_;
    my $cmd               = $params{'cmd'};                  # command to execute, must be an array ref (with possible parameters)
    my $expects_stdin     = $params{'expects_stdin'};        # the command called expects stdin, pipe caller stdin to it
    my $noisy_stdout      = $params{'noisy_stdout'};         # capture stdout but print it too
    my $noisy_stderr      = $params{'noisy_stderr'};         # capture stderr but print it too
    my $capture_result_fd = $params{'capture_result_fd'};    # wire fd 3 as the child's result channel (real helpers), capture it into result_fd_output
    my $hide_json_result  = $params{'hide_json_result'};     # suppress a JSON_START..JSON_END block from the live stdout tee (osh.pl --json, e.g. batch)
    my $is_binary         = $params{'is_binary'};            # used for e.g. scp, stdout/stderr are NOT returned to caller
    my $stdin_str         = $params{'stdin_str'};            # string to push to the STDIN of the command
    my $must_succeed      = $params{'must_succeed'};         # if the executed command returns a non-zero exit value, turn OK_NON_ZERO_EXIT to ERR_NON_ZERO_EXIT
    my $max_stdout_bytes  = $params{'max_stdout_bytes'};     # if the amount of stored stdout bytes exceeds this, halt the command and return to caller
    my $system            = $params{'system'};               # if set to 1, will use system() instead, needed for some plugins

    $noisy_stderr = $noisy_stdout = 1 if ($ENV{'PLUGIN_DEBUG'} or $is_binary);
    my $fnret;

    # Normalize the command list: callers may pass undef positional args (e.g. osh.pl passes
    # undef user/ip/host for plugin commands). open3/system silently stringify undef to '',
    # but IPC::Run dies ("undef passed") on any undef element, so do it explicitly here.
    $cmd = [map { defined $_ ? $_ : '' } @$cmd];

    # taint check: refuse to silently exec a tainted command
    require Scalar::Util;
    foreach (@$cmd) {
        if (Scalar::Util::tainted($_) && /(.+)/) {
            # to be able to warn under -T; untaint it. we're going to crash right after anyway.
            require Carp;
            warn(Carp::longmess("would exec <" . join('^', @$cmd) . "> but param '$1' is tainted!"));
        }
    }

    # if caller wants us to use system(), just do it here and call it a day: this is a faithful
    # full-inheritance exec, kept as-is (needed for some plugins, such as scp)
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

    # otherwise, delegate the select loop, backpressure and deadlock avoidance to IPC::Run
    require IPC::Run;

    # IPC::Run resolves a bare command name (one with no '/') by searching $ENV{PATH} in pure Perl,
    # and unlike the open3()/execvp() path we used before, it does NOT fall back to a system default
    # path when $ENV{PATH} is empty or unset: it just dies with "Command 'x' not found". Some callers
    # legitimately run with a cleared environment and relied on that execvp fallback -- notably the
    # HTTP proxy, where Net::Server::HTTP does `%ENV = ()` on every request. Restore the old behavior
    # by giving IPC::Run a sane default PATH for its lookup when none is set (scoped to this call).
    local $ENV{'PATH'} =
      (defined $ENV{'PATH'} && length $ENV{'PATH'})
      ? $ENV{'PATH'}
      : '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';

    # ensure our own std handles are in raw mode: we tee raw bytes (including binary payloads, e.g.
    # selfPlaySession) to STDOUT/STDERR and pump STDIN through verbatim, so no PerlIO layer (:utf8,
    # :crlf, ...) must be allowed to mangle them. Wrap each in eval{} as binmode may fail on an
    # already-closed handle.
    eval { binmode STDIN; };
    eval { binmode STDOUT; };
    eval { binmode STDERR; };

    my %bytesnb = (stdout => 0, stderr => 0);
    my ($stdout_output, $stderr_output) = ('', '');

    # --- stdin source ---
    my ($in_spec, $stdin_wh);
    if (defined $stdin_str && length $stdin_str) {
        # Feed the buffer ourselves through a pipe we own (see the feeding loop below), instead of
        # handing IPC::Run a scalar ref: its writer pump croaks on EPIPE on all the IPC::Run versions
        # shipped by our supported OSes (only fixed upstream in 20250715), whereas a child exiting
        # before consuming its whole stdin is a normal occurrence (e.g. passwd rejecting a password
        # early): in that case we must keep draining its stdout/stderr and report its real exit
        # status, as the pre-IPC::Run implementation of execute() did. The read end is passed as a
        # GLOB: IPC::Run dup()s it straight into the child with no writer pump attached, so there's
        # nothing left on its side to croak. Perl's default $^F guarantees both ends are
        # close-on-exec, so the child doesn't inherit a copy of the write end (which would prevent
        # it from ever seeing EOF on its stdin once we're done writing).
        pipe(my $stdin_rh, $stdin_wh) or return R('ERR_SYSCALL_FAILED', msg => "Couldn't create a pipe ($!)");
        binmode $stdin_rh;
        binmode $stdin_wh;
        $in_spec = $stdin_rh;
    }
    elsif ($expects_stdin) {
        $in_spec = \*STDIN;    # dup'ed into the child by IPC::Run: it reads our own stdin directly
    }
    else {
        $in_spec = \undef;     # child gets /dev/null (immediate EOF)
    }

    # --- output sinks: count bytes, capture (unless binary), optionally tee to our own fd ---
    # hide_json_result is for running osh.pl recursively (e.g. the batch plugin): osh.pl is not a
    # bastion helper, it emits its --json result as a JSON_START..JSON_END block on stdout. When teeing,
    # hide any such block from the live tee (line by line): both to keep the console clean and so a
    # caller capturing our stdout doesn't mistake it for our own result. The raw bytes are still
    # captured in $stdout_output, which execute_osh() parses. (Real helpers don't need this: they
    # return over fd 3 and emit nothing structured on stdout, see capture_result_fd below.)
    my ($json_tee_buf, $in_json_block) = ('', 0);
    my $stdout_sink = sub {
        my $chunk = shift;
        $bytesnb{stdout} += length $chunk;
        $stdout_output .= $chunk if !$is_binary;

        if ($noisy_stdout) {
            if (!$hide_json_result) {
                print {*STDOUT} $chunk;
            }
            else {
                # consume complete lines via index()/substr() rather than a `s/^(.*\n)//` that
                # re-scans a growing buffer from the front (O(n^2) on a long newline-less run, e.g.
                # osh.pl's single-line encoded JSON result).
                $json_tee_buf .= $chunk;
                my $nl;
                while (($nl = index($json_tee_buf, "\n")) >= 0) {
                    my $line = substr($json_tee_buf, 0, $nl + 1, '');    # take one line incl. newline
                    (my $bare = $line) =~ s/\r?\n\z//;
                    if    ($bare eq 'JSON_START') { $in_json_block = 1; }
                    elsif ($bare eq 'JSON_END')   { $in_json_block = 0; }
                    else                          { print {*STDOUT} $line if !$in_json_block; }
                }
                # inside a hidden block, the leftover partial line is either the tail of a long
                # (newline-less) data line we're hiding, or the start of the short JSON_END marker
                # split across two chunks. Drop it only once it's too long to be a marker: this keeps
                # the buffer bounded on a huge single-line result (still captured in $stdout_output)
                # without ever losing a JSON_END that straddles a chunk boundary (which would otherwise
                # wedge us in-block and hide all subsequent human output).
                $json_tee_buf = '' if ($in_json_block && length($json_tee_buf) > length('JSON_START'));
            }
        }

        # honor max_stdout_bytes: we have enough, signal the loop to stop
        die "EXECUTE_MAX_STDOUT_BYTES\n" if ($max_stdout_bytes && $bytesnb{stdout} >= $max_stdout_bytes);
        return;
    };

    my $stderr_sink = sub {
        my $chunk = shift;
        $bytesnb{stderr} += length $chunk;
        $stderr_output .= $chunk if !$is_binary;
        print {*STDERR} $chunk   if $noisy_stderr;
        return;
    };

    # for real helpers (bin/helper/osh-*), capture their JSON result on a dedicated fd (3) instead of
    # having them frame it on stdout: this keeps stdout clean (human output only) for the live tee. The
    # helper finds this channel as its (only) open fd 3 at startup and writes its result there (see
    # OVH::Bastion::Helper). helper() consumes result_fd_output below.
    my $result_fd_output;

    # For binary bulk transfers (e.g. the sftp/rsync data path), keep ourselves out of the child's
    # I/O entirely: in is_binary mode the sinks above neither capture (skipped) nor filter (no JSON
    # to hide), they'd only relay bytes to our own std fds -- and IPC::Run pumps CODE sinks through
    # its select loop in small chunks, a hefty CPU cost at data-transfer rates. Passing our fds as
    # GLOBs instead makes IPC::Run dup2() them straight into the child, which then writes to them
    # directly, with no parent-side pumping at all (just like we already do for '<' STDIN above).
    # We can't do this when max_stdout_bytes is set: the counting sink is what stops the child. No
    # counting happens in passthrough mode either (bytesnb stays 0, nothing consumes it here).
    my ($out_spec, $err_spec) = ($stdout_sink, $stderr_sink);
    ($out_spec, $err_spec) = (\*STDOUT, \*STDERR) if ($is_binary && !$max_stdout_bytes);

    my @harness_args = ([@$cmd], '<', $in_spec, '>', $out_spec, '2>', $err_spec);
    push @harness_args, '3>', \$result_fd_output if $capture_result_fd;

    osh_debug("about to run_cmd ['" . join("','", @$cmd) . "'] (via IPC::Run)");
    my $harness = IPC::Run::harness(@harness_args);

    my $hit_max_stdout = 0;
    my $ok             = eval {
        $harness->start;

        # feed stdin_str to the child ourselves, with the same graceful semantics the pre-IPC::Run
        # implementation had: a child no longer reading its stdin is not an error, stop feeding it
        # and keep going to collect its output and real exit status (see the pipe() creation above)
        if ($stdin_wh) {
            # Writing to the pipe of a child that exited raises SIGPIPE: this one is pure execute()
            # machinery, so shield the caller from it for the duration of the feeding phase -- an
            # unhandled caller would get killed outright, and a handled one would have its handler
            # spuriously triggered by what is a benign event (Plugin.pm's handler tears the whole
            # process group down!). With the signal ignored, our syswrite cleanly gets EPIPE, which
            # the loop below handles. This is deliberately scoped to the feeding phase and NOT to
            # finish(): a SIGPIPE raised by the stdout/stderr tee means the CALLER's own output
            # channel died (e.g. user disconnected), and acting on that (like Plugin.pm killing the
            # process group to tear the session down) is the caller's policy, not ours to silence.
            local $SIG{'PIPE'} = 'IGNORE';

            # the child got its own dup of the read end when it was spawned; close ours so that
            # once the child is gone, our syswrites get a proper EPIPE instead of filling a pipe
            # that nobody will ever read
            close($in_spec);

            # set our write end non-blocking: when the pipe is full, we must keep draining the
            # child's stdout/stderr while it digests, or we'd deadlock each other
            my $flflags = fcntl($stdin_wh, F_GETFL, 0);
            fcntl($stdin_wh, F_SETFL, $flflags | O_NONBLOCK) if defined $flflags;

            my $offset = 0;
            my $len    = length $stdin_str;
            while ($offset < $len) {
                my $written = syswrite($stdin_wh, $stdin_str, $len - $offset, $offset);
                if (defined $written) {
                    $offset += $written;
                }
                elsif ($!{'EINTR'}) {
                    next;    # interrupted by a signal, just retry
                }
                elsif ($!{'EAGAIN'} || $!{'EWOULDBLOCK'}) {
                    # pipe full: drain the child's pending output, then wait (10ms max) for room.
                    # waiting for room alone would deadlock us with a child that blocks writing
                    # its stdout until we read it, hence the pump_nb (non-blocking pump) each round
                    $harness->pump_nb if $harness->pumpable;
                    my $win = '';
                    vec($win, fileno($stdin_wh), 1) = 1;
                    select(undef, $win, undef, 0.01);
                }
                else {
                    # EPIPE & friends: the child stopped reading its stdin (most likely it exited,
                    # or closed it on purpose); not an error, it just doesn't want our data
                    osh_debug("execute: stopped feeding stdin_str to the child ($!)");
                    last;
                }
            }
            close($stdin_wh);    # done writing (or gave up): give the child its EOF
        }

        $harness->finish;
        1;
    };
    if (!$ok) {
        my $err = $@ || 'unknown error';
        # note: IPC::Run prepends context (e.g. "ack ") to exceptions thrown from within a sink
        # callback, so match our sentinel anywhere in the message, not anchored at the start.
        if ($err =~ /EXECUTE_MAX_STDOUT_BYTES/) {
            $hit_max_stdout = 1;              # this is a deliberate stop, not a command failure
            eval { $harness->kill_kill; };    # we got enough output, stop the child
            eval { $harness->finish; };       # then reap it
        }
        else {
            # genuine failure: either the exec itself failed, or IPC::Run hit an internal error
            # (such as EPIPE while pumping the child's stdin), in which case the child HAS been
            # started: kill and reap it if any, instead of leaving a zombie behind us until we exit
            eval { $harness->kill_kill; };
            eval { $harness->finish; };
            chomp $err;
            return R('ERR_EXEC_FAILED', msg => "Couldn't exec requested command ($err)");
        }
    }

    # flush any trailing (newline-less) line we held back from the hide_json_result tee, unless it's
    # part of a JSON result block we're hiding
    print {*STDOUT} $json_tee_buf
      if ($noisy_stdout && $hide_json_result && length $json_tee_buf && !$in_json_block);

    # raw wait status ($?) of our single command. Use the plural full_results() and take the first
    # element rather than full_result(0): in IPC::Run 20180523.0 (shipped on e.g. RockyLinux 8 and
    # Ubuntu 20.04), full_result($index) does `goto &result if @_ > 1`, so it wrongly returns the
    # already->>8-shifted exit code instead of the raw $?, and our own >>8 below would then zero out
    # every sub-256 exit code. full_results() returns the raw RESULT and behaves identically across
    # versions.
    my $child_exit_status = 0;
    eval { ($child_exit_status) = $harness->full_results; };
    $child_exit_status = 0 if !defined $child_exit_status;

    $fnret = sysret2human($child_exit_status);
    osh_debug("cmd returned with $fnret");

    # decide our return code. note: a signal death yields status => undef (not 0), so guard with
    # defined() before the == 0 test, otherwise `undef == 0` is true and we'd wrongly report OK (and
    # silently defeat must_succeed) for a killed command. A command we deliberately stopped after
    # max_stdout_bytes is NOT a failure: keep it OK even under must_succeed (e.g. connect.pl truncating
    # a ttyrec preview), as we killed it on purpose once we had enough output.
    my $status = $fnret->value->{'status'};
    my $code =
        $hit_max_stdout                   ? 'OK'
      : (defined $status && $status == 0) ? 'OK'
      : $must_succeed                     ? 'ERR_NON_ZERO_EXIT'
      :                                     'OK_NON_ZERO_EXIT';
    return R(
        $code,
        value => {
            sysret           => $child_exit_status >> 8,
            sysret_raw       => $child_exit_status,
            stdout           => [split($/, $stdout_output // '')],
            stderr           => [split($/, $stderr_output // '')],
            result_fd_output => $result_fd_output,             # raw JSON from the fd-3 result channel, if any (capture_result_fd)
            bytesnb          => \%bytesnb,
            status           => $fnret->value->{'status'},
            coredump         => $fnret->value->{'coredump'},
            signal           => $fnret->value->{'signal'},
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
    osh_debug("cmd returned with $fnret");

    # a signal death yields status => undef (not 0); guard with defined() before == 0, otherwise
    # `undef == 0` is true and we'd wrongly report OK (and silently defeat must_succeed) for a kill.
    my $status = $fnret->value->{'status'};
    return R(
        (defined $status && $status == 0) ? 'OK' : ($must_succeed ? 'ERR_NON_ZERO_EXIT' : 'OK_NON_ZERO_EXIT'),
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

# Parse a JSON result framed as a JSON_START..JSON_END block within an array of stdout lines. This is
# the format osh.pl emits for --json output, consumed by execute_osh() (e.g. the batch plugin, which
# runs osh.pl recursively). Real helpers (bin/helper/osh-*) don't use this: they return their result
# over the dedicated fd 3 (see json_output()), which helper() reads directly.
sub result_from_json_output {
    my $input = shift;

    if (ref $input ne 'ARRAY') {
        $input = [$input];
    }

    my $state = 1;
    my @json;
    foreach my $line (@$input) {
        chomp $line;
        if ($state == 1) {
            if ($line eq 'JSON_START') {
                @json  = ();
                $state = 2;
            }
        }
        elsif ($state == 2) {
            if ($line eq 'JSON_END') {
                $state = 1;
            }
            else {
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

# Shared core for helper() and execute_osh(): run a result-bearing child via execute() with the
# caller-chosen result-transport flag ($result_flag, 'capture_result_fd' for real helpers via fd 3, or
# 'hide_json_result' for osh.pl framing its result on stdout), tee its human output live, then hand the
# execute() $fnret to $extract, which pulls out and decapsulates the structured JSON result.
sub _execute_with_result {
    my %params      = @_;
    my $result_flag = $params{'result_flag'};
    my $extract     = $params{'extract'};

    my $fnret = OVH::Bastion::execute(
        cmd           => [@{$params{'cmd'} || []}],
        noisy_stdout  => 1,
        noisy_stderr  => 1,
        $result_flag  => 1,
        expects_stdin => $params{'expects_stdin'},
        stdin_str     => $params{'stdin_str'},
    );
    $fnret or return R('ERR_HELPER_FAILED', msg => "something went wrong while running the command ($fnret)");

    return $extract->($fnret);
}

# Run a bastion helper (bin/helper/osh-*) under sudo via execute(), and return its decapsulated
# result. The helper returns its JSON result over the dedicated fd 3 (see json_output()/HEXIT and
# OVH::Bastion::Helper), which keeps its stdout clean for the live tee. To run osh.pl recursively
# instead (which is not a helper and frames its result on stdout), use execute_osh().
sub helper {
    my %params = @_;
    return _execute_with_result(
        %params,
        result_flag => 'capture_result_fd',
        extract     => sub {
            my $fnret  = shift;
            my $result = $fnret->value->{'result_fd_output'};
            if (!defined $result || !length $result) {
                return R('ERR_HELPER_RETURN_EMPTY',
                    msg => "The helper didn't return any data, maybe it crashed, please report to your sysadmin!");
            }
            my $decoded;
            eval { $decoded = decode_json($result); };
            if ($@) {
                return R('ERR_HELPER_RETURN_INVALID', msg => $@);
            }
            return OVH::Bastion::helper_decapsulate($decoded);
        },
    );
}

# Run osh.pl recursively (the login shell) with --json, and return its decapsulated result. Unlike a
# bastion helper, osh.pl is not run under sudo and doesn't use the fd-3 result channel: it frames its
# result as a JSON_START..JSON_END block on stdout. We hide that block from the live tee (so the user
# only sees human output) but still capture it, then parse it. Currently used by the batch plugin.
sub execute_osh {
    my %params = @_;
    return _execute_with_result(
        %params,
        result_flag => 'hide_json_result',
        extract     => sub {
            my $fnret = shift;
            $fnret = OVH::Bastion::result_from_json_output($fnret->value->{'stdout'});
            $fnret or return $fnret;
            return OVH::Bastion::helper_decapsulate($fnret->value);
        },
    );
}

1;
