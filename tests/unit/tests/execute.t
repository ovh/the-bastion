#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;
use Test::More;

use File::Basename;
use lib dirname(__FILE__) . '/../../../lib/perl';
use OVH::Bastion;
use OVH::Result;

# execute() now delegates to IPC::Run; if it's not installed here (e.g. a dev machine that
# never ran packages-check), execute() can't run at all, so skip rather than hard-fail.
if (!eval { require IPC::Run; 1 }) {
    plan skip_all => "IPC::Run is not available, can't test OVH::Bastion::execute()";
}

# we use the running perl as a portable, always-present test program
my $perl = $^X;

# --- basic exec: exit code, stdout/stderr split, must_succeed -----------------------------------
# This also guards the exit-code extraction: execute() reads the raw wait status via the plural
# full_results() to dodge the IPC::Run 20180523.0 full_result($idx) quirk that would otherwise
# zero out every sub-256 exit code. So a child exiting 3 MUST come back as 3, not 0.
{
    my $r = OVH::Bastion::execute(
        cmd          => [$perl, '-e', 'print "out1\nout2\n"; print STDERR "err1\n"; exit 3'],
        must_succeed => 1,
    );
    isa_ok($r, 'OVH::Result', "execute() returns an OVH::Result");
    is($r->err,               'ERR_NON_ZERO_EXIT', "must_succeed turns a non-zero exit into ERR_NON_ZERO_EXIT");
    is($r->value->{'status'}, 3, "child exit code 3 is reported as 3 (not zeroed by full_result quirk)");
    is($r->value->{'sysret'}, 3, "sysret matches the exit code");
    is_deeply($r->value->{'stdout'}, ['out1', 'out2'], "stdout is captured and split into lines");
    is_deeply($r->value->{'stderr'}, ['err1'],         "stderr is captured separately");

    # without must_succeed, the same non-zero exit is a soft OK_NON_ZERO_EXIT (still truthy)
    my $r2 = OVH::Bastion::execute(cmd => [$perl, '-e', 'exit 3']);
    ok($r2, "non-zero exit without must_succeed is still a truthy result");
    is($r2->err, 'OK_NON_ZERO_EXIT', "non-zero exit without must_succeed -> OK_NON_ZERO_EXIT");
}

# --- stdin_str is fed to the child --------------------------------------------------------------
{
    my $r = OVH::Bastion::execute(
        cmd       => [$perl, '-ne', 'print'],    # cat-like: echo stdin back to stdout
        stdin_str => "fed-via-stdin\n",
    );
    ok($r, "execute() with stdin_str returns a truthy result");
    is($r->value->{'status'}, 0, "child reading stdin_str exits cleanly");
    is_deeply($r->value->{'stdout'}, ['fed-via-stdin'], "stdin_str is delivered to the child's stdin");
}

# --- stdin_str to a child that stops reading it: graceful, the real status is returned ----------
# The pre-IPC::Run execute() tolerated a child exiting before consuming its whole stdin (e.g.
# passwd rejecting a password early): it kept draining the child's output and returned its real
# exit status and diagnostics. IPC::Run's own writer instead croaks on EPIPE on every version
# shipped by our supported OSes, so execute() feeds stdin_str itself: guard that behavior here.
{
    # we deliberately run with the default SIGPIPE disposition: execute() shields its callers
    # from the SIGPIPE its own stdin-feeding machinery can raise, and this block also guards
    # that contract -- if it regresses, the signal kills the whole test, loudly

    # 5MB, way beyond pipe capacity: writes are still pending whenever the child bails out
    my $big = 'A' x (5 * 1024 * 1024);

    # a child that reads a little, then exits cleanly
    my $r = OVH::Bastion::execute(
        cmd       => [$perl, '-e', 'read(STDIN, my $buf, 100); print "got100\n"; exit 0'],
        stdin_str => $big,
    );
    ok($r, "a child exiting before consuming its whole stdin_str is not an error");
    is($r->err,               'OK', "...it reports OK");
    is($r->value->{'status'}, 0,    "...with its real exit code");
    is_deeply($r->value->{'stdout'}, ['got100'], "...and its output is still fully collected");

    # a child that fails outright without reading anything: its diagnostics must reach the caller
    $r = OVH::Bastion::execute(
        cmd       => [$perl, '-e', 'print STDERR "cannot comply\n"; exit 3'],
        stdin_str => $big,
    );
    is($r->err,               'OK_NON_ZERO_EXIT', "a child failing without reading stdin_str reports its real exit");
    is($r->value->{'status'}, 3,                  "...with its real exit code, not ERR_EXEC_FAILED");
    is_deeply($r->value->{'stderr'}, ['cannot comply'], "...and its stderr diagnostics are preserved");

    # a child that consumes everything gets every byte (exercises the pipe-full/pump interleaving)
    $r = OVH::Bastion::execute(
        cmd       => [$perl, '-e', 'my $l = 0; while (read(STDIN, my $b, 65536)) { $l += length $b } print "len=$l\n"'],
        stdin_str => $big,
    );
    is($r->err, 'OK', "a child consuming a stdin_str larger than the pipe capacity succeeds");
    is_deeply($r->value->{'stdout'}, ['len=' . length($big)], "...and receives every single byte of it");
}

# --- bare command name still resolves when $ENV{PATH} is empty (regression for the HTTP proxy) ---
# IPC::Run looks up a bare command via $ENV{PATH} and, unlike open3()/execvp(), doesn't fall back to
# a default path when it's empty. The HTTP proxy runs execute() with a cleared %ENV (Net::Server::HTTP
# does `%ENV = ()` per request), so a bare 'sudo' must still be found. execute() restores the fallback.
{
    local $ENV{'PATH'} = '';    # mimic the proxy's cleared environment
    my $r = OVH::Bastion::execute(cmd => ['sh', '-c', 'exit 0']);
    ok($r, "execute() finds a bare command even with an empty \$ENV{PATH}");
    isnt($r->err, 'ERR_EXEC_FAILED', "no 'command not found' when PATH is empty (proxy regression)");
    is($r->value->{'status'}, 0, "the bare command ran and exited cleanly") if $r->value;
}

# --- max_stdout_bytes: below the cap, the command completes normally ----------------------------
{
    my $r = OVH::Bastion::execute(
        cmd              => [$perl, '-e', 'print "short output\n"; exit 0'],
        max_stdout_bytes => 2000,
    );
    ok($r, "execute() with max_stdout_bytes (below cap) returns a truthy result");
    is($r->value->{'status'}, 0, "command under the byte cap completes normally with its real exit code");
    is_deeply($r->value->{'stdout'}, ['short output'], "full output is returned when under the cap");
    cmp_ok($r->value->{'bytesnb'}{'stdout'}, '<', 2000, "captured fewer than max_stdout_bytes bytes");
}

# --- max_stdout_bytes: above the cap, the child is killed and we don't hang (regression for #3) --
# A child that floods stdout far past the cap. Pipe backpressure means it blocks long before
# producing it all, but even if the abort were broken it stays finite, so a regression surfaces as
# a failed byte-count assertion rather than an infinite hang. The header marker on the first line
# mirrors the real caller (connect.pl reading the first 2k of a compressed ttyrec).
{
    my $flood = 'BEGIN { $| = 1 } print "HEADER_MARKER\n"; print "A" x 65536 for 1 .. 1000;';
    my $t0    = time();
    my $r     = OVH::Bastion::execute(
        cmd              => [$perl, '-e', $flood],
        max_stdout_bytes => 2000,
    );
    my $elapsed = time() - $t0;

    ok($r, "execute() returns (does not hang) when output exceeds max_stdout_bytes");
    cmp_ok($elapsed,                         '<',  20, "execute() aborts promptly instead of draining the whole flood");
    cmp_ok($r->value->{'bytesnb'}{'stdout'}, '>=', 2000,      "captured at least max_stdout_bytes before aborting");
    cmp_ok($r->value->{'bytesnb'}{'stdout'}, '<',  1_000_000, "stopped reading well before the child's full output");
    is($r->value->{'stdout'}[0], 'HEADER_MARKER', "the truncated capture preserves the start of the stream");

    # the abort path kills the child (kill_kill -> SIGKILL), so it exits on a signal, not cleanly
    ok(!defined $r->value->{'status'}, "a killed child reports no exit status (terminated by signal)");
    ok(defined $r->value->{'signal'},  "a killed child reports the terminating signal");
}

# --- is_binary passthrough: the child writes to our fds directly, bypassing the parent ----------
# In is_binary mode (without max_stdout_bytes), execute() hands our own STDOUT/STDERR to IPC::Run
# as GLOBs, which dup2()s them straight into the child: no parent-side pumping on the bulk data
# path (sftp/rsync). Swap our STDOUT for a temp file around the call to observe the passthrough
# without corrupting the TAP stream (Test::More writes to its own dup of the original STDOUT).
{
    require File::Temp;
    my ($tmpfh, $tmpfile) = File::Temp::tempfile(UNLINK => 1);

    open(my $saved_stdout, '>&', \*STDOUT) or die "can't save STDOUT: $!";
    open(STDOUT,           '>&', $tmpfh)   or die "can't redirect STDOUT: $!";
    my $r = OVH::Bastion::execute(
        cmd       => [$perl, '-e', 'print "binary-passthrough\n"; exit 4'],
        is_binary => 1,
    );
    open(STDOUT, '>&', $saved_stdout) or die "can't restore STDOUT: $!";

    ok($r, "execute() with is_binary returns a truthy result");
    is($r->err,               'OK_NON_ZERO_EXIT', "is_binary child's non-zero exit is still reported");
    is($r->value->{'status'}, 4,                  "is_binary child's real exit code is preserved");
    is_deeply($r->value->{'stdout'}, [], "is_binary mode does not capture stdout");

    my $content = do { local $/; open(my $fh, '<', $tmpfile) or die "can't read $tmpfile: $!"; <$fh> };
    is($content, "binary-passthrough\n", "child output landed directly on our (redirected) STDOUT");
}

done_testing();
