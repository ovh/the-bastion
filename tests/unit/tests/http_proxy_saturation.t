#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;
use File::Basename;
use Test::More;

use lib dirname(__FILE__) . '/../../../lib/perl';
use OVH::Bastion::ProxyHTTP;

my $now = 100;
my @logs;
my $server = OVH::Bastion::ProxyHTTP->new();
$server->{'server'} = {
    max_servers  => 2,
    children     => {1 => {status => "waiting"}, 2 => {status => "waiting"}},
    log_level    => 2,
    log_function => sub { push @logs, $_[1]; return; },
};

# Control elapsed time without sleeping, and model housekeeping separately from
# status delivery so that a peak immediately followed by a reaped child is exercised.
local *Time::HiRes::clock_gettime = sub { return $now; };
my $reap = 0;
local *Net::Server::HTTP::coordinate_children = sub {
    my $self = shift;
    delete $self->{'server'}{'children'}{2} if $reap;
    return;
};

sub set_busy {
    my ($busy) = @_;
    foreach my $pid (1 .. 2) {
        $server->{'server'}{'children'}{$pid} = {status => $pid <= $busy ? 'processing' : 'waiting'};
    }
    return;
}

$server->coordinate_children();
is(scalar @logs, 0, 'a pool at its process limit with idle workers is not saturated');
set_busy(1);
$server->coordinate_children();
is(scalar @logs, 0, 'below full utilization stays quiet');
set_busy(2);
$server->coordinate_children();
is(scalar @logs, 1, 'entering saturation logs once');
like(
    $logs[0],
    qr/full capacity: 2\/2 workers occupied; new connections may have to wait/,
    'warning describes capacity, not proven queuing'
);

$now = 105;
$server->coordinate_children();
is(scalar @logs, 1, 'no duplicate warning while saturated');
set_busy(1);
$server->coordinate_children();
like(
    $logs[1],
    qr/below full capacity: 1\/2 workers occupied; saturation lasted 5\.000 seconds/,
    'recovery includes elapsed duration'
);
$server->coordinate_children();
is(scalar @logs, 2, 'recovery logs only once');

$now = 110;
set_busy(2);
$server->coordinate_children();
set_busy(1);
$server->coordinate_children();
is(scalar @logs, 2, 'brief repeated episodes and their recovery are rate limited');

$now = 120;
set_busy(2);
$server->coordinate_children();
$now = 159;
$server->coordinate_children();
is(scalar @logs, 2, 'an ongoing episode respects the warning cooldown');
$now = 160;
$server->coordinate_children();
is(scalar @logs, 3, 'an ongoing episode is reported once the cooldown expires');
$now  = 165;
$reap = 1;
$server->coordinate_children();
$reap = 0;
like(
    $logs[3],
    qr/saturation lasted 45\.000 seconds/,
    'reaping ends saturation and duration includes the suppressed period'
);

$now = 220;
set_busy(2);
$reap = 1;
$server->coordinate_children();
$reap = 0;
is(scalar @logs, 6, 'a peak followed immediately by reaping still logs saturation and recovery');
like($logs[5], qr/saturation lasted 0\.000 seconds/, 'a short episode is retained');

$now = 280;
$server->{'server'}{'max_servers'} = 1;
$server->coordinate_children();
like($logs[6], qr/full capacity: 1\/1 workers occupied/, 'uses the current worker limit');
$server->{'server'}{'max_servers'} = 3;
$server->coordinate_children();
like($logs[7], qr/below full capacity: 1\/3 workers occupied/, 'increasing capacity ends saturation');

# Re-exec creates a fresh monitor while Net::Server restores old children marked 'hup'.
# Keep the same logging sink, but none of the old monitor's duration/cooldown state.
my $config = $server->{'server'};
$server                  = OVH::Bastion::ProxyHTTP->new();
$server->{'server'}      = $config;
$config->{'max_servers'} = 2;
set_busy(0);
$config->{'children'}{11} = {status => 'processing', hup => 1};
$config->{'children'}{12} = {status => 'processing', hup => 1};
$config->{'children'}{13} = {status => 'waiting',    hup => 1};
$server->coordinate_children();
is(scalar @logs, 8, 'reload with two old busy workers and new idle workers does not warn');
set_busy(1);
$server->coordinate_children();
is(scalar @logs, 8, 'old busy workers do not push a partially used new pool over the limit');
set_busy(2);
$server->coordinate_children();
is(scalar @logs, 9, 'the new pool can report real saturation immediately after reload');
like($logs[8], qr/full capacity: 2\/2 workers occupied/, 'warning counts only new workers');
$now += 3;
set_busy(1);
$server->coordinate_children();
like(
    $logs[9],
    qr/below full capacity: 1\/2 workers occupied; saturation lasted 3\.000 seconds/,
    'recovery counts and duration start afresh after reload'
);

# Even with a temporarily oversized pool, available workers must prevent a warning.
$now += 60;
set_busy(2);
$config->{'children'}{3} = {status => 'waiting'};
$server->coordinate_children();
is(scalar @logs, 10, 'no saturation warning when an extra current worker is idle');
delete $config->{'children'}{3};
$config->{'max_servers'} = 0;
$server->coordinate_children();
is(scalar @logs, 10, 'graceful shutdown does not report saturation against a zero limit');

done_testing();
