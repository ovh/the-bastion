#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;
use Test::More;
use Test::Deep;

use File::Basename;
use lib dirname(__FILE__) . '/../../../lib/perl';
use OVH::Bastion;
use OVH::Result;

# build_proxyjump_ssh_options() is the single choke point used by osh.pl, scp and
# ssh_test_access_way to build the "-o ProxyCommand=..." option for egress proxy-jump
# connections. It enforces the egressProxyJumpAllowed policy, re-validates the proxy tuple
# (defense in depth) and shell-quotes the resulting command.

OVH::Bastion::enable_mocking();

my $fnret;

#
# feature ENABLED
#
OVH::Bastion::load_configuration(mock_data => {egressProxyJumpAllowed => 1});

# nominal case, default port (22) => no '-p', extra ssh options and keys are kept in order
$fnret = OVH::Bastion::build_proxyjump_ssh_options(
    proxyIp    => '1.2.3.4',
    proxyPort  => 22,
    proxyUser  => 'puser',
    sshOptions => ['-o', 'ForwardAgent=no', '-i', '/home/k/key1'],
);
ok($fnret, "enabled: build_proxyjump_ssh_options() returns OK");
is_deeply(
    $fnret->value->{'sshArgs'},
    ['-o', q{ProxyCommand='ssh' '-o' 'ForwardAgent=no' '-i' '/home/k/key1' '-l' 'puser' '-W' '[%h]:%p' '1.2.3.4'}],
    "enabled: nominal ProxyCommand (port 22 => no -p)"
);

# non-default port => '-p <port>' is added
$fnret = OVH::Bastion::build_proxyjump_ssh_options(
    proxyIp    => '1.2.3.4',
    proxyPort  => 2222,
    proxyUser  => 'puser',
    sshOptions => ['-i', '/k'],
);
is_deeply(
    $fnret->value->{'sshArgs'},
    ['-o', q{ProxyCommand='ssh' '-i' '/k' '-p' '2222' '-l' 'puser' '-W' '[%h]:%p' '1.2.3.4'}],
    "enabled: non-default port adds '-p 2222'"
);

# a value containing a single quote (here passed through sshOptions) must be shell-escaped
# using the classic '\'' trick, so it stays a single argument once handed to /bin/sh
$fnret = OVH::Bastion::build_proxyjump_ssh_options(
    proxyIp    => '1.2.3.4',
    proxyPort  => 22,
    proxyUser  => 'puser',
    sshOptions => ['-o', q{Foo=a'b}],
);
is_deeply(
    $fnret->value->{'sshArgs'},
    ['-o', q{ProxyCommand='ssh' '-o' 'Foo=a'\''b' '-l' 'puser' '-W' '[%h]:%p' '1.2.3.4'}],
    "enabled: embedded single quote is shell-escaped"
);

# defense in depth: an invalid proxy tuple is refused even when the feature is enabled
$fnret = OVH::Bastion::build_proxyjump_ssh_options(proxyIp => '999.1.1.1', proxyPort => 22, proxyUser => 'puser');
is($fnret->err, 'KO_INVALID_PROXY_IP', "enabled: invalid proxy IP is refused");

$fnret = OVH::Bastion::build_proxyjump_ssh_options(proxyIp => '1.2.3.4', proxyPort => 70000, proxyUser => 'puser');
is($fnret->err, 'KO_INVALID_PROXY_PORT', "enabled: invalid proxy port is refused");

$fnret = OVH::Bastion::build_proxyjump_ssh_options(proxyIp => '1.2.3.4', proxyPort => 22, proxyUser => 'inva lid');
is($fnret->err, 'KO_INVALID_PROXY_USER', "enabled: invalid proxy user is refused");

#
# feature DISABLED (default): the policy is enforced before anything else, even for a valid tuple
#
OVH::Bastion::load_configuration(mock_data => {egressProxyJumpAllowed => 0});

$fnret = OVH::Bastion::build_proxyjump_ssh_options(proxyIp => '1.2.3.4', proxyPort => 22, proxyUser => 'puser');
ok(!$fnret, "disabled: build_proxyjump_ssh_options() returns KO");
is($fnret->err, 'KO_PROXYJUMP_DENIED', "disabled: err is KO_PROXYJUMP_DENIED");
like($fnret->msg, qr/disabled by policy/, "disabled: error message mentions the policy");

done_testing();
