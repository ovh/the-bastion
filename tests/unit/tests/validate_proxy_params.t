#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;
use Test::More;
use Test::Deep;

use File::Basename;
use lib dirname(__FILE__) . '/../../../lib/perl';
use OVH::Bastion;
use OVH::Result;

# validate_proxy_params() is the single place that both parses the "-J [user@]host[:port]" proxy-jump
# spec (used by osh.pl and the scp plugin) AND validates an already-split proxy tuple (used by the ACL
# plugins via --proxy-host/--proxy-port/--proxy-user). These tests pin both behaviors. We use literal
# IPs only, so the host resolution stays in is_valid_ip() and we don't depend on DNS.

OVH::Bastion::enable_mocking();
OVH::Bastion::load_configuration(mock_data => {});

my $fnret;

#
# proxyJump spec-parsing mode
#

# a malformed spec is rejected with a dedicated error code
$fnret = OVH::Bastion::validate_proxy_params(proxyJump => 'bad spec', allowWildcards => 0);
is($fnret->err, 'ERR_INVALID_PROXYJUMP', "spec: malformed spec is rejected");

# a trailing non-numeric port doesn't match the grammar either
$fnret = OVH::Bastion::validate_proxy_params(proxyJump => 'host:nope', allowWildcards => 0);
is($fnret->err, 'ERR_INVALID_PROXYJUMP', "spec: non-numeric port is rejected");

# bare IPv4, no user, no port: port/user come back undef so callers can apply their own defaults
$fnret = OVH::Bastion::validate_proxy_params(proxyJump => '10.0.0.1', allowWildcards => 0);
ok($fnret, "spec: bare IPv4 is accepted");
is_deeply(
    $fnret->value,
    {proxyIp => '10.0.0.1', proxyPort => undef, proxyUser => undef},
    "spec: bare IPv4 leaves port/user undef"
);

# full user@ipv4:port
$fnret = OVH::Bastion::validate_proxy_params(proxyJump => 'puser@10.0.0.1:2222', allowWildcards => 0);
is_deeply(
    $fnret->value,
    {proxyIp => '10.0.0.1', proxyPort => 2222, proxyUser => 'puser'},
    "spec: user\@ipv4:port is fully parsed"
);

# a bracketed IPv6 literal: the brackets must be stripped so downstream gets a bare IP
$fnret = OVH::Bastion::validate_proxy_params(proxyJump => '[2001:db8::1]:22', allowWildcards => 0);
is_deeply(
    $fnret->value,
    {proxyIp => '2001:db8::1', proxyPort => 22, proxyUser => undef},
    "spec: bracketed IPv6 is stripped, port parsed"
);

# user@[ipv6] without a port
$fnret = OVH::Bastion::validate_proxy_params(proxyJump => 'puser@[2001:db8::1]', allowWildcards => 0);
is_deeply(
    $fnret->value,
    {proxyIp => '2001:db8::1', proxyPort => undef, proxyUser => 'puser'},
    "spec: user\@[ipv6] is parsed, brackets stripped"
);

# out-of-range port (literal IP, so we reach the port validation) is rejected
$fnret = OVH::Bastion::validate_proxy_params(proxyJump => '10.0.0.1:99999', allowWildcards => 0);
is($fnret->err, 'ERR_INVALID_PARAMETER', "spec: out-of-range port is rejected");

#
# split-param mode (the ACL plugins): adding proxyJump support must not change it
#

# nominal split tuple
$fnret = OVH::Bastion::validate_proxy_params(proxyHost => '10.0.0.2', proxyPort => 22, proxyUser => 'puser');
is_deeply(
    $fnret->value,
    {proxyIp => '10.0.0.2', proxyPort => 22, proxyUser => 'puser'},
    "split: nominal tuple validates"
);

# a wildcard proxy-user is allowed when allowWildcards is on (the default)
$fnret = OVH::Bastion::validate_proxy_params(proxyHost => '10.0.0.2', proxyPort => 22, proxyUser => '*');
ok($fnret, "split: wildcard user accepted with allowWildcards on (default)");
is($fnret->value->{proxyUser}, '*', "split: wildcard user returned verbatim");

# ... but refused when allowWildcards is off
$fnret =
  OVH::Bastion::validate_proxy_params(proxyHost => '10.0.0.2', proxyPort => 22, proxyUser => '*', allowWildcards => 0);
is($fnret->err, 'ERR_INVALID_PARAMETER', "split: wildcard user refused with allowWildcards off");

done_testing();
