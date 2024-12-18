#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;
use Test::More;
use Test::Deep;

use File::Basename;
use lib dirname(__FILE__) . '/../../lib/perl';
use OVH::Bastion;
use OVH::Result;
use JSON;

OVH::Bastion::enable_mocking();
OVH::Bastion::set_mock_data(
    {
        "accounts" => {
            "me" => {
                "uid"               => 99982,
                "gid"               => 99982,
                "personal_accesses" => [qw{ me@1.2.3.4 }],
                "legacy_accesses"   => [qw{ me@1.2.3.5 }],
                "guest_accesses"    => {
                    "group2" => [qw{ group1@9.9.9.9 }],
                }
            },
            "wildcard" => {
                "uid"               => 99981,
                "gid"               => 99981,
                "personal_accesses" => [qw{ 0.0.0.0/0 }],
            },
        },
        "groups" => {
            "group1" => {
                "members"  => [qw{ me }],
                "accesses" => [qw{ group1@0.0.0.0/0 }],
            },
            "group2" => {}
        },
    }
);
OVH::Bastion::load_configuration(
    mock_data => {
        ingressToEgressRules => [
            [["10.19.0.0/16", "10.15.15.0/24"], ["10.20.0.0/16"], "ALLOW-EXCLUSIVE"],
            [["192.168.42.0/24"], ["192.168.42.0/24"], "ALLOW"],
            [["192.168.0.0/16"],  ["192.168.0.0/16"],  "DENY"]
        ],
        bastionName => "mock",

        idleLockTimeout => 17,
        idleKillTimeout => 29,

        # all options below are bool, we'll test for their normalization
        enableSyslog           => 1,
        enableGlobalAccessLog  => JSON::true,
        enableAccountAccessLog => "yes",
        enableGlobalSqlLog     => 0,
        enableAccountSqlLog    => JSON::false,
        displayLastLogin       => "",
        debug                  => JSON::null,
        passwordAllowed        => "no",
        telnetAllowed          => "false",
    }
);

# TESTS
my $fnret;

$fnret = OVH::Bastion::build_ttyrec_cmdline(
    ip             => "127.0.0.1",
    port           => 7979,
    user           => "randomuser",
    account        => "bastionuser",
    uniqid         => 'cafed00dcafe',
    home           => "/home/randomuser",
    stealth_stdout => 1,
);
cmp_deeply(
    $fnret->value->{'saveFile'},
    re(
        qr{^\Q/home/randomuser/ttyrec/127.0.0.1/20\E\d\d-\d\d-\d\d.\d\d\-\d\d\-\d\d\.\d{6}\Q.cafed00dcafe.bastionuser.randomuser.127.0.0.1.7979.ttyrec\E$}
    ),
    "build_ttyrec_cmdline saveFile"
);
cmp_deeply(
    $fnret->value->{'cmd'},
    [
        'ttyrec',
        '-f',
        $fnret->value->{'saveFile'},
        '-F',
        '/home/randomuser/ttyrec/127.0.0.1/%Y-%m-%d.%H-%M-%S.#usec#.cafed00dcafe.bastionuser.randomuser.127.0.0.1.7979.ttyrec',
        '-t',
        17,
        '-s',
        "To unlock, use '--osh unlock' from another console",
        '-k',
        29,
        '--stealth-stdout',
    ],
    "build_ttyrec_cmdline cmd"
);

$fnret = OVH::Bastion::build_ttyrec_cmdline_part1of2(
    ip      => "127.0.0.1",
    port    => 7979,
    user    => "randomuser",
    account => "bastionuser",
    uniqid  => 'cafed00dcafe',
    home    => "/home/randomuser",
);
cmp_deeply(
    $fnret->value->{'saveFile'},
    re(
        qr{^\Q/home/randomuser/ttyrec/127.0.0.1/20\E\d\d-\d\d-\d\d.\d\d\-\d\d\-\d\d\.\d{6}\Q.cafed00dcafe.bastionuser.randomuser.127.0.0.1.7979.ttyrec\E$}
    ),
    "build_ttyrec_cmdline_part1of2 saveFile"
);
cmp_deeply(
    $fnret->value->{'cmd'},
    [
        'ttyrec',
        '-f',
        $fnret->value->{'saveFile'},
        '-F',
        '/home/randomuser/ttyrec/127.0.0.1/%Y-%m-%d.%H-%M-%S.#usec#.cafed00dcafe.bastionuser.randomuser.127.0.0.1.7979.ttyrec'
    ],
    "build_ttyrec_cmdline_part1of2 cmd"
);
$fnret = OVH::Bastion::build_ttyrec_cmdline_part2of2(
    input           => $fnret->value,
    idleKillTimeout => 88,
    idleLockTimeout => 99,
    stealth_stderr  => 1,
);
cmp_deeply(
    $fnret->value->{'saveFile'},
    re(
        qr{^\Q/home/randomuser/ttyrec/127.0.0.1/20\E\d\d-\d\d-\d\d.\d\d\-\d\d\-\d\d\.\d{6}\Q.cafed00dcafe.bastionuser.randomuser.127.0.0.1.7979.ttyrec\E$}
    ),
    "build_ttyrec_cmdline_part2of2 saveFile"
);
cmp_deeply(
    $fnret->value->{'cmd'},
    [
        'ttyrec',
        '-f',
        $fnret->value->{'saveFile'},
        '-F',
        '/home/randomuser/ttyrec/127.0.0.1/%Y-%m-%d.%H-%M-%S.#usec#.cafed00dcafe.bastionuser.randomuser.127.0.0.1.7979.ttyrec',
        '-t',
        99,
        '-s',
        "To unlock, use '--osh unlock' from another console",
        '-k',
        88,
        '--stealth-stderr',
    ],
    "build_ttyrec_cmdline_part2of2 cmd"
);

is(OVH::Bastion::config("bastionName")->value, "mock", "bastion name is mocked");

ok(OVH::Bastion::is_account_valid(account => "azerty")->is_ok, "is_account_valid('azerty')");

is(OVH::Bastion::is_account_valid(account => "in valid")->err, "KO_FORBIDDEN_CHARS", "is_account_valid('in valid')");

for my $suffix (qw{ tty aclkeeper gatekeeper owner }) {
    is(OVH::Bastion::is_account_valid(account => "account-$suffix")->err,
        "KO_FORBIDDEN_SUFFIX", "is_account_valid('account-$suffix')");
}

is(OVH::Bastion::is_account_valid(account => "root")->err, "KO_FORBIDDEN_NAME", "is_account_valid('root')");

ok(OVH::Bastion::is_bastion_account_valid_and_existing(account => "me")->is_ok,
    "is_bastion_account_valid_and_existing('me')");

is_deeply(
    OVH::Bastion::is_access_granted(
        account => "me",
        user    => "remote",
        ipfrom  => "1.2.3.4",
        ip      => "5.6.7.8",
        port    => "9876"
    ),
    R('KO_ACCESS_DENIED', msg => 'Access denied for me to remote@5.6.7.8:9876'),
    "is_access_granted(me) on denied machine"
);

ok(
    OVH::Bastion::is_access_granted(
        account => "me",
        user    => "me",
        ipfrom  => "1.1.1.1",
        ip      => "1.2.3.4",
        port    => "9876"
    )->is_ok,
    "is_access_granted(me) on allowed machine"
);

is(
    OVH::Bastion::is_access_granted(
        account => "wildcard",
        user    => "root",
        ipfrom  => "10.15.15.15",
        ip      => "1.2.3.4",
        port    => "9876"
    )->err,
    "KO_ACCESS_DENIED",
    "is_access_granted(wildcard) on disallowed machine due to ingressToEgressRules #1"
);

is(
    OVH::Bastion::is_access_granted(
        account => "wildcard",
        user    => "root",
        ipfrom  => "10.19.1.2",
        ip      => "1.2.3.4",
        port    => "9876"
    )->err,
    "KO_ACCESS_DENIED",
    "is_access_granted(wildcard) on disallowed machine due to ingressToEgressRules #1"
);

ok(
    OVH::Bastion::is_access_granted(
        account => "wildcard",
        user    => "root",
        ipfrom  => "10.19.1.2",
        ip      => "10.20.1.2",
        port    => "9876"
    )->is_ok,
    "is_access_granted(wildcard) on allowed machine due to ingressToEgressRules #1"
);

ok(
    OVH::Bastion::is_access_granted(
        account => "wildcard",
        user    => "root",
        ipfrom  => "192.168.42.1",
        ip      => "192.168.42.4",
        port    => "9876"
    )->is_ok,
    "is_access_granted(wildcard) on allowed machine due to ingressToEgressRules #2"
);

ok(
    OVH::Bastion::is_access_granted(
        account => "wildcard",
        user    => "root",
        ipfrom  => "192.168.42.1",
        ip      => "5.6.7.8",
        port    => "9876"
    )->is_ok,
    "is_access_granted(wildcard) on allowed machine due to ingressToEgressRules #2"
);

is(
    OVH::Bastion::is_access_granted(
        account => "wildcard",
        user    => "root",
        ipfrom  => "192.168.43.1",
        ip      => "192.168.42.4",
        port    => "9876"
    )->err,
    "KO_ACCESS_DENIED",
    "is_access_granted(wildcard) on disallowed machine due to ingressToEgressRules #3"
);

ok(
    OVH::Bastion::is_access_granted(
        account => "wildcard",
        user    => "root",
        ipfrom  => "192.168.43.1",
        ip      => "5.6.7.8",
        port    => "9876"
    )->is_ok,
    "is_access_granted(wildcard) on allowed machine due to ingressToEgressRules catch-all"
);

# check that "bool" type options are correctly normalized
is(OVH::Bastion::config("enableSyslog")->value,             1, "config bool(1)");
is(OVH::Bastion::config("enableGlobalAccessLog")->value,    1, "config bool(true)");
is(OVH::Bastion::config("enableAccountAccessLog")->value,   1, "config bool(\"yes\")");
is(OVH::Bastion::config("enableGlobalSqlLog")->value,       0, "config bool(0)");
is(OVH::Bastion::config("enableAccountSqlLog")->value,      0, "config bool(false)");
is(OVH::Bastion::config("displayLastLogin")->value,         0, "config bool(\"\")");
is(OVH::Bastion::config("interactiveModeByDefault")->value, 1, "config bool(missing, default true)");
is(OVH::Bastion::config("interactiveModeAllowed")->value,   0, "config bool(missing, default false)");
is(OVH::Bastion::config("debug")->value,                    0, "config bool(null)");
is(OVH::Bastion::config("passwordAllowed")->value,          0, "config bool(\"no\")");
is(OVH::Bastion::config("telnetAllowed")->value,            0, "config bool(\"false\")");

is(
    OVH::Bastion::plugin_config(
        plugin    => "help",
        key       => "disabled",
        mock_data => {disabled => JSON::true}
    )->value ? 1 : 0,
    1,
    "is_plugin_disabled(disabled=true)"
);
is(
    OVH::Bastion::plugin_config(
        plugin    => "help",
        key       => "disabled",
        mock_data => {disabled => JSON::false}
    )->value ? 1 : 0,
    0,
    "is_plugin_disabled(disabled=false)"
);
is(
    OVH::Bastion::plugin_config(
        plugin    => "help",
        key       => "disabled",
        mock_data => {disabled => JSON::null}
    )->value ? 1 : 0,
    0,
    "is_plugin_disabled(disabled=null)"
);
is(
    OVH::Bastion::plugin_config(
        plugin    => "help",
        key       => "disabled",
        mock_data => {disabled => "yes"}
    )->value ? 1 : 0,
    1,
    "is_plugin_disabled(disabled=\"yes\")"
);
is(
    OVH::Bastion::plugin_config(
        plugin    => "help",
        key       => "disabled",
        mock_data => {disabled => "no"}
    )->value ? 1 : 0,
    0,
    "is_plugin_disabled(disabled=\"no\")"
);
is(
    OVH::Bastion::plugin_config(
        plugin    => "help",
        key       => "disabled",
        mock_data => {disabled => "true"}
    )->value ? 1 : 0,
    1,
    "is_plugin_disabled(disabled=\"true\")"
);
is(
    OVH::Bastion::plugin_config(
        plugin    => "help",
        key       => "disabled",
        mock_data => {disabled => "false"}
    )->value ? 1 : 0,
    0,
    "is_plugin_disabled(disabled=\"false\")"
);
is(
    OVH::Bastion::plugin_config(
        plugin    => "help",
        key       => "disabled",
        mock_data => {disabled => ""}
    )->value ? 1 : 0,
    0,
    "is_plugin_disabled(disabled=\"\")"
);
is(
    OVH::Bastion::plugin_config(
        plugin    => "help",
        key       => "disabled",
        mock_data => {disabled => "0"}
    )->value ? 1 : 0,
    0,
    "is_plugin_disabled(disabled=\"0\")"
);
is(
    OVH::Bastion::plugin_config(
        plugin    => "help",
        key       => "disabled",
        mock_data => {disabled => "1"}
    )->value ? 1 : 0,
    1,
    "is_plugin_disabled(disabled=\"1\")"
);
is(
    OVH::Bastion::plugin_config(
        plugin    => "help",
        key       => "disabled",
        mock_data => {disabled => 0}
    )->value ? 1 : 0,
    0,
    "is_plugin_disabled(disabled=0)"
);
is(
    OVH::Bastion::plugin_config(
        plugin    => "help",
        key       => "disabled",
        mock_data => {disabled => 1}
    )->value ? 1 : 0,
    1,
    "is_plugin_disabled(disabled=1)"
);
is(
    OVH::Bastion::plugin_config(
        plugin    => "help",
        key       => "disabled",
        mock_data => {}
    )->value ? 1 : 0,
    0,
    "is_plugin_disabled()"
);

is(
    OVH::Bastion::build_re_from_wildcards(wildcards => ["azerty", "st*ar", "que?stion", "c*ompl?i*cated*"])->value,
    qr/^azerty$|^st.*ar$|^que.stion$|^c.*ompl.i.*cated.*$/,
    "build_re_from_wildcards() 1"
);

is(
    OVH::Bastion::build_re_from_wildcards(
        wildcards         => ["azerty", "st*ar", "que?stion", "c*ompl?i*cated*"],
        implicit_contains => 1
    )->value,
    qr/^.*azerty.*$|^st.*ar$|^que.stion$|^c.*ompl.i.*cated.*$/,
    "build_re_from_wildcards() 2"
);

# is_valid_ip

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0", allowPrefixes => 0, fast => 0),
    R(
        "OK",
        msg => ignore(),
        value =>
          {"prefix" => "1.2.0.0/32", "version" => "4", "prefixlen" => "32", "ip" => "1.2.0.0", "type" => "single",}
    ),
    "is_valid_ip(1.2.0.0,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0/0", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(1.2.0.0/0,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0/16", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(1.2.0.0/16,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0/24", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(1.2.0.0/24,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0/32", allowPrefixes => 0, fast => 0),
    R(
        "OK",
        msg => ignore(),
        value =>
          {"prefix" => "1.2.0.0/32", "version" => "4", "prefixlen" => "32", "ip" => "1.2.0.0", "type" => "single",}
    ),
    "is_valid_ip(1.2.0.0/32,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0/33", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(1.2.0.0/33,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255", allowPrefixes => 0, fast => 0),
    R(
        "OK",
        msg   => ignore(),
        value => {
            "prefix"    => "255.255.255.255/32",
            "version"   => "4",
            "prefixlen" => "32",
            "ip"        => "255.255.255.255",
            "type"      => "single",
        }
    ),
    "is_valid_ip(255.255.255.255,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255/0", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(255.255.255.255/0,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255/16", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(255.255.255.255/16,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255/24", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(255.255.255.255/24,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255/32", allowPrefixes => 0, fast => 0),
    R(
        "OK",
        msg   => ignore(),
        value => {
            "prefix"    => "255.255.255.255/32",
            "version"   => "4",
            "prefixlen" => "32",
            "ip"        => "255.255.255.255",
            "type"      => "single",
        }
    ),
    "is_valid_ip(255.255.255.255/32,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255/33", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(255.255.255.255/33,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0/0", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0/0,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0/16", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0/16,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0/24", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0/24,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0/32", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0/32,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0/33", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0/33,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0", allowPrefixes => 0, fast => 0),
    R(
        "OK",
        msg => ignore(),
        value =>
          {"prefix" => "4.5.6.0/32", "version" => "4", "prefixlen" => "32", "ip" => "4.5.6.0", "type" => "single",}
    ),
    "is_valid_ip(4.5.6.0,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0/0", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(4.5.6.0/0,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0/16", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(4.5.6.0/16,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0/24", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(4.5.6.0/24,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0/32", allowPrefixes => 0, fast => 0),
    R(
        "OK",
        msg => ignore(),
        value =>
          {"prefix" => "4.5.6.0/32", "version" => "4", "prefixlen" => "32", "ip" => "4.5.6.0", "type" => "single",}
    ),
    "is_valid_ip(4.5.6.0/32,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0/33", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(4.5.6.0/33,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0", allowPrefixes => 0, fast => 0),
    R(
        "OK",
        msg   => ignore(),
        value => {
            "prefix"    => "0000:0000:0000:0000:0000:feef:0000:0000/128",
            "version"   => "6",
            "prefixlen" => "128",
            "ip"        => "::feef:0:0",
            "type"      => "single",
        }
    ),
    "is_valid_ip(::feef:0:0,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0/0", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(::feef:0:0/0,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0/16", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(::feef:0:0/16,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0/24", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(::feef:0:0/24,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0/32", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(::feef:0:0/32,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0/33", allowPrefixes => 0, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(::feef:0:0/33,fast=0,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0", allowPrefixes => 1, fast => 0),
    R(
        "OK",
        msg => ignore(),
        value =>
          {"prefix" => "1.2.0.0/32", "version" => "4", "prefixlen" => "32", "ip" => "1.2.0.0", "type" => "single",}
    ),
    "is_valid_ip(1.2.0.0,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0/0", allowPrefixes => 1, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(1.2.0.0/0,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0/16", allowPrefixes => 1, fast => 0),
    R(
        "OK",
        msg => ignore(),
        value =>
          {"prefix" => "1.2.0.0/16", "version" => "4", "prefixlen" => "16", "ip" => "1.2.0.0/16", "type" => "prefix",}
    ),
    "is_valid_ip(1.2.0.0/16,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0/24", allowPrefixes => 1, fast => 0),
    R(
        "OK",
        msg => ignore(),
        value =>
          {"prefix" => "1.2.0.0/24", "version" => "4", "prefixlen" => "24", "ip" => "1.2.0.0/24", "type" => "prefix",}
    ),
    "is_valid_ip(1.2.0.0/24,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0/32", allowPrefixes => 1, fast => 0),
    R(
        "OK",
        msg => ignore(),
        value =>
          {"prefix" => "1.2.0.0/32", "version" => "4", "prefixlen" => "32", "ip" => "1.2.0.0", "type" => "single",}
    ),
    "is_valid_ip(1.2.0.0/32,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0/33", allowPrefixes => 1, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(1.2.0.0/33,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255", allowPrefixes => 1, fast => 0),
    R(
        "OK",
        msg   => ignore(),
        value => {
            "prefix"    => "255.255.255.255/32",
            "version"   => "4",
            "prefixlen" => "32",
            "ip"        => "255.255.255.255",
            "type"      => "single",
        }
    ),
    "is_valid_ip(255.255.255.255,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255/0", allowPrefixes => 1, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(255.255.255.255/0,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255/16", allowPrefixes => 1, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(255.255.255.255/16,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255/24", allowPrefixes => 1, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(255.255.255.255/24,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255/32", allowPrefixes => 1, fast => 0),
    R(
        "OK",
        msg   => ignore(),
        value => {
            "prefix"    => "255.255.255.255/32",
            "version"   => "4",
            "prefixlen" => "32",
            "ip"        => "255.255.255.255",
            "type"      => "single",
        }
    ),
    "is_valid_ip(255.255.255.255/32,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255/33", allowPrefixes => 1, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(255.255.255.255/33,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0", allowPrefixes => 1, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0/0", allowPrefixes => 1, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0/0,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0/16", allowPrefixes => 1, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0/16,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0/24", allowPrefixes => 1, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0/24,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0/32", allowPrefixes => 1, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0/32,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0/33", allowPrefixes => 1, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0/33,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0", allowPrefixes => 1, fast => 0),
    R(
        "OK",
        msg => ignore(),
        value =>
          {"prefix" => "4.5.6.0/32", "version" => "4", "prefixlen" => "32", "ip" => "4.5.6.0", "type" => "single",}
    ),
    "is_valid_ip(4.5.6.0,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0/0", allowPrefixes => 1, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(4.5.6.0/0,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0/16", allowPrefixes => 1, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(4.5.6.0/16,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0/24", allowPrefixes => 1, fast => 0),
    R(
        "OK",
        msg => ignore(),
        value =>
          {"prefix" => "4.5.6.0/24", "version" => "4", "prefixlen" => "24", "ip" => "4.5.6.0/24", "type" => "prefix",}
    ),
    "is_valid_ip(4.5.6.0/24,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0/32", allowPrefixes => 1, fast => 0),
    R(
        "OK",
        msg => ignore(),
        value =>
          {"prefix" => "4.5.6.0/32", "version" => "4", "prefixlen" => "32", "ip" => "4.5.6.0", "type" => "single",}
    ),
    "is_valid_ip(4.5.6.0/32,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0/33", allowPrefixes => 1, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(4.5.6.0/33,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0", allowPrefixes => 1, fast => 0),
    R(
        "OK",
        msg   => ignore(),
        value => {
            "prefix"    => "0000:0000:0000:0000:0000:feef:0000:0000/128",
            "version"   => "6",
            "prefixlen" => "128",
            "ip"        => "::feef:0:0",
            "type"      => "single",
        }
    ),
    "is_valid_ip(::feef:0:0,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0/0", allowPrefixes => 1, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(::feef:0:0/0,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0/16", allowPrefixes => 1, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(::feef:0:0/16,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0/24", allowPrefixes => 1, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(::feef:0:0/24,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0/32", allowPrefixes => 1, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(::feef:0:0/32,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0/33", allowPrefixes => 1, fast => 0),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(::feef:0:0/33,fast=0,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0", allowPrefixes => 0, fast => 1),
    R("OK", msg => ignore(), value => {"ip" => "1.2.0.0",}),
    "is_valid_ip(1.2.0.0,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0/0", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(1.2.0.0/0,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0/16", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(1.2.0.0/16,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0/24", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(1.2.0.0/24,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0/32", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(1.2.0.0/32,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0/33", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(1.2.0.0/33,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255", allowPrefixes => 0, fast => 1),
    R("OK", msg => ignore(), value => {"ip" => "255.255.255.255",}),
    "is_valid_ip(255.255.255.255,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255/0", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(255.255.255.255/0,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255/16", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(255.255.255.255/16,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255/24", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(255.255.255.255/24,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255/32", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(255.255.255.255/32,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255/33", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(255.255.255.255/33,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0/0", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0/0,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0/16", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0/16,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0/24", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0/24,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0/32", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0/32,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0/33", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0/33,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0", allowPrefixes => 0, fast => 1),
    R("OK", msg => ignore(), value => {"ip" => "4.5.6.0",}),
    "is_valid_ip(4.5.6.0,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0/0", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(4.5.6.0/0,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0/16", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(4.5.6.0/16,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0/24", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(4.5.6.0/24,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0/32", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(4.5.6.0/32,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0/33", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(4.5.6.0/33,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0", allowPrefixes => 0, fast => 1),
    R(
        "OK",
        msg   => ignore(),
        value => {
            "prefix"    => "0000:0000:0000:0000:0000:feef:0000:0000/128",
            "version"   => "6",
            "prefixlen" => "128",
            "ip"        => "::feef:0:0",
            "type"      => "single",
        }
    ),
    "is_valid_ip(::feef:0:0,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0/0", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(::feef:0:0/0,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0/16", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(::feef:0:0/16,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0/24", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(::feef:0:0/24,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0/32", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(::feef:0:0/32,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0/33", allowPrefixes => 0, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(::feef:0:0/33,fast=1,pfx=0)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0", allowPrefixes => 1, fast => 1),
    R("OK", msg => ignore(), value => {"ip" => "1.2.0.0",}),
    "is_valid_ip(1.2.0.0,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0/0", allowPrefixes => 1, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(1.2.0.0/0,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0/16", allowPrefixes => 1, fast => 1),
    R("OK", msg => ignore(), value => {"prefix" => "16", "ip" => "1.2.0.0/16",}),
    "is_valid_ip(1.2.0.0/16,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0/24", allowPrefixes => 1, fast => 1),
    R("OK", msg => ignore(), value => {"prefix" => "24", "ip" => "1.2.0.0/24",}),
    "is_valid_ip(1.2.0.0/24,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0/32", allowPrefixes => 1, fast => 1),
    R("OK", msg => ignore(), value => {"ip" => "1.2.0.0"}),
    "is_valid_ip(1.2.0.0/32,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "1.2.0.0/33", allowPrefixes => 1, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(1.2.0.0/33,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255", allowPrefixes => 1, fast => 1),
    R("OK", msg => ignore(), value => {"ip" => "255.255.255.255",}),
    "is_valid_ip(255.255.255.255,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255/0", allowPrefixes => 1, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(255.255.255.255/0,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255/16", allowPrefixes => 1, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(255.255.255.255/16,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255/24", allowPrefixes => 1, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(255.255.255.255/24,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255/32", allowPrefixes => 1, fast => 1),
    R("OK", msg => ignore(), value => {"ip" => "255.255.255.255",}),
    "is_valid_ip(255.255.255.255/32,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "255.255.255.255/33", allowPrefixes => 1, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(255.255.255.255/33,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0", allowPrefixes => 1, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0/0", allowPrefixes => 1, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0/0,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0/16", allowPrefixes => 1, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0/16,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0/24", allowPrefixes => 1, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0/24,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0/32", allowPrefixes => 1, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0/32,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "256.0.0.0/33", allowPrefixes => 1, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(256.0.0.0/33,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0", allowPrefixes => 1, fast => 1),
    R("OK", msg => ignore(), value => {"ip" => "4.5.6.0",}),
    "is_valid_ip(4.5.6.0,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0/0", allowPrefixes => 1, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(4.5.6.0/0,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0/16", allowPrefixes => 1, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(4.5.6.0/16,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0/24", allowPrefixes => 1, fast => 1),
    R("OK", msg => ignore(), value => {"prefix" => "24", "ip" => "4.5.6.0/24",}),
    "is_valid_ip(4.5.6.0/24,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0", allowPrefixes => 1, fast => 1),
    R("OK", msg => ignore(), value => {"ip" => "4.5.6.0",}),
    "is_valid_ip(4.5.6.0/32,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "4.5.6.0/33", allowPrefixes => 1, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(4.5.6.0/33,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0", allowPrefixes => 1, fast => 1),
    R(
        "OK",
        msg   => ignore(),
        value => {
            "prefix"    => "0000:0000:0000:0000:0000:feef:0000:0000/128",
            "version"   => "6",
            "prefixlen" => "128",
            "ip"        => "::feef:0:0",
            "type"      => "single",
        }
    ),
    "is_valid_ip(::feef:0:0,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0/0", allowPrefixes => 1, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(::feef:0:0/0,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0/16", allowPrefixes => 1, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(::feef:0:0/16,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0/24", allowPrefixes => 1, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(::feef:0:0/24,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0/32", allowPrefixes => 1, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(::feef:0:0/32,fast=1,pfx=1)"
);

cmp_deeply(
    OVH::Bastion::is_valid_ip(ip => "::feef:0:0/33", allowPrefixes => 1, fast => 1),
    R("KO_INVALID_IP", msg => ignore(), value => undef),
    "is_valid_ip(::feef:0:0/33,fast=1,pfx=1)"
);

done_testing();
