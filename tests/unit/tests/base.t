#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;
use Test::More;
use Test::Deep;

use File::Basename;
use lib dirname(__FILE__) . '/../../../lib/perl';
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
            [["10.19.0.0/16", "10.15.15.0/24"], ["10.20.0.0/16"],    "ALLOW-EXCLUSIVE"],
            [["192.168.42.0/24"],               ["192.168.42.0/24"], "ALLOW"],
            [["192.168.0.0/16"],                ["192.168.0.0/16"],  "DENY"]
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

# Test ttyrec with proxy parameters
$fnret = OVH::Bastion::build_ttyrec_cmdline_part1of2(
    ip        => "192.168.1.100",
    port      => 22,
    user      => "targetuser",
    account   => "bastionuser",
    uniqid    => 'cafed00dcafe',
    home      => "/home/randomuser",
    proxyIp   => "10.0.0.1",
    proxyPort => 2222,
    proxyUser => "jumpi",
);
cmp_deeply(
    $fnret->value->{'saveFile'},
    re(
        qr{^\Q/home/randomuser/ttyrec/via-10.0.0.1-192.168.1.100/20\E\d\d-\d\d-\d\d.\d\d\-\d\d\-\d\d\.\d{6}\Q.cafed00dcafe.bastionuser.targetuser.192.168.1.100.22.ttyrec\E$}
    ),
    "build_ttyrec_cmdline_part1of2 with proxy saveFile"
);
cmp_deeply(
    $fnret->value->{'cmd'},
    [
        'ttyrec',
        '-f',
        $fnret->value->{'saveFile'},
        '-F',
        '/home/randomuser/ttyrec/via-10.0.0.1-192.168.1.100/%Y-%m-%d.%H-%M-%S.#usec#.cafed00dcafe.bastionuser.targetuser.192.168.1.100.22.ttyrec'
    ],
    "build_ttyrec_cmdline_part1of2 with proxy cmd"
);

# Test ttyrec with IPv6 proxy
$fnret = OVH::Bastion::build_ttyrec_cmdline_part1of2(
    ip        => "192.168.1.200",
    port      => 22,
    user      => "targetuser",
    account   => "bastionuser",
    uniqid    => 'cafed00dcafe',
    home      => "/home/randomuser",
    proxyIp   => "2001:db8::1",
    proxyPort => 22,
    proxyUser => "jumpi",
);
cmp_deeply(
    $fnret->value->{'saveFile'},
    re(
        qr{^\Q/home/randomuser/ttyrec/via-v6[2001.db8..1]-192.168.1.200/20\E\d\d-\d\d-\d\d.\d\d\-\d\d\-\d\d\.\d{6}\Q.cafed00dcafe.bastionuser.targetuser.192.168.1.200.22.ttyrec\E$}
    ),
    "build_ttyrec_cmdline_part1of2 with IPv6 proxy saveFile"
);
cmp_deeply(
    $fnret->value->{'cmd'},
    [
        'ttyrec',
        '-f',
        $fnret->value->{'saveFile'},
        '-F',
        '/home/randomuser/ttyrec/via-v6[2001.db8..1]-192.168.1.200/%Y-%m-%d.%H-%M-%S.#usec#.cafed00dcafe.bastionuser.targetuser.192.168.1.200.22.ttyrec'
    ],
    "build_ttyrec_cmdline_part1of2 with IPv6 proxy cmd"
);

# osh plugin/command session: 'ip' is the command name and port/user are 0 (there's no real egress
# target, see osh.pl). Those zero values are valid and must still be substituted into the path: a
# falsy-but-defined parameter must NOT be treated as missing.
$fnret = OVH::Bastion::build_ttyrec_cmdline_part1of2(
    ip      => "groupCreate",
    port    => 0,
    user    => 0,
    account => "bastionuser",
    uniqid  => 'cafed00dcafe',
    home    => "/home/randomuser",
);
cmp_deeply(
    $fnret->value->{'cmd'},
    [
        'ttyrec',
        '-f',
        $fnret->value->{'saveFile'},
        '-F',
        '/home/randomuser/ttyrec/groupCreate/%Y-%m-%d.%H-%M-%S.#usec#.cafed00dcafe.bastionuser.0.groupCreate.0.ttyrec'
    ],
    "build_ttyrec_cmdline_part1of2 plugin session (port/user = 0)"
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

# The proxy hop must be subject to the SAME ingressToEgressRules as the target: each hop is checked
# independently, so a proxy outside the allowed egress is refused even if the target is allowed.
$fnret = OVH::Bastion::is_access_granted(
    account   => "wildcard",
    user      => "root",
    ipfrom    => "10.19.1.2",
    ip        => "10.20.1.2",    # target IS in the ALLOW-EXCLUSIVE egress net
    port      => "9876",
    proxyIp   => "1.2.3.4",      # but the proxy is NOT
    proxyPort => 22,
    proxyUser => "root",
);
is($fnret->err, "KO_ACCESS_DENIED", "ingressToEgressRules: proxy outside the exclusive egress is denied");
like(
    $fnret->msg,
    qr/via proxy 1\.2\.3\.4, as the proxy is not part of the allowed networks/,
    "ingressToEgressRules: denial message points at the proxy"
);

# a proxy caught by a DENY rule is refused too (the target alone would be allowed by the catch-all)
$fnret = OVH::Bastion::is_access_granted(
    account   => "wildcard",
    user      => "root",
    ipfrom    => "192.168.43.1",
    ip        => "5.6.7.8",
    port      => "9876",
    proxyIp   => "192.168.42.4",    # in the DENY egress net 192.168.0.0/16
    proxyPort => 22,
    proxyUser => "root",
);
is($fnret->err, "KO_ACCESS_DENIED", "ingressToEgressRules: proxy matching a DENY rule is denied");
like($fnret->msg, qr/via proxy 192\.168\.42\.4/, "ingressToEgressRules: DENY denial points at the proxy");

# when BOTH target and proxy are within the exclusive egress, the network filter passes (the access
# is then only refused by the regular ACL check, not by the network policy)
$fnret = OVH::Bastion::is_access_granted(
    account   => "wildcard",
    user      => "root",
    ipfrom    => "10.19.1.2",
    ip        => "10.20.1.2",
    port      => "9876",
    proxyIp   => "10.20.5.5",    # both target and proxy in 10.20.0.0/16
    proxyPort => 22,
    proxyUser => "root",
);
unlike(
    $fnret->msg // '',
    qr/not part of the allowed networks/,
    "ingressToEgressRules: proxy inside the exclusive egress passes the network filter"
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

# ttyrecDirectPathFormat / ttyrecViaPathFormat

# a custom direct path format: full path with &home, &account, &ip, &port and a filename
OVH::Bastion::load_configuration(
    mock_data => {
        bastionName            => 'mock',
        ttyrecDirectPathFormat => '&home/rec/&account/&ip-&port/%Y.#usec#.&uniqid.&user.ttyrec',
    }
);
$fnret = OVH::Bastion::build_ttyrec_cmdline_part1of2(
    ip      => "203.0.113.5",
    port    => 2222,
    user    => "alice",
    account => "bob",
    uniqid  => 'deadbeef',
    home    => "/home/bob",
);
cmp_deeply(
    $fnret->value->{'saveFile'},
    re(qr{^\Q/home/bob/rec/bob/203.0.113.5-2222/20\E\d\d\Q.\E\d{6}\Q.deadbeef.alice.ttyrec\E$}),
    "ttyrecDirectPathFormat: custom path saveFile"
);
is(
    $fnret->value->{'cmd'}[4],
    '/home/bob/rec/bob/203.0.113.5-2222/%Y.#usec#.deadbeef.alice.ttyrec',
    "ttyrecDirectPathFormat: custom path -F format"
);

# a custom via path format: proxy tokens are available, and only the via format is consulted for proxy connections
OVH::Bastion::load_configuration(
    mock_data => {
        bastionName         => 'mock',
        ttyrecViaPathFormat => '&home/rec/via-&proxyuser-at-&proxyip-&proxyport/&ip/%Y.#usec#.&uniqid.ttyrec',
    }
);
$fnret = OVH::Bastion::build_ttyrec_cmdline_part1of2(
    ip        => "203.0.113.5",
    port      => 22,
    user      => "alice",
    account   => "bob",
    uniqid    => 'deadbeef',
    home      => "/home/bob",
    proxyIp   => "198.51.100.9",
    proxyPort => 2222,
    proxyUser => "jump",
);
is(
    $fnret->value->{'cmd'}[4],
    '/home/bob/rec/via-jump-at-198.51.100.9-2222/203.0.113.5/%Y.#usec#.deadbeef.ttyrec',
    "ttyrecViaPathFormat: custom path with proxy tokens"
);

# realm account, fallback layout: the &remoteaccount subfolder is inserted
OVH::Bastion::load_configuration(mock_data => {bastionName => 'mock'});
$fnret = OVH::Bastion::build_ttyrec_cmdline_part1of2(
    ip            => "203.0.113.5",
    port          => 22,
    user          => "alice",
    account       => "realm_foo",
    uniqid        => 'deadbeef',
    home          => "/home/realm_foo",
    realm         => "foo",
    remoteaccount => "bob",
);
cmp_deeply(
    $fnret->value->{'saveFile'},
    re(qr{^\Q/home/realm_foo/ttyrec/bob/203.0.113.5/20\E\d\d.*\Q.deadbeef.realm_foo.alice.203.0.113.5.22.ttyrec\E$}),
    "fallback realm account: &remoteaccount subfolder is present"
);

# a path format that tries to climb out of the tree must be refused
OVH::Bastion::load_configuration(
    mock_data => {bastionName => 'mock', ttyrecDirectPathFormat => '&home/../../etc/&ip/x'});
$fnret = OVH::Bastion::build_ttyrec_cmdline_part1of2(
    ip      => "1.2.3.4",
    port    => 22,
    user    => "u",
    account => "a",
    uniqid  => 'x',
    home    => "/home/u",
);
is($fnret->err, 'ERR_SECURITY_VIOLATION', "ttyrec path with '..' is refused");

# full matrix: {only Direct, only Via, both, neither} x {direct conn, via conn}
# each of ttyrecDirectPathFormat and ttyrecViaPathFormat falls back independently to the legacy
# layout (built from ttyrecFilenameFormat) when its own value is empty. We verify every cell.

# returns the ttyrec '-F' format (i.e. the resolved path template, before strftime expansion)
sub _ttyrec_F {
    my %extra = @_;
    my $r     = OVH::Bastion::build_ttyrec_cmdline_part1of2(
        ip      => "203.0.113.5",
        port    => 22,
        user    => "alice",
        account => "bob",
        uniqid  => 'deadbeef',
        home    => "/home/bob",
        %extra,
    );
    return $r ? $r->value->{'cmd'}[4] : "ERR:" . $r->err;
}

my $DIRECT_FMT = '&home/D/&account/&ip-&port/%Y.#usec#.&uniqid.&user.ttyrec';
my $VIA_FMT    = '&home/V/&proxyuser-&proxyip-&proxyport/&ip/%Y.#usec#.&uniqid.ttyrec';
my %VIA_CONN   = (proxyIp => "198.51.100.9", proxyPort => 2222, proxyUser => "jump");

my $DIRECT_CUSTOM   = '/home/bob/D/bob/203.0.113.5-22/%Y.#usec#.deadbeef.alice.ttyrec';
my $VIA_CUSTOM      = '/home/bob/V/jump-198.51.100.9-2222/203.0.113.5/%Y.#usec#.deadbeef.ttyrec';
my $DIRECT_FALLBACK = '/home/bob/ttyrec/203.0.113.5/%Y-%m-%d.%H-%M-%S.#usec#.deadbeef.bob.alice.203.0.113.5.22.ttyrec';
my $VIA_FALLBACK =
  '/home/bob/ttyrec/via-198.51.100.9-203.0.113.5/%Y-%m-%d.%H-%M-%S.#usec#.deadbeef.bob.alice.203.0.113.5.22.ttyrec';

# only ttyrecDirectPathFormat defined
OVH::Bastion::load_configuration(mock_data => {bastionName => 'mock', ttyrecDirectPathFormat => $DIRECT_FMT});
is(_ttyrec_F(),          $DIRECT_CUSTOM, "only Direct defined: direct conn uses ttyrecDirectPathFormat");
is(_ttyrec_F(%VIA_CONN), $VIA_FALLBACK,  "only Direct defined: via conn falls back (ttyrecViaPathFormat empty)");

# only ttyrecViaPathFormat defined
OVH::Bastion::load_configuration(mock_data => {bastionName => 'mock', ttyrecViaPathFormat => $VIA_FMT});
is(_ttyrec_F(),          $DIRECT_FALLBACK, "only Via defined: direct conn falls back (ttyrecDirectPathFormat empty)");
is(_ttyrec_F(%VIA_CONN), $VIA_CUSTOM,      "only Via defined: via conn uses ttyrecViaPathFormat");

# both defined
OVH::Bastion::load_configuration(
    mock_data => {bastionName => 'mock', ttyrecDirectPathFormat => $DIRECT_FMT, ttyrecViaPathFormat => $VIA_FMT});
is(_ttyrec_F(),          $DIRECT_CUSTOM, "both defined: direct conn uses ttyrecDirectPathFormat");
is(_ttyrec_F(%VIA_CONN), $VIA_CUSTOM,    "both defined: via conn uses ttyrecViaPathFormat");

# neither defined (fallback for both)
OVH::Bastion::load_configuration(mock_data => {bastionName => 'mock'});
is(_ttyrec_F(),          $DIRECT_FALLBACK, "neither defined: direct conn uses fallback layout");
is(_ttyrec_F(%VIA_CONN), $VIA_FALLBACK,    "neither defined: via conn uses fallback layout");

# &home and &remoteaccount are usable in ttyrecFilenameFormat too: the substitution is applied to
# the whole resolved path, so these tokens are not restricted to the new path-format options.
OVH::Bastion::load_configuration(
    mock_data => {bastionName => 'mock', ttyrecFilenameFormat => '&uniqid.&remoteaccount.&user.&ip.&port.ttyrec'});
is(
    _ttyrec_F(account => "realm_foo", home => "/home/realm_foo", realm => "foo", remoteaccount => "bob"),
    '/home/realm_foo/ttyrec/bob/203.0.113.5/deadbeef.bob.alice.203.0.113.5.22.ttyrec',
    "&remoteaccount is usable inside ttyrecFilenameFormat"
);
OVH::Bastion::load_configuration(mock_data => {bastionName => 'mock', ttyrecFilenameFormat => '&home.&uniqid.ttyrec'});
is(_ttyrec_F(), '/home/bob/ttyrec/203.0.113.5/home/bob.deadbeef.ttyrec', "&home is usable inside ttyrecFilenameFormat");

# pre-proxyjump directory-layout regression: the &remoteaccount subfolder must be inserted IFF both 'realm'
# and 'remoteaccount' are passed (matching the pre-proxyjump 'if ($realm && $remoteaccount)' behavior).
OVH::Bastion::load_configuration(mock_data => {bastionName => 'mock'});
my $WITH_REMACCT =
  '/home/bob/ttyrec/remacct/203.0.113.5/%Y-%m-%d.%H-%M-%S.#usec#.deadbeef.bob.alice.203.0.113.5.22.ttyrec';
is(_ttyrec_F(), $DIRECT_FALLBACK, "pre-proxyjump layout: no realm + no remoteaccount => no subfolder");
is(_ttyrec_F(realm => "myrealm", remoteaccount => "remacct"),
    $WITH_REMACCT, "pre-proxyjump layout: realm + remoteaccount => remoteaccount subfolder");
is(_ttyrec_F(realm => "myrealm"), $DIRECT_FALLBACK,
    "pre-proxyjump layout: realm without remoteaccount => no subfolder");
is(_ttyrec_F(remoteaccount => "remacct"),
    $DIRECT_FALLBACK, "pre-proxyjump layout: remoteaccount without realm => no subfolder");

# Default vanilla install: ttyrecFilenameFormat at its shipped default, and both path-format options
# unset (''). This is the most common configuration, so its behavior must be identical before and
# after this PR. First pin those default values (mock-defaulting == a freshly copied bastion.conf):
OVH::Bastion::load_configuration(mock_data => {bastionName => 'mock'});
my $DEFAULT_FNAME = '%Y-%m-%d.%H-%M-%S.#usec#.&uniqid.&account.&user.&ip.&port.ttyrec';
is(OVH::Bastion::config('ttyrecFilenameFormat')->value, $DEFAULT_FNAME, "vanilla: ttyrecFilenameFormat default value");
is(OVH::Bastion::config('ttyrecDirectPathFormat')->value, '', "vanilla: ttyrecDirectPathFormat defaults to ''");
is(OVH::Bastion::config('ttyrecViaPathFormat')->value,    '', "vanilla: ttyrecViaPathFormat defaults to ''");

# Same, but with all three options set EXPLICITLY to their vanilla values (as a copied
# bastion.conf.dist would have them): the resolved paths must match the pre-proxyjump layout, i.e. be
# identical to omitting the path-format options entirely.
OVH::Bastion::load_configuration(
    mock_data => {
        bastionName            => 'mock',
        ttyrecFilenameFormat   => $DEFAULT_FNAME,
        ttyrecDirectPathFormat => '',
        ttyrecViaPathFormat    => '',
    }
);
is(_ttyrec_F(),          $DIRECT_FALLBACK, "vanilla (explicit defaults): direct conn => pre-proxyjump layout");
is(_ttyrec_F(%VIA_CONN), $VIA_FALLBACK,    "vanilla (explicit defaults): via conn => pre-proxyjump layout");
is(_ttyrec_F(realm => "myrealm", remoteaccount => "remacct"),
    $WITH_REMACCT, "vanilla (explicit defaults): realm+remoteaccount => pre-proxyjump layout");

# The proxy hop is also subject to forbiddenNetworks: a proxy in a forbidden net is refused, even
# when the target itself is not forbidden.
OVH::Bastion::load_configuration(mock_data => {bastionName => 'mock', forbiddenNetworks => ["192.0.2.0/24"]});
$fnret = OVH::Bastion::is_access_granted(
    account   => "wildcard",
    user      => "root",
    ipfrom    => "203.0.113.1",
    ip        => "198.51.100.5",    # target NOT forbidden
    port      => "9876",
    proxyIp   => "192.0.2.10",      # proxy IS in the forbidden net
    proxyPort => 22,
    proxyUser => "root",
);
is($fnret->err, "KO_ACCESS_DENIED", "forbiddenNetworks: proxy in a forbidden net is denied");
like(
    $fnret->msg,
    qr/via proxy 192\.0\.2\.10 as it's part of the forbidden networks/,
    "forbiddenNetworks: denial message points at the proxy"
);

# a proxy outside any forbidden net passes the forbidden-networks filter (then only the ACL may deny)
$fnret = OVH::Bastion::is_access_granted(
    account   => "wildcard",
    user      => "root",
    ipfrom    => "203.0.113.1",
    ip        => "198.51.100.5",
    port      => "9876",
    proxyIp   => "203.0.113.9",    # not forbidden
    proxyPort => 22,
    proxyUser => "root",
);
unlike($fnret->msg // '', qr/forbidden networks/, "forbiddenNetworks: non-forbidden proxy passes the filter");

# The proxy hop is also subject to allowedNetworks: when set, a proxy outside the allowed nets is
# refused, even when the target is inside them.
OVH::Bastion::load_configuration(mock_data => {bastionName => 'mock', allowedNetworks => ["198.51.100.0/24"]});
$fnret = OVH::Bastion::is_access_granted(
    account   => "wildcard",
    user      => "root",
    ipfrom    => "203.0.113.1",
    ip        => "198.51.100.5",    # target IS in the allowed net
    port      => "9876",
    proxyIp   => "203.0.113.9",     # proxy is NOT
    proxyPort => 22,
    proxyUser => "root",
);
is($fnret->err, "KO_ACCESS_DENIED", "allowedNetworks: proxy outside the allowed nets is denied");
like(
    $fnret->msg,
    qr/via proxy 203\.0\.113\.9 as it's not part of the allowed networks/,
    "allowedNetworks: denial message points at the proxy"
);

# a proxy inside the allowed nets passes the allowed-networks filter (then only the ACL may deny)
$fnret = OVH::Bastion::is_access_granted(
    account   => "wildcard",
    user      => "root",
    ipfrom    => "203.0.113.1",
    ip        => "198.51.100.5",
    port      => "9876",
    proxyIp   => "198.51.100.9",    # in the allowed net
    proxyPort => 22,
    proxyUser => "root",
);
unlike($fnret->msg // '', qr/not part of the allowed networks/, "allowedNetworks: in-net proxy passes the filter");

done_testing();
