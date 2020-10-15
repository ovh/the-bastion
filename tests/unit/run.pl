#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;
use Test::More;

use File::Basename;
use lib dirname(__FILE__) . '/../../lib/perl';
use OVH::Bastion;
use OVH::Result;

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
    }
);

# TESTS

is(OVH::Bastion::config("bastionName")->value, "mock", "bastion name is mocked");

ok(OVH::Bastion::is_account_valid(account => "azerty")->is_ok, "is_account_valid('azerty')");

is(OVH::Bastion::is_account_valid(account => "in valid")->err, "KO_FORBIDDEN_CHARS", "is_account_valid('in valid')");

is(OVH::Bastion::is_account_valid(account => "root")->err, "KO_FORBIDDEN_NAME", "is_account_valid('root')");

ok(OVH::Bastion::is_bastion_account_valid_and_existing(account => "me")->is_ok, "is_bastion_account_valid_and_existing('me')");

is_deeply(
    OVH::Bastion::is_access_granted(account => "me", user => "remote", ipfrom => "1.2.3.4", ip => "5.6.7.8", port => "9876"),
    R('KO_ACCESS_DENIED', msg => 'Access denied for me to remote@5.6.7.8:9876'),
    "is_access_granted(me) on denied machine"
);

ok(OVH::Bastion::is_access_granted(account => "me", user => "me", ipfrom => "1.1.1.1", ip => "1.2.3.4", port => "9876")->is_ok, "is_access_granted(me) on allowed machine");

is(OVH::Bastion::is_access_granted(account => "wildcard", user => "root", ipfrom => "10.15.15.15", ip => "1.2.3.4", port => "9876")->err,
    "KO_ACCESS_DENIED", "is_access_granted(wildcard) on disallowed machine due to ingressToEgressRules #1");

is(OVH::Bastion::is_access_granted(account => "wildcard", user => "root", ipfrom => "10.19.1.2", ip => "1.2.3.4", port => "9876")->err,
    "KO_ACCESS_DENIED", "is_access_granted(wildcard) on disallowed machine due to ingressToEgressRules #1");

ok(OVH::Bastion::is_access_granted(account => "wildcard", user => "root", ipfrom => "10.19.1.2", ip => "10.20.1.2", port => "9876")->is_ok,
    "is_access_granted(wildcard) on allowed machine due to ingressToEgressRules #1");

ok(OVH::Bastion::is_access_granted(account => "wildcard", user => "root", ipfrom => "192.168.42.1", ip => "192.168.42.4", port => "9876")->is_ok,
    "is_access_granted(wildcard) on allowed machine due to ingressToEgressRules #2");

ok(OVH::Bastion::is_access_granted(account => "wildcard", user => "root", ipfrom => "192.168.42.1", ip => "5.6.7.8", port => "9876")->is_ok,
    "is_access_granted(wildcard) on allowed machine due to ingressToEgressRules #2");

is(OVH::Bastion::is_access_granted(account => "wildcard", user => "root", ipfrom => "192.168.43.1", ip => "192.168.42.4", port => "9876")->err,
    "KO_ACCESS_DENIED", "is_access_granted(wildcard) on disallowed machine due to ingressToEgressRules #3");

ok(OVH::Bastion::is_access_granted(account => "wildcard", user => "root", ipfrom => "192.168.43.1", ip => "5.6.7.8", port => "9876")->is_ok,
    "is_access_granted(wildcard) on allowed machine due to ingressToEgressRules catch-all");

done_testing();
