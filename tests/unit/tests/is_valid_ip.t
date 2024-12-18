#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;
use Test::More;
use Test::Deep;

use File::Basename;
use lib dirname(__FILE__) . '/../../../lib/perl';
use OVH::Bastion;
use OVH::Result;

OVH::Bastion::enable_mocking();
OVH::Bastion::set_mock_data({});
OVH::Bastion::load_configuration(
    mock_data => {
        bastionName => "mock",
    }
);

foreach my $testip (
    qw{
    0.0.0.0
    239.0.0.0
    225.225.0.0
    192.0.2.0
    192.0.2.1
    192.0.2.128
    192.0.2.147
    255.255.255.255
    255.256.255.255
    192.00.0002.002
    }
  )
{

    foreach my $allowPrefixes (0 .. 1) {
        foreach my $prefixlen (0 .. 33) {
            my $ip   = $testip . ($prefixlen != 33 ? "/$prefixlen" : "");
            my $Fast = OVH::Bastion::is_valid_ip(ip => $ip, allowPrefixes => $allowPrefixes, fast => 1);
            my $Slow = OVH::Bastion::is_valid_ip(ip => $ip, allowPrefixes => $allowPrefixes, fast => 0);
            # both should have the same error code and returned IP if any:
            cmp_deeply(
                {err => $Fast->err, value_ip => ($Fast->value ? $Fast->value->{'ip'} : undef)},
                {err => $Slow->err, value_ip => ($Slow->value ? $Slow->value->{'ip'} : undef)},
                "is_valid_ip(ip=$ip, allowPrefixes=$allowPrefixes)"
            );
        }
    }
}

done_testing();
