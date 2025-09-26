#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;
use Test::More;

use File::Basename;
use lib dirname(__FILE__) . '/../../../lib/perl';
use OVH::Bastion;
use OVH::Result;

OVH::Bastion::enable_mocking();
OVH::Bastion::set_mock_data(
    {
        "accounts" => {
            "me" => {
                "uid"               => 99982,
                "gid"               => 99982,
                "personal_accesses" => [
                    "me\@192.0.2.10:22",
                    "me\@192.0.2.11",
                    "me\@192.0.2.20:22 # PROXYHOST=10.0.0.1 # PROXYPORT=2222",
                    "me\@192.0.2.21:80 # PROXYHOST=10.0.0.1 # PROXYPORT=2222",
                    "me\@192.0.2.30:22 # PROXYHOST=10.0.0.2 # PROXYPORT=3333",
                    "me\@192.0.2.50 # PROXYHOST=10.0.0.4 # PROXYPORT=4444",
                    "192.0.2.60:22 # PROXYHOST=10.0.0.5 # PROXYPORT=5555",
                    "198.51.100.0/24:22 # PROXYHOST=10.0.0.1 # PROXYPORT=2222",
                    # IPv6 entries
                    "me\@[2001:db8::10]:22",
                    "me\@[2001:db8::11]",
                    "me\@[2001:db8::20]:22 # PROXYHOST=2001:db8:cafe::1 # PROXYPORT=2222",
                    "me\@[2001:db8::30]:80 # PROXYHOST=2001:db8:cafe::2 # PROXYPORT=3333",
                    "[2001:db8::40]:22 # PROXYHOST=2001:db8:cafe::4 # PROXYPORT=4444",
                    "[2001:aaaa::/64]:22 # PROXYHOST=2001:db8:cafe::1 # PROXYPORT=2222",
                ],
            },
        },
    }
);
OVH::Bastion::load_configuration(
    mock_data => {
        bastionName => "mock",
    }
);

my %want;                # truth table
my $undef = '_none_';    # can't use undef as a hash key, so we'll use this special value instead

# Test 1: Regular access without proxy - should work as before
$want{"192.0.2.10"}{"22"}{"me"}{$undef}{$undef}     = 'OK';
$want{"192.0.2.10"}{"22"}{"me"}{"10.0.0.1"}{"2222"} = 'KO_ACCESS_DENIED';    # proxy requested but not configured
$want{"192.0.2.11"}{"22"}{"me"}{$undef}{$undef}     = 'OK';
$want{"192.0.2.11"}{"80"}{"me"}{$undef}{$undef}     = 'OK';

# Test 2: Access with specific proxy - should only work with exact proxy match
$want{"192.0.2.20"}{"22"}{"me"}{$undef}{$undef}     = 'KO_ACCESS_DENIED';    # proxy required but not provided
$want{"192.0.2.20"}{"22"}{"me"}{"10.0.0.1"}{"2222"} = 'OK';
$want{"192.0.2.20"}{"22"}{"me"}{"10.0.0.1"}{"3333"} = 'KO_ACCESS_DENIED';    # wrong proxy port
$want{"192.0.2.20"}{"22"}{"me"}{"10.0.0.2"}{"2222"} = 'KO_ACCESS_DENIED';    # wrong proxy IP
$want{"192.0.2.20"}{"22"}{"me"}{"10.0.0.1"}{$undef} = 'KO_ACCESS_DENIED';    # proxy IP without port

# Test 3: Different proxy configuration
$want{"192.0.2.30"}{"22"}{"me"}{"10.0.0.2"}{"3333"} = 'OK';
$want{"192.0.2.30"}{"22"}{"me"}{"10.0.0.1"}{"2222"} = 'KO_ACCESS_DENIED';    # wrong proxy

# Test 4: Subnet access with proxy (198.51.100.0/24 covers 198.51.100.0 - 198.51.100.255)
$want{"198.51.100.100"}{"22"}{"me"}{"10.0.0.1"}{"2222"} = 'OK';                  # subnet match with proxy
$want{"198.51.100.200"}{"22"}{"me"}{"10.0.0.1"}{"2222"} = 'OK';                  # subnet match with proxy
$want{"198.51.100.100"}{"22"}{"me"}{"10.0.0.1"}{"3333"} = 'KO_ACCESS_DENIED';    # subnet match, wrong proxy port
$want{"198.51.100.100"}{"22"}{"me"}{$undef}{$undef}     = 'KO_ACCESS_DENIED';    # subnet match but no proxy requested when proxy required

# Test 5: Port wildcard with proxy
$want{"192.0.2.50"}{"22"}{"me"}{"10.0.0.4"}{"4444"} = 'OK';                      # port wildcard with proxy
$want{"192.0.2.50"}{"80"}{"me"}{"10.0.0.4"}{"4444"} = 'OK';                      # port wildcard with proxy
$want{"192.0.2.50"}{"22"}{"me"}{"10.0.0.4"}{"5555"} = 'KO_ACCESS_DENIED';        # wrong proxy port

# Test 6: User wildcard with proxy - this tests a specific edge case
$want{"192.0.2.60"}{"22"}{"root"}{"10.0.0.5"}{"5555"}  = 'OK';                   # user wildcard should match any user with exact proxy
$want{"192.0.2.60"}{"22"}{"admin"}{"10.0.0.5"}{"5555"} = 'OK';                   # user wildcard should match any user with exact proxy
$want{"192.0.2.60"}{"22"}{"root"}{"10.0.0.5"}{"6666"}  = 'KO_ACCESS_DENIED';     # user wildcard but wrong proxy port

# Test 7: Negative cases - hosts not in ACL
$want{"192.0.2.99"}{"22"}{"me"}{$undef}{$undef} = 'KO_ACCESS_DENIED';
$want{"192.0.2.99"}{"22"}{"me"}{"10.0.0.1"}{"2222"} = 'KO_ACCESS_DENIED';

# IPv6 Tests
# Test 8: Regular IPv6 access without proxy - should work as before
$want{"2001:db8::10"}{"22"}{"me"}{$undef}{$undef}             = 'OK';
$want{"2001:db8::10"}{"22"}{"me"}{"2001:db8:cafe::1"}{"2222"} = 'KO_ACCESS_DENIED';    # proxy requested but not configured
$want{"2001:db8::11"}{"22"}{"me"}{$undef}{$undef}             = 'OK';
$want{"2001:db8::11"}{"80"}{"me"}{$undef}{$undef}             = 'OK';

# Test 9: IPv6 access with specific proxy - should only work with exact proxy match
$want{"2001:db8::20"}{"22"}{"me"}{$undef}{$undef}             = 'KO_ACCESS_DENIED';    # proxy required but not provided
$want{"2001:db8::20"}{"22"}{"me"}{"2001:db8:cafe::1"}{"2222"} = 'OK';
$want{"2001:db8::20"}{"22"}{"me"}{"2001:db8:cafe::1"}{"3333"} = 'KO_ACCESS_DENIED';    # wrong proxy port
$want{"2001:db8::20"}{"22"}{"me"}{"2001:db8:cafe::2"}{"2222"} = 'KO_ACCESS_DENIED';    # wrong proxy IP

# Test 10: IPv6 different proxy configuration
$want{"2001:db8::30"}{"80"}{"me"}{"2001:db8:cafe::2"}{"3333"} = 'OK';
$want{"2001:db8::30"}{"80"}{"me"}{"2001:db8:cafe::1"}{"2222"} = 'KO_ACCESS_DENIED';    # wrong proxy

# Test 11: IPv6 user wildcard with proxy
$want{"2001:db8::40"}{"22"}{"root"}{"2001:db8:cafe::4"}{"4444"}  = 'OK';                  # user wildcard should match any user with exact proxy
$want{"2001:db8::40"}{"22"}{"admin"}{"2001:db8:cafe::4"}{"4444"} = 'OK';                  # user wildcard should match any user with exact proxy
$want{"2001:db8::40"}{"22"}{"root"}{"2001:db8:cafe::4"}{"5555"}  = 'KO_ACCESS_DENIED';    # user wildcard but wrong proxy port

# Test 12: IPv6 subnet access with proxy (2001:aaaa::/64 covers 2001:db8::0 - 2001:aaaa::ffff:ffff:ffff:ffff)
$want{"2001:aaaa::100"}{"22"}{"me"}{"2001:db8:cafe::1"}{"2222"} = 'OK';                   # subnet match with proxy
$want{"2001:aaaa::200"}{"22"}{"me"}{"2001:db8:cafe::1"}{"2222"} = 'OK';                   # subnet match with proxy
$want{"2001:aaaa::100"}{"22"}{"me"}{"2001:db8:cafe::1"}{"3333"} = 'KO_ACCESS_DENIED';     # subnet match, wrong proxy port
$want{"2001:aaaa::100"}{"22"}{"me"}{$undef}{$undef}             = 'KO_ACCESS_DENIED';     # subnet match but no proxy requested when proxy required

# Test 13: IPv6 negative cases - hosts not in ACL
$want{"2001:ffff::999"}{"22"}{"me"}{$undef}{$undef} = 'KO_ACCESS_DENIED';
$want{"2001:ffff::999"}{"22"}{"me"}{"2001:db8:cafe::1"}{"2222"} = 'KO_ACCESS_DENIED';

# Run all the tests
foreach my $ip (
    qw{
    192.0.2.10
    192.0.2.11
    192.0.2.20
    192.0.2.30
    198.51.100.100
    198.51.100.200
    192.0.2.50
    192.0.2.60
    192.0.2.99
    2001:db8::10
    2001:db8::11
    2001:db8::20
    2001:db8::30
    2001:db8::40
    2001:aaaa::100
    2001:aaaa::200
    2001:ffff::999
    }
  )
{

    foreach my $port (qw{22 80}) {
        foreach my $user (qw{me root admin}) {
            foreach my $proxyIp (
                $undef,     "10.0.0.1", "10.0.0.2",         "10.0.0.3",
                "10.0.0.4", "10.0.0.5", "2001:db8:cafe::1", "2001:db8:cafe::2",
                "2001:db8:cafe::4"
              )
            {
                foreach my $proxyPort ($undef, "2222", "3333", "1234", "4444", "5555", "6666") {
                    # Skip combinations that don't make sense (proxy port without proxy IP)
                    next if (!defined $proxyIp || $proxyIp eq $undef) && (defined $proxyPort && $proxyPort ne $undef);

                    my $expected = $want{$ip}{$port}{$user}{$proxyIp // $undef}{$proxyPort // $undef};
                    next unless defined $expected;

                    my %params = (
                        ipfrom  => "127.0.0.1",
                        account => "me",
                        user    => $user,
                        ip      => $ip,
                        port    => $port,
                    );

                    # Add proxy parameters if they are defined
                    if (defined $proxyIp && $proxyIp ne $undef) {
                        $params{proxyIp} = $proxyIp;
                    }
                    if (defined $proxyPort && $proxyPort ne $undef) {
                        $params{proxyPort} = $proxyPort;
                    }

                    my $result = OVH::Bastion::is_access_granted(%params);

                    my $test_desc = sprintf(
                        "is_access_granted with %s@%s:%s proxy=%s:%s",
                        $user, $ip, $port,
                        $proxyIp   // '<none>',
                        $proxyPort // '<none>'
                    );

                    is($result->err, $expected, $test_desc);

                    # If access is granted, verify proxy information is returned
                    _verify_proxy_information($expected, $proxyIp, $proxyPort, $result, $test_desc);
                }
            }
        }
    }
}

sub _verify_proxy_information {
    my ($expected, $proxyIp, $proxyPort, $result, $test_desc) = @_;

    # Early return if access is not granted or no proxy expected
    return if $expected ne 'OK';
    return if !defined $proxyIp || $proxyIp eq $undef;

    my $value = $result->value;
    return if ref $value ne 'ARRAY' || @$value == 0;

    # Check if any of the returned grants has proxy info
    my $found_proxy = 0;
    foreach my $grant (@$value) {
        next if !defined $grant->{proxyIp};
        next if $grant->{proxyIp} ne $proxyIp;

        $found_proxy = 1;
        if (defined $proxyPort && $proxyPort ne $undef) {
            is($grant->{proxyPort}, $proxyPort, "$test_desc - proxy port returned");
        }
        last;
    }
    ok($found_proxy, "$test_desc - proxy IP returned in grant");
    return;
}

done_testing();
