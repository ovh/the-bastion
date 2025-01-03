#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;
use Test::More;
use Test::Deep;

use File::Basename;
use lib dirname(__FILE__) . '/../../../lib/perl';
use OVH::Bastion;
use OVH::Result;

# if Net::Netmask is too old, IPv6 is not supported
if (!OVH::Bastion::system_supports_ipv6()) {
    plan skip_all => "IPv6 is not supported, skipping IPv6 tests";
}

OVH::Bastion::enable_mocking();
OVH::Bastion::set_mock_data(
    {
        "accounts" => {
            "me" => {
                "uid"               => 99982,
                "gid"               => 99982,
                "personal_accesses" => [
                    qw{
                      me@[2001:db8::1:2]:12
                      me@[2001:db8:cafe::/48]:12
                      me@[2001:db8::1:3]
                      me@[2001:db8:beef::/48]

                      [2001:db8::2:2]:12
                      [2001:db8:feed::/48]:12
                      [2001:db8::2:3]
                      [2001:db8:deaf::/48]
                      }
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

my %want;    # truth table
my $undef = '_none_';    # can't use undef as a hash key, so we'll use this special value instead

$want{"2001:0db8:0::1:2"}{$undef}{$undef} = 'KO_ACCESS_DENIED';
$want{"2001:0db8:0::1:2"}{$undef}{"12"}   = 'KO_ACCESS_DENIED';
$want{"2001:0db8:0::1:2"}{$undef}{"80"}   = 'KO_ACCESS_DENIED';
$want{"2001:0db8:0::1:2"}{"me"}{$undef}   = 'KO_ACCESS_DENIED';
$want{"2001:0db8:0::1:2"}{"me"}{"12"}     = 'OK';
$want{"2001:0db8:0::1:2"}{"me"}{"80"}     = 'KO_ACCESS_DENIED';
$want{"2001:0db8:0::1:2"}{"not"}{$undef}  = 'KO_ACCESS_DENIED';
$want{"2001:0db8:0::1:2"}{"not"}{"12"}    = 'KO_ACCESS_DENIED';
$want{"2001:0db8:0::1:2"}{"not"}{"80"}    = 'KO_ACCESS_DENIED';

$want{"2001:db8:cafe:42::42"}{$undef}{$undef} = 'KO_ACCESS_DENIED';
$want{"2001:db8:cafe:42::42"}{$undef}{"12"}   = 'KO_ACCESS_DENIED';
$want{"2001:db8:cafe:42::42"}{$undef}{"80"}   = 'KO_ACCESS_DENIED';
$want{"2001:db8:cafe:42::42"}{"me"}{$undef}   = 'KO_ACCESS_DENIED';
$want{"2001:db8:cafe:42::42"}{"me"}{"12"}     = 'OK';
$want{"2001:db8:cafe:42::42"}{"me"}{"80"}     = 'KO_ACCESS_DENIED';
$want{"2001:db8:cafe:42::42"}{"not"}{$undef}  = 'KO_ACCESS_DENIED';
$want{"2001:db8:cafe:42::42"}{"not"}{"12"}    = 'KO_ACCESS_DENIED';
$want{"2001:db8:cafe:42::42"}{"not"}{"80"}    = 'KO_ACCESS_DENIED';

$want{"2001:db8::0:01:03"}{$undef}{$undef} = 'KO_ACCESS_DENIED';
$want{"2001:db8::0:01:03"}{$undef}{"12"}   = 'KO_ACCESS_DENIED';
$want{"2001:db8::0:01:03"}{$undef}{"80"}   = 'KO_ACCESS_DENIED';
$want{"2001:db8::0:01:03"}{"me"}{$undef}   = 'OK';
$want{"2001:db8::0:01:03"}{"me"}{"12"}     = 'OK';
$want{"2001:db8::0:01:03"}{"me"}{"80"}     = 'OK';
$want{"2001:db8::0:01:03"}{"not"}{$undef}  = 'KO_ACCESS_DENIED';
$want{"2001:db8::0:01:03"}{"not"}{"12"}    = 'KO_ACCESS_DENIED';
$want{"2001:db8::0:01:03"}{"not"}{"80"}    = 'KO_ACCESS_DENIED';

$want{"2001:db8:beef::123"}{$undef}{$undef} = 'KO_ACCESS_DENIED';
$want{"2001:db8:beef::123"}{$undef}{"12"}   = 'KO_ACCESS_DENIED';
$want{"2001:db8:beef::123"}{$undef}{"80"}   = 'KO_ACCESS_DENIED';
$want{"2001:db8:beef::123"}{"me"}{$undef}   = 'OK';
$want{"2001:db8:beef::123"}{"me"}{"12"}     = 'OK';
$want{"2001:db8:beef::123"}{"me"}{"80"}     = 'OK';
$want{"2001:db8:beef::123"}{"not"}{$undef}  = 'KO_ACCESS_DENIED';
$want{"2001:db8:beef::123"}{"not"}{"12"}    = 'KO_ACCESS_DENIED';
$want{"2001:db8:beef::123"}{"not"}{"80"}    = 'KO_ACCESS_DENIED';

$want{"2001:db8::2:2"}{$undef}{$undef} = 'KO_ACCESS_DENIED';
$want{"2001:db8::2:2"}{$undef}{"12"}   = 'OK';
$want{"2001:db8::2:2"}{$undef}{"80"}   = 'KO_ACCESS_DENIED';
$want{"2001:db8::2:2"}{"me"}{$undef}   = 'KO_ACCESS_DENIED';
$want{"2001:db8::2:2"}{"me"}{"12"}     = 'OK';
$want{"2001:db8::2:2"}{"me"}{"80"}     = 'KO_ACCESS_DENIED';
$want{"2001:db8::2:2"}{"not"}{$undef}  = 'KO_ACCESS_DENIED';
$want{"2001:db8::2:2"}{"not"}{"12"}    = 'OK';
$want{"2001:db8::2:2"}{"not"}{"80"}    = 'KO_ACCESS_DENIED';

$want{"2001:db8:feed::21"}{$undef}{$undef} = 'KO_ACCESS_DENIED';
$want{"2001:db8:feed::21"}{$undef}{"12"}   = 'OK';
$want{"2001:db8:feed::21"}{$undef}{"80"}   = 'KO_ACCESS_DENIED';
$want{"2001:db8:feed::21"}{"me"}{$undef}   = 'KO_ACCESS_DENIED';
$want{"2001:db8:feed::21"}{"me"}{"12"}     = 'OK';
$want{"2001:db8:feed::21"}{"me"}{"80"}     = 'KO_ACCESS_DENIED';
$want{"2001:db8:feed::21"}{"not"}{$undef}  = 'KO_ACCESS_DENIED';
$want{"2001:db8:feed::21"}{"not"}{"12"}    = 'OK';
$want{"2001:db8:feed::21"}{"not"}{"80"}    = 'KO_ACCESS_DENIED';

$want{"2001:db8::2:3"}{$undef}{$undef} = 'OK';
$want{"2001:db8::2:3"}{$undef}{"12"}   = 'OK';
$want{"2001:db8::2:3"}{$undef}{"80"}   = 'OK';
$want{"2001:db8::2:3"}{"me"}{$undef}   = 'OK';
$want{"2001:db8::2:3"}{"me"}{"12"}     = 'OK';
$want{"2001:db8::2:3"}{"me"}{"80"}     = 'OK';
$want{"2001:db8::2:3"}{"not"}{$undef}  = 'OK';
$want{"2001:db8::2:3"}{"not"}{"12"}    = 'OK';
$want{"2001:db8::2:3"}{"not"}{"80"}    = 'OK';

$want{"2001:db8:deaf::1"}{$undef}{$undef} = 'OK';
$want{"2001:db8:deaf::1"}{$undef}{"12"}   = 'OK';
$want{"2001:db8:deaf::1"}{$undef}{"80"}   = 'OK';
$want{"2001:db8:deaf::1"}{"me"}{$undef}   = 'OK';
$want{"2001:db8:deaf::1"}{"me"}{"12"}     = 'OK';
$want{"2001:db8:deaf::1"}{"me"}{"80"}     = 'OK';
$want{"2001:db8:deaf::1"}{"not"}{$undef}  = 'OK';
$want{"2001:db8:deaf::1"}{"not"}{"12"}    = 'OK';
$want{"2001:db8:deaf::1"}{"not"}{"80"}    = 'OK';

$want{"2001:db8:cafe:ffff::/64"}{$undef}{$undef} = 'KO_ACCESS_DENIED';
$want{"2001:db8:cafe:ffff::/64"}{$undef}{"12"}   = 'KO_ACCESS_DENIED';
$want{"2001:db8:cafe:ffff::/64"}{$undef}{"80"}   = 'KO_ACCESS_DENIED';
$want{"2001:db8:cafe:ffff::/64"}{"me"}{$undef}   = 'KO_ACCESS_DENIED';
$want{"2001:db8:cafe:ffff::/64"}{"me"}{"12"}     = 'OK';
$want{"2001:db8:cafe:ffff::/64"}{"me"}{"80"}     = 'KO_ACCESS_DENIED';
$want{"2001:db8:cafe:ffff::/64"}{"not"}{$undef}  = 'KO_ACCESS_DENIED';
$want{"2001:db8:cafe:ffff::/64"}{"not"}{"12"}    = 'KO_ACCESS_DENIED';
$want{"2001:db8:cafe:ffff::/64"}{"not"}{"80"}    = 'KO_ACCESS_DENIED';

$want{"2001:db8:beef:ffff::/64"}{$undef}{$undef} = 'KO_ACCESS_DENIED';
$want{"2001:db8:beef:ffff::/64"}{$undef}{"12"}   = 'KO_ACCESS_DENIED';
$want{"2001:db8:beef:ffff::/64"}{$undef}{"80"}   = 'KO_ACCESS_DENIED';
$want{"2001:db8:beef:ffff::/64"}{"me"}{$undef}   = 'OK';
$want{"2001:db8:beef:ffff::/64"}{"me"}{"12"}     = 'OK';
$want{"2001:db8:beef:ffff::/64"}{"me"}{"80"}     = 'OK';
$want{"2001:db8:beef:ffff::/64"}{"not"}{$undef}  = 'KO_ACCESS_DENIED';
$want{"2001:db8:beef:ffff::/64"}{"not"}{"12"}    = 'KO_ACCESS_DENIED';
$want{"2001:db8:beef:ffff::/64"}{"not"}{"80"}    = 'KO_ACCESS_DENIED';

$want{"2001:db8:feed:ffff::/64"}{$undef}{$undef} = 'KO_ACCESS_DENIED';
$want{"2001:db8:feed:ffff::/64"}{$undef}{"12"}   = 'OK';
$want{"2001:db8:feed:ffff::/64"}{$undef}{"80"}   = 'KO_ACCESS_DENIED';
$want{"2001:db8:feed:ffff::/64"}{"me"}{$undef}   = 'KO_ACCESS_DENIED';
$want{"2001:db8:feed:ffff::/64"}{"me"}{"12"}     = 'OK';
$want{"2001:db8:feed:ffff::/64"}{"me"}{"80"}     = 'KO_ACCESS_DENIED';
$want{"2001:db8:feed:ffff::/64"}{"not"}{$undef}  = 'KO_ACCESS_DENIED';
$want{"2001:db8:feed:ffff::/64"}{"not"}{"12"}    = 'OK';
$want{"2001:db8:feed:ffff::/64"}{"not"}{"80"}    = 'KO_ACCESS_DENIED';

$want{"2001:db8:deaf:ffff::/64"}{$undef}{$undef} = 'OK';
$want{"2001:db8:deaf:ffff::/64"}{$undef}{"12"}   = 'OK';
$want{"2001:db8:deaf:ffff::/64"}{$undef}{"80"}   = 'OK';
$want{"2001:db8:deaf:ffff::/64"}{"me"}{$undef}   = 'OK';
$want{"2001:db8:deaf:ffff::/64"}{"me"}{"12"}     = 'OK';
$want{"2001:db8:deaf:ffff::/64"}{"me"}{"80"}     = 'OK';
$want{"2001:db8:deaf:ffff::/64"}{"not"}{$undef}  = 'OK';
$want{"2001:db8:deaf:ffff::/64"}{"not"}{"12"}    = 'OK';
$want{"2001:db8:deaf:ffff::/64"}{"not"}{"80"}    = 'OK';

$want{"2001:db8:ffff::1"}{$undef}{$undef} = 'KO_ACCESS_DENIED';
$want{"2001:db8:ffff::1"}{$undef}{"12"}   = 'KO_ACCESS_DENIED';
$want{"2001:db8:ffff::1"}{$undef}{"80"}   = 'KO_ACCESS_DENIED';
$want{"2001:db8:ffff::1"}{"me"}{$undef}   = 'KO_ACCESS_DENIED';
$want{"2001:db8:ffff::1"}{"me"}{"12"}     = 'KO_ACCESS_DENIED';
$want{"2001:db8:ffff::1"}{"me"}{"80"}     = 'KO_ACCESS_DENIED';
$want{"2001:db8:ffff::1"}{"not"}{$undef}  = 'KO_ACCESS_DENIED';
$want{"2001:db8:ffff::1"}{"not"}{"12"}    = 'KO_ACCESS_DENIED';
$want{"2001:db8:ffff::1"}{"not"}{"80"}    = 'KO_ACCESS_DENIED';

foreach my $ip (
    qw{
    2001:0db8:0::1:2
    2001:db8:cafe:42::42
    2001:db8::0:01:03
    2001:db8:beef::123
    2001:db8::2:2
    2001:db8:feed::21
    2001:db8::2:3
    2001:db8:deaf::1
    2001:db8:cafe:ffff::/64
    2001:db8:beef:ffff::/64
    2001:db8:feed:ffff::/64
    2001:db8:deaf:ffff::/64
    2001:db8:ffff::1
    }
  )
{

    foreach my $user (undef, "me", "not") {
        foreach my $port (undef, 12, 80) {
            # To generate the truth table skeleton:
            # printf "\$want{\"%s\"}{%s}{%s} = 'ERR';\n", $ip, $user ? "\"$user\"" : "undef", $port ? "\"$port\"" : "undef";
            is(
                OVH::Bastion::is_access_granted(
                    ipfrom  => "127.0.0.1",
                    account => "me",
                    user    => $user,
                    ip      => $ip,
                    port    => $port
                )->err,
                $want{$ip}{$user // $undef}{$port // $undef} || 'ERR_UNDEFINED',
                "is_access_granted IPv6 with " . ($user // '<u>') . '@[' . $ip . "]:" . ($port // '<u>')
            );
        }
    }
}

done_testing();
