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
OVH::Bastion::set_mock_data(
    {
        "accounts" => {
            "me" => {
                "uid"               => 99982,
                "gid"               => 99982,
                "personal_accesses" => [
                    qw{
                      me@192.0.2.12:12
                      me@198.51.100.0/28:12
                      me@192.0.2.13
                      me@198.51.100.16/28

                      192.0.2.22:12
                      198.51.100.32/28:12
                      192.0.2.23
                      198.51.100.48/28
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

my %want;                # truth table
my $undef = '_none_';    # can't use undef as a hash key, so we'll use this special value instead

$want{"192.0.2.12"}{$undef}{$undef} = 'KO_ACCESS_DENIED';
$want{"192.0.2.12"}{$undef}{"12"}   = 'KO_ACCESS_DENIED';
$want{"192.0.2.12"}{$undef}{"80"}   = 'KO_ACCESS_DENIED';
$want{"192.0.2.12"}{"me"}{$undef}   = 'KO_ACCESS_DENIED';
$want{"192.0.2.12"}{"me"}{"12"}     = 'OK';
$want{"192.0.2.12"}{"me"}{"80"}     = 'KO_ACCESS_DENIED';
$want{"192.0.2.12"}{"not"}{$undef}  = 'KO_ACCESS_DENIED';
$want{"192.0.2.12"}{"not"}{"12"}    = 'KO_ACCESS_DENIED';
$want{"192.0.2.12"}{"not"}{"80"}    = 'KO_ACCESS_DENIED';

$want{"198.51.100.4"}{$undef}{$undef} = 'KO_ACCESS_DENIED';
$want{"198.51.100.4"}{$undef}{"12"}   = 'KO_ACCESS_DENIED';
$want{"198.51.100.4"}{$undef}{"80"}   = 'KO_ACCESS_DENIED';
$want{"198.51.100.4"}{"me"}{$undef}   = 'KO_ACCESS_DENIED';
$want{"198.51.100.4"}{"me"}{"12"}     = 'OK';
$want{"198.51.100.4"}{"me"}{"80"}     = 'KO_ACCESS_DENIED';
$want{"198.51.100.4"}{"not"}{$undef}  = 'KO_ACCESS_DENIED';
$want{"198.51.100.4"}{"not"}{"12"}    = 'KO_ACCESS_DENIED';
$want{"198.51.100.4"}{"not"}{"80"}    = 'KO_ACCESS_DENIED';

$want{"192.0.2.13"}{$undef}{$undef} = 'KO_ACCESS_DENIED';
$want{"192.0.2.13"}{$undef}{"12"}   = 'KO_ACCESS_DENIED';
$want{"192.0.2.13"}{$undef}{"80"}   = 'KO_ACCESS_DENIED';
$want{"192.0.2.13"}{"me"}{$undef}   = 'OK';
$want{"192.0.2.13"}{"me"}{"12"}     = 'OK';
$want{"192.0.2.13"}{"me"}{"80"}     = 'OK';
$want{"192.0.2.13"}{"not"}{$undef}  = 'KO_ACCESS_DENIED';
$want{"192.0.2.13"}{"not"}{"12"}    = 'KO_ACCESS_DENIED';
$want{"192.0.2.13"}{"not"}{"80"}    = 'KO_ACCESS_DENIED';

$want{"198.51.100.19"}{$undef}{$undef} = 'KO_ACCESS_DENIED';
$want{"198.51.100.19"}{$undef}{"12"}   = 'KO_ACCESS_DENIED';
$want{"198.51.100.19"}{$undef}{"80"}   = 'KO_ACCESS_DENIED';
$want{"198.51.100.19"}{"me"}{$undef}   = 'OK';
$want{"198.51.100.19"}{"me"}{"12"}     = 'OK';
$want{"198.51.100.19"}{"me"}{"80"}     = 'OK';
$want{"198.51.100.19"}{"not"}{$undef}  = 'KO_ACCESS_DENIED';
$want{"198.51.100.19"}{"not"}{"12"}    = 'KO_ACCESS_DENIED';
$want{"198.51.100.19"}{"not"}{"80"}    = 'KO_ACCESS_DENIED';

$want{"192.0.2.22"}{$undef}{$undef} = 'KO_ACCESS_DENIED';
$want{"192.0.2.22"}{$undef}{"12"}   = 'OK';
$want{"192.0.2.22"}{$undef}{"80"}   = 'KO_ACCESS_DENIED';
$want{"192.0.2.22"}{"me"}{$undef}   = 'KO_ACCESS_DENIED';
$want{"192.0.2.22"}{"me"}{"12"}     = 'OK';
$want{"192.0.2.22"}{"me"}{"80"}     = 'KO_ACCESS_DENIED';
$want{"192.0.2.22"}{"not"}{$undef}  = 'KO_ACCESS_DENIED';
$want{"192.0.2.22"}{"not"}{"12"}    = 'OK';
$want{"192.0.2.22"}{"not"}{"80"}    = 'KO_ACCESS_DENIED';

$want{"198.51.100.35"}{$undef}{$undef} = 'KO_ACCESS_DENIED';
$want{"198.51.100.35"}{$undef}{"12"}   = 'OK';
$want{"198.51.100.35"}{$undef}{"80"}   = 'KO_ACCESS_DENIED';
$want{"198.51.100.35"}{"me"}{$undef}   = 'KO_ACCESS_DENIED';
$want{"198.51.100.35"}{"me"}{"12"}     = 'OK';
$want{"198.51.100.35"}{"me"}{"80"}     = 'KO_ACCESS_DENIED';
$want{"198.51.100.35"}{"not"}{$undef}  = 'KO_ACCESS_DENIED';
$want{"198.51.100.35"}{"not"}{"12"}    = 'OK';
$want{"198.51.100.35"}{"not"}{"80"}    = 'KO_ACCESS_DENIED';

$want{"192.0.2.23"}{$undef}{$undef} = 'OK';
$want{"192.0.2.23"}{$undef}{"12"}   = 'OK';
$want{"192.0.2.23"}{$undef}{"80"}   = 'OK';
$want{"192.0.2.23"}{"me"}{$undef}   = 'OK';
$want{"192.0.2.23"}{"me"}{"12"}     = 'OK';
$want{"192.0.2.23"}{"me"}{"80"}     = 'OK';
$want{"192.0.2.23"}{"not"}{$undef}  = 'OK';
$want{"192.0.2.23"}{"not"}{"12"}    = 'OK';
$want{"192.0.2.23"}{"not"}{"80"}    = 'OK';

$want{"198.51.100.49"}{$undef}{$undef} = 'OK';
$want{"198.51.100.49"}{$undef}{"12"}   = 'OK';
$want{"198.51.100.49"}{$undef}{"80"}   = 'OK';
$want{"198.51.100.49"}{"me"}{$undef}   = 'OK';
$want{"198.51.100.49"}{"me"}{"12"}     = 'OK';
$want{"198.51.100.49"}{"me"}{"80"}     = 'OK';
$want{"198.51.100.49"}{"not"}{$undef}  = 'OK';
$want{"198.51.100.49"}{"not"}{"12"}    = 'OK';
$want{"198.51.100.49"}{"not"}{"80"}    = 'OK';

$want{"198.51.100.4/30"}{$undef}{$undef} = 'KO_ACCESS_DENIED';
$want{"198.51.100.4/30"}{$undef}{"12"}   = 'KO_ACCESS_DENIED';
$want{"198.51.100.4/30"}{$undef}{"80"}   = 'KO_ACCESS_DENIED';
$want{"198.51.100.4/30"}{"me"}{$undef}   = 'KO_ACCESS_DENIED';
$want{"198.51.100.4/30"}{"me"}{"12"}     = 'OK';
$want{"198.51.100.4/30"}{"me"}{"80"}     = 'KO_ACCESS_DENIED';
$want{"198.51.100.4/30"}{"not"}{$undef}  = 'KO_ACCESS_DENIED';
$want{"198.51.100.4/30"}{"not"}{"12"}    = 'KO_ACCESS_DENIED';
$want{"198.51.100.4/30"}{"not"}{"80"}    = 'KO_ACCESS_DENIED';

$want{"198.51.100.20/30"}{$undef}{$undef} = 'KO_ACCESS_DENIED';
$want{"198.51.100.20/30"}{$undef}{"12"}   = 'KO_ACCESS_DENIED';
$want{"198.51.100.20/30"}{$undef}{"80"}   = 'KO_ACCESS_DENIED';
$want{"198.51.100.20/30"}{"me"}{$undef}   = 'OK';
$want{"198.51.100.20/30"}{"me"}{"12"}     = 'OK';
$want{"198.51.100.20/30"}{"me"}{"80"}     = 'OK';
$want{"198.51.100.20/30"}{"not"}{$undef}  = 'KO_ACCESS_DENIED';
$want{"198.51.100.20/30"}{"not"}{"12"}    = 'KO_ACCESS_DENIED';
$want{"198.51.100.20/30"}{"not"}{"80"}    = 'KO_ACCESS_DENIED';

$want{"198.51.100.36/30"}{$undef}{$undef} = 'KO_ACCESS_DENIED';
$want{"198.51.100.36/30"}{$undef}{"12"}   = 'OK';
$want{"198.51.100.36/30"}{$undef}{"80"}   = 'KO_ACCESS_DENIED';
$want{"198.51.100.36/30"}{"me"}{$undef}   = 'KO_ACCESS_DENIED';
$want{"198.51.100.36/30"}{"me"}{"12"}     = 'OK';
$want{"198.51.100.36/30"}{"me"}{"80"}     = 'KO_ACCESS_DENIED';
$want{"198.51.100.36/30"}{"not"}{$undef}  = 'KO_ACCESS_DENIED';
$want{"198.51.100.36/30"}{"not"}{"12"}    = 'OK';
$want{"198.51.100.36/30"}{"not"}{"80"}    = 'KO_ACCESS_DENIED';

$want{"198.51.100.52/30"}{$undef}{$undef} = 'OK';
$want{"198.51.100.52/30"}{$undef}{"12"}   = 'OK';
$want{"198.51.100.52/30"}{$undef}{"80"}   = 'OK';
$want{"198.51.100.52/30"}{"me"}{$undef}   = 'OK';
$want{"198.51.100.52/30"}{"me"}{"12"}     = 'OK';
$want{"198.51.100.52/30"}{"me"}{"80"}     = 'OK';
$want{"198.51.100.52/30"}{"not"}{$undef}  = 'OK';
$want{"198.51.100.52/30"}{"not"}{"12"}    = 'OK';
$want{"198.51.100.52/30"}{"not"}{"80"}    = 'OK';

$want{"192.0.2.255"}{$undef}{$undef} = 'KO_ACCESS_DENIED';
$want{"192.0.2.255"}{$undef}{"12"}   = 'KO_ACCESS_DENIED';
$want{"192.0.2.255"}{$undef}{"80"}   = 'KO_ACCESS_DENIED';
$want{"192.0.2.255"}{"me"}{$undef}   = 'KO_ACCESS_DENIED';
$want{"192.0.2.255"}{"me"}{"12"}     = 'KO_ACCESS_DENIED';
$want{"192.0.2.255"}{"me"}{"80"}     = 'KO_ACCESS_DENIED';
$want{"192.0.2.255"}{"not"}{$undef}  = 'KO_ACCESS_DENIED';
$want{"192.0.2.255"}{"not"}{"12"}    = 'KO_ACCESS_DENIED';
$want{"192.0.2.255"}{"not"}{"80"}    = 'KO_ACCESS_DENIED';

foreach my $ip (
    qw{
    192.0.2.12
    198.51.100.4
    192.0.2.13
    198.51.100.19
    192.0.2.22
    198.51.100.35
    192.0.2.23
    198.51.100.49
    198.51.100.4/30
    198.51.100.20/30
    198.51.100.36/30
    198.51.100.52/30
    192.0.2.255
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
                "is_access_granted IPv4 with " . ($user // '<u>') . '@' . $ip . ":" . ($port // '<u>')
            );
        }
    }
}

done_testing();
