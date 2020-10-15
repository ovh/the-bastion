#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

# DO NOT USE THIS SCRIPT IN PRODUCTION!
# This is only used for the functional tests, it returns true for odd UIDs, false otherwise.
# If you think this is a good way of determining your users activeness, you might want to revise your security procedures.

use constant {
    EXIT_ACTIVE               => 0,
    EXIT_INACTIVE             => 1,
    EXIT_UNKNOWN              => 2,
    EXIT_UNKNOWN_SILENT_ERROR => 3,
    EXIT_UNKNOWN_NOISY_ERROR  => 4,
};

sub failtest {
    my $msg = shift || "Error";
    print STDERR "$msg. This will fail the test: MAKETESTFAIL\n";
    exit EXIT_UNKNOWN_NOISY_ERROR;
}

my $sysaccount = shift;
if (!$sysaccount) {
    failtest("No account name to check");
}

my $uid = getpwnam($sysaccount);
failtest("Can't find this account") if not defined $uid;

exit EXIT_ACTIVE if ($uid % 2 == 0);
exit EXIT_INACTIVE;
