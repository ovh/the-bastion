#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;
use TAP::Harness;

use FindBin qw{ $RealDir };

my @testfiles = glob("$RealDir/tests/*.t");
print "Got " . @testfiles . " unit test files to run:\n";

my $harness = TAP::Harness->new(
    {
        verbosity => 0,
        failures  => 1,
        color     => 1,
    }
);
exit($harness->runtests(@testfiles)->all_passed ? 0 : 1);
