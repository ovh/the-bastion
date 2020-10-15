#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

# This is an basic script to check whether an account is active or not.
# It serves as an example of what such a script can look like, but can also be used
# as is in production if it matches your use case.
# See the 'accountExternalValidationProgram' option in bastion.conf for more information

use constant {
    EXIT_ACTIVE               => 0,
    EXIT_INACTIVE             => 1,
    EXIT_UNKNOWN              => 2,
    EXIT_UNKNOWN_SILENT_ERROR => 3,
    EXIT_UNKNOWN_NOISY_ERROR  => 4,
};

my $sysaccount = shift;
if (!$sysaccount) {
    print STDERR "No account name to check. Report this to sysadmin!\n";
    exit EXIT_UNKNOWN_NOISY_ERROR;
}

# This file should be a simple plaintext file containing one account name per line
# It should be populated by e.g. a cron script that queries some external directory
# such as an LDAP for example.
# Ensure that this file is readable at least by the bastion-users system group!
my $file = '/home/allowkeeper/active_accounts.txt';

if (!(-e $file)) {

    print STDERR "Active accounts file is not present. Report this to sysadmin!\n";
    exit EXIT_UNKNOWN_NOISY_ERROR;
}

# Load file
my $f;
if (!(open $f, '<', $file)) {
    print STDERR "Active logins file is unreadable ($!). Report this to sysadmin!\n";
    exit EXIT_UNKNOWN_NOISY_ERROR;
}

# check that the account is present in the file
while (<$f>) {
    chomp;
    if ($_ eq $sysaccount) {
        close($f);
        exit EXIT_ACTIVE;
    }
}
close($f);

# If not, account is inactive
exit EXIT_INACTIVE;
