#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

# DO NOT USE THIS SCRIPT IN PRODUCTION!
# This is only used for the functional tests: it waits for a few seconds before declaring the
# account as active. As this program is called by the bastion at the very beginning of a session,
# this is a deterministic way to artificially slow down the session setup phase, which is needed
# to test the `sessionSetupTimeout' option.

use constant {
    EXIT_ACTIVE => 0,

    # keep this short: the functional tests have their own per-command timeout, and this
    # delay is added to every single bastion session while this program is configured
    SLEEP_TIME => 2,
};

sleep(SLEEP_TIME);
exit EXIT_ACTIVE;
