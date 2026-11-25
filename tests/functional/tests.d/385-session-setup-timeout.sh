# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2317,SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_session_setup_timeout()
{
    # a plain non-admin account: it must NOT be always-active, otherwise the activeness check
    # program (which we use below to slow down the session setup phase) would be skipped for it
    success sst_create_a1 $a0 --osh accountCreate --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    # grant an access to 127.0.0.1, just so that the connection code path goes all the way to
    # connect.pl (even if the egress connection doesn't make it through in the end)
    success sst_add_access_a1 $a0 --osh accountAddPersonalAccess --account $account1 --host 127.0.0.1 --user sst --port 22
    json .command accountAddPersonalAccess

    # now, make every session setup phase take ~2 seconds, by using an activeness check
    # program that waits before declaring the account as active
    configsetquoted accountExternalValidationProgram /opt/bastion/bin/other/slow-check-active-account-fortestsonly.pl

    # with a 1 second deadline, the setup phase is always too slow: the requested action must
    # be refused instead of being launched with stale verifications

    configset sessionSetupTimeout 1

    run sst_plugin_denied $a1 --osh info
    retvalshouldbe 136
    json .error_code KO_SETUP_TIMEOUT
    contain "Too much time has passed"

    run sst_connection_denied $a1 sst@127.0.0.1 -- echo notreached
    retvalshouldbe 136
    json .error_code KO_SETUP_TIMEOUT
    contain "Too much time has passed"
    nocontain "notreached"

    # with a deadline that is not exceeded, the very same actions are launched as usual:
    # this ensures we're testing the deadline and not the slowness itself

    configset sessionSetupTimeout 30

    success sst_plugin_allowed $a1 --osh info
    json .error_code OK .command info

    # 255 is the egress ssh failure: we don't have a valid key on the target, but we did
    # reach connect.pl, which is what we're testing here
    run sst_connection_allowed $a1 sst@127.0.0.1 -- echo notreached
    retvalshouldbe 255
    contain "allowed ... log on"
    nocontain "Too much time has passed"

    # a value of 0 disables the feature entirely

    configset sessionSetupTimeout 0

    success sst_plugin_disabled $a1 --osh info
    json .error_code OK .command info

    # cleanup: disable the slow activeness check program before doing anything else, or the
    # admin account might get caught by the deadline too
    configsetquoted accountExternalValidationProgram ''

    success sst_del_a1 $a0 --osh accountDelete --account $account1 --no-confirm
    json .command accountDelete .error_code OK
}

testsuite_session_setup_timeout
unset -f testsuite_session_setup_timeout
