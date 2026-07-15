# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2317,SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_maintenance()
{
    local reason=maintenance_reason_test

    # a plain non-admin account we use to prove logins are denied while locked
    success maint_create_a1 $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    # adminMaintenance is admin-only: the non-admin account may not run it at all
    run maint_a1_denied $a1 --osh adminMaintenance --unlock
    retvalshouldbe 106
    json .error_code KO_RESTRICTED_COMMAND .command null

    # parameter validation
    plgfail maint_missing_param $a0 --osh adminMaintenance
    json .command adminMaintenance .error_code ERR_MISSING_PARAMETER
    plgfail maint_incompatible_params $a0 --osh adminMaintenance --lock --unlock
    json .command adminMaintenance .error_code ERR_INCOMPATIBLE_PARAMETERS

    # lock the bastion with a reason
    success maint_lock $a0 --osh adminMaintenance --lock --message "$reason"
    json .command adminMaintenance .error_code OK

    # a non-admin login is now refused with the maintenance exit code, and told the reason. Note the
    # maintenance gate in osh.pl fires before command-line options are parsed, so there is no JSON
    # envelope here (--json-greppable hasn't taken effect yet): we assert on the exit code and the
    # human-readable output instead.
    run maint_a1_login_denied $a1 --osh info
    retvalshouldbe 118
    contain "maintenance mode"
    contain "$reason"

    # an admin is let through anyway (with a warning), so the bastion stays manageable while locked
    success maint_a0_bypass $a0 --osh info
    json .command info .error_code OK
    contain "allowing anyway"

    # unlock the bastion
    success maint_unlock $a0 --osh adminMaintenance --unlock
    json .command adminMaintenance .error_code OK

    # the non-admin account can log in again
    success maint_a1_login_ok $a1 --osh info
    json .command info .error_code OK

    # cleanup
    success maint_del_a1 $a0 --osh accountDelete --account $account1 --no-confirm
    json .command accountDelete .error_code OK
}

testsuite_maintenance
unset -f testsuite_maintenance
