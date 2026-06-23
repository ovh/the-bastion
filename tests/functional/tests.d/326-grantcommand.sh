# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2317,SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_grantcommand()
{
    # create account1: it will be a plain non-admin that only holds the accountGrantCommand right
    success a0_create_a1 $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    # create account2: the target of the (attempted) grants
    success a0_create_a2 $a0 --osh accountCreate --always-active --account $account2 --uid $uid2 --public-key "\"$(cat $account2key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    # sanity: account1 has no rights yet, so it can't run accountGrantCommand at all
    run a1_grant_denied_no_right $a1 --osh accountGrantCommand --command accountInfo --account $account2
    retvalshouldbe 106
    json .error_code KO_RESTRICTED_COMMAND .command null

    # give account1 the accountGrantCommand right (Unix group membership), but NOT admin/superowner
    success grant_a1_the_grantcommand_right $r0 "\". $opt_remote_basedir/lib/shell/functions.inc; add_user_to_group_compat $account1 osh-accountGrantCommand\""

    # positive control: account1 may now grant a *normal* restricted command (here: accountInfo).
    success a1_grant_normal_command_ok $a1 --osh accountGrantCommand --command accountInfo --account $account2
    json .error_code OK .command accountGrantCommand

    # non-admin grantor must NOT be able to grant accountGrantCommand
    plgfail a1_grant_grantcommand_refused $a1 --osh accountGrantCommand --command accountGrantCommand --account $account2
    json .error_code ERR_SECURITY_VIOLATION .command accountGrantCommand

    # same for accountRevokeCommand
    plgfail a1_grant_revokecommand_refused $a1 --osh accountGrantCommand --command accountRevokeCommand --account $account2
    json .error_code ERR_SECURITY_VIOLATION .command accountGrantCommand

    # the refused grants must not have taken effect, so account2 still cannot run accountGrantCommand
    run a2_still_cannot_grantcommand $a2 --osh accountGrantCommand --command accountInfo --account $account1
    retvalshouldbe 106
    json .error_code KO_RESTRICTED_COMMAND .command null

    # a bastion admin (a0) IS allowed to grant it
    success a0_grant_grantcommand_ok $a0 --osh accountGrantCommand --command accountGrantCommand --account $account2
    json .error_code OK .command accountGrantCommand

    # cleanup
    success a0_delete_a1 $a0 --osh accountDelete --account $account1 --no-confirm
    json .command accountDelete .error_code OK
    success a0_delete_a2 $a0 --osh accountDelete --account $account2 --no-confirm
    json .command accountDelete .error_code OK
}

testsuite_grantcommand
unset -f testsuite_grantcommand
