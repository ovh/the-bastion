# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_accountinfo()
{
    grant accountCreate
    # create regular account to compare info access between auditor and non auditor
    success a0_create_a1 $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    # create another target account we'll use for accountInfo
    success a0_create_a2 $a0 --osh accountCreate --always-active --account $account2 --uid $uid2 --public-key "\"$(cat $account2key1file.pub)\"" --comment "\"'this is a comment'\""
    json .error_code OK .command accountCreate .value null
    revoke accountCreate

    # grant account0 as admin
    success set_a0_as_admin $r0 "\". $opt_remote_basedir/lib/shell/functions.inc; add_user_to_group_compat $account0 osh-admin\""
    configchg 's=^\\\\x22adminAccounts\\\\x22.+=\\\\x22adminAccounts\\\\x22:[\\\\x22'"$account0"'\\\\x22],='

    # grant account1 as auditor
    success a0_grant_a1_as_auditor $a0 --osh accountGrantCommand --command auditor --account $account1

    # grant accountInfo to a0 and a1
    success a0_grant_a0_accountinfo $a0 --osh accountGrantCommand --command accountInfo --account $account0
    success a0_grant_a1_accountinfo $a0 --osh accountGrantCommand --command accountInfo --account $account1

    # a0 should see basic info about a2
    success a0_accountinfo_a2_basic $a0 --osh accountInfo --account $account2
    json_document '{"error_message":"OK","command":"accountInfo","error_code":"OK","value":{"always_active":1,"is_active":1,"allowed_commands":[],"groups":{}}}'

    # a1 should see detailed info about a2
    success a1_accountinfo_a2_detailed $a1 --osh accountInfo --account $account2
    json .error_code OK .command accountInfo .value.always_active 1 .value.is_active 1 .value.allowed_commands "[]"
    json .value.ingress_piv_policy null .value.personal_egress_mfa_required none .value.pam_auth_bypass 0
    json .value.password.min_days 0 .value.password.warn_days 7 .value.password.user "$account2" .value.password.password locked
    json .value.password.inactive_days -1 .value.password.date_disabled null .value.password.date_disabled_timestamp 0 .value.password.date_changed $(date +%Y-%m-%d)
    json .value.ingress_piv_enforced 0 .value.always_active 1 .value.creation_information.by "$account0"
    json .value.creation_information.comment "this is a comment"
    json .value.already_seen_before 0 .value.last_activity null
    json .value.max_inactive_days null

    # a2 connects, which will update already_seen_before
    success a2_connects $a2 --osh info
    json .command info .error_code OK

    # a1 should see the updated fields
    success a1_accountinfo_a2_detailed2 $a1 --osh accountInfo --account $account2
    json .value.already_seen_before 1
    contain "Last seen on"

    grant accountModify

    # a0 changes a2 expiration policy
    success a0_accountmodify_a2_expi_15 $a0 --osh accountModify --account $account2 --max-inactive-days 15

    # a1 should see the updated field
    success a1_accountinfo_a2_inactive_days $a1 --osh accountInfo --account $account2
    json .value.max_inactive_days 15

    # a0 changes a2 expiration policy
    success a0_accountmodify_a2_expi_disabled $a0 --osh accountModify --account $account2 --max-inactive-days 0

    # a1 should see the updated field
    success a1_accountinfo_a2_inactive_days_disabled $a1 --osh accountInfo --account $account2
    json .value.max_inactive_days 0

    # a0 changes a2 expiration policy
    success a0_accountmodify_a2_expi_default $a0 --osh accountModify --account $account2 --max-inactive-days -1

    # a1 should see the updated field
    success a1_accountinfo_a2_inactive_days_default $a1 --osh accountInfo --account $account2
    json .value.max_inactive_days null

    # should work with accountcreate too
    grant accountCreate
    success a0_accountcreate_a4_max_inactive_days $a0 --osh accountCreate --account $account4 --uid $uid4 --max-inactive-days 42 --no-key
    revoke accountCreate

    grant auditor
    success a0_accountinfo_a4_max_inactive_days $a0 --osh accountInfo --account $account4
    json .value.max_inactive_days 42
    revoke auditor

    revoke accountModify

    # delete account1 & account2
    grant accountDelete
    success a0_delete_a1 $a0 --osh accountDelete --account $account1 --no-confirm
    success a0_delete_a2 $a0 --osh accountDelete --account $account2 --no-confirm
    success a0_delete_a4 $a0 --osh accountDelete --account $account4 --no-confirm
    revoke accountDelete
}

testsuite_accountinfo
unset -f testsuite_accountinfo
