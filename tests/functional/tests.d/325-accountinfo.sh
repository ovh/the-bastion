# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_accountinfo()
{
    # create regular account to compare info access between auditor and non auditor
    success a0_create_a1 $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    # create another target account we'll use for accountInfo
    success a0_create_a2 $a0 --osh accountCreate --always-active --account $account2 --uid $uid2 --public-key "\"$(cat $account2key1file.pub)\"" --comment "\"'this is a comment'\""
    json .error_code OK .command accountCreate .value null

    # create a third account with a ttl
    local ttl_account_seconds
    ttl_account_seconds=55
    success a0_create_a3 $a0 --osh accountCreate --always-active --account $account3 --uid $uid3 --public-key "\"$(cat $account3key1file.pub)\"" --ttl ${ttl_account_seconds}s
    json .error_code OK .command accountCreate .value null
    local ttl_account_created_at
    ttl_account_created_at=$(date +%s)

    # check that account3 can connect during their TTL
    success a3_ttl_connect $a3 --osh info
    json .error_code OK

    # grant accountInfo to a1
    success a0_grant_a1_accountinfo $a0 --osh accountGrantCommand --command accountInfo --account $account1

    # check that account3 info has the ttl in it
    success a0_info_a3_ttl $a0 --osh accountInfo --account $account3
    json .error_code OK .value.is_ttl_expired 0

    # a1 should see basic info about a2
    success a1_accountinfo_a2_basic $a1 --osh accountInfo --account $account2
    json .error_code OK .command accountInfo
    json .value.account "$account2"
    json .value.always_active 1
    json .value.always_active_reason "account local configuration"
    json .value.is_active 1
    json .value.allowed_commands '[]'
    json .value.groups '{}'

    # a0 should see detailed info about a2
    success a0_accountinfo_a2_detailed $a0 --osh accountInfo --account $account2 --with-mfa-password-info
    json $(cat <<EOS
    .error_code OK
    .command accountInfo
    .value.always_active 1
    .value.is_active 1
    .value.allowed_commands []
    .value.ingress_piv_policy null
    .value.personal_egress_mfa_required none
    .value.pam_auth_bypass 0
    .value.password.min_days 0
    .value.password.user $account2
    .value.password.password locked
    .value.password.inactive_days -1
    .value.password.date_disabled null
    .value.password.date_disabled_timestamp 0
    .value.ingress_piv_enforced 0
    .value.always_active 1
    .value.creation_information.by $account0
    .value.already_seen_before 0
    .value.last_activity null
    .value.max_inactive_days null
    .value.is_ttl_expired 0
    .value.ttl_timestamp null
EOS
)
    json .value.creation_information.comment "this is a comment"
    if [ "$OS_FAMILY" = Linux ]; then
        json .value.password.date_changed $(date +%Y-%m-%d)
    fi

    # a2 connects, which will update already_seen_before
    success a2_connects $a2 --osh info
    json .command info .error_code OK

    # a0 should see the updated fields
    success a0_accountinfo_a2_detailed2 $a0 --osh accountInfo --account $account2
    json .value.already_seen_before 1
    contain "Last seen on"

    # try to unlock
    run a0_unlock_a1 $a0 --osh accountUnlock --account $account1
    json .command accountUnlock
    if [ "$OS_FAMILY" = Linux ]; then
        retvalshouldbe 0
        json .error_code OK
    else
        retvalshouldbe 100
        json .error_code ERR_UNSUPPORTED_FEATURE
    fi

    # a0 changes a2 expiration policy
    success a0_accountmodify_a2_expi_15 $a0 --osh accountModify --account $account2 --max-inactive-days 15

    # a0 should see the updated field
    success a0_accountinfo_a2_inactive_days $a0 --osh accountInfo --account $account2
    json .value.max_inactive_days 15

    # a0 changes a2 expiration policy
    success a0_accountmodify_a2_expi_disabled $a0 --osh accountModify --account $account2 --max-inactive-days 0

    # a0 should see the updated field
    success a0_accountinfo_a2_inactive_days_disabled $a0 --osh accountInfo --account $account2
    json .value.max_inactive_days 0

    # a0 changes a2 expiration policy
    success a0_accountmodify_a2_expi_default $a0 --osh accountModify --account $account2 --max-inactive-days -1

    # a0 should see the updated field
    success a0_accountinfo_a2_inactive_days_default $a0 --osh accountInfo --account $account2
    json .value.max_inactive_days null

    # should work with accountcreate too
    success a0_accountcreate_a4_max_inactive_days $a0 --osh accountCreate --account $account4 --uid $uid4 --max-inactive-days 42 --no-key

    success a0_accountinfo_a4_max_inactive_days $a0 --osh accountInfo --account $account4
    json .value.max_inactive_days 42

    # take the opportunity to test --all
    success a0_accountinfo_all $a0 --osh accountInfo --all
    json $(cat <<EOS
    .command accountInfo
    .error_code OK
    .value|length  6
    .value["$account4"].creation_information.by $account0
    .value["$account4"].personal_egress_mfa_required none
    .value["healthcheck"].allowed_commands|length 0
    .value["$account0"].max_inactive_days null
EOS
)

    # --all should not work when not auditor
    plgfail a1_accountinfo_all_no_auditor $a1 --osh accountInfo --all
    json .command accountInfo .error_code ERR_ACCESS_DENIED .value null

    # sleep to ensure TTL has expired. add 2 seconds to be extra-sure and avoid int-rounding errors
    local sleep_for
    sleep_for=$(( ttl_account_seconds - ( $(date +%s) - ttl_account_created_at ) + 2 ))
    if [ "$COUNTONLY" != 1 ] && [ $sleep_for -gt 0 ]; then
        sleep $sleep_for
    fi

    # check that account3 can no longer connect due to their TTL
    run a3_ttl_connect_no $a3 --osh info
    retvalshouldbe 121
    contain 'TTL has expired'

    success a0_info_a3_ttl_no $a0 --osh accountInfo --account $account3
    json .error_code OK .value.is_ttl_expired 1

    # lock account2
    success a0_freeze_a2 $a0 --osh accountFreeze --account $account2 --reason "\"'cest la vie'\""
    json .command accountFreeze .error_code OK .value.account $account2 .value.reason "cest la vie"

    success a0_freeze_a2_dupe $a0 --osh accountFreeze --account $account2
    json .command accountFreeze .error_code OK_NO_CHANGE

    # ensure account2 can no longer connect
    run a2_cannot_connect_frozen $a2 --osh info
    contain "is frozen"
    retvalshouldbe 131

    # unlock account2
    success a0_unfreeze_a2 $a0 --osh accountUnfreeze --account $account2
    json .command accountUnfreeze .error_code OK .value.account $account2

    success a0_unfreeze_a2_dupe $a0 --osh accountUnfreeze --account $account2
    json .command accountUnfreeze .error_code OK_NO_CHANGE

    # ensure account2 can connect again
    success a2_can_connect_again $a2 --osh info
    nocontain "is frozen"

    # delete account1 & account2
    success a0_delete_a1 $a0 --osh accountDelete --account $account1 --no-confirm
    success a0_delete_a2 $a0 --osh accountDelete --account $account2 --no-confirm
    success a0_delete_a3 $a0 --osh accountDelete --account $account3 --no-confirm
    success a0_delete_a4 $a0 --osh accountDelete --account $account4 --no-confirm
}

testsuite_accountinfo
unset -f testsuite_accountinfo
