# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2317,SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_plugin_restrictions()
{
    # account1 will be restricted by the rules below, account2 never is
    success pr_create_a1 $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command accountCreate .value null
    success pr_create_a2 $a0 --osh accountCreate --always-active --account $account2 --uid $uid2 --public-key "\"$(cat $account2key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    # the restriction is orthogonal to the grants: both accounts are granted the commands first
    success pr_grant_a1_groupCreate $a0 --osh accountGrantCommand --command groupCreate --account $account1
    json .error_code OK .command accountGrantCommand
    success pr_grant_a1_groupDelete $a0 --osh accountGrantCommand --command groupDelete --account $account1
    json .error_code OK .command accountGrantCommand
    success pr_grant_a2_groupCreate $a0 --osh accountGrantCommand --command groupCreate --account $account2
    json .error_code OK .command accountGrantCommand

    # sanity: with no rule at all, account1 can work on any group
    success pr_a1_create_g3_unrestricted $a1 --osh groupCreate --group $group3 --algo ed25519 --owner $account1
    json .error_code OK .command groupCreate
    success pr_a1_delete_g3_unrestricted $a1 --osh groupDelete --group $group3 --no-confirm
    json .error_code OK .command groupDelete

    # from now on, account1 may only touch $group3 with groupCreate and groupDelete
    configsetjson pluginRestrictions '[{"accounts":["'$account1'"],"plugins":["groupCreate","groupDelete"],"resources":{"group":"^'$group3'$"}}]'

    success pr_a1_create_allowed_group $a1 --osh groupCreate --group $group3 --algo ed25519 --owner $account1
    json .error_code OK .command groupCreate

    plgfail pr_a1_create_denied_group $a1 --osh groupCreate --group $group1 --algo ed25519 --owner $account1
    json .error_code KO_RESTRICTED_RESOURCE .command groupCreate
    contain "the group you use this command on must match"

    # account2 isn't listed in the rule, so the very same command is allowed
    success pr_a2_create_denied_group $a2 --osh groupCreate --group $group1 --algo ed25519 --owner $account2
    json .error_code OK .command groupCreate

    # the rule applies to every command it lists, not just the first one
    plgfail pr_a1_delete_denied_group $a1 --osh groupDelete --group $group1 --no-confirm
    json .error_code KO_RESTRICTED_RESOURCE .command groupDelete

    success pr_a1_delete_allowed_group $a1 --osh groupDelete --group $group3 --no-confirm
    json .error_code OK .command groupDelete

    # a command that isn't listed in any rule is never restricted
    success pr_a1_info_not_restricted $a1 --osh info
    json .error_code OK .command info .value.account $account1

    # a rule naming a resource the command doesn't have can't be enforced, so it denies outright
    configsetjson pluginRestrictions '[{"accounts":["'$account1'"],"plugins":["groupList"],"resources":{"group":"^'$group3'$"}}]'
    code_warn_exclude="pluginRestrictions"
    plgfail pr_a1_unenforceable_rule $a1 --osh groupList
    json .error_code KO_RESTRICTED_RESOURCE .command groupList
    contain "can't be enforced"

    # ... and only for the accounts it lists
    success pr_a2_unenforceable_rule_other_account $a2 --osh groupList
    json .error_code OK .command groupList

    # ---- the same rule shape, on the account resource ----

    success pr_grant_a1_accountCreate $a0 --osh accountGrantCommand --command accountCreate --account $account1
    json .error_code OK .command accountGrantCommand
    success pr_grant_a1_accountModify $a0 --osh accountGrantCommand --command accountModify --account $account1
    json .error_code OK .command accountGrantCommand
    success pr_grant_a1_accountDelete $a0 --osh accountGrantCommand --command accountDelete --account $account1
    json .error_code OK .command accountGrantCommand

    # account1 may only ever act on $account3, never on $account4
    configsetjson pluginRestrictions '[{"accounts":["'$account1'"],"plugins":["accountCreate","accountModify","accountDelete"],"resources":{"account":"^'$account3'$"}}]'

    plgfail pr_a1_create_denied_account $a1 --osh accountCreate --always-active --account $account4 --uid $uid4 --public-key "\"$(cat $account4key1file.pub)\""
    json .error_code KO_RESTRICTED_RESOURCE .command accountCreate
    contain "the account you use this command on must match"

    success pr_a1_create_allowed_account $a1 --osh accountCreate --always-active --account $account3 --uid $uid3 --public-key "\"$(cat $account3key1file.pub)\""
    json .error_code OK .command accountCreate

    # the rule applies to every command it lists
    success pr_a1_modify_allowed_account $a1 --osh accountModify --account $account3 --osh-only yes
    json .error_code OK .command accountModify
    success pr_a1_modify_back_allowed_account $a1 --osh accountModify --account $account3 --osh-only no
    json .error_code OK .command accountModify

    # a0 creates $account4 so that account1 has an existing account it may not touch
    success pr_a0_create_a4 $a0 --osh accountCreate --always-active --account $account4 --uid $uid4 --public-key "\"$(cat $account4key1file.pub)\""
    json .error_code OK .command accountCreate

    plgfail pr_a1_modify_denied_account $a1 --osh accountModify --account $account4 --osh-only yes
    json .error_code KO_RESTRICTED_RESOURCE .command accountModify

    plgfail pr_a1_delete_denied_account $a1 --osh accountDelete --account $account4 --no-confirm
    json .error_code KO_RESTRICTED_RESOURCE .command accountDelete

    # $account4 must still be there, and a0 isn't listed in the rule so it can delete it
    success pr_a0_delete_a4 $a0 --osh accountDelete --account $account4 --no-confirm
    json .error_code OK .command accountDelete

    success pr_a1_delete_allowed_account $a1 --osh accountDelete --account $account3 --no-confirm
    json .error_code OK .command accountDelete

    # cleanup
    configsetjson pluginRestrictions '[]'
    success pr_delete_g1 $a0 --osh groupDelete --group $group1 --no-confirm
    json .error_code OK .command groupDelete
    success pr_delete_a1 $a0 --osh accountDelete --account $account1 --no-confirm
    json .error_code OK .command accountDelete
    success pr_delete_a2 $a0 --osh accountDelete --account $account2 --no-confirm
    json .error_code OK .command accountDelete
}

testsuite_plugin_restrictions
unset -f testsuite_plugin_restrictions
