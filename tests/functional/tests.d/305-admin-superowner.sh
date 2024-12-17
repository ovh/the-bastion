# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_admin_superowner()
{
    # create account1
    success create_a1 $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    # create a group, account1 is not a member or anything
    success create_g1 $a0 --osh groupCreate --owner $account0 --no-key --group $group1
    json .error_code OK .command groupCreate

    # account1 can't add members
    run a1_add_members_g1_fail $a1 --osh groupAddMember --group $group1 --account $account1
    retvalshouldbe 106
    json .error_code KO_RESTRICTED_COMMAND .command null

    # now set account1 as superowner
    success set_a1_as_superowner $r0 "\". $opt_remote_basedir/lib/shell/functions.inc; add_user_to_group_compat $account1 osh-superowner\""
    configchg 's=^\\\\x22superOwnerAccounts\\\\x22.+=\\\\x22superOwnerAccounts\\\\x22:[\\\\x22'"$account1"'\\\\x22],='

    # account1 now can add/del members
    success a1_add_members_g1_ok $a1 --osh groupAddMember --group $group1 --account $account1
    json .error_code OK .command groupAddMember
    contain OVERRIDE

    success a1_del_members_g1_ok $a1 --osh groupDelMember --group $group1 --account $account1
    json .error_code OK .command groupDelMember
    contain OVERRIDE

    # now set account1 as admin
    success set_a1_as_admin $r0 "\". $opt_remote_basedir/lib/shell/functions.inc; add_user_to_group_compat $account1 osh-admin\""
    configchg 's=^\\\\x22adminAccounts\\\\x22.+=\\\\x22adminAccounts\\\\x22:[\\\\x22'"$account0"'\\\\x22,\\\\x22'"$account1"'\\\\x22],='

    # account1 now can add/del aclkeepers
    success a1_add_gk_g1_ok $a1 --osh groupAddAclkeeper --group $group1 --account $account1
    json .error_code OK .command groupAddAclkeeper
    contain OVERRIDE

    success a1_del_gk_g1_ok $a1 --osh groupDelAclkeeper --group $group1 --account $account1
    json .error_code OK .command groupDelAclkeeper
    contain OVERRIDE

    # now remove superowner grant from a1, the account is still admin so it should inherhit superowner powers
    success del_a1_as_superowner $r0 "\". $opt_remote_basedir/lib/shell/functions.inc; del_user_from_group_compat $account1 osh-superowner\""
    configchg 's=^\\\\x22superOwnerAccounts\\\\x22.+=\\\\x22superOwnerAccounts\\\\x22:[],='

    # account1 can add/del gatekeepers
    success a1_add_members_g1_ok2 $a1 --osh groupAddGatekeeper --group $group1 --account $account1
    json .error_code OK .command groupAddGatekeeper
    contain OVERRIDE

    success a1_del_members_g1_ok2 $a1 --osh groupDelGatekeeper --group $group1 --account $account1
    json .error_code OK .command groupDelGatekeeper
    contain OVERRIDE

    # and finally remove admin grant
    success del_a1_as_admin $r0 "\". $opt_remote_basedir/lib/shell/functions.inc; del_user_from_group_compat $account1 osh-admin\""
    configchg 's=^\\\\x22adminAccounts\\\\x22.+=\\\\x22adminAccounts\\\\x22:[\\\\x22'"$account0"'\\\\x22],='

    # account1 can no longer add members
    run a1_add_members_g1_fail2 $a1 --osh groupAddMember --group $group1 --account $account1
    retvalshouldbe 106
    json .error_code KO_RESTRICTED_COMMAND .command null

    script delete_a1 $a0 --osh accountDelete --account $account1 "<<< \"Yes, do as I say and delete $account1, kthxbye\""
    retvalshouldbe 0
    json .command accountDelete .error_code OK

    script delete_g1 "$a0 --osh groupDelete --group $group1 <<< $group1"
    retvalshouldbe 0
    json .command groupDelete .error_code OK
}

testsuite_admin_superowner
unset -f testsuite_admin_superowner
