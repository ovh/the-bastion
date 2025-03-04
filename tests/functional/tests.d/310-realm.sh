# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2317,SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_realm()
{
    local realm_egress_group=realm
    local realm_shared_account=UniVerse

    # create account1 on local bastion
    success create_account1 $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key \""$(cat $account1key1file.pub)"\"
    json .error_code OK .command accountCreate .value null
    success modify_account1 $a0 --osh accountModify --pam-auth-bypass yes --account $account1
    json .error_code OK .command accountModify

    # create account2 on local bastion
    success create_account2 $a0 --osh accountCreate --always-active --account $account2 --uid $uid2 --public-key \""$(cat $account2key1file.pub)"\"
    json .error_code OK .command accountCreate .value null
    success modify_account1 $a0 --osh accountModify --pam-auth-bypass yes --account $account2
    json .error_code OK .command accountModify

    # create realm-egress group on local bastion
    success create_support_group $a0 --osh groupCreate --group $realm_egress_group --owner $account0 --algo rsa --size 4096
    local realm_group_key
    realm_group_key=$(get_json | $jq '.value.public_key.line')

    success a0_delowner_egressgroup $a0 --osh groupDelOwner --group $realm_egress_group --account $account0

    # add account1 to this group on local bastion
    success add_account1_to_support_group $a0 --osh groupAddMember --group $realm_egress_group --account $account1

    # add account1 to this group on local bastion
    success add_account2_to_support_group $a0 --osh groupAddMember --group $realm_egress_group --account $account2

    # fail to create a realm with forbidden name
    plgfail realm_forbidden_name $a0 --osh realmCreate --realm realm --from 0.0.0.0/0 --public-key \"$realm_group_key\"

    # fail to create account with forbidden name
    plgfail account_forbidden_name $a0 --osh accountCreate --account realm_foobar --uid-auto --public-key \""$(cat $account1key1file.pub)"\"

    # create shared realm-account on remote bastion
    success create_shared_account $a0 --osh realmCreate --realm $realm_shared_account --public-key \"$realm_group_key\" --from 0.0.0.0/0

    # add remote bastion ip on group of local bastion
    success add_remote_bastion_to_group $a0 --osh groupAddServer --host 127.0.0.1 --user realm_$realm_shared_account --port 22 --group $realm_egress_group --kbd-interactive

    # attempt inter-realm connection
    success firstconnect1 $a1 realm_$realm_shared_account@127.0.0.1 --kbd-interactive -- $js --osh info
    json .value.account $account1 .value.realm $realm_shared_account

    # attempt inter-realm connection
    success firstconnect2 $a2 realm_$realm_shared_account@127.0.0.1 --kbd-interactive -- $js --osh info
    json .value.account $account2 .value.realm $realm_shared_account

    # try forbidden plugins
    for plugin in selfAddPersonalAccess selfAddIngressKey selfDelIngressKey selfGenerateEgressKey selfAddPersonalAccess selfDelPersonalAccess selfPlaySession selfListSessions selfResetIngressKeys
    do
            run plugindenied $a2 realm_$realm_shared_account@127.0.0.1 --kbd-interactive -- $js --osh $plugin
            retvalshouldbe 106
            json .error_message "Realm accounts can't execute this plugin, use --osh help to get the allowed plugin list" .error_code KO_RESTRICTED_COMMAND
    done
    unset plugin

    # add an access to account1 from realm on remote bastion
    success add_access_to_remote $a0 --osh accountAddPersonalAccess --account $realm_shared_account/$account1 --user-any --port-any --host 127.0.0.5
    json .error_code OK

    # fail to add a dup access to account1 from realm on remote bastion
    success add_access_to_remote_dup $a0 --osh accountAddPersonalAccess --account $realm_shared_account/$account1 --user-any --port-any --host 127.0.0.5
    json .error_code OK_NO_CHANGE

    # list accesses remotely
    success list_my_accesses1 $a1 realm_$realm_shared_account@127.0.0.1 --kbd-interactive -- $js --osh selfListAccesses
    json .error_code OK .value[0].acl[0].addedBy $account0 .value[0].acl[0].ip 127.0.0.5

    # list accesses remotely
    success list_my_accesses2 $a2 realm_$realm_shared_account@127.0.0.1 --kbd-interactive -- $js --osh selfListAccesses
    json .error_code OK_EMPTY

    # try to access remotely (success)
    run access1 $a1 realm_$realm_shared_account@127.0.0.1 --kbd-interactive -- test@127.0.0.5
    retvalshouldbe 255
    nocontain 'Access denied'
    contain 'will try the following accesses you have'

    # try to access remotely (fail)
    run access2 $a2 realm_$realm_shared_account@127.0.0.1 --kbd-interactive -- test@127.0.0.5
    retvalshouldbe 107
    contain "Access denied for $realm_shared_account/$account2 to test@127.0.0.5:22"

    # create a group on remote bastion
    success create_normal_group $a0 --osh groupCreate --group $group1 --owner $account0 --algo rsa --size 4096

    # can't add a realm user as gk, aclk or owner of group
    for acc in "realm_$realm_shared_account" "$realm_shared_account/$account1"
    do
        for role in Owner Gatekeeper Aclkeeper
        do
            plgfail add_${acc}_as_$role $a0 --osh groupAdd$role --group $group1 --account $acc
            if [ "$acc" = "$realm_shared_account/$account1" ]; then
                json .error_code ERR_REALM_USER
            else
                json .error_code KO_FORBIDDEN_PREFIX
            fi
        done
    done
    unset role acc
    plgfail add_support_account_as_member $a0 --osh groupAddMember --group $group1 --account realm_$realm_shared_account

    # add account1 as member
    success add_account1_as_member $a0 --osh groupAddMember --group $group1 --account $realm_shared_account/$account1
    json .error_code OK

    success add_account1_as_member $a0 --osh groupAddMember --group $group1 --account $realm_shared_account/$account1
    json .error_code OK_NO_CHANGE

    # check groupInfo
    success groupinfo $a0 --osh groupInfo --group $group1
    json --arg want "$realm_shared_account/$account1 $account0" '.value.members|sort == ($want|split(" ")|sort)' true

    # add a remote account as member
    success add_account2_as_member $a0 --osh groupAddMember --group $group1 --account $realm_shared_account/alien
    json .error_code OK

    success add_account2_as_member $a0 --osh groupAddMember --group $group1 --account $realm_shared_account/alien
    json .error_code OK_NO_CHANGE

    # check groupInfo
    success groupinfo $a0 --osh groupInfo --group $group1
    json --arg want "$realm_shared_account/$account1 $realm_shared_account/alien $account0" '.value.members|sort == ($want|split(" ")|sort)' true

    # add a dummy host to the group, to see it in the accountListAccesses afterwards
    success add_server_to_group1 $a0 --osh groupAddServer --group $group1 --host 172.16.4.4 --user nobody --port 12345 --force
    success add_server_to_group1 $a0 --osh groupAddServer --group $group1 --host 172.16.4.4 --user nobody --port 12346 --force

    success removemyselffromaclk $a0 --osh groupDelAclkeeper --group $group1 --account $account0
    success a0_delowner_group1 $a0 --osh groupDelOwner --group $group1 --account $account0

    # check access list
    success access_list_account1 $a0 --osh accountListAccesses --account $realm_shared_account/$account1
    json '.value|[.[]|.type]|sort' '["group-member","personal"]'
    json '.value[]|select(.type == "personal")|.acl[]|.ip' 127.0.0.5
    json '.value[]|select(.type == "group-member")|[.acl[]|.port]' '["12345","12346"]'

    # revoke group membership
    success del_account1_as_member $a0 --osh groupDelMember --group $group1 --account $realm_shared_account/$account1
    json .error_code OK

    success del_account1_as_member_dup $a0 --osh groupDelMember --group $group1 --account $realm_shared_account/$account1
    json .error_code OK_NO_CHANGE

    # check groupInfo
    success groupinfo $a0 --osh groupInfo --group $group1
    json --arg want "$realm_shared_account/alien $account0" '.value.members|sort == ($want|split(" ")|sort)' true

    # check access list
    success access_list_account1_again $a0 --osh accountListAccesses --account $realm_shared_account/$account1
    json '.value|[.[]|.type]|sort' '["personal"]'
    json '.value[]|select(.type == "personal")|.acl[]|.ip' 127.0.0.5

    # check access list
    success access_list_account2_again $a0 --osh accountListAccesses --account $realm_shared_account/alien
    json '.value|[.[]|.type]|sort' '["group-member"]'
    json '.value[]|select(.type == "group-member")|[.acl[]|.port]' '["12345","12346"]'

    # revoke group membership
    success del_account2_as_member $a0 --osh groupDelMember --group $group1 --account $realm_shared_account/alien
    json .error_code OK

    success del_account2_as_member_dup $a0 --osh groupDelMember --group $group1 --account $realm_shared_account/alien
    json .error_code OK_NO_CHANGE

    # check groupInfo
    success groupinfo $a0 --osh groupInfo --group $group1
    json '.value.members|sort' "[\"$account0\"]"

    # add guest access
    success add_guest_account1 $a0 --osh groupAddGuestAccess --account $realm_shared_account/first --group $group1 --host 172.16.4.4 --user nobody --port 12345
    success add_guest_account1 $a0 --osh groupAddGuestAccess --account $realm_shared_account/first --group $group1 --host 172.16.4.4 --user nobody --port 12346

    # add other guest access
    success add_guest_account2 $a0 --osh groupAddGuestAccess --account $realm_shared_account/second --group $group1 --host 172.16.4.4 --user nobody --port 12345

    # check groupInfo
    success groupinfo $a0 --osh groupInfo --group $group1
    json '.value.members|sort' "[\"$account0\"]"
    json '.value.guests|sort' "[\"$realm_shared_account/first\",\"$realm_shared_account/second\"]"

    # check access list of account
    success access_list_account1_guest $a0 --osh accountListAccesses --account $realm_shared_account/first
    json '.value|[.[]|.type]|sort' '["group-guest"]'
    json '.value[]|select(.type == "group-guest")|[.acl[]|.port]' '["12345","12346"]'

    # remove guest access 1
    success del_guest_account1 $a0 --osh groupDelGuestAccess --account $realm_shared_account/first --group $group1 --host 172.16.4.4 --user nobody --port 12345
    nocontain "removed group key"

    # check access list of account
    success access_list_account1_guest $a0 --osh accountListAccesses --account $realm_shared_account/first
    json '.value|[.[]|.type]|sort' '["group-guest"]'
    json '.value[]|select(.type == "group-guest")|.acl[]|.port' 12346

    # remove guest access 1
    success del_guest_account1 $a0 --osh groupDelGuestAccess --account $realm_shared_account/first --group $group1 --host 172.16.4.4 --user nobody --port 12346
    nocontain "removed group key"

    # check groupInfo
    success groupinfo $a0 --osh groupInfo --group $group1
    json '.value.members|sort' "[\"$account0\"]"
    json '.value.guests|sort' "[\"$realm_shared_account/second\"]"

    # remove last guest access
    success del_guest_account2 $a0 --osh groupDelGuestAccess --account $realm_shared_account/second --group $group1 --host 172.16.4.4 --user nobody --port 12345
    contain "removed group key"

    # check groupInfo
    success groupinfo $a0 --osh groupInfo --group $group1
    json '.value.members|sort' "[\"$account0\"]"
    json '.value.guests|sort' "[]"

    # check max account length
    success add_guest_account3 $a0 --osh groupAddGuestAccess --account $realm_shared_account/verylongaccountnam --group $group1 --host 172.16.4.4 --user nobody --port 12345

    # delete account1
    success account1_cleanup $a0 --osh accountDelete --account $account1 --no-confirm

    # delete account2
    script account2_cleanup "$a0 --osh accountDelete --account $account2 <<< \"Yes, do as I say and delete $account2, kthxbye\""
    retvalshouldbe 0

    # delete realm-egress group
    run cleanup_realm_support_group $a0 --osh groupDelete --group $realm_egress_group --no-confirm
    retvalshouldbe 0

    # delete shared realm-account
    script cleanup_shared_realm_account_fail "$a0 --osh accountDelete --account realm_$realm_shared_account <<< \"Yes, do as I say and delete realm_$realm_shared_account, kthxbye\""
    retvalshouldbe 100
    json .error_code KO_FORBIDDEN_PREFIX

    script cleanup_shared_realm_account "$a0 --osh realmDelete --realm $realm_shared_account <<< \"Yes, do as I say and delete $realm_shared_account, kthxbye\""
    retvalshouldbe 0

    # delete group1
    script group_cleanup "$a0 --osh groupDelete --group $group1 <<< \"$group1\""
    retvalshouldbe 0
}

testsuite_realm
unset -f testsuite_realm
