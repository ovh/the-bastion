# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2317,SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

# This suite exercises a true realm setup: an *ingress* bastion A (the main test target, where the
# real accounts account1/account2 and the realm-egress group live) reaching a *remote* bastion B
# (the second instance, $target2_ip) that hosts the shared realm account and everything attached to
# it (the realm sub-accounts UniVerse/<user>, their accesses, group1, guest accesses, lastlog files).
# Operations that target the realm account or its sub-accounts therefore run on B ($b2 as admin, $r2
# as root, $b2ip as host), while the ingress-side setup stays on A ($a0/$r0).
testsuite_realm()
{
    local realm_egress_group=realm
    local realm_shared_account=UniVerse

    # this suite needs a real, separate remote bastion (B) to host the realm; bail out if the runner
    # didn't provide one
    if [ -z "${target2_ip:-}" ]; then
        echo "realm: no second bastion provided by the runner, skipping"
        return 0
    fi

    # resolve B's container name to an IP and wait for its sshd to be up
    local b2ip=""
    [ "${COUNTONLY:-}" != 1 ] && b2ip=$(wait_for_target2)

    # create account1 on the ingress bastion A
    success create_account1 $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key \""$(cat $account1key1file.pub)"\"
    json .error_code OK .command accountCreate .value null
    success modify_account1 $a0 --osh accountModify --pam-auth-bypass yes --account $account1
    json .error_code OK .command accountModify

    # create account2 on the ingress bastion A
    success create_account2 $a0 --osh accountCreate --always-active --account $account2 --uid $uid2 --public-key \""$(cat $account2key1file.pub)"\"
    json .error_code OK .command accountCreate .value null
    success modify_account1 $a0 --osh accountModify --pam-auth-bypass yes --account $account2
    json .error_code OK .command accountModify

    # create realm-egress group on the ingress bastion A
    success create_support_group $a0 --osh groupCreate --group $realm_egress_group --owner $account0 --algo rsa --size 4096
    local realm_group_key
    realm_group_key=$(get_json | $jq '.value.public_key.line')

    success a0_delowner_egressgroup $a0 --osh groupDelOwner --group $realm_egress_group --account $account0

    # add account1 to this group on the ingress bastion A
    success add_account1_to_support_group $a0 --osh groupAddMember --group $realm_egress_group --account $account1

    # add account1 to this group on the ingress bastion A
    success add_account2_to_support_group $a0 --osh groupAddMember --group $realm_egress_group --account $account2

    # fail to create a realm with forbidden name (on B, where the realm lives)
    plgfail realm_forbidden_name $b2 --osh realmCreate --realm realm --from 0.0.0.0/0 --public-key \"$realm_group_key\"

    # fail to create account with forbidden name
    plgfail account_forbidden_name $a0 --osh accountCreate --account realm_foobar --uid-auto --public-key \""$(cat $account1key1file.pub)"\"

    # create shared realm-account on the remote bastion B
    success create_shared_account $b2 --osh realmCreate --realm $realm_shared_account --public-key \"$realm_group_key\" --from 0.0.0.0/0

    # point A's egress group at B's realm account
    success add_remote_bastion_to_group $a0 --osh groupAddServer --host $b2ip --user realm_$realm_shared_account --port $remote_port --group $realm_egress_group --kbd-interactive

    # attempt inter-realm connection
    success firstconnect1 $a1 realm_$realm_shared_account@$b2ip --kbd-interactive -- $js --osh info
    json .value.account $account1 .value.realm $realm_shared_account

    # attempt inter-realm connection
    success firstconnect2 $a2 realm_$realm_shared_account@$b2ip --kbd-interactive -- $js --osh info
    json .value.account $account2 .value.realm $realm_shared_account

    # accountUnexpire on a 'realm/user' account (all done on B, where the realm account lives)
    local realm_sys="realm_$realm_shared_account"
    local realm_user="$realm_shared_account/$account1"

    # the per-remote-user lastlog file must have been created by firstconnect1 above (on B)
    success realm_lastlog_user_present $r2 "test -f /home/$realm_sys/lastlog_$account1 && echo PRESENT"
    contain PRESENT

    # with no expiration policy configured, unexpiring still refreshes the activity date and reports it
    success realm_unexpire_noexpi $b2 --osh accountUnexpire --account $realm_user
    json .command accountUnexpire .error_code OK_EXPIRATION_NOT_CONFIGURED .value.account $realm_user

    # unexpiring the realm support account (the bare realm_* sysaccount) directly is forbidden:
    # only the 'realm/user' form is a valid account to operate on, never the realm_* account itself
    plgfail realm_unexpire_sysaccount $b2 --osh accountUnexpire --account $realm_sys
    json .error_code KO_FORBIDDEN_PREFIX

    # now configure an expiration policy on B and artificially expire *only* the realm user's per-user
    # lastlog; the shared realm-account lastlog is left fresh, so a detected expiry can only come from
    # the per-user file
    configchg2 's=^\\\\x22accountMaxInactiveDays\\\\x22.+=\\\\x22accountMaxInactiveDays\\\\x22:2,='
    success realm_expire_user $r2 "touch -t 201501010101 /home/$realm_sys/lastlog_$account1"

    # accountUnexpire detects the expiry (reading the per-user file, not the fresh shared one) and reactivates
    success realm_unexpire_expired $b2 --osh accountUnexpire --account $realm_user
    json .command accountUnexpire .error_code OK .value.account $realm_user
    json '.value.days > 1000' true

    # running it again proves the per-user file was the one refreshed: it now reads as not-expired
    success realm_unexpire_again $b2 --osh accountUnexpire --account $realm_user
    json .command accountUnexpire .error_code OK_NOT_EXPIRED .value.account $realm_user

    # accountUnexpire must ALSO refresh the shared realm-account lastlog, not just the per-user file.
    # age *only* the shared file (per-user is fresh now), drop a dated reference, then unexpire: even
    # though the account isn't expired, the shared file's mtime must move past the reference, proving
    # it was really touched (a plain existence check wouldn't catch a missing refresh).
    success realm_age_shared $r2 "touch -t 201501010101 /home/$realm_sys/lastlog && touch -t 202001010101 /tmp/bastiontest_lastlog_ref"
    success realm_unexpire_refresh_shared $b2 --osh accountUnexpire --account $realm_user
    json .command accountUnexpire .error_code OK_NOT_EXPIRED .value.account $realm_user
    success realm_lastlog_shared_touched $r2 "test /home/$realm_sys/lastlog -nt /tmp/bastiontest_lastlog_ref && echo TOUCHED"
    contain TOUCHED
    success realm_ref_cleanup $r2 "rm -f /tmp/bastiontest_lastlog_ref"

    # reset the expiration policy on B for the rest of this module
    configchg2 's=^\\\\x22accountMaxInactiveDays\\\\x22.+=\\\\x22accountMaxInactiveDays\\\\x22:0,='

    # try forbidden plugins
    for plugin in selfAddPersonalAccess selfAddIngressKey selfDelIngressKey selfGenerateEgressKey selfAddPersonalAccess selfDelPersonalAccess selfPlaySession selfListSessions selfResetIngressKeys
    do
            run plugindenied $a2 realm_$realm_shared_account@$b2ip --kbd-interactive -- $js --osh $plugin
            retvalshouldbe 106
            json .error_message "Realm accounts can't execute this plugin, use --osh help to get the allowed plugin list" .error_code KO_RESTRICTED_COMMAND
    done
    unset plugin

    # add an access to account1 from realm on remote bastion B
    success add_access_to_remote $b2 --osh accountAddPersonalAccess --account $realm_shared_account/$account1 --user-any --port-any --host 127.0.0.5
    json .error_code OK

    # fail to add a dup access to account1 from realm on remote bastion B
    success add_access_to_remote_dup $b2 --osh accountAddPersonalAccess --account $realm_shared_account/$account1 --user-any --port-any --host 127.0.0.5
    json .error_code OK_NO_CHANGE

    # list accesses remotely
    success list_my_accesses1 $a1 realm_$realm_shared_account@$b2ip --kbd-interactive -- $js --osh selfListAccesses
    json .error_code OK .value[0].acl[0].addedBy $account0 .value[0].acl[0].ip 127.0.0.5

    # list accesses remotely
    success list_my_accesses2 $a2 realm_$realm_shared_account@$b2ip --kbd-interactive -- $js --osh selfListAccesses
    json .error_code OK_EMPTY

    # try to access remotely (success)
    run access1 $a1 realm_$realm_shared_account@$b2ip --kbd-interactive -- test@127.0.0.5
    retvalshouldbe 255
    nocontain 'Access denied'
    contain 'will try the following accesses you have'

    # try to access remotely (fail)
    run access2 $a2 realm_$realm_shared_account@$b2ip --kbd-interactive -- test@127.0.0.5
    retvalshouldbe 107
    contain "Access denied for $realm_shared_account/$account2 to test@127.0.0.5:22"

    # create a group on remote bastion B
    success create_normal_group $b2 --osh groupCreate --group $group1 --owner $account0 --algo rsa --size 4096

    # can't add a realm user as gk, aclk or owner of group
    for acc in "realm_$realm_shared_account" "$realm_shared_account/$account1"
    do
        for role in Owner Gatekeeper Aclkeeper
        do
            plgfail add_${acc}_as_$role $b2 --osh groupAdd$role --group $group1 --account $acc
            if [ "$acc" = "$realm_shared_account/$account1" ]; then
                json .error_code ERR_REALM_USER
            else
                json .error_code KO_FORBIDDEN_PREFIX
            fi
        done
    done
    unset role acc
    plgfail add_support_account_as_member $b2 --osh groupAddMember --group $group1 --account realm_$realm_shared_account

    # add account1 as member
    success add_account1_as_member $b2 --osh groupAddMember --group $group1 --account $realm_shared_account/$account1
    json .error_code OK

    success add_account1_as_member $b2 --osh groupAddMember --group $group1 --account $realm_shared_account/$account1
    json .error_code OK_NO_CHANGE

    # check groupInfo
    success groupinfo $b2 --osh groupInfo --group $group1
    json --arg want "$realm_shared_account/$account1 $account0" '.value.members|sort == ($want|split(" ")|sort)' true

    # add a remote account as member
    success add_account2_as_member $b2 --osh groupAddMember --group $group1 --account $realm_shared_account/alien
    json .error_code OK

    success add_account2_as_member $b2 --osh groupAddMember --group $group1 --account $realm_shared_account/alien
    json .error_code OK_NO_CHANGE

    # check groupInfo
    success groupinfo $b2 --osh groupInfo --group $group1
    json --arg want "$realm_shared_account/$account1 $realm_shared_account/alien $account0" '.value.members|sort == ($want|split(" ")|sort)' true

    # add a dummy host to the group, to see it in the accountListAccesses afterwards
    success add_server_to_group1 $b2 --osh groupAddServer --group $group1 --host 172.16.4.4 --user nobody --port 12345 --force
    success add_server_to_group1 $b2 --osh groupAddServer --group $group1 --host 172.16.4.4 --user nobody --port 12346 --force

    success removemyselffromaclk $b2 --osh groupDelAclkeeper --group $group1 --account $account0
    success a0_delowner_group1 $b2 --osh groupDelOwner --group $group1 --account $account0

    # check access list
    success access_list_account1 $b2 --osh accountListAccesses --account $realm_shared_account/$account1
    json '.value|[.[]|.type]|sort' '["group-member","personal"]'
    json '.value[]|select(.type == "personal")|.acl[]|.ip' 127.0.0.5
    json '.value[]|select(.type == "group-member")|[.acl[]|.port]' '["12345","12346"]'

    # revoke group membership
    success del_account1_as_member $b2 --osh groupDelMember --group $group1 --account $realm_shared_account/$account1
    json .error_code OK

    success del_account1_as_member_dup $b2 --osh groupDelMember --group $group1 --account $realm_shared_account/$account1
    json .error_code OK_NO_CHANGE

    # check groupInfo
    success groupinfo $b2 --osh groupInfo --group $group1
    json --arg want "$realm_shared_account/alien $account0" '.value.members|sort == ($want|split(" ")|sort)' true

    # check access list
    success access_list_account1_again $b2 --osh accountListAccesses --account $realm_shared_account/$account1
    json '.value|[.[]|.type]|sort' '["personal"]'
    json '.value[]|select(.type == "personal")|.acl[]|.ip' 127.0.0.5

    # check access list
    success access_list_account2_again $b2 --osh accountListAccesses --account $realm_shared_account/alien
    json '.value|[.[]|.type]|sort' '["group-member"]'
    json '.value[]|select(.type == "group-member")|[.acl[]|.port]' '["12345","12346"]'

    # revoke group membership
    success del_account2_as_member $b2 --osh groupDelMember --group $group1 --account $realm_shared_account/alien
    json .error_code OK

    success del_account2_as_member_dup $b2 --osh groupDelMember --group $group1 --account $realm_shared_account/alien
    json .error_code OK_NO_CHANGE

    # check groupInfo
    success groupinfo $b2 --osh groupInfo --group $group1
    json '.value.members|sort' "[\"$account0\"]"

    # add guest access
    success add_guest_account1 $b2 --osh groupAddGuestAccess --account $realm_shared_account/first --group $group1 --host 172.16.4.4 --user nobody --port 12345
    success add_guest_account1 $b2 --osh groupAddGuestAccess --account $realm_shared_account/first --group $group1 --host 172.16.4.4 --user nobody --port 12346

    # add other guest access
    success add_guest_account2 $b2 --osh groupAddGuestAccess --account $realm_shared_account/second --group $group1 --host 172.16.4.4 --user nobody --port 12345

    # check groupInfo
    success groupinfo $b2 --osh groupInfo --group $group1
    json '.value.members|sort' "[\"$account0\"]"
    json '.value.guests|sort' "[\"$realm_shared_account/first\",\"$realm_shared_account/second\"]"

    # check access list of account
    success access_list_account1_guest $b2 --osh accountListAccesses --account $realm_shared_account/first
    json '.value|[.[]|.type]|sort' '["group-guest"]'
    json '.value[]|select(.type == "group-guest")|[.acl[]|.port]' '["12345","12346"]'

    # remove guest access 1
    success del_guest_account1 $b2 --osh groupDelGuestAccess --account $realm_shared_account/first --group $group1 --host 172.16.4.4 --user nobody --port 12345
    nocontain "removed group key"

    # check access list of account
    success access_list_account1_guest $b2 --osh accountListAccesses --account $realm_shared_account/first
    json '.value|[.[]|.type]|sort' '["group-guest"]'
    json '.value[]|select(.type == "group-guest")|.acl[]|.port' 12346

    # remove guest access 1
    success del_guest_account1 $b2 --osh groupDelGuestAccess --account $realm_shared_account/first --group $group1 --host 172.16.4.4 --user nobody --port 12346
    nocontain "removed group key"

    # check groupInfo
    success groupinfo $b2 --osh groupInfo --group $group1
    json '.value.members|sort' "[\"$account0\"]"
    json '.value.guests|sort' "[\"$realm_shared_account/second\"]"

    # remove last guest access
    success del_guest_account2 $b2 --osh groupDelGuestAccess --account $realm_shared_account/second --group $group1 --host 172.16.4.4 --user nobody --port 12345
    contain "removed group key"

    # check groupInfo
    success groupinfo $b2 --osh groupInfo --group $group1
    json '.value.members|sort' "[\"$account0\"]"
    json '.value.guests|sort' "[]"

    # check max account length
    success add_guest_account3 $b2 --osh groupAddGuestAccess --account $realm_shared_account/verylongaccountnam --group $group1 --host 172.16.4.4 --user nobody --port 12345

    # delete account1 on A
    success account1_cleanup $a0 --osh accountDelete --account $account1 --no-confirm

    # delete account2 on A
    script account2_cleanup "$a0 --osh accountDelete --account $account2 <<< \"Yes, do as I say and delete $account2, kthxbye\""
    retvalshouldbe 0

    # delete realm-egress group on A
    run cleanup_realm_support_group $a0 --osh groupDelete --group $realm_egress_group --no-confirm
    retvalshouldbe 0

    # delete shared realm-account on B
    script cleanup_shared_realm_account_fail "$b2 --osh accountDelete --account realm_$realm_shared_account <<< \"Yes, do as I say and delete realm_$realm_shared_account, kthxbye\""
    retvalshouldbe 100
    json .error_code KO_FORBIDDEN_PREFIX

    script cleanup_shared_realm_account "$b2 --osh realmDelete --realm $realm_shared_account <<< \"Yes, do as I say and delete $realm_shared_account, kthxbye\""
    retvalshouldbe 0

    # delete group1 on B
    script group_cleanup "$b2 --osh groupDelete --group $group1 <<< \"$group1\""
    retvalshouldbe 0
}

testsuite_realm
unset -f testsuite_realm
