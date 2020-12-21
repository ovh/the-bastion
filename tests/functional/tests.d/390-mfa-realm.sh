# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_mfa_realm()
{
    local realm_egress_group=realmsuppgrp
    local realm_shared_account=supplier42
    grant accountCreate

    # create account4
    success mfarealm a0_create_a4 $a0 --osh accountCreate --always-active --account $account4 --uid $uid4 --public-key "\"$(cat $account4key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    revoke accountCreate

    # now setup a realm
    grant groupCreate

    # create realm-egress group on local bastion
    success realm create_support_group $a0 --osh groupCreate --group $realm_egress_group --owner $account4 --algo ed25519
    local realm_group_key
    realm_group_key=$(get_json | $jq '.value.public_key.line')

    grant realmCreate

    # create shared realm-account on remote bastion
    success realm create_shared_account $a0 --osh realmCreate --realm $realm_shared_account --public-key \"$realm_group_key\" --from 0.0.0.0/0

    revoke realmCreate

    # add remote bastion ip on group of local bastion
    success realm add_remote_bastion_to_group $a4 --osh groupAddServer --host 127.0.0.1 --user realm_$realm_shared_account --port 22 --group $realm_egress_group --kbd-interactive

    # attempt inter-realm connection
    success realm firstconnect1 $a4 realm_$realm_shared_account@127.0.0.1 --kbd-interactive -- $js --osh info
    json .value.account $account4 .value.realm $realm_shared_account

    # create a remote-group on which we'll add the realm user
    success mfarealm remote_group_create $a0 --osh groupCreate --group remotegrp --owner $account0 --algo ed25519
    revoke groupCreate

    success mfarealm remote_group_add_server $a0 --osh groupAddServer --group remotegrp --host 127.0.0.5 --port 22 --user nevermind --force

    # try to connect, as a realm user, to 127.0.0.5 through the realm: won't work
    run mfarealm realm_user_fail_connect_not_member $a4 realm_$realm_shared_account@127.0.0.1 --kbd-interactive -- $js nevermind@127.0.0.5
    retvalshouldbe 107
    json .error_code KO_ACCESS_DENIED .error_message "Access denied for $realm_shared_account/$account4 to nevermind@127.0.0.5:22"

    # now add the realm user and retry
    success mfarealm remote_group_add_user $a0 --osh groupAddMember --group remotegrp --account $realm_shared_account/$account4

    run mfarealm realm_user_fail_connect_not_member $a4 realm_$realm_shared_account@127.0.0.1 --kbd-interactive -- $js nevermind@127.0.0.5
    retvalshouldbe 255
    contain "group-member of remotegrp"
    contain "Permission denied (publickey)"

    # now setup mandatory MFA on the group
    success mfarealm remote_group_set_mfa $a0 --osh groupModify --group remotegrp --mfa-required password

    # try to connect won't work
    run mfarealm realm_user_fail_connect_no_mfa $a4 realm_$realm_shared_account@127.0.0.1 --kbd-interactive -- $js nevermind@127.0.0.5
    retvalshouldbe 122
    json .error_code KO_MFA_PASSWORD_SETUP_REQUIRED

    # setup our MFA
    # setup our password, step1
    run mfa a4_setup_pass_step1of2 $a4f --osh selfMFASetupPassword --yes
    retvalshouldbe 124
    contain 'enter this:'
    local a4_password_tmp
    a4_password_tmp=$(get_stdout | grep -Eo 'enter this: [a-zA-Z0-9_-]+' | sed -e 's/enter this: //')

    # setup our password, step2
    local a4_password='Hfv$!OKiG:(xl>Th8Kv!alz4436BFt~'
    script mfa a4_setup_pass_step2of2 "echo 'set timeout 30; \
        spawn $a4 --osh selfMFASetupPassword --yes; \
        expect \":\" { sleep 0.2; send \"$a4_password_tmp\\n\"; }; \
        expect \":\" { sleep 0.2; send \"$a4_password\\n\"; }; \
        expect \":\" { sleep 0.2; send \"$a4_password\\n\"; }; \
        expect eof; \
        lassign [wait] pid spawnid value value; \
        exit \$value' | expect -f -"
    retvalshouldbe 0
    unset a4_password_tmp
    nocontain 'enter this:'
    nocontain 'unchanged'
    nocontain 'sorry'
    json .command selfMFASetupPassword .error_code OK

    # set account4 as nopam, to only use JIT MFA because that's what we want to test
    grant accountModify

    success mfarealm a4_set_nopam $a0 --osh accountModify --account $account4 --pam-auth-bypass yes
    json .command accountModify .error_code OK

    revoke accountModify

    # try to connect will still not work because we have MFA but we're asked for it on our first bastion
    run mfarealm realm_user_still_fail_connect_no_mfa $a4 realm_$realm_shared_account@127.0.0.1 --kbd-interactive -- $js nevermind@127.0.0.5
    retvalshouldbe 122
    json .error_code KO_MFA_PASSWORD_SETUP_REQUIRED

    # force MFA for the support group
    success mfarealm set_mfa_for_support_group $a4 --osh groupModify --group $realm_egress_group --mfa-required password
    json .command groupModify .error_code OK

    # try to connect, this one will finally work
    script mfarealm a4_connect_success_realm_with_remote_mfa "echo 'set timeout 30; \
        spawn $a4 realm_$realm_shared_account@127.0.0.1 --kbd-interactive -- $js nevermind@127.0.0.5; \
        expect \"word:\" { sleep 0.2; send \"$a4_password\\n\"; }; \
        expect eof; \
        lassign [wait] pid spawnid value value; \
        exit \$value' | expect -f -"
    retvalshouldbe 255
    contain "you already validated MFA on the bastion you're coming from"
    contain "Permission denied (publickey)"

    # cleanup
    grant realmDelete

    success mfarealm realmDelete $a0 --osh realmDelete --realm $realm_shared_account "<<< \"Yes, do as I say and delete $realm_shared_account, kthxbye\""

    revoke realmDelete
    grant accountDelete

    script mfarealm a0_delete_a4 $a0 --osh accountDelete --account $account4 "<<< \"Yes, do as I say and delete $account4, kthxbye\""
    retvalshouldbe 0
    json .command accountDelete .error_code OK

    revoke accountDelete
    grant groupDelete

    success mfarealm groupDelete $a0 --osh groupDelete --group $realm_egress_group --no-confirm

    revoke groupDelete
}

if [ "$HAS_MFA" = 1 ] || [ "$HAS_MFA_PASSWORD" = 1 ]; then
    testsuite_mfa_realm
fi
unset -f testsuite_mfa_realm
