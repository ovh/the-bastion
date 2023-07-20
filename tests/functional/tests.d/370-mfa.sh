# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_mfa()
{
    grant accountCreate
    grant accountModify

    # create account4
    success a0_create_a4 $a0 --osh accountCreate --always-active --account $account4 --uid $uid4 --public-key "\"$(cat $account4key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    # set account4 as mfa password required
    success a0_accountModify_passreq_a4 $a0 --osh accountModify --account $account4 --mfa-password-required yes
    json .error_code OK .command accountModify .value.mfa_password_required.error_code OK

    # set account4 as mfa password required (dupe)
    success a0_accountModify_passreq_a4_dupe $a0 --osh accountModify --account $account4 --mfa-password-required yes
    json .error_code OK .command accountModify .value.mfa_password_required.error_code OK_NO_CHANGE

    # now try to connect with account4
    run a4_connect_with_passreq $a4 --osh groupList
    retvalshouldbe 122
    json .error_code KO_MFA_PASSWORD_SETUP_REQUIRED

    # setup our password, step1
    run a4_setup_pass_step1of2 $a4f --osh selfMFASetupPassword --yes
    retvalshouldbe 124
    contain 'enter this:'
    local a4_password_tmp
    a4_password_tmp=$(get_stdout | grep -Eo 'enter this: [a-zA-Z0-9_-]+' | sed -e 's/enter this: //')

    # setup our password, step2
    local a4_password
    a4_password=']BkL>3x#T)g~~B#rLv^!T2&N'
    script a4_setup_pass_step2of2 "echo 'set timeout 30; \
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

    # now try to connect after we have a pass
    run a4_connect_after_pass $a4f --osh groupList
    if [ "${capabilities[mfa]}" = 1 ] || [ "${capabilities[mfa-password]}" = 1 ]; then
        # now we need a password, we don't enter it so it'll timeout (124)
        retvalshouldbe 124
        contain 'Multi-Factor Authentication enabled, an additional authentication factor is required (password).'
        contain REGEX 'Password:|Password for'
        nocontain 'JSON_OUTPUT'
    else
        # our system doesn't support MFA so it still works without asking for a password
        retvalshouldbe 0
        nocontain 'Multi-Factor Authentication enabled'
        nocontain REGEX 'Password:|Password for'
        json .command groupList .error_code OK_EMPTY
    fi

    # batch trying to start a plugin that requires mfa => should get an error

    if [ "${capabilities[pamtester]}" = 1 ]; then

        success batch_set_mfa $r0 "echo '{\\\"mfa_required\\\":\\\"any\\\"}' \> $opt_remote_etc_bastion/plugin.info.conf \; chmod o+r $opt_remote_etc_bastion/plugin.info.conf"

        if [ "${capabilities[mfa]}" = 1 ] || [ "${capabilities[mfa-password]}" = 1 ]; then
            script batch_try_mfa "echo 'set timeout 30; \
                spawn $a4 --osh batch; \
                expect \":\" { sleep 0.2; send \"$a4_password\\n\"; }; \
                expect \"waiting for input\" { sleep 0.2; send \"info\\n\"; }; \
                expect \"failed\" { sleep 0.2; send \"quit\\n\"; }; \
                expect eof; \
                lassign [wait] pid spawnid value value; \
                exit \$value' | expect -f -"
            retvalshouldbe 0
            contain "launching command: info"
            contain "entering MFA phase"
            contain "please use --proactive-mfa"
            nocontain "Your alias to connect"
            json .command batch .error_code OK '.value[0].command' info '.value[0].result.error_code' KO_MFA_FAILED
        else
            script batch_try_mfa "echo 'set timeout 30; \
                spawn $a4 --osh batch; \
                expect \"waiting for input\" { sleep 0.2; send \"info\\n\"; }; \
                expect \"failed\" { sleep 0.2; send \"quit\\n\"; }; \
                expect eof; \
                lassign [wait] pid spawnid value value; \
                exit \$value' | expect -f -"
            retvalshouldbe 0
            contain "launching command: info"
            contain "entering MFA phase"
            contain "please use --proactive-mfa"
            nocontain "Your alias to connect"
            json .command batch .error_code OK '.value[0].command' info '.value[0].result.error_code' KO_MFA_FAILED
        fi

        success batch_unset_mfa $r0 "rm -f $opt_remote_etc_bastion/plugin.info.conf"
    fi

    # /batch

    if [ "${capabilities[pamtester]}" = 1 ]; then
        grant groupCreate

        success a0_create_g3 $a0 --osh groupCreate --group $group3 --algo rsa --size 4096 --owner $account4

        revoke groupCreate

        # setup group to force JIT egress MFA
        script a4_modify_g3_egress_mfa "echo 'set timeout 30; \
            spawn $a4 --osh groupModify --group $group3 --mfa-required any; \
            expect \":\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect eof; \
            lassign [wait] pid spawnid value value; \
            exit \$value' | expect -f -"
        retvalshouldbe 0
        contain 'Multi-Factor Authentication enabled, an additional authentication factor is required (password).'
        contain REGEX 'Password:|Password for'
        json .command groupModify .error_code OK

        # check that the MFA is set for the group
        script a4_verify_g3_egress_mfa "echo 'set timeout 30; \
            spawn $a4 --osh groupInfo --group $group3; \
            expect \":\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect eof; \
            lassign [wait] pid spawnid value value; \
            exit \$value' | expect -f -"
        retvalshouldbe 0
        contain 'Multi-Factor Authentication enabled, an additional authentication factor is required (password).'
        contain REGEX 'Password:|Password for'
        json .command groupInfo .error_code OK
        json .value.mfa_required any

        # add 127.7.7.7 to this group
        script a4_add_g3_server "echo 'set timeout 30; \
            spawn $a4 --osh groupAddServer --group $group3 --host 127.7.7.7 --user-any --port-any --force; \
            expect \":\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect eof; \
            lassign [wait] pid spawnid value value; \
            exit \$value' | expect -f -"
        retvalshouldbe 0
        contain 'Multi-Factor Authentication enabled, an additional authentication factor is required (password).'
        contain REGEX 'Password:|Password for'

        # connect to 127.7.7.7 with MFA JIT, bad password
        script a4_connect_g3_server_badpass "echo 'set timeout 45; \
            spawn $a4 root@127.7.7.7; \
            expect \"is required (password)\" { sleep 0.1; }; \
            expect \":\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect \"is required (password)\" { sleep 0.1; }; \
            expect \":\" { sleep 0.2; send \"BADPASSWORD\\n\"; }; \
            expect \"is required (password)\" { sleep 0.1; }; \
            expect \":\" { sleep 0.2; send \"BADPASSWORD\\n\"; }; \
            expect \"is required (password)\" { sleep 0.1; }; \
            expect \":\" { sleep 0.2; send \"BADPASSWORD\\n\\n\"; }; \
            expect eof; \
            lassign [wait] pid spawnid value value; \
            exit \$value' | expect -f -"
        retvalshouldbe 125
        contain 'Multi-Factor Authentication enabled, an additional authentication factor is required (password).'
        contain REGEX 'Password:|Password for'
        contain 'pamtester: '
        nocontain 'Permission denied'

        # connect to 127.7.7.7 with MFA JIT, good password
        script a4_connect_g3_server_goodpass "echo 'set timeout 30; \
            spawn $a4 root@127.7.7.7; \
            expect \":\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect \"is required (password)\" { sleep 0.1; }; \
            expect \":\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect eof; \
            lassign [wait] pid spawnid value value; \
            exit \$value' | expect -f -"
        retvalshouldbe 255
        contain 'Multi-Factor Authentication enabled, an additional authentication factor is required (password).'
        contain REGEX 'Password:|Password for'
        contain 'pamtester: successfully authenticated'
        contain 'Permission denied'

        # test proactive mfa
        script set_help_mfa $r0 "'"'echo \{\"mfa_required\":\ \"password\"\} > '"$opt_remote_etc_bastion"'/plugin.help.conf; chmod 644 '"$opt_remote_etc_bastion"'/plugin.help.conf'"'"
        retvalshouldbe 0

        script a4_mfa_help_jitmfa "echo 'set timeout 30; \
            spawn $a4 --osh help; \
            expect \":\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect \"is required (password)\" { sleep 0.1; }; \
            expect \":\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect eof; \
            lassign [wait] pid spawnid value value; \
            exit \$value' | expect -f -"
        contain 'pamtester: successfully authenticated'
        retvalshouldbe 0
        contain 'Multi-Factor Authentication enabled, an additional authentication factor is required (password).'
        contain REGEX 'Password:|Password for'
        nocontain 'proactive MFA'

        script a4_proactive_mfa_help "echo 'set timeout 30; \
            spawn $a4 --osh help --proactive-mfa; \
            expect \":\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect \"is required (password)\" { sleep 0.1; }; \
            expect \":\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect eof; \
            lassign [wait] pid spawnid value value; \
            exit \$value' | expect -f -"
        retvalshouldbe 0
        contain 'Multi-Factor Authentication enabled, an additional authentication factor is required (password).'
        contain REGEX 'Password:|Password for'
        contain 'pamtester: successfully authenticated'
        contain 'proactive MFA'
        json .command help .error_code OK

        script remove_help_mfa $r0 "'"'rm -f '"$opt_remote_etc_bastion"'/plugin.help.conf'"'"
        retvalshouldbe 0
        # /proactive mfa

        # create another account
        success a0_create_a3 $a0 --osh accountCreate --always-active --account $account3 --uid $uid3 --public-key "\"$(cat $account3key1file.pub)\""
        json .error_code OK .command accountCreate .value null

        # set the account as bypass
        success a0_set_a3_as_robot $a0 --osh accountModify --account $account3 --mfa-password-required bypass
        json .command accountModify .error_code OK

        # add to JIT MFA group
        script a0_add_a3_as_member "echo 'set timeout 30; \
            spawn $a4 --osh groupAddMember --group $group3 --account $account3; \
            expect \":\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect eof; \
            lassign [wait] pid spawnid value value; \
            exit \$value' | expect -f -"
        json .command groupAddMember .error_code OK

        # connect to 127.7.7.7 with MFA JIT, no MFA needed
        run a3_connect_g3_server_mfa_bypass $a3 root@127.7.7.7
        retvalshouldbe 255
        nocontain 'pamtester: successfully authenticated'
        contain 'Permission denied'

        # remove the account bypass
        success a0_unset_a3_as_robot $a0 --osh accountModify --account $account3 --mfa-password-required no
        json .command accountModify .error_code OK

        # connect to 127.7.7.7 with MFA JIT, password setup needed
        run a3_connect_mfa_jit_need_pass_setup $a3 root@127.7.7.7
        json .error_code KO_MFA_ANY_SETUP_REQUIRED

        grant groupDelete

        script a0_delete_g3 "$a0 --osh groupDelete --group $group3 <<< \"$group3\""

        revoke groupDelete

        grant accountDelete

        script a0_delete_a3 $a0 --osh accountDelete --account $account3 "<<< \"Yes, do as I say and delete $account3, kthxbye\""
        retvalshouldbe 0
        json .command accountDelete .error_code OK

        revoke accountDelete
    fi

    # change our password
    a4_password_new="rkw=*Ffyqs23"
    if [ "${capabilities[mfa]}" = 1 ] || [ "${capabilities[mfa-password]}" = 1 ]; then
        script a4_change_pass "echo 'set timeout 30; \
            spawn $a4 --osh selfMFASetupPassword --yes; \
            expect \":\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect \":\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect \":\" { sleep 0.2; send \"$a4_password_new\\n\"; }; \
            expect \":\" { sleep 0.2; send \"$a4_password_new\\n\"; }; \
            expect eof; \
            lassign [wait] pid spawnid value value; \
            exit \$value' | expect -f -"
        retvalshouldbe 0
        contain 'Multi-Factor Authentication enabled, an additional authentication factor is required (password).'
        contain REGEX 'Password:|Password for'
    else
        script a4_change_pass "echo 'set timeout 30; \
            spawn $a4 --osh selfMFASetupPassword --yes; \
            expect \":\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect \":\" { sleep 0.2; send \"$a4_password_new\\n\"; }; \
            expect \":\" { sleep 0.2; send \"$a4_password_new\\n\"; }; \
            expect eof; \
            lassign [wait] pid spawnid value value; \
            exit \$value' | expect -f -"
        retvalshouldbe 0
        nocontain 'Multi-Factor Authentication enabled'
    fi
    nocontain 'enter this:'
    nocontain 'unchanged'
    json .command selfMFASetupPassword .error_code OK

    a4_password="$a4_password_new"
    unset a4_password_new

    if [ "${capabilities[mfa]}" = 1 ] || [ "${capabilities[mfa-password]}" = 1 ]; then
        script a4_connect_with_pass "echo 'set timeout 30; \
            spawn $a4 --osh groupList; \
            expect \":\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect eof; \
            lassign [wait] pid spawnid value value; \
            exit \$value' | expect -f -"
        retvalshouldbe 0
        contain 'Multi-Factor Authentication enabled, an additional authentication factor is required (password).'
        contain REGEX 'Password:|Password for'
        json .command groupList .error_code OK_EMPTY
    fi

    # set account4 as mfa totp required
    success a0_accountModify_totpreq_a4 $a0 --osh accountModify --account $account4 --mfa-totp-required yes
    json .error_code OK .command accountModify .value.mfa_totp_required.error_code OK

    # set account4 as mfa totp required (dupe)
    success a0_accountModify_totpreq_a4_dupe $a0 --osh accountModify --account $account4 --mfa-totp-required yes
    json .error_code OK .command accountModify .value.mfa_totp_required.error_code OK_NO_CHANGE

    # now try to connect with account4
    if [ "${capabilities[mfa]}" = 1 ] || [ "${capabilities[mfa-password]}" = 1 ]; then
        script a4_connect_with_totpreq "echo 'set timeout 30; \
            spawn $a4 --osh groupList; \
            expect \":\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect eof; \
            lassign [wait] pid spawnid value value; \
            exit \$value' | expect -f -"
    else
        run a4_connect_with_totpreq $a4 --osh groupList
    fi
    retvalshouldbe 123
    json .error_code KO_MFA_TOTP_SETUP_REQUIRED

    if [ "${capabilities[mfa]}" = 1 ]; then
        # setup totp
        script a4_setup_totp "echo 'set timeout 30; \
            spawn $a4 --osh selfMFASetupTOTP --no-confirm; \
            expect \"word:\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect \"word:\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect eof; \
            lassign [wait] pid spawnid value value; \
            exit \$value' | expect -f -"
        retvalshouldbe 0
        contain 'Multi-Factor Authentication enabled, an additional authentication factor is required (password).'
        contain REGEX 'Password:|Password for'

        local a4_totp_code_1
        a4_totp_code_1=$(get_stdout | grep -A1 'Your emergency scratch codes are:' | tail -n1 | tr -d '[:space:]')
        #a4_totp_code_2=$(get_stdout | grep -A2 'Your emergency scratch codes are:' | tail -n1 | tr -d '[:space:]')
        #a4_totp_code_3=$(get_stdout | grep -A3 'Your emergency scratch codes are:' | tail -n1 | tr -d '[:space:]')
        #a4_totp_code_4=$(get_stdout | grep -A4 'Your emergency scratch codes are:' | tail -n1 | tr -d '[:space:]')

        # login and fail without totp (timeout)
        script a4_connect_after_totp_fail "echo 'set timeout 30; \
            spawn $a4 --osh groupList; \
            expect \"word:\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect eof; \
            lassign [wait] pid spawnid value value; \
            exit \$value' | expect -f -"
        retvalshouldbe 124
        contain 'Multi-Factor Authentication enabled, an additional authentication factor is required (password).'
        contain 'Multi-Factor Authentication enabled, an additional authentication factor is required (OTP).'
        contain 'Your password expires on'
        contain 'in 89 days'
        contain REGEX 'Password:|Password for'
        contain 'Verification code:'
        nocontain 'JSON_OUTPUT'

        # success with password + totp
        script a4_connect_after_totp_ok "echo 'set timeout 30; \
            spawn $a4 --osh groupList; \
            expect \"word:\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect \"code:\" { sleep 0.2; send \"$a4_totp_code_1\\n\"; }; \
            expect eof; \
            lassign [wait] pid spawnid value value; \
            exit \$value' | expect -f -"
        retvalshouldbe 0
        contain 'Multi-Factor Authentication enabled, an additional authentication factor is required (password).'
        contain 'Multi-Factor Authentication enabled, an additional authentication factor is required (OTP).'
        contain REGEX 'Password:|Password for'
        contain 'Verification code:'
        json .command groupList .error_code OK_EMPTY

        # totp scratch codes don't work twice
        script a4_connect_after_totp_dupe "echo 'set timeout 30; \
            spawn $a4 --osh groupList; \
            expect \"word:\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect \"code:\" { sleep 0.2; send \"$a4_totp_code_1\\n\"; }; \
            expect \"word:\" { exit 222; }; \
            expect eof; \
            lassign [wait] pid spawnid value value; \
            exit \$value' | expect -f -"
        retvalshouldbe 222
        contain 'Multi-Factor Authentication enabled, an additional authentication factor is required (password).'
        contain 'Multi-Factor Authentication enabled, an additional authentication factor is required (OTP).'
        contain REGEX 'Password:|Password for'
        contain 'Verification code:'
        nocontain 'JSON_OUTPUT'

        # set pam bypass on account4 (dupe)
        success a0_set_pambypass_a4 $a0 --osh accountModify --account $account4 --pam-auth-bypass yes
        json .error_code OK .command accountModify .value.pam_auth_bypass.error_code OK

        # set pam bypass on account4
        success a0_set_pambypass_a4_dupe $a0 --osh accountModify --account $account4 --pam-auth-bypass yes
        json .error_code OK .command accountModify .value.pam_auth_bypass.error_code OK_NO_CHANGE

        # we don't provide password or totp, it should work because bypass
        success a4_pam_auth_bypass $a4 --osh groupList
        json .command groupList .error_code OK_EMPTY

        # remove requirement of password and totp for account4, also remove bypass
        success a0_remove_mfa_req_a4 $a0 --osh accountModify --account $account4 --pam-auth-bypass no --mfa-totp-required no --mfa-password-required no
        json .error_code OK .command accountModify .value.pam_auth_bypass.error_code OK .value.mfa_totp_required.error_code OK .value.mfa_password_required.error_code OK

        # remove requirement of password and totp for account4, also remove bypass (dupe)
        success a0_remove_mfa_req_a4_dupe $a0 --osh accountModify --account $account4 --pam-auth-bypass no --mfa-totp-required no --mfa-password-required no
        json .error_code OK .command accountModify .value.pam_auth_bypass.error_code OK_NO_CHANGE .value.mfa_totp_required.error_code OK_NO_CHANGE .value.mfa_password_required.error_code OK_NO_CHANGE

        # pubkey-auth-optional

        # remove totp from account4 to simplify the following tests
        grant accountMFAResetTOTP

        success a0_nototp_a4 $a0 --osh accountMFAResetTOTP --account $account4
        json .command accountMFAResetTOTP .error_code OK

        revoke accountMFAResetTOTP

        # pubkey-auth-optional disabled: success with pubkey and password
        script a4_no_pubkeyauthoptional_login_pubkey_pam "echo 'set timeout 30; \
            spawn $a4 --osh groupList; \
            expect \"word:\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect eof; \
            lassign [wait] pid spawnid value value; \
            exit \$value' | expect -f -"
        retvalshouldbe 0
        contain 'Multi-Factor Authentication enabled, an additional authentication factor is required (password).'
        contain REGEX 'Password:|Password for'
        json .command groupList .error_code OK_EMPTY

        # pubkey-auth-optional disabled: fail with pubkey but no password (timeout)
        script a4_no_pubkeyauthoptional_login_pubkey_nopam $a4 --osh groupList
        retvalshouldbe 124
        contain 'Multi-Factor Authentication enabled, an additional authentication factor is required (password).'
        contain 'Your password expires on'
        contain 'in 89 days'
        contain REGEX 'Password:|Password for'
        nocontain 'JSON_OUTPUT'

        # pubkey-auth-optional disabled: fail with no pubkey (never gets to ask for the password)
        script a4_no_pubkeyauthoptional_login_nopubkey_pam $a4np --osh groupList
        retvalshouldbe 255
        contain 'Permission denied (publickey).'
        nocontain 'password'
        nocontain 'JSON_OUTPUT'

        # set pubkey-auth-optional on account4
        success a0_set_pubkeyauthoptional_a4 $a0 --osh accountModify --account $account4 --pubkey-auth-optional yes
        json .error_code OK .command accountModify .value.pubkey_auth_optional.error_code OK

        # set pubkey-auth-optional on account4 (dupe)
        success a0_set_pubkeyauthoptional_a4_dupe $a0 --osh accountModify --account $account4 --pubkey-auth-optional yes
        json .error_code OK .command accountModify .value.pubkey_auth_optional.error_code OK_NO_CHANGE

        # pubkey-auth-optional enabled: success with pubkey and password
        script a4_pubkeyauthoptional_login_pubkey_pam "echo 'set timeout 30; \
            spawn $a4 --osh groupList; \
            expect \"word:\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect eof; \
            lassign [wait] pid spawnid value value; \
            exit \$value' | expect -f -"
        retvalshouldbe 0
        contain 'Multi-Factor Authentication enabled, an additional authentication factor is required (password).'
        contain REGEX 'Password:|Password for'
        json .command groupList .error_code OK_EMPTY

        # pubkey-auth-optional enabled: success with password only
        script a4_pubkeyauthoptional_login_nopubkey_pam "echo 'set timeout 30; \
            spawn $a4np --osh groupList; \
            expect \"word:\" { sleep 0.2; send \"$a4_password\\n\"; }; \
            expect eof; \
            lassign [wait] pid spawnid value value; \
            exit \$value' | expect -f -"
        retvalshouldbe 0
        contain 'Multi-Factor Authentication enabled, an additional authentication factor is required (password).'
        contain REGEX 'Password:|Password for'
        json .command groupList .error_code OK_EMPTY

        # pubkey-auth-optional enabled: fail with pubkey only
        script a4_pubkeyauthoptional_login_pubkey_nopam $a4 --osh groupList
        retvalshouldbe 124
        contain 'Multi-Factor Authentication enabled, an additional authentication factor is required (password).'
        contain 'Your password expires on'
        contain 'in 89 days'
        contain REGEX 'Password:|Password for'
        nocontain 'JSON_OUTPUT'

        # unset pubkey-auth-optional on account4
        success a0_unset_pubkeyauthoptional_a4 $a0 --osh accountModify --account $account4 --pubkey-auth-optional no
        json .error_code OK .command accountModify .value.pubkey_auth_optional.error_code OK

        # unset mfa-any on account4 (dupe)
        success a0_unset_pubkeyauthoptional_a4_dupe $a0 --osh accountModify --account $account4 --pubkey-auth-optional no
        json .error_code OK .command accountModify .value.pubkey_auth_optional.error_code OK_NO_CHANGE



    # FIXME
    #   # reset totp
    #    script mfa a4_reset_totp "echo 'set timeout 30; \
    #        spawn $a4 --osh selfMFAResetTOTP; \
    #        expect \"word:\" { send_user \"premier password\\n\"; send \"$a4_password\\n\"; }; \
    #        expect \"code:\" { send_user \"premier code\\n\"; send \"$a4_totp_code_2\\n\"; }; \
    #        expect \"word:\" { send_user \"second password\\n\"; send \"$a4_password\\n\"; }; \
    #        expect \"code:\" { send_user \"second code\\n\"; send \"$a4_totp_code_3\\n\"; }; \
    #        expect eof; \
    #        lassign [wait] pid spawnid value value; \
    #        exit \$value' | expect -f -"
    #    retvalshouldbe 0
    #    json .error_code OK .command selfMFAResetTOTP
    #
    #    # reset password
    #    script mfa a4_reset_password "echo 'set timeout 30; \
    #        spawn $a4 --osh selfMFAResetPassword; \
    #        expect \"word:\" { send \"$a4_password\\n\"; }; \
    #        expect eof; \
    #        lassign [wait] pid spawnid value value; \
    #        exit \$value' | expect -f -"
    #    retvalshouldbe 0
    #    json .error_code OK .command selfMFAResetPassword

    #   # now we no longer need MFA
    #    success mfa a4_mfa_deconfigured $a4 --osh groupList
    #    json .command groupList .error_code OK_EMPTY
    fi

    grant accountRevokeCommand
    revoke accountModify
    grant accountDelete

    # remove account
    script a0_delete_a4 $a0 --osh accountDelete --account $account4 "<<< \"Yes, do as I say and delete $account4, kthxbye\""
    retvalshouldbe 0
    json .command accountDelete .error_code OK

    revoke accountDelete
}

testsuite_mfa
unset -f testsuite_mfa
