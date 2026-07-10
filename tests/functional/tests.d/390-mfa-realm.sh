# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2317,SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_mfa_realm()
{
    local realm_egress_group=realmsuppgrp
    local realm_shared_account=supplier42

    # this suite needs a real, separate remote bastion (B) to host the realm; bail out if the runner
    # didn't provide one
    if [ -z "${target2_ip:-}" ]; then
        echo "mfa-realm: no second bastion provided by the runner, skipping"
        return 0
    fi

    # resolve B's container name to an IP and wait for its sshd to be up
    local b2ip=""
    [ "${COUNTONLY:-}" != 1 ] && b2ip=$(wait_for_target2)

    # create account4 on the ingress bastion A
    success a0_create_a4 $a0 --osh accountCreate --always-active --account $account4 --uid $uid4 --public-key "\"$(cat $account4key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    # now setup a realm
    # create realm-egress group on local bastion
    success create_support_group $a0 --osh groupCreate --group $realm_egress_group --owner $account4 --algo ed25519
    local realm_group_key
    realm_group_key=$(get_json | $jq '.value.public_key.line')

    # create shared realm-account on the remote bastion B
    success create_shared_account $b2 --osh realmCreate --realm $realm_shared_account --public-key \"$realm_group_key\" --from 0.0.0.0/0

    # point A's egress group at B's realm account
    success add_remote_bastion_to_group $a4 --osh groupAddServer --host $b2ip --user realm_$realm_shared_account --port $remote_port --group $realm_egress_group --kbd-interactive

    # attempt inter-realm connection
    success firstconnect1 $a4 realm_$realm_shared_account@$b2ip --kbd-interactive -- $js --osh info
    json .value.account $account4 .value.realm $realm_shared_account

    # create a remote-group on B, on which we'll add the realm user
    success remote_group_create $b2 --osh groupCreate --group remotegrp --owner $account0 --algo ed25519

    success remote_group_add_server $b2 --osh groupAddServer --group remotegrp --host 127.0.0.5 --port 22 --user nevermind --force

    # try to connect, as a realm user, to 127.0.0.5 through the realm: won't work
    run realm_user_fail_connect_not_member $a4 realm_$realm_shared_account@$b2ip --kbd-interactive -- $js nevermind@127.0.0.5
    retvalshouldbe 107
    json .error_code KO_ACCESS_DENIED .error_message "Access denied for $realm_shared_account/$account4 to nevermind@127.0.0.5:22"

    # now add the realm user and retry
    success remote_group_add_user $b2 --osh groupAddMember --group remotegrp --account $realm_shared_account/$account4

    run realm_user_fail_connect_not_member $a4 realm_$realm_shared_account@$b2ip --kbd-interactive -- $js nevermind@127.0.0.5
    retvalshouldbe 255
    contain "group-member of remotegrp"
    contain "Permission denied (publickey)"

    # now setup mandatory MFA on the remote group (on B)
    success remote_group_set_mfa $b2 --osh groupModify --group remotegrp --mfa-required password

    # try to connect won't work
    run realm_user_fail_connect_no_mfa $a4 realm_$realm_shared_account@$b2ip --kbd-interactive -- $js nevermind@127.0.0.5
    retvalshouldbe 122
    json .error_code KO_MFA_PASSWORD_SETUP_REQUIRED

    # setup our MFA
    # setup our password, step1
    run a4_setup_pass_step1of2 $a4f --osh selfMFASetupPassword --yes
    retvalshouldbe 124
    contain 'enter this:'
    local a4_password_tmp
    a4_password_tmp=$(get_stdout | grep -Eo 'enter this: [a-zA-Z0-9_-]+' | sed -e 's/enter this: //')

    # setup our password, step2
    local a4_password='Hfv$!OKiG:(xl>Th8Kv!alz4436BFt~'
    script a4_setup_pass_step2of2 "echo 'set timeout $default_timeout; \
        spawn $a4 --osh selfMFASetupPassword --yes; \
        expect \"word:\" { sleep 0.2; send \"$a4_password_tmp\\n\"; }; \
        expect \"word:\" { sleep 0.2; send \"$a4_password\\n\"; }; \
        expect \"word:\" { sleep 0.2; send \"$a4_password\\n\"; }; \
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

    success a4_set_nopam $a0 --osh accountModify --account $account4 --pam-auth-bypass yes
    json .command accountModify .error_code OK

    # try to connect will still not work because we have MFA but we're asked for it on our first bastion
    run realm_user_still_fail_connect_no_mfa $a4 realm_$realm_shared_account@$b2ip --kbd-interactive -- $js nevermind@127.0.0.5
    retvalshouldbe 122
    json .error_code KO_MFA_PASSWORD_SETUP_REQUIRED

    # force MFA for the support group
    success set_mfa_for_support_group $a4 --osh groupModify --group $realm_egress_group --mfa-required password
    json .command groupModify .error_code OK

    # try to connect, this one will finally work
    script a4_connect_success_realm_with_remote_mfa "echo 'set timeout $default_timeout; \
        spawn $a4 realm_$realm_shared_account@$b2ip --kbd-interactive -- $js nevermind@127.0.0.5; \
        expect \"word:\" { sleep 0.2; send \"$a4_password\\n\"; }; \
        expect eof; \
        lassign [wait] pid spawnid value value; \
        exit \$value' | expect -f -"
    retvalshouldbe 255
    contain "you already validated MFA on the bastion you're coming from"
    contain "Permission denied (publickey)"

    # cleanup: delete the realm on B, account4 and the egress group on A
    script realmDelete $b2 --osh realmDelete --realm $realm_shared_account "<<< \"Yes, do as I say and delete $realm_shared_account, kthxbye\""

    script a0_delete_a4 $a0 --osh accountDelete --account $account4 "<<< \"Yes, do as I say and delete $account4, kthxbye\""
    retvalshouldbe 0
    json .command accountDelete .error_code OK

    success groupDelete $a0 --osh groupDelete --group $realm_egress_group --no-confirm
}

# This second suite exercises the cross-realm TOTP login-gate fixed in commit 7f72292
# (bin/shell/osh.pl): a realm user whose TOTP was already validated on the ingress bastion must be
# let onto a remote bastion that enforces a global 'totp-required' policy, instead of being wrongly
# told to set up TOTP (which a realm account cannot do). Unlike testsuite_mfa_realm above (which only
# drives the JIT-MFA path with a password and a single self-realm), this one needs *real* PAM TOTP
# (capabilities[mfa]) and a *second*, full-fledged bastion instance ($target2_ip) acting as the
# remote/egress bastion, so its global MFA policy doesn't disturb the main test bastion.
testsuite_mfa_realm_totp()
{
    local realm_name=bastiontotp
    local egress_group=realmtotpegress

    # the remote bastion (B) is provided by the runner; bail out cleanly if it isn't there
    if [ -z "${target2_ip:-}" ]; then
        echo "mfa-realm-totp: no second bastion provided by the runner, skipping"
        return 0
    fi

    # resolve B's container name to an IP and wait for its sshd to be up
    local b2ip=""
    [ "${COUNTONLY:-}" != 1 ] && b2ip=$(wait_for_target2)

    # account4 lives on the main (ingress) bastion A
    success a0_create_a4 $a0 --osh accountCreate --always-active --account $account4 --uid $uid4 --public-key "\"$(cat $account4key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    # IMPORTANT ordering: do all of account4's group setup *before* it has TOTP configured. Once it's
    # in the mfa-totp-configd group, every ingress login to A requires an interactive OTP (see the
    # 'Match Group mfa-totp-configd' stanza in sshd_config), which would force an OTP on each command.

    # create the realm-egress group on A, owned by account4, and grab its egress public key.
    success create_egress_group $a0 --osh groupCreate --group $egress_group --owner $account4 --algo ed25519
    local egress_group_key
    egress_group_key=$(get_json | $jq '.value.public_key.line')

    # create the matching realm shared account on the *remote* bastion B, trusting that egress key
    success create_realm_on_b2 $b2 --osh realmCreate --realm $realm_name --public-key \"$egress_group_key\" --from 0.0.0.0/0
    json .command realmCreate .error_code OK

    # on A, point the egress group at B's realm account...
    success add_b2_to_egress_group $a4 --osh groupAddServer --host $b2ip --user realm_$realm_name --port $remote_port --group $egress_group --kbd-interactive

    # ...and require TOTP on that egress hop. This is what makes account4 validate its TOTP when going
    # through, populating type.totp=1/validated=1 in LC_BASTION_DETAILS for B to trust.
    success set_totp_on_egress_group $a4 --osh groupModify --group $egress_group --mfa-required totp
    json .command groupModify .error_code OK .value.mfa_required.error_code OK
    contain 'policy is now: totp'

    # now set up real TOTP for account4 on A (no factor is required to do the first setup), and grab a
    # couple of emergency scratch codes to use as one-time OTPs
    success a4_setup_totp $a4 --osh selfMFASetupTOTP --no-confirm
    nocontain 'Multi-Factor Authentication enabled'
    local a4_totp_code_1 a4_totp_code_2
    a4_totp_code_1=$(get_stdout | grep -A1 'Your emergency scratch codes are:' | tail -n1 | tr -d '[:space:]')
    a4_totp_code_2=$(get_stdout | grep -A2 'Your emergency scratch codes are:' | tail -n1 | tr -d '[:space:]')

    # enforce a global totp-required policy on B (done now, *after* B's admin set up the realm, so the
    # admin account stays usable). osh reads bastion.conf fresh per invocation, so no reload is needed.
    configsetquoted2 accountMFAPolicy totp-required

    # account4 connects A -> realm_$realm_name@B and, *through* B, attempts
    # to reach a server it has no access to. Two OTPs are asked along the way: one for the ingress login
    # to A (because TOTP is configured), one for the JIT TOTP on the A->B egress hop; this is what gets
    # the already-validated TOTP carried over to B in LC_BASTION_DETAILS for B's login gate to trust.
    #
    # B's gate trusts the realm-carried TOTP and lets us past it; the connection then fails
    # later with a harmless KO_ACCESS_DENIED (exit 107), whose message also proves we were recognized as
    # $realm_name/$account4 on B.
    script a4_crossrealm_totp_connect "echo 'set timeout $default_timeout;
        spawn $a4 realm_$realm_name@$b2ip --kbd-interactive -- $js nevermind@127.0.0.5;
        expect \"code:\" { sleep 0.2; send \"$a4_totp_code_1\\n\"; };
        expect \"code:\" { sleep 0.2; send \"$a4_totp_code_2\\n\"; };
        expect eof;
        lassign [wait] pid spawnid value value;
        exit \$value' | expect -f -"
    retvalshouldbe 107
    nocontain 'KO_MFA_TOTP_SETUP_REQUIRED'
    json .error_code KO_ACCESS_DENIED .error_message "Access denied for $realm_name/$account4 to nevermind@127.0.0.5:22"

    # cleanup: relax B's policy again so its admin can delete the realm, then tear everything down
    configsetquoted2 accountMFAPolicy enabled
    script realmDelete_on_b2 $b2 --osh realmDelete --realm $realm_name "<<< \"Yes, do as I say and delete $realm_name, kthxbye\""

    script a0_delete_a4 $a0 --osh accountDelete --account $account4 "<<< \"Yes, do as I say and delete $account4, kthxbye\""
    retvalshouldbe 0
    json .command accountDelete .error_code OK

    success groupDelete $a0 --osh groupDelete --group $egress_group --no-confirm
}

# this suite drives a real bastion A -> bastion B realm connection, so it needs the second bastion
if { [ "${capabilities[mfa]}" = 1 ] || [ "${capabilities[mfa-password]}" = 1 ]; } && [ -n "${target2_ip:-}" ]; then
    testsuite_mfa_realm
fi
unset -f testsuite_mfa_realm

# the cross-realm TOTP suite needs real PAM TOTP and a second bastion instance
if [ "${capabilities[mfa]}" = 1 ] && [ -n "${target2_ip:-}" ]; then
    testsuite_mfa_realm_totp
fi
unset -f testsuite_mfa_realm_totp
