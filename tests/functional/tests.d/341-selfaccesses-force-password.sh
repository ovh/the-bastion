# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_selfaccesses_force_password()
{
    # create account4, it will be used as an egress target to test password connections
    success a4_create $a0 --osh accountCreate --always-active --account $account4 --uid $uid4 --public-key "\"$(cat $account4key1file.pub)\""
    json .error_code OK .command accountCreate

    # set account4 to require a password
    success a4_setup_passreq $a0 --osh accountModify --account $account4 --mfa-password-required yes
    json .error_code OK .command accountModify .value.mfa_password_required.error_code OK

    # set a4's ingress password
    a4_password="276r8q76ZF5Y3"
    run a4_setup_pass_1of2 $a4f --osh selfMFASetupPassword --yes
    retvalshouldbe 124
    contain 'enter this:'
    a4_password_tmp=$(get_stdout | grep -Eo 'enter this: [a-zA-Z0-9_-]+' | sed -e 's/enter this: //')
    script a4_setup_pass_2of2 "echo 'set timeout $default_timeout; \
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
    json .error_code OK .command selfMFASetupPassword

    # disable account4's pubkey requirement because autologin doesn't handle that
    success a4_unset_pubkey $a0 --osh accountModify --account $account4 --pubkey-auth-optional yes
    json .error_code OK .command accountModify .value.pubkey_auth_optional.error_code OK

    # on non-mfa systems, temporarily update sshd's config to accept passwords for account4
    if [ "${capabilities[mfa]}" = 0 ] && [ "${capabilities[mfa-password]}" = 0 ]
    then
        success sshd_config_backup $r0 "\"cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.bak\""
        success sshd_config_patch $r0 "\"sed -i 's/^ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config\""
        success sshd_config_patch $r0 "\"echo -e 'Match User ${account4}\n  KbdInteractiveAuthentication yes\n  AuthenticationMethods keyboard-interactive' >> /etc/ssh/sshd_config\""
        success sshd_reload $r0 "\"pkill -SIGHUP -f '^(/usr/sbin/sshd\\\$|sshd.+listener)'\""
        # during tests, under some OSes it takes some time for sshd to accept new connections again after the SIGHUP
        [ "$COUNTONLY" != 1 ] && sleep 1
    fi


    # the tests for personal/group-member accesses are almost the same
    for mode in personal group-member
    do
        # create account1, it will be used to connect to account4
        success a1_create $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
        json .error_code OK .command accountCreate

        local target gen_pass_plugin list_pass_plugin add_access_plugin del_access_plugin password_switch password_base_path
        if [ $mode = "personal" ]
        then
            # in personal mode, we manipulate account1's own personal accesses to connect to account4
            target="--account ${account1}"
            gen_pass_plugin="accountGeneratePassword"
            list_pass_plugin="accountListPasswords"
            add_access_plugin="accountAddPersonalAccess"
            del_access_plugin="accountDelPersonalAccess"
            password_switch="-P"
            password_base_path="/home/${account1}/pass/${account1}"
        else # group-member
            # in group-member mode, account1 is a member of group1 and we manipulate group1's accesses to connect to account4
            target="--group ${group1}"
            gen_pass_plugin="groupGeneratePassword"
            list_pass_plugin="groupListPasswords"
            add_access_plugin="groupAddServer"
            del_access_plugin="groupDelServer"
            password_switch="--password ${group1}"
            password_base_path="/home/key${group1}/pass/${group1}"

            # create group1
            success g1_create $a0 --osh groupCreate --group $group1 --owner $account0 --no-key
            json .error_code OK .command groupCreate

            # add account1 as member
            success g1_member_a1 $a0 --osh groupAddMember --group $group1 --account $account1
            json .error_code OK .command groupAddMember
        fi

        # missing hash
        run ${mode}_add_a4_fp_nohash $a0 --osh $add_access_plugin $target --host $remote_ip --user $account4 --port $remote_port --force-password
        retvalshouldbe 100
        contain "Option force-password requires an argument"
        json .error_code ERR_BAD_OPTIONS .command $add_access_plugin

        # invalid hash
        run ${mode}_add_a4_fp_invalidhash $a0 --osh $add_access_plugin $target --host $remote_ip --user $account4 --port $remote_port --force-password "invalid"
        retvalshouldbe 100
        contain "Specified hash is invalid"
        json .error_code ERR_INVALID_PARAMETER .command $add_access_plugin

        # test if the forced password appears in the access list
        fake_hash='$5$fakefake$fakefakefakefakefakefakefakefakefakefakefak'
        success ${mode}_add_a4_fp_fake $a0 --osh $add_access_plugin $target --host $remote_ip --user $account4 --port $remote_port --force-password "'${fake_hash}'"
        json .error_code OK .command $add_access_plugin

        success ${mode}_listaccess $a0 --osh accountListAccesses --account $account1
        json .error_code OK .command accountListAccesses
        contain "FORCED-PASSWORD"
        json .value[0].acl[0].forcePassword $fake_hash

        success ${mode}_del_a4_fp_fake $a0 --osh $del_access_plugin $target --host $remote_ip --user $account4 --port $remote_port
        json .error_code OK .command $del_access_plugin

        # add a few egress passwords to account1|group1
        success ${mode}_gen_pass1 $a0 --osh $gen_pass_plugin $target --do-it
        json .error_code OK .command $gen_pass_plugin
        success ${mode}_gen_pass2 $a0 --osh $gen_pass_plugin $target --do-it
        json .error_code OK .command $gen_pass_plugin
        success ${mode}_gen_pass3 $a0 --osh $gen_pass_plugin $target --do-it
        json .error_code OK .command $gen_pass_plugin
        success ${mode}_gen_pass4 $a0 --osh $gen_pass_plugin $target --do-it
        json .error_code OK .command $gen_pass_plugin

        # overwrite a1|g1's second egress password with account4's ingress password
        success ${mode}_overwrite_pass2 $r0 "\"echo ${a4_password} > ${password_base_path}.1\""

        # fetch checksums for a1|g1's second and third egress passwords
        success ${mode}_listpass $a0 --osh $list_pass_plugin $target
        json .error_code OK .command $list_pass_plugin
        local password2_sha256 password3_sha256
        password2_sha256=$(get_json | jq -r '.value[1].hashes.sha256crypt')
        password3_sha256=$(get_json | jq -r '.value[2].hashes.sha256crypt')

        # account1 => account4 *without* force-password: success because the correct password is one of the fallbacks
        success ${mode}_add_a4_nofp $a0 --osh $add_access_plugin $target --host $remote_ip --user $account4 --port $remote_port
        json .error_code OK .command $add_access_plugin

        success ${mode}_connect_a4_nofp $a1 $account4@$remote_ip $password_switch -- --osh help --json-greppable
        contain "will use SSH with password autologin"
        contain "trying with fallback password 1 after sleeping"
        nocontain "trying with fallback password 2 after sleeping"
        nocontain "forcing password with hash"
        json .error_code OK .command help

        success ${mode}_del_a4_nofp $a0 --osh $del_access_plugin $target --host $remote_ip --user $account4 --port $remote_port
        json .error_code OK .command $del_access_plugin

        # account1 => account4 with force-password but with a non existant hash: fail because --force-password aborts when the forced password cannot be found
        success ${mode}_add_a4_fp_hashnotfound $a0 --osh $add_access_plugin $target --host $remote_ip --user $account4 --port $remote_port --force-password "'${fake_hash}'"
        json .error_code OK .command $add_access_plugin

        run ${mode}_connect_a4_fp_hashnotfound $a1 $account4@$remote_ip $password_switch -- --osh help
        retvalshouldbe 108
        json .error_code KO_FORCED-PASSWORD-NOT-FOUND
        nocontain "will use SSH with password autologin"

        success ${mode}_del_a4_fp_hashnotfound $a0 --osh $del_access_plugin $target --host $remote_ip --user $account4 --port $remote_port
        json .error_code OK .command $del_access_plugin

        # account1 => account4 with force-password and an existing but wrong hash: autologin fails because it's the wrong password
        success ${mode}_add_a4_fp_wrong $a0 --osh $add_access_plugin $target --host $remote_ip --user $account4 --port $remote_port --force-password "'${password3_sha256}'"
        json .error_code OK .command $add_access_plugin

        run ${mode}_connect_a4_fp_wrong $a1 $account4@$remote_ip $password_switch -- --osh help
        retvalshouldbe 100
        contain "forcing password with hash: ${password3_sha256}"
        contain "will use SSH with password autologin"
        contain "authentication failed"
        nocontain "trying with fallback password 1 after sleeping"

        success ${mode}_del_a4_fp_wrong $a0 --osh $del_access_plugin $target --host $remote_ip --user $account4 --port $remote_port
        json .error_code OK .command $del_access_plugin

        # account1 => account4 with force-password and the correct hash: success
        success ${mode}_add_a4_fp_ok $a0 --osh $add_access_plugin $target --host $remote_ip --user $account4 --port $remote_port --force-password "'${password2_sha256}'"
        json .error_code OK .command $add_access_plugin

        success ${mode}_connect_a4_fp_ok $a1 $account4@$remote_ip $password_switch -- --osh help --json-greppable
        contain "forcing password with hash: ${password2_sha256}"
        contain "will use SSH with password autologin"
        nocontain "trying with fallback password 1 after sleeping"
        json .error_code OK .command help

        success ${mode}_del_a4_fp_ok $a0 --osh $del_access_plugin $target --host $remote_ip --user $account4 --port $remote_port
        json .error_code OK .command $del_access_plugin

        # cleanup
        if [ $mode = "group-member" ]; then
            success ${mode}_delete_g1 $a0 --osh groupDelete --group $group1 --no-confirm
            json .error_code OK .command groupDelete
        fi

        # cleanup account1
        success ${mode}_delete_a1 $a0 --osh accountDelete --account $account1 --no-confirm
        json .error_code OK .command accountDelete
    done

    # final cleanup
    success a4_delete $a0 --osh accountDelete --account $account4 --no-confirm
    json .error_code OK .command accountDelete

    # restore sshd_config on non-mfa systems
    if [ "${capabilities[mfa]}" = 0 ] && [ "${capabilities[mfa-password]}" = 0 ]
    then
        success sshd_config_restore $r0 "\"mv -f /etc/ssh/sshd_config.bak /etc/ssh/sshd_config\""
        success sshd_reload $r0 "\"pkill -SIGHUP -f '^(/usr/sbin/sshd\\\$|sshd.+listener)'\""
    fi

}

testsuite_selfaccesses_force_password
unset -f testsuite_selfaccesses_force_password
