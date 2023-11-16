# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_mfa_scp_sftp()
{
    # these are the old pre-3.14.15 helper versions, we want to check for descendant compatibility
    cat >/tmp/scphelper <<'EOF'
#! /bin/sh
while ! [ "$1" = "--" ] ; do
    if [ "$1" = "-l" ] ; then
        remoteuser="--user $2"
        shift 2
    elif [ "$1" = "-p" ] ; then
        remoteport="--port $2"
        shift 2
    elif [ "$1" = "-s" ]; then
        # caller is a newer scp that tries to use the sftp subsystem
        # instead of plain old scp, warn because it won't work
        echo "scpwrapper: WARNING: your scp version is recent, you need to add '-O' to your scp command-line, exiting." >&2
        exit 1
    else
        sshcmdline="$sshcmdline $1"
        shift
    fi
done
host="$2"
scpcmd=`echo "$3" | sed -e 's/#/##/g;s/ /#/g'`
EOF
    echo "exec ssh -p $remote_port $account0@$remote_ip -T \$sshcmdline -- \$remoteuser \$remoteport --host \$host --osh scp --scp-cmd \"\$scpcmd\"" >> /tmp/scphelper
    chmod +x /tmp/scphelper

    cat >/tmp/sftphelper <<'EOF'
#! /usr/bin/env bash
shopt -s nocasematch

while ! [ "$1" = "--" ] ; do
    # user
    if [ "$1" = "-l" ] ; then
        remoteuser="--user $2"
        shift 2
    elif [[ $1 =~ ^-oUser[=\ ]([^\ ]+)$ ]] ; then
        remoteuser="--user ${BASH_REMATCH[1]}"
        shift
    elif [ "$1" = "-o" ] && [[ $2 =~ ^user=([0-9]+)$ ]] ; then
        remoteuser="--user ${BASH_REMATCH[1]}"
        shift 2

    # port
    elif [ "$1" = "-p" ] ; then
        remoteport="--port $2"
        shift 2
    elif [[ $1 =~ ^-oPort[=\ ]([0-9]+)$ ]] ; then
        remoteport="--port ${BASH_REMATCH[1]}"
        shift
    elif [ "$1" = "-o" ] && [[ $2 =~ ^port=([0-9]+)$ ]] ; then
        remoteport="--port ${BASH_REMATCH[1]}"
        shift 2

    # other '-oFoo Bar'
    elif [[ $1 =~ ^-o([^\ ]+)\ (.+)$ ]] ; then
        sshcmdline="$sshcmdline -o${BASH_REMATCH[1]}=${BASH_REMATCH[2]}"
        shift

    # don't forward -s
    elif [ "$1" = "-s" ]; then
        shift

    # other stuff passed directly to ssh
    else
        sshcmdline="$sshcmdline $1"
        shift
    fi
done

# after '--', remaining args are always host then 'sftp'
host="$2"
subsystem="$3"
if [ "$subsystem" != sftp ]; then
    echo "Unknown subsystem requested '$subsystem', expected 'sftp'" >&2
    exit 1
fi

# if host is in the form remoteuser@remotehost, split it
if [[ $host =~ @ ]]; then
    remoteuser="--user ${host%@*}"
    host=${host#*@}
fi
EOF
    echo "exec ssh -p $remote_port $account0@$remote_ip -T \$sshcmdline -- \$remoteuser \$remoteport --host \$host --osh sftp" >> /tmp/sftphelper
    chmod +x /tmp/sftphelper

    ## get both helpers first
    for proto in scp sftp; do
        success $proto $a0 --osh $proto
        if [ "$COUNTONLY" != 1 ]; then
            get_json | $jq '.value.script' | base64 -d | gunzip -c > /tmp/${proto}wrapper
            perl -i -pe 'print "BASTION_SCP_DEBUG=1\nBASTION_SFTP_DEBUG=1\n" if ++$line==2' "/tmp/${proto}wrapper"
            chmod +x /tmp/${proto}wrapper
        fi
    done
    unset proto

    # scp

    ## detect recent scp
    local scp_options=""
    if [ "$COUNTONLY" != 1 ]; then
        if scp -O -S /bin/true a: b 2>/dev/null; then
            echo "scp: will use new version params"
            scp_options="-O"
        else
            echo "scp: will use old version params"
        fi
    fi

    grant selfAddPersonalAccess
    grant selfDelPersonalAccess

    success a0_add_ssh_access $a0 --osh selfAddPersonalAccess -h 127.0.0.2 -u $shellaccount -p 22 --kbd-interactive
    success a0_add_scp_up $a0 --osh selfAddPersonalAccess --host 127.0.0.2 --scpup --port 22

    sleepafter 2
    run scp_downloadfailnoright_old scp $scp_options -F $mytmpdir/ssh_config -S /tmp/scphelper -i $account0key1file $shellaccount@127.0.0.2:uptest /tmp/downloaded
    retvalshouldbe 1
    contain "Sorry, but even"

    run scp_downloadfailnoright_new env BASTION_SCP_DEBUG=1 /tmp/scpwrapper -i $account0key1file $shellaccount@127.0.0.2:uptest /tmp/downloaded
    retvalshouldbe 1
    contain "Sorry, but even"

    success a0_add_scp_down $a0 --osh selfAddPersonalAccess --host 127.0.0.2 --scpdown --port 22

    sleepafter 2
    run scp_downloadfailnofile_old scp $scp_options -F $mytmpdir/ssh_config -S /tmp/scphelper -i $account0key1file $shellaccount@127.0.0.2:uptest /tmp/downloaded
    retvalshouldbe 1
    contain "through the bastion from"
    contain "Error launching transfer"
    contain "No such file or directory"
    nocontain "Permission denied"

    run scp_downloadfailnofile_new /tmp/scpwrapper -i $account0key1file $shellaccount@127.0.0.2:uptest /tmp/downloaded
    retvalshouldbe 1
    contain "through the bastion from"
    contain "Error launching transfer"
    contain "No such file or directory"
    nocontain "Permission denied"

    run scp_invalidhostname_old scp $scp_options -F $mytmpdir/ssh_config -S /tmp/scphelper -i $account0key1file $shellaccount@_invalid._invalid:uptest /tmp/downloaded
    retvalshouldbe 1
    contain REGEX "Sorry, couldn't resolve the host you specified|I was unable to resolve host"

    run scp_invalidhostname_new /tmp/scpwrapper -i $account0key1file $shellaccount@_invalid._invalid:uptest /tmp/downloaded
    retvalshouldbe 1
    contain REGEX "Sorry, couldn't resolve the host you specified|I was unable to resolve host"

    success scp_upload_old scp $scp_options -F $mytmpdir/ssh_config -S /tmp/scphelper -i $account0key1file /etc/passwd $shellaccount@127.0.0.2:uptest
    contain "through the bastion to"
    contain "Done,"

    success scp_upload_new /tmp/scpwrapper -i $account0key1file /etc/passwd $shellaccount@127.0.0.2:uptest
    contain "through the bastion to"
    contain "Done,"

    success scp_download_old scp $scp_options -F $mytmpdir/ssh_config -S /tmp/scphelper -i $account0key1file $shellaccount@127.0.0.2:uptest /tmp/downloaded
    contain "through the bastion from"
    contain "Done,"

    success scp_download_new /tmp/scpwrapper -i $account0key1file $shellaccount@127.0.0.2:uptest /tmp/downloaded
    contain "through the bastion from"
    contain "Done,"

    success forscpremove1 $a0 --osh selfDelPersonalAccess --host 127.0.0.2 --scpup   --port 22
    success forscpremove2 $a0 --osh selfDelPersonalAccess --host 127.0.0.2 --scpdown --port 22

    # sftp

    run sftp_no_access_old sftp -F $mytmpdir/ssh_config -S /tmp/sftphelper -i $account0key1file $shellaccount@127.0.0.2
    retvalshouldbe 255
    contain "Sorry, but even"

    run sftp_no_access_new /tmp/sftpwrapper -i $account0key1file $shellaccount@127.0.0.2
    retvalshouldbe 255
    contain "Sorry, but even"

    success forsftp $a0 --osh selfAddPersonalAccess --host 127.0.0.2 --sftp --port 22

    if [ "$COUNTONLY" != 1 ]; then
        cat >"/tmp/sftpcommands" <<'EOF'
ls
exit
EOF
    fi

    success sftp_access_old sftp -F $mytmpdir/ssh_config -b /tmp/sftpcommands -S /tmp/sftphelper -i $account0key1file $shellaccount@127.0.0.2
    contain 'sftp> ls'
    contain 'uptest'
    contain 'sftp> exit'
    contain '>>> Done,'

    success sftp_access_new /tmp/sftpwrapper -b /tmp/sftpcommands -i $account0key1file $shellaccount@127.0.0.2
    contain 'sftp> ls'
    contain 'uptest'
    contain 'sftp> exit'
    contain '>>> Done,'

    success forsftpremove $a0 --osh selfDelPersonalAccess --host 127.0.0.2 --sftp --port 22

    grant groupCreate

    # create group1
    success groupCreate $a0 --osh groupCreate --group $group1 --owner $account0 --algo ed25519 --size 256
    json .error_code OK .command groupCreate
    local g1key
    g1key="$(get_json | jq '.value.public_key.line')"

    revoke groupCreate

    # push group1 egress key to $shellaccount@localhost
    success add_grp1_key_to_shellaccount $r0 "echo '$g1key' \>\> ~$shellaccount/.ssh/authorized_keys"

    # add server to group1
    success groupAddServer $a0 --osh groupAddServer --group $group1 --host 127.0.0.2 --user $shellaccount --port 22

    # scp: upload something (denied, not granted)
    run scp_upload_denied /tmp/scpwrapper -i $account0key1file $shellaccount@127.0.0.2:passwd /tmp/
    retvalshouldbe 1
    contain 'MFA_TOKEN=notrequired'
    contain 'you still need to be granted specifically for scp'
    nocontain '>>> Done'

    # allow scpup
    success allow_scpup $a0 --osh groupAddServer --group $group1 --host 127.0.0.2 --scpup --port 22

    # scp: upload something
    success scp_upload /tmp/scpwrapper -i $account0key1file /etc/passwd $shellaccount@127.0.0.2:
    contain 'MFA_TOKEN=notrequired'
    contain 'transferring your file through the bastion'
    contain '>>> Done'

    # sftp: download something (denied, not granted)
    run sftp_download_denied /tmp/sftpwrapper -i $account0key1file sftp://$shellaccount@127.0.0.2//etc/passwd
    retvalshouldbe 255
    contain 'MFA_TOKEN=notrequired'
    contain 'you still need to be granted specifically for sftp'
    nocontain '>>> Done'

    # allow sftp
    success allow_sftp $a0 --osh groupAddServer --group $group1 --host 127.0.0.2 --sftp --port 22

    # sftp: download something
    success sftp_download /tmp/sftpwrapper -i $account0key1file sftp://$shellaccount@127.0.0.2//etc/passwd
    contain 'MFA_TOKEN=notrequired'
    contain 'Fetching /etc/passwd'
    contain '>>> Done'

    # set --personal-egress-mfa-required on this account
    grant accountModify
    success personal_egress_mfa $a0 --osh accountModify --account $account0 --personal-egress-mfa-required password

    # add personal access
    grant selfAddPersonalAccess
    success a0_add_personal_access_ssh $a0 --osh selfAddPersonalAccess --host 127.0.0.2 --user $shellaccount --port 22 --force
    success a0_add_personal_access_scpup $a0 --osh selfAddPersonalAccess --host 127.0.0.2 --scpup --port 22
    success a0_add_personal_access_sftp $a0 --osh selfAddPersonalAccess --host 127.0.0.2 --sftp --port 22
    revoke selfAddPersonalAccess

    # scp: upload something after personal mfa, wont work
    run scp_upload_personal_mfa_fail /tmp/scpwrapper -i $account0key1file /etc/passwd $shellaccount@127.0.0.2:
    retvalshouldbe 1
    nocontain 'MFA_TOKEN=notrequired'
    contain 'entering MFA phase'
    contain 'you need to setup the Multi-Factor Authentication for this plugin'

    # sftp: download something after personal mfa, wont work
    run sftp_upload_personal_mfa_fail /tmp/sftpwrapper -i $account0key1file sftp://$shellaccount@127.0.0.2//etc/passwd
    retvalshouldbe 1
    nocontain 'MFA_TOKEN=notrequired'
    contain 'entering MFA phase'
    contain 'you need to setup the Multi-Factor Authentication for this plugin'

    # reset --personal-egress-mfa-required on this account
    success personal_egress_nomfa $a0 --osh accountModify --account $account0 --personal-egress-mfa-required none
    revoke accountModify

    # del personal access
    grant selfDelPersonalAccess
    success a0_del_personal_access_ssh $a0 --osh selfDelPersonalAccess --host 127.0.0.2 --user $shellaccount --port 22
    success a0_del_personal_access_scpup $a0 --osh selfDelPersonalAccess --host 127.0.0.2 --scpup --port 22
    success a0_del_personal_access_sftp $a0 --osh selfDelPersonalAccess --host 127.0.0.2 --sftp --port 22
    revoke selfDelPersonalAccess

    # now set MFA required on group
    success group_need_mfa $a0 --osh groupModify --group $group1 --mfa-required password

    # scp: upload something after mfa, wont work
    run scp_upload_mfa_fail /tmp/scpwrapper -i $account0key1file /etc/passwd $shellaccount@127.0.0.2:
    retvalshouldbe 1
    nocontain 'MFA_TOKEN=notrequired'
    contain 'entering MFA phase'
    contain 'you need to setup the Multi-Factor Authentication for this plugin'

    # sftp: download something after mfa, wont work
    run sftp_upload_mfa_fail /tmp/sftpwrapper -i $account0key1file sftp://$shellaccount@127.0.0.2//etc/passwd
    retvalshouldbe 1
    nocontain 'MFA_TOKEN=notrequired'
    contain 'entering MFA phase'
    contain 'you need to setup the Multi-Factor Authentication for this plugin'

    # setup MFA on our account, step1
    run a0_setup_pass_step1of2 $a0f --osh selfMFASetupPassword --yes
    retvalshouldbe 124
    contain 'enter this:'
    local a0_password_tmp
    a0_password_tmp=$(get_stdout | grep -Eo 'enter this: [a-zA-Z0-9_-]+' | sed -e 's/enter this: //')

    # setup our password, step2
    local a0_password='ohz8Ciujuboh'
    script a0_setup_pass_step2of2 "echo 'set timeout $default_timeout;
        spawn $a0 --osh selfMFASetupPassword --yes;
        expect \":\" { sleep 0.2; send \"$a0_password_tmp\\n\"; };
        expect \":\" { sleep 0.2; send \"$a0_password\\n\"; };
        expect \":\" { sleep 0.2; send \"$a0_password\\n\"; };
        expect eof;
        lassign [wait] pid spawnid value value;
        exit \$value' | timeout --foreground $default_timeout expect -f -"
    retvalshouldbe 0
    unset a0_password_tmp
    nocontain 'enter this:'
    nocontain 'unchanged'
    nocontain 'sorry'
    json .command selfMFASetupPassword .error_code OK

    # scp: upload something after mfa, should work
    script scp_upload_mfa_ok "echo 'set timeout $default_timeout;
        spawn /tmp/scpwrapper -i $account0key1file /etc/passwd $shellaccount@127.0.0.2: ;
        expect \"is required (password)\" { sleep 0.1; };
        expect \":\" { sleep 0.2; send \"$a0_password\\n\"; };
        expect eof;
        lassign [wait] pid spawnid value value;
        exit \$value' | timeout --foreground $default_timeout expect -f -"
    nocontain 'MFA_TOKEN=notrequired'
    if [ "${capabilities[mfa]}" = 1 ] || [ "${capabilities[mfa-password]}" = 1 ]; then
        retvalshouldbe 0
        contain 'MFA_TOKEN=v1,'
    else
        retvalshouldbe 1
        contain 'this bastion is missing'
    fi

    # sftp: upload something after mfa, should work
    script sftp_upload_mfa_ok "echo 'set timeout $default_timeout;
        spawn /tmp/sftpwrapper -i $account0key1file sftp://$shellaccount@127.0.0.2//etc/passwd ;
        expect \"is required (password)\" { sleep 0.1; };
        expect \":\" { sleep 0.2; send \"$a0_password\\n\"; };
        expect eof;
        lassign [wait] pid spawnid value value;
        exit \$value' | timeout --foreground $default_timeout expect -f -"
    nocontain 'MFA_TOKEN=notrequired'
    if [ "${capabilities[mfa]}" = 1 ] || [ "${capabilities[mfa-password]}" = 1 ]; then
        retvalshouldbe 0
        contain 'MFA_TOKEN=v1,'
    else
        retvalshouldbe 1
        contain 'this bastion is missing'
    fi

    # provide invalid tokens manually
    run scp_upload_bad_token_format $a0 --osh scp --host 127.0.0.2 --port 22 --user $shellaccount --mfa-token invalid
    retvalshouldbe 125
    json .error_code KO_MFA_FAILED_INVALID_FORMAT

    local invalid_token
    invalid_token="v1,$(perl -e 'CORE::say time()-3600'),9f25d680b1bae2ef73abc3c62926ddb9c88f8ea1f4120b1125cc09720c74268b"
    run scp_upload_bad_token_expired $a0 --osh scp --host 127.0.0.2 --port 22 --user $shellaccount --mfa-token "$invalid_token"
    retvalshouldbe 125
    json .error_code KO_MFA_FAILED_EXPIRED_TOKEN

    invalid_token="v1,$(perl -e 'CORE::say time()+3600'),9f25d680b1bae2ef73abc3c62926ddb9c88f8ea1f4120b1125cc09720c74268b"
    run scp_upload_bad_token_future $a0 --osh scp --host 127.0.0.2 --port 22 --user $shellaccount --mfa-token "$invalid_token"
    retvalshouldbe 125
    json .error_code KO_MFA_FAILED_FUTURE_TOKEN

    # remove MFA from account
    if [ "${capabilities[mfa]}" = 1 ] || [ "${capabilities[mfa-password]}" = 1 ]; then
        script a0_reset_password "echo 'set timeout $default_timeout;
            spawn $a0 --osh selfMFAResetPassword;
            expect \"additional authentication factor is required (password)\" { sleep 0.1; };
            expect \"word:\" { sleep 0.2; send \"$a0_password\\n\"; };
            expect eof;
            lassign [wait] pid spawnid value value;
            exit \$value' | timeout --foreground $default_timeout expect -f -"
            retvalshouldbe 0
            json .error_code OK .command selfMFAResetPassword
    else
        grant accountMFAResetPassword
        success a0_reset_password $a0 --osh accountMFAResetPassword --account $account0
    fi

    # set account as exempt from MFA
    grant accountModify
    success a0_mfa_bypass $a0 --osh accountModify --account $account0 --mfa-password-required bypass

    # scp: upload something after exempt from mfa
    success scp_upload_mfa_exempt_ok /tmp/scpwrapper -i $account0key1file /etc/passwd $shellaccount@127.0.0.2:
    nocontain 'MFA_TOKEN=v1'
    contain 'MFA_TOKEN=notrequired'
    contain 'skipping as your account is exempt from MFA'

    # sftp: upload something after except from mfa
    script sftp_upload_mfa_exempt_ok /tmp/sftpwrapper -i $account0key1file sftp://$shellaccount@127.0.0.2//etc/passwd
    nocontain 'MFA_TOKEN=v1'
    contain 'MFA_TOKEN=notrequired'
    contain 'skipping as your account is exempt from MFA'

    # same but with old helpers
    sleepafter 2
    success scp_upload_mfa_exempt_old_ok scp $scp_options -F $mytmpdir/ssh_config -S /tmp/scphelper -i $account0key1file /etc/passwd $shellaccount@127.0.0.2:uptest
    contain 'skipping as your account is exempt from MFA'
    contain "through the bastion to"
    contain "Done,"

    success sftp_list_mfa_exempt_old_ok sftp -F $mytmpdir/ssh_config -b /tmp/sftpcommands -S /tmp/sftphelper -i $account0key1file $shellaccount@127.0.0.2
    contain 'skipping as your account is exempt from MFA'
    contain 'sftp> ls'
    contain 'uptest'
    contain 'sftp> exit'
    contain '>>> Done,'

    # reset account setup
    success a0_mfa_default $a0 --osh accountModify --account $account0 --mfa-password-required no
    revoke accountModify

    # delete group1
    success groupDestroy $a0 --osh groupDestroy --group $group1 --no-confirm

    revoke selfAddPersonalAccess
    revoke selfDelPersonalAccess
}

testsuite_mfa_scp_sftp
unset -f testsuite_mfa_scp_sftp
