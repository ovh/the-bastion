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

    ### test personal ssh access, must fail without protocol access, must work with protocol access

    # scp

    success personal_scp_add_ssh_access $a0 --osh selfAddPersonalAccess -h 127.0.0.2 -u $shellaccount -p 22 --kbd-interactive
    success personal_scp_add_scpup_access $a0 --osh selfAddPersonalAccess --host 127.0.0.2 --protocol scpupload --port 22

    sleepafter 2
    run personal_scp_download_oldhelper_mustfail scp $scp_options -F $mytmpdir/ssh_config -S /tmp/scphelper -i $account0key1file $shellaccount@127.0.0.2:uptest /tmp/downloaded
    retvalshouldbe 1
    contain "Sorry, you have ssh access to"

    run personal_scp_download_newwrapper_mustfail env BASTION_SCP_DEBUG=1 /tmp/scpwrapper -i $account0key1file $shellaccount@127.0.0.2:uptest /tmp/downloaded
    retvalshouldbe 1
    contain "Sorry, you have ssh access to"

    success personal_scp_add_scpdown_access $a0 --osh selfAddPersonalAccess --host 127.0.0.2 --protocol scpdownload --port 22

    sleepafter 2
    run personal_scp_download_oldhelper_badfile scp $scp_options -F $mytmpdir/ssh_config -S /tmp/scphelper -i $account0key1file $shellaccount@127.0.0.2:uptest /tmp/downloaded
    retvalshouldbe 1
    contain "through the bastion from"
    contain "Error launching transfer"
    contain "No such file or directory"
    nocontain "Permission denied"

    run personal_scp_download_newwrapper_badfile /tmp/scpwrapper -i $account0key1file $shellaccount@127.0.0.2:uptest /tmp/downloaded
    retvalshouldbe 1
    contain "through the bastion from"
    contain "Error launching transfer"
    contain "No such file or directory"
    nocontain "Permission denied"

    run invalidhostname_scp_oldhelper scp $scp_options -F $mytmpdir/ssh_config -S /tmp/scphelper -i $account0key1file $shellaccount@_invalid._invalid:uptest /tmp/downloaded
    retvalshouldbe 1
    contain REGEX "Sorry, couldn't resolve the host you specified|I was unable to resolve host|Unable to resolve host"

    run invalidhostname_scp_newwrapper /tmp/scpwrapper -i $account0key1file $shellaccount@_invalid._invalid:uptest /tmp/downloaded
    retvalshouldbe 1
    contain REGEX "Sorry, couldn't resolve the host you specified|I was unable to resolve host|Unable to resolve host"

    success personal_scp_upload_oldhelper_ok scp $scp_options -F $mytmpdir/ssh_config -S /tmp/scphelper -i $account0key1file /etc/passwd $shellaccount@127.0.0.2:uptest
    contain "through the bastion to"
    contain "Done,"

    success personal_scp_upload_newwrapper_ok /tmp/scpwrapper -i $account0key1file /etc/passwd $shellaccount@127.0.0.2:uptest
    contain "through the bastion to"
    contain "Done,"

    success personal_scp_download_oldhelper_ok scp $scp_options -F $mytmpdir/ssh_config -S /tmp/scphelper -i $account0key1file $shellaccount@127.0.0.2:uptest /tmp/downloaded
    contain "through the bastion from"
    contain "Done,"

    success personal_scp_download_newwrapper_ok /tmp/scpwrapper -i $account0key1file $shellaccount@127.0.0.2:uptest /tmp/downloaded
    contain "through the bastion from"
    contain "Done,"

    success personal_scp_del_scpup_access $a0 --osh selfDelPersonalAccess --host 127.0.0.2 --protocol scpupload --port 22
    success personal_scp_del_scpdown_access $a0 --osh selfDelPersonalAccess --host 127.0.0.2 --protocol scpdownload --port 22

    # sftp

    if [ "$COUNTONLY" != 1 ]; then
        printf "ls\nexit\n" >"/tmp/sftpcommands"
    fi

    run personal_sftp_use_oldhelper_mustfail sftp -F $mytmpdir/ssh_config -S /tmp/sftphelper -i $account0key1file $shellaccount@127.0.0.2
    retvalshouldbe 255
    contain "Sorry, you have ssh access to"

    run personal_sftp_use_newwrapper_mustfail /tmp/sftpwrapper -i $account0key1file $shellaccount@127.0.0.2
    retvalshouldbe 255
    contain "Sorry, you have ssh access to"

    success personal_sftp_add_sftp_access $a0 --osh selfAddPersonalAccess --host 127.0.0.2 --sftp --port 22

    success personal_sftp_use_oldhelper_ok sftp -F $mytmpdir/ssh_config -b /tmp/sftpcommands -S /tmp/sftphelper -i $account0key1file $shellaccount@127.0.0.2
    contain 'sftp> ls'
    contain 'uptest'
    contain 'sftp> exit'
    contain '>>> Done,'

    success personal_sftp_use_newwrapper_ok /tmp/sftpwrapper -b /tmp/sftpcommands -i $account0key1file $shellaccount@127.0.0.2
    contain 'sftp> ls'
    contain 'uptest'
    contain 'sftp> exit'
    contain '>>> Done,'

    success personal_sftp_del_sftp_access $a0 --osh selfDelPersonalAccess --host 127.0.0.2 --protocol sftp --port 22

    # rsync

    run personal_rsync_use_mustfail rsync --rsh \"$a0 --osh rsync --\" /etc/passwd $shellaccount@127.0.0.2:/tmp/
    retvalshouldbe 2
    contain "Sorry, you have ssh access to"

    success personal_rsync_add_rsync_access $a0 --osh selfAddPersonalAccess --host 127.0.0.2 --protocol rsync --port 22

    success personal_rsync_upload_ok rsync --rsh \"$a0 --osh rsync --\" /etc/passwd $shellaccount@127.0.0.2:rsync_file
    nocontain "rsync:"
    nocontain "rsync error:"
    contain ">>> Hello"
    contain ">>> Done,"

    success personal_rsync_download_ok rsync --rsh \"$a0 --osh rsync --\" $shellaccount@127.0.0.2:rsync_file /tmp/downloaded
    nocontain "rsync:"
    nocontain "rsync error:"
    contain ">>> Hello"
    contain ">>> Done,"

    success personal_rsync_del_rsync_access $a0 --osh selfDelPersonalAccess --host 127.0.0.2 --protocol rsync --port 22

    ### test personal ssh access with group protocol access, must fail, and works only if group ssh access is added too

    # create group1
    success groupCreate $a0 --osh groupCreate --group $group1 --owner $account0 --algo ed25519 --size 256
    json .error_code OK .command groupCreate
    local g1key
    g1key="$(get_json | jq '.value.public_key.line')"

    # push group1 egress key to $shellaccount@localhost
    success personalssh_groupprotocol_add_key_to_shellaccount $r0 "echo '$g1key' \>\> ~$shellaccount/.ssh/authorized_keys"

    # add server to group1
    success personalssh_groupprotocol_add_server_to_group $a0 --osh groupAddServer --group $group1 --host 127.0.0.2 --user $shellaccount --port 22

    # scp

    run personalssh_groupprotocol_scp_download_mustfail /tmp/scpwrapper -i $account0key1file $shellaccount@127.0.0.2:passwd /tmp/
    retvalshouldbe 1
    contain 'MFA_TOKEN=notrequired'
    contain 'need to be granted specifically for scpdownload'
    nocontain '>>> Done'

    run personalssh_groupprotocol_scp_upload_mustfail /tmp/scpwrapper -i $account0key1file /etc/passwd $shellaccount@127.0.0.2:
    retvalshouldbe 1
    contain 'MFA_TOKEN=notrequired'
    contain 'need to be granted specifically for scpupload'
    nocontain '>>> Done'

    success groupssh_groupprotocol_scp_add_scpup_access $a0 --osh groupAddServer --group $group1 --host 127.0.0.2 --protocol scpupload --port 22

    success groupssh_groupprotocol_scp_upload_ok /tmp/scpwrapper -i $account0key1file /etc/passwd $shellaccount@127.0.0.2:
    contain 'MFA_TOKEN=notrequired'
    contain 'transferring your file through the bastion'
    contain '>>> Done'

    run personalssh_groupprotocol_scp_download_mustfail /tmp/scpwrapper -i $account0key1file $shellaccount@127.0.0.2:passwd /tmp/
    retvalshouldbe 1
    contain 'MFA_TOKEN=notrequired'
    contain 'need to be granted specifically for scpdownload'
    nocontain '>>> Done'

    success groupssh_groupprotocol_scp_del_scpup_access $a0 --osh groupDelServer --group $group1 --host 127.0.0.2 --protocol scpupload --port 22

    # sftp

    run personalssh_groupprotocol_sftp_download_mustfail /tmp/sftpwrapper -i $account0key1file sftp://$shellaccount@127.0.0.2//etc/passwd
    retvalshouldbe 255
    contain 'MFA_TOKEN=notrequired'
    contain 'need to be granted specifically for sftp'
    nocontain '>>> Done'

    success groupssh_groupprotocol_sftp_add_sftp_access $a0 --osh groupAddServer --group $group1 --host 127.0.0.2 --protocol sftp --port 22

    success groupssh_groupprotocol_sftp_use_ok /tmp/sftpwrapper -i $account0key1file sftp://$shellaccount@127.0.0.2//etc/passwd
    contain 'MFA_TOKEN=notrequired'
    contain 'Fetching /etc/passwd'
    contain '>>> Done'

    success groupssh_groupprotocol_sftp_del_sftp_access $a0 --osh groupDelServer --group $group1 --host 127.0.0.2 --protocol sftp --port 22

    # rsync

    run personalssh_groupprotocol_rsync_download_mustfail rsync --rsh \"$a0 --osh rsync --\" $shellaccount@127.0.0.2:/etc/passwd /tmp/
    retvalshouldbe 2
    contain 'need to be granted specifically for rsync'
    nocontain '>>> Done'

    success groupssh_groupprotocol_rsync_add_rsync_access $a0 --osh groupAddServer --group $group1 --host 127.0.0.2 --protocol rsync --port 22

    success groupssh_groupprotocol_rsync_use_ok rsync --rsh \"$a0 --osh rsync --\" $shellaccount@127.0.0.2:/etc/passwd /tmp/
    contain '>>> Hello'
    contain '>>> Done,'

    success groupssh_groupprotocol_rsync_del_rsync_access $a0 --osh groupDelServer --group $group1 --host 127.0.0.2 --protocol rsync --port 22

    ## set --personal-egress-mfa-required on this account, and add matching ssh/proto personal access: scp/sftp must request MFA, rsync must be denied

    success personal_egress_mfa $a0 --osh accountModify --account $account0 --personal-egress-mfa-required password

    success personal_access_add_scpup $a0 --osh selfAddPersonalAccess --host 127.0.0.2 --port 22 --protocol scpupload
    success personal_access_add_sftp $a0 --osh selfAddPersonalAccess --host 127.0.0.2 --port 22 --protocol sftp
    success personal_access_add_rsync $a0 --osh selfAddPersonalAccess --host 127.0.0.2 --port 22 --protocol rsync

    # scp

    run account_mfa_scp_upload_mfa_fail /tmp/scpwrapper -i $account0key1file /etc/passwd $shellaccount@127.0.0.2:
    retvalshouldbe 1
    nocontain 'MFA_TOKEN=notrequired'
    contain 'entering MFA phase'
    contain 'you need to setup the Multi-Factor Authentication for this plugin'

    # sftp

    run account_mfa_sftp_use_mfa_fail /tmp/sftpwrapper -i $account0key1file sftp://$shellaccount@127.0.0.2//etc/passwd
    retvalshouldbe 1
    nocontain 'MFA_TOKEN=notrequired'
    contain 'entering MFA phase'
    contain 'you need to setup the Multi-Factor Authentication for this plugin'

    # rsync

    run account_mfa_rsync_use_mfa_fail rsync --rsh \"$a0 --osh rsync --\" $shellaccount@127.0.0.2:/etc/passwd /tmp/
    retvalshouldbe 2
    contain 'MFA is required for this host, which is not supported by rsync'
    contain 'rsync error:'

    # reset --personal-egress-mfa-required on this account and remove protocol personal accesses

    success personal_egress_nomfa $a0 --osh accountModify --account $account0 --personal-egress-mfa-required none

    success personal_access_del_scpup $a0 --osh selfDelPersonalAccess --host 127.0.0.2 --port 22 --protocol scpupload
    success personal_access_del_sftp $a0 --osh selfDelPersonalAccess --host 127.0.0.2 --port 22 --protocol sftp
    success personal_access_del_rsync $a0 --osh selfDelPersonalAccess --host 127.0.0.2 --port 22 --protocol rsync

    ## set MFA required on group (and add back group protocol access), MFA should be asked by scp/sftp, and rsync should abort

    success group_need_mfa $a0 --osh groupModify --group $group1 --mfa-required password
    success account_mfa_scp_add_scpup_access $a0 --osh groupAddServer --group $group1 --host 127.0.0.2 --protocol scpupload --port 22
    success account_mfa_sftp_add_sftp_access $a0 --osh groupAddServer --group $group1 --host 127.0.0.2 --protocol sftp --port 22
    success account_mfa_rsync_add_rsync_access $a0 --osh groupAddServer --group $group1 --host 127.0.0.2 --protocol rsync --port 22

    # scp

    run group_mfa_scp_upload_mfa_fail /tmp/scpwrapper -i $account0key1file /etc/passwd $shellaccount@127.0.0.2:
    retvalshouldbe 1
    nocontain 'MFA_TOKEN=notrequired'
    contain 'entering MFA phase'
    contain 'you need to setup the Multi-Factor Authentication for this plugin'

    # sftp

    run group_mfa_sftp_upload_mfa_fail /tmp/sftpwrapper -i $account0key1file sftp://$shellaccount@127.0.0.2//etc/passwd
    retvalshouldbe 1
    nocontain 'MFA_TOKEN=notrequired'
    contain 'entering MFA phase'
    contain 'you need to setup the Multi-Factor Authentication for this plugin'

    # rsync

    run group_mfa_rsync_use_mfa_fail rsync --rsh \"$a0 --osh rsync --\" $shellaccount@127.0.0.2:/etc/passwd /tmp/
    retvalshouldbe 2
    nocontain 'MFA_TOKEN='
    contain 'MFA is required for this host, which is not supported by rsync'
    contain 'rsync error:'

    ## keep MFA required on group, but setup MFA on our account, so we can test the MFA process

    # setup MFA on our account, step1
    run personal_mfa_setup_step1of2 $a0f --osh selfMFASetupPassword --yes
    retvalshouldbe 124
    contain 'enter this:'
    local a0_password_tmp
    a0_password_tmp=$(get_stdout | grep -Eo 'enter this: [a-zA-Z0-9_-]+' | sed -e 's/enter this: //')

    # setup our password, step2
    local a0_password='ohz8Ciujuboh'
    script personal_mfa_setup_step2of2 "echo 'set timeout $default_timeout;
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

    # scp

    script group_mfa_scp_upload_mfa_ok "echo 'set timeout $default_timeout;
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

    # sftp

    script group_mfa_sftp_use_mfa_ok "echo 'set timeout $default_timeout;
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

    # rsync

    run group_mfa_rsync_use_mfa_unsupported rsync --rsh \"$a0 --osh rsync --\" $shellaccount@127.0.0.2:/etc/passwd /tmp/
    retvalshouldbe 2
    nocontain 'MFA_TOKEN='
    contain 'MFA is required for this host, which is not supported by rsync'
    contain 'rsync error:'

    # provide invalid tokens manually

    for proto in scp sftp; do
        run ${proto}_upload_bad_token_format $a0 --osh ${proto} --host 127.0.0.2 --port 22 --user $shellaccount --mfa-token invalid
        retvalshouldbe 125
        json .error_code KO_MFA_FAILED_INVALID_FORMAT

        local invalid_token
        invalid_token="v1,$(perl -e 'CORE::say time()-3600'),9f25d680b1bae2ef73abc3c62926ddb9c88f8ea1f4120b1125cc09720c74268b"
        run ${proto}_upload_bad_token_expired $a0 --osh ${proto} --host 127.0.0.2 --port 22 --user $shellaccount --mfa-token "$invalid_token"
        retvalshouldbe 125
        json .error_code KO_MFA_FAILED_EXPIRED_TOKEN

        invalid_token="v1,$(perl -e 'CORE::say time()+3600'),9f25d680b1bae2ef73abc3c62926ddb9c88f8ea1f4120b1125cc09720c74268b"
        run ${proto}_upload_bad_token_future $a0 --osh ${proto} --host 127.0.0.2 --port 22 --user $shellaccount --mfa-token "$invalid_token"
        retvalshouldbe 125
        json .error_code KO_MFA_FAILED_FUTURE_TOKEN
    done

    # remove MFA from account
    if [ "${capabilities[mfa]}" = 1 ] || [ "${capabilities[mfa-password]}" = 1 ]; then
        script personal_mfa_reset_password "echo 'set timeout $default_timeout;
            spawn $a0 --osh selfMFAResetPassword;
            expect \"additional authentication factor is required (password)\" { sleep 0.1; };
            expect \"word:\" { sleep 0.2; send \"$a0_password\\n\"; };
            expect eof;
            lassign [wait] pid spawnid value value;
            exit \$value' | timeout --foreground $default_timeout expect -f -"
            retvalshouldbe 0
            json .error_code OK .command selfMFAResetPassword
    else
        success personal_mfa_reset_password $a0 --osh accountMFAResetPassword --account $account0
    fi

    ## set account as exempt from MFA, and see whether scp/sftp/rsync (that still require MFA as per the group) do work

    success personal_mfa_set_exempt $a0 --osh accountModify --account $account0 --mfa-password-required bypass

    success scp_upload_mfa_exempt_oldhelper_ok /tmp/scpwrapper -i $account0key1file /etc/passwd $shellaccount@127.0.0.2:
    nocontain 'MFA_TOKEN=v1'
    contain 'MFA_TOKEN=notrequired'
    contain 'skipping as your account is exempt from MFA'

    script sftp_upload_mfa_exempt_oldhelper_ok /tmp/sftpwrapper -i $account0key1file sftp://$shellaccount@127.0.0.2//etc/passwd
    nocontain 'MFA_TOKEN=v1'
    contain 'MFA_TOKEN=notrequired'
    contain 'skipping as your account is exempt from MFA'

    sleepafter 2
    success scp_upload_mfa_exempt_oldwrapper_ok scp $scp_options -F $mytmpdir/ssh_config -S /tmp/scphelper -i $account0key1file /etc/passwd $shellaccount@127.0.0.2:uptest
    contain 'skipping as your account is exempt from MFA'
    contain "through the bastion to"
    contain "Done,"

    success sftp_use_mfa_exempt_oldwrapper_ok sftp -F $mytmpdir/ssh_config -b /tmp/sftpcommands -S /tmp/sftphelper -i $account0key1file $shellaccount@127.0.0.2
    contain 'skipping as your account is exempt from MFA'
    contain 'sftp> ls'
    contain 'uptest'
    contain 'sftp> exit'
    contain '>>> Done,'

    run rsync_use_mfa_exempt_ok rsync --rsh \"$a0 --osh rsync --\" $shellaccount@127.0.0.2:/etc/passwd /tmp/
    nocontain "rsync:"
    nocontain "rsync error:"
    contain "requires password MFA but your account has password MFA bypass, allowing"
    contain ">>> Hello"
    contain ">>> Done,"

    # reset account setup
    success personal_mfa_reset_policy $a0 --osh accountModify --account $account0 --mfa-password-required no

    # delete group1
    success groupDestroy $a0 --osh groupDestroy --group $group1 --no-confirm
}

testsuite_mfa_scp_sftp
unset -f testsuite_mfa_scp_sftp
