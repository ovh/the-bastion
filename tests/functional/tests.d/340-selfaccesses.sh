# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_selfaccesses()
{
    # now bastion key stuff

    # create 10 accounts with no keys and with default uids
    grant accountCreate

    for i in {1..10}; do
        success a0_create_a1_uidauto_nokey_$i $a0 --osh accountCreate --account delme$i --uid-auto --no-key
        json .error_code OK .command accountCreate
    done

    revoke accountCreate
    grant accountDelete

    # delete those accounts
    for i in {1..10}; do
        script a0_delete_a1_uidauto_nokey_$i $a0 --osh accountDelete --account delme$i "<<< \"Yes, do as I say and delete delme$i, kthxbye\""
        retvalshouldbe 0
        json .error_code OK .command accountDelete
    done

    revoke accountDelete
    grant accountCreate

    unset i

    # create account1
    success accountCreate $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    revoke accountCreate
    grant accountModify

    success modify_account1 $a0 --osh accountModify --pam-auth-bypass yes --account $account1
    json .error_code OK .command accountModify

    # test osh-only
    success enable_osh_only $a0 --osh accountModify --osh-only yes --account $account1
    json .error_code OK .command accountModify

    # account1 can not connect to anything
    run no_ssh_after_osh_only $a1 anybody@127.0.0.1
    retvalshouldbe 107
    json .error_code KO_ACCESS_DENIED .error_message "You don't have the right to connect anywhere"

    success disable_osh_only $a0 --osh accountModify --osh-only no --account $account1
    json .error_code OK .command accountModify

    # account1 can connect now (or could if they were granted)
    run can_ssh_after_osh_only_disable $a1 anybody@127.0.0.1
    retvalshouldbe 107
    json .error_code KO_ACCESS_DENIED
    contain "Access denied"
    nocontain "anywhere"

    revoke accountModify

    success beforeadd $a1 -osh selfListEgressKeys
    tmpfp=$(get_json | $jq '.value|keys[0]')
    json .command selfListEgressKeys .error_code OK '.value|keys[1]'  null
    pattern "^$account1@fix-my-config-please-missing-bastion-name:[0-9]+$" "$(get_json | $jq ".value|.[\"$tmpfp\"]|.comment")"

    success selfGenerateEgressKey $a1 --osh selfGenerateEgressKey --algo rsa --size 4096
    json .error_code OK .command selfGenerateEgressKey .value.size 4096 .value.family RSA
    tmpfp2=$(get_json | $jq '.value.fingerprint')

    success afteradd $a1 -osh selfListEgressKeys
    json .command    selfListEgressKeys .error_code OK '.value|keys[2]'  null
    pattern "^$account1@fix-my-config-please-missing-bastion-name:[0-9]+$" "$(get_json | $jq ".value|.[\"$tmpfp\"]|.comment")"
    pattern "^$account1@fix-my-config-please-missing-bastion-name:[0-9]+$" "$(get_json | $jq ".value|.[\"$tmpfp2\"]|.comment")"
    unset tmpfp
    unset tmpfp2

    # batch plugin

    script batch_one "printf \"%b\\n\" \"info\\naccountInfo --account $account0\\nselfListEgressKeys\" | $a1 --osh batch"
    retvalshouldbe 0
    json .command batch .error_code OK
    json '.value[0].result.error_code' OK '.value[0].command' info '.value[0].result.value.account' "$account1"
    json '.value[1].result.error_code' KO_RESTRICTED_COMMAND '.value[1].command' "accountInfo --account $account0"
    json '.value[2].result.error_code' OK '.value[2].command' selfListEgressKeys

    # ssh

    run a1atlo2 $a1 127.0.0.2 -- id
    retvalshouldbe 107
    contain "Access denied for"
    json .command    null .error_code KO_ACCESS_DENIED

    run invalid_host $a1 127.0./0.1 -- id
    retvalshouldbe 102
    json .error_code KO_HOST_NOT_FOUND

    run invalid_host $a1 127.0.%0.1 -- id
    retvalshouldbe 128
    json .error_code KO_INVALID_REMOTE_HOST

    run invalid_user $a1 ro/ot@127.0.0.1 -- id
    retvalshouldbe 127
    json .error_code KO_INVALID_REMOTE_USER

    grant selfAddPersonalAccess
    grant selfDelPersonalAccess

    run mustfail $a1 -osh selfAddPersonalAccess -h 127.0.0.2 -u $shellaccount -p 22
    retvalshouldbe 106
    contain "you to be specifically granted"
    json .command    null .error_code KO_RESTRICTED_COMMAND

    success mustwork $a0 -osh selfAddPersonalAccess -h 127.0.0.2 -u $shellaccount -p 22 --kbd-interactive
    nocontain "already"
    json .command   selfAddPersonalAccess .error_code   OK .value.ip 127.0.0.2 .value.user $shellaccount .value.port 22

    success dupe $a0 -osh selfAddPersonalAccess -h 127.0.0.2 -u $shellaccount -p 22 --kbd-interactive
    contain "already"
    json .command   selfAddPersonalAccess .error_code   OK_NO_CHANGE .value null

    # test selfAddPersonalAccess config items
    success selfAddPersonalAccess_setconfig1 $r0 "echo '\{\\\"self_remote_user_only\\\":true\,\\\"widest_v4_prefix\\\":30\}' \> $opt_remote_etc_bastion/plugin.selfAddPersonalAccess.conf \; chmod o+r $opt_remote_etc_bastion/plugin.selfAddPersonalAccess.conf"

    plgfail selfAddPersonalAccess_self_remote_user_only $a0 --osh selfAddPersonalAccess --host 127.0.0.9 --user notme --port-any
    json .error_code ERR_INVALID_PARAMETER
    contain "you may retry"

    plgfail selfAddPersonalAccess_too_wide $a0 --osh selfAddPersonalAccess --host 127.0.0.0/8 --user $account0 --port-any
    json .error_code ERR_INVALID_PARAMETER
    contain "IPv4 is /30 by this"

    success selfAddPersonalAccess_constraints_ok $a0 --osh selfAddPersonalAccess --host 127.0.0.9 --user $account0 --port-any --ttl 1 --force

    success selfAddPersonalAccess_delconfig $r0 "rm -f $opt_remote_etc_bastion/plugin.selfAddPersonalAccess.conf"

    # same with accountAddPersonalAccess
    grant accountAddPersonalAccess
    success accountAddPersonalAccess_setconfig1 $r0 "echo '\{\\\"self_remote_user_only\\\":true\,\\\"widest_v4_prefix\\\":30\}' \> $opt_remote_etc_bastion/plugin.accountAddPersonalAccess.conf \; chmod o+r $opt_remote_etc_bastion/plugin.accountAddPersonalAccess.conf"

    plgfail accountAddPersonalAccess_self_remote_user_only $a0 --osh accountAddPersonalAccess --host 127.0.0.9 --user notme --port-any --account $account1
    json .error_code ERR_INVALID_PARAMETER
    contain "you may retry"

    plgfail accountAddPersonalAccess_too_wide $a0 --osh accountAddPersonalAccess --host 127.0.0.0/8 --user $account1 --port-any --account $account1
    json .error_code ERR_INVALID_PARAMETER
    contain "IPv4 is /30 by this"

    success accountAddPersonalAccess_constaints_ok $a0 --osh accountAddPersonalAccess --host 127.0.0.9 --user $account1 --port-any --ttl 1 --account $account1

    success accountAddPersonalAccess_delconfig $r0 "rm -f $opt_remote_etc_bastion/plugin.accountAddPersonalAccess.conf"

    revoke accountAddPersonalAccess
    # /test (self|account)AddPersonalAccess config items

    success withttl $a0 -osh selfAddPersonalAccess -h 127.0.0.4 -u $shellaccount -p 22 --force --ttl 0d0h0m3s
    json .command   selfAddPersonalAccess .error_code   OK .value.ip 127.0.0.4 .value.user $shellaccount .value.port 22 .value.ttl 3

    run a1atlo2_login8     $a0           127.0.0.2 -- id
    retvalshouldbe 107
    contain "Access denied for"
    json .command null .value null .error_code KO_ACCESS_DENIED

    # auto hostname=$host comment

    success self_add_personal_access_auto_comment $a0 --osh selfAddPersonalAccess --host localhost -u autocomment -p 1234 --force --ttl 1
    json .command selfAddPersonalAccess .error_code OK .value.comment "hostname=localhost" .value.user autocomment .value.port 1234 .value.ttl 1

    # forcekey

    success for_force_key $a0 --osh selfListEgressKeys
    local account0key1fp
    account0key1fp=$(get_json | $jq '.value|keys[0]')

    success forcekey $a0 --osh selfAddPersonalAccess -h 127.7.7.7 -u $shellaccount -p 22 --force --force-key "$account0key1fp"

    success forcekey $a0 --osh selfListAccesses
    contain "$account0key1fp"

    # try to use the force key

    success forcekey $a0 $shellaccount@127.7.7.7 --kbd-interactive -- id
    contain 'FORCED IN ACL'

    success forcekey $a0 -osh selfDelPersonalAccess -h 127.7.7.7 -u $shellaccount -p 22

    # /forcekey

    success shellaccountatlo2_mustwork   $a0 $shellaccount@127.0.0.2 --kbd-interactive -- echo $randomstr
    contain REGEX "$shellaccount@[a-zA-Z0-9._-]+:22"
    contain "allowed ... log on"
    nocontain "Permission denied"
    contain "$randomstr"

    # scp & sftp

    ## get both helpers first
    for proto in scp sftp; do
        success $proto $a0 --osh $proto
        if [ "$COUNTONLY" != 1 ]; then
            tmpb64=$(get_json | $jq '.value.script')
            base64 -d <<< "$tmpb64" | gunzip -c > /tmp/${proto}helpertmp
            perl -pe "s/ssh $account0\\@\\S+/ssh -p $remote_port $account0\\@$remote_ip/" /tmp/${proto}helpertmp > /tmp/${proto}helper
            chmod +x /tmp/${proto}helper
            unset tmpb64
        fi
    done
    unset proto

    # scp

    ## detect recent scp
    local scp_options=""
    run scp_checkversion $r0 "scp 2>&1 | grep -q O && echo NEWVERSION || echo OLDVERSION"
    if get_stdout | grep -q NEWVERSION; then
        echo "scp: will use new version params"
        scp_options="-O"
    elif get_stdout | grep -q OLDVERSION; then
        echo "scp: will use old version params"
        scp_options=""
    else
        contain "unknown scp version"
    fi

    success forscp $a0 --osh selfAddPersonalAccess --host 127.0.0.2 --scpup --port 22

    run scp_downloadfailnoright scp $scp_options -F $mytmpdir/ssh_config -S /tmp/scphelper -i $account0key1file $shellaccount@127.0.0.2:uptest /tmp/downloaded
    retvalshouldbe 1
    contain "Sorry, but even"

    success forscp $a0 --osh selfAddPersonalAccess --host 127.0.0.2 --scpdown --port 22

    run scp_downloadfailnofile scp $scp_options -F $mytmpdir/ssh_config -S /tmp/scphelper -i $account0key1file $shellaccount@127.0.0.2:uptest /tmp/downloaded
    retvalshouldbe 1
    contain "through the bastion from"
    contain "Error launching transfer"
    contain "No such file or directory"
    nocontain "Permission denied"

    run scp_invalidhostname scp $scp_options -F $mytmpdir/ssh_config -S /tmp/scphelper -i $account0key1file $shellaccount@_invalid._invalid:uptest /tmp/downloaded
    retvalshouldbe 1
    contain "Sorry, couldn't resolve the host you specified"

    success scp_upload scp $scp_options -F $mytmpdir/ssh_config -S /tmp/scphelper -i $account0key1file /etc/passwd $shellaccount@127.0.0.2:uptest
    contain "through the bastion to"
    contain "Done,"

    success scp_download scp $scp_options -F $mytmpdir/ssh_config -S /tmp/scphelper -i $account0key1file $shellaccount@127.0.0.2:uptest /tmp/downloaded
    contain "through the bastion from"
    contain "Done,"

    success forscpremove1 $a0 --osh selfDelPersonalAccess --host 127.0.0.2 --scpup   --port 22
    success forscpremove2 $a0 --osh selfDelPersonalAccess --host 127.0.0.2 --scpdown --port 22

    # sftp

    run sftp_no_access sftp -F $mytmpdir/ssh_config -S /tmp/sftphelper -i $account0key1file $shellaccount@127.0.0.2
    retvalshouldbe 255
    contain "Sorry, but even"

    success forsftp $a0 --osh selfAddPersonalAccess --host 127.0.0.2 --sftp --port 22

    success sftp_access sftp -F $mytmpdir/ssh_config -b - -S /tmp/sftphelper -i $account0key1file $shellaccount@127.0.0.2 "<<< exit"
    contain "sftp> exit"
    contain ">>> Done,"

    success forsftpremove $a0 --osh selfDelPersonalAccess --host 127.0.0.2 --sftp --port 22

    # /scp & sftp

    # (forced commands)

    # ESCAPE HELL
    success escapehell1ae $a0 --always-escape $shellaccount@127.0.0.2 -- "\"echo 'test1;test1' ; id\""
    contain "'test1"
    contain 'uid='
    contain REGEX "test1': (command )?not found"
    nocontain 'test1;test1'
    nocontain 'crazy'

    success escapehell2ae $a0 --always-escape $shellaccount@127.0.0.2 -- "'echo \"test1;test1\" ; id'"
    contain "test1;test1"
    contain 'uid='
    nocontain 'not found'
    nocontain 'crazy'

    success escapehell3ae $a0 --always-escape $shellaccount@127.0.0.2 -- "'echo \\\"test1;test1\\\" ; id'"
    contain '"test1'
    contain 'uid='
    contain REGEX 'test1": (command )?not found'
    nocontain 'crazy'

    success escapehell4ae $a0 --always-escape $shellaccount@127.0.0.2 -- "\"echo \\\"test1;test1\\\" ; id\""
    contain 'test1;test1'
    contain 'uid='
    nocontain 'not found'
    nocontain 'crazy'

    success escapehell5ae $a0 --always-escape $shellaccount@127.0.0.2 -- "\"echo \\\"test1';'test1\\\" ; id\""
    contain "test1\\';\\'test1"
    contain 'uid='
    nocontain 'not found'
    nocontain 'crazy'

    success escapehell1ne $a0 --never-escape $shellaccount@127.0.0.2 -- "\"echo 'test1;test1' ; id\""
    contain "test1;test1"
    contain 'uid='
    nocontain 'not found'
    nocontain 'crazy'

    success escapehell2ne $a0 --never-escape $shellaccount@127.0.0.2 -- "'echo \"test1;test1\" ; id'"
    contain "test1;test1"
    contain 'uid='
    nocontain 'not found'
    nocontain 'crazy'

    success escapehell3ne $a0 --never-escape $shellaccount@127.0.0.2 -- "'echo \\\"test1;test1\\\" ; id'"
    contain '"test1'
    contain 'uid='
    contain REGEX 'test1": (command )?not found'
    nocontain 'crazy'

    success escapehell4ne $a0 --never-escape $shellaccount@127.0.0.2 -- "\"echo \\\"test1;test1\\\" ; id\""
    contain 'test1;test1'
    contain 'uid='
    nocontain 'not found'
    nocontain 'crazy'

    success escapehell5ne $a0 --never-escape $shellaccount@127.0.0.2 -- "\"echo \\\"test1';'test1\\\" ; id\""
    contain "test1';'test1"
    contain 'uid='
    nocontain 'not found'
    nocontain 'crazy'

    success escapehellnoprotect1ae $a0 --always-escape $shellaccount@127.0.0.2 "\"echo 'test1;test1' ; id\""
    contain "test1"
    contain 'uid='
    contain REGEX "test1: (command )?not found"
    nocontain 'test1;test1'
    contain 'crazy'

    success escapehellnoprotect2ae $a0 --always-escape $shellaccount@127.0.0.2 "'echo \"test1;test1\" ; id'"
    contain "test1"
    contain 'uid='
    contain REGEX 'test1: (command )?not found'
    nocontain 'test1;test1'
    contain 'crazy'

    success escapehellnoprotect3ae $a0 --always-escape $shellaccount@127.0.0.2 "'echo \\\"test1;test1\\\" ; id'"
    contain 'test1;test1'
    contain 'uid='
    nocontain REGEX ': (command )?not found'
    contain 'crazy'

    success escapehellnoprotect4ae $a0 --always-escape $shellaccount@127.0.0.2 "\"echo \\\"test1;test1\\\" ; id\""
    contain "test1"
    contain 'uid='
    contain REGEX 'test1: (command )?not found'
    nocontain 'test1;test1'
    contain 'crazy'

    success escapehellnoprotect5ae $a0 --always-escape $shellaccount@127.0.0.2 "\"echo \\\"test1';'test1\\\" ; id\""
    contain 'test1;test1'
    contain 'uid='
    nocontain 'not found'
    contain 'crazy'

    success escapehellnoprotect1ne $a0 --never-escape $shellaccount@127.0.0.2 "\"echo 'test1;test1' ; id\""
    contain "test1"
    contain 'uid='
    contain REGEX 'test1: (command )?not found'
    nocontain 'test1;test1'
    contain 'crazy'

    success escapehellnoprotect2ne $a0 --never-escape $shellaccount@127.0.0.2 "'echo \"test1;test1\" ; id'"
    contain "test1"
    contain 'uid='
    contain REGEX 'test1: (command )?not found'
    nocontain 'test1;test1'
    contain 'crazy'

    success escapehellnoprotect3ne $a0 --never-escape $shellaccount@127.0.0.2 "'echo \\\"test1;test1\\\" ; id'"
    contain 'test1;test1'
    contain 'uid='
    nocontain 'not found'
    contain 'crazy'

    success escapehellnoprotect4ne $a0 --never-escape $shellaccount@127.0.0.2 "\"echo \\\"test1;test1\\\" ; id\""
    contain "test1"
    contain 'uid='
    contain REGEX 'test1: (command )?not found'
    nocontain 'test1;test1'
    contain 'crazy'

    success escapehellnoprotect5ne $a0 --never-escape $shellaccount@127.0.0.2 "\"echo \\\"test1';'test1\\\" ; id\""
    contain 'test1;test1'
    contain 'uid='
    nocontain 'not found'
    contain 'crazy'

    run shellaccountatlo_badport $a0 $shellaccount@127.0.0.2 -p 223 -- echo $randomstr
    retvalshouldbe 107
    contain "Access denied for"
    nocontain "$randomstr"
    json .command null .value null .error_code KO_ACCESS_DENIED

    run shellaccountatlo_badip $a0 $shellaccount@127.0.0.1 -- echo $randomstr
    retvalshouldbe 107
    contain "Access denied for"
    nocontain "$randomstr"
    json .command null .value null .error_code KO_ACCESS_DENIED

    run shellaccountatlo_badroot $a0 root@127.0.0.2 -- echo $randomstr
    retvalshouldbe 107
    contain "Access denied for"
    nocontain "$randomstr"
    json .command null .value null .error_code KO_ACCESS_DENIED

    run mustfailnosudo $a1 -osh selfDelPersonalAccess -h 127.0.0.2 -u $shellaccount -p 22
    retvalshouldbe 106
    contain "you to be specifically granted"
    json .command null .value null .error_code KO_RESTRICTED_COMMAND

    #sudo usermod -a -G osh-selfDelPersonalAccess $account1
    success mustwork $a0 -osh selfDelPersonalAccess -h 127.0.0.2 -u $shellaccount -p 22
    contain "Access to $shellaccount@127.0.0.2:22"
    json  .command selfDelPersonalAccess .error_code OK .value.ip 127.0.0.2 .value.user $shellaccount .value.port 22

    run shellaccountatlo2_mustfail   $a1 $shellaccount@127.0.0.2 -- echo $randomstr
    retvalshouldbe 107
    contain "Access denied for"
    nocontain "$randomstr"
    json .command null .value null .error_code KO_ACCESS_DENIED

    success mustwork $a0 -osh selfAddPersonalAccess -h 127.0.0.2 -u $shellaccount -p 226
    nocontain "already"
    json .command selfAddPersonalAccess .error_code OK .value.ip 127.0.0.2 .value.user $shellaccount .value.port 226

    # shouldn't work

    run shellaccountatlo2_badport2   $a0 $shellaccount@127.0.0.2 -- echo $randomstr
    retvalshouldbe 107
    contain "Access denied for"
    nocontain "$randomstr"
    json .command   null .value      null .error_code KO_ACCESS_DENIED

    # should

    success shellaccountatlo2_mustwork226   $a0 $shellaccount@127.0.0.2 -p 226 -- echo $randomstr
    contain REGEX "$shellaccount@[a-zA-Z0-9._-]+:226"
    contain "allowed ... log on"
    nocontain "Permission denied"
    contain "$randomstr"

    success mustwork $a0 -osh selfDelPersonalAccess -h 127.0.0.2 -u $shellaccount -p 226
    contain "Access to $shellaccount@127.0.0.2:226"
    json .command selfDelPersonalAccess .error_code OK .value.ip 127.0.0.2 .value.user $shellaccount .value.port 226

    run shellaccountatlo2_mustfailnow   $a0 $shellaccount@127.0.0.2 -p 226 -- echo $randomstr
    retvalshouldbe 107
    contain "Access denied for"
    nocontain "$randomstr"
    json .command   null .value      null .error_code KO_ACCESS_DENIED

    plgfail nousernoportnoforce $a0 -osh selfAddPersonalAccess -h 127.0.0.4
    nocontain "already"
    json .command selfAddPersonalAccess .error_code ERR_MISSING_PARAMETER .value null

    plgfail nousernoport $a0 -osh selfAddPersonalAccess -h 127.0.0.4 --force
    nocontain "already"
    json .command selfAddPersonalAccess .error_code ERR_MISSING_PARAMETER .value null

    plgfail userportnoforce $a0 -osh selfAddPersonalAccess -h 127.0.0.4 --user-any --port 22
    nocontain "already"
    contain REGEX "Couldn't connect to $account0@127.0.0.4 \\(ssh returned error (255|124)\\)"
    json .command selfAddPersonalAccess .error_code ERR_CONNECTION_FAILED .value      null

    success userportandforce $a0 -osh selfAddPersonalAccess -h 127.0.0.4 --force --user-any --port-any
    nocontain "already"
    contain "Forcing add as asked"
    json .command selfAddPersonalAccess .error_code OK .value.ip 127.0.0.4 .value.port null .value.user null

    run rootport22 $a0 root@127.0.0.4 -- echo $randomstr
    retvalshouldbe 255
    contain "allowed ... log on"
    contain "Permission denied"
    nocontain "$randomstr"

    run anyuserport22 $a0 whatevaah@127.0.0.4 -- echo $randomstr
    retvalshouldbe 255
    contain "allowed ... log on"
    contain "Permission denied"
    nocontain "$randomstr"

    success gooduserport22 $a0 $shellaccount@127.0.0.4 -- echo $randomstr
    contain "allowed ... log on"
    contain "$randomstr"

    run exitcode $a0 $shellaccount@127.0.0.4 -- exit 43
    retvalshouldbe 43
    contain "allowed ... log on"

    success gooduserport226 $a0 $shellaccount@127.0.0.4 -p 226 -- echo $randomstr
    contain "allowed ... log on"
    contain "$randomstr"

    run anyuseaarrport226 $a0 pokpozkpab@127.0.0.4 -p 226 -- echo $randomstr
    retvalshouldbe 255
    contain "allowed ... log on"
    nocontain "$randomstr"

    success nousernoport $a0 -osh selfDelPersonalAccess -h 127.0.0.4 --user-any --port-any
    contain "Access to 127.0.0.4 "
    json .command selfDelPersonalAccess .error_code OK .value.ip 127.0.0.4 .value.port null .value.user null

    success nousernoport_dupe $a0 -osh selfDelPersonalAccess -h 127.0.0.4 --user-any --port-any
    nocontain "no longer has a personal access"
    json .command selfDelPersonalAccess .error_code OK_NO_CHANGE .value      null

    # TODO try add/del accesses with and without port/user specification
    # ... then try to ssh with all combinations

    # TODO try partial group thing, and try to ssh to ip pertaining to group
    success oka0 $a0 --osh selfListAccesses
    contain 'no registered accesses'
    nocontain 'personal'
    nocontain 'group-member'
    nocontain 'group-guest'
    json .command selfListAccesses .error_code OK_EMPTY .value          null

    # FIXME with bastion config => auto-added private accesses ?
    success oka1 $a1 --osh selfListAccesses
    contain 'no registered accesses'
    nocontain 'personal'
    nocontain 'group-member'
    nocontain 'group-guest'
    json .command selfListAccesses .error_code OK_EMPTY .value          null

    success   loportnomatch   $a0 --osh selfForgetHostKey --host 127.0.0.1 --port 1234
    json .command selfForgetHostKey .error_code OK '.value."[127.0.0.1]:1234".action' OK_NO_MATCH

    success   lonomatch   $a0 --osh selfForgetHostKey --host 127.0.0.1
    json .command selfForgetHostKey .error_code OK '.value."127.0.0.1".action'   OK_NO_MATCH

    success   lonofile   $a1 --osh selfForgetHostKey --host 127.0.0.1
    json .command selfForgetHostKey .error_code OK_NO_CHANGE .value      null

    success   works   $a0 --osh selfForgetHostKey --host 127.0.0.2
    json .command selfForgetHostKey .error_code OK '.value."127.0.0.2".action'   OK_DELETED

    success   dupe   $a0 --osh selfForgetHostKey --host 127.0.0.2
    json .command selfForgetHostKey .error_code OK '.value."127.0.0.2".action'   OK_NO_MATCH

    grant accountUnexpire

    success nochange $a0 --osh accountUnexpire --account $account1
    json .command accountUnexpire .error_code OK_NO_CHANGE

    # artificially expire account1
    configchg 's=^\\\\x22accountMaxInactiveDays\\\\x22.+=\\\\x22accountMaxInactiveDays\\\\x22:2,='
    success manuallyExpireAccount1 $r0 "touch -t 201501010101 /home/$account1/lastlog"

    run expired $a1 --osh info
    retvalshouldbe 113

    success works $a0 --osh accountUnexpire --account $account1
    json .command accountUnexpire .error_code OK

    success unexpired $a1 --osh info
    json .error_code OK

    success worksnochange $a0 --osh accountUnexpire --account $account1
    json .command accountUnexpire .error_code OK_NO_CHANGE

    # try on never logged-in account (different code path)
    success manuallyRemoveLastlog $r0 "rm -f /home/$account1/lastlog"

    success worksnochange $a0 --osh accountUnexpire --account $account1
    json .command accountUnexpire .error_code OK_NO_CHANGE

    revoke accountUnexpire

    # delete account1
    grant accountDelete
    script cleanup $a0 --osh accountDelete --account $account1 "<<< \"Yes, do as I say and delete $account1, kthxbye\""
    retvalshouldbe 0
    revoke accountDelete
}

testsuite_selfaccesses
unset -f testsuite_selfaccesses
