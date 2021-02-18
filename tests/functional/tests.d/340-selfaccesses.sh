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
        success selfaccess a0_create_a1_uidauto_nokey_$i $a0 --osh accountCreate --account delme$i --uid-auto --no-key
        json .error_code OK .command accountCreate
    done

    revoke accountCreate
    grant accountDelete

    # delete those accounts
    for i in {1..10}; do
        script selfaccess a0_delete_a1_uidauto_nokey_$i $a0 --osh accountDelete --account delme$i "<<< \"Yes, do as I say and delete delme$i, kthxbye\""
        retvalshouldbe 0
        json .error_code OK .command accountDelete
    done

    revoke accountDelete
    grant accountCreate

    # create account1
    success osh accountCreate $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    revoke accountCreate
    grant accountModify

    success realm modify_account1 $a0 --osh accountModify --pam-auth-bypass yes --account $account1
    json .error_code OK .command accountModify

    # test osh-only
    success accountModify enable_osh_only $a0 --osh accountModify --osh-only yes --account $account1
    json .error_code OK .command accountModify

    # account1 can not connect to anything
    run accountModify no_ssh_after_osh_only $a1 anybody@127.0.0.1
    retvalshouldbe 107
    json .error_code KO_ACCESS_DENIED .error_message "You don't have the right to connect anywhere"

    success accountModify disable_osh_only $a0 --osh accountModify --osh-only no --account $account1
    json .error_code OK .command accountModify

    # account1 can connect now (or could if they were granted)
    run accountModify can_ssh_after_osh_only_disable $a1 anybody@127.0.0.1
    retvalshouldbe 107
    json .error_code KO_ACCESS_DENIED
    contain "Access denied"
    nocontain "anywhere"

    revoke accountModify

    success selfListEgressKeys beforeadd $a1 -osh selfListEgressKeys
    tmpfp=$(get_json | $jq '.value|keys[0]')
    json .command selfListEgressKeys .error_code OK '.value|keys[1]'  null
    pattern "^$account1@fix-my-config-please-missing-bastion-name:[0-9]+$" "$(get_json | $jq ".value|.[\"$tmpfp\"]|.comment")"

    success osh selfGenerateEgressKey $a1 --osh selfGenerateEgressKey --algo rsa --size 4096
    json .error_code OK .command selfGenerateEgressKey .value.size 4096 .value.family RSA
    tmpfp2=$(get_json | $jq '.value.fingerprint')

    success selfListEgressKeys afteradd $a1 -osh selfListEgressKeys
    json .command    selfListEgressKeys .error_code OK '.value|keys[2]'  null
    pattern "^$account1@fix-my-config-please-missing-bastion-name:[0-9]+$" "$(get_json | $jq ".value|.[\"$tmpfp\"]|.comment")"
    pattern "^$account1@fix-my-config-please-missing-bastion-name:[0-9]+$" "$(get_json | $jq ".value|.[\"$tmpfp2\"]|.comment")"
    unset tmpfp
    unset tmpfp2

    # batch plugin

    script plugin-batch one "printf \"%b\\n\" \"info\\naccountInfo --account $account0\\nselfListEgressKeys\" | $a1 --osh batch"
    retvalshouldbe 0
    json .command batch .error_code OK
    json '.value[0].result.error_code' OK '.value[0].command' info '.value[0].result.value.account' "$account1"
    json '.value[1].result.error_code' KO_RESTRICTED_COMMAND '.value[1].command' "accountInfo --account $account0"
    json '.value[2].result.error_code' OK '.value[2].command' selfListEgressKeys

    # ssh

    run ssh a1atlo2 $a1 127.0.0.2 -- id
    retvalshouldbe 107
    contain "Access denied for"
    json .command    null .error_code KO_ACCESS_DENIED

    run ssh invalid_host $a1 127.0./0.1 -- id
    retvalshouldbe 102
    json .error_code KO_HOST_NOT_FOUND

    run ssh invalid_host $a1 127.0.%0.1 -- id
    retvalshouldbe 128
    json .error_code KO_INVALID_REMOTE_HOST

    run ssh invalid_user $a1 ro/ot@127.0.0.1 -- id
    retvalshouldbe 127
    json .error_code KO_INVALID_REMOTE_USER

    grant selfAddPersonalAccess
    grant selfDelPersonalAccess

    run selfAddPersonalAccess mustfail $a1 -osh selfAddPersonalAccess -h 127.0.0.2 -u $shellaccount -p 22
    retvalshouldbe 106
    contain "you to be specifically granted"
    json .command    null .error_code KO_RESTRICTED_COMMAND

    success selfAddPersonalAccess mustwork $a0 -osh selfAddPersonalAccess -h 127.0.0.2 -u $shellaccount -p 22 --kbd-interactive
    nocontain "already"
    json .command   selfAddPersonalAccess .error_code   OK .value.ip 127.0.0.2 .value.user $shellaccount .value.port 22

    success selfAddPersonalAccess dupe $a0 -osh selfAddPersonalAccess -h 127.0.0.2 -u $shellaccount -p 22 --kbd-interactive
    contain "already"
    json .command   selfAddPersonalAccess .error_code   OK_NO_CHANGE .value null

    success selfAddPersonalAccess withttl $a0 -osh selfAddPersonalAccess -h 127.0.0.4 -u $shellaccount -p 22 --force --ttl 0d0h0m3s
    json .command   selfAddPersonalAccess .error_code   OK .value.ip 127.0.0.4 .value.user $shellaccount .value.port 22 .value.ttl 3

    run ssh a1atlo2_login8     $a0           127.0.0.2 -- id
    retvalshouldbe 107
    contain "Access denied for"
    json .command null .value null .error_code KO_ACCESS_DENIED

    # auto hostname=$host comment

    success selfAddPersonalAccess self_add_personal_access_auto_comment $a0 --osh selfAddPersonalAccess --host localhost -u autocomment -p 1234 --force --ttl 1
    json .command selfAddPersonalAccess .error_code OK .value.comment "hostname=localhost" .value.user autocomment .value.port 1234 .value.ttl 1

    # forcekey

    success selfListIngressKeys for_force_key $a0 --osh selfListEgressKeys
    account0key1fp=$(get_json | $jq '.value|keys[0]')

    success selfAddPersonalAccess forcekey $a0 --osh selfAddPersonalAccess -h 127.7.7.7 -u $shellaccount -p 22 --force --force-key "$account0key1fp"

    success selfListAccesses forcekey $a0 --osh selfListAccesses
    contain "$account0key1fp"

    # try to use the force key

    success ssh forcekey $a0 $shellaccount@127.7.7.7 --kbd-interactive -- id
    contain 'FORCED IN ACL'

    success selfDelPersonalAccess forcekey $a0 -osh selfDelPersonalAccess -h 127.7.7.7 -u $shellaccount -p 22

    # /forcekey

    # this should work...

    set +e
    if [ "$COUNTONLY" = 1 ]; then
        targethostname=dummy
    else
        targethostname=$($r0 hostname | tail -n1 | grep -E -o '[a-z0-9._-]+')
    fi
    set -e

    success ssh shellaccountatlo2_mustwork   $a0 $shellaccount@127.0.0.2 --kbd-interactive -- echo $randomstr
    contain REGEX "$shellaccount@($targethostname|127.0.0.2|fv-[a-z0-9-]+):22"
    contain "allowed ... log on"
    nocontain "Permission denied"
    contain "$randomstr"

    # scp
    success accountAddPersonalAccess forscp $a0 --osh selfAddPersonalAccess --host 127.0.0.2 --scpup --port 22

    success osh scp $a0 --osh scp
    if [ "$COUNTONLY" != 1 ]; then
        tmpb64=$(get_json | $jq '.value.script')
        base64 -d <<< "$tmpb64" | gunzip -c > /tmp/scphelpertmp
        perl -pe "s/ssh $account0\\@\\S+/ssh -p $remote_port $account0\\@$remote_ip/" /tmp/scphelpertmp > /tmp/scphelper
        chmod +x /tmp/scphelper
        cat /tmp/scphelper
        unset tmpb64
    fi

    run scp downloadfailnoright scp -F $mytmpdir/ssh_config -S /tmp/scphelper -i $account0key1file $shellaccount@127.0.0.2:uptest /tmp/downloaded
    retvalshouldbe 1
    contain "Sorry, but even"

    success accountAddPersonalAccess forscp $a0 --osh selfAddPersonalAccess --host 127.0.0.2 --scpdown --port 22

    run scp downloadfailnofile scp -F $mytmpdir/ssh_config -S /tmp/scphelper -i $account0key1file $shellaccount@127.0.0.2:uptest /tmp/downloaded
    retvalshouldbe 1
    contain "through the bastion from"
    contain "Error launching transfer"
    contain "No such file or directory"
    nocontain "Permission denied"

    success scp upload scp -F $mytmpdir/ssh_config -S /tmp/scphelper -i $account0key1file /etc/passwd $shellaccount@127.0.0.2:uptest
    contain "through the bastion to"
    contain "Done,"

    success scp download scp -F $mytmpdir/ssh_config -S /tmp/scphelper -i $account0key1file $shellaccount@127.0.0.2:uptest /tmp/downloaded
    contain "through the bastion from"
    contain "Done,"

    success accountAddPersonalAccess forscpremove1 $a0 --osh selfDelPersonalAccess --host 127.0.0.2 --scpup   --port 22
    success accountAddPersonalAccess forscpremove2 $a0 --osh selfDelPersonalAccess --host 127.0.0.2 --scpdown --port 22

    # /scp

    # (forced commands)

    # ESCAPE HELL
    success ssh escapehell1ae $a0 --always-escape $shellaccount@127.0.0.2 -- "\"echo 'test1;test1' ; id\""
    contain "'test1"
    contain 'uid='
    contain REGEX "test1': (command )?not found"
    nocontain 'test1;test1'
    nocontain 'crazy'

    success ssh escapehell2ae $a0 --always-escape $shellaccount@127.0.0.2 -- "'echo \"test1;test1\" ; id'"
    contain "test1;test1"
    contain 'uid='
    nocontain 'not found'
    nocontain 'crazy'

    success ssh escapehell3ae $a0 --always-escape $shellaccount@127.0.0.2 -- "'echo \\\"test1;test1\\\" ; id'"
    contain '"test1'
    contain 'uid='
    contain REGEX 'test1": (command )?not found'
    nocontain 'crazy'

    success ssh escapehell4ae $a0 --always-escape $shellaccount@127.0.0.2 -- "\"echo \\\"test1;test1\\\" ; id\""
    contain 'test1;test1'
    contain 'uid='
    nocontain 'not found'
    nocontain 'crazy'

    success ssh escapehell5ae $a0 --always-escape $shellaccount@127.0.0.2 -- "\"echo \\\"test1';'test1\\\" ; id\""
    contain "test1\\';\\'test1"
    contain 'uid='
    nocontain 'not found'
    nocontain 'crazy'

    success ssh escapehell1ne $a0 --never-escape $shellaccount@127.0.0.2 -- "\"echo 'test1;test1' ; id\""
    contain "test1;test1"
    contain 'uid='
    nocontain 'not found'
    nocontain 'crazy'

    success ssh escapehell2ne $a0 --never-escape $shellaccount@127.0.0.2 -- "'echo \"test1;test1\" ; id'"
    contain "test1;test1"
    contain 'uid='
    nocontain 'not found'
    nocontain 'crazy'

    success ssh escapehell3ne $a0 --never-escape $shellaccount@127.0.0.2 -- "'echo \\\"test1;test1\\\" ; id'"
    contain '"test1'
    contain 'uid='
    contain REGEX 'test1": (command )?not found'
    nocontain 'crazy'

    success ssh escapehell4ne $a0 --never-escape $shellaccount@127.0.0.2 -- "\"echo \\\"test1;test1\\\" ; id\""
    contain 'test1;test1'
    contain 'uid='
    nocontain 'not found'
    nocontain 'crazy'

    success ssh escapehell5ne $a0 --never-escape $shellaccount@127.0.0.2 -- "\"echo \\\"test1';'test1\\\" ; id\""
    contain "test1';'test1"
    contain 'uid='
    nocontain 'not found'
    nocontain 'crazy'

    success ssh escapehellnoprotect1ae $a0 --always-escape $shellaccount@127.0.0.2 "\"echo 'test1;test1' ; id\""
    contain "test1"
    contain 'uid='
    contain REGEX "test1: (command )?not found"
    nocontain 'test1;test1'
    contain 'crazy'

    success ssh escapehellnoprotect2ae $a0 --always-escape $shellaccount@127.0.0.2 "'echo \"test1;test1\" ; id'"
    contain "test1"
    contain 'uid='
    contain REGEX 'test1: (command )?not found'
    nocontain 'test1;test1'
    contain 'crazy'

    success ssh escapehellnoprotect3ae $a0 --always-escape $shellaccount@127.0.0.2 "'echo \\\"test1;test1\\\" ; id'"
    contain 'test1;test1'
    contain 'uid='
    nocontain REGEX ': (command )?not found'
    contain 'crazy'

    success ssh escapehellnoprotect4ae $a0 --always-escape $shellaccount@127.0.0.2 "\"echo \\\"test1;test1\\\" ; id\""
    contain "test1"
    contain 'uid='
    contain REGEX 'test1: (command )?not found'
    nocontain 'test1;test1'
    contain 'crazy'

    success ssh escapehellnoprotect5ae $a0 --always-escape $shellaccount@127.0.0.2 "\"echo \\\"test1';'test1\\\" ; id\""
    contain 'test1;test1'
    contain 'uid='
    nocontain 'not found'
    contain 'crazy'

    success ssh escapehellnoprotect1ne $a0 --never-escape $shellaccount@127.0.0.2 "\"echo 'test1;test1' ; id\""
    contain "test1"
    contain 'uid='
    contain REGEX 'test1: (command )?not found'
    nocontain 'test1;test1'
    contain 'crazy'

    success ssh escapehellnoprotect2ne $a0 --never-escape $shellaccount@127.0.0.2 "'echo \"test1;test1\" ; id'"
    contain "test1"
    contain 'uid='
    contain REGEX 'test1: (command )?not found'
    nocontain 'test1;test1'
    contain 'crazy'

    success ssh escapehellnoprotect3ne $a0 --never-escape $shellaccount@127.0.0.2 "'echo \\\"test1;test1\\\" ; id'"
    contain 'test1;test1'
    contain 'uid='
    nocontain 'not found'
    contain 'crazy'

    success ssh escapehellnoprotect4ne $a0 --never-escape $shellaccount@127.0.0.2 "\"echo \\\"test1;test1\\\" ; id\""
    contain "test1"
    contain 'uid='
    contain REGEX 'test1: (command )?not found'
    nocontain 'test1;test1'
    contain 'crazy'

    success ssh escapehellnoprotect5ne $a0 --never-escape $shellaccount@127.0.0.2 "\"echo \\\"test1';'test1\\\" ; id\""
    contain 'test1;test1'
    contain 'uid='
    nocontain 'not found'
    contain 'crazy'

    run ssh shellaccountatlo_badport $a0 $shellaccount@127.0.0.2 -p 223 -- echo $randomstr
    retvalshouldbe 107
    contain "Access denied for"
    nocontain "$randomstr"
    json .command null .value null .error_code KO_ACCESS_DENIED

    run ssh shellaccountatlo_badip $a0 $shellaccount@127.0.0.1 -- echo $randomstr
    retvalshouldbe 107
    contain "Access denied for"
    nocontain "$randomstr"
    json .command null .value null .error_code KO_ACCESS_DENIED

    run ssh shellaccountatlo_badroot $a0 root@127.0.0.2 -- echo $randomstr
    retvalshouldbe 107
    contain "Access denied for"
    nocontain "$randomstr"
    json .command null .value null .error_code KO_ACCESS_DENIED

    run selfDelPersonalAccess mustfailnosudo $a1 -osh selfDelPersonalAccess -h 127.0.0.2 -u $shellaccount -p 22
    retvalshouldbe 106
    contain "you to be specifically granted"
    json .command null .value null .error_code KO_RESTRICTED_COMMAND

    #sudo usermod -a -G osh-selfDelPersonalAccess $account1
    success selfDelPersonalAccess mustwork $a0 -osh selfDelPersonalAccess -h 127.0.0.2 -u $shellaccount -p 22
    contain "Access to $shellaccount@127.0.0.2:22"
    json  .command selfDelPersonalAccess .error_code OK .value.ip 127.0.0.2 .value.user $shellaccount .value.port 22

    run ssh shellaccountatlo2_mustfail   $a1 $shellaccount@127.0.0.2 -- echo $randomstr
    retvalshouldbe 107
    contain "Access denied for"
    nocontain "$randomstr"
    json .command null .value null .error_code KO_ACCESS_DENIED

    success selfAddPersonalAccess mustwork $a0 -osh selfAddPersonalAccess -h 127.0.0.2 -u $shellaccount -p 226
    nocontain "already"
    json .command selfAddPersonalAccess .error_code OK .value.ip 127.0.0.2 .value.user $shellaccount .value.port 226

    # shouldn't work

    run ssh shellaccountatlo2_badport2   $a0 $shellaccount@127.0.0.2 -- echo $randomstr
    retvalshouldbe 107
    contain "Access denied for"
    nocontain "$randomstr"
    json .command   null .value      null .error_code KO_ACCESS_DENIED

    # should

    success ssh shellaccountatlo2_mustwork226   $a0 $shellaccount@127.0.0.2 -p 226 -- echo $randomstr
    contain REGEX "$shellaccount@(127.0.0.2|$targethostname|fv-[a-z0-9-]+):226"
    contain "allowed ... log on"
    nocontain "Permission denied"
    contain "$randomstr"

    success selfDelPersonalAccess mustwork $a0 -osh selfDelPersonalAccess -h 127.0.0.2 -u $shellaccount -p 226
    contain "Access to $shellaccount@127.0.0.2:226"
    json .command selfDelPersonalAccess .error_code OK .value.ip 127.0.0.2 .value.user $shellaccount .value.port 226

    run ssh shellaccountatlo2_mustfailnow   $a0 $shellaccount@127.0.0.2 -p 226 -- echo $randomstr
    retvalshouldbe 107
    contain "Access denied for"
    nocontain "$randomstr"
    json .command   null .value      null .error_code KO_ACCESS_DENIED

    plgfail selfAddPersonalAccess nousernoportnoforce $a0 -osh selfAddPersonalAccess -h 127.0.0.4
    nocontain "already"
    contain REGEX "Couldn't connect to $account0@127.0.0.4 \\(ssh returned error (255|124)\\)"
    json .command selfAddPersonalAccess .error_code ERR_CONNECTION_FAILED .value      null

    success selfAddPersonalAccess nousernoport $a0 -osh selfAddPersonalAccess -h 127.0.0.4 --force
    nocontain "already"
    contain "Forcing add as asked"
    json .command selfAddPersonalAccess .error_code OK .value.ip 127.0.0.4 .value.port null .value.user null

    run ssh rootport22 $a0 root@127.0.0.4 -- echo $randomstr
    retvalshouldbe 255
    contain "allowed ... log on"
    contain "Permission denied"
    nocontain "$randomstr"

    run ssh anyuserport22 $a0 whatevaah@127.0.0.4 -- echo $randomstr
    retvalshouldbe 255
    contain "allowed ... log on"
    contain "Permission denied"
    nocontain "$randomstr"

    success ssh gooduserport22 $a0 $shellaccount@127.0.0.4 -- echo $randomstr
    contain "allowed ... log on"
    contain "$randomstr"

    run ssh exitcode $a0 $shellaccount@127.0.0.4 -- exit 43
    retvalshouldbe 43
    contain "allowed ... log on"

    success ssh gooduserport226 $a0 $shellaccount@127.0.0.4 -p 226 -- echo $randomstr
    contain "allowed ... log on"
    contain "$randomstr"

    run ssh anyuseaarrport226 $a0 pokpozkpab@127.0.0.4 -p 226 -- echo $randomstr
    retvalshouldbe 255
    contain "allowed ... log on"
    nocontain "$randomstr"

    success selfDelPersonalAccess nousernoport $a0 -osh selfDelPersonalAccess -h 127.0.0.4
    contain "Access to 127.0.0.4 "
    json .command selfDelPersonalAccess .error_code OK .value.ip 127.0.0.4 .value.port null .value.user null

    success selfDelPersonalAccess nousernoport_dupe $a0 -osh selfDelPersonalAccess -h 127.0.0.4
    nocontain "no longer has a personal access"
    json .command selfDelPersonalAccess .error_code OK_NO_CHANGE .value      null

    # TODO try add/del accesses with and without port/user specification
    # ... then try to ssh with all combinations

    # TODO try partial group thing, and try to ssh to ip pertaining to group
    success selfListAccesses oka0 $a0 --osh selfListAccesses
    contain 'no registered accesses'
    nocontain 'personal'
    nocontain 'group-member'
    nocontain 'group-guest'
    json .command selfListAccesses .error_code OK_EMPTY .value          null

    # FIXME with bastion config => auto-added private accesses ?
    success selfListAccesses oka1 $a1 --osh selfListAccesses
    contain 'no registered accesses'
    nocontain 'personal'
    nocontain 'group-member'
    nocontain 'group-guest'
    json .command selfListAccesses .error_code OK_EMPTY .value          null

    success   selfForgetHostKey   loportnomatch   $a0 --osh selfForgetHostKey --host 127.0.0.1 --port 1234
    json .command selfForgetHostKey .error_code OK '.value."[127.0.0.1]:1234".action' OK_NO_MATCH

    success   selfForgetHostKey   lonomatch   $a0 --osh selfForgetHostKey --host 127.0.0.1
    json .command selfForgetHostKey .error_code OK '.value."127.0.0.1".action'   OK_NO_MATCH

    success   selfForgetHostKey   lonofile   $a1 --osh selfForgetHostKey --host 127.0.0.1
    json .command selfForgetHostKey .error_code OK_NO_CHANGE .value      null

    success   selfForgetHostKey   works   $a0 --osh selfForgetHostKey --host 127.0.0.2
    json .command selfForgetHostKey .error_code OK '.value."127.0.0.2".action'   OK_DELETED

    success   selfForgetHostKey   dupe   $a0 --osh selfForgetHostKey --host 127.0.0.2
    json .command selfForgetHostKey .error_code OK '.value."127.0.0.2".action'   OK_NO_MATCH

    grant accountUnexpire

    success accountUnexpire nochange $a0 --osh accountUnexpire --account $account1
    json .command accountUnexpire .error_code OK_NO_CHANGE

    # artificially expire account1
    configchg 's=^\\\\x22accountMaxInactiveDays\\\\x22.+=\\\\x22accountMaxInactiveDays\\\\x22:2,='
    success bastion manuallyExpireAccount1 $r0 "touch -t 201501010101 /home/$account1/lastlog"

    run account expired $a1 --osh info
    retvalshouldbe 113

    success accountUnexpire works $a0 --osh accountUnexpire --account $account1
    json .command accountUnexpire .error_code OK

    success account unexpired $a1 --osh info
    json .error_code OK

    success accountUnexpire worksnochange $a0 --osh accountUnexpire --account $account1
    json .command accountUnexpire .error_code OK_NO_CHANGE

    # try on never logged-in account (different code path)
    success bastion manuallyRemoveLastlog $r0 "rm -f /home/$account1/lastlog"

    success accountUnexpire worksnochange $a0 --osh accountUnexpire --account $account1
    json .command accountUnexpire .error_code OK_NO_CHANGE

    revoke accountUnexpire

    # delete account1
    grant accountDelete
    script accountDelete cleanup $a0 --osh accountDelete --account $account1 "<<< \"Yes, do as I say and delete $account1, kthxbye\""
    retvalshouldbe 0
    revoke accountDelete
}

testsuite_selfaccesses
