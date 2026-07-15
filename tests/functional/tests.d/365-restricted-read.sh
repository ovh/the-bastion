# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2317,SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_restricted_read()
{
    # a fixed target IP used for the access/ACL assertions below, and a second one nobody can reach
    local granted_ip=10.100.100.100
    local ungranted_ip=10.200.200.200

    # two plain accounts to enumerate and to hang accesses off of
    success rr_create_a1 $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command accountCreate .value null
    success rr_create_a2 $a0 --osh accountCreate --always-active --account $account2 --uid $uid2 --public-key "\"$(cat $account2key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    # ---- accountList ----

    # unfiltered listing contains both accounts, with the expected uids
    success rr_accountlist_all $a0 --osh accountList
    json .command accountList .error_code OK
    json --arg a "$account1" '.value | has($a)' true
    json --arg a "$account2" '.value | has($a)' true
    json --arg a "$account1" '.value[$a].uid' $uid1
    json --arg a "$account2" '.value[$a].uid' $uid2

    # filtered to a single account
    success rr_accountlist_one $a0 --osh accountList --account $account1
    json .command accountList .error_code OK
    json --arg a "$account1" '.value | has($a)' true
    json --arg a "$account2" '.value | has($a)' false

    # --include narrows to matching names, --exclude drops them (exclude wins over include)
    success rr_accountlist_include $a0 --osh accountList --include "$account1"
    json --arg a "$account1" '.value | has($a)' true
    json --arg a "$account2" '.value | has($a)' false
    success rr_accountlist_exclude $a0 --osh accountList --exclude "$account1"
    json --arg a "$account1" '.value | has($a)' false
    json --arg a "$account2" '.value | has($a)' true

    # --inactive-only excludes our always-active accounts
    success rr_accountlist_inactive $a0 --osh accountList --inactive-only
    json .command accountList .error_code OK
    json --arg a "$account1" '.value | has($a)' false

    # --realm-only is no longer supported and must be rejected
    plgfail rr_accountlist_realmonly $a0 --osh accountList --realm-only
    json .command accountList .error_code ERR_INVALID_PARAMETER

    # ---- rootListIngressKeys ----

    # lists the public keys that can log in as root on the bastion (the runner installed at least one)
    success rr_rootkeys $a0 --osh rootListIngressKeys
    json .command rootListIngressKeys .error_code OK .value.account root
    json '.value.keys | length >= 1' true

    # ---- whoHasAccessTo ----

    # whoHasAccessTo requires a host
    plgfail rr_who_nohost $a0 --osh whoHasAccessTo
    json .command whoHasAccessTo .error_code ERR_MISSING_PARAMETER

    # nobody has access to our target yet
    success rr_who_empty $a0 --osh whoHasAccessTo --host $granted_ip
    json .command whoHasAccessTo .error_code OK .value '{}'

    # grant account1 a *personal* access to the target
    success rr_add_personal $a0 --osh accountAddPersonalAccess --account $account1 --host $granted_ip --user-any --port-any
    json .command accountAddPersonalAccess .error_code OK

    # now account1 shows up as having personal (and only personal) access; account2 still doesn't
    success rr_who_personal $a0 --osh whoHasAccessTo --host $granted_ip
    json .command whoHasAccessTo .error_code OK
    json --arg a "$account1" '.value[$a].personal_access' 1
    json --arg a "$account1" '.value[$a].group_access | length' 0
    json --arg a "$account2" '.value | has($a)' false

    # create a group owned by a0 (so a0 can manage it), point it at the same target, add account2
    success rr_create_group $a0 --osh groupCreate --group $group1 --owner $account0 --algo ed25519 --size 256
    json .command groupCreate .error_code OK
    success rr_group_add_server $a0 --osh groupAddServer --group $group1 --host $granted_ip --user nobody --port 22 --force
    json .command groupAddServer .error_code OK
    success rr_group_add_member $a0 --osh groupAddMember --group $group1 --account $account2
    json .command groupAddMember .error_code OK

    # account2 now has *group* access; account1 keeps its personal access
    success rr_who_group $a0 --osh whoHasAccessTo --host $granted_ip
    json .command whoHasAccessTo .error_code OK
    json --arg a "$account1" '.value[$a].personal_access' 1
    json --arg a "$account2" '.value[$a].personal_access' 0
    json --arg a "$account2" '.value[$a].group_access | length >= 1' true

    # a host nobody is granted access to yields an empty result
    success rr_who_ungranted $a0 --osh whoHasAccessTo --host $ungranted_ip
    json .command whoHasAccessTo .error_code OK .value '{}'

    # cleanup
    success rr_del_group $a0 --osh groupDelete --group $group1 --no-confirm
    json .command groupDelete .error_code OK
    success rr_del_a1 $a0 --osh accountDelete --account $account1 --no-confirm
    json .command accountDelete .error_code OK
    success rr_del_a2 $a0 --osh accountDelete --account $account2 --no-confirm
    json .command accountDelete .error_code OK
}

testsuite_restricted_read
unset -f testsuite_restricted_read
