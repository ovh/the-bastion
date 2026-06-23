# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2317,SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_realm_from_validation()
{
    local realm=fromtest
    local realm_account="realm_$realm"
    local realm_home="/home/$realm_account"

    # every malformed --from element must be refused
    plgfail realm_from_reject_notanip $a0 --osh realmCreate --realm $realm --from notanip \
        --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code ERR_INVALID_PARAMETER

    # a partially-valid list must still be fully rejected (proves every element is checked)
    plgfail realm_from_reject_partial $a0 --osh realmCreate --realm $realm --from 1.2.3.4,bogus \
        --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code ERR_INVALID_PARAMETER

    # looks-like-an-IP but isn't (out-of-range octet)
    plgfail realm_from_reject_badoctet $a0 --osh realmCreate --realm $realm --from 999.1.2.3 \
        --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code ERR_INVALID_PARAMETER

    # canonicalization check
    success realm_from_valid $a0 --osh realmCreate --realm $realm --from 1.2.3.4/32,192.168.001.002 \
        --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command realmCreate

    # inspect the realm account's ingress authorized_keys as root
    success realm_from_keyfile $r0 "cat $realm_home/.ssh/authorized_keys2"
    # the from="" clause must hold the canonical values
    contain '1.2.3.4,192.168.1.2'
    # ...and must NOT contain the raw input
    nocontain '192.168.001.002'
    nocontain '/32'

    # cleanup: delete the realm
    script realm_from_cleanup "$a0 --osh realmDelete --realm $realm <<< \"Yes, do as I say and delete $realm, kthxbye\""
    retvalshouldbe 0
    json .command realmDelete .error_code OK
}

testsuite_realm_from_validation
unset -f testsuite_realm_from_validation
