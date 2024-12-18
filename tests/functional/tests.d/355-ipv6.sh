# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_ipv6()
{
    # create account1
    success accountCreate $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    plgfail use_ipv6_notenabled_1 $a0 --osh selfAddPersonalAccess --host ::1 --force --user-any --port-any
    contain 'Unable to resolve host'
    contain 'looks like an IPv6'
    json .command selfAddPersonalAccess .error_code ERR_MISSING_PARAMETER

    plgfail use_ipv6_notenabled_2 $a0 --osh selfAddPersonalAccess --host '[::1]' --force --user-any --port-any
    contain 'Unable to resolve host'
    contain 'looks like an IPv6'
    json .command selfAddPersonalAccess .error_code ERR_MISSING_PARAMETER

    # now enable IPv6
    configchg 's=^\\\\x22IPv6Allowed\\\\x22.+=\\\\x22IPv6Allowed\\\\x22:true,='

    success add_access_ipv6 $a0 --osh selfAddPersonalAccess --host '::1' --force --user-any --port-any
    nocontain "already"
    contain "Forcing add as asked"
    json .command selfAddPersonalAccess .error_code OK .value.ip ::1 .value.port null .value.user null

    success add_access_ipv6_dupe $a0 --osh selfAddPersonalAccess --host '::1' --force --user-any --port-any
    contain "already"
    json .command selfAddPersonalAccess .error_code OK_NO_CHANGE

    success add_access_ipv6_multiformat $a0 --osh selfAddPersonalAccess --host 'fe80:cafe::000f:ff' --force --user-any --port-any
    nocontain "already"
    json .command selfAddPersonalAccess .error_code OK .value.ip fe80:cafe::f:ff .value.port null .value.user null

    success add_access_ipv6_multiformat_dupe1 $a0 --osh selfAddPersonalAccess --host 'fe80:cafe:0000:0000:0000:0000:000f:00ff' --force --user-any --port-any
    contain "already"
    json .command selfAddPersonalAccess .error_code OK_NO_CHANGE

    success add_access_ipv6_multiformat_dupe2 $a0 --osh selfAddPersonalAccess --host 'fe80:cafe:00::0:f:ff' --force --user-any --port-any
    contain "already"
    json .command selfAddPersonalAccess .error_code OK_NO_CHANGE

    success self_listaccesses $a0 --osh selfListAccesses
    json .command selfListAccesses .error_code OK
    json --splitsort '[.value[]|select(.type == "personal").acl[]|.ip]' '::1 fe80:cafe::f:ff'

    run connect_ipv6 $a0 ::1
    contain "Connecting..."
    contain "$account0.v6[..1].22.ttyrec"

    success self_delaccess $a0 --osh selfDelPersonalAccess --host 'fe80:cafe:0:00:0::f:ff' --port '*' --user '*'
    json .command selfDelPersonalAccess .error_code OK

    success self_delaccess_dupe $a0 --osh selfDelPersonalAccess --host 'fe80:cafe:00:0:00::f:ff' --port '*' --user '*'
    json .command selfDelPersonalAccess .error_code OK_NO_CHANGE

    success self_listaccesses_2 $a0 --osh selfListAccesses
    json .command selfListAccesses .error_code OK
    json --splitsort '[.value[]|select(.type == "personal").acl[]|.ip]' '::1'

    # delete account1
    script cleanup $a0 --osh accountDelete --account $account1 "<<< \"Yes, do as I say and delete $account1, kthxbye\""
    retvalshouldbe 0
}

testsuite_ipv6
unset -f testsuite_ipv6
