# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2317,SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_ipv6()
{
    # create account1
    success accountCreate $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    run use_ipv6_notenabled_1 $a0 --osh selfAddPersonalAccess --host ::1 --force --user-any --port-any
    retvalshouldbe 133
    contain "Can't use '::1', IPv6 support disabled by policy"
    json .error_code KO_IP_VERSION_DISABLED

    run use_ipv6_notenabled_2 $a0 --osh selfAddPersonalAccess --host '[::1]' --force --user-any --port-any
    retvalshouldbe 133
    contain "Can't use '[::1]', IPv6 support disabled by policy"
    json .error_code KO_IP_VERSION_DISABLED

    # now enable IPv6
    configchg 's=^\\\\x22IPv6Allowed\\\\x22.+=\\\\x22IPv6Allowed\\\\x22:true,='

    run add_access_ipv6_invalid $a0 --osh selfAddPersonalAccess --host '2001:db8:3:4:5:6:7:8:9' --force --user-any --port-any
    retvalshouldbe 102
    json .error_code KO_HOST_NOT_FOUND

    run add_access_ipv6 $a0 --osh selfAddPersonalAccess --host '::1' --force --user-any --port-any
    if [ "${capabilities[ipv6]}" = 1 ]; then
        retvalshouldbe 0
        nocontain "already"
        contain "Forcing add as asked"
        json .command selfAddPersonalAccess .error_code OK .value.ip ::1 .value.port null .value.user null
    else
        retvalshouldbe 133
        json .error_code KO_IP_VERSION_DISABLED
    fi

    if [ "${capabilities[ipv6]}" = 1 ]; then
        success add_access_ipv6_dupe $a0 --osh selfAddPersonalAccess --host '::1' --force --user-any --port-any
        contain "already"
        json .command selfAddPersonalAccess .error_code OK_NO_CHANGE

        success add_access_ipv6_multiformat $a0 --osh selfAddPersonalAccess --host '2001:db8::000f:ff' --force --user-any --port-any
        nocontain "already"
        json .command selfAddPersonalAccess .error_code OK .value.ip 2001:db8::f:ff .value.port null .value.user null

        success add_access_ipv6_multiformat_dupe1 $a0 --osh selfAddPersonalAccess --host '2001:db8:0000:0000:0000:0000:000f:00ff' --force --user-any --port-any
        contain "already"
        json .command selfAddPersonalAccess .error_code OK_NO_CHANGE

        success add_access_ipv6_multiformat_dupe2 $a0 --osh selfAddPersonalAccess --host '2001:db8:00::0:f:ff' --force --user-any --port-any
        contain "already"
        json .command selfAddPersonalAccess .error_code OK_NO_CHANGE

        success add_access_ipv6_multiformat_dupe3 $a0 --osh selfAddPersonalAccess --host '2001:DB8:00::0:F:fF' --force --user-any --port-any
        contain "already"
        json .command selfAddPersonalAccess .error_code OK_NO_CHANGE

        success self_listaccesses $a0 --osh selfListAccesses
        json .command selfListAccesses .error_code OK
        json --splitsort '[.value[]|select(.type == "personal").acl[]|.ip]' '::1 2001:db8::f:ff'
    fi

    run connect_ipv6_1 $a0 ::1
    if [ "${capabilities[ipv6]}" = 1 ]; then
        contain "Connecting..."
        contain "$account0.v6[..1].22.ttyrec"
    else
        retvalshouldbe 133
        json .error_code KO_IP_VERSION_DISABLED
    fi

    run connect_ipv6_2 $a0 '[0:00:000:0000::1]'
    if [ "${capabilities[ipv6]}" = 1 ]; then
        contain "Connecting..."
        contain "$account0.v6[..1].22.ttyrec"
    else
        retvalshouldbe 133
        json .error_code KO_IP_VERSION_DISABLED
    fi

    if [ "${capabilities[ipv6]}" = 1 ]; then
        success self_delaccess $a0 --osh selfDelPersonalAccess --host '2001:db8:0:00:0::f:ff' --port '*' --user '*'
        json .command selfDelPersonalAccess .error_code OK

        success self_delaccess_dupe $a0 --osh selfDelPersonalAccess --host '2001:db8:00:0:00::f:ff' --port '*' --user '*'
        json .command selfDelPersonalAccess .error_code OK_NO_CHANGE

        success self_listaccesses_2 $a0 --osh selfListAccesses
        json .command selfListAccesses .error_code OK
        json --splitsort '[.value[]|select(.type == "personal").acl[]|.ip]' '::1'
    fi

    # delete account1
    script cleanup $a0 --osh accountDelete --account $account1 "<<< \"Yes, do as I say and delete $account1, kthxbye\""
    retvalshouldbe 0
}

testsuite_ipv6
unset -f testsuite_ipv6
