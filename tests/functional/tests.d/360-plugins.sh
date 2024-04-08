# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_plugins()
{
    success ping_withHost $a0 --osh ping -w 2 --host 127.0.0.1 -c 2
    json .command     ping .error_code  OK
    # in some tests environments, ping is not allowed...
    _sysret=$(get_json | $jq .value.sysret)
    if [ "$_sysret" = 0 ]; then
        json .value.host 127.0.0.1 .value.packets_transmitted  2 .value.packets_loss_percentage  0 .value.packets_received  2
    elif [ "$_sysret" = 2 ]; then
        :
    else
        json .value.sysret 0
    fi
    unset _sysret

    success ping_withoutHost $a0 --osh ping -c 1 127.0.0.1 -w 1
    json .command    ping .error_code  OK
    _sysret=$(get_json | $jq .value.sysret)
    if [ "$_sysret" = 0 ]; then
        json .value.host 127.0.0.1 .value.packets_transmitted  1 .value.packets_loss_percentage  0 .value.packets_received  1
    elif [ "$_sysret" = 2 ]; then
        :
    else
        json .value.sysret 0
    fi
    unset _sysret

    success ping_loss $a0 --osh ping 192.0.2.1 -w 1 -c 1
    json .command ping .error_code OK
    _sysret=$(get_json | $jq .value.sysret)
    if [ "$_sysret" = 1 ]; then
        json .value.host 192.0.2.1 .value.packets_loss_percentage  100 .value.packets_received  0
    elif [ "$_sysret" = 2 ]; then
        :
    else
        json .value.sysret 1
    fi
    unset _sysret

    success nc_withHost $a0 --osh nc --port 22 --host 127.0.0.1 --timeout 1
    json $(cat <<EOS
    .command nc
    .error_code OK
    .value.host 127.0.0.1
    .value.port  22
    .value.result open
EOS
    )

    success nc_withoutHost $a0 --osh nc 127.0.0.1 22 --timeout 1
    json $(cat <<EOS
    .command nc
    .error_code OK
    .value.host 127.0.0.1
    .value.port   22
    .value.result open
EOS
    )

    success nc_closed $a0 --osh nc 127.0.0.1 1 --timeout 1
    json $(cat <<EOS
    .command nc
    .error_code OK
    .value.host 127.0.0.1
    .value.port   1
    .value.result closed
EOS
    )

    success nc_timeout $a0 --osh nc --timeout 1 192.0.2.1 22
    json $(cat <<EOS
    .command nc
    .error_code OK
    .value.host 192.0.2.1
    .value.port   22
    .value.result timeout
EOS
    )

    success alive_withHost $a0 --osh alive --host 127.0.0.1
    json .command alive .error_code OK .value.waited_for 0

    success alive_withoutHost $a0 --osh alive 127.0.0.1
    json .command alive .error_code OK .value.waited_for 0

    run alive_unreachable $a0f --osh alive 192.0.2.0
    retvalshouldbe 124
}

testsuite_plugins
unset -f testsuite_plugins
