# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2317,SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_config_options()
{
    configchg 's=^\\\\x22dnsSupportLevel\\\\x22.+=\\\\x22dnsSupportLevel\\\\x22:0,='

    run a1_connect_nodns $a0 localhost
    retvalshouldbe 132
    json .error_code KO_DNS_DISABLED
    contain 'DNS resolving is disabled'
}

testsuite_config_options
unset -f testsuite_config_options
