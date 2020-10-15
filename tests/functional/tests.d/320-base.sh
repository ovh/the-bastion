# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_base()
{
    # basic stuff and help
    run     base  nocmd     $a0
    retvalshouldbe 112
    contain "command specified and no host to connect to"
    json .command null .error_code KO_NO_HOST .value null

    success osh   empty     $a0 -osh
    contain "OSH help"
    json .command help .error_code OK .value null

    success osh   help1     $a0 -osh  help
    contain "OSH help"
    json .error_code OK .command help .value null

    success osh   help2     $a0 --osh help
    contain "OSH help"
    json .error_code OK .command help .value null

    run osh   boguscmd  $a0 --osh nonexistent
    retvalshouldbe 104
    contain "Unknown command"
    json .error_code KO_UNKNOWN_COMMAND .command null .value null

    success osh   info $a0 -osh info
    contain "Your alias to connect"
    json .error_code OK .command info .value.account $account0
}

testsuite_base
