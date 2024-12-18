# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_base()
{
    # create regular account to compare info access between auditor and non auditor
    success a0_create_a1 $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    # basic stuff and help
    run     nocmd     $a0
    retvalshouldbe 112
    contain "command specified and no host to connect to"
    json .command null .error_code KO_NO_HOST .value null

    success   empty     $a0 -osh
    contain "OSH help"
    json .command help .error_code OK .value null

    success   help1     $a0 -osh  help
    contain "OSH help"
    json .error_code OK .command help .value null

    success   help2     $a0 --osh help
    contain "OSH help"
    json .error_code OK .command help .value null

    run   boguscmd  $a0 --osh nonexistent
    retvalshouldbe 104
    contain "Unknown command"
    json .error_code KO_UNKNOWN_COMMAND .command null .value null

    # a1 is not auditor, won't seem the admins/superowners
    success   info $a1                --osh info
    contain "Your alias to connect"
    nocontain "My admins are: "
    nocontain "My super owners are: "
    json .error_code OK .command info .value.account $account1

    # now check that an admin can see the admins/superowners
    success   info $a0 -osh info
    contain "Your alias to connect"
    contain "My admins are: "
    contain "My super owners are: "
    json .error_code OK .command info .value.account $account0 .value.adminAccounts '["'"$account0"'"]'

    # delete account1
    success delete_a1 $a0 --osh accountDelete --account $account1 --no-confirm
}

testsuite_base
unset -f testsuite_base
