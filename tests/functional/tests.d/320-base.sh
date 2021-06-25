# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_base()
{
    grant accountCreate
    # create regular account to compare info access between auditor and non auditor
    success accountCreate a0_create_a1 $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command accountCreate .value null
    revoke accountCreate

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

    # grant account0 as admin
    success admin_superowner set_a0_as_admin $r0 "\". $opt_remote_basedir/lib/shell/functions.inc; add_user_to_group_compat $account0 osh-admin\""
    configchg 's=^\\\\x22adminAccounts\\\\x22.+=\\\\x22adminAccounts\\\\x22:[\\\\x22'"$account0"'\\\\x22],='
    # grant account1 as auditor
    success osh   accountGrantAuditor $a0 --osh accountGrantCommand --command auditor --account $account1
    success osh   info $a1                --osh info
    contain "Your alias to connect"
    contain "My admins are: "
    contain "My super owners are: "
    json .error_code OK .command info .value.account $account1 .value.adminAccounts '["'"$account0"'"]'


    # now check that regular user do not see admins list
    success osh   info $a0 -osh info
    contain "Your alias to connect"
    nocontain "My admins are: "
    nocontain "My super owners are: "
    json .error_code OK .command info .value.account $account0

    # delete account1
    grant accountDelete
    success admin_superowner delete_a1 $a0 --osh accountDelete --account $account1 --no-confirm
    revoke accountDelete

}

testsuite_base
