# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_activeness()
{
    grant accountCreate
    # create account1 on local bastion
    success create_account1 $a0 --osh accountCreate --account $account1 --uid $uid1 --public-key \""$(cat $account1key1file.pub)"\"
    json .error_code OK .command accountCreate .value null

    success create_account2 $a0 --osh accountCreate --account $account2 --uid $uid2 --public-key \""$(cat $account2key1file.pub)"\"
    json .error_code OK .command accountCreate .value null

    success create_account3 $a0 --osh accountCreate --account $account3 --uid $uid3 --always-active --public-key \""$(cat $account3key1file.pub)"\"
    json .error_code OK .command accountCreate .value null

    revoke accountCreate

    configchg 's=^\\\\x22accountExternalValidationProgram\\\\x22.+=\\\\x22accountExternalValidationProgram\\\\x22:\\\\x22/opt/bastion/bin/other/doesnotexist.pl\\\\x22,='

    success test_invalid_config_but_always_active $a3 --osh info

    ignorecodewarn 'is not readable+executable'
    run test_invalid_config $a1 --osh info
    retvalshouldbe 101

    configchg 's=^\\\\x22accountExternalValidationProgram\\\\x22.+=\\\\x22accountExternalValidationProgram\\\\x22:\\\\x22/opt/bastion/bin/other/check-active-account-fortestsonly.pl\\\\x22,='

    run test_account1 $a1 --osh info
    retvalshouldbe 101

    success test_account2 $a2 --osh info

    success test_account3 $a3 --osh info

    # for remaining tests, disable the feature
    configchg 's=^\\\\x22accountExternalValidationProgram\\\\x22.+=\\\\x22accountExternalValidationProgram\\\\x22:\\\\x22\\\\x22,='

    # SSH-AS

    grant accountAddPersonalAccess

    # allow account1 to localhost, just so that ssh-as calls connect.pl (even if the connection doesn't make it through in the end)
    success add_access_to_a1 $a0 --osh accountAddPersonalAccess --account $account2 --host 127.0.0.1 --user sshas --port 22

    revoke accountAddPersonalAccess

    # now, test ssh-as
    run ssh_as_denied $a1 --ssh-as $account2 sshas@127.0.0.1
    retvalshouldbe 106
    json .error_code KO_SSHAS_DENIED

    # set account1 as admin
    success set_a1_as_admin $r0 "\". $opt_remote_basedir/lib/shell/functions.inc; add_user_to_group_compat $account1 osh-admin\""
    configchg 's=^\\\\x22adminAccounts\\\\x22.+=\\\\x22adminAccounts\\\\x22:[\\\\x22'"$account0"'\\\\x22,\\\\x22'"$account1"'\\\\x22],='

    # test ssh-as again
    run ssh_as_allowed $a1 --ssh-as $account2 sshas@127.0.0.1
    retvalshouldbe 255
    contain "you'll now impersonate"
    contain "Connecting..."
    contain "Permission denied (publickey)"

    # and finally remove admin grant
    success del_a1_as_admin $r0 "\". $opt_remote_basedir/lib/shell/functions.inc; del_user_from_group_compat $account1 osh-admin\""
    configchg 's=^\\\\x22adminAccounts\\\\x22.+=\\\\x22adminAccounts\\\\x22:[\\\\x22'"$account0"'\\\\x22],='

    # /SSH-AS

    grant accountDelete

    # delete account1
    success account1_cleanup $a0 --osh accountDelete --account $account1 --no-confirm

    # delete account2
    script account2_cleanup "$a0 --osh accountDelete --account $account2 <<< \"Yes, do as I say and delete $account2, kthxbye\""
    retvalshouldbe 0

    # delete account3
    success account3_cleanup $a0 --osh accountDelete --account $account3 --no-confirm

    revoke accountDelete
}

testsuite_activeness
unset -f testsuite_activeness
