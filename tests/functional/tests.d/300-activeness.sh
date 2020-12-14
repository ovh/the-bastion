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
    success activeness create_account1 $a0 --osh accountCreate --account $account1 --uid $uid1 --public-key \""$(cat $account1key1file.pub)"\"
    json .error_code OK .command accountCreate .value null

    success activeness create_account2 $a0 --osh accountCreate --account $account2 --uid $uid2 --public-key \""$(cat $account2key1file.pub)"\"
    json .error_code OK .command accountCreate .value null

    success activeness create_account3 $a0 --osh accountCreate --account $account3 --uid $uid3 --always-active --public-key \""$(cat $account3key1file.pub)"\"
    json .error_code OK .command accountCreate .value null

    revoke accountCreate

    configchg 's=^\\\\x22accountExternalValidationProgram\\\\x22.+=\\\\x22accountExternalValidationProgram\\\\x22:\\\\x22/opt/bastion/bin/other/doesnotexist.pl\\\\x22,='

    success activeness test_invalid_config_but_always_active $a3 --osh info

    ignorecodewarn 'is not readable+executable'
    run activeness test_invalid_config $a1 --osh info
    retvalshouldbe 101

    configchg 's=^\\\\x22accountExternalValidationProgram\\\\x22.+=\\\\x22accountExternalValidationProgram\\\\x22:\\\\x22/opt/bastion/bin/other/check-active-account-fortestsonly.pl\\\\x22,='

    run activeness test_account1 $a1 --osh info
    retvalshouldbe 101

    success activeness test_account2 $a2 --osh info

    success activeness test_account3 $a3 --osh info

    # for remaining tests, disable the feature
    configchg 's=^\\\\x22accountExternalValidationProgram\\\\x22.+=\\\\x22accountExternalValidationProgram\\\\x22:\\\\x22\\\\x22,='

    grant accountDelete

    # delete account1
    success realm account1_cleanup $a0 --osh accountDelete --account $account1 --no-confirm

    # delete account2
    script realm account2_cleanup "$a0 --osh accountDelete --account $account2 <<< \"Yes, do as I say and delete $account2, kthxbye\""
    retvalshouldbe 0

    # delete account3
    success realm account3_cleanup $a0 --osh accountDelete --account $account3 --no-confirm

    revoke accountDelete
}

testsuite_activeness
