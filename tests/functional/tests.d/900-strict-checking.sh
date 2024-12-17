# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_strict_checking()
{
    # test that strict host key checking with hostkey change is detected by the bastion and prints a help message

    # first we need to create account1
    success a0_create_a1 $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    # add access to root@127.0.0.1 (there are no keys deployed, but we don't care, connection should fail early due to the hostkey change)
    success add_local_access $a0 --osh accountAddPersonalAccess --account $account1 --host 127.0.0.1 --port 22 --user root
    json .command accountAddPersonalAccess .error_code OK

    # try to connect a first time, so that our bastion known_hosts is populated
    run connect_before $a1 root@127.0.0.1
    retvalshouldbe 255
    contain "Permanently added"

    # change the remote hostkeys, also send HUP to force sshd to take the change into account (Ubuntu 24+ at least),
    # don't check return value as we'll kill our own session with pkill, as a collateral damage.
    # uname -s: under FreeBSD, this interrupts the tests otherwise.
    run change_host_keys $r0 "\"find /etc/ssh/ -type f -name 'ssh_host_*' -delete; ssh-keygen -A; test \$(uname -s) = Linux && pkill -HUP sshd\""

    # set bastion ssh_client config to StrictHostKeyChecking yes
    sshclientconfigchg 's=StrictHostKeyChecking.*=StrictHostKeyChecking\\\\x20yes=g'

    # forget our local hostkeys cache
    #local a1home
    #a1home=$(getent passwd "$account1" | cut -d: -f6)
    #success strict-checking remove_local_host_keys_cache mv $a1home/.ssh/known_hosts $a1home/.ssh/known_hosts.bak
    rm -f $HOME/.ssh/known_hosts

    # now try to connect again
    run connect_after $a1 root@127.0.0.1
    retvalshouldbe 255
    contain NASTY
    contain "strict checking"
    contain "BASTION SAYS"
    contain selfForgetHostKey

    # delete account1
    script a0_delete_a1 $a0 --osh accountDelete --account $account1 "<<< \"Yes, do as I say and delete $account1, kthxbye\""
    retvalshouldbe 0
    json .command accountDelete .error_code OK
}

testsuite_strict_checking
unset -f testsuite_strict_checking
