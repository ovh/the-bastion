# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2317,SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

# Exercise the --bind option: the egress connection must be made from the specified local IP,
# and this must be verified on the target side (SSH_CONNECTION), not just accepted by osh.
# We connect from the bastion to itself ($shellaccount@127.0.0.1) while binding to 127.0.0.2,
# which is implicitly available on Linux (the whole 127/8 is) and explicitly aliased on
# FreeBSD by target_role.sh.

testsuite_bind()
{
    # --bind only accepts IPs returned by get_bastion_ips(), which uses the egressKeysFrom
    # config when set, and 'hostname --all-ip-addresses' otherwise: the latter excludes
    # loopback addresses (and doesn't exist on FreeBSD), so declare 127.0.0.2 explicitly.
    # This is reverted by the automatic post-module configuration restore.
    configchg 's=^\\\\x22egressKeysFrom\\\\x22.+=\\\\x22egressKeysFrom\\\\x22:[\\\\x22127.0.0.2\\\\x22],='

    # connectivity must be exercised as an unprivileged account, not as a0 (admin, would
    # bypass access grants); a0 is only used to create/grant/delete a1
    success a0_create_a1 $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    # grant a1 a personal access to the target
    success a0_grant_a1 $a0 --osh accountAddPersonalAccess --account $account1 --host 127.0.0.1 --user $shellaccount --port 22
    json .error_code OK .command accountAddPersonalAccess .value.ip 127.0.0.1 .value.user $shellaccount .value.port 22

    # authorize a1's egress key on the target account (the bastion is also the target box)
    success a1_key_on_target $r0 "cat /home/$account1/.ssh/id_*.pub \>\> /home/$shellaccount/.ssh/authorized_keys"

    # control test: without --bind, the connection to 127.0.0.1 comes from 127.0.0.1
    success a1_connect_nobind $a1 $shellaccount@127.0.0.1 -- env
    contain "SSH_CONNECTION=127.0.0.1 "

    # the actual --bind test: the target's sshd must see the connection coming from 127.0.0.2
    success a1_connect_bind $a1 --bind 127.0.0.2 $shellaccount@127.0.0.1 -- env
    contain "SSH_CONNECTION=127.0.0.2 "

    # negative test: an IP that is not one of the bastion's IPs must be refused
    run a1_connect_invalid_bind $a1 --bind 192.0.2.1 $shellaccount@127.0.0.1 -- env
    retvalshouldbe 115
    contain "Invalid binding IP"
    nocontain "SSH_CONNECTION="

    # cleanup. The key line we appended to the target's authorized_keys is left behind but
    # inert: the matching private key is deleted along with the account
    success a0_delete_a1 $a0 --osh accountDelete --account $account1 --no-confirm
}

testsuite_bind
unset -f testsuite_bind
