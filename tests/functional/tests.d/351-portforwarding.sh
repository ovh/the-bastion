# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2317,SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

# Port forwarding tests, in two parts:
#
# 1. ACL management: adding/removing portforward accesses (personal, group, guest), local port
#    allocation, limits, and the per-account sshd config generated under $pfdir. These only use
#    placeholder IPs (--force), so they run against any bastion.
#
# 2. Live forwarding, using the slim "remoteserver" ssh box that docker_build_and_run_tests.sh starts
#    for us (see tests/functional/docker/sshhost_role.sh): data really flows
#    tester -> bastion (localhost:LOCALPORT) -> remoteserver:$pfport, and what is not granted is refused.
#    Skipped when the runner didn't provide a remoteserver.
#
# As in 348-proxyjump-connect.sh, live connectivity is exercised as the unprivileged $account1, never
# as the admin $account0.

testsuite_portforwarding()
{
    local pfdir=/etc/ssh/sshd_config.forward.d
    # placeholder target (TEST-NET-1) for the ACL-only tests
    local fakeip=192.0.2.10
    local lp1="" lp2="" lp3="" glp=""

    #
    # feature disabled (default)
    #

    plgfail pf_add_disabled $a0 --osh selfAddPersonalAccess --host $fakeip --port 22 --remote-port 8080 --force
    contain "Port forwarding is disabled on this bastion"
    json .command selfAddPersonalAccess .error_code ERR_INVALID_PARAMETER

    run pf_connect_disabled $a0 -L 20000:127.0.0.1:8080 $shellaccount@127.0.0.1 -- true
    retvalshouldbe 107
    contain "Port forwarding feature is disabled on this bastion"

    # enable the feature, restricting the local port pool to 3 ports so we can test its exhaustion.
    # There is no systemd in the test containers, so the default sshdReloadCommand can't work: send
    # sshd a SIGHUP ourselves (the command is exec'ed without a shell, hence the hex-escaped spaces).
    # All of this is reverted by the automatic post-module configuration restore.
    configset portForwardingEnabled true
    configchg 's=^\\\\x22sshdReloadCommand\\\\x22.+=\\\\x22sshdReloadCommand\\\\x22:\\\\x22pkill\\\\x20-HUP\\\\x20-F\\\\x20/var/run/sshd.pid\\\\x22,='
    configset portForwardingLocalPortMin 20000
    configset portForwardingLocalPortMax 20002

    #
    # parameter validation
    #

    plgfail pf_add_with_user $a0 --osh selfAddPersonalAccess --host $fakeip --user test --port 22 --remote-port 8080 --force
    json .command selfAddPersonalAccess .error_code ERR_INCOMPATIBLE_PARAMETERS

    plgfail pf_add_with_other_protocol $a0 --osh selfAddPersonalAccess --host $fakeip --port 22 --protocol sftp --remote-port 8080 --force
    json .command selfAddPersonalAccess .error_code ERR_INCOMPATIBLE_PARAMETERS

    # forwarding the ssh port itself would allow bypassing the bastion
    plgfail pf_add_ssh_port $a0 --osh selfAddPersonalAccess --host $fakeip --port 22 --remote-port 22 --force
    json .command selfAddPersonalAccess .error_code ERR_INCOMPATIBLE_PARAMETERS

    plgfail pf_add_invalid_remote_port $a0 --osh selfAddPersonalAccess --host $fakeip --port 22 --remote-port 99999 --force
    json .command selfAddPersonalAccess .error_code ERR_INVALID_PARAMETER

    #
    # personal accesses
    #

    success pf_add_1 $a0 --osh selfAddPersonalAccess --host $fakeip --port 22 --remote-port 8080 --force
    json .command selfAddPersonalAccess .error_code OK .value.action add .value.ip $fakeip .value.port 22 .value.remotePort 8080
    lp1=$(get_json | $jq '.value.localPort')
    pattern '^2000[0-2]$' "$lp1"

    # the account now has an sshd config allowing it to forward to this local port, and nothing else
    success pf_add_1_sshdconf $r0 cat $pfdir/$account0.conf
    contain "Match User $account0"
    contain "AllowTcpForwarding local"
    contain REGEX "PermitOpen localhost:${lp1}[[:space:]]*\$"

    success pf_add_1_listed $a0 --osh selfListAccesses
    json .command selfListAccesses .error_code OK
    contain "$lp1->8080"

    success pf_add_1_dupe $a0 --osh selfAddPersonalAccess --host $fakeip --port 22 --remote-port 8080 --force
    json .command selfAddPersonalAccess .error_code OK_NO_CHANGE

    # each access gets its own local port
    success pf_add_2 $a0 --osh selfAddPersonalAccess --host $fakeip --port 22 --remote-port 8081 --force
    json .command selfAddPersonalAccess .error_code OK .value.remotePort 8081
    lp2=$(get_json | $jq '.value.localPort')
    pattern '^2000[0-2]$' "$lp2"

    success pf_add_3 $a0 --osh selfAddPersonalAccess --host $fakeip --port 22 --remote-port 8082 --force
    json .command selfAddPersonalAccess .error_code OK .value.remotePort 8082
    lp3=$(get_json | $jq '.value.localPort')
    pattern '^2000[0-2]$' "$lp3"

    success pf_local_ports_are_unique test $(printf '%s\n' "$lp1" "$lp2" "$lp3" | sort -u | wc -l) = 3

    success pf_add_3_sshdconf $r0 cat $pfdir/$account0.conf
    contain "localhost:$lp1"
    contain "localhost:$lp2"
    contain "localhost:$lp3"

    # per-account limit
    configset portForwardingMaxPerUser 3
    plgfail pf_add_over_limit $a0 --osh selfAddPersonalAccess --host $fakeip --port 22 --remote-port 8083 --force
    json .command selfAddPersonalAccess .error_code ERR_PORTFORWARDING_LIMIT_EXCEEDED
    # 0 means unlimited: the next failure must come from the pool, not from the limit
    configset portForwardingMaxPerUser 0

    # the 3 ports of the pool are allocated: a 4th access must be refused, not be given an already used port
    plgfail pf_add_pool_exhausted $a0 --osh selfAddPersonalAccess --host $fakeip --port 22 --remote-port 8083 --force
    json .command selfAddPersonalAccess .error_code ERR_NO_FREE_PORTS

    # removal: the local port is no longer allowed by sshd, and is quarantined so that it's not handed
    # to somebody else while a session of this account might still be able to use it
    success pf_del_1 $a0 --osh selfDelPersonalAccess --host $fakeip --port 22 --remote-port 8080
    json .command selfDelPersonalAccess .error_code OK .value.action del .value.remotePort 8080 .value.localPort "$lp1"

    success pf_del_1_sshdconf $r0 cat $pfdir/$account0.conf
    nocontain "localhost:$lp1"
    contain "localhost:$lp2"
    contain "localhost:$lp3"

    success pf_del_1_quarantined $r0 cat /home/allowkeeper/.portforwarding_unavailable_ports
    contain REGEX "$lp1:[0-9]+"

    success pf_del_1_dupe $a0 --osh selfDelPersonalAccess --host $fakeip --port 22 --remote-port 8080
    json .command selfDelPersonalAccess .error_code OK_NO_CHANGE

    success pf_del_2 $a0 --osh selfDelPersonalAccess --host $fakeip --port 22 --remote-port 8081
    json .command selfDelPersonalAccess .error_code OK .value.localPort "$lp2"

    success pf_del_3 $a0 --osh selfDelPersonalAccess --host $fakeip --port 22 --remote-port 8082
    json .command selfDelPersonalAccess .error_code OK .value.localPort "$lp3"

    # no forwarding left: the account's sshd config must be gone
    run pf_del_all_sshdconf $r0 test -e $pfdir/$account0.conf
    retvalshouldbe 1

    # we're done with the small pool
    configset portForwardingLocalPortMax 20099

    #
    # group accesses
    #

    success pf_create_a1 $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    success pf_create_a2 $a0 --osh accountCreate --always-active --account $account2 --uid $uid2 --public-key "\"$(cat $account2key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    # group owned by a1: the owner is also member, gatekeeper and aclkeeper
    success pf_create_group1 $a0 --osh groupCreate --group $group1 --owner $account1 --algo ed25519 --size 256
    json .error_code OK .command groupCreate
    local g1json g1key
    g1json=$(get_json)
    g1key="$(echo "$g1json" | $jq '.value.public_key.typecode') $(echo "$g1json" | $jq '.value.public_key.base64')"

    success pf_group_add $a1 --osh groupAddServer --group $group1 --host $fakeip --port 22 --remote-port 8080 --force
    json .command groupAddServer .error_code OK .value.action add .value.ip $fakeip .value.port 22 .value.remotePort 8080
    glp=$(get_json | $jq '.value.localPort')
    pattern '^200[0-9][0-9]$' "$glp"

    # members get the group's forwardings...
    success pf_group_member_sshdconf $r0 cat $pfdir/$account1.conf
    contain "Match User $account1"
    contain "localhost:$glp"

    # ... non-members don't
    run pf_group_nonmember_sshdconf $r0 test -e $pfdir/$account2.conf
    retvalshouldbe 1

    # ... until they become members
    success pf_group_addmember $a1 --osh groupAddMember --group $group1 --account $account2
    json .command groupAddMember .error_code OK

    success pf_group_newmember_sshdconf $r0 cat $pfdir/$account2.conf
    contain "Match User $account2"
    contain "localhost:$glp"

    success pf_group_delmember $a1 --osh groupDelMember --group $group1 --account $account2
    json .command groupDelMember .error_code OK

    run pf_group_exmember_sshdconf $r0 test -e $pfdir/$account2.conf
    retvalshouldbe 1

    # a guest access reuses the local port of the group access
    success pf_guest_add $a1 --osh groupAddGuestAccess --group $group1 --account $account2 --host $fakeip --port 22 --remote-port 8080
    json .command groupAddGuestAccess .error_code OK

    success pf_guest_sshdconf $r0 cat $pfdir/$account2.conf
    contain "Match User $account2"
    contain "localhost:$glp"

    success pf_guest_del $a1 --osh groupDelGuestAccess --group $group1 --account $account2 --host $fakeip --port 22 --remote-port 8080
    json .command groupDelGuestAccess .error_code OK

    run pf_exguest_sshdconf $r0 test -e $pfdir/$account2.conf
    retvalshouldbe 1

    # an admin can regenerate everybody's sshd config, e.g. after a master/slave failover
    success pf_admin_regen_prepare $r0 rm -f $pfdir/$account1.conf
    success pf_admin_regen $a0 --osh adminGenerateAllSshdConfigs
    json .command adminGenerateAllSshdConfigs .error_code OK

    success pf_admin_regen_sshdconf $r0 cat $pfdir/$account1.conf
    contain "localhost:$glp"

    # sshd must only be reloaded when a config actually changed: with a reload command that always fails,
    # regenerating configs that are already up to date must not report any failure
    configchg 's=^\\\\x22sshdReloadCommand\\\\x22.+=\\\\x22sshdReloadCommand\\\\x22:\\\\x22false\\\\x22,='
    success pf_admin_regen_noop $a0 --osh adminGenerateAllSshdConfigs
    json .command adminGenerateAllSshdConfigs .error_code OK
    nocontain "Failed to reload sshd"

    # on a slave, all the configs are removed, and sshd must be reloaded (which fails here, as expected)
    configset readOnlySlaveMode true
    plgfail pf_admin_regen_slave $a0 --osh adminGenerateAllSshdConfigs
    json .command adminGenerateAllSshdConfigs .error_code ERR_SSHD_RELOAD_FAILED
    run pf_admin_regen_slave_sshdconf $r0 test -e $pfdir/$account1.conf
    retvalshouldbe 1
    configset readOnlySlaveMode false
    configchg 's=^\\\\x22sshdReloadCommand\\\\x22.+=\\\\x22sshdReloadCommand\\\\x22:\\\\x22pkill\\\\x20-HUP\\\\x20-F\\\\x20/var/run/sshd.pid\\\\x22,='

    # back to master with a working reload command: everything is regenerated
    success pf_admin_regen_back $a0 --osh adminGenerateAllSshdConfigs
    json .command adminGenerateAllSshdConfigs .error_code OK
    success pf_admin_regen_back_sshdconf $r0 cat $pfdir/$account1.conf
    contain "localhost:$glp"

    success pf_group_del $a1 --osh groupDelServer --group $group1 --host $fakeip --port 22 --remote-port 8080
    json .command groupDelServer .error_code OK .value.action del .value.remotePort 8080 .value.localPort "$glp"

    run pf_group_del_sshdconf $r0 test -e $pfdir/$account1.conf
    retvalshouldbe 1

    #
    # live forwarding through the bastion to the remoteserver box
    #

    if [ -z "${remoteserver_ip:-}" ]; then
        echo "portforwarding: no remoteserver provided by the runner, skipping live tests"
    else
        testsuite_portforwarding_live
    fi

    #
    # forwardings must not outlive the accounts and groups they were granted through
    #

    success pf_add_for_a1 $a0 --osh accountAddPersonalAccess --account $account1 --host $fakeip --port 22 --remote-port 8080
    json .command accountAddPersonalAccess .error_code OK
    lp1=$(get_json | $jq '.value.localPort')

    success pf_group_readd $a1 --osh groupAddServer --group $group1 --host $fakeip --port 22 --remote-port 8080 --force
    json .command groupAddServer .error_code OK
    glp=$(get_json | $jq '.value.localPort')

    success pf_group_readd_member $a1 --osh groupAddMember --group $group1 --account $account2
    json .command groupAddMember .error_code OK

    success pf_before_cleanup_a1_sshdconf $r0 cat $pfdir/$account1.conf
    contain "localhost:$lp1"
    contain "localhost:$glp"

    success pf_before_cleanup_a2_sshdconf $r0 cat $pfdir/$account2.conf
    contain "localhost:$glp"

    # an account deleted while it's still member of a group having forwardings
    success pf_del_a2 $a0 --osh accountDelete --account $account2 --no-confirm
    json .error_code OK .command accountDelete

    run pf_del_a2_sshdconf $r0 test -e $pfdir/$account2.conf
    retvalshouldbe 1

    # a group deleted while it still has forwardings: its members keep their own forwardings
    success pf_del_group1 $a0 --osh groupDelete --group $group1 --no-confirm
    json .error_code OK .command groupDelete

    success pf_del_group1_sshdconf $r0 cat $pfdir/$account1.conf
    contain "localhost:$lp1"
    nocontain "localhost:$glp"

    success pf_del_group1_quarantine $r0 cat /home/allowkeeper/.portforwarding_unavailable_ports
    contain "$glp"

    # an account deleted while it still has a personal forwarding
    success pf_del_a1 $a0 --osh accountDelete --account $account1 --no-confirm
    json .error_code OK .command accountDelete

    run pf_del_a1_sshdconf $r0 test -e $pfdir/$account1.conf
    retvalshouldbe 1
}

# Outputs a script that tests a forwarding end to end, and prints what it has seen. In the background,
# a1 opens a session through the bastion to the remoteserver, asking the bastion to forward its local
# port $1 to the remoteserver's $pfport ($2 being additional options for the bastion, such as -J), and
# asking its own ssh client for two forwardings to the bastion: $tp_ok to localhost:$1 (granted) and
# $tp_ungranted to the bastion's own sshd (not granted). Meanwhile a2, who has no forwarding rights at
# all, tries to reach localhost:$1 on the bastion through $tp_other.
# The script then probes the three tester-side ports: "connected" tells whether the tester-side listener
# was there (so that an empty banner really means that the bastion refused to forward), and the banner
# is the first line received through the forwarding, if any.
# Uses the variables of testsuite_portforwarding_live.
_portforwarding_probe_script()
{
    cat <<EOF
tmp=\$(mktemp)
probe() {
    echo SSH-2.0-bastiontest_probe | nc -w 2 127.0.0.1 "\$1" > "\$tmp" 2>/dev/null
    echo "connected=\$? banner=\$(head -n 1 "\$tmp" | tr -cd '[:print:]')"
}
ssh -F $mytmpdir/ssh_config -i $account1key1file -T \\
    -L 127.0.0.1:$tp_ok:localhost:$1 -L 127.0.0.1:$tp_ungranted:localhost:$remote_port \\
    $account1@$remote_ip -p $remote_port -- -T ${2:-} -L $1:$rsip:$pfport test-shell_@$rsip -p $rsport -- sleep 30 >/dev/null 2>&1 &
pid1=\$!
ssh -F $mytmpdir/ssh_config -i $account2key1file -T -N \\
    -L 127.0.0.1:$tp_other:localhost:$1 $account2@$remote_ip -p $remote_port >/dev/null 2>&1 &
pid2=\$!
for _ in \$(seq 1 $((default_timeout * 2))); do
    granted=\$(probe $tp_ok)
    echo "\$granted" | grep -q pftest-landed && break
    sleep 1
done
echo "granted=<\$granted>"
echo "ungranted=<\$(probe $tp_ungranted)>"
echo "other_account=<\$(probe $tp_other)>"
kill \$pid1 \$pid2
rm -f "\$tmp"
EOF
}

# expects $account1 (owner of $group1), $account2 and $g1key from testsuite_portforwarding
testsuite_portforwarding_live()
{
    local rsport="${remoteserver_port:-22}"
    # port of the service we'll forward on the remoteserver
    local pfport=2222
    # local ports used on the tester side of the forwardings
    local tp_ok=23001 tp_ungranted=23002 tp_other=23003
    local rsip="" lp=""

    # same as in 348-proxyjump-connect.sh: no DNS/network side effects during the counting pass
    if [ "${COUNTONLY:-}" != 1 ]; then
        rsip=$(getent hosts "$remoteserver_ip" 2>/dev/null | awk '{print $1; exit}')
        [ -z "$rsip" ] && rsip="$remoteserver_ip"
        for _ in $(seq 1 30); do
            echo 'SSH-2.0-bastiontest_healthcheck' | nc -w 1 "$rsip" "$rsport" 2>/dev/null | grep -q ^SSH-2 && break
            sleep 1
        done
    fi

    # the service we forward: a second sshd on the remoteserver, announcing itself with a distinctive
    # banner so that we can assert where a forwarded connection really landed
    success pfl_start_service $rR "/usr/sbin/sshd -p $pfport -o PidFile=/run/sshd-pftest.pid -o VersionAddendum=pftest-landed-on-remoteserver"

    success pfl_push_key_to_remoteserver $rR "echo '$g1key' \>\> /home/test-shell_/.ssh/authorized_keys"

    # ssh access to the remoteserver (really tested, as we don't pass --force), then the right to forward $pfport
    success pfl_add_server $a1 --osh groupAddServer --group $group1 --host $rsip --user test-shell_ --port $rsport
    json .command groupAddServer .error_code OK .value.action add .value.ip $rsip .value.user test-shell_ .value.port $rsport

    success pfl_add_forward $a1 --osh groupAddServer --group $group1 --host $rsip --port $rsport --remote-port $pfport --force
    json .command groupAddServer .error_code OK .value.action add .value.ip $rsip .value.port $rsport .value.remotePort $pfport
    lp=$(get_json | $jq '.value.localPort')
    pattern '^200[0-9][0-9]$' "$lp"

    # the egress side alone: the bastion accepts to open the forwarding along with the session
    success pfl_connect $a1 -T -L $lp:$rsip:$pfport test-shell_@$rsip -p $rsport -- cat /sshhost-role
    contain "proxyjump-test-landed-on=remoteserver"
    contain "with port forwards"
    nocontain "Permission denied"

    # ... but only for what has been granted: another remote port, or another local port
    run pfl_connect_ungranted_remote_port $a1 -T -L $lp:$rsip:$((pfport + 1)) test-shell_@$rsip -p $rsport -- cat /sshhost-role
    retvalshouldbe 107
    contain "you don't have the right to forward port"
    nocontain "proxyjump-test-landed-on=remoteserver"

    run pfl_connect_wrong_local_port $a1 -T -L $((lp + 1)):$rsip:$pfport test-shell_@$rsip -p $rsport -- cat /sshhost-role
    retvalshouldbe 107
    contain "you don't have the right to forward port"
    nocontain "proxyjump-test-landed-on=remoteserver"

    # the forwarding can only point to the server we're connecting to
    run pfl_connect_other_remote_host $a1 -T -L $lp:192.0.2.1:$pfport test-shell_@$rsip -p $rsport -- cat /sshhost-role
    retvalshouldbe 136
    contain "must match the target IP"

    run pfl_connect_malformed $a1 -T -L notaforward test-shell_@$rsip -p $rsport -- cat /sshhost-role
    retvalshouldbe 136
    contain "Invalid port forward specification"

    # read-only slaves never forward
    configset readOnlySlaveMode true
    run pfl_connect_slave $a1 -T -L $lp:$rsip:$pfport test-shell_@$rsip -p $rsport -- cat /sshhost-role
    retvalshouldbe 107
    contain "disabled on read-only slave"
    configset readOnlySlaveMode false

    # Now the real thing, end to end, see _portforwarding_probe_script
    script pfl_forward "$(_portforwarding_probe_script "$lp")"
    retvalshouldbe 0
    contain REGEX 'granted=<connected=0 banner=SSH-2\.0-.*pftest-landed-on-remoteserver>'
    contain 'ungranted=<connected=0 banner=>'
    contain 'other_account=<connected=0 banner=>'

    # forwarding also works when the remoteserver is reached through a jumphost (-J)
    if [ -n "${jumphost_ip:-}" ]; then
        local jhport="${jumphost_port:-22}" jhip="" lpj=""
        if [ "${COUNTONLY:-}" != 1 ]; then
            jhip=$(getent hosts "$jumphost_ip" 2>/dev/null | awk '{print $1; exit}')
            [ -z "$jhip" ] && jhip="$jumphost_ip"
        fi
        local via="--proxy-host $jhip --proxy-port $jhport --proxy-user jump_"

        configset egressProxyJumpAllowed true
        success pflj_push_key_to_jumphost $rJ "echo '$g1key' \>\> /home/jump_/.ssh/authorized_keys"

        success pflj_add_server $a1 --osh groupAddServer --group $group1 --host $rsip --user test-shell_ --port $rsport $via
        json .command groupAddServer .error_code OK .value.action add .value.ip $rsip .value.proxyIp $jhip

        # this is another access than the direct one, so it gets its own local port
        success pflj_add_forward $a1 --osh groupAddServer --group $group1 --host $rsip --port $rsport --remote-port $pfport $via --force
        json .command groupAddServer .error_code OK .value.action add .value.remotePort $pfport .value.proxyIp $jhip
        lpj=$(get_json | $jq '.value.localPort')
        pattern '^200[0-9][0-9]$' "$lpj"
        success pflj_local_ports_are_unique test "$lp" != "$lpj"

        # the local port of the direct access is not granted through the jumphost, and vice versa
        run pflj_connect_direct_local_port $a1 -T -J jump_@$jhip:$jhport -L $lp:$rsip:$pfport test-shell_@$rsip -p $rsport -- cat /sshhost-role
        retvalshouldbe 107
        contain "you don't have the right to forward port"

        run pflj_connect_proxied_local_port $a1 -T -L $lpj:$rsip:$pfport test-shell_@$rsip -p $rsport -- cat /sshhost-role
        retvalshouldbe 107
        contain "you don't have the right to forward port"

        script pflj_forward "$(_portforwarding_probe_script "$lpj" "-J jump_@$jhip:$jhport")"
        retvalshouldbe 0
        contain REGEX 'granted=<connected=0 banner=SSH-2\.0-.*pftest-landed-on-remoteserver>'
        contain 'ungranted=<connected=0 banner=>'
        contain 'other_account=<connected=0 banner=>'

        success pflj_del_forward $a1 --osh groupDelServer --group $group1 --host $rsip --port $rsport --remote-port $pfport $via
        json .command groupDelServer .error_code OK .value.action del .value.localPort "$lpj"

        success pflj_del_server $a1 --osh groupDelServer --group $group1 --host $rsip --user test-shell_ --port $rsport $via
        json .command groupDelServer .error_code OK .value.action del
    fi

    # once the access is removed, the forwarding is refused and sshd no longer allows the local port
    success pfl_del_forward $a1 --osh groupDelServer --group $group1 --host $rsip --port $rsport --remote-port $pfport
    json .command groupDelServer .error_code OK .value.action del .value.remotePort $pfport .value.localPort "$lp"

    run pfl_connect_after_del $a1 -T -L $lp:$rsip:$pfport test-shell_@$rsip -p $rsport -- cat /sshhost-role
    retvalshouldbe 107
    contain "you don't have the right to forward port"

    run pfl_sshdconf_after_del $r0 test -e /etc/ssh/sshd_config.forward.d/$account1.conf
    retvalshouldbe 1

    success pfl_del_server $a1 --osh groupDelServer --group $group1 --host $rsip --user test-shell_ --port $rsport
    json .command groupDelServer .error_code OK .value.action del .value.ip $rsip

    success pfl_stop_service $rR "kill \\\$\(cat /run/sshd-pftest.pid\)"
}

testsuite_portforwarding
unset -f testsuite_portforwarding testsuite_portforwarding_live _portforwarding_probe_script
