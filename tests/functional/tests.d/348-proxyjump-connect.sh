# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2317,SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

# Live proxy-jump connection tests: unlike 347-proxyjump.sh (which only exercises ACL
# add/del/parsing against placeholder IPs), this module performs a *real* egress connection
# through a jumphost to a remoteserver, using the two slim ssh boxes that
# docker_build_and_run_tests.sh starts for us (see tests/functional/docker/sshhost_role.sh).
#
# Topology: tester -> bastion -> jumphost (jump_) -> remoteserver (test-shell_)
#
# IMPORTANT: all connectivity is exercised as the unprivileged account $account1 (a1), NOT as the
# admin account0 (a0). a0 has elevated privileges that would bypass access grants, so connecting as
# a0 could let a broken proxy-ACL check pass unnoticed. a0 is only used here to create/delete a1 and
# the group; a1 owns the group (hence can manage it) but is a normal account when it connects.

testsuite_proxyjump_connect()
{
    # this module needs the two slim ssh boxes; if the runner didn't provide them (e.g. when
    # running against a non-docker bastion), skip the whole module
    if [ -z "${jumphost_ip:-}" ] || [ -z "${remoteserver_ip:-}" ]; then
        echo "proxyjump-connect: no jumphost/remoteserver provided by the runner, skipping live tests"
        return 0
    fi

    # ssh ports of the jump/remote boxes (default 22). A single-host runner may put the jumphost on
    # another port, as the bastion's own sshd already owns port 22 (see launch_tests_on_instance.sh,
    # which exports $jumphost_port/$remoteserver_port from the JUMPHOST_PORT/REMOTESERVER_PORT env).
    local jhport="${jumphost_port:-22}" rsport="${remoteserver_port:-22}"

    # Resolving the container names to IPs and probing the boxes' ssh port both have side effects
    # (DNS lookups, TCP connections to the boxes' sshd), so they must NOT run during the test-counting
    # pass (COUNTONLY=1). jhip/rsip stay empty there, which is harmless as the test bodies below are
    # not executed during counting.
    local jhip="" rsip=""
    if [ "${COUNTONLY:-}" != 1 ]; then
        # the bastion stores/uses IPs in its ACLs, so resolve the container names to IPs
        jhip=$(getent hosts "$jumphost_ip"     2>/dev/null | awk '{print $1; exit}')
        rsip=$(getent hosts "$remoteserver_ip" 2>/dev/null | awk '{print $1; exit}')
        # fall back to the value as-is when it's already an IP or getent is unavailable (e.g. FreeBSD)
        [ -z "$jhip" ] && jhip="$jumphost_ip"
        [ -z "$rsip" ] && rsip="$remoteserver_ip"

        # wait for the ssh port (not just ICMP reachability) to be up on both boxes. We feed nc a
        # well-formed "SSH-2.0-..." identification string rather than arbitrary data, so the remote
        # sshd doesn't log a spurious "banner exchange ... invalid format" line; nc's own stderr is
        # silenced to keep the retry loop quiet while the port isn't open yet.
        for _ in $(seq 1 30); do
            if echo 'SSH-2.0-bastiontest_healthcheck' | nc -w 1 "$jhip" "$jhport" 2>/dev/null | grep -q ^SSH-2 \
                && echo 'SSH-2.0-bastiontest_healthcheck' | nc -w 1 "$rsip" "$rsport" 2>/dev/null | grep -q ^SSH-2; then
                break
            fi
            sleep 1
        done
    fi

    # enable the proxy-jump feature (disabled by default)
    configset egressProxyJumpAllowed true

    # a0 (admin) creates the unprivileged account we'll actually connect as
    success a0_create_a1 $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    # group owned by a1: the owner is granted gatekeeper+aclkeeper, so a1 can add itself as a member,
    # get the egress key, and add servers
    success a0_create_group1 $a0 --osh groupCreate --group $group1 --owner $account1 --algo ed25519 --size 256
    json .error_code OK .command groupCreate
    local g1json g1key
    g1json=$(get_json)
    g1key="$(echo "$g1json" | $jq '.value.public_key.typecode') $(echo "$g1json" | $jq '.value.public_key.base64')"

    # ensure a1 is a member so it can connect to the group's servers. a1 is the group owner, and
    # groupCreate already adds the owner as a member, so this is a no-op (hence OK_NO_CHANGE); we keep
    # it to make the membership explicit and robust against any future change to that behavior.
    success a1_addmember_group1 $a1 --osh groupAddMember --group $group1 --account $account1
    json .command groupAddMember .error_code OK_NO_CHANGE

    # authorize the bastion egress key on the jumphost (user jump_) and on the remoteserver
    # (user test-shell_), over the root SSH sessions the runner gave us
    success push_key_to_jumphost     $rJ "echo '$g1key' \>\> /home/jump_/.ssh/authorized_keys"
    success push_key_to_remoteserver $rR "echo '$g1key' \>\> /home/test-shell_/.ssh/authorized_keys"

    # a1 adds the remoteserver to the group, reachable through the jumphost. We do NOT pass --force, so
    # the bastion runs a *real* proxied connectivity test here (exercising ssh_test_access_way and the
    # ProxyCommand assembly), which must succeed now that the keys are in place
    success a1_add_server_via_proxy $a1 --osh groupAddServer --group $group1 \
        --host $rsip --user test-shell_ --port $rsport \
        --proxy-host $jhip --proxy-port $jhport --proxy-user jump_
    json .command groupAddServer .error_code OK .value.action add .value.ip $rsip .value.user test-shell_ .value.port $rsport .value.proxyIp $jhip .value.proxyPort $jhport .value.proxyUser jump_

    # the actual end-to-end connection AS A1 (unprivileged), so the proxy ACL is genuinely enforced:
    # tester -> bastion -> jumphost -> remoteserver. We run a command on the remoteserver that returns
    # its role marker, and assert we really landed there.
    success connect_through_proxy $a1 -J jump_@$jhip:$jhport test-shell_@$rsip -p $rsport -- cat /sshhost-role
    contain "proxyjump-test-landed-on=remoteserver"
    nocontain "Permission denied"

    # the session recording must land in a "via-<proxyip>-<targetip>" folder.
    # The egress ssh runs its ProxyCommand under /bin/sh (osh.pl pins $SHELL=/bin/sh for the hop), so
    # osh.pl is never re-entered to run the proxy command and the ttyrec setup is not bypassed.
    # We read a1's ttyrec dir as root on the bastion.
    success a1_ttyrec_via_folder $r0 "ls /home/$account1/ttyrec/"
    contain "via-$jhip-$rsip"

    # negative: connecting through a proxy that is NOT the one granted in the ACL must be denied
    # (here we point -J at the remoteserver's IP, which is not an authorized proxy)
    run connect_through_unauthorized_proxy $a1 -J jump_@$rsip:$rsport test-shell_@$rsip -p $rsport -- cat /sshhost-role
    retvalshouldbe 107
    contain "Access denied"
    nocontain "proxyjump-test-landed-on=remoteserver"

    # negative: connecting WITHOUT a proxy to a host that requires one must also be denied
    run connect_without_required_proxy $a1 test-shell_@$rsip -p $rsport -- cat /sshhost-role
    retvalshouldbe 107
    contain "Access denied"

    # ---- "escape hell" over proxy-jump ----
    # A quoted remote command must reach the remoteserver *through the jumphost* exactly as it would on a
    # direct connection. These cases mirror the escapehell* matrix of 340-selfaccesses.sh (same command
    # strings, same expected results), but sent via -J: this locks in the "how do commands/options get
    # passed to the bastion, even with interleaved quoting" contract specifically for the proxy-jump path.
    # The far end (test-shell_ on the remoteserver) runs /bin/sh, just like 340's shellaccount, so the
    # quoting must resolve identically.

    # baseline: a plain echo survives the double hop intact.
    # NB: every live jump case below sets the retry_until variable before it: the egress -W ProxyCommand
    # hop rarely truncates the tail of the output (OpenSSH teardown race; run() in
    # launch_tests_on_instance.sh re-runs the case until this marker is captured, bounded). The marker is
    # the last thing each command emits: $randomstr for the echo, 'uid=' (from the trailing `id`) for
    # every escapehell case. It's a plain variable, not a function call, so an older runner that predates
    # the retry loop simply ignores it instead of aborting the module. We clear it after the block below.
    retry_until="$randomstr"
    success pj_echo_simple $a1 -J jump_@$jhip:$jhport test-shell_@$rsip -- echo $randomstr
    contain "$randomstr"
    nocontain "Permission denied"

    # --always-escape
    retry_until='uid='
    success pj_escapehell1ae $a1 --always-escape -J jump_@$jhip:$jhport test-shell_@$rsip -- "\"echo 'test1;test1' ; id\""
    contain "'test1"
    contain 'uid='
    contain REGEX "test1': (command )?not found"
    nocontain 'test1;test1'

    retry_until='uid='
    success pj_escapehell2ae $a1 --always-escape -J jump_@$jhip:$jhport test-shell_@$rsip -- "'echo \"test1;test1\" ; id'"
    contain "test1;test1"
    contain 'uid='
    nocontain 'not found'

    retry_until='uid='
    success pj_escapehell3ae $a1 --always-escape -J jump_@$jhip:$jhport test-shell_@$rsip -- "'echo \\\"test1;test1\\\" ; id'"
    contain '"test1'
    contain 'uid='
    contain REGEX 'test1": (command )?not found'

    retry_until='uid='
    success pj_escapehell4ae $a1 --always-escape -J jump_@$jhip:$jhport test-shell_@$rsip -- "\"echo \\\"test1;test1\\\" ; id\""
    contain 'test1;test1'
    contain 'uid='
    nocontain 'not found'

    retry_until='uid='
    success pj_escapehell5ae $a1 --always-escape -J jump_@$jhip:$jhport test-shell_@$rsip -- "\"echo \\\"test1';'test1\\\" ; id\""
    contain "test1\\';\\'test1"
    contain 'uid='
    nocontain 'not found'

    # --never-escape
    retry_until='uid='
    success pj_escapehell1ne $a1 --never-escape -J jump_@$jhip:$jhport test-shell_@$rsip -- "\"echo 'test1;test1' ; id\""
    contain "test1;test1"
    contain 'uid='
    nocontain 'not found'

    retry_until='uid='
    success pj_escapehell2ne $a1 --never-escape -J jump_@$jhip:$jhport test-shell_@$rsip -- "'echo \"test1;test1\" ; id'"
    contain "test1;test1"
    contain 'uid='
    nocontain 'not found'

    retry_until='uid='
    success pj_escapehell3ne $a1 --never-escape -J jump_@$jhip:$jhport test-shell_@$rsip -- "'echo \\\"test1;test1\\\" ; id'"
    contain '"test1'
    contain 'uid='
    contain REGEX 'test1": (command )?not found'

    retry_until='uid='
    success pj_escapehell4ne $a1 --never-escape -J jump_@$jhip:$jhport test-shell_@$rsip -- "\"echo \\\"test1;test1\\\" ; id\""
    contain 'test1;test1'
    contain 'uid='
    nocontain 'not found'

    retry_until='uid='
    success pj_escapehell5ne $a1 --never-escape -J jump_@$jhip:$jhport test-shell_@$rsip -- "\"echo \\\"test1';'test1\\\" ; id\""
    contain "test1';'test1"
    contain 'uid='
    nocontain 'not found'

    # A current runner clears retry_until in run() after each case; clear it here too so that against an
    # older runner (which ignores and thus never clears it) it can't leak past this module and trip the
    # per-module env-diff check (module_postrun_check_env).
    unset retry_until

    # ---- scp through the proxy (still as a1) ----
    # to ensure proxy-jump also works through the scp plugin, do a *real* proxied scp transfer here,
    # reusing the same topology: the group egress key is already authorized on both the jumphost and the
    # remoteserver. scp/sftp need their own protocol grants (scpupload/scpdownload) on top of ssh access.

    # fetch the per-account scp wrapper the bastion generates for a1 (base64+gzip in .value.script),
    # exactly like the 395 test does. The wrapper handles -J and the two-pass (token generation + transfer).
    success a1_get_scp_wrapper $a1 --osh scp
    json .error_code OK .command scp
    if [ "${COUNTONLY:-}" != 1 ]; then
        get_json | $jq '.value.script' | base64 -d | gunzip -c > /tmp/scpwrapper_proxy
        chmod +x /tmp/scpwrapper_proxy
        # a small payload to upload, with a distinctive marker we can assert on the remoteserver
        echo "proxyjump-scp-payload-$$" > /tmp/scp_proxy_src
        rm -f /tmp/scp_proxy_back /tmp/scp_proxy_denied
    fi

    # a1 grants scp upload+download on the remoteserver, reachable through the jumphost. A protocol grant
    # is userless (the protocol is a property of the host:port, and the SSH access carrying the user was
    # granted above), so we must NOT pass --user here. We DO keep the proxy tuple: has_protocol_access()
    # is proxy-aware, so the protocol entry has to carry the same proxy to match at transfer time.
    success a1_add_scpup_via_proxy $a1 --osh groupAddServer --group $group1 \
        --host $rsip --port $rsport --protocol scpupload \
        --proxy-host $jhip --proxy-port $jhport --proxy-user jump_
    json .command groupAddServer .error_code OK .value.action add .value.ip $rsip .value.user "!scpupload" .value.port $rsport .value.proxyIp $jhip .value.proxyPort $jhport .value.proxyUser jump_
    success a1_add_scpdown_via_proxy $a1 --osh groupAddServer --group $group1 \
        --host $rsip --port $rsport --protocol scpdownload \
        --proxy-host $jhip --proxy-port $jhport --proxy-user jump_
    json .command groupAddServer .error_code OK .value.action add .value.ip $rsip .value.user "!scpdownload" .value.port $rsport .value.proxyIp $jhip .value.proxyPort $jhport .value.proxyUser jump_

    # upload a local file to the remoteserver, through the jumphost (a1's ingress key authenticates to
    # the bastion; the group egress key reaches the target)
    success scp_upload_via_proxy /tmp/scpwrapper_proxy -J jump_@$jhip:$jhport -i $account1key1file \
        /tmp/scp_proxy_src test-shell_@$rsip:/tmp/scp_proxy_dst
    # it must really have landed on the remoteserver (not on the jumphost or the bastion)
    success scp_upload_landed $rR "cat /tmp/scp_proxy_dst"
    contain "proxyjump-scp-payload-"

    # download it back through the proxy and check the content round-trips to the tester
    success scp_download_via_proxy /tmp/scpwrapper_proxy -J jump_@$jhip:$jhport -i $account1key1file \
        test-shell_@$rsip:/tmp/scp_proxy_dst /tmp/scp_proxy_back
    success scp_download_content cat /tmp/scp_proxy_back
    contain "proxyjump-scp-payload-"

    # negative: scp through a proxy that is NOT the one granted in the ACL must be denied. We assert the
    # robust invariant (nothing was written on the remoteserver); the exact denial wording is already
    # covered by the ssh negative tests above, which share the same is_access_granted() check.
    run scp_via_unauthorized_proxy /tmp/scpwrapper_proxy -J jump_@$rsip:$rsport -i $account1key1file \
        /tmp/scp_proxy_src test-shell_@$rsip:/tmp/scp_proxy_denied
    retvalshouldbe 1
    run scp_denied_left_no_file $rR "cat /tmp/scp_proxy_denied"
    retvalshouldbe 1
    nocontain "proxyjump-scp-payload-"

    # cleanup: a1 removes the accesses it added, then a0 removes the group and the account
    success a1_del_scpup_via_proxy $a1 --osh groupDelServer --group $group1 \
        --host $rsip --port $rsport --protocol scpupload \
        --proxy-host $jhip --proxy-port $jhport --proxy-user jump_
    json .command groupDelServer .error_code OK .value.action del .value.ip $rsip .value.user "!scpupload" .value.port $rsport .value.proxyIp $jhip .value.proxyPort $jhport .value.proxyUser jump_
    success a1_del_scpdown_via_proxy $a1 --osh groupDelServer --group $group1 \
        --host $rsip --port $rsport --protocol scpdownload \
        --proxy-host $jhip --proxy-port $jhport --proxy-user jump_
    json .command groupDelServer .error_code OK .value.action del .value.ip $rsip .value.user "!scpdownload" .value.port $rsport .value.proxyIp $jhip .value.proxyPort $jhport .value.proxyUser jump_

    success a1_del_server $a1 --osh groupDelServer --group $group1 \
        --host $rsip --user test-shell_ --port $rsport \
        --proxy-host $jhip --proxy-port $jhport --proxy-user jump_
    json .command groupDelServer .error_code OK .value.action del .value.ip $rsip .value.user test-shell_ .value.port $rsport .value.proxyIp $jhip .value.proxyPort $jhport .value.proxyUser jump_

    success a0_del_group1 $a0 --osh groupDelete --group $group1 --no-confirm
    json .error_code OK .command groupDelete

    success a0_del_a1 $a0 --osh accountDelete --account $account1 --no-confirm
    json .error_code OK .command accountDelete
}

testsuite_proxyjump_connect
unset -f testsuite_proxyjump_connect
