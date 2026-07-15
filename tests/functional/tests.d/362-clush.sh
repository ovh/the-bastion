# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2317,SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_clush()
{
    # --- parameter validation ---

    # clush needs a host list
    plgfail clush_missing_list $a0 --osh clush --command "\"true\""
    json .command clush .error_code ERR_MISSING_PARAMETER

    # clush needs a command
    plgfail clush_missing_command $a0 --osh clush --list 127.0.0.1
    json .command clush .error_code ERR_MISSING_PARAMETER

    # an invalid host in the list (underscore is not a legal hostname char) is rejected before any connect
    plgfail clush_invalid_host $a0 --osh clush --list bad_host --command "\"true\"" --no-confirm --no-stdin
    json .command clush .error_code ERR_INVALID_PARAMETER

    # --- live dispatch (needs the remoteserver slim box) ---
    if [ -z "${remoteserver_ip:-}" ]; then
        echo "clush: no remoteserver provided by the runner, skipping live dispatch tests"
        return 0
    fi

    local rsport="${remoteserver_port:-22}"

    # waiting for remote server to be up if needed
    local rsip=""
    if [ "${COUNTONLY:-}" != 1 ]; then
        rsip=$(getent hosts "$remoteserver_ip" 2>/dev/null | awk '{print $1; exit}')
        [ -z "$rsip" ] && rsip="$remoteserver_ip"
        for _ in $(seq 1 30); do
            if echo 'SSH-2.0-bastiontest_healthcheck' | nc -w 1 "$rsip" "$rsport" 2>/dev/null | grep -q ^SSH-2; then
                break
            fi
            sleep 1
        done
    fi

    # a0 (admin) creates the unprivileged account we'll actually run clush as
    success clush_create_a1 $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    # a group owned by a1 (owner is granted gatekeeper+aclkeeper, so a1 can add servers and itself)
    success clush_create_group $a0 --osh groupCreate --group $group1 --owner $account1 --algo ed25519 --size 256
    json .error_code OK .command groupCreate
    local g1json g1key
    g1json=$(get_json)
    g1key="$(echo "$g1json" | $jq '.value.public_key.typecode') $(echo "$g1json" | $jq '.value.public_key.base64')"

    success clush_addmember $a1 --osh groupAddMember --group $group1 --account $account1
    json .command groupAddMember .error_code OK_NO_CHANGE

    # authorize the group's egress key on the remoteserver (user test-shell_)
    success clush_push_key $rR "echo '$g1key' \>\> /home/test-shell_/.ssh/authorized_keys"

    # register the remoteserver in the group; without --force this runs a real connectivity test, which
    # must now succeed since the key is in place
    success clush_add_server $a1 --osh groupAddServer --group $group1 --host $rsip --user test-shell_ --port $rsport
    json .command groupAddServer .error_code OK .value.action add .value.ip $rsip .value.user test-shell_ .value.port $rsport

    # dispatch a command over a one-host list, non-interactively. clush re-enters osh.pl to connect, so
    # this genuinely exercises the connect path as the unprivileged account a1.
    success clush_single_host $a1 --osh clush --no-confirm --no-pause-on-failure --no-stdin --user test-shell_ --port $rsport --command "'\"cat /sshhost-role\"'" --list $rsip
    json .command clush .error_code OK
    json --arg h "$rsip" '.value[$h].sysret' 0
    # clush returns stdout as an array of lines, so match the marker across the array
    json --arg h "$rsip" '.value[$h].stdout | any(test("proxyjump-test-landed-on=remoteserver"))' true

    # a command that fails on the remote host is reported with a non-zero sysret (and, thanks to
    # --no-pause-on-failure, clush doesn't block waiting for input)
    success clush_failing_command $a1 --osh clush --no-confirm --no-pause-on-failure --no-stdin --user test-shell_ --port $rsport --command "'\"exit 3\"'" --list $rsip
    json .command clush .error_code OK
    json --arg h "$rsip" '.value[$h].sysret' 3

    # cleanup
    success clush_del_group $a0 --osh groupDelete --group $group1 --no-confirm
    json .command groupDelete .error_code OK
    success clush_del_a1 $a0 --osh accountDelete --account $account1 --no-confirm
    json .command accountDelete .error_code OK
}

testsuite_clush
unset -f testsuite_clush
