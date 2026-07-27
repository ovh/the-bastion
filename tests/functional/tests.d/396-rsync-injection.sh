# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2317,SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

# Regression test for command injection through the rsync plugin.

testsuite_rsync_injection()
{
    local marker="/tmp/RSYNC_INJECTION_SUCCEEDED"

    # make sure no stale marker exists, so any positive result can only come from THIS run
    success rsync_injection_marker_cleanup_before $r0 rm -f "$marker"

    # grant a0 both ssh access and rsync-protocol access to test-shell_@127.0.0.2:22
    # (has_protocol_access requires BOTH); --force skips the key-install connectivity check
    success rsync_injection_add_ssh_access $a0 --osh selfAddPersonalAccess --host 127.0.0.2 --user $shellaccount --port 22 --force
    json .command selfAddPersonalAccess .error_code OK
    success rsync_injection_add_rsync_access $a0 --osh selfAddPersonalAccess --host 127.0.0.2 --protocol rsync --port 22 --force
    json .command selfAddPersonalAccess .error_code OK

    # THE INJECTION ATTEMPT.
    # We hand-craft exactly what the rsync binary would send to the plugin after '--osh rsync --',
    # i.e. '-l USER HOST rsync <args>', but append '; touch MARKER'. The ';' is written as '\;'
    # ">>> Hello" confirms the plugin got past the access checks and actually ran the transfer.
    run rsync_command_injection $a0 --osh rsync -- -l $shellaccount 127.0.0.2 rsync --version '\;' touch "$marker"
    contain ">>> Hello"

    # PROOF THE FIX HOLDS.
    # With shell-quoting, the ';' is passed to rsync as an inert literal argument instead of a
    # shell command separator, so the injected 'touch' never runs and the marker is never created.
    # When absent, stat prints "No such file or directory" and its output does NOT mention the remote egress
    # user; if the injection had worked, the marker would exist and be owned by test-shell_.
    run rsync_injection_blocked $r0 stat "$marker"
    retvalshouldbe 1
    contain "stat:"
    contain "file or directory"
    nocontain "$shellaccount"

    # cleanup: remove any marker (just in case) and both grants so the module leaves no state
    success rsync_injection_marker_cleanup_after $r0 rm -f "$marker"
    success rsync_injection_del_rsync_access $a0 --osh selfDelPersonalAccess --host 127.0.0.2 --protocol rsync --port 22
    json .command selfDelPersonalAccess .error_code OK
    success rsync_injection_del_ssh_access $a0 --osh selfDelPersonalAccess --host 127.0.0.2 --user $shellaccount --port 22
    json .command selfDelPersonalAccess .error_code OK
}

testsuite_rsync_injection
unset -f testsuite_rsync_injection
