# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2317,SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

# Regression test for command injection through the scp plugin, and for the non-breakage of
# legitimate "exotic" scp usage.
#
# osh.pl checks ssh access to the host (do_plugin_jit_mfa) BEFORE it runs the plugin at all, so an
# ssh grant on the exact host/user/port tuple we pass is a prerequisite here: without it we'd exit on
# KO_ACCESS_DENIED with a null .command and never reach the code under test. Mind also that omitting
# '--host' is not a way around it: the plugin would then just print its help and exit OK, which would
# make every case below pass vacuously.
# No scp-protocol grant is needed on top of that, as our checks run before has_protocol_access.

testsuite_scp_injection()
{
    # grant a0 the ssh access the plugin needs to be reached at all; --force skips the key-install
    # connectivity check, which we don't depend on here
    success scp_injection_add_ssh_access $a0 --osh selfAddPersonalAccess --host 127.0.0.2 --user $shellaccount --port 22 --force
    json .command selfAddPersonalAccess .error_code OK

    # --- injection attempts: must be rejected by the plugin's security filter ---

    # a ';' in the remote path would, unquoted, run a second command on the remote shell
    # (CVE-2020-15778 class); the path-scoped denylist must reject it
    run scp_inject_semicolon $a0 --osh scp --host 127.0.0.2 --user $shellaccount --port 22 --scp-cmd "scp#-t#/tmp/x\;#id"
    json .command scp .error_code ERR_SECURITY_VIOLATION
    contain "Invalid characters detected"

    # a server option outside the machine-generated set {-v -r -p -d} is a red flag: reject it
    run scp_inject_bad_option $a0 --osh scp --host 127.0.0.2 --user $shellaccount --port 22 --scp-cmd "scp#-X#-t#/tmp/x"
    json .command scp .error_code ERR_SECURITY_VIOLATION
    contain "Unrecognized scp server option"

    # a second mode option in the option segment is an attempt at mode confusion (we'd report one
    # way while the egress scp does the other): -t/-f are not in the allowlist, so reject
    run scp_inject_mode_confusion $a0 --osh scp --host 127.0.0.2 --user $shellaccount --port 22 --scp-cmd "scp#-t#-f#/etc/shadow"
    json .command scp .error_code ERR_SECURITY_VIOLATION
    contain "Unrecognized scp server option"

    # --- legitimate 'exotic' commands: must PASS the security filter (must NOT be wrongly rejected) ---
    # We hold ssh access but no scp-protocol grant, so these get past our filter and then stop on
    # has_protocol_access; the only thing we assert is that the filter did not reject them. A remote
    # glob '*' (expanded by the remote shell on download) and a space in the path are legitimate scp
    # usage that shell-quoting would break.

    run scp_legit_glob_download $a0 --osh scp --host 127.0.0.2 --user $shellaccount --port 22 --scp-cmd "scp#-f#/var/log/*.log"
    nocontain "ERR_SECURITY_VIOLATION"
    nocontain "Invalid characters detected"
    nocontain "command format unrecognized"

    run scp_legit_space_upload $a0 --osh scp --host 127.0.0.2 --user $shellaccount --port 22 --scp-cmd "scp#-t#/tmp/my#file"
    nocontain "ERR_SECURITY_VIOLATION"
    nocontain "Invalid characters detected"
    nocontain "command format unrecognized"

    # OpenSSH adds '--' itself when the remote path starts with a '-': don't reject that form.
    # A path segment holding option-looking words (here after the '--' scp sent) is likewise not a
    # filter matter: the '--' we reinsert when rebuilding the command keeps it a path on the egress side.
    run scp_legit_dash_path_upload $a0 --osh scp --host 127.0.0.2 --user $shellaccount --port 22 --scp-cmd "scp#-t#--#-dashy/path"
    nocontain "ERR_SECURITY_VIOLATION"
    nocontain "Invalid characters detected"
    nocontain "command format unrecognized"

    run scp_legit_dash_path_download $a0 --osh scp --host 127.0.0.2 --user $shellaccount --port 22 --scp-cmd "scp#-r#-f#--#-dashy#-fr"
    nocontain "ERR_SECURITY_VIOLATION"
    nocontain "Invalid characters detected"
    nocontain "command format unrecognized"

    # cleanup: drop the grant so the module leaves no state behind
    success scp_injection_del_ssh_access $a0 --osh selfDelPersonalAccess --host 127.0.0.2 --user $shellaccount --port 22
    json .command selfDelPersonalAccess .error_code OK
}

testsuite_scp_injection
unset -f testsuite_scp_injection
