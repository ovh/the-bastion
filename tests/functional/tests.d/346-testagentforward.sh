# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2317,SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_agent_forwarding()
{
    #create account1
    success accountCreate $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    # Add access to $remote_ip for $shellaccount
    success mustwork $a0 -osh selfAddPersonalAccess -h $remote_ip -u $shellaccount -p 22 --kbd-interactive
    nocontain "already"
    json .command selfAddPersonalAccess .error_code OK .value.user $shellaccount .value.port 22

    # Patch sshd to allow Agent Forwarding, else all other steps are useless to test
    success sshd_config_backup $r0 "\"cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.bak\""
    success sshd_config_patch $r0 "\"command -v freebsd-version >/dev/null && sed -I '' 's=^AllowAgentForwarding no=AllowAgentForwarding yes=' /etc/ssh/sshd_config || sed -i 's=^AllowAgentForwarding no=AllowAgentForwarding yes=' /etc/ssh/sshd_config\""
    # pkill doesn't work well under FreeBSD, so do it ourselves for all OSes
    success sshd_reload $r0 "\"ps -U 0 -o pid,command | grep -E '/usr/sbin/sshd\\\$|sshd:.+liste[n]er' | awk '{print \\\$1}' | xargs -r kill -SIGHUP\""
    # during tests, under some OSes it takes some time for sshd to accept new connections again after the SIGHUP
    [ "$COUNTONLY" != 1 ] && sleep 1

    # Test if ssh-agent is spawned without requesting it; it shouldn't
    run shellaccount_noagent $a0 $shellaccount@$remote_ip --kbd-interactive -- ssh-add -L
    retvalshouldbe 2
    contain REGEX "$shellaccount@[a-zA-Z0-9._-]+:22"
    contain "allowed ... log on"
    nocontain "Permission denied"
    contain "Could not open a connection to your authentication agent."

    # test if ssh-agent is spawned whilst requesting it but with the addkeystoagentallowed-config directive set to false
    run shellaccount_with_fwd_cfg_disallowed_noagent $a0 $shellaccount@$remote_ip --kbd-interactive -- ssh-add -L
    retvalshouldbe 2
    contain REGEX "$shellaccount@[a-zA-Z0-9._-]+:22"
    contain "allowed ... log on"
    nocontain "Permission denied"
    contain "Could not open a connection to your authentication agent."

    # test if ssh-agent is spawned whilst requesting it,  with the addkeystoagentallowed-config directive set to True
    # Change config
    configchg 's=^\\\\x22sshAddKeysToAgentAllowed\\\\x22.+=\\\\x22sshAddKeysToAgentAllowed\\\\x22:\\\\x20true='

    # Run test with --forward-agent; agent should spawn
    run shellaccount_with_fwd_cfg_longarg $a0 --forward-agent $shellaccount@$remote_ip -- ssh-add -L
    retvalshouldbe 0
    contain REGEX "$shellaccount@[a-zA-Z0-9._-]+:22"
    contain "allowed ... log on"
    nocontain "Permission denied"
    nocontain "Could not open a connection to your authentication agent."

    # Run test with -x; agent should spawn
    run shellaccount_with_fwd_cfg_shortarg $a0 -x $shellaccount@$remote_ip -- ssh-add -L
    retvalshouldbe 0
    contain REGEX "$shellaccount@[a-zA-Z0-9._-]+:22"
    contain "allowed ... log on"
    nocontain "Permission denied"
    nocontain "Could not open a connection to your authentication agent."

    # Patch sshd to allow Agent Forwarding, else all other steps are useless to test
    success sshd_config_backup $r0 "\"cp -a /etc/ssh/sshd_config.bak /etc/ssh/sshd_config\""
    # pkill doesn't work well under FreeBSD, so do it ourselves for all OSes
    success sshd_reload $r0 "\"ps -U 0 -o pid,command | grep -E '/usr/sbin/sshd\\\$|sshd:.+liste[n]er' | awk '{print \\\$1}' | xargs -r kill -SIGHUP\""

    # Remove access for our testaccount first...
    success removeaccess $a0 -osh selfDelPersonalAccess -h $remote_ip -u $shellaccount -p 22
    contain "Access to $shellaccount"
    json .command selfDelPersonalAccess .error_code OK .value.port 22

    # delete account1
    script cleanup $a0 --osh accountDelete --account $account1 "<<< \"Yes, do as I say and delete $account1, kthxbye\""
    retvalshouldbe 0
}

testsuite_agent_forwarding
unset -f testsuite_agent_forwarding
