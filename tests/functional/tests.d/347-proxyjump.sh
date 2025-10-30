# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2317,SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_proxyjump()
{
    # Create test accounts
    success a0_create_a1 $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command accountCreate

    success a0_create_a2 $a0 --osh accountCreate --always-active --account $account2 --uid $uid2 --public-key "\"$(cat $account2key1file.pub)\""
    json .error_code OK .command accountCreate

    # Create a test group
    success a0_create_group1 $a0 --osh groupCreate --group $group1 --owner $account1 --algo ed25519 --size 256
    json .error_code OK .command groupCreate

    #
    # Test selfAddPersonalAccess with proxy parameters
    #

    # Test basic proxy parameter
    success selfAddPersonalAccess_with_proxy_host $a0 --osh selfAddPersonalAccess --host 192.168.1.100 --user testuser --port 22 --proxy-host 10.0.0.1 --proxy-port 22 --force
    json .command selfAddPersonalAccess .error_code OK .value.ip 192.168.1.100 .value.user testuser .value.port 22 .value.proxyIp 10.0.0.1 .value.proxyPort 22

    # Test with hostname as proxy-host
    success selfAddPersonalAccess_with_proxy_hostname $a0 --osh selfAddPersonalAccess --host 192.168.1.102 --user testuser --port 22 --proxy-host localhost --proxy-port 22 --force
    json .command selfAddPersonalAccess .error_code OK .value.ip 192.168.1.102 .value.user testuser .value.port 22 .value.proxyIp 127.0.0.1

    # Test invalid proxy-host
    plgfail selfAddPersonalAccess_invalid_proxy_host $a0 --osh selfAddPersonalAccess --host 192.168.1.103 --user testuser --port 22 --proxy-host "invalid..host..name" --proxy-port 22 --force
    json .command selfAddPersonalAccess .error_code KO_INVALID_IP

    # Test proxy-port without proxy-host
    plgfail selfAddPersonalAccess_proxy_port_without_host $a0  --osh selfAddPersonalAccess --host 192.168.1.104 --user testuser --port 22 --proxy-port 2222 --force
    json .command selfAddPersonalAccess .error_code ERR_MISSING_PARAMETER

    # Test proxy-host without proxy-port
    plgfail selfAddPersonalAccess_proxy_host_without_port $a0 --osh selfAddPersonalAccess --host 192.168.1.107 --user testuser --port 22 --proxy-host 10.0.0.1 --force
    json .command selfAddPersonalAccess .error_code ERR_MISSING_PARAMETER

    # Test invalid proxy-port
    plgfail selfAddPersonalAccess_invalid_proxy_port $a0 --osh selfAddPersonalAccess --host 192.168.1.105 --user testuser --port 22 --proxy-host 10.0.0.1 --proxy-port abc --force
    json .command selfAddPersonalAccess .error_code ERR_INVALID_PARAMETER

    # Test invalid proxy-port (out of range)
    plgfail selfAddPersonalAccess_proxy_port_out_of_range $a0 --osh selfAddPersonalAccess --host 192.168.1.106 --user testuser --port 22 --proxy-host 10.0.0.1 --proxy-port 99999 --force
    json .command selfAddPersonalAccess .error_code ERR_INVALID_PARAMETER

    #
    # Test accountAddPersonalAccess with proxy parameters
    #

    # Test basic proxy-host parameter
    success accountAddPersonalAccess_with_proxy_host $a0 --osh accountAddPersonalAccess --account $account2 --host 192.168.2.100 --user testuser --port 22 --proxy-host 10.0.0.2 --proxy-port 22
    json .command accountAddPersonalAccess .error_code OK .value.ip 192.168.2.100 .value.user testuser .value.port 22 .value.proxyIp 10.0.0.2

    # Test with proxy hostname
    success accountAddPersonalAccess_with_proxy_port $a0 --osh accountAddPersonalAccess --account $account2 --host 192.168.2.101 --user testuser --port 22 --proxy-host localhost --proxy-port 3333
    json .command accountAddPersonalAccess .error_code OK .value.ip 192.168.2.101 .value.user testuser .value.port 22 .value.proxyIp 127.0.0.1 .value.proxyPort 3333

    # Test proxy-port without proxy-host
    plgfail accountAddPersonalAccess_proxy_port_without_host $a0 --osh accountAddPersonalAccess --account $account2 --host 192.168.2.102 --user testuser --port 22 --proxy-port 3333
    json .command accountAddPersonalAccess .error_code ERR_MISSING_PARAMETER

    # Test proxy-host without proxy-port
    plgfail accountAddPersonalAccess_proxy_host_without_port $a0 --osh accountAddPersonalAccess --account $account2 --host 192.168.2.102 --user testuser --port 22 --proxy-host 10.0.0.2
    json .command accountAddPersonalAccess .error_code ERR_MISSING_PARAMETER

    #
    # Test groupAddServer with proxy parameters
    #

    # Test basic proxy-host parameter
    success groupAddServer_with_proxy_host $a1 --osh groupAddServer --group $group1 --host 192.168.3.100 --user testuser --port 22 --proxy-host 10.0.0.3 --proxy-port 22 --force
    json .command groupAddServer .error_code OK .value.ip 192.168.3.100 .value.user testuser .value.port 22 .value.proxyIp 10.0.0.3 .value.proxyPort 22

    # Test with proxy hostname
    success groupAddServer_with_proxy_port $a1 --osh groupAddServer --group $group1 --host 192.168.3.101 --user testuser --port 22 --proxy-host localhost --proxy-port 4444 --force
    json .command groupAddServer .error_code OK .value.ip 192.168.3.101 .value.user testuser .value.port 22 .value.proxyIp 127.0.0.1 .value.proxyPort 4444

    # Test proxy-port without proxy-host
    plgfail groupAddServer_proxy_port_without_host $a1 --osh groupAddServer --group $group1 --host 192.168.3.102 --user testuser --port 22 --proxy-port 4444 --force
    json .command groupAddServer .error_code ERR_MISSING_PARAMETER

    # Test proxy-host without proxy-port
    plgfail groupAddServer_proxy_host_without_port $a1 --osh groupAddServer --group $group1 --host 192.168.3.102 --user testuser --port 22 --proxy-host 10.0.0.3 --force
    json .command groupAddServer .error_code ERR_MISSING_PARAMETER

    # Test invalid proxy-host
    plgfail groupAddServer_invalid_proxy_host $a1 --osh groupAddServer --group $group1 --host 192.168.3.103 --user testuser --port 22 --proxy-host "bad...hostname" --proxy-port 22 --force
    json .command groupAddServer .error_code KO_INVALID_IP

    #
    # Test deletion of accesses with proxy parameters
    #

    # Delete selfAddPersonalAccess entries with missing proxy-port
    plgfail selfDelPersonalAccess_without_proxy_port $a0 --osh selfDelPersonalAccess --host 192.168.1.100 --user testuser --port 22 --proxy-host 10.0.0.1
    json .command selfDelPersonalAccess .error_code ERR_MISSING_PARAMETER

    # Delete selfAddPersonalAccess entries with missing proxy-host
    plgfail selfDelPersonalAccess_without_proxy_host $a0 --osh selfDelPersonalAccess --host 192.168.1.100 --user testuser --port 22 --proxy-port 22
    json .command selfDelPersonalAccess .error_code ERR_MISSING_PARAMETER

    # Delete selfAddPersonalAccess entries
    success selfDelPersonalAccess_with_proxy $a0 --osh selfDelPersonalAccess --host 192.168.1.100 --user testuser --port 22 --proxy-host 10.0.0.1 --proxy-port 22
    json .command selfDelPersonalAccess .error_code OK

    success selfDelPersonalAccess_with_proxy_hostname $a0 --osh selfDelPersonalAccess --host 192.168.1.102 --user testuser --port 22 --proxy-host localhost --proxy-port 22
    json .command selfDelPersonalAccess .error_code OK

    # Delete accountAddPersonalAccess entries with missing proxy-port
    plgfail accountDelPersonalAccess_without_proxy_port $a0 --osh accountDelPersonalAccess --account $account2 --host 192.168.2.100 --user testuser --port 22 --proxy-host 10.0.0.2
    json .command accountDelPersonalAccess .error_code ERR_MISSING_PARAMETER

    # Delete accountAddPersonalAccess entries with missing proxy-host
    plgfail accountDelPersonalAccess_without_proxy_host $a0 --osh accountDelPersonalAccess --account $account2 --host 192.168.2.100 --user testuser --port 22 --proxy-port 22
    json .command accountDelPersonalAccess .error_code ERR_MISSING_PARAMETER

    # Delete accountAddPersonalAccess entries
    success accountDelPersonalAccess_with_proxy $a0 --osh accountDelPersonalAccess --account $account2 --host 192.168.2.100 --user testuser --port 22 --proxy-host 10.0.0.2 --proxy-port 22
    json .command accountDelPersonalAccess .error_code OK

    success accountDelPersonalAccess_with_proxy_hostname $a0 --osh accountDelPersonalAccess --account $account2 --host 192.168.2.101 --user testuser --port 22 --proxy-host localhost --proxy-port 3333
    json .command accountDelPersonalAccess .error_code OK

    # Delete groupAddServer entries with missing proxy-port
    plgfail groupDelServer_without_proxy_port $a1 --osh groupDelServer --group $group1 --host 192.168.3.100 --user testuser --port 22 --proxy-host 10.0.0.3
    json .command groupDelServer .error_code ERR_MISSING_PARAMETER

    # Delete groupAddServer entries with missing proxy-host
    plgfail groupDelServer_without_proxy_host $a1 --osh groupDelServer --group $group1 --host 192.168.3.100 --user testuser --port 22 --proxy-port 22
    json .command groupDelServer .error_code ERR_MISSING_PARAMETER

    # Delete groupAddServer entries
    success groupDelServer_with_proxy $a1 --osh groupDelServer --group $group1 --host 192.168.3.100 --user testuser --port 22 --proxy-host 10.0.0.3 --proxy-port 22
    json .command groupDelServer .error_code OK

    success groupDelServer_with_proxy_hostname $a1 --osh groupDelServer --group $group1 --host 192.168.3.101 --user testuser --port 22 --proxy-host localhost --proxy-port 4444 
    json .command groupDelServer .error_code OK

    #
    # Test that proxy information is displayed in access lists
    #

    # Add self access with proxy
    success add_access_for_list_check $a0 --osh selfAddPersonalAccess --host 192.168.1.200 --user listtest --port 2222 --proxy-host 10.0.0.5 --proxy-port 5555 --force
    json .command selfAddPersonalAccess .error_code OK

    # Check that selfListAccesses shows the proxy information
    success selfListAccesses_shows_proxy $a0 --osh selfListAccesses
    json .command selfListAccesses .error_code OK
    contain '"ip":"192.168.1.200"'
    contain '"port":"2222"'
    contain '"user":"listtest"'
    contain '"proxyIp":"10.0.0.5"'
    contain '"proxyPort":"5555"'

    # Clean up
    success cleanup_list_test $a0 --osh selfDelPersonalAccess --host 192.168.1.200 --user listtest --port 2222 --proxy-host 10.0.0.5 --proxy-port 5555
    json .command selfDelPersonalAccess .error_code OK

    # Add account access with proxy
    success add_account_access_for_list_check $a0 --osh accountAddPersonalAccess --account $account2 --host 192.168.2.100 --user testuser --port 22 --proxy-host 10.0.0.2 --proxy-port 22
    json .command accountAddPersonalAccess .error_code OK

    # Check that accountListAccesses shows the proxy information
    success accountListAccesses_shows_proxy $a0 --osh accountListAccesses --account $account2
    json .command accountListAccesses .error_code OK
    contain '"ip":"192.168.2.100"'
    contain '"port":"22"'
    contain '"user":"testuser"'
    contain '"proxyIp":"10.0.0.2"'
    contain '"proxyPort":"22"'

    # Clean up
    success cleanup_account_list_test $a0 --osh accountDelPersonalAccess --account $account2 --host 192.168.2.100 --user testuser --port 22 --proxy-host 10.0.0.2 --proxy-port 22
    json .command accountDelPersonalAccess .error_code OK

    # Add group server with proxy
    success add_group_server_for_list_check $a1 --osh groupAddServer --group $group1 --host 192.168.3.100 --user testuser --port 22 --proxy-host 10.0.0.3 --proxy-port 22 --force
    json .command groupAddServer .error_code OK

    # Check that groupListServers shows the proxy information
    success groupListServers_shows_proxy $a1 --osh groupListServers --group $group1
    json .command groupListServers .error_code OK
    contain '"ip":"192.168.3.100"'
    contain '"port":"22"'
    contain '"user":"testuser"'
    contain '"proxyIp":"10.0.0.3"'
    contain '"proxyPort":"22"'

    # Clean up
    success cleanup_group_list_test $a1 --osh groupDelServer --group $group1 --host 192.168.3.100 --user testuser --port 22 --proxy-host 10.0.0.3 --proxy-port 22
    json .command groupDelServer .error_code OK

    success a0_delete_group1 $a0 --osh groupDelete --group $group1 --no-confirm
    json .error_code OK .command groupDelete

    success a0_delete_a1 $a0 --osh accountDelete --account $account1 --no-confirm
    json .error_code OK .command accountDelete

    success a0_delete_a2 $a0 --osh accountDelete --account $account2 --no-confirm
    json .error_code OK .command accountDelete
}

testsuite_proxyjump
unset -f testsuite_proxyjump
