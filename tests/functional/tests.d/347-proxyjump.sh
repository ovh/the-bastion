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

    # Test that proxy parameters are rejected while the feature is disabled
    run selfAddPersonalAccess_proxy_feature_disabled $a0 --osh selfAddPersonalAccess --host 192.168.1.100 --user testuser --port 22 --proxy-host 10.0.0.1 --proxy-port 22 --proxy-user testuser --force
    retvalshouldbe 100
    contain "ProxyJump egress connections are disabled by policy"
    json .error_code ERR_INVALID_PARAMETER

    # now enable the proxyjump feature
    configchg 's=^\\\\x22egressProxyJumpAllowed\\\\x22.+=\\\\x22egressProxyJumpAllowed\\\\x22:true,='

    #
    # Test selfAddPersonalAccess with proxy parameters
    #

    # Test basic proxy parameter
    success selfAddPersonalAccess_with_proxy_host $a0 --osh selfAddPersonalAccess --host 192.168.1.100 --user testuser --port 22 --proxy-host 10.0.0.1 --proxy-port 22 --proxy-user testuser --force
    json .command selfAddPersonalAccess .error_code OK .value.ip 192.168.1.100 .value.user testuser .value.port 22 .value.proxyIp 10.0.0.1 .value.proxyPort 22

    # Test with hostname as proxy-host
    success selfAddPersonalAccess_with_proxy_hostname $a0 --osh selfAddPersonalAccess --host 192.168.1.102 --user testuser --port 22 --proxy-host localhost --proxy-port 22 --proxy-user testuser --force
    json .command selfAddPersonalAccess .error_code OK .value.ip 192.168.1.102 .value.user testuser .value.port 22 .value.proxyIp 127.0.0.1

    # Test invalid proxy-host
    plgfail selfAddPersonalAccess_invalid_proxy_host $a0 --osh selfAddPersonalAccess --host 192.168.1.103 --user testuser --port 22 --proxy-host "invalid..host..name" --proxy-port 22 --proxy-user testuser --force
    json .command selfAddPersonalAccess .error_code KO_INVALID_IP

    # Test proxy-port without proxy-host
    plgfail selfAddPersonalAccess_proxy_port_without_host $a0  --osh selfAddPersonalAccess --host 192.168.1.104 --user testuser --port 22 --proxy-port 2222 --force
    json .command selfAddPersonalAccess .error_code ERR_MISSING_PARAMETER

    # Test proxy-host without proxy-port
    plgfail selfAddPersonalAccess_proxy_host_without_port $a0 --osh selfAddPersonalAccess --host 192.168.1.107 --user testuser --port 22 --proxy-host 10.0.0.1 --proxy-user testuser --force
    json .command selfAddPersonalAccess .error_code ERR_MISSING_PARAMETER

    # Test invalid proxy-port
    plgfail selfAddPersonalAccess_invalid_proxy_port $a0 --osh selfAddPersonalAccess --host 192.168.1.105 --user testuser --port 22 --proxy-host 10.0.0.1 --proxy-port abc --proxy-user testuser --force
    json .command selfAddPersonalAccess .error_code ERR_INVALID_PARAMETER

    # Test invalid proxy-port (out of range)
    plgfail selfAddPersonalAccess_proxy_port_out_of_range $a0 --osh selfAddPersonalAccess --host 192.168.1.106 --user testuser --port 22 --proxy-host 10.0.0.1 --proxy-port 99999 --proxy-user testuser --force
    json .command selfAddPersonalAccess .error_code ERR_INVALID_PARAMETER

    # Test proxy-host and proxy-port without proxy-user (should fail)
    plgfail selfAddPersonalAccess_proxy_without_user $a0 --osh selfAddPersonalAccess --host 192.168.1.108 --user testuser --port 22 --proxy-host 10.0.0.1 --proxy-port 22 --force
    json .command selfAddPersonalAccess .error_code ERR_MISSING_PARAMETER
    contain "When --proxy-host is specified, --proxy-user becomes mandatory"

    #
    # Test selfAddPersonalAccess with proxy-user parameter
    #

    # Test basic proxy-user parameter
    success selfAddPersonalAccess_with_proxy_user $a0 --osh selfAddPersonalAccess --host 192.168.1.110 --user testuser --port 22 --proxy-host 10.0.0.1 --proxy-port 22 --proxy-user proxyuser --force
    json .command selfAddPersonalAccess .error_code OK .value.ip 192.168.1.110 .value.user testuser .value.port 22 .value.proxyIp 10.0.0.1 .value.proxyPort 22 .value.proxyUser proxyuser

    # Test proxy-user wildcard
    success selfAddPersonalAccess_with_proxy_user_wildcard $a0 --osh selfAddPersonalAccess --host 192.168.1.111 --user testuser --port 22 --proxy-host 10.0.0.1 --proxy-port 22 --proxy-user '*' --force
    json .command selfAddPersonalAccess .error_code OK .value.ip 192.168.1.111 .value.user testuser .value.port 22 .value.proxyIp 10.0.0.1 .value.proxyPort 22

    # Test invalid proxy-user
    plgfail selfAddPersonalAccess_invalid_proxy_user $a0 --osh selfAddPersonalAccess --host 192.168.1.112 --user testuser --port 22 --proxy-host 10.0.0.1 --proxy-port 22 --proxy-user "inväliduse{r" --force
    json .command selfAddPersonalAccess .error_code ERR_INVALID_PARAMETER

    # Clean up proxy-user test entries
    success selfDelPersonalAccess_with_proxy_user $a0 --osh selfDelPersonalAccess --host 192.168.1.110 --user testuser --port 22 --proxy-host 10.0.0.1 --proxy-port 22 --proxy-user proxyuser
    json .command selfDelPersonalAccess .error_code OK

    success selfDelPersonalAccess_with_proxy_user_wildcard $a0 --osh selfDelPersonalAccess --host 192.168.1.111 --user testuser --port 22 --proxy-host 10.0.0.1 --proxy-port 22 --proxy-user '*'
    json .command selfDelPersonalAccess .error_code OK

    #
    # Test accountAddPersonalAccess with proxy parameters
    #

    # Test basic proxy-host parameter
    success accountAddPersonalAccess_with_proxy_host $a0 --osh accountAddPersonalAccess --account $account2 --host 192.168.2.100 --user testuser --port 22 --proxy-host 10.0.0.2 --proxy-port 22 --proxy-user testuser
    json .command accountAddPersonalAccess .error_code OK .value.ip 192.168.2.100 .value.user testuser .value.port 22 .value.proxyIp 10.0.0.2

    # Test with proxy hostname
    success accountAddPersonalAccess_with_proxy_port $a0 --osh accountAddPersonalAccess --account $account2 --host 192.168.2.101 --user testuser --port 22 --proxy-host localhost --proxy-port 3333 --proxy-user testuser
    json .command accountAddPersonalAccess .error_code OK .value.ip 192.168.2.101 .value.user testuser .value.port 22 .value.proxyIp 127.0.0.1 .value.proxyPort 3333

    # Test proxy-port without proxy-host
    plgfail accountAddPersonalAccess_proxy_port_without_host $a0 --osh accountAddPersonalAccess --account $account2 --host 192.168.2.102 --user testuser --port 22 --proxy-port 3333
    json .command accountAddPersonalAccess .error_code ERR_MISSING_PARAMETER

    # Test proxy-host without proxy-port
    plgfail accountAddPersonalAccess_proxy_host_without_port $a0 --osh accountAddPersonalAccess --account $account2 --host 192.168.2.102 --user testuser --port 22 --proxy-host 10.0.0.2 --proxy-user testuser
    json .command accountAddPersonalAccess .error_code ERR_MISSING_PARAMETER

    # Test proxy-host and proxy-port without proxy-user (should fail)
    plgfail accountAddPersonalAccess_proxy_without_user $a0 --osh accountAddPersonalAccess --account $account2 --host 192.168.2.103 --user testuser --port 22 --proxy-host 10.0.0.2 --proxy-port 22
    json .command accountAddPersonalAccess .error_code ERR_MISSING_PARAMETER
    contain "When --proxy-host is specified, --proxy-user becomes mandatory"

    #
    # Test accountAddPersonalAccess with proxy-user parameter
    #

    # Test basic proxy-user parameter
    success accountAddPersonalAccess_with_proxy_user $a0 --osh accountAddPersonalAccess --account $account2 --host 192.168.2.110 --user testuser --port 22 --proxy-host 10.0.0.2 --proxy-port 22 --proxy-user proxyuser
    json .command accountAddPersonalAccess .error_code OK .value.ip 192.168.2.110 .value.user testuser .value.port 22 .value.proxyIp 10.0.0.2 .value.proxyPort 22 .value.proxyUser proxyuser

    # Test proxy-user wildcard
    success accountAddPersonalAccess_with_proxy_user_wildcard $a0 --osh accountAddPersonalAccess --account $account2 --host 192.168.2.111 --user testuser --port 22 --proxy-host 10.0.0.2 --proxy-port 22 --proxy-user '*'
    json .command accountAddPersonalAccess .error_code OK .value.ip 192.168.2.111 .value.user testuser .value.port 22 .value.proxyIp 10.0.0.2 .value.proxyPort 22

    # Clean up proxy-user test entries
    success accountDelPersonalAccess_with_proxy_user $a0 --osh accountDelPersonalAccess --account $account2 --host 192.168.2.110 --user testuser --port 22 --proxy-host 10.0.0.2 --proxy-port 22 --proxy-user proxyuser
    json .command accountDelPersonalAccess .error_code OK

    success accountDelPersonalAccess_with_proxy_user_wildcard $a0 --osh accountDelPersonalAccess --account $account2 --host 192.168.2.111 --user testuser --port 22 --proxy-host 10.0.0.2 --proxy-port 22 --proxy-user '*'
    json .command accountDelPersonalAccess .error_code OK

    #
    # Test groupAddServer with proxy parameters
    #

    # Test basic proxy-host parameter
    success groupAddServer_with_proxy_host $a1 --osh groupAddServer --group $group1 --host 192.168.3.100 --user testuser --port 22 --proxy-host 10.0.0.3 --proxy-port 22 --proxy-user testuser --force
    json .command groupAddServer .error_code OK .value.ip 192.168.3.100 .value.user testuser .value.port 22 .value.proxyIp 10.0.0.3 .value.proxyPort 22

    # Test with proxy hostname
    success groupAddServer_with_proxy_port $a1 --osh groupAddServer --group $group1 --host 192.168.3.101 --user testuser --port 22 --proxy-host localhost --proxy-port 4444 --proxy-user testuser --force
    json .command groupAddServer .error_code OK .value.ip 192.168.3.101 .value.user testuser .value.port 22 .value.proxyIp 127.0.0.1 .value.proxyPort 4444

    # Test proxy-port without proxy-host
    plgfail groupAddServer_proxy_port_without_host $a1 --osh groupAddServer --group $group1 --host 192.168.3.102 --user testuser --port 22 --proxy-port 4444 --force
    json .command groupAddServer .error_code ERR_MISSING_PARAMETER

    # Test proxy-host without proxy-port
    plgfail groupAddServer_proxy_host_without_port $a1 --osh groupAddServer --group $group1 --host 192.168.3.102 --user testuser --port 22 --proxy-host 10.0.0.3 --proxy-user testuser --force
    json .command groupAddServer .error_code ERR_MISSING_PARAMETER

    # Test invalid proxy-host
    plgfail groupAddServer_invalid_proxy_host $a1 --osh groupAddServer --group $group1 --host 192.168.3.103 --user testuser --port 22 --proxy-host "bad...hostname" --proxy-port 22 --proxy-user testuser --force
    json .command groupAddServer .error_code KO_INVALID_IP

    # Test proxy-host and proxy-port without proxy-user (should fail)
    plgfail groupAddServer_proxy_without_user $a1 --osh groupAddServer --group $group1 --host 192.168.3.104 --user testuser --port 22 --proxy-host 10.0.0.3 --proxy-port 22 --force
    json .command groupAddServer .error_code ERR_MISSING_PARAMETER
    contain "When --proxy-host is specified, --proxy-user becomes mandatory"

    #
    # Test groupAddServer with proxy-user parameter
    #

    # Test basic proxy-user parameter
    success groupAddServer_with_proxy_user $a1 --osh groupAddServer --group $group1 --host 192.168.3.110 --user testuser --port 22 --proxy-host 10.0.0.3 --proxy-port 22 --proxy-user proxyuser --force
    json .command groupAddServer .error_code OK .value.ip 192.168.3.110 .value.user testuser .value.port 22 .value.proxyIp 10.0.0.3 .value.proxyPort 22 .value.proxyUser proxyuser

    # Test proxy-user wildcard
    success groupAddServer_with_proxy_user_wildcard $a1 --osh groupAddServer --group $group1 --host 192.168.3.111 --user testuser --port 22 --proxy-host 10.0.0.3 --proxy-port 22 --proxy-user '*' --force
    json .command groupAddServer .error_code OK .value.ip 192.168.3.111 .value.user testuser .value.port 22 .value.proxyIp 10.0.0.3 .value.proxyPort 22

    # Clean up proxy-user test entries
    success groupDelServer_with_proxy_user $a1 --osh groupDelServer --group $group1 --host 192.168.3.110 --user testuser --port 22 --proxy-host 10.0.0.3 --proxy-port 22 --proxy-user proxyuser
    json .command groupDelServer .error_code OK

    success groupDelServer_with_proxy_user_wildcard $a1 --osh groupDelServer --group $group1 --host 192.168.3.111 --user testuser --port 22 --proxy-host 10.0.0.3 --proxy-port 22 --proxy-user '*'
    json .command groupDelServer .error_code OK

    #
    # Test deletion of accesses with proxy parameters
    #

    # Delete selfAddPersonalAccess entries with missing proxy-port
    plgfail selfDelPersonalAccess_without_proxy_port $a0 --osh selfDelPersonalAccess --host 192.168.1.100 --user testuser --port 22 --proxy-host 10.0.0.1 --proxy-user testuser
    json .command selfDelPersonalAccess .error_code ERR_MISSING_PARAMETER

    # Delete selfAddPersonalAccess entries with missing proxy-host
    plgfail selfDelPersonalAccess_without_proxy_host $a0 --osh selfDelPersonalAccess --host 192.168.1.100 --user testuser --port 22 --proxy-port 22
    json .command selfDelPersonalAccess .error_code ERR_MISSING_PARAMETER

    # Delete selfAddPersonalAccess entries with missing proxy-user
    plgfail selfDelPersonalAccess_without_proxy_user $a0 --osh selfDelPersonalAccess --host 192.168.1.100 --user testuser --port 22 --proxy-host 10.0.0.1 --proxy-port 22
    json .command selfDelPersonalAccess .error_code ERR_MISSING_PARAMETER
    contain "When --proxy-host is specified, --proxy-user becomes mandatory"

    # Delete selfAddPersonalAccess entries
    success selfDelPersonalAccess_with_proxy $a0 --osh selfDelPersonalAccess --host 192.168.1.100 --user testuser --port 22 --proxy-host 10.0.0.1 --proxy-port 22 --proxy-user testuser
    json .command selfDelPersonalAccess .error_code OK

    success selfDelPersonalAccess_with_proxy_hostname $a0 --osh selfDelPersonalAccess --host 192.168.1.102 --user testuser --port 22 --proxy-host localhost --proxy-port 22 --proxy-user testuser
    json .command selfDelPersonalAccess .error_code OK

    # Delete accountAddPersonalAccess entries with missing proxy-port
    plgfail accountDelPersonalAccess_without_proxy_port $a0 --osh accountDelPersonalAccess --account $account2 --host 192.168.2.100 --user testuser --port 22 --proxy-host 10.0.0.2 --proxy-user testuser
    json .command accountDelPersonalAccess .error_code ERR_MISSING_PARAMETER

    # Delete accountAddPersonalAccess entries with missing proxy-host
    plgfail accountDelPersonalAccess_without_proxy_host $a0 --osh accountDelPersonalAccess --account $account2 --host 192.168.2.100 --user testuser --port 22 --proxy-port 22
    json .command accountDelPersonalAccess .error_code ERR_MISSING_PARAMETER

    # Delete accountAddPersonalAccess entries with missing proxy-user
    plgfail accountDelPersonalAccess_without_proxy_user $a0 --osh accountDelPersonalAccess --account $account2 --host 192.168.2.100 --user testuser --port 22 --proxy-host 10.0.0.2 --proxy-port 22
    json .command accountDelPersonalAccess .error_code ERR_MISSING_PARAMETER
    contain "When --proxy-host is specified, --proxy-user becomes mandatory"

    # Delete accountAddPersonalAccess entries
    success accountDelPersonalAccess_with_proxy $a0 --osh accountDelPersonalAccess --account $account2 --host 192.168.2.100 --user testuser --port 22 --proxy-host 10.0.0.2 --proxy-port 22 --proxy-user testuser
    json .command accountDelPersonalAccess .error_code OK

    success accountDelPersonalAccess_with_proxy_hostname $a0 --osh accountDelPersonalAccess --account $account2 --host 192.168.2.101 --user testuser --port 22 --proxy-host localhost --proxy-port 3333 --proxy-user testuser
    json .command accountDelPersonalAccess .error_code OK

    # Delete groupAddServer entries with missing proxy-port
    plgfail groupDelServer_without_proxy_port $a1 --osh groupDelServer --group $group1 --host 192.168.3.100 --user testuser --port 22 --proxy-host 10.0.0.3 --proxy-user testuser
    json .command groupDelServer .error_code ERR_MISSING_PARAMETER

    # Delete groupAddServer entries with missing proxy-host
    plgfail groupDelServer_without_proxy_host $a1 --osh groupDelServer --group $group1 --host 192.168.3.100 --user testuser --port 22 --proxy-port 22
    json .command groupDelServer .error_code ERR_MISSING_PARAMETER

    # Delete groupAddServer entries with missing proxy-user
    plgfail groupDelServer_without_proxy_user $a1 --osh groupDelServer --group $group1 --host 192.168.3.100 --user testuser --port 22 --proxy-host 10.0.0.3 --proxy-port 22
    json .command groupDelServer .error_code ERR_MISSING_PARAMETER
    contain "When --proxy-host is specified, --proxy-user becomes mandatory"

    # Delete groupAddServer entries
    success groupDelServer_with_proxy $a1 --osh groupDelServer --group $group1 --host 192.168.3.100 --user testuser --port 22 --proxy-host 10.0.0.3 --proxy-port 22 --proxy-user testuser
    json .command groupDelServer .error_code OK

    success groupDelServer_with_proxy_hostname $a1 --osh groupDelServer --group $group1 --host 192.168.3.101 --user testuser --port 22 --proxy-host localhost --proxy-port 4444 --proxy-user testuser
    json .command groupDelServer .error_code OK

    #
    # Test that proxy information is displayed in access lists
    #

    # Add self access with proxy
    success add_access_for_list_check $a0 --osh selfAddPersonalAccess --host 192.168.1.200 --user listtest --port 2222 --proxy-host 10.0.0.5 --proxy-port 5555 --proxy-user listtest --force
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
    success cleanup_list_test $a0 --osh selfDelPersonalAccess --host 192.168.1.200 --user listtest --port 2222 --proxy-host 10.0.0.5 --proxy-port 5555 --proxy-user listtest
    json .command selfDelPersonalAccess .error_code OK    # Add self access with proxy and proxy-user
    success add_access_with_proxy_user_for_list_check $a0 --osh selfAddPersonalAccess --host 192.168.1.201 --user listtest --port 2222 --proxy-host 10.0.0.5 --proxy-port 5555 --proxy-user proxyuser --force
    json .command selfAddPersonalAccess .error_code OK

    # Check that selfListAccesses shows the proxy-user information
    success selfListAccesses_shows_proxy_user $a0 --osh selfListAccesses
    json .command selfListAccesses .error_code OK
    json .value[0].ip 192.168.1.201
    contain '"port":"2222"'
    contain '"user":"listtest"'
    contain '"proxyIp":"10.0.0.5"'
    contain '"proxyPort":"5555"'
    contain '"proxyUser":"proxyuser"'

    # Clean up
    success cleanup_list_test_with_proxy_user $a0 --osh selfDelPersonalAccess --host 192.168.1.201 --user listtest --port 2222 --proxy-host 10.0.0.5 --proxy-port 5555 --proxy-user proxyuser
    json .command selfDelPersonalAccess .error_code OK

    # Add account access with proxy
    success add_account_access_for_list_check $a0 --osh accountAddPersonalAccess --account $account2 --host 192.168.2.100 --user testuser --port 22 --proxy-host 10.0.0.2 --proxy-port 22 --proxy-user testuser
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
    success cleanup_account_list_test $a0 --osh accountDelPersonalAccess --account $account2 --host 192.168.2.100 --user testuser --port 22 --proxy-host 10.0.0.2 --proxy-port 22 --proxy-user testuser
    json .command accountDelPersonalAccess .error_code OK

    # Add account access with proxy and proxy-user
    success add_account_access_with_proxy_user_for_list_check $a0 --osh accountAddPersonalAccess --account $account2 --host 192.168.2.200 --user testuser --port 22 --proxy-host 10.0.0.2 --proxy-port 22 --proxy-user proxyuser
    json .command accountAddPersonalAccess .error_code OK

    # Check that accountListAccesses shows the proxy-user information
    success accountListAccesses_shows_proxy_user $a0 --osh accountListAccesses --account $account2
    json .command accountListAccesses .error_code OK
    contain '"ip":"192.168.2.200"'
    contain '"port":"22"'
    contain '"user":"testuser"'
    contain '"proxyIp":"10.0.0.2"'
    contain '"proxyPort":"22"'
    contain '"proxyUser":"proxyuser"'

    # Clean up
    success cleanup_account_list_test_with_proxy_user $a0 --osh accountDelPersonalAccess --account $account2 --host 192.168.2.200 --user testuser --port 22 --proxy-host 10.0.0.2 --proxy-port 22 --proxy-user proxyuser
    json .command accountDelPersonalAccess .error_code OK

    # Add group server with proxy
    success add_group_server_for_list_check $a1 --osh groupAddServer --group $group1 --host 192.168.3.100 --user testuser --port 22 --proxy-host 10.0.0.3 --proxy-port 22 --proxy-user testuser --force
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
    success cleanup_group_list_test $a1 --osh groupDelServer --group $group1 --host 192.168.3.100 --user testuser --port 22 --proxy-host 10.0.0.3 --proxy-port 22 --proxy-user testuser
    json .command groupDelServer .error_code OK

    # Add group server with proxy and proxy-user
    success add_group_server_with_proxy_user_for_list_check $a1 --osh groupAddServer --group $group1 --host 192.168.3.200 --user testuser --port 22 --proxy-host 10.0.0.3 --proxy-port 22 --proxy-user proxyuser --force
    json .command groupAddServer .error_code OK

    # Check that groupListServers shows the proxy-user information
    success groupListServers_shows_proxy_user $a1 --osh groupListServers --group $group1
    json .command groupListServers .error_code OK
    contain '"ip":"192.168.3.200"'
    contain '"port":"22"'
    contain '"user":"testuser"'
    contain '"proxyIp":"10.0.0.3"'
    contain '"proxyPort":"22"'
    contain '"proxyUser":"proxyuser"'

    # Clean up
    success cleanup_group_list_test_with_proxy_user $a1 --osh groupDelServer --group $group1 --host 192.168.3.200 --user testuser --port 22 --proxy-host 10.0.0.3 --proxy-port 22 --proxy-user proxyuser
    json .command groupDelServer .error_code OK

    #
    # Test groupAddGuestAccess with proxy parameters
    #

    # Add a server to the group first so we can test guest access
    success a1_add_server_to_g1 $a1 --osh groupAddServer --group $group1 --host 192.168.4.100 --user testuser --port 22 --proxy-host 10.0.0.4 --proxy-port 22 --proxy-user testuser --force
    json .command groupAddServer .error_code OK

    # Test basic proxy parameter with groupAddGuestAccess
    success groupAddGuestAccess_with_proxy_host $a1 --osh groupAddGuestAccess --group $group1 --account $account2 --host 192.168.4.100 --user testuser --port 22 --proxy-host 10.0.0.4 --proxy-port 22 --proxy-user testuser
    json .command groupAddGuestAccess .error_code OK

    # Test with hostname as proxy-host
    success a1_add_server_with_proxy_hostname $a1 --osh groupAddServer --group $group1 --host 192.168.4.101 --user testuser --port 22 --proxy-host localhost --proxy-port 2222 --proxy-user testuser --force
    json .command groupAddServer .error_code OK

    success groupAddGuestAccess_with_proxy_hostname $a1 --osh groupAddGuestAccess --group $group1 --account $account2 --host 192.168.4.101 --user testuser --port 22 --proxy-host localhost --proxy-port 2222 --proxy-user testuser
    json .command groupAddGuestAccess .error_code OK 

    # Test proxy-port without proxy-host
    plgfail groupAddGuestAccess_proxy_port_without_host $a1 --osh groupAddGuestAccess --group $group1 --account $account2 --host 192.168.4.102 --user testuser --port 22 --proxy-port 2222
    json .command groupAddGuestAccess .error_code ERR_MISSING_PARAMETER

    # Test proxy-host without proxy-port
    plgfail groupAddGuestAccess_proxy_host_without_port $a1 --osh groupAddGuestAccess --group $group1 --account $account2 --host 192.168.4.103 --user testuser --port 22 --proxy-host 10.0.0.4 --proxy-user testuser
    json .command groupAddGuestAccess .error_code ERR_MISSING_PARAMETER

    # Test proxy-host and proxy-port without proxy-user
    plgfail groupAddGuestAccess_proxy_without_user $a1 --osh groupAddGuestAccess --group $group1 --account $account2 --host 192.168.4.104 --user testuser --port 22 --proxy-host 10.0.0.4 --proxy-port 22
    json .command groupAddGuestAccess .error_code ERR_MISSING_PARAMETER

    # Test invalid proxy-host
    plgfail groupAddGuestAccess_invalid_proxy_host $a1 --osh groupAddGuestAccess --group $group1 --account $account2 --host 192.168.4.105 --user testuser --port 22 --proxy-host "badhostnäim" --proxy-port 22 --proxy-user testuser
    json .command groupAddGuestAccess .error_code ERR_INVALID_PARAMETER

    # Test guest access that requires group to have access to proxy params
    success a1_add_server_no_proxy $a1 --osh groupAddServer --group $group1 --host 192.168.4.110 --user testuser --port 22 --force
    json .command groupAddServer .error_code OK

    plgfail groupAddGuestAccess_group_no_access_to_proxy $a1 --osh groupAddGuestAccess --group $group1 --account $account2 --host 192.168.4.110 --user testuser --port 22 --proxy-host 10.0.0.4 --proxy-port 22 --proxy-user testuser
    json .command groupAddGuestAccess .error_code ERR_GROUP_HAS_NO_ACCESS

    #
    # Test groupDelGuestAccess with proxy parameters
    #

    # Delete with missing proxy-port
    plgfail groupDelGuestAccess_without_proxy_port $a1 --osh groupDelGuestAccess --group $group1 --account $account2 --host 192.168.4.100 --user testuser --port 22 --proxy-host 10.0.0.4 --proxy-user testuser
    json .command groupDelGuestAccess .error_code ERR_MISSING_PARAMETER

    # Delete with missing proxy-host
    plgfail groupDelGuestAccess_without_proxy_host $a1 --osh groupDelGuestAccess --group $group1 --account $account2 --host 192.168.4.100 --user testuser --port 22 --proxy-port 22
    json .command groupDelGuestAccess .error_code ERR_MISSING_PARAMETER

    # Delete with missing proxy-user
    plgfail groupDelGuestAccess_without_proxy_user $a1 --osh groupDelGuestAccess --group $group1 --account $account2 --host 192.168.4.100 --user testuser --port 22 --proxy-host 10.0.0.4 --proxy-port 22
    json .command groupDelGuestAccess .error_code ERR_MISSING_PARAMETER
    contain "When --proxy-host is specified, --proxy-user becomes mandatory"

    # Delete guest access with proxy
    success groupDelGuestAccess_with_proxy $a1 --osh groupDelGuestAccess --group $group1 --account $account2 --host 192.168.4.100 --user testuser --port 22 --proxy-host 10.0.0.4 --proxy-port 22 --proxy-user testuser
    json .command groupDelGuestAccess .error_code OK

    success groupDelGuestAccess_with_proxy_hostname $a1 --osh groupDelGuestAccess --group $group1 --account $account2 --host 192.168.4.101 --user testuser --port 22 --proxy-host localhost --proxy-port 2222 --proxy-user testuser
    json .command groupDelGuestAccess .error_code OK

    #
    # Test that proxy information is displayed in groupListGuestAccesses
    #

    # Add guest access with proxy for list check
    success a1_add_server_for_guest_list_check $a1 --osh groupAddServer --group $group1 --host 192.168.4.200 --user listtest --port 2222 --proxy-host 10.0.0.6 --proxy-port 6666 --proxy-user listtest --force
    json .command groupAddServer .error_code OK

    success add_guest_access_for_list_check $a1 --osh groupAddGuestAccess --group $group1 --account $account2 --host 192.168.4.200 --user listtest --port 2222 --proxy-host 10.0.0.6 --proxy-port 6666 --proxy-user listtest
    json .command groupAddGuestAccess .error_code OK

    # Check that groupListGuestAccesses shows the proxy information
    success groupListGuestAccesses_shows_proxy $a1 --osh groupListGuestAccesses --group $group1 --account $account2
    json .command groupListGuestAccesses .error_code OK .value[0].ip 192.168.4.200 .value[0].port 2222 .value[0].user listtest .value[0].proxyIp 10.0.0.6 .value[0].proxyPort 6666 .value[0].proxyUser listtest

    # Clean up
    success cleanup_guest_list_test $a1 --osh groupDelGuestAccess --group $group1 --account $account2 --host 192.168.4.200 --user listtest --port 2222 --proxy-host 10.0.0.6 --proxy-port 6666 --proxy-user listtest
    json .command groupDelGuestAccess .error_code OK

    # Add guest access with proxy-user for list check
    success a1_add_server_with_proxy_user_for_guest_list $a1 --osh groupAddServer --group $group1 --host 192.168.4.201 --user listtest --port 2222 --proxy-host 10.0.0.6 --proxy-port 6666 --proxy-user proxyuser --force
    json .command groupAddServer .error_code OK

    success add_guest_access_with_proxy_user_for_list_check $a1 --osh groupAddGuestAccess --group $group1 --account $account2 --host 192.168.4.201 --user listtest --port 2222 --proxy-host 10.0.0.6 --proxy-port 6666 --proxy-user proxyuser
    json .command groupAddGuestAccess .error_code OK

    # Clean up
    success cleanup_guest_list_test_with_proxy_user $a1 --osh groupDelGuestAccess --group $group1 --account $account2 --host 192.168.4.201 --user listtest --port 2222 --proxy-host 10.0.0.6 --proxy-port 6666 --proxy-user proxyuser
    json .command groupDelGuestAccess .error_code OK

    # Clean up servers added for testing
    success cleanup_server_192_168_4_100 $a1 --osh groupDelServer --group $group1 --host 192.168.4.100 --user testuser --port 22 --proxy-host 10.0.0.4 --proxy-port 22 --proxy-user testuser
    json .command groupDelServer .error_code OK

    success cleanup_server_192_168_4_101 $a1 --osh groupDelServer --group $group1 --host 192.168.4.101 --user testuser --port 22 --proxy-host localhost --proxy-port 2222 --proxy-user testuser
    json .command groupDelServer .error_code OK

    success cleanup_server_192_168_4_110 $a1 --osh groupDelServer --group $group1 --host 192.168.4.110 --user testuser --port 22
    json .command groupDelServer .error_code OK

    success cleanup_server_192_168_4_200 $a1 --osh groupDelServer --group $group1 --host 192.168.4.200 --user listtest --port 2222 --proxy-host 10.0.0.6 --proxy-port 6666 --proxy-user listtest
    json .command groupDelServer .error_code OK

    success cleanup_server_192_168_4_201 $a1 --osh groupDelServer --group $group1 --host 192.168.4.201 --user listtest --port 2222 --proxy-host 10.0.0.6 --proxy-port 6666 --proxy-user proxyuser
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
