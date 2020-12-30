# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_piv()
{
    local piv_pub='ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0WJjTpqEDq/phKdaaFo0LXv9HBvQGeCxk/7cn4Gs9IZ4KVTeVV+ec8o9w6U8T4VfH+0ldcrnBIyVq2y7IcvLm/ozWahMCr9Fmo4qWRJSdps1s/rmzsjpdNIwlwfiT06lkEJBTs5FPl2az4rTJDU80igsSmfNDSH7q28LST2FodFEe7SZpZXSEJKAk0KXZcOLSZ8xseOg1g/lcsXcvVsBtymQpwBI6zRFAZ1hCOf340Zu0l7jH5jl0dYbr/G628eKTf4lE0k7E0r9XcBPgV4ptcJNtj8/LJbL0fgPmDlYdgwIPr/a8j+3iGRhkaj0zUlinxZePq6+EsbVPIkYc7EGN'

    local piv_attestation="
-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIRAItlTzjX4IX8mh6CNHcOMdkwDQYJKoZIhvcNAQELBQAw
ITEfMB0GA1UEAwwWWXViaWNvIFBJViBBdHRlc3RhdGlvbjAgFw0xNjAzMTQwMDAw
MDBaGA8yMDUyMDQxNzAwMDAwMFowJTEjMCEGA1UEAwwaWXViaUtleSBQSVYgQXR0
ZXN0YXRpb24gOWEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0WJjT
pqEDq/phKdaaFo0LXv9HBvQGeCxk/7cn4Gs9IZ4KVTeVV+ec8o9w6U8T4VfH+0ld
crnBIyVq2y7IcvLm/ozWahMCr9Fmo4qWRJSdps1s/rmzsjpdNIwlwfiT06lkEJBT
s5FPl2az4rTJDU80igsSmfNDSH7q28LST2FodFEe7SZpZXSEJKAk0KXZcOLSZ8xs
eOg1g/lcsXcvVsBtymQpwBI6zRFAZ1hCOf340Zu0l7jH5jl0dYbr/G628eKTf4lE
0k7E0r9XcBPgV4ptcJNtj8/LJbL0fgPmDlYdgwIPr/a8j+3iGRhkaj0zUlinxZeP
q6+EsbVPIkYc7EGNAgMBAAGjTjBMMBEGCisGAQQBgsQKAwMEAwUBAjAUBgorBgEE
AYLECgMHBAYCBAChqx8wEAYKKwYBBAGCxAoDCAQCAwEwDwYKKwYBBAGCxAoDCQQB
ATANBgkqhkiG9w0BAQsFAAOCAQEAjnLtgCOWk3tsG2Uq+D5oU9x8PGfUDzNlecoi
rYC0nYXKynF4NELKreRf2/qzz06HunZd5LpCDKgC5U0lpOYGYZEmKdXLrLYeY7tr
ewemsMMcA/kfRGa0rNYP83DWAl1GpiYfPhOsWp/CBb5Pp5j74jtjumfNI/nuP8Ic
aEuWlizfpBGumvp6Sp5RTWH/9RD0R2MIR3QNhfFc6umK8tAcup+erZGZjJwGYxn+
K2EeMh26iZ/SAbW2oGSAr8Td/9N+ZCDP6tEvuqQ4izM/7b0Jj92BUyKpsMR1Dxnw
D28mVHaPVB8LqFxHtXa44JQ2whnql2OpnPLjB6i/g+jv21o3nA==
-----END CERTIFICATE-----"

    local piv_certificate="
-----BEGIN CERTIFICATE-----
MIIC+jCCAeKgAwIBAgIJAIZ3F+AdGSsmMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNV
BAMMIFl1YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAw
MDAwMFoYDzIwNTIwNDE3MDAwMDAwWjAhMR8wHQYDVQQDDBZZdWJpY28gUElWIEF0
dGVzdGF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxVuN6bk8
U2mCiP7acPxciHhBJaIde4SOkzatZytMq0W+suDVnBuhaNVr+GNcg8uDOGK3ZK6D
NzeOyGCA5gH4daqu9m6n1XbFwSWtqp6d3LV+6Y4qtD+ZDfefIKAooJ+zsSJfrzj7
c0b0x5Mw3frQhuDJxnKZr/sklwWHh91hRW+BhspDCNzeBKOm1qYglknKDI/FnacL
kCyNaYlb5JdnUEx+L8iq2SWkAg57UPOIT0Phz3RvxXCguMj+BWsSAPVhv5lnABha
L0b/y7V4OprZKfkSolVuYHS5YqRVnDepJ7IylEpdMpEW4/7rOHSMqocIEB8SPt2T
jibBrZvzkcoJbwIDAQABoykwJzARBgorBgEEAYLECgMDBAMFAQIwEgYDVR0TAQH/
BAgwBgEB/wIBADANBgkqhkiG9w0BAQsFAAOCAQEABVe3v1pBdPlf7C7SuHgm5e9P
6r9aZMnPBn/KjAr8Gkcc1qztyFtUcgCfuFmrcyWy1gKjWYMxae7BXz3yKxsiyrb8
+fshMp4I8whUbckmEEIIHTy18FqxmNRo3JHx05FUeqA0i/Zl6xOfOhy/Q8XR0DMj
xiWgTOTpqlmA2AIesBBfuOENDDAccukRMLTXDY97L2luDFTJ99NaHKjjhCOLHmTS
BuCSS5h/F6roSi7rjh2bEOaErLG+G1hVWAzfBNXgrsUuirWRk0WKhJKeUrfNPILh
CzYH/zLEaIsLjRg+tnmKJu2E4IdodScri7oGVhVyhUW5DrcX+/8CPqnoBpd7zQ==
-----END CERTIFICATE-----"

    grant accountCreate

    success osh accountCreate $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key \""$(cat $account1key1file.pub)"\"
    json .error_code OK .command accountCreate .value null

    revoke accountCreate
    grant accountModify
    grant accountPIV
    grant accountListIngressKeys

    script selfAddIngressKey piv_nopivspecified $a1 --osh selfAddIngressKey --piv "< $account2key1file.pub"
    retvalshouldbe 100
    json .command selfAddIngressKey .error_code ERR_NO_PEM_START_MARKER

    # set min rsa size to 2048 so we can work
    configchg 's=^\\\\x22minimumIngressRsaKeySize\\\\x22.+=\\\\x22minimumIngressRsaKeySize\\\\x22:2048,='

    # add a key which doesn't match the certs
    script selfAddIngressKey piv_badcert "( cat $account2key1file.pub; echo \"$piv_attestation\"; echo \"$piv_certificate\" ) | $a1 --osh selfAddIngressKey --piv"
    retvalshouldbe 100
    json .command selfAddIngressKey .error_code ERR_PIV_VALIDATION_FAILED

    # add a proper PIV key
    script selfAddIngressKey piv_ok "( echo \"$piv_pub\"; echo \"$piv_attestation\"; echo \"$piv_certificate\" ) | $a1 --osh selfAddIngressKey --piv"
    retvalshouldbe 0
    json .command selfAddIngressKey .error_code OK .value.key.isPiv 1 .value.key.pivInfo.SSHKey.FingerprintMD5 '01:de:fa:fd:0a:3e:9d:45:d2:0c:a1:9c:1b:97:79:dd'

    # we should see it here
    success selfListIngressKeys piv_list $a1 --osh selfListIngressKeys
    json .command selfListIngressKeys .error_code OK .value.keys[1].isPiv 1 .value.keys[1].pivInfo.Yubikey.SerialNumber 10595103
    # save the fp for later
    local piv_fp
    piv_fp=$(get_json | $jq '.value.keys[1].fingerprint')

    # add a third normal key (needed for a test few lines below)
    success selfAddIngressKey normalkey $a1 --osh selfAddIngressKey "< $account1key2file.pub"
    json .command selfAddIngressKey .error_code OK
    # save the fp for later too
    local other_fp
    other_fp=$(get_json | $jq '.value.key.fingerprint')

    # enforce PIV only on account1
    success accountPIV a0_piv_enforce_a1 $a0 --osh accountPIV --policy enforce --account $account1
    json .command accountPIV .error_code OK

    # account1 can no longer connect because only its PIV key is active, and this testcase doesn't have the corresponding private key (obviously)
    run selfListIngressKeys a1_listkeys $a1 --osh selfListIngressKeys
    retvalshouldbe 255
    contain "Permission denied"

    # account0 checks the ingress keys of account1, only the PIV key must remain.
    success accountListIngressKeys a0_listkeys_a1 $a0 --osh accountListIngressKeys --account $account1
    json .command accountListIngressKeys .error_code OK .value.keys[1] null .value.keys[0].isPiv 1 .value.keys[0].pivInfo.Yubikey.SerialNumber 10595103

    # account0 sudo account1 to try to add a non-piv key. this must not work.
    # for this trick, a0 needs to use adminSudo hence needs to be an admin
    configchg 's=^\\\\x22adminAccounts\\\\x22.+=\\\\x22adminAccounts\\\\x22:[\\\\x22'"$account0"'\\\\x22],='

    success root set_a0_as_admin $r0 "\". $remote_basedir/lib/shell/functions.inc; add_user_to_group_compat $account0 osh-admin\""

    script sudo-selfListIngressKeys a0_sudo_a1_selfaddnonpiv $a0 --osh adminSudo -- --sudo-as $account1 --sudo-cmd selfAddIngressKey -- $js "< $account2key1file.pub"
    retvalshouldbe 0
    json .command adminSudo .error_code OK_NON_ZERO_EXIT .value.status 100
    contain ERR_NO_PEM_START_MARKER

    # account0 sudo account1 remove the PIV key
    script sudo-selfDelIngressKey a0_sudo_a1_selfdelpiv $a0 --osh adminSudo -- --sudo-as $account1 --sudo-cmd selfDelIngressKey -- --fingerprint-to-delete "$piv_fp" $js
    retvalshouldbe 0
    json .command adminSudo .error_code OK

    # account0 list the keys of account1; no key must remain because all non-PIV keys are disabled and the PIV key is gone
    success accountListIngressKeys a0_listkeys_a1_empty $a0 --osh accountListIngressKeys --account $account1
    json .command accountListIngressKeys .error_code OK '.value.keys|length' 0

    # account1 still can't connect
    run info a1_noconnect $a1 --osh info
    retvalshouldbe 255
    contain "Permission denied"

    # set PIV grace on account1
    success accountPIV a0_piv_grace_a1 $a0 --osh accountPIV --policy grace --ttl 10 --account $account1
    json .command accountPIV .error_code OK

    # account1 should be able to connect now
    success selfListIngressKeys a1_listkeys_after_piv_grace $a1 --osh selfListIngressKeys
    json .command selfListIngressKeys .error_code OK '.value.keys|length' 2

    # sleep to ensure grace expires
    echo "sleeping to wait for grace expiration"
    [ "$COUNTONLY" != 1 ] && sleep 10

    # manually launch the grace reaper (normally done by cron)
    echo "manually launching piv grace reaper..."
    success root grace_reaper $r0 $remote_basedir/bin/cron/osh-piv-grace-reaper.pl

    # account1 should no longer be able to connect, as PIV grace expired
    run info a1_noconnect_grace_expired $a1 --osh info
    retvalshouldbe 255
    contain "Permission denied"

    # remove PIV only from account1
    success accountPIV a0_piv_none_a1 $a0 --osh accountPIV --policy none --account $account1
    json .command accountPIV .error_code OK

    # account1 can connect
    success selfListIngressKeys a1_listkeys_piv_none $a1 --osh selfListIngressKeys
    json .command selfListIngressKeys .error_code OK '.value.keys|length' 2

    # remove the test key
    success selfDelIngressKey a1_delkey_test $a1 --osh selfDelIngressKey --fingerprint-to-delete $other_fp
    json .command selfDelIngressKey .error_code OK

    # remove a0 from admins
    success root del_a0_as_admin $r0 "\". $remote_basedir/lib/shell/functions.inc; del_user_from_group_compat $account0 osh-admin\""

    revoke accountListIngressKeys
    revoke accountPIV
    revoke accountModify

    # delete account1
    grant accountDelete
    script accountDelete cleanup $a0 --osh accountDelete --account $account1 "<<< \"Yes, do as I say and delete $account1, kthxbye\""
    retvalshouldbe 0

    revoke accountDelete

    # restore default config
    success bastion configrestore $r0 "dd if=$osh_etc/bastion.conf.bak.$now of=$osh_etc/bastion.conf"
}

if [ "$HAS_PIV" = 1 ]; then
    testsuite_piv
fi
