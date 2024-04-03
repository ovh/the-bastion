# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

# now try adding a key with a from="" when server has allowOverride=1 and ingressKeyFrom="x"
# also try creating an account with it (code paths from selfAddIngressKey and accountCreate differ)
_ingress_from_test()
{
    local testname="$1" ip1="$2" ip2="$3" keytoadd="$4" fingerprint="$5"

    script $testname "echo '$keytoadd' | $a1 --osh selfAddIngressKey"
    retvalshouldbe 0
    json .value.connect_only_from[0] $ip1
    json .value.connect_only_from[1] $ip2
    json .value.key.from_list[0] $ip1
    json .value.key.from_list[1] $ip2
    if [ "$ip1" = null ] && [ "$ip2" = null ]; then
        json .value.key.prefix ""
    else
        json .value.key.prefix "from=\"$ip1,$ip2\""
    fi

    success $testname $a1 --osh selfListIngressKeys
    json .value.keys[1].from_list[0] $ip1
    json .value.keys[1].from_list[1] $ip2
    if [ "$ip1" = null ] && [ "$ip2" = null ]; then
        json .value.keys[1].prefix ""
    else
        json .value.keys[1].prefix "from=\"$ip1,$ip2\""
    fi

    success $testname $a1 --osh selfDelIngressKey -f "$fingerprint"

    # now on account creation
    grant accountCreate

    script $testname "echo '$keytoadd' | $a0 --osh accountCreate --account $account2 --uid $uid2"
    json .error_code OK .command accountCreate .value null

    revoke accountCreate
    grant accountListIngressKeys

    success $testname $a0 --osh accountListIngressKeys --account $account2
    json .value.keys[0].from_list[0] $ip1
    json .value.keys[0].from_list[1] $ip2
    if [ "$ip1" = null ] && [ "$ip2" = null ]; then
        json .value.keys[0].prefix ""
    else
        json .value.keys[0].prefix "from=\"$ip1,$ip2\""
    fi

    revoke accountListIngressKeys
    grant accountDelete

    script $testname "$a0 --osh accountDelete --account $account2" "<<< \"Yes, do as I say and delete $account2, kthxbye\""
    retvalshouldbe 0
    json .error_code OK .command accountDelete

    revoke accountDelete
}

testsuite_selfkeys()
{
    grant accountCreate

    success accountCreate $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key \""$(cat $account1key1file.pub)"\"
    json .error_code OK .command accountCreate .value null

    revoke accountCreate
    grant accountModify

    # <accountModify --egress-strict-host-key-checking>
    grant accountInfo
    grant auditor

    configchg 's=^\\\\x22minimumIngressRsaKeySize\\\\x22.+=\\\\x22minimumIngressRsaKeySize\\\\x22:4096,='

    success info0 $a0 --osh accountInfo --account $account1
    json .error_code OK .command accountInfo
    json .value.account_egress_ssh_config.type default

    success modifyssh1 $a0 --osh accountModify --account $account1 --egress-strict-host-key-checking no
    json .error_code OK .command accountModify

    success info1 $a0 --osh accountInfo --account $account1
    json .error_code OK .command accountInfo
    json .value.account_egress_ssh_config.type custom
    json .value.account_egress_ssh_config.items.stricthostkeychecking no

    success modifyssh2 $a0 --osh accountModify --account $account1 --egress-strict-host-key-checking accept-new
    json .error_code OK .command accountModify

    success info2 $a0 --osh accountInfo --account $account1
    json .error_code OK .command accountInfo
    json .value.account_egress_ssh_config.type custom
    json .value.account_egress_ssh_config.items.stricthostkeychecking accept-new

    success modifyssh2 $a0 --osh accountModify --account $account1 --egress-strict-host-key-checking yes
    json .error_code OK .command accountModify

    success info2 $a0 --osh accountInfo --account $account1
    json .error_code OK .command accountInfo
    json .value.account_egress_ssh_config.type custom
    json .value.account_egress_ssh_config.items.stricthostkeychecking yes

    success modifyssh3 $a0 --osh accountModify --account $account1 --egress-strict-host-key-checking ask
    json .error_code OK .command accountModify

    success info3 $a0 --osh accountInfo --account $account1
    json .error_code OK .command accountInfo
    json .value.account_egress_ssh_config.type custom
    json .value.account_egress_ssh_config.items.stricthostkeychecking ask

    success modifyssh4 $a0 --osh accountModify --account $account1 --egress-strict-host-key-checking bypass
    json .error_code OK .command accountModify

    success info4 $a0 --osh accountInfo --account $account1
    json .error_code OK .command accountInfo
    json .value.account_egress_ssh_config.type custom
    json .value.account_egress_ssh_config.items.stricthostkeychecking no
    json .value.account_egress_ssh_config.items.userknownhostsfile /dev/null

    success modifyssh5 $a0 --osh accountModify --account $account1 --egress-strict-host-key-checking default
    json .error_code OK .command accountModify

    success info5 $a0 --osh accountInfo --account $account1
    json .error_code OK .command accountInfo
    json .value.account_egress_ssh_config.type default

    revoke auditor
    revoke accountInfo
    # </accountModify --egress-strict-host-key-checking>

    success modify_account1 $a0 --osh accountModify --pam-auth-bypass yes --account $account1
    json .error_code OK .command accountModify

    revoke accountModify
    grant accountListEgressKeys

    success accountListEgressKeys $a0 --osh accountListEgressKeys --account $account1
    contain "keyline"
    json .error_code OK .command accountListEgressKeys
    set +e
    local tmpfp
    tmpfp=$(get_json | $jq '.value|keys[0]')
    set -e
    json $(cat <<EOS
    .value|.["$tmpfp"]|.family      RSA
    .value|.["$tmpfp"]|.size        4096
    .value|.["$tmpfp"]|.fingerprint $tmpfp
    .value|.["$tmpfp"]|.typecode    ssh-rsa
EOS
    )
    set +e
    pattern "^$account1@fix-my-config-please-missing-bastion-name:[0-9]+$" "$(get_json | $jq ".value|.[\"$tmpfp\"]|.comment")"
    set -e
    unset tmpfp

    revoke accountListEgressKeys

    # add del list pub keys
    success beforeadd $a1 -osh selfListIngressKeys
    json $(cat <<EOS
    .command selfListIngressKeys
    .error_code OK
    .value.account $account1
    .value.keys[0].id 1
    .value.keys[0].validity OK
    .value.keys[0].size 256
EOS
    )
    local account1key1fp
    account1key1fp=$(get_json | $jq '.value.keys[0].fingerprint')

    ignorecodewarn "possible deadlock"
    script  flood   $a1 -osh selfAddIngressKey '<' /dev/urandom
    retvalshouldbe 0

    script  privkey $a1 -osh selfAddIngressKey '<<< "-----BEGIN DSA PRIVATE KEY-----
    MIIBugIBAAKBgQCawvohH0r9B4NxdaYHiBT5pLWDe14o3MTE3WwtKF0l7az+zw0P"'
    retvalshouldbe 100
    contain "HOLY SH"
    json $(cat <<EOS
    .command selfAddIngressKey
    .error_code KO_PRIVATE_KEY
    .value null
EOS
    )

    script  privkey $a1 -osh selfAddIngressKey '<<< "-----BEGIN RSA PRIVATE KEY-----
    MIIBugIBAAKBgQCawvohH0r9B4NxdaYHiBT5pLWDe14o3MTE3WwtKF0l7az+zw0P"'
    retvalshouldbe 100
    contain "HOLY SH"
    json .command selfAddIngressKey .error_code KO_PRIVATE_KEY .value null

    script  privkey $a1 -osh selfAddIngressKey '<<< "-----BEGIN EC PRIVATE KEY-----
    MIIBugIBAAKBgQCawvohH0r9B4NxdaYHiBT5pLWDe14o3MTE3WwtKF0l7az+zw0P"'
    retvalshouldbe 100
    contain "HOLY SH"
    json .command selfAddIngressKey .error_code KO_PRIVATE_KEY .value null

    script  privkey $a1 -osh selfAddIngressKey '<<< "-----BEGIN OPENSSH PRIVATE KEY-----
    MIIBugIBAAKBgQCawvohH0r9B4NxdaYHiBT5pLWDe14o3MTE3WwtKF0l7az+zw0P"'
    retvalshouldbe 100
    contain "HOLY SH"
    json .command selfAddIngressKey .error_code KO_PRIVATE_KEY .value null

    script  bogus $a1 -osh selfAddIngressKey '<<<' "bogus"
    retvalshouldbe 100
    contain "look like an SSH public key"
    json .command selfAddIngressKey .error_code KO_NOT_A_KEY .value.key.line bogus

    script  eof $a1 -osh selfAddIngressKey '</dev/null'
    retvalshouldbe 100
    contain "look like an SSH public key"
    json .command selfAddIngressKey .error_code KO_NOT_A_KEY .value null

    local b64 FP_TYPE fpdsa
    b64='AAAAB3NzaC1kc3MAAACBAPOCqEho94k9fEArLgR1kuNTMo52aozaw1jr7sKLTjt3BZslvt3zl264THsIN4XeuI6noiD7QwCO3PSMUsPnrlreQEGff8f97IE+LpH7rZQB7kSM50PGk0QfS1qpVnWbsi5NAvV3ib12gErtXg/YiJfx0x+lWaZTMkaFUdwpyaEXAAAAFQCOng3YNx+KK38h6675jJD78k6bpwAAAIEA2Y/3CZHgzIIBtddVssfLBv3196SAbYMA/eDmsbTM9dyhWdAGPc36/sfveITpbQ2kZYvR4S1pstQ4ZNMM3cdD6GHy+CkDXYEH7SbEa60jEaIue3OK4FhtBLSs4n7sIzNYgRm8hoXYNM4jpC+zf1dpUqIZd1d742JPFJAk07vnj2AAAACAWWpKTEg9ArdpkkvX6FC5lxq7uhVN1uo7+5TBCE8C31fXppHfp9M2FvL2hubbIRYJ+QNDzU+f0UYJr2Nv1v3tyG8LJ2942B9ym+TYb6SzMJ20jWW5v+wfSXuwaPLIAWYFLIbUCp/pv+BnQKAXrVLIsM+iWj6amB/2NrZH5q0j/8k='
    script  dsa     $a1 -osh selfAddIngressKey "<<< \"ssh-dss $b64 test@dsa\""
    retvalshouldbe 100
    contain "Wait, DSA key"
    # here we need to determine if ssh-keygen is using MD5 or SHA256 for fingerprints
    if get_json | $jq '.value.key.fingerprint' | grep SHA256: ; then
        FP_TYPE=sha256
        fpdsa="SHA256:0r7vajJstsoQbf7k3S7hx7usIrdroNYyVi3ILPCFa/0"
    else
        FP_TYPE=md5
        fpdsa="0b:8f:6b:8a:9e:f0:38:bd:74:0c:71:50:ad:c1:ab:4b"
    fi
    json $(cat <<EOS
    .command      selfAddIngressKey
    .error_code   KO_FORBIDDEN_ALGORITHM
    .value.key.base64 $b64
    .value.key.comment      test@dsa
    .value.key.typecode     ssh-dss
    .value.key.fingerprint  $fpdsa
    .value.key.size         1024
    .value.key.family       DSA
EOS
    ) \
        .value.key.line         "ssh-dss $b64 test@dsa" \
        .value.key.prefix       ""

    script  dsaDup   $a1 -osh selfAddIngressKey "<<< \"ssh-dss $b64 test@dsaduplicate\""
    retvalshouldbe 100
    contain "Wait, DSA key"
    json $(cat <<EOS
    .command      selfAddIngressKey
    .error_code   KO_FORBIDDEN_ALGORITHM
    .value.key.base64 $b64
    .value.key.comment      test@dsaduplicate
    .value.key.typecode     ssh-dss
    .value.key.fingerprint  $fpdsa
    .value.key.size         1024
    .value.key.family       DSA
EOS
    ) \
        .value.key.line         "ssh-dss $b64 test@dsaduplicate" \
        .value.key.prefix       ""

    b64='AAAAB3NzaC1yc2EAAAADAQABAAAAgQDNbJemAKF6u4xZtbbkHtQeXeh9EvsYgBdUlnES1oBSS/ICKU7lcUrW4UvUpYLQ0+N1f0XaYfGO01BnEPwJDYJngkybh1Qwo6IbCBySpIFJG7ToK4M1U2arALGelwgoVP3AE+HoLjSH9W0ZisBvWtiyCekBWnzf+kD5hLkblPXYkQ=='
    local fp1024
    fp1024="SHA256:tHu5MD2vgUWxduQUnXqtHaRCCbez7CB9hOvD7zMZu/U"
    [ "$FP_TYPE" = md5 ] && fp1024="65:94:cc:f1:5d:29:6e:11:70:44:ce:a8:61:df:25:0a"
    script  rsa1024  $a1 -osh selfAddIngressKey "<<< \"ssh-rsa $b64 test@rsa1024\""
    retvalshouldbe 100
    contain "This is too small"
    json $(cat <<EOS
    .command               selfAddIngressKey
    .error_code            KO_KEY_SIZE_TOO_SMALL
    .value.key.base64      $b64
    .value.key.comment     test@rsa1024
    .value.key.typecode    ssh-rsa
    .value.key.fingerprint $fp1024
    .value.key.size        1024
    .value.key.family      RSA
EOS
    ) \
        .value.key.line     "ssh-rsa $b64 test@rsa1024" \
        .value.key.prefix   ""

    b64='AAAAB3NzaC1yc2EAAAADAQABAAABAQDUcjtSpPwY9kdBtmfAURXEIwvUnfJ41acboaNyXU0Vv9C0hg6DNemm8FjDC4xp9AtQgKc8Sq2VGrUXIMO/xxD8LA9u3DjwWLYAzoBYGzKZ9p7QynoeEAa/Fpv811LmSJMVw1NPDahMrv1mVR4vXrU5Z/S4VkIEY19DnO0TlpciWPC9ePLhcF/MIb2dwzRlWaKm0JRw8D/V3aPbacyZL1zO+Gdk8an95DZ7T8KbxDdLxf6pLLWbtdMxZKnTQeAJGW7JXsf6ybmHgOqHTI3gWfydbRe0bHBcqORT21resFcqqyqKrKjGedWYqDraAi3k8G+U0T8RwDGMJpC2EFDk7c0H'
    local fp2048
    fp2048="SHA256:ZdeU0HZyYoqz+ysPxoZ5cUX8eDIV4PIn7s0oDipqUnI"
    [ "$FP_TYPE" = md5 ] && fp2048="a0:cf:72:54:59:b5:61:26:37:5f:98:14:83:c7:d3:8f"
    script  rsa2048  $a1 -osh selfAddIngressKey "<<< \"ssh-rsa $b64 test@rsa2048\""
    retvalshouldbe 100
    contain "This is too small"
    json $(cat <<EOS
    .command                selfAddIngressKey
    .error_code             KO_KEY_SIZE_TOO_SMALL
    .value.key.base64       $b64
    .value.key.comment      test@rsa2048
    .value.key.typecode     ssh-rsa
    .value.key.fingerprint  $fp2048
    .value.key.family       RSA
    .value.key.size         2048
EOS
    ) \
        .value.key.line   "ssh-rsa $b64 test@rsa2048" \
        .value.key.prefix ""

    b64='AAAAB3NzaC1yc2EAAAADAQABAAACAQDC6clamfZUjOfWR9T5TG/QbN8lTDwdJXPmKXa7P4F9+QKDRoKfcRn0hTW4LeTsBlbnPoeolRPNuhjW/l1Sv1MLCVqzwUljbbvAZ4QBAMhXIFy0Z2i2zE/jpi2oC7J7+/2sHtznW0mxQppcb6pMWLRNuU4p85l+XZanzbQoR+7aEdvjn1eTYa/jkAJwMCS+HO3F9nVkV7EyVYXoPYEDya/mrdgLcZktSuE42zD9TVpBXlW5pONeuo2q0h7soJp1VhJwwO1/VXPmz7JfvFhFrHit+Bh+RJeTOrLRG1kE/5DZoLbOiXpBzG08bbyQQS17DynHk2afMrbqQx3tV6a/TqCF0LJTaNPDTKmYinsremHXxKpzStNkJ7UArgfipoUk20QyPJX3P5T0JF1LLu8rfE6GpqB7CVgYDjPIKcfiG5o+gKrwYrLkyDaEKkhdD0KSAZ5HmL/Z4t/3aDYUK96/IiYE49PI6rsuD5RRCASv8U68v2Kk14X7MmR7mZxJZ2oRMtPftS/Z+nvoStyUQF5LBOTKlrJd5PTjC6OlMG85qLmYjbDViUK/b/KtdwgQPhupzsHIq3hAaSvudjMWqbOQ/YlwwOxqAC7EVe9nv6cZTyBHIq2AINlNRqL1f6hzxrL6oBAMAvirNYI8/B/8yYGYwbNdTTNIZOXxWqHW8OIeA+QgMQ=='
    local fp4096
    fp4096="SHA256:esuEP68vVxW7uJd1jxUXfmMj0Hk3my/Lv181K/XFlfY"
    [ "$FP_TYPE" = md5 ] && fp4096="84:0a:ae:13:62:1e:c4:bc:d7:2b:b4:d4:fe:c8:6d:0a"
    script  rsa4096  $a1 -osh selfAddIngressKey "<<< \"ssh-rsa $b64 test@rsa4096\""
    retvalshouldbe 0
    contain "key successfully added"
    json $(cat <<EOS
    .command                selfAddIngressKey
    .error_code             OK
    .value.key.base64       $b64
    .value.key.comment      test@rsa4096
    .value.key.typecode     ssh-rsa
    .value.key.fingerprint  $fp4096
    .value.key.family       RSA
    .value.key.size         4096
EOS
    ) \
        .value.key.line   "ssh-rsa $b64 test@rsa4096" \
        .value.key.prefix ""

    script  rsa4096dup $a1 -osh selfAddIngressKey "<<< \"ssh-rsa $b64 test@rsa4096duplicate\""
    retvalshouldbe 100
    contain "already exists"
    json $(cat <<EOS
    .command                selfAddIngressKey
    .error_code             KO_DUPLICATE_KEY
    .value.key.base64       $b64
    .value.key.comment      test@rsa4096duplicate
    .value.key.typecode     ssh-rsa
    .value.key.fingerprint  $fp4096
    .value.key.family       RSA
    .value.key.size         4096
EOS
    ) \
        .value.key.line   "ssh-rsa $b64 test@rsa4096duplicate" \
        .value.key.prefix ""

    b64='AAAAB3NzaC1yc2EAAAADAQABAAAEAQD2anHdMJgmE87uinVQjvg1BgsiLZm8Ra6b0xknf6IGd/ZK3FHq5FxBAHUtubqAsM5DyKgf9DtG+MIb43Zv3ECXWppPcplyM5B0L4Y/QVlPf6cgL6gug4ct6XiK1Ck+CH9kc5tkEdk10GV89teTBhq9xXw0tcVkoMwrc9mNGb7OVG6RQRROk+LzoWYiIMUPRW0gYRBxQnliBqQmlbs5lZbWbFhsjBJPSEeY2h0OEtoEItZyM6om2IwI2o9D8QzgoL8KbYEknuBS5zJIkT82HRBxKvttjaZakiEoT3Ir82YavFgwHpkA4N6Gz6IAyWofcB+qp2p0Wi1VILim07gXdWOmVbX/WN6NsY4g05V2FQVqECIR/dHwePkzA0DvHLbeY720nm6YV2v29i5imd1jOzgFPFDSQ12HL0JyHw0Cl8XH/1DpGYTIG1hXgCxi6wAtKKEg/hYaEvAA5Jl/GtVOWbRT9dZ0FNQyfvfPeM64+SBWVHeAIKpyr+Gpq81JbYDcUlm566ukwfUi1cif87ZU4MQZKIYJet1FDkEnOi8n20jeZH6EgCWROdPtXYHohT6u6g3JC4MEUl1V7fr2CXAP/XMQfjz31UycZjtI9/76YIF0N6NORSQ/eN0MY1kCvFaDahkaJwp98t6UxUMfTtDf1IImWWatWMB+viNhH5gi26ar3zWeBXRlwuUmz7t64qmwgywc7qYtGCfWAxuMhVS88rbnGSj/Dcw6dJFJu1+5ysYY7Z4tgbShFeOioFIf9hg/j1+Ouubcjs2wZELjfXr9KHCwoDINvn+wVDn/02V7OYxeP/a8UxECKPRL6qa1JfIKYlx9w8Kt0TDSAEOc5P+rsZFfTYeUro7V/gv9gXxI/GuWkCQOexaeDGqo9+QVtlxInWrjd+vXAzEs977oSkNmRD9Ev7pSTZSEHd9bYvoMB2dzJgeYwl9YsQ7mLNMLX/du/q7s7L8qvS4thHi68XmypFUtrq0g6K2ybodgdjUEd2IGuLDdqDw2EmXN9yXu/giVd0/XKx4eRf82OK6UAjr2ZSvBQE7CQN+HsvKrnS+V4xd758BWIjR78PUGIR0tNt8pZmpE7mbluWcBTPkPalSna5l4bigtJkKKjrKHELhsVr6LtBjMy+VVOBworsaqFXwDzj0a39vRwEcfuY7YPe12hrNI9zjq/3exr1GaK4YDa/mojsfxoyKgNaoOarIAX0RRBLqmJt3lTyAkvnxe23CVPAjNcOx/m1HjqbbxJ+GWXpOHvh3RXIZbvyAKYrgM3YydGaDGfMjgmWUHeYFcydfyRuNoCXKl0fCgduQAdjpyyUSFLvdeI4HEfVsWF4AUn7A4IwUmh2kcQ56naHABgpIbf+8V'
    local fp8192
    fp8192="SHA256:nQl/AkakKTV25MKXZQpEBAEECq2BKLBqrRICR0YBn8s"
    [ "$FP_TYPE" = md5 ] && fp8192="cd:26:73:ff:7e:b5:72:d7:7d:d5:dd:da:d7:c0:8d:35"
    script  rsa8192 $a1 -osh selfAddIngressKey "<<< \"ssh-rsa $b64 test@rsa8192\""
    retvalshouldbe 0
    contain "key successfully added"
    json $(cat <<EOS
    .command                selfAddIngressKey
    .error_code             OK
    .value.key.base64       $b64
    .value.key.comment      test@rsa8192
    .value.key.typecode     ssh-rsa
    .value.key.fingerprint  $fp8192
    .value.key.family       RSA
    .value.key.size         8192
EOS
    ) \
        .value.key.line   "ssh-rsa $b64 test@rsa8192" \
        .value.key.prefix ""

    b64='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'
    local fp16384
    fp16384="SHA256:xexcqmW+ZCLf5ulEQvVoldakfEJMcD51myTuxQbkgIA"
    [ "$FP_TYPE" = md5 ] && fp16384="fc:67:ee:6d:0e:d4:19:46:38:8f:2c:6b:e1:e8:07:f3"
    script  rsa16384  $a1 -osh selfAddIngressKey "<<< \"ssh-rsa $b64 test@rsa16384\""
    retvalshouldbe 0
    contain "key successfully added"
    json $(cat <<EOS
    .command                selfAddIngressKey
    .error_code             OK
    .value.key.base64       $b64
    .value.key.comment      test@rsa16384
    .value.key.typecode     ssh-rsa
    .value.key.fingerprint  $fp16384
    .value.key.family       RSA
    .value.key.size         16384
EOS
    ) \
        .value.key.line   "ssh-rsa $b64 test@rsa16384" \
        .value.key.prefix ""

    b64='AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBezrCa6RsyyWnHDypyGZ4/72UsiLaDmJ+A04vVuxO0XsjrhX52Q7zkz5NOA2VccAFJCLwN9h/+LLrIxM6FK64k='
    local fpe256
    fpe256="SHA256:7jAGgQXAu4DfrL5cpa1Gh5gDJjwLDGLr0Ahc5TwTPOA"
    [ "$FP_TYPE" = md5 ] && fpe256="4d:35:52:9f:0f:c7:54:68:7e:57:c5:10:32:54:da:bc"
    script  ecdsa256  $a1 -osh selfAddIngressKey "<<< \"ecdsa-sha2-nistp256 $b64 test@ecdsa256\""
    retvalshouldbe 0
    contain "key successfully added"
    json $(cat <<EOS
    .command                selfAddIngressKey
    .error_code             OK
    .value.key.base64       $b64
    .value.key.comment      test@ecdsa256
    .value.key.typecode     ecdsa-sha2-nistp256
    .value.key.fingerprint  $fpe256
    .value.key.family       ECDSA
    .value.key.size         256
EOS
    ) \
        .value.key.line   "ecdsa-sha2-nistp256 $b64 test@ecdsa256" \
        .value.key.prefix ""

    script  ecdsa256D $a1 -osh selfAddIngressKey "<<< \"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBezrCa6RsyyWnHDypyGZ4/72UsiLaDmJ+A04vVuxO0XsjrhX52Q7zkz5NOA2VccAFJCLwN9h/+LLrIxM6FK64k= test@ecdsa256duplicate\""
    retvalshouldbe 100
    contain "already exists"
    json $(cat <<EOS
    .command                selfAddIngressKey
    .error_code             KO_DUPLICATE_KEY
    .value.key.base64       $b64
    .value.key.comment      test@ecdsa256duplicate
    .value.key.typecode     ecdsa-sha2-nistp256
    .value.key.fingerprint  $fpe256
    .value.key.family       ECDSA
    .value.key.size         256
EOS
    ) \
        .value.key.line   "ecdsa-sha2-nistp256 $b64 test@ecdsa256duplicate" \
        .value.key.prefix ""

    b64='AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBICjCWYk5lCOX/977vdlDqcuF1ZWb4cX8cZuskRCSJBwMaCBHKvSwxzcbVdS++4MAaCsQisDSgwAhK6KcbjwitKAiSUWmRhIxFrPQojrfrDlw20bgFqc/RGiSykMTbL1jg=='
    local fpe384
    fpe384="SHA256:P2NDAsOb6ZelE6dwCdqnnSaw/KVXhXMgFWI/pwNF2z0"
    [ "$FP_TYPE" = md5 ] && fpe384="4d:e3:e3:c2:13:79:69:e9:f7:3d:4f:18:21:d3:1b:ef"
    script  ecdsa384  $a1 -osh selfAddIngressKey "<<< \"ecdsa-sha2-nistp384 $b64 test@ecdsa384\""
    retvalshouldbe 0
    contain "key successfully added"
    json $(cat <<EOS
    .command                selfAddIngressKey
    .error_code             OK
    .value.key.base64       $b64
    .value.key.comment      test@ecdsa384
    .value.key.typecode     ecdsa-sha2-nistp384
    .value.key.fingerprint  $fpe384
    .value.key.family       ECDSA
    .value.key.size         384
EOS
    ) \
        .value.key.line   "ecdsa-sha2-nistp384 $b64 test@ecdsa384" \
        .value.key.prefix ""

    b64='AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBADaVbKH5FN1Dcb/jXbb4Xa1UM/l4qVKFSHQKo1o0Zk/T9eHt+vpgvMUnbyZpawktdBgF4ScnPvO7qzgM+fgy62LYACbExQvYLcrYTK+h6TxISptpCFNli4XjjW88YhL7qGmZDlezZTUCHDZryVato7Fzfe66mqZcT6aMWO+Lyr5RLc4uw=='
    local fpe521
    fpe521="SHA256:qK+FmUoa7OBqzyiuH+hp974f/pt8L9SWTsjzId2I4/w"
    [ "$FP_TYPE" = md5 ] && fpe521="2d:af:3a:b1:b7:9f:74:71:f9:8e:3f:85:03:f8:4e:c0"
    script  ecdsa521  $a1 -osh selfAddIngressKey "<<< \"ecdsa-sha2-nistp521 $b64 test@ecdsa521\""
    retvalshouldbe 0
    contain "key successfully added"
    json $(cat <<EOS
    .command                selfAddIngressKey
    .error_code             OK
    .value.key.base64       $b64
    .value.key.comment      test@ecdsa521
    .value.key.typecode     ecdsa-sha2-nistp521
    .value.key.fingerprint  $fpe521
    .value.key.family       ECDSA
    .value.key.size         521
EOS
    ) \
        .value.key.line   "ecdsa-sha2-nistp521 $b64 test@ecdsa521" \
        .value.key.prefix ""
    
b64='AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBBTjpImSazDYONgM5plDyz7R2dFmVJMtKCYRemL+XNvVpyRc4e+V8GBF+UZFSc2ieCpGmcB54GfjryznSgyYHHYAAAAEc3NoOg=='
    local fpe256_sk
    fpe256_sk="SHA256:DRMDgE8K3ByBwYEcosmosvLfHMT7XabCzzM4MoIiIgU"
    [ "$FP_TYPE" = md5 ] && fpe256_sk="dc:e1:9b:e4:64:97:d6:c3:47:a7:9b:33:3d:35:e2:cb"
    script  sk-ecdsa256  $a1 -osh selfAddIngressKey "<<< \"sk-ecdsa-sha2-nistp256@openssh.com $b64 test@ecdsa256-sk\""
    retvalshouldbe 0
    contain "key successfully added"
    json $(cat <<EOS
    .command                selfAddIngressKey
    .error_code             OK
    .value.key.base64       $b64
    .value.key.comment      test@ecdsa256-sk
    .value.key.typecode     sk-ecdsa-sha2-nistp256@openssh.com
    .value.key.fingerprint  $fpe256_sk
    .value.key.family       ECDSA-SK
    .value.key.size         256
EOS
    ) \
        .value.key.line   "sk-ecdsa-sha2-nistp256@openssh.com $b64 test@ecdsa256-sk" \
        .value.key.prefix ""


    b64='AAAAC3NzaC1lZDI1NTE5AAAAIB+fS15BtjxBL338aMGMZus6OuPYP1Ix1yKY1RRCa5VB'
    local fped
    fped="SHA256:DFITA8tNfJknq6a/xbro1SxTLTWn/vwZkEROk4IB2LM"
    [ "$FP_TYPE" = md5 ] && fped="d7:92:5b:77:8b:69:03:cb:e7:5a:11:76:d1:a6:ea:e4"
    local fplist
    fplist="$fp4096 $fp8192 $fp16384 $fpe256 $fpe384 $fpe521 $fpe256_sk"
    script  ed25519   $a1 -osh selfAddIngressKey "<<< \"ssh-ed25519 $b64 test@ed25519\""
    if [ "${capabilities[ed25519]}" = "1" ] ; then
        fplist="$fplist $fped"
        retvalshouldbe 0
        contain "key successfully added"
        json $(cat <<EOS
        .command                selfAddIngressKey
        .error_code             OK
        .value.key.base64       $b64
        .value.key.comment      test@ed25519
        .value.key.typecode     ssh-ed25519
        .value.key.fingerprint  $fped
        .value.key.family       ED25519
        .value.key.size         256
EOS
    ) \
            .value.key.line   "ssh-ed25519 $b64 test@ed25519" \
            .value.key.prefix ""
    else
        retvalshouldbe 100
        contain "look like an SSH public key"
        json $(cat <<EOS
        .command                selfAddIngressKey
        .error_code             KO_NOT_A_KEY
        .value.key.base64       $b64
        .value.key.comment      test@ed25519
        .value.key.typecode     ssh-ed25519
        .value.key.fingerprint  null
        .value.key.family       null
        .value.key.size         null
EOS
        ) \
            .value.key.line   "ssh-ed25519 $b64 test@ed25519" \
            .value.key.prefix ""
    fi

    b64='AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIELpTERg9ds+oj8afq/8fOHdpbf1HBhbRcn5JTzv2QOSAAAABHNzaDo='
    local fped_sk
    fped_sk="SHA256:iV2l8+uJjJwyHnbaWAO25xIsYbZWN77C1kx5vxzbz9k"
    [ "$FP_TYPE" = md5 ] && fped_sk="f5:bd:0c:4f:c7:6a:9d:15:d9:9e:55:9d:89:b3:2b:8f"
    script  ed25519-sk   $a1 -osh selfAddIngressKey "<<< \"sk-ssh-ed25519@openssh.com $b64 test@ed25519-sk\""
    if [ "${capabilities[ed25519]}" = "1" ] ; then
        fplist="$fplist $fped_sk"
        retvalshouldbe 0
        contain "key successfully added"
        json $(cat <<EOS
        .command                selfAddIngressKey
        .error_code             OK
        .value.key.base64       $b64
        .value.key.comment      test@ed25519-sk
        .value.key.typecode     sk-ssh-ed25519@openssh.com
        .value.key.fingerprint  $fped_sk
        .value.key.family       ED25519-SK
        .value.key.size         256
EOS
    ) \
            .value.key.line   "sk-ssh-ed25519@openssh.com $b64 test@ed25519-sk" \
            .value.key.prefix ""
    else
        retvalshouldbe 100
        contain "look like an SSH public key"
        json $(cat <<EOS
        .command                selfAddIngressKey
        .error_code             KO_NOT_A_KEY
        .value.key.base64       $b64
        .value.key.comment      test@ed25519-sk
        .value.key.typecode     sk-ssh-ed25519@openssh.com
        .value.key.fingerprint  null
        .value.key.family       null
        .value.key.size         null
EOS
        ) \
            .value.key.line   "sk-ssh-ed25519@openssh.com $b64 test@ed25519-sk" \
            .value.key.prefix ""
    fi

    run user1key2beforeadd $a1k2 -osh info
    retvalshouldbe 255
    contain "Permission denied"

    script user1key2 $a1 -osh selfAddIngressKey '<' $account1key2file.pub
    retvalshouldbe 0
    contain "key successfully added"
    json .command selfAddIngressKey .error_code OK

    success afteradd $a1 -osh selfListIngressKeys
    account1key1fp=""
    local account1key2fp
    account1key2fp=""
    for i in {0..20}
    do
       tmpline=$(get_json | $jq ".value.keys[$i].line")
       [ "$tmpline" = "null" ] && continue
       grep -qF "$tmpline" $account1key1file.pub && account1key1fp=$(get_json | $jq ".value.keys[$i].fingerprint")
       grep -qF "$tmpline" $account1key2file.pub && account1key2fp=$(get_json | $jq ".value.keys[$i].fingerprint")
    done
    unset tmpline i
    json .command selfListIngressKeys .error_code OK .value.account $account1

    script key1 grep -Eq "'^SHA256:|([0-9a-f]{2}:){7}'" "<<<" "$account1key1fp"
    retvalshouldbe 0

    script key2 grep -Eq "'^SHA256:|([0-9a-f]{2}:){7}'" "<<<" "$account1key2fp"
    retvalshouldbe 0

    # remove all keys except key1 key2
    for fp in $fplist ; do
        success otherkeys $a1 -osh selfDelIngressKey -f $fp
        contain "successfully deleted"
        json .command selfDelIngressKey .error_code OK
    done
    unset fp

    success afterdel $a1 -osh selfListIngressKeys
    json $(cat <<EOS
    .command    selfListIngressKeys
    .error_code OK
    .value.account  $account1
    .value.keys[0].fingerprint $account1key1fp
    .value.keys[1].fingerprint $account1key2fp
    .value.keys[2]             null
EOS
    )

    success user1key2aftereadd $a1k2 -osh info
    contain "Your alias to connect"
    json .command info .error_code OK .value.account $account1

    success key2 $a1k2 -osh selfDelIngressKey -f "$account1key2fp"
    json .command selfDelIngressKey .error_code OK .value.deleted_key.err OK

    plgfail a1k1mustfail $a1 -osh selfDelIngressKey -f "$account1key1fp"
    json .command selfDelIngressKey .error_code ERR_ONLY_ONE_KEY .value null

    success afterdel2only1remain $a1 -osh selfListIngressKeys
    contain "$account1key1fp"
    nocontain "$account1key2fp"
    json $(cat <<EOS
    .command        selfListIngressKeys
    .error_code     OK
    .value.account  $account1
    .value.keys[0].fingerprint $account1key1fp
    .value.keys[1]  null
EOS
    )

    # ingresskeysfrom=0.0.0.0/0,255.255.255.255, allowoverride=1, noFrom
    configchg 's=^\\\\x22ingressKeysFromAllowOverride\\\\x22.+=\\\\x22ingressKeysFromAllowOverride\\\\x22:1,='
    configchg 's=^\\\\x22ingressKeysFrom\\\\x22:.+=\\\\x22ingressKeysFrom\\\\x22:\\\\x5B\\\\x220.0.0.0/0\\\\x22,\\\\x22255.255.255.255\\\\x22\\\\x5D,='
    _ingress_from_test fromTest1 0.0.0.0/0 255.255.255.255 "$(< $account1key2file.pub)" "$account1key2fp"

    # ingresskeysfrom=0.0.0.0/0,255.255.255.255, allowoverride=1, withFrom
    _ingress_from_test fromTest2 1.2.3.4 5.6.7.8 "from=\"1.2.3.4,5.6.7.8\" $(< $account1key2file.pub)" "$account1key2fp"

    # ingresskeysfrom=0.0.0.0/0,255.255.255.255, allowoverride=0, noFrom
    configchg 's=^\\\\x22ingressKeysFromAllowOverride\\\\x22.+=\\\\x22ingressKeysFromAllowOverride\\\\x22:0,='
    _ingress_from_test fromTest3 0.0.0.0/0 255.255.255.255 "$(< $account1key2file.pub)" "$account1key2fp"

    # ingresskeysfrom=0.0.0.0/0,255.255.255.255 allowoverride=0, withFrom
    _ingress_from_test fromTest4 0.0.0.0/0 255.255.255.255 "from=\\\"1.2.3.4,5.6.7.8\\\" $(< $account1key2file.pub)" "$account1key2fp"

    # ingresskeysfrom=empty, allowoverride=1, noFrom
    configchg 's=^\\\\x22ingressKeysFromAllowOverride\\\\x22.+=\\\\x22ingressKeysFromAllowOverride\\\\x22:1,='
    configchg 's=^\\\\x22ingressKeysFrom\\\\x22:.+=\\\\x22ingressKeysFrom\\\\x22:\\\\x5B\\\\x5D,='
    _ingress_from_test fromTest5 null null "$(< $account1key2file.pub)" "$account1key2fp"

    # ingresskeysfrom=empty, allowoverride=1, withFrom
    _ingress_from_test fromTest6 1.2.3.4 5.6.7.8 "from=\"1.2.3.4,5.6.7.8\" $(< $account1key2file.pub)" "$account1key2fp"

    # ingresskeysfrom=empty, allowoverride=0, noFrom
    configchg 's=^\\\\x22ingressKeysFromAllowOverride\\\\x22.+=\\\\x22ingressKeysFromAllowOverride\\\\x22:0,='
    _ingress_from_test fromTest7 null null "$(< $account1key2file.pub)" "$account1key2fp"

    # ingresskeysfrom=empty allowoverride=0, withFrom
    _ingress_from_test fromTest8 null null "from=\"1.2.3.4,5.6.7.8\" $(< $account1key2file.pub)" "$account1key2fp"

    # delete account1
    grant accountDelete
    script cleanup $a0 --osh accountDelete --account $account1 "<<< \"Yes, do as I say and delete $account1, kthxbye\""
    retvalshouldbe 0
    revoke accountDelete

    # restore default config
    success configrestore $r0 "dd if=$opt_remote_etc_bastion/bastion.conf.bak.$now of=$opt_remote_etc_bastion/bastion.conf"
}

testsuite_selfkeys
unset -f _ingress_from_test
unset -f testsuite_selfkeys
