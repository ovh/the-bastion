# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_groups()
{
    grant accountCreate

    # first we need to create account1, account2 and account3
    success a0_create_a1 $a0 --osh accountCreate --always-active --account $account1 --uid $uid1 --public-key "\"$(cat $account1key1file.pub)\""
    json .error_code OK .command accountCreate .value null

    #grant accountModify

    #success realm modify_account1 $a0 --osh accountModify --pam-auth-bypass yes --account $account1
    #json .error_code OK .command accountModify

    run a1_fail_to_create_a2_because_not_granted $a1 --osh accountCreate --always-active --account $account2 --uid $uid2
    retvalshouldbe 106
    contain "you to be specifically granted"
    json .command null .value null .error_code KO_RESTRICTED_COMMAND

    run a2_cannot_connect_because_does_not_exist $a2 --osh info
    retvalshouldbe 255
    nocontain "Your alias to connect"
    contain "Permission denied"

    # account with no key
    success a0_create_a2_nokey $a0 --osh accountCreate --always-active --account $account2 --uid $uid2 --no-key
    contain "info"
    json .command accountCreate .error_code OK .value      null

    grant accountListIngressKeys

    success a0_check_a2_ingress_keys $a0 --osh accountListIngressKeys --account $account2
    json .command accountListIngressKeys .error_code OK .value.account "$account2" .value.keys '[]'

    revoke accountListIngressKeys

    grant accountDelete
    script a0_delete_a2 $a0 --osh accountDelete --account $account2 "<<< \"Yes, do as I say and delete $account2, kthxbye\""
    retvalshouldbe 0
    json .command accountDelete .error_code OK
    revoke accountDelete
    # /account with no key

    script a0_create_a2 $a0 --osh accountCreate --always-active --account $account2 --uid $uid2 \< $account2key1file.pub
    retvalshouldbe 0
    contain "info"
    json .command accountCreate .error_code OK .value      null

    script a0_fail_to_create_a2_already_exists $a0 --osh accountCreate --always-active --account $account2 --uid $uid2 \< $account2key1file.pub
    retvalshouldbe 100
    contain "already exists"
    json .command accountCreate .error_code KO_ALREADY_EXISTING .value      null

    #success realm modify_account1 $a0 --osh accountModify --pam-auth-bypass yes --account $account2
    #json .error_code OK .command accountModify

    success a2_can_access_the_bastion $a2 --osh info
    contain "Your alias to connect"
    json .command info .error_code OK .value.account $account2

    # now create a3 directly, we'll need it to test groups
    script a0_create_a3 $a0 --osh accountCreate --always-active --account $account3 --uid $uid3 \< $account3key1file.pub
    retvalshouldbe 0
    contain "info"
    json .command accountCreate .error_code OK .value      null

    #success realm modify_account1 $a0 --osh accountModify --pam-auth-bypass yes --account $account3
    #json .error_code OK .command accountModify

    success a3_can_access_the_bastion $a3 --osh info
    contain "Your alias to connect"
    json .command info .error_code OK .value.account $account3

    revoke accountCreate

    # now create g1

    grant groupCreate

    run a2_fail_to_create_g1_with_a1_as_owner_because_not_granted $a2 --osh groupCreate --group $group1 --algo rsa --size 2048 --owner $account1
    retvalshouldbe 106
    contain "you to be specifically granted"
    json .command   null .value      null .error_code KO_RESTRICTED_COMMAND

    plgfail a0_fail_to_create_g1_with_a1_as_owner_because_bad_key_size $a0 --osh groupCreate --group $group1 --algo rsa --size 1024 --owner $account1
    contain "minimum configured key size"
    json .command groupCreate .error_code KO_KEY_SIZE_TOO_SMALL .value      null

    plgfail a0_fail_create_group_reserved_1 $a0 --osh groupCreate --group key --no-key --owner $account1
    json .command groupCreate .error_code ERR_INVALID_PARAMETER

    plgfail a0_fail_create_group_reserved_2 $a0 --osh groupCreate --group keytothegate --no-key --owner $account1
    json .command groupCreate .error_code ERR_INVALID_PARAMETER

    plgfail a0_fail_create_group_invalid_options $a0 --osh groupCreate --group invalid --no-key --algo ed25519 --owner $account1
    json .command groupCreate .error_code ERR_INVALID_PARAMETER

    success a0_create_g1_with_a1_as_owner $a0 --osh groupCreate --group $group1 --algo rsa --size 4096 --owner $account1
    contain "The public key of this group is"
    json $(cat <<EOS
    .command groupCreate
    .error_code OK
    .value.owner $account1
    .value.group $group1
    .value.public_key.family RSA
EOS
    )
    local key0fp
    key0fp=$(get_json | $jq .value.fingerprint)
    # new state: g1[a1(ow,gk,acl,member)]

    # create g3 with a3 as owner to test key generation of a group a3 is not an owner of, without getting the early no-owner deny
    success a0_create_g3_with_a3_as_owner $a0 --osh groupCreate --group $group3 --algo ed25519 --owner $account3

    # test egress key generation as an owner
    run a0_generate_key_g1_fail $a0 --osh groupGenerateEgressKey --group $group1 --algo ed25519
    retvalshouldbe 106
    json .command null .error_code KO_RESTRICTED_COMMAND .value null

    plgfail a3_generate_key_help $a3 --osh groupGenerateEgressKey
    json .command groupGenerateEgressKey .error_code ERR_MISSING_PARAMETER

    plgfail a3_generate_key_g1_fail $a3 --osh groupGenerateEgressKey --group $group1 --algo ed25519
    json .command groupGenerateEgressKey .error_code ERR_NOT_GROUP_OWNER

    success a1_generate_key_g1 $a1 --osh groupGenerateEgressKey --group $group1 --algo ed25519
    json .command groupGenerateEgressKey .error_code OK .value.typecode ssh-ed25519
    local key1id
    local key1fp
    key1id=$(get_json | $jq .value.id)
    key1fp=$(get_json | $jq .value.fingerprint)

    success a1_list_group_keys_g1 $a1 --osh groupInfo --group $group1
    json .command groupInfo .error_code OK ".value.keys.\"$key1fp\".typecode" ssh-ed25519

    # now that we have several keys, take the opportunity to test force-key

    plgfail a1_add_access_force_key_and_pwd_g1 $a1 --osh groupAddServer --host 127.1.2.3 --user-any --port-any --force --force-password '$1$2$3456' --force-key "$key1fp" --group $group1
    json .error_code ERR_INCOMPATIBLE_PARAMETERS

    success a1_add_access_force_key_g1 $a1 --osh groupAddServer --host 127.1.2.3 --user-any --port-any --force --force-key "$key1fp" --group $group1

    success a1_list_servers_check_force_key_g1 $a1 --osh groupListServers --group $group1
    json '.value|.[]|select(.ip=="127.1.2.3")|.forceKey' "$key1fp"

    # try to use the force key

    run a1_connect_g1_with_forcekey $a1 forcedkey@127.1.2.3 -- false
    contain 'Connecting...'
    contain 'FORCED IN ACL'
    contain "$key1fp"
    nocontain "$key0fp"

    success a1_remove_forcekey_acl_g1 $a1 --osh groupDelServer --host 127.1.2.3 --user-any --port-any --group $group1

    # /force-key

    run a0_del_key_g1 $a0 --osh groupDelEgressKey --group $group1 --id $key1id
    retvalshouldbe 106
    json .command null .error_code KO_RESTRICTED_COMMAND .value null

    plgfail a3_del_key_g1 $a3 --osh groupDelEgressKey --group $group1 --id $key1id
    json .command groupDelEgressKey .error_code ERR_NOT_GROUP_OWNER

    success a1_del_key_g1 $a1 --osh groupDelEgressKey --group $group1 --id $key1id
    json .command groupDelEgressKey .error_code OK .value.id "$key1id" .value.fingerprint "$key1fp"
    unset key1id
    unset key1fp

    grant groupDelete
    script a0_delete_g3 $a0 --osh groupDelete --group $group3 '<<<' "$group3"
    retvalshouldbe 0
    revoke groupDelete
    # /egress key generation

    # now test all group-* commands from a2 to grant a3 on g1 => should get an early deny

    run a2_fail_to_addowner_a3_on_g1_early_deny_owner_cmd $a2 --osh groupAddOwner --group $group1 --account $account3
    retvalshouldbe 106
    contain "owner"
    json .command    null .value      null .error_code KO_RESTRICTED_COMMAND

    run a2_fail_to_addmember_a3_on_g1_early_deny_gatekeeper_cmd $a2 --osh groupAddMember --group $group1 --account $account3
    retvalshouldbe 106
    contain "gatekeeper"
    json .command    null .value      null .error_code KO_RESTRICTED_COMMAND

    run a2_fail_to_addserver_on_g1_early_deny_aclkeeper_cmd $a2 --osh groupAddServer --group $group1 --host 1.2.3.4 --port 1234 --user nobody
    retvalshouldbe 106
    contain "aclkeeper"
    json .command    null .value      null .error_code KO_RESTRICTED_COMMAND

    # a0: create g3 and set a0, a2 and a3 as owner/gatekeeper/aclkeeper to rule out early denies for next tests
    # >>>BEGIN
    success a0_create_g3_with_a0_as_owner $a0 --osh groupCreate --group $group3 --algo ecdsa --size 256 --owner $account0
    json .error_code OK .command groupCreate .value.group $group3 .value.owner $account0
    json .value.public_key.family ECDSA .value.public_key.typecode ecdsa-sha2-nistp256 .value.public_key.size 256
    #g3_pubkey=$(get_json | $jq .value.public_key.line)
    #g3_fp=$(    get_json | $jq .value.public_key.fingerprint)

    revoke groupCreate

    success   a0_info_on_g3_after_create $a0 --osh groupInfo --group $group3
    json .error_code OK .command groupInfo .value.group $group3
    json --arg want "$account0" '.value.owners|sort      == ($want|split(" ")|sort)' true
    json --arg want "$account0" '.value.gatekeepers|sort == ($want|split(" ")|sort)' true
    json --arg want "$account0" '.value.aclkeepers|sort  == ($want|split(" ")|sort)' true
    json --arg want "$account0" '.value.members|sort     == ($want|split(" ")|sort)' true
    json .value.guests '[]'

    # ... we also take the opportunity to check with groupinfo that the add/del works as intended
    # ... we always try to remove a3 and fail, then add it, then add it again and fail, then remove it, then remove it and fail, then add it back

    # ...... for owner
    success      a0_del_a3_as_g3_owner_no_change      $a0 --osh groupDelOwner      --group $group3 --account $account3
    json .error_code OK_NO_CHANGE .command groupDelOwner .value null

    success      a0_add_a3_as_g3_owner      $a0 --osh groupAddOwner      --group $group3 --account $account3
    json .error_code OK           .command groupAddOwner .value null

    success          a0_info_on_g3_after_owneradd    $a0 --osh groupInfo --group $group3
    json .error_code OK           .command groupInfo     .value.group $group3
    json --arg want "$account0 $account3" '.value.owners|sort      == ($want|split(" ")|sort)' true
    json --arg want "$account0"           '.value.gatekeepers|sort == ($want|split(" ")|sort)' true
    json --arg want "$account0"           '.value.aclkeepers|sort  == ($want|split(" ")|sort)' true
    json --arg want "$account0"           '.value.members|sort     == ($want|split(" ")|sort)' true
    json .value.guests '[]'

    success      a0_add_a3_as_g3_owner_no_change      $a0 --osh groupAddOwner      --group $group3 --account $account3
    json .error_code OK_NO_CHANGE .command groupAddOwner .value null

    success      a0_del_a3_as_g3_owner      $a0 --osh groupDelOwner      --group $group3 --account $account3
    json .error_code OK .command groupDelOwner .value null

    success   a0_info_on_g3_after_ownerdel $a0 --osh groupInfo --group $group3
    json .error_code OK .command groupInfo .value.group $group3
    json --arg want "$account0" '.value.owners|sort      == ($want|split(" ")|sort)' true
    json --arg want "$account0" '.value.gatekeepers|sort == ($want|split(" ")|sort)' true
    json --arg want "$account0" '.value.aclkeepers|sort  == ($want|split(" ")|sort)' true
    json --arg want "$account0" '.value.members|sort     == ($want|split(" ")|sort)' true
    json .value.guests '[]'

    success      a0_add_a3_as_g3_owner      $a0 --osh groupAddOwner      --group $group3 --account $account3
    json .error_code OK           .command groupAddOwner .value null

    success          a0_info_on_g3_after_owneradd2   $a0 --osh groupInfo --group $group3
    json .error_code OK           .command groupInfo     .value.group $group3
    json --arg want "$account0 $account3" '.value.owners|sort      == ($want|split(" ")|sort)' true
    json --arg want "$account0"           '.value.gatekeepers|sort == ($want|split(" ")|sort)' true
    json --arg want "$account0"           '.value.aclkeepers|sort  == ($want|split(" ")|sort)' true
    json --arg want "$account0"           '.value.members|sort     == ($want|split(" ")|sort)' true
    json .value.guests '[]'

    # ...... for gatekeeper
    success      a0_del_a3_as_g3_gatekeeper_no_change      $a0 --osh groupDelGatekeeper      --group $group3 --account $account3
    json .error_code OK_NO_CHANGE .command groupDelGatekeeper .value null

    success      a0_add_a3_as_g3_gatekeeper      $a0 --osh groupAddGatekeeper      --group $group3 --account $account3
    json .error_code OK           .command groupAddGatekeeper .value null

    success          a0_info_on_g3_after_gatekeeperadd    $a0 --osh groupInfo --group $group3
    json .error_code OK           .command groupInfo     .value.group $group3
    json --arg want "$account0 $account3" '.value.owners|sort      == ($want|split(" ")|sort)' true
    json --arg want "$account0 $account3" '.value.gatekeepers|sort == ($want|split(" ")|sort)' true
    json --arg want "$account0"           '.value.aclkeepers|sort  == ($want|split(" ")|sort)' true
    json --arg want "$account0"           '.value.members|sort     == ($want|split(" ")|sort)' true
    json .value.guests '[]'

    success      a0_add_a3_as_g3_gatekeeper_no_change      $a0 --osh groupAddGatekeeper      --group $group3 --account $account3
    json .error_code OK_NO_CHANGE .command groupAddGatekeeper .value null

    success      a0_del_a3_as_g3_gatekeeper      $a0 --osh groupDelGatekeeper      --group $group3 --account $account3
    json .error_code OK .command groupDelGatekeeper .value null

    success   a0_info_on_g3_after_gatekeeperdel $a0 --osh groupInfo --group $group3
    json .error_code OK .command groupInfo .value.group $group3
    json --arg want "$account0 $account3" '.value.owners|sort      == ($want|split(" ")|sort)' true
    json --arg want "$account0"           '.value.gatekeepers|sort == ($want|split(" ")|sort)' true
    json --arg want "$account0"           '.value.aclkeepers|sort  == ($want|split(" ")|sort)' true
    json --arg want "$account0"           '.value.members|sort     == ($want|split(" ")|sort)' true
    json .value.guests '[]'

    success      a0_add_a3_as_g3_gatekeeper      $a0 --osh groupAddGatekeeper      --group $group3 --account $account3
    json .error_code OK           .command groupAddGatekeeper .value null

    success          a0_info_on_g3_after_gatekeeperadd2   $a0 --osh groupInfo --group $group3
    json .error_code OK           .command groupInfo     .value.group $group3
    json --arg want "$account0 $account3" '.value.owners|sort      == ($want|split(" ")|sort)' true
    json --arg want "$account0 $account3" '.value.gatekeepers|sort == ($want|split(" ")|sort)' true
    json --arg want "$account0"           '.value.aclkeepers|sort  == ($want|split(" ")|sort)' true
    json --arg want "$account0"           '.value.members|sort     == ($want|split(" ")|sort)' true
    json .value.guests '[]'

    # ...... for aclkeeper
    success      a0_del_a3_as_g3_aclkeeper_no_change      $a0 --osh groupDelAclkeeper      --group $group3 --account $account3
    json .error_code OK_NO_CHANGE .command groupDelAclkeeper .value null

    success      a0_add_a3_as_g3_aclkeeper      $a0 --osh groupAddAclkeeper      --group $group3 --account $account3
    json .error_code OK           .command groupAddAclkeeper .value null

    #success postreq a0_g3_removembr  $a0 --osh groupDelMember --group $group3 --account $account0
    success a0_g3_removeaclk $a0 --osh groupDelAclkeeper --group $group3 --account $account0
    success a0_g3_removegk   $a0 --osh groupDelGatekeeper --group $group3 --account $account0

    # START egress passwords

    # ... for groups

    success works1 $a0 --osh groupGeneratePassword --group $group3 --size 17 --do-it
    json .command groupGeneratePassword .error_code OK .value.group $group3
    md5a=$(get_json | $jq '.value.hashes.md5crypt')
    sha256a=$(get_json | $jq '.value.hashes.sha256crypt')
    sha512a=$(get_json | $jq '.value.hashes.sha512crypt')
    type8a=$(get_json | $jq '.value.hashes.type8')
    type9a=$(get_json | $jq '.value.hashes.type9')

    success works $a0 --osh groupListPasswords --group $group3
    json $(cat <<EOS
    .command groupListPasswords
    .error_code OK
    .value[0].metadata.created_by $account0
    .value[0].hashes.md5crypt     $md5a
    .value[0].hashes.sha256crypt  $sha256a
    .value[0].hashes.sha512crypt  $sha512a
    .value[0].hashes.type8        $type8a
    .value[0].hashes.type9        $type9a
    .value[1]                     null
EOS
    )

    success works2 $a0 --osh groupGeneratePassword --group $group3 --size 17 --do-it
    json .command groupGeneratePassword .error_code OK .value.group $group3
    md5b=$(get_json | $jq '.value.hashes.md5crypt')
    sha256b=$(get_json | $jq '.value.hashes.sha256crypt')
    sha512b=$(get_json | $jq '.value.hashes.sha512crypt')
    type8b=$(get_json | $jq '.value.hashes.type8')
    type9b=$(get_json | $jq '.value.hashes.type9')

    success works $a0 --osh groupListPasswords --group $group3
    json $(cat <<EOS
    .command groupListPasswords
    .error_code OK
    .value[0].metadata.created_by $account0
    .value[0].hashes.md5crypt     $md5b
    .value[0].hashes.sha256crypt  $sha256b
    .value[0].hashes.sha512crypt  $sha512b
    .value[0].hashes.type8        $type8b
    .value[0].hashes.type9        $type9b
    .value[1].hashes.md5crypt     $md5a
    .value[1].hashes.sha256crypt  $sha256a
    .value[1].hashes.sha512crypt  $sha512a
    .value[1].hashes.type8        $type8a
    .value[1].hashes.type9        $type9a
    .value[2]                     null
EOS
    )
    unset md5a sha256a sha512a type8a type9a
    unset md5b sha256b sha512b type8b type9b

    # ... for accounts

    grant accountGeneratePassword

    success works1 $a0 --osh accountGeneratePassword --account $account1 --do-it
    json .command accountGeneratePassword .error_code OK .value.account $account1
    md5a=$(get_json | $jq '.value.hashes.md5crypt')
    sha256a=$(get_json | $jq '.value.hashes.sha256crypt')
    sha512a=$(get_json | $jq '.value.hashes.sha512crypt')
    type8a=$(get_json | $jq '.value.hashes.type8')
    type9a=$(get_json | $jq '.value.hashes.type9')

    revoke accountGeneratePassword
    grant accountListPasswords

    success works $a0 --osh accountListPasswords --account $account1
    json $(cat <<EOS
    .command accountListPasswords
    .error_code OK
    .value[0].metadata.created_by $account0
    .value[0].hashes.md5crypt     $md5a
    .value[0].hashes.sha256crypt  $sha256a
    .value[0].hashes.sha512crypt  $sha512a
    .value[0].hashes.type8        $type8a
    .value[0].hashes.type9        $type9a
    .value[1]                     null
EOS
    )

    revoke accountListPasswords

    success works2 $a1 --osh selfGeneratePassword --do-it
    json .command selfGeneratePassword .error_code OK
    md5b=$(get_json | $jq '.value.hashes.md5crypt')
    sha256b=$(get_json | $jq '.value.hashes.sha256crypt')
    sha512b=$(get_json | $jq '.value.hashes.sha512crypt')
    type8b=$(get_json | $jq '.value.hashes.type8')
    type9b=$(get_json | $jq '.value.hashes.type9')

    success works $a1 --osh selfListPasswords
    json $(cat <<EOS
    .command selfListPasswords
    .error_code OK
    .value[0].metadata.created_by $account1
    .value[0].hashes.md5crypt     $md5b
    .value[0].hashes.sha256crypt  $sha256b
    .value[0].hashes.sha512crypt  $sha512b
    .value[0].hashes.type8        $type8b
    .value[0].hashes.type9        $type9b
    .value[1].metadata.created_by $account0
    .value[1].hashes.md5crypt     $md5a
    .value[1].hashes.sha256crypt  $sha256a
    .value[1].hashes.sha512crypt  $sha512a
    .value[1].hashes.type8        $type8a
    .value[1].hashes.type9        $type9a
    .value[2]                     null
EOS
    )
    unset md5a sha256a sha512a type8a type9a
    unset md5b sha256b sha512b type8b type9b


    # END egress passwords

    success          a0_info_on_g3_after_aclkeeperadd    $a0 --osh groupInfo --group $group3
    json .error_code OK           .command groupInfo     .value.group $group3
    json --argjson want "[\"$account0\",\"$account3\"]" '.value.owners|sort      == ($want|sort)' true
    json --argjson want "[              \"$account3\"]" '.value.gatekeepers|sort == ($want|sort)' true
    json --argjson want "[              \"$account3\"]" '.value.aclkeepers|sort  == ($want|sort)' true
    json --argjson want "[\"$account0\"]"               '.value.members|sort     == ($want|sort)' true
    json --argjson want "[]"                            '.value.guests|sort      == ($want|sort)' true

    success      a0_add_a3_as_g3_aclkeeper_no_change      $a0 --osh groupAddAclkeeper      --group $group3 --account $account3
    json .error_code OK_NO_CHANGE .command groupAddAclkeeper .value null

    success      a0_del_a3_as_g3_aclkeeper      $a0 --osh groupDelAclkeeper      --group $group3 --account $account3
    json .error_code OK .command groupDelAclkeeper .value null

    success   a0_info_on_g3_after_aclkeeperdel $a0 --osh groupInfo --group $group3
    json .error_code OK .command groupInfo .value.group $group3
    json --argjson want "[\"$account0\",\"$account3\"]" '.value.owners|sort      == ($want|sort)' true
    json --argjson want "[              \"$account3\"]" '.value.gatekeepers|sort == ($want|sort)' true
    json --argjson want "[             ]"               '.value.aclkeepers|sort  == ($want|sort)' true
    json --argjson want "[\"$account0\"]"               '.value.members|sort     == ($want|sort)' true
    json --argjson want "[]"                            '.value.guests|sort      == ($want|sort)' true

    success      a0_add_a3_as_g3_aclkeeper      $a0 --osh groupAddAclkeeper      --group $group3 --account $account3
    json .error_code OK           .command groupAddAclkeeper .value null

    success          a0_info_on_g3_after_aclkeeperadd2   $a0 --osh groupInfo --group $group3
    json .error_code OK           .command groupInfo     .value.group $group3
    json --argjson want "[\"$account0\",\"$account3\"]" '.value.owners|sort      == ($want|sort)' true
    json --argjson want "[              \"$account3\"]" '.value.gatekeepers|sort == ($want|sort)' true
    json --argjson want "[              \"$account3\"]" '.value.aclkeepers|sort  == ($want|sort)' true
    json --argjson want "[\"$account0\"]"               '.value.members|sort     == ($want|sort)' true
    json --argjson want "[]"                            '.value.guests|sort      == ($want|sort)' true

    # ...... for member
    success      a3_del_a3_as_g3_member_no_change      $a3 --osh groupDelMember      --group $group3 --account $account3
    json .error_code OK_NO_CHANGE .command groupDelMember .value null

    success      a3_add_a3_as_g3_member      $a3 --osh groupAddMember      --group $group3 --account $account3
    json .error_code OK           .command groupAddMember .value null

    success          a0_info_on_g3_after_memberadd    $a0 --osh groupInfo --group $group3
    json .error_code OK           .command groupInfo     .value.group $group3
    json --argjson want "[\"$account0\",\"$account3\"]" '.value.owners|sort      == ($want|sort)' true
    json --argjson want "[              \"$account3\"]" '.value.gatekeepers|sort == ($want|sort)' true
    json --argjson want "[              \"$account3\"]" '.value.aclkeepers|sort  == ($want|sort)' true
    json --argjson want "[\"$account0\",\"$account3\"]" '.value.members|sort     == ($want|sort)' true
    json --argjson want "[]"                            '.value.guests|sort      == ($want|sort)' true

    success      a3_add_a3_as_g3_member_no_change      $a3 --osh groupAddMember      --group $group3 --account $account3
    json .error_code OK_NO_CHANGE .command groupAddMember .value null

    success      a3_del_a3_as_g3_member      $a3 --osh groupDelMember      --group $group3 --account $account3
    json .error_code OK .command groupDelMember .value null

    success   a0_info_on_g3_after_memberdel $a0 --osh groupInfo --group $group3
    json .error_code OK .command groupInfo .value.group $group3
    json --argjson want "[\"$account0\",\"$account3\"]" '.value.owners|sort      == ($want|sort)' true
    json --argjson want "[              \"$account3\"]" '.value.gatekeepers|sort == ($want|sort)' true
    json --argjson want "[              \"$account3\"]" '.value.aclkeepers|sort  == ($want|sort)' true
    json --argjson want "[\"$account0\"]"               '.value.members|sort     == ($want|sort)' true
    json --argjson want "[]"                            '.value.guests|sort      == ($want|sort)' true

    success      a3_add_a3_as_g3_member      $a3 --osh groupAddMember      --group $group3 --account $account3
    json .error_code OK           .command groupAddMember .value null

    success          a0_info_on_g3_after_memberadd2   $a0 --osh groupInfo --group $group3
    json .error_code OK           .command groupInfo     .value.group $group3
    json --argjson want "[\"$account0\",\"$account3\"]" '.value.owners|sort      == ($want|sort)' true
    json --argjson want "[              \"$account3\"]" '.value.gatekeepers|sort == ($want|sort)' true
    json --argjson want "[              \"$account3\"]" '.value.aclkeepers|sort  == ($want|sort)' true
    json --argjson want "[\"$account0\",\"$account3\"]" '.value.members|sort     == ($want|sort)' true
    json --argjson want "[]"                            '.value.guests|sort      == ($want|sort)' true

    # ...... ok now resume to just adding a2 to avoid early denies as stated above

    success      a3_add_a2_as_g3_owner           $a3 --osh groupAddOwner      --group $group3 --account $account2
    success a2_add_himself_as_g3_gatekeeper $a2 --osh groupAddGatekeeper --group $group3 --account $account2
    success  a2_add_himself_as_g3_aclkeeper  $a2 --osh groupAddAclkeeper  --group $group3 --account $account2

    # new state: g1[a1(ow,gk,acl,member)] g3[a0,a2,a3(ow,gk,acl,member)]
    # check with groupInfo that the data is correct

    success          a0_info_on_g3_after_a2_add   $a0 --osh groupInfo --group $group3
    json .error_code OK           .command groupInfo     .value.group $group3
    json --argjson want "[\"$account0\",\"$account3\",\"$account2\"]" '.value.owners|sort      == ($want|sort)' true
    json --argjson want "[              \"$account3\",\"$account2\"]" '.value.gatekeepers|sort == ($want|sort)' true
    json --argjson want "[              \"$account3\",\"$account2\"]" '.value.aclkeepers|sort  == ($want|sort)' true
    json --argjson want "[\"$account0\",\"$account3\"]"               '.value.members|sort     == ($want|sort)' true
    json --argjson want "[]"                                          '.value.guests|sort      == ($want|sort)' true

    # now come gatekeeper tests, first check that a2 can't do anything privileged on g1

    plgfail       a2_fail_add_a3_as_g1_owner      $a2 --osh groupAddOwner        --group $group1 --account $account3
    json .command groupAddOwner .error_code ERR_NOT_GROUP_OWNER .value null

    plgfail  a2_fail_add_a3_as_g1_gatekeeper $a2 --osh groupAddGatekeeper   --group $group1 --account $account3
    json .command groupAddGatekeeper .error_code ERR_NOT_GROUP_OWNER .value null

    plgfail  a2_fail_add_a3_as_g1_aclkeeper $a2 --osh groupAddAclkeeper      --group $group1 --account $account3
    json .command groupAddAclkeeper .error_code ERR_NOT_GROUP_OWNER .value null

    plgfail      a2_fail_add_a3_as_g1_member     $a2 --osh groupAddMember       --group $group1 --account $account3
    json .command groupAddMember .error_code ERR_NOT_GROUP_GATEKEEPER .value null

    plgfail a2_fail_add_a3_as_g1_guest      $a2 --osh groupAddGuestAccess  --group $group1 --account $account3 --host 1.2.3.7 --port 15487 --user username
    json .command groupAddGuestAccess .error_code ERR_NOT_GROUP_GATEKEEPER .value null

    plgfail      a2_fail_add_server_to_g1        $a2 --osh groupAddServer       --group $group1 --host 1.2.3.7 --port 15487 --user username
    json .command groupAddServer .error_code ERR_NOT_GROUP_ACLKEEPER .value null

    # ... then grant a2 as g1 aclkeeper

    success a1_add_a2_as_g1_aclkeeper $a1 --osh groupAddAclkeeper --group $group1 --account $account2
    json .command groupAddAclkeeper .error_code OK .value null

    # new state: g1[a1(ow,gk,acl,member) a2(acl)] g3[a0,a2,a3(ow,gk,acl,member)]

    # --all requires auditor rights
    plgfail a0_groupInfo_all_not_auditor $a0 --osh groupInfo --all
    json .command groupInfo .error_code ERR_ACCESS_DENIED .value null

    grant auditor

    success a0_groupInfo_all $a0 --osh groupInfo --all
    json $(cat <<EOS
    .command groupInfo
    .error_code OK
    .value|length 2
    .value["$group1"].aclkeepers[0]  $account1
    .value["$group1"].aclkeepers[1]  $account2
    .value["$group1"].gatekeepers[0] $account1
    .value["$group1"].members[0]     $account1
    .value["$group1"].owners[0]      $account1
    .value["$group1"].guests|length    0
    .value["$group1"].keys|.[]|.family RSA
    .value["$group3"].owners[0]      $account0
    .value["$group3"].owners[1]      $account3
    .value["$group3"].owners[2]      $account2
EOS
)

    revoke auditor

    # then check that owner/gatekeeper commands still don't work

    plgfail       a2_fail_add_a3_as_g1_owner      $a2 --osh groupAddOwner        --group $group1 --account $account3
    json .command groupAddOwner .error_code ERR_NOT_GROUP_OWNER .value null

    plgfail  a2_fail_add_a3_as_g1_gatekeeper $a2 --osh groupAddGatekeeper   --group $group1 --account $account3
    json .command groupAddGatekeeper .error_code ERR_NOT_GROUP_OWNER .value null

    plgfail   a2_fail_add_a3_as_g1_aclkeeper  $a2 --osh groupAddAclkeeper    --group $group1 --account $account3
    json .command groupAddAclkeeper .error_code ERR_NOT_GROUP_OWNER .value null

    plgfail      a2_fail_add_a3_as_g1_member     $a2 --osh groupAddMember       --group $group1 --account $account3
    json .command groupAddMember .error_code ERR_NOT_GROUP_GATEKEEPER .value null

    plgfail a2_fail_add_a3_as_g1_guest      $a2 --osh groupAddGuestAccess  --group $group1 --account $account3 --host 1.2.3.7 --port 15487 --user username
    json .command groupAddGuestAccess .error_code ERR_NOT_GROUP_GATEKEEPER .value null

    # and see that aclkeeper command now works from a2 on g1
    # TODO test elsewhere the syntax/good functioning of those commands with all combinations of parameters allowed. here we test the RIGHTS.

    success a2_add_server_to_g1_works $a2 --osh groupAddServer --group $group1 --host 127.0.0.1 --port 22 --user g1
    json .command groupAddServer .error_code OK .value.ip 127.0.0.1 .value.group $group1 .value.port 22 .value.user g1
    contain "have access to yourself"

    success a2_add_server_to_g1_force_but_dup               $a2 --osh groupAddServer --group $group1 --host 127.0.0.1 --port 22 --user g1 --force
    json .command groupAddServer .error_code OK_NO_CHANGE .value null

    success a2_add_server_to_g1               $a2 --osh groupAddServer --group $group1 --host 127.0.0.2 --port 22 --user g2 --force --comment '"\"this is a comment\""'
    json .command groupAddServer .error_code OK .value.ip 127.0.0.2 .value.group $group1 .value.user g2 .value.comment "this is a comment"

    # new state: g1[a1(ow,gk,acl,member) a2(acl) acl(g1@127.0.0.1:22,g2@127.0.0.2:22)] g3[a0,a2,a3(ow,gk,acl,member)]

    # ... then grant a2 as g1 gatekeeper and remove it as aclkeeper

    success a1_add_a2_as_g1_gatekeeper $a1 --osh groupAddGatekeeper --group $group1 --account $account2
    json .command groupAddGatekeeper .error_code OK .value null

    success  a1_del_a2_as_g1_aclkeeper  $a1 --osh groupDelAclkeeper  --group $group1 --account $account2
    json .command groupDelAclkeeper .error_code OK .value null

    # new state: g1[a1(ow,gk,acl,member) a2(gk) acl(g1@127.0.0.1:22,g2@127.0.0.2:22)] g3[a0,a2,a3(ow,gk,acl,member)]

    # then check that owner/aclkeeper commands still don't work

    plgfail       a2_fail_add_a3_as_g1_owner      $a2 --osh groupAddOwner        --group $group1 --account $account3
    json .command groupAddOwner .error_code ERR_NOT_GROUP_OWNER .value null

    plgfail  a2_fail_add_a3_as_g1_gatekeeper $a2 --osh groupAddGatekeeper   --group $group1 --account $account3
    json .command groupAddGatekeeper .error_code ERR_NOT_GROUP_OWNER .value null

    plgfail   a2_fail_add_a3_as_g1_aclkeeper  $a2 --osh groupAddAclkeeper    --group $group1 --account $account3
    json .command groupAddAclkeeper .error_code ERR_NOT_GROUP_OWNER .value null

    plgfail      a2_fail_add_server_to_g1        $a2 --osh groupAddServer       --group $group1 --host 1.2.3.7 --port 15487 --user username
    json .command groupAddServer .error_code ERR_NOT_GROUP_ACLKEEPER .value null

    # ... and now try working gatekeeper commands

    run a3_noaccess_not_a_member_of_g1 $a3 g1@127.0.0.1
    retvalshouldbe 107

    success a2_add_a3_as_g1_member $a2 --osh groupAddMember --group $group1 --account $account3

    # new state: g1[a1(ow,gk,acl,member) a2(gk) a3(member) acl(g1@127.0.0.1:22,g2@127.0.0.2:22)] g3[a0,a2,a3(ow,gk,acl,member)]

    # a3 is now a member of g1 so should be able to access the 2 added user@ip:port of g1
    # (err255 because the pubkey is not there, but we're only testing if the bastion code allows the connection)

    run a3_access_g1_as_member_a $a3 g1@127.0.0.1
    retvalshouldbe 255
    contain "allowed ... log on"
    contain 'Permission denied (publickey'

    run a3_access_g1_as_member_b $a3 g2@127.0.0.2
    retvalshouldbe 255
    contain "allowed ... log on"
    contain 'Permission denied (publickey'

    # ttyrec: take the opportunity to test selfListSessions/selfPlaySession as we just recorded a ttyrec
    success a3_selfListSessions $a3 --osh selfListSessions --host 127.0.0.2 --user g2 --type ssh
    json .command selfListSessions .error_code OK .value[0].allowed 1
    local sessionid
    sessionid=$(get_json | $jq '.value[0].id')

    plgfail a3_selfPlaySession_nonexisting $a3 --osh selfPlaySession --id 123456
    json .command selfPlaySession .error_code ERR_NOT_FOUND

    script a3_selfPlaySession_existing $a3 --osh selfPlaySession --id $sessionid '< /dev/null'
    retvalshouldbe 0
    json .command selfPlaySession .error_code OK
    contain 'Total Recall'
    contain 'Permission denied (publickey'
    nocontain 'n/a'
    # /ttyrec

    run a3_access_g1_as_member_but_ip_not_in_group $a3 g1@127.0.0.3
    retvalshouldbe 107
    json .error_code KO_ACCESS_DENIED

    # try to add a3 as a guest of g1, should not work because already a member
    plgfail a1_add_a3_guest_of_g1_fail_already_member $a1 --osh groupAddGuestAccess --group $group1 --account $account3 --user g2 --host 127.0.0.2 --port 22
    json .command groupAddGuestAccess .error_code ERR_MEMBER_CANNOT_BE_GUEST

    # now remove membership of a3

    success a2_del_a3_as_g1_member $a2 --osh groupDelMember --group $group1 --account $account3
    json .command groupDelMember .error_code OK .value null

    # add a guest access to a3...
    success a1_add_a3_guest_of_g1 $a1 --osh groupAddGuestAccess --group $group1 --account $account3 --user g2 --host 127.0.0.2 --port 22
    json .command groupAddGuestAccess .error_code OK

    # ... then add it as member again: it should remove the guest access we've added just above...
    success a1_add_a3_member_of_g1 $a1 --osh groupAddMember --group $group1 --account $account3
    contain "Cleaning these guest accesses"
    json .command groupAddMember .error_code OK

    # ... then remove its membership
    success a2_del_a3_as_g1_member_2 $a2 --osh groupDelMember --group $group1 --account $account3
    json .command groupDelMember .error_code OK .value null

    # ... and verify there's no ghost guest access remaining
    success a2_list_a3_guest_access_g1_empty $a2 --osh groupListGuestAccesses --group $group1 --account $account3
    json .command groupListGuestAccesses .error_code OK_EMPTY .value null

    # new state: g1[a1(ow,gk,acl,member) a2(gk) acl(g1@127.0.0.1:22,g2@127.0.0.2:22)] g3[a0,a2,a3(ow,gk,acl,member)]

    # check that a3 can no longer access the ips
    run a3_fail_access_g1_as_member_a $a3 g1@127.0.0.1
    retvalshouldbe 107
    json .error_code KO_ACCESS_DENIED

    run a3_fail_access_g1_as_member_b $a3 g2@127.0.0.2
    retvalshouldbe 107
    json .error_code KO_ACCESS_DENIED

    # and now we add a3 as guest of g1 with only access to 127.0.0.2 and not 127.0.0.1

    plgfail a2_fail_add_a3_as_g1_guest_invalid_tuple $a2 --osh groupAddGuestAccess --group $group1 --account $account3 --host 1.2.3.7 --port 15487 --user username
    json .command groupAddGuestAccess .error_code ERR_GROUP_HAS_NO_ACCESS

    plgfail a2_add_a3_as_g1_guest_1 $a2 --osh groupAddGuestAccess --group $group1 --account $account3 --host 127.0.0.1 --user g1 --port 222
    json .command groupAddGuestAccess .error_code ERR_GROUP_HAS_NO_ACCESS

    plgfail a2_add_a3_as_g1_guest_2 $a2 --osh groupAddGuestAccess --group $group1 --account $account3 --host 127.0.0.1 --user g1 --port-any
    json .command groupAddGuestAccess .error_code ERR_GROUP_HAS_NO_ACCESS

    plgfail a2_add_a3_as_g1_guest_3 $a2 --osh groupAddGuestAccess --group $group1 --account $account3 --host 127.0.0.1 --user g9 --port 22
    json .command groupAddGuestAccess .error_code ERR_GROUP_HAS_NO_ACCESS

    plgfail a2_add_a3_as_g1_guest_4 $a2 --osh groupAddGuestAccess --group $group1 --account $account3 --host 127.0.0.9 --user g1 --port 22
    json .command groupAddGuestAccess .error_code ERR_GROUP_HAS_NO_ACCESS

    success a2_add_a3_as_g1_guest_and_works $a2 --osh groupAddGuestAccess --group $group1 --account $account3 --host 127.0.0.1 --user g1 --port 22
    json .error_code OK

    # new state: g1[a1(ow,gk,acl,member) a2(gk) a3(g1@127.0.0.1:22) acl(g1@127.0.0.1:22,g2@127.0.0.2:22)] g3[a0,a2,a3(ow,gk,acl,member)]

    success a2_add_a3_as_g1_guest_and_dupe $a2 --osh groupAddGuestAccess --group $group1 --account $account3 --host 127.0.0.1 --user g1 --port 22
    json .error_code OK_NO_CHANGE

    run a3_noaccess_guest_but_not_to_this_g1_tuple $a3 g2@127.0.0.2
    retvalshouldbe 107

    run a3_access_because_guest $a3 g1@127.0.0.1
    retvalshouldbe 255
    contain "allowed ... log on"
    contain 'Permission denied (publickey'

    # now we want to try selfListAccesses, work with a3 that has a groupguest access to g1: add a server to g3 (he's a member of it), and a personal access

    success a3_add_server_to_g3 $a3 --osh groupAddServer --group $group3 --host 10.20.0.0/17 --port-any --user-any

    grant accountAddPersonalAccess

    run a0_add_personal_access_to_a3_works_slash_1 $a0 --osh accountAddPersonalAccess --account $account3 --host 77.66.55.0/24 --user-any --port-any
    json .command accountAddPersonalAccess .error_code OK .value.ip 77.66.55.0/24 .value.port null .value.user null

    run a0_add_personal_access_to_a3_fail_badslash $a0 --osh accountAddPersonalAccess --account $account3 --host 77.66.55.0/23 --user-any --port-any
    json .command null .error_code KO_INVALID_IP .value null

    run a0_add_personal_access_to_a3_works_slash_2 $a0 --osh accountAddPersonalAccess --account $account3 --host 1.2.3.4/32 --user-any --port-any
    json .command accountAddPersonalAccess .error_code OK .value.ip 1.2.3.4 .value.port null .value.user null

    success a0_add_personal_access_to_a3_works $a0 --osh accountAddPersonalAccess --account $account3 --host 77.66.55.4 --user-any --port-any

    local todo_inc todo_port todo_ip todo_user
    (( todo_inc=1 ))
    for todo_port in --port-any "--port 33"
    do
        for todo_user in --user-any "--user usah"
        do
            (( todo_inc++ ))
            for todo_ip in 2.2.$todo_inc.2 2.2.$todo_inc.3/32 2.2.$todo_inc.0/24 2.$todo_inc.5.0/23
            do
                run a0a3_add_personalxs_batch $a0 --osh  accountAddPersonalAccess --account $account3 --host $todo_ip $todo_port $todo_user
                if [ "$todo_ip" = "2.$todo_inc.5.0/23" ]; then
                    retvalshouldbe 100
                else
                    retvalshouldbe 0
                fi
            done

            (( todo_inc++ ))
            for todo_ip in 2.2.$todo_inc.2 2.2.$todo_inc.3/32 2.2.$todo_inc.0/24 2.$todo_inc.5.0/23
            do
                run a2g3_add_server_batch $a2 --osh  groupAddServer --group $group3 --host $todo_ip $todo_port $todo_user --force
                if [ "$todo_ip" = "2.$todo_inc.5.0/23" ]; then
                    retvalshouldbe 100
                else
                    retvalshouldbe 0
                fi
            done

            (( todo_inc++ ))
            success a1g1_add_server_batch $a1 --osh  groupAddServer --group $group1 --host 2.2.$todo_inc.0/24 $todo_port $todo_user --force
            success a2g1a3_add_guestxs_batch $a2 --osh  groupAddGuestAccess --group $group1 --account $account3 --host 2.2.$todo_inc.66 $todo_port $todo_user
            plgfail a2g1a3_add_guestxs_batch $a2 --osh  groupAddGuestAccess --group $group1 --account $account3 --host 2.3.$todo_inc.1 $todo_port $todo_user
        done
    done

    # TODO check after removing a group access that the guest access no longer works

    success a3_list_own_accesses $a3 --osh selfListAccesses
    json .command selfListAccesses .error_code OK
    json --splitsort '[.value[]|.type]' "group-member group-guest personal"
    json --splitsort '[.value[]|.group]' "$group3 $group1 null"
    json --splitsort '[.value[]|select(.type == "group-member" and .group == "'$group3'").acl[]|.user]' "null null null null usah usah usah null null null usah usah usah"
    json --splitsort '[.value[]|select(.type == "group-member" and .group == "'$group3'").acl[]|.user]' "null null null null usah usah usah null null null usah usah usah"
    json --splitsort '[.value[]|select(.type == "group-member" and .group == "'$group3'").acl[]|.ip]' "10.20.0.0/17 2.2.3.2 2.2.3.0/24 2.2.3.3 2.2.6.2 2.2.6.3 2.2.6.0/24 2.2.9.2 2.2.9.3 2.2.9.0/24 2.2.12.2 2.2.12.0/24 2.2.12.3"
    json --splitsort '[.value[]|select(.type == "group-member" and .group == "'$group3'").acl[]|.port]' "null null null null null null null 33 33 33 33 33 33"
    json --splitsort '[.value[]|select(.type == "group-guest"  and .group == "'$group1'").acl[]|.user]' "g1 null usah null usah"
    json --splitsort '[.value[]|select(.type == "group-guest"  and .group == "'$group1'").acl[]|.ip]' "127.0.0.1 2.2.4.66 2.2.7.66 2.2.10.66 2.2.13.66"
    json --splitsort '[.value[]|select(.type == "group-guest"  and .group == "'$group1'").acl[]|.port]' "22 null null 33 33"
    json --splitsort '[.value[]|select(.type == "personal").acl[]|.user]' "null null null null null null usah usah usah null null null usah usah usah"
    json --splitsort '[.value[]|select(.type == "personal").acl[]|.ip]' "77.66.55.0/24 1.2.3.4 2.2.2.2 77.66.55.4 2.2.2.0/24 2.2.2.3 2.2.5.2 2.2.5.0/24 2.2.5.3 2.2.8.2 2.2.8.0/24 2.2.8.3 2.2.11.2 2.2.11.0/24 2.2.11.3"
    json --splitsort '[.value[]|select(.type == "personal").acl[]|.port]' "null null null null null null null null null 33 33 33 33 33 33"
    contain "33 accesses listed"

    # TODO check in selfListAccesses that comments / addedDate addedBy remain

    # TODO try keys with from="" and command="" etc (also in selfAddIngressKey)

    revoke accountAddPersonalAccess
    grant accountDelPersonalAccess

    (( todo_inc=1 ))
    for todo_port in --port-any "--port 33"
    do
        for todo_user in --user-any "--user usah"
        do
            (( todo_inc++ ))
            for todo_ip in 2.2.$todo_inc.2 2.2.$todo_inc.3/32 2.2.$todo_inc.0/24 2.$todo_inc.5.0/23
            do
                run a0a3_del_personalxs_batch $a0 --osh  accountDelPersonalAccess --account $account3 --host $todo_ip $todo_port $todo_user
                if [ "$todo_ip" = "2.$todo_inc.5.0/23" ]; then
                    retvalshouldbe 100
                else
                    retvalshouldbe 0
                fi
            done

            (( todo_inc++ ))
            for todo_ip in 2.2.$todo_inc.2 2.2.$todo_inc.3/32 2.2.$todo_inc.0/24 2.$todo_inc.5.0/23
            do
                run a2g3_del_server_batch $a2 --osh  groupDelServer --group $group3 --host $todo_ip $todo_port $todo_user --force
                if [ "$todo_ip" = "2.$todo_inc.5.0/23" ]; then
                    retvalshouldbe 100
                else
                    retvalshouldbe 0
                fi
            done

            (( todo_inc++ ))
            success a1g1_del_server_batch $a1 --osh  groupDelServer --group $group1 --host 2.2.$todo_inc.0/24 $todo_port $todo_user --force
            success a2g1a3_del_guestxs_batch_1 $a2 --osh  groupDelGuestAccess --group $group1 --account $account3 --host 2.2.$todo_inc.66 $todo_port $todo_user
            # TODO next line should be OK_NO_CHANGE
            success a2g1a3_del_guestxs_batch_2 $a2 --osh  groupDelGuestAccess --group $group1 --account $account3 --host 2.3.$todo_inc.1 $todo_port $todo_user
        done
    done

    revoke accountDelPersonalAccess
    grant accountAddPersonalAccess

    success a3_list_own_accesses $a3 --osh selfListAccesses
    json .command selfListAccesses .error_code OK
    contain REGEX '77\.66\.55\.0/24[[:space:]]+\(any\)[[:space:]]+\(any\)[[:space:]]+personal[[:space:]]+'$account0'[[:space:]]'
    contain REGEX '1\.2\.3\.4[[:space:]]+\(any\)[[:space:]]+\(any\)[[:space:]]+personal[[:space:]]+'$account0'[[:space:]]'
    contain REGEX '77\.66\.55\.4[[:space:]]+\(any\)[[:space:]]+\(any\)[[:space:]]+personal[[:space:]]+'$account0'[[:space:]]'
    contain REGEX '127\.0\.0\.1[[:space:]]+22[[:space:]]+g1[[:space:]]+'$group1'\(group-guest\)[[:space:]]+'$account2'[[:space:]]'
    contain REGEX '10\.20\.0\.0/17[[:space:]]+\(any\)[[:space:]]+\(any\)[[:space:]]+'$group3'\(group-member\)[[:space:]]+'$account3'[[:space:]]'
    contain "5 accesses listed"

    run notingroup $a1 --osh accountDelete --account $account2
    retvalshouldbe 106
    contain "you to be specifically granted"
    nocontain "attempting to continue"
    json .command   null .value      null .error_code KO_RESTRICTED_COMMAND

    #sudo usermod -a -G osh-accountDelete $account1
    grant accountDelete
    script sudookbadconfirm $a0 --osh accountDelete --account $account2 "<<<" "foobar"
    retvalshouldbe 100
    contain "aborted"
    nocontain "attempting to continue"
    json .command accountDelete .value      null .error_code ERR_OPERATOR_IS_DRUNK

    script sudook $a0 --osh accountDelete --account $account2 "<<< \"Yes, do as I say and delete $account2, kthxbye\""
    retvalshouldbe 0
    nocontain "attempting to continue"
    json .command accountDelete .error_code OK .value.account $account2

    script sudooknotexists $a0 --osh accountDelete --account $account2 "<<< \"Yes, do as I say and delete $account2, kthxbye\""
    retvalshouldbe 100
    contain "Account '$account2' doesn't exist"
    nocontain "attempting to continue"
    json .command accountDelete .error_code KO_NOT_FOUND .value      null

    revoke accountDelete

    run nosuchaccount $a2 --osh info
    retvalshouldbe 255
    contain "Permission denied"
    nocontain "Your alias to connect"

    grant accountCreate

    script sudookrecreate $a0 --osh accountCreate --always-active --account $account2 --uid $uid2 \< $account2key1file.pub
    retvalshouldbe 0
    contain "info"
    json .command accountCreate .error_code OK .value      null

    revoke accountCreate
    grant groupCreate

    #success realm modify_account1 $a0 --osh accountModify --pam-auth-bypass yes --account $account2
    #json .error_code OK .command accountModify

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2() servers()
    plgfail dup $a0 --osh groupCreate --group $group1 --algo rsa --size 4096 --owner $account2
    contain "The group $group1 already exists"
    json .command groupCreate .error_code KO_ALREADY_EXISTING .value      null

    revoke groupCreate

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2() servers()
    success noaccess $a2 --osh groupList --all
    json $(cat <<EOS
    .command groupList
    .error_code OK
    .value["$group1"].flags[0]   no-access
    .value["$group1"].flags[1]   null
EOS
    )

    # --- now test some group-*/ plugins and ensure that a2 gets early denied because he's not gatekeeper/aclkeeper/owner of any group

    # early deny for group-gatekeeper plugins
    # group1:a1(owner,aclkeeper,gatekeeper,member)
    run earlydeny $a2 --osh groupAddGatekeeper --group $group1 --account $account1
    retvalshouldbe 106
    json .command   null .value      null .error_code KO_RESTRICTED_COMMAND

    # early deny for group-aclkeeper plugins
    # group1:a1(owner,aclkeeper,gatekeeper,member)
    run earlydeny $a2 --osh groupAddAclkeeper --group $group1 --account $account1
    retvalshouldbe 106
    json .command   null .value      null .error_code KO_RESTRICTED_COMMAND

    # early deny for group-owner plugins
    # group1:a1(owner,aclkeeper,gatekeeper,member)
    run earlydeny $a2 --osh groupAddOwner --group $group1 --account $account1
    retvalshouldbe 106
    json .command   null .value      null .error_code KO_RESTRICTED_COMMAND

    # early deny for restricted plugins
    # group1:a1(owner,aclkeeper,gatekeeper,member)
    run earlydeny $a2 --osh accountListAccesses --account $account1
    retvalshouldbe 106
    json .command   null .value      null .error_code KO_RESTRICTED_COMMAND

    # now just add a2 as aclk/groupk of group3, we won't use but it's just so that for other tests it won't get early-denied for group cmds
    success a0_add_gatekeeper_g3_a2 $a0 --osh groupAddGatekeeper --account $account2 --group $group3
    success  a0_add_aclkeeper_g3_a2  $a0 --osh groupAddAclkeeper  --account $account2 --group $group3

    # done with group3

    # ---

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2() servers()
    plgfail notanaclkeeper $a2 --osh groupAddServer --group $group1 --host 127.0.0.10 --port-any --user-any
    contain "an aclkeeper"
    json .command   groupAddServer .error_code ERR_NOT_GROUP_ACLKEEPER .value null

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2() servers()
    plgfail firstadd $a1 --osh groupAddServer --group $group1 --host 127.0.0.10 --port-any --user-any
    contain "you still want to add"
    json .command groupAddServer .error_code ERR_CONNECTION_FAILED .value      null

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2() servers()
    success firstadd_ok $a1 --osh groupAddServer --group $group1 --host 127.0.0.10 --port-any --user-any --force
    contain "was added to group"
    json .command groupAddServer .error_code OK .value.group $group1 .value.ip 127.0.0.10 .value.port null .value.user null

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2() servers(127.0.0.10)
    success firstadd_dup $a1 --osh groupAddServer --group $group1 --host 127.0.0.10 --port-any --user-any --force
    json .command groupAddServer .error_code OK_NO_CHANGE .value      null

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2() servers(127.0.0.10)
    success secondadd $a1 --osh groupAddServer --group $group1 --host 127.0.0.11 --port-any --user-any --force
    contain "was added to group"
    json .command groupAddServer .error_code OK .value.group $group1 .value.ip 127.0.0.11 .value.port null .value.user null

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2() servers(127.0.0.10,127.0.0.11)
    success thirdaddttl $a1 --osh groupAddServer --group $group1 --host 127.0.0.12 --port-any --user-any --force --ttl 0w19s0d
    contain "was added to group"
    contain "expires in 00:00:"
    json .command groupAddServer .error_code OK .value.group $group1 .value.ip 127.0.0.12 .value.port null .value.user null .value.ttl 19

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2() servers(127.0.0.10,127.0.0.11,127.0.0.12-TTL)
    success list   $a1 --osh groupListServers --group $group1
    json .command groupListServers .error_code OK
    contain REGEX '127\.0\.0\.1[[:space:]]+22[[:space:]]+g1[[:space:]]+'$group1'\(group\)[[:space:]]+'$account2'[[:space:]]'
    contain REGEX '127\.0\.0\.2[[:space:]]+22[[:space:]]+g2[[:space:]]+'$group1'\(group\)[[:space:]]+'$account2'[[:space:]]'
    contain REGEX '127\.0\.0\.10[[:space:]]+\(any\)[[:space:]]+\(any\)[[:space:]]+'$group1'\(group\)[[:space:]]+'$account1'[[:space:]]'
    contain REGEX '127\.0\.0\.11[[:space:]]+\(any\)[[:space:]]+\(any\)[[:space:]]+'$group1'\(group\)[[:space:]]+'$account1'[[:space:]]'
    contain REGEX '127\.0\.0\.12[[:space:]]+\(any\)[[:space:]]+\(any\)[[:space:]]+'$group1'\(group\)[[:space:]]+'$account1'[[:space:]]+\S+[[:space:]]+00:00:[01][0123456789]'
    contain '5 accesses listed'

    # wait for the access to expire
    [ "$COUNTONLY" != 1 ] && sleep 20

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2() servers(127.0.0.10,127.0.0.11)
    success listttlexpired   $a1 --osh groupListServers --group $group1
    json .command groupListServers .error_code OK
    contain REGEX '127\.0\.0\.1[[:space:]]+22[[:space:]]+g1[[:space:]]+'$group1'\(group\)[[:space:]]+'$account2'[[:space:]]'
    contain REGEX '127\.0\.0\.2[[:space:]]+22[[:space:]]+g2[[:space:]]+'$group1'\(group\)[[:space:]]+'$account2'[[:space:]]'
    contain REGEX '127\.0\.0\.10[[:space:]]+\(any\)[[:space:]]+\(any\)[[:space:]]+'$group1'\(group\)[[:space:]]+'$account1'[[:space:]]'
    contain REGEX '127\.0\.0\.11[[:space:]]+\(any\)[[:space:]]+\(any\)[[:space:]]+'$group1'\(group\)[[:space:]]+'$account1'[[:space:]]'
    nocontain REGEX '127\.0\.0\.12[[:space:]]+\(any\)[[:space:]]+\(any\)[[:space:]]+'$group1'\(group\)[[:space:]]+'$account1'[[:space:]]'
    contain '4 accesses listed'

    success include $a1 --osh groupListServers --group $group1 --include 127.0.0.1
    json .command groupListServers .error_code OK
    contain REGEX '127\.0\.0\.1[[:space:]]+22[[:space:]]+g1[[:space:]]+'$group1'\(group\)[[:space:]]+'$account2'[[:space:]]'
    contain REGEX '127\.0\.0\.10[[:space:]]+\(any\)[[:space:]]+\(any\)[[:space:]]+'$group1'\(group\)[[:space:]]+'$account1'[[:space:]]'
    contain REGEX '127\.0\.0\.11[[:space:]]+\(any\)[[:space:]]+\(any\)[[:space:]]+'$group1'\(group\)[[:space:]]+'$account1'[[:space:]]'
    contain '3 accesses listed'

    success include_exclude $a1 --osh groupListServers --group $group1 --include 127.0.0.1 --exclude 127.0.0.10 --exclude 127.?.0.11
    json .command groupListServers .error_code OK
    contain REGEX '127\.0\.0\.1[[:space:]]+22[[:space:]]+g1[[:space:]]+'$group1'\(group\)[[:space:]]+'$account2'[[:space:]]'
    contain '1 accesses listed'

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2() servers(127.0.0.10,127.0.0.11)
    plgfail list   $a2 --osh groupListServers --group $group1
    json .command groupListServers .error_code KO_ACCESS_DENIED .value      null

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2() servers(127.0.0.10,127.0.0.11)
    run a2_noaccess $a2 127.0.0.10
    retvalshouldbe 107
    contain "Access denied for"
    json .command    null .error_code KO_ACCESS_DENIED

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2() servers(127.0.0.10,127.0.0.11)
    run a2_noaccess2 $a2 127.0.0.11
    retvalshouldbe 107
    contain "Access denied for"
    json .command    null .error_code KO_ACCESS_DENIED

    # owner sets a max ttl guest access policy
    success guest_ttl_limit $a1 --osh groupModify --group $group1 --guest-ttl-limit 15s
    contain "with maximum allowed duration of 00:00:15"
    json .command groupModify .error_code OK .value.guest_ttl_limit.error_code OK

    # try to add a guest without a ttl (should fail)
    plgfail guest_add_fail_nottl $a1 --osh groupAddGuestAccess --group $group1 --account $account2 --port-any --user-any --host 127.0.0.10
    json .command groupAddGuestAccess .error_code ERR_INVALID_PARAMETER .error_message "This group requires guest accesses to have a TTL set, to a duration of 00:00:15 or less"

    # try to add a guest with a too big ttl (should fail)
    plgfail guest_add_fail_bigttl $a1 --osh groupAddGuestAccess --group $group1 --account $account2 --port-any --user-any --host 127.0.0.10 --ttl 14d
    json .command groupAddGuestAccess .error_code ERR_INVALID_PARAMETER .error_message "The TTL you specified is invalid, this group requires guest accesses to have a TTL of 00:00:15 maximum"

    # try to add a guest with a low ttl (should work)
    success guest_add_ok_lowttl $a1 --osh groupAddGuestAccess --group $group1 --account $account2 --port-any --user-any --host 127.0.0.10 --ttl 1s
    json .command groupAddGuestAccess .error_code OK

    # remove ttl policy
    success guest_ttl_limit $a1 --osh groupModify --group $group1 --guest-ttl-limit 0
    json .command groupModify .error_code OK

    # if we're just counting the number of tests, don't sleep
    [ "$COUNTONLY" != 1 ] && sleep 1

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2() servers(127.0.0.10,127.0.0.11)
    success works $a1 --osh groupAddGuestAccess --group $group1 --account $account2 --port-any --user-any --host 127.0.0.10
    contain "has now access"
    json .command groupAddGuestAccess .error_code OK

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2(guest(127.0.0.10)) servers(127.0.0.10,127.0.0.11)
    plgfail nosuchserver $a1 --osh groupAddGuestAccess --group $group1 --account $account2 --port-any --user-any --host 127.9.0.10
    nocontain "has now access"
    json .command groupAddGuestAccess .error_code ERR_GROUP_HAS_NO_ACCESS

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2(guest(127.0.0.10)) servers(127.0.0.10,127.0.0.11)
    run a2_partialxs $a2 127.0.0.10
    retvalshouldbe 255
    contain "allowed ... log on"
    contain "group-guest of $group1"

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2(guest(127.0.0.10)) servers(127.0.0.10,127.0.0.11)
    plgfail shouldfail $a2 --osh groupAddServer --group $group1 --port-any --user-any --host 127.0.0.10
    nocontain "was added to group"
    nocontain "you still want to add"
    contain "must be an aclkeeper"
    json .command groupAddServer .error_code ERR_NOT_GROUP_ACLKEEPER .value      null

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2(guest(127.0.0.10)) servers(127.0.0.10,127.0.0.11)
    run a2_noxsnofull $a2 127.0.0.11
    retvalshouldbe 107
    contain "Access denied for"
    nocontain "$group1 group key"

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2(guest(127.0.0.10)) servers(127.0.0.10,127.0.0.11)
    success works $a1 --osh groupDelGuestAccess --group $group1 --account $account2 --port-any --user-any --host 127.0.0.10
    contain "removed group key access"
    json .command groupDelGuestAccess .error_code OK .value      null


    # even if user2 adds himself private access to .11 ? TODO

    grant accountAddPersonalAccess

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2(guest(127.0.0.10)) servers(127.0.0.10,127.0.0.11)
    success own11 $a0 --osh accountAddPersonalAccess --account $account2 --host 127.0.0.11 --user $account2 --port 22
    contain "adding the access blindly"
    json .command accountAddPersonalAccess .error_code OK .value.account $account2 .value.ip 127.0.0.11 .value.user $account2 .value.port 22

    # just try the ttl param
    success own11_ttl $a0 --osh accountAddPersonalAccess --account $account2 --host 127.7.0.11 --user $account2 --port 22 --ttl 3
    contain "adding the access blindly"
    contain "expires in 00:00:0"
    json .command accountAddPersonalAccess .error_code OK .value.account $account2 .value.ip 127.7.0.11 .value.user $account2 .value.port 22 .value.ttl 3

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2(guest(127.0.0.10)) servers(127.0.0.10,127.0.0.11)
    # account1: perso(account1@127.0.0.11:22)
    run a2_noxsnofullevenprivate $a2 127.0.0.11
    retvalshouldbe 255
    contain "allowed ... log on"
    nocontain "$group1"
    contain "personal access"

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2(guest(127.0.0.10)) servers(127.0.0.10,127.0.0.11)
    # account1: perso(account1@127.0.0.11:22)
    plgfail noright1 $a0 --osh groupTransmitOwnership --group $group1 --account $account1
    json .command groupTransmitOwnership .error_code ERR_NOT_GROUP_OWNER .value null

    # group1: a1(owner,aclkeeper,gatekeeper,member) a2(guest(127.0.0.10)) servers(127.0.0.10,127.0.0.11)
    # account1: perso(account1@127.0.0.11:22)
    plgfail noright2 $a1 --osh groupTransmitOwnership --group $group2 --account $account0
    json .command groupTransmitOwnership .error_code KO_GROUP_NOT_FOUND

    grant groupCreate
    success works      $a0  --osh groupCreate --group $group2 --owner $account2 --algo ecdsa --size 521
    revoke groupCreate

    success owner $a2 --osh groupInfo --group $group2
    tmpfp=$(get_json | $jq '.value.keys|keys[0]')
    json $(cat <<EOS
    .command groupInfo
    .error_code OK
    .members      null
    .value.group $group2
    .value.owners[0]   $account2
    .value.owners[1]   null
    .value.gatekeepers[0]   $account2
    .value.gatekeepers[1]   null
    .value.full_members[0]   $account2
    .value.full_members[1]   null
    .value.partial_members[0]   null
    .value.keys|.["$tmpfp"]|.family      ECDSA
    .value.keys|.["$tmpfp"]|.size        521
    .value.keys|.["$tmpfp"]|.fingerprint $tmpfp
    .value.keys|.["$tmpfp"]|.typecode    ecdsa-sha2-nistp521
EOS
    )
    unset tmpfp

    plgfail nope     $a2 --osh groupTransmitOwnership --group $group1 --account $account0
    json .command groupTransmitOwnership .error_code ERR_NOT_GROUP_OWNER .value          null

    success oknochg  $a1 --osh groupTransmitOwnership --group $group1 --account $account1
    json .command groupTransmitOwnership .error_code OK_NO_CHANGE .value          null

    success ok       $a1 --osh groupTransmitOwnership --group $group1 --account $account2
    json .command groupTransmitOwnership .error_code OK .value          null

    run     nopedup  $a1 --osh groupTransmitOwnership --group $group1 --account $account2
    retvalshouldbe 106
    json .command   null .error_code KO_RESTRICTED_COMMAND .value      null

    run   notmember $a0 --osh groupInfo --group $group1
    tmpfp=$(get_json | $jq '.value.keys|keys[0]')
    json $(cat <<EOS
    .command groupInfo
    .error_code OK
    .members      null
    .value.owners[0]   $account2
    .value.owners[1]   null
    .value.gatekeepers[0]   $account1
    .value.gatekeepers[1]   null
    .value.full_members[0]   null
    .value.partial_members[0]   null
    .value.keys|.["$tmpfp"]|.family      RSA
    .value.keys|.["$tmpfp"]|.size        4096
    .value.keys|.["$tmpfp"]|.fingerprint $tmpfp
    .value.keys|.["$tmpfp"]|.typecode    ssh-rsa
EOS
    )

    run notOwner $a1 --osh groupAddGatekeeper --group $group1 --account $account2
    retvalshouldbe 106
    json .command   null .error_code KO_RESTRICTED_COMMAND .value      null

    success add $a2 --osh groupAddGatekeeper --group $group1 --account $account2
    json .command groupAddGatekeeper .error_code OK .value          null

    run shouldBeGK $a0 --osh groupInfo --group $group1
    tmpfp=$(get_json | $jq '.value.keys|keys[0]')
    json $(cat <<EOS
    .command groupInfo
    .error_code OK
    .members        null
    .value.owners[0]    $account2
    .value.owners[1]    null
    .value.gatekeepers[0]   $account1
    .value.gatekeepers[1]   $account2
    .value.gatekeepers[2]   null
    .value.full_members[0]  null
    .value.partial_members[0]   null
    .value.keys|.["$tmpfp"]|.family      RSA
    .value.keys|.["$tmpfp"]|.size        4096
    .value.keys|.["$tmpfp"]|.fingerprint $tmpfp
    .value.keys|.["$tmpfp"]|.typecode    ssh-rsa
EOS
    )

    run notOwner $a1 --osh groupDelGatekeeper --group $group1 --account $account1
    retvalshouldbe 106
    json .command   null .error_code KO_RESTRICTED_COMMAND .value      null

    success add $a2 --osh groupDelGatekeeper --group $group1 --account $account1
    json .command groupDelGatekeeper .error_code OK .value          null

    run shouldNotBeGK $a0 --osh groupInfo --group $group1
    tmpfp=$(get_json | $jq '.value.keys|keys[0]')
    json $(cat <<EOS
    .command groupInfo
    .error_code OK
    .members        null
    .value.owners[0]    $account2
    .value.owners[1]    null
    .value.gatekeepers[0]   $account2
    .value.gatekeepers[1]   null
    .value.full_members[0]  null
    .value.partial_members[0]   null
    .value.keys|.["$tmpfp"]|.family      RSA
    .value.keys|.["$tmpfp"]|.size        4096
    .value.keys|.["$tmpfp"]|.fingerprint $tmpfp
    .value.keys|.["$tmpfp"]|.typecode    ssh-rsa
EOS
    )
    unset tmpfp

    plgfail  groupDestroy_fail   $a2 --osh groupDestroy --group $group3 --no-confirm
    retvalshouldbe 100
    json .command groupDestroy .error_code ERR_NOT_GROUP_OWNER

    success  groupDestroy   $a3 --osh groupDestroy --group $group3 --no-confirm
    json .command groupDestroy .error_code OK

    success  groupDestroy   $a2 --osh groupDestroy --group $group2 --no-confirm
    json .command groupDestroy .error_code OK

    success  groupDestroy   $a2 --osh groupDestroy --group $group1 --no-confirm
    json .command groupDestroy .error_code OK

    grant accountDelete

    script   accountDelete   $a0 --osh accountDelete --account $account3 "<<< \"Yes, do as I say and delete $account3, kthxbye\""
    retvalshouldbe 0
    nocontain "attempting to continue"
    json .command accountDelete .error_code OK

    script   accountDelete   $a0 --osh accountDelete --account $account2 "<<< \"Yes, do as I say and delete $account2, kthxbye\""
    retvalshouldbe 0
    nocontain "attempting to continue"
    json .command accountDelete .error_code OK

    script   accountDelete   $a0 --osh accountDelete --account $account1 "<<< \"Yes, do as I say and delete $account1, kthxbye\""
    retvalshouldbe 0
    nocontain "attempting to continue"
    json .command accountDelete .error_code OK

    revoke accountDelete
}

testsuite_groups
unset -f testsuite_groups
