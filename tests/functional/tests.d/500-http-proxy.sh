# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2317,SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_proxy_check_response()
{
    [ "$COUNTONLY" = 1 ] && return 0
    # ensure there's no header duplicates
    local dupes;
    dupes="$(get_stdout | awk '{if (NF==0) { exit }}; /^[a-zA-Z0-9_-]+: / {print $1}' | tr "[:upper:]" "[:lower:]" | sort | uniq -c | grep -Ev '^ *1 ')"
    if [ -n "$dupes" ]; then
        fail "HEADER DUPES" "$dupes"
    else
        ok "HEADER DUPES" "(no duplicate headers)"
    fi
    # a single request must get a single response.
    local nbstatus
    nbstatus="$(get_stdout | grep -c '^HTTP/' || true)"
    if [ "$nbstatus" != 1 ]; then
        fail "SINGLE RESPONSE" "(expected exactly 1 HTTP status line in the body, got $nbstatus)"
    else
        ok "SINGLE RESPONSE" "(exactly one HTTP response)"
    fi
    # headers that should always be there
    contain 'Server: The Bastion'
    contain 'X-Bastion-Instance: '
    contain 'X-Bastion-ReqID: '
    contain 'X-Bastion-Local-Status: '
}

# build osh-http-proxy.conf from osh-http-proxy-methods.conf, with the given egress TLS settings
# usage: testsuite_proxy_set_egress_tls <test_name> <egress_ciphers> <allow_downgrade:true|false|absent> <downgraded_egress_ciphers>
# Those settings are read by the worker on each request, so no daemon restart is needed.
testsuite_proxy_set_egress_tls()
{
    local name="$1" egress_ciphers="$2" allow_downgrade="$3" downgraded_egress_ciphers="$4"
    # the perl code is base64-encoded to avoid any quoting nightmare through ssh,
    # and uses q{} so that perl doesn't interpolate e.g. "@SECLEVEL" in the cipher strings
    local code
    code=$(cat <<EOF
s{^"egress_ciphers":.*}{q{"egress_ciphers": "$egress_ciphers",}}e;
s{^"downgraded_egress_ciphers":.*}{q{"downgraded_egress_ciphers": "$downgraded_egress_ciphers",}}e;
s{^"allow_downgrade":.*}{q{"allow_downgrade": $allow_downgrade,}}e;
\$_ = "" if "$allow_downgrade" eq "absent" && /^"allow_downgrade":/;
EOF
)
    local codeb64
    codeb64=$(echo "$code" | base64 -w0)
    success "$name" $r0 "\"echo $codeb64 | base64 -d > /tmp/proxyconf.pl && perl -p /tmp/proxyconf.pl $opt_remote_etc_bastion/osh-http-proxy-methods.conf > $opt_remote_etc_bastion/osh-http-proxy.conf && rm -f /tmp/proxyconf.pl && grep -E '^.(egress_ciphers|allow_downgrade|downgraded_egress_ciphers).:' $opt_remote_etc_bastion/osh-http-proxy.conf; true\""
}

# test the egress TLS settings of the proxy: egress_ciphers, allow_downgrade and downgraded_egress_ciphers
testsuite_proxy_egress_tls()
{
    local proxy_password="$1"

    # The fake remote server (tests/functional/proxy/remote-daemon) exposes:
    # - 9444: TLSv1.2-only, honoring the client's cipher order
    # - 9445: TLSv1.0-only "old device", preferring AES256-SHA (RSA kx), also accepting ECDHE-RSA-AES256-SHA
    # - 9447: TLSv1.2-only, only accepting AES256-SHA, which is not in our egress_ciphers below
    # - 9448: TLSv1.0-only "old device", only accepting ECDHE-RSA-AES256-SHA, which is in our egress_ciphers
    #         but not in our downgraded_egress_ciphers below
    #
    # To get a deterministic "unsupported protocol" error from the TLSv1.0 device regardless of the distro's
    # openssl.cnf, we restrict egress_ciphers to two ECDHE ciphers with @SECLEVEL=3, which forbids TLS < 1.2
    # on the client side: the device only shares ECDHE-RSA-AES256-SHA with us, answers with TLSv1.0,
    # and our client rejects it with "unsupported protocol". Without this restriction, the error depends on
    # the system's openssl.cnf (e.g. "legacy sigalg disallowed" on stock Debian 12, which doesn't trigger
    # the downgrade).
    # The ECDHE-RSA-AES128-SHA256 cipher is a TLSv1.2-only cipher that is not in the default preference
    # order, so seeing it negotiated on 9444 proves that egress_ciphers is applied.
    local egress_ciphers='ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:@SECLEVEL=3'
    # when downgrading, allow AES256-SHA (no MD5-SHA1 signature needed in the handshake, contrary to ECDHE)
    local downgraded_egress_ciphers='AES256-SHA:@SECLEVEL=0'
    local curl_base="curl -m $default_timeout -ski"

    # 1) egress_ciphers is applied
    testsuite_proxy_set_egress_tls egress_tls_config_full "$egress_ciphers" true "$downgraded_egress_ciphers"
    contain "\"egress_ciphers\": \"$egress_ciphers\","

    script egress_ciphers_applied "$curl_base -u '$account0@test@127.0.0.1%9444:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain "X-Bastion-Remote-Client-SSL-Cipher: ECDHE-RSA-AES128-SHA256"
    nocontain 'X-Bastion-Downgraded'
    contain 'X-Bastion-Remote-Client-SSL-Version: TLSv1_2'
    # the TLS version and cipher we've negotiated must also be logged to syslog, for compliance stats
    testsuite_proxy_get_tls_syslog egress_ciphers_applied_syslog
    contain 'host="127.0.0.1"'
    contain 'port="9444"'
    contain 'enforced="0"'
    contain 'verdict="failed"'
    # the @SECLEVEL=3 of our egress_ciphers also applies to the certificate verification, and the 2048 bits RSA key
    # of the device is too weak for it, which is reported before the self-signed error (seen with OpenSSL 3.0, we
    # accept both in case another OpenSSL version reports them the other way around)
    contain REGEX 'reason="(EE certificate key too weak|self[- ]signed certificate)"'
    contain 'ssl_version="TLSv1_2"'
    contain 'ssl_cipher="ECDHE-RSA-AES128-SHA256"'
    contain 'cert_subject="/CN=testcert"'
    contain 'downgraded="0"'

    # a modern TLS1.3 device must still work fine (TLS1.3 ciphersuites are not affected by egress_ciphers)
    script egress_ciphers_tls13 "$curl_base -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    contain "X-Bastion-Remote-Status: 200"
    nocontain 'X-Bastion-Downgraded'
    testsuite_proxy_get_tls_syslog egress_ciphers_tls13_syslog
    contain 'port="9443"'
    contain REGEX 'ssl_version="TLSv1_[23]"'
    contain REGEX 'ssl_cipher="[A-Z0-9_-]+"'
    contain 'downgraded="0"'

    # 2) old device, the client doesn't ask for a downgrade: we must get the TLS error
    script egress_old_device_no_downgrade "$curl_base -u '$account0@test@127.0.0.1%9445:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 500 Can't connect to 127.0.0.1:9445"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain 'unsupported protocol'
    nocontain 'X-Bastion-Downgraded'
    # the TLS handshake failed, and not because of the certificate: there's no TLS connection to log
    testsuite_proxy_get_tls_syslog egress_old_device_no_downgrade_syslog 0

    # 3) old device, the client asks for a downgrade and the config allows it: it must work
    script egress_old_device_downgrade "$curl_base -H 'X-Bastion-Allow-Downgrade: 1' -u '$account0@test@127.0.0.1%9445:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain 'X-Bastion-Downgraded: 1'
    contain "X-Bastion-Remote-Status: 200"
    contain "X-Bastion-Remote-Client-SSL-Cipher: AES256-SHA"
    contain "Content-Length: 64"
    contain 'X-Bastion-Remote-Client-SSL-Version: TLSv1'
    nocontain 'X-Bastion-Remote-Client-SSL-Version: TLSv1_'
    # only the downgraded connection is logged (the first attempt didn't establish any), and flagged as such
    testsuite_proxy_get_tls_syslog egress_old_device_downgrade_syslog
    contain 'port="9445"'
    contain 'enforced="0"'
    contain 'verdict="failed"'
    contain REGEX 'reason="self[- ]signed certificate"'
    contain 'ssl_version="TLSv1"'
    contain 'ssl_cipher="AES256-SHA"'
    contain 'downgraded="1"'

    # 4) the remote device itself returns a 500 whose message looks like an SSL error: this is NOT
    # an LWP-internal error (no "Client-Warning: Internal response"), so we must not downgrade
    script egress_remote_500_no_downgrade "$curl_base -H 'X-Bastion-Allow-Downgrade: 1' -H 'X-Test-Add-Response-Header-Status: 500 fake error:0A000102:SSL routines::unsupported protocol' -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 500 fake error"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain 'X-Bastion-Remote-Status: 500 fake error'
    nocontain 'X-Bastion-Downgraded'
    testsuite_proxy_get_tls_syslog egress_remote_500_no_downgrade_syslog
    contain 'port="9443"'
    contain REGEX 'ssl_version="TLSv1_[23]"'
    contain 'downgraded="0"'

    # 4b) TLSv1.2 device sharing no cipher with our egress_ciphers: the handshake fails, but not because of the
    # protocol version, so a downgrade can't help and must not be attempted, even if the client asks for it
    script egress_no_shared_cipher "$curl_base -u '$account0@test@127.0.0.1%9447:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 500 Can't connect to 127.0.0.1:9447"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain 'handshake failure'
    nocontain 'X-Bastion-Downgraded'
    nocontain 'X-Bastion-Remote-Client-SSL'
    testsuite_proxy_get_tls_syslog egress_no_shared_cipher_syslog 0

    script egress_no_shared_cipher_downgrade "$curl_base -H 'X-Bastion-Allow-Downgrade: 1' -u '$account0@test@127.0.0.1%9447:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 500 Can't connect to 127.0.0.1:9447"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain 'handshake failure'
    nocontain 'unsupported protocol'
    nocontain 'X-Bastion-Downgraded'
    nocontain 'X-Bastion-Remote-Client-SSL'
    # no TLS connection has been established, so there's nothing to log about its compliance
    testsuite_proxy_get_tls_syslog egress_no_shared_cipher_downgrade_syslog 0

    # 4c) old TLSv1.0 device sharing no cipher with our downgraded_egress_ciphers: the downgrade is attempted,
    # but fails too. We must cleanly report the error of the downgraded attempt (once), and tell that we tried
    script egress_old_device_downgrade_no_shared_cipher "$curl_base -H 'X-Bastion-Allow-Downgrade: 1' -u '$account0@test@127.0.0.1%9448:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 500 Can't connect to 127.0.0.1:9448"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain 'X-Bastion-Downgraded: 1'
    contain 'handshake failure'
    nocontain 'unsupported protocol'
    nocontain 'X-Bastion-Remote-Client-SSL'
    nocontain 'X-Bastion-Remote-Status: 200'
    testsuite_proxy_get_tls_syslog egress_old_device_downgrade_no_shared_cipher_syslog 0

    # without the downgrade, we get the error of the first attempt, as for the other old device
    script egress_old_device_no_shared_cipher_no_downgrade "$curl_base -u '$account0@test@127.0.0.1%9448:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 500 Can't connect to 127.0.0.1:9448"
    testsuite_proxy_check_response
    contain 'unsupported protocol'
    nocontain 'X-Bastion-Downgraded'
    testsuite_proxy_get_tls_syslog egress_old_device_no_shared_cipher_no_downgrade_syslog 0

    # same in secure mode: neither of the two failed handshakes is about the certificate (which was never
    # verified), so they must not be logged as certificate verification failures
    script egress_old_device_downgrade_no_shared_cipher_secure "$curl_base -H 'X-Bastion-Enforce-Secure: 1' -H 'X-Bastion-Allow-Downgrade: 1' -u '$account0@test@127.0.0.1%9448:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 500 Can't connect to 127.0.0.1:9448"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain 'X-Bastion-Downgraded: 1'
    contain 'handshake failure'
    nocontain 'X-Bastion-Remote-Client-SSL'
    testsuite_proxy_get_tls_syslog egress_old_device_downgrade_no_shared_cipher_secure_syslog 0

    # 5) the client asks for a downgrade but the config forbids it: we must get the TLS error
    testsuite_proxy_set_egress_tls egress_tls_config_nodowngrade "$egress_ciphers" false "$downgraded_egress_ciphers"
    contain '"allow_downgrade": false,'

    script egress_old_device_downgrade_forbidden "$curl_base -H 'X-Bastion-Allow-Downgrade: 1' -u '$account0@test@127.0.0.1%9445:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 500 Can't connect to 127.0.0.1:9445"
    testsuite_proxy_check_response
    contain 'unsupported protocol'
    nocontain 'X-Bastion-Downgraded'
    testsuite_proxy_get_tls_syslog egress_old_device_downgrade_forbidden_syslog 0

    # 6) allow_downgrade is absent from the config (e.g. config from a previous version): defaults to true
    testsuite_proxy_set_egress_tls egress_tls_config_absent "$egress_ciphers" absent "$downgraded_egress_ciphers"
    nocontain '"allow_downgrade"'

    script egress_old_device_downgrade_default "$curl_base -H 'X-Bastion-Allow-Downgrade: 1' -u '$account0@test@127.0.0.1%9445:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    contain 'X-Bastion-Downgraded: 1'
    contain "X-Bastion-Remote-Client-SSL-Cipher: AES256-SHA"
    contain 'X-Bastion-Remote-Client-SSL-Version: TLSv1'
    testsuite_proxy_get_tls_syslog egress_old_device_downgrade_default_syslog
    contain 'port="9445"'
    contain 'ssl_version="TLSv1"'
    contain 'ssl_cipher="AES256-SHA"'
    contain 'downgraded="1"'

    # 7) no downgraded_egress_ciphers: the downgrade is attempted, but with our (too strict) egress_ciphers
    # still applied, so it can't succeed. This proves downgraded_egress_ciphers is what made 3) work.
    testsuite_proxy_set_egress_tls egress_tls_config_nodowngradedciphers "$egress_ciphers" true ""
    contain '"downgraded_egress_ciphers": "",'

    script egress_old_device_downgrade_no_ciphers "$curl_base -H 'X-Bastion-Allow-Downgrade: 1' -u '$account0@test@127.0.0.1%9445:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 500 Can't connect to 127.0.0.1:9445"
    testsuite_proxy_check_response
    contain 'X-Bastion-Downgraded: 1'
    nocontain 'X-Bastion-Remote-Client-SSL-Cipher'
    # the downgrade has been attempted, but no TLS connection has been established
    testsuite_proxy_get_tls_syslog egress_old_device_downgrade_no_ciphers_syslog 0

    # restore the config the subsequent tests expect
    success egress_tls_config_restore $r0 "\"cp $opt_remote_etc_bastion/osh-http-proxy-methods.conf $opt_remote_etc_bastion/osh-http-proxy.conf\""
}

# get the http-proxy-tls syslog line(s) logged by the worker for the request of the previous test,
# found through its X-Bastion-ReqID (which is the uniqid of the syslog lines), then use contain/nocontain on them.
# usage: testsuite_proxy_get_tls_syslog <test_name> [expected_number_of_lines, defaults to 1]
# There is one line per egress TLS connection established (or refused because of its certificate), so 0 is
# expected for plain http egress or when the TLS handshake failed for another reason, and 2 or more when
# a redirect is followed. The fields common to all our requests are checked here.
# With --consistency-check, the syslog file is truncated after each test, its previous content is kept in .prev
testsuite_proxy_get_tls_syslog()
{
    local name="$1" expected="${2:-1}"
    local reqid
    reqid=$(get_stdout | grep -Eo 'X-Bastion-ReqID: [a-zA-Z0-9]+' | head -n1 | cut -d' ' -f2)
    # if we didn't find any ReqID, use a value that can't match anything, so that the checks fail properly
    [ -n "$reqid" ] || reqid=NO_REQID_FOUND
    # base64-encode the remote command to avoid any quoting nightmare through ssh
    local codeb64
    codeb64=$(printf '%s' "cat /var/log/bastion/bastion.log.prev /var/log/bastion/bastion.log 2>/dev/null | grep -F http-proxy-tls | grep -E 'uniqid=.$reqid.'; true" | base64 -w0)
    success "$name" $r0 "\"echo $codeb64 | base64 -d | sh\""
    [ "$COUNTONLY" = 1 ] && return 0
    # without a ReqID, we would find no line at all, don't let the tests expecting none pass by accident
    if [ "$reqid" = NO_REQID_FOUND ]; then
        fail "TLS SYSLOG REQID" "(no X-Bastion-ReqID found in the output of the previous test)"
    fi
    local nblines
    nblines="$(get_stdout | grep -c 'http-proxy-tls' || true)"
    if [ "$nblines" != "$expected" ]; then
        fail "TLS SYSLOG LINES" "(expected $expected http-proxy-tls line(s) for this request, got $nblines)"
    else
        ok "TLS SYSLOG LINES" "($nblines http-proxy-tls line(s) for this request)"
    fi
    if [ "$expected" != 0 ]; then
        contain "account=\"$account0\""
        contain 'auth_mode="self/default"'
        contain 'user="test"'
    fi
}

# set (or clear, if empty) the egress_ca_file option, starting from osh-http-proxy-methods.conf (or the given config)
testsuite_proxy_set_egress_ca_file()
{
    local name="$1" ca_file="$2" base_conf="${3:-osh-http-proxy-methods.conf}"
    # same base64 trick as testsuite_proxy_set_egress_tls, to avoid any quoting nightmare through ssh
    local code
    code=$(cat <<EOF
s{^"egress_ca_file":.*}{q{"egress_ca_file": "$ca_file",}}e;
EOF
)
    local codeb64
    codeb64=$(echo "$code" | base64 -w0)
    success "$name" $r0 "\"echo $codeb64 | base64 -d > /tmp/proxyconf.pl && perl -p /tmp/proxyconf.pl $opt_remote_etc_bastion/$base_conf > $opt_remote_etc_bastion/osh-http-proxy.conf && rm -f /tmp/proxyconf.pl && grep -E '^.egress_ca_file.:' $opt_remote_etc_bastion/osh-http-proxy.conf; true\""
}

testsuite_proxy_egress_ca_file()
{
    local proxy_password="$1"
    local curl_base="curl -m $default_timeout -ski"

    # The fake remote server (tests/functional/proxy/remote-daemon) exposes, on 9446, a certificate for
    # localhost only (not 127.0.0.1) signed by our test CA (/tmp/testca.crt), see tests/functional/docker/target_role.sh.
    # On 9449, it exposes an expired certificate, for the same name and signed by the same CA.
    # Both names reach the same device, and are allowed for our account (which has access to 127.0.0.1)

    # 1) insecure (the default of the tests), no egress_ca_file: the system CA store doesn't know our test CA
    script egress_ca_unknown "$curl_base -u '$account0@test@localhost%9446:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain "X-Bastion-Remote-Client-SSL-Cert-Subject: /CN=localhost"
    contain "X-Bastion-Remote-Client-SSL-Cert-Issuer: /CN=Bastion Test CA"
    contain "X-Bastion-Remote-Client-SSL-Cert-Verify: FAILED (unable to get local issuer certificate)"
    # the same verdict must have been logged to syslog, with the TLS version and cipher, for compliance stats
    testsuite_proxy_get_tls_syslog egress_ca_unknown_syslog
    contain 'enforced="0"'
    contain 'verdict="failed"'
    contain 'reason="unable to get local issuer certificate"'
    contain 'host="localhost"'
    contain 'ip="127.0.0.1"'
    contain 'port="9446"'
    contain REGEX 'ssl_version="TLSv1_[23]"'
    contain REGEX 'ssl_cipher="[A-Z0-9_-]+"'
    contain 'cert_subject="/CN=localhost"'
    contain 'cert_issuer="/CN=Bastion Test CA"'

    # 2) now trust our test CA through egress_ca_file
    testsuite_proxy_set_egress_ca_file egress_ca_file_set /tmp/testca.crt
    contain '"egress_ca_file": "/tmp/testca.crt",'

    # insecure, valid certificate, reached by the name it's been issued for: we would have accepted it if secure
    script egress_ca_valid_by_name "$curl_base -u '$account0@test@localhost%9446:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain 'X-Bastion-Remote-Host: localhost'
    contain "X-Bastion-Remote-Client-SSL-Cert-Verify: OK"
    testsuite_proxy_get_tls_syslog egress_ca_valid_by_name_syslog
    contain 'verdict="ok"'
    contain 'reason=""'
    contain 'host="localhost"'

    # insecure, valid chain, but reached by a name not in the certificate: we would have refused it if secure
    script egress_ca_name_mismatch "$curl_base -u '$account0@test@127.0.0.1%9446:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    contain "X-Bastion-Remote-Client-SSL-Cert-Verify: FAILED (certificate doesn't match 127.0.0.1)"
    testsuite_proxy_get_tls_syslog egress_ca_name_mismatch_syslog
    contain 'verdict="failed"'
    contain "reason=\"certificate doesn't match 127.0.0.1\""

    # insecure, valid chain and name, but expired certificate: we would have refused it if secure
    script egress_ca_expired "$curl_base -u '$account0@test@localhost%9449:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain "X-Bastion-Remote-Status: 200"
    contain "X-Bastion-Remote-Client-SSL-Cert-Subject: /CN=localhost"
    contain "X-Bastion-Remote-Client-SSL-Cert-Issuer: /CN=Bastion Test CA"
    contain "X-Bastion-Remote-Client-SSL-Cert-Verify: FAILED (certificate has expired)"
    testsuite_proxy_get_tls_syslog egress_ca_expired_syslog
    contain 'host="localhost"'
    contain 'port="9449"'
    contain 'enforced="0"'
    contain 'verdict="failed"'
    contain 'reason="certificate has expired"'
    contain REGEX 'ssl_version="TLSv1_[23]"'
    contain 'cert_subject="/CN=localhost"'
    contain 'cert_issuer="/CN=Bastion Test CA"'

    # the self-signed device is still reported as invalid, even with our test CA trusted
    script egress_ca_selfsigned "$curl_base -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    contain REGEX "X-Bastion-Remote-Client-SSL-Cert-Verify: FAILED \(self[- ]signed certificate\)"
    testsuite_proxy_get_tls_syslog egress_ca_selfsigned_syslog
    contain 'port="9443"'
    contain 'enforced="0"'
    contain 'verdict="failed"'
    contain REGEX 'reason="self[- ]signed certificate"'
    contain 'cert_issuer="/CN=testcert"'

    # 3) secure mode (enforced by the client): the diagnostic must match reality.
    # The valid device must be accepted, which also proves that the certificate is checked against the name
    # the client used (and that this name is sent through SNI), not against the IP we connect to
    script egress_ca_secure_valid "$curl_base -H 'X-Bastion-Enforce-Secure: 1' -u '$account0@test@localhost%9446:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain "X-Bastion-Remote-Status: 200"
    nocontain "X-Bastion-Remote-Client-SSL-Cert-Verify"
    nocontain "X-Bastion-Remote-Client-SSL-Warning"
    # TLS connections are logged regardless of the insecure option: here, enforced and accepted
    testsuite_proxy_get_tls_syslog egress_ca_secure_valid_syslog
    contain 'enforced="1"'
    contain 'verdict="ok"'
    contain 'reason=""'
    contain REGEX 'ssl_version="TLSv1_[23]"'
    contain 'cert_issuer="/CN=Bastion Test CA"'

    # when secure, LWP doesn't set Client-SSL-Cert-Verify nor Client-SSL-Warning: the device must not be able
    # to inject them (nor any other Client-* header) through <meta http-equiv> tags in its HTML answer
    script egress_ca_secure_meta_spoof "$curl_base -H 'X-Bastion-Enforce-Secure: 1' -H 'X-Test-Html-Meta-Spoof: 1' -u '$account0@test@localhost%9446:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain 'meta spoof'
    contain "X-Bastion-Remote-Client-SSL-Cert-Issuer: /CN=Bastion Test CA"
    contain REGEX "X-Bastion-Remote-Client-SSL-Cipher: [A-Z0-9_-]+"
    nocontain "X-Bastion-Remote-Client-SSL-Cert-Verify"
    nocontain "X-Bastion-Remote-Client-SSL-Warning"
    nocontain "X-Bastion-Remote-Client-SSL-Cipher: SPOOFED"
    # and neither must our syslog line be influenced by the device
    testsuite_proxy_get_tls_syslog egress_ca_secure_meta_spoof_syslog
    contain 'enforced="1"'
    contain 'verdict="ok"'
    contain 'reason=""'
    contain 'cert_subject="/CN=localhost"'
    nocontain 'SPOOFED'

    # the expired certificate must be refused, as the diagnostic above predicted
    script egress_ca_secure_expired "$curl_base -H 'X-Bastion-Enforce-Secure: 1' -u '$account0@test@localhost%9449:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    # we connect to the IP we've checked, hence the IP in the LWP error message, even if the client used a name
    contain "HTTP/1.0 500 Can't connect to 127.0.0.1:9449"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    nocontain 'X-Bastion-Remote-Client-SSL'
    testsuite_proxy_get_tls_syslog egress_ca_secure_expired_syslog
    contain 'host="localhost"'
    contain 'port="9449"'
    contain 'enforced="1"'
    contain 'verdict="failed"'
    contain 'reason="certificate verify failed"'
    contain 'ssl_version=""'

    # the name mismatch must be refused, as the diagnostic above predicted
    script egress_ca_secure_name_mismatch "$curl_base -H 'X-Bastion-Enforce-Secure: 1' -u '$account0@test@127.0.0.1%9446:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 500 Can't connect to 127.0.0.1:9446"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'

    # the refused connection must also be logged, as it's precisely what an admin wants to know about
    testsuite_proxy_get_tls_syslog egress_ca_secure_name_mismatch_syslog
    contain 'enforced="1"'
    contain 'verdict="failed"'
    contain 'reason="hostname verification failed"'
    contain 'ssl_version=""'

    # 4) an unreadable egress_ca_file must be refused (never silently fall back to the system CA store),
    # and must be logged to syslog for the admin
    testsuite_proxy_set_egress_ca_file egress_ca_file_missing /nonexistent/ca.crt
    contain '"egress_ca_file": "/nonexistent/ca.crt",'

    ignorecodewarn 'invalid egress_ca_file config value'
    script egress_ca_missing "$curl_base -u '$account0@test@localhost%9446:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 500 Internal Error"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 500 Internal Error'
    contain 'Configuration is invalid, please contact the bastion admin'
    nocontain '/nonexistent/ca.crt'
    nocontain 'X-Bastion-Remote-Status'

    # the warning must have reached the system logs
    success egress_ca_missing_syslog $r0 "\"cat /var/log/bastion/bastion.log.prev /var/log/bastion/bastion.log 2>/dev/null | grep -F 'invalid egress_ca_file config value' | tail -n1\""
    contain '/nonexistent/ca.crt'
    contain "readable by the bastion accounts (checked as '$account0')"

    # 5) with allow_redirects=any, a followed redirect to another name must be checked against this new name,
    # and logged with it: start from 127.0.0.1 (name mismatch), then get redirected to localhost (valid)
    testsuite_proxy_set_egress_ca_file egress_ca_file_set_redirects_any /tmp/testca.crt osh-http-proxy-redirects-any.conf
    contain '"egress_ca_file": "/tmp/testca.crt",'

    script egress_ca_redirect_other_name "$curl_base -H 'X-Test-Redirect-To: https://localhost:9446/redirected' -u '$account0@test@127.0.0.1%9446:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    contain "X-Bastion-Remote-Status: 200 OK"
    contain "X-Bastion-Remote-Client-SSL-Cert-Verify: OK"
    testsuite_proxy_get_tls_syslog egress_ca_redirect_other_name_syslog 2
    contain REGEX 'host="127\.0\.0\.1".*verdict="failed" reason="certificate doesn.t match 127\.0\.0\.1"'
    contain REGEX 'host="localhost" ip="127\.0\.0\.1" port="9446" enforced="0" verdict="ok"'

    # same in secure mode, the other way around: the first hop (localhost) is valid, but the second hop must be
    # refused, as its certificate doesn't match 127.0.0.2. Note that a redirect to 127.0.0.1 wouldn't do here: as it's
    # the IP we've checked, it's same-host, so the request keeps the name used by the client (localhost)
    script egress_ca_secure_redirect_other_name "$curl_base -H 'X-Bastion-Enforce-Secure: 1' -H 'X-Test-Redirect-To: https://127.0.0.2:9446/redirected' -u '$account0@test@localhost%9446:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 500 Can't connect to 127.0.0.2:9446"
    testsuite_proxy_check_response
    testsuite_proxy_get_tls_syslog egress_ca_secure_redirect_other_name_syslog 2
    contain REGEX 'host="localhost" ip="127\.0\.0\.1" port="9446" enforced="1" verdict="ok"'
    contain REGEX 'host="127\.0\.0\.2" ip="127\.0\.0\.2" port="9446" enforced="1" verdict="failed" reason="hostname verification failed"'

    # restore the config the subsequent tests expect
    success egress_ca_config_restore $r0 "\"cp $opt_remote_etc_bastion/osh-http-proxy-methods.conf $opt_remote_etc_bastion/osh-http-proxy.conf\""
}

testsuite_proxy()
{
    # note: we use "curl | cat" to force curl to disable color output, to be grep friendly,
    # as a --no-color or similar option doesn't seem to exist for curl.

    # check that the proxy is up
    script monitoring "curl -m $default_timeout -vki https://$remote_ip:$remote_proxy_port/bastion-health-check | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'running nominally'
    contain 'X-Bastion-Local-Status: 200 OK'

    # and let's go
    script noauth "curl -m $default_timeout -vki https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    testsuite_proxy_check_response
    contain 'HTTP/1.0 401 Authorization required (no auth provided)'
    contain 'X-Bastion-Local-Status: 401 Authorization required (no auth provided)'
    contain 'WWW-Authenticate: Basic realm="bastion"'
    contain 'Content-Type: text/plain'
    contain 'No authentication provided, and authentication is mandatory'

    script bad_auth_format "curl -m $default_timeout -vki -u test:test https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 400 Bad Request (bad login format)'
    contain 'X-Bastion-Local-Status: 400 Bad Request (bad login format)'
    testsuite_proxy_check_response
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'Expected an Authorization line with credentials of the form'

    script bad_auth "curl -m $default_timeout -vki -u test@test@test:test https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 403 Access Denied'
    contain 'Server: The Bastion'
    contain 'X-Bastion-Instance: '
    contain 'X-Bastion-ReqID: '
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'Incorrect username (test) or password (#REDACTED#, length=4)'

    # create valid credentials
    success generate_proxy_password $a0 --osh selfGenerateProxyPassword --do-it
    json .command selfGenerateProxyPassword .error_code OK
    local proxy_password
    proxy_password=$(get_json | jq -r '.value.password')

    # now try to use these
    script good_auth_bad_host "curl -m $default_timeout -vki -u '$account0@test@test.invalid:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 400 Bad Request (ERR_HOST_NOT_FOUND)'
    testsuite_proxy_check_response
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'X-Bastion-Remote-Host: test.invalid'
    nocontain 'X-Bastion-Remote-IP'
    contain 'X-Bastion-Request-Length: 0'
    contain 'X-Bastion-Local-Status: 400'
    contain 'Content-Type: text/plain'
    contain "Unable to resolve 'test.invalid' ("

    # change credentials again
    success generate_proxy_password2 $a0 --osh selfGenerateProxyPassword --do-it
    json .command selfGenerateProxyPassword .error_code OK
    local proxy_password2
    proxy_password2=$(get_json | jq -r '.value.password')

    # attempt to use the previous credentials (and fail)
    script bad_auth2 "curl -m $default_timeout -vki -u test@test@test:test https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    testsuite_proxy_check_response
    contain 'HTTP/1.0 403 Access Denied'
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'Incorrect username (test) or password (#REDACTED#, length='

    proxy_password="$proxy_password2"

    # a remote user name with forbidden characters must be rejected (regression test for the
    # user revalidation done by both the daemon and the worker, see is_valid_remote_user(stricter => 1)).
    # '!' is rejected under stricter mode; the daemon's previous (loose, unanchored) regex let it through.
    script bad_user_name "curl -m $default_timeout -vki -u '$account0@te!st@127.0.0.1:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 400 Bad Request (bad user name)'
    testsuite_proxy_check_response
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain "User name 'te!st' has forbidden characters"

    script good_auth_no_access "curl -m $default_timeout -vki -u '$account0@test@127.0.0.1:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 403 Access Denied (access denied to remote)'
    testsuite_proxy_check_response
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'X-Bastion-Remote-IP: 127.0.0.1'
    contain 'X-Bastion-Request-Length: 0'
    contain 'X-Bastion-Auth-Mode: self/default'
    contain 'X-Bastion-Local-Status: 403'
    contain 'Content-Type: text/plain'
    contain "This account doesn't have access to this user@host tuple (Access denied for $account0 to test@127.0.0.1:443)"

    script good_auth_no_access_other_port "curl -m $default_timeout -vki -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 403 Access Denied (access denied to remote)'
    testsuite_proxy_check_response
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'X-Bastion-Remote-IP: 127.0.0.1'
    contain 'X-Bastion-Request-Length: 0'
    contain 'X-Bastion-Auth-Mode: self/default'
    contain 'X-Bastion-Local-Status: 403'
    contain 'Content-Type: text/plain'
    contain "This account doesn't have access to this user@host tuple (Access denied for $account0 to test@127.0.0.1:9443)"

    # add ourselves access
    success add_personal_access $a0 --osh selfAddPersonalAccess --host 127.0.0.1 --port-any --user test --force
    json .command selfAddPersonalAccess .error_code OK

    script missing_egress_pwd "curl -m $default_timeout -vki -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 412 Precondition Failed (egress password missing)'
    testsuite_proxy_check_response
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'X-Bastion-Remote-IP: 127.0.0.1'
    contain 'X-Bastion-Request-Length: 0'
    contain 'X-Bastion-Auth-Mode: self/default'
    contain 'X-Bastion-Local-Status: 412'
    contain 'Content-Type: text/plain'
    contain "Unable to find (or read) a password file in context 'self' and name '$account0'"

    # generate an egress password
    success generate_egress_pwd $a0 --osh selfGeneratePassword --do-it
    json .command selfGeneratePassword .error_code OK .value.account $account0 .value.context account

    # and retry
    script bad_certificate "curl -m $default_timeout -vki -H 'X-Bastion-Enforce-Secure: 1' -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    # not all versions of LWP add "(certificate verify failed)" at the end of the below error message, so omit it
    contain "HTTP/1.0 500 Can't connect to 127.0.0.1:9443"
    testsuite_proxy_check_response
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'X-Bastion-Remote-IP: 127.0.0.1'
    contain 'X-Bastion-Request-Length: 0'
    contain 'X-Bastion-Auth-Mode: self/default'
    contain 'X-Bastion-Local-Status: 200 OK'
    contain 'Content-Type: text/plain'
    contain "Can't connect to 127.0.0.1:9443"
    nocontain "X-Bastion-Remote-Client-SSL-Cert-Verify"

    # the refused connection must be logged to syslog
    testsuite_proxy_get_tls_syslog bad_certificate_syslog
    contain 'enforced="1"'
    contain 'verdict="failed"'
    contain 'reason="certificate verify failed"'
    contain 'host="127.0.0.1"'
    contain 'port="9443"'
    contain 'ssl_version=""'
    contain 'ssl_cipher=""'
    contain 'downgraded="0"'

    script insecure "curl -m $default_timeout -vki -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'X-Bastion-Remote-IP: 127.0.0.1'
    contain 'X-Bastion-Request-Length: 0'
    contain 'X-Bastion-Auth-Mode: self/default'
    contain 'X-Bastion-Local-Status: 200 OK'
    contain "X-Bastion-Remote-Client-SSL-Cert-Subject: /CN=testcert"
    contain "X-Bastion-Remote-Client-SSL-Cert-Issuer: /CN=testcert"
    contain "X-Bastion-Remote-Client-SSL-Cipher: "
    contain REGEX "X-Bastion-Remote-Client-SSL-Version: TLSv1_[23]"
    contain "X-Bastion-Remote-Client-SSL-Warning: Peer certificate not verified"
    nocontain "X-Bastion-Remote-Client-SSL-Socket-Class"
    # insecure is enabled, but the remote certificate is self-signed: this would have been refused if it wasn't
    # (OpenSSL 3 says "self-signed", older versions say "self signed")
    contain REGEX "X-Bastion-Remote-Client-SSL-Cert-Verify: FAILED \(self[- ]signed certificate\)"
    contain "X-Bastion-Remote-Status: 200"
    contain "X-Bastion-Remote-Server: Net::Server::HTTP/"
    contain "X-Bastion-Egress-Timing: "
    contain "Content-Length: 64"
    # and this must be logged to syslog, with the same values as the headers above
    testsuite_proxy_get_tls_syslog insecure_syslog
    contain 'host="127.0.0.1"'
    contain 'ip="127.0.0.1"'
    contain 'port="9443"'
    contain 'enforced="0"'
    contain 'verdict="failed"'
    contain REGEX 'reason="self[- ]signed certificate"'
    contain REGEX 'ssl_version="TLSv1_[23]"'
    contain REGEX 'ssl_cipher="[A-Z0-9_-]+"'
    contain 'cert_subject="/CN=testcert"'
    contain 'cert_issuer="/CN=testcert"'
    contain 'downgraded="0"'

    # the device must not be able to spoof the Client-SSL-* headers LWP generates (https egress):
    # the ones LWP sets must have their real value, and the device's Client-SSL-Warning must not be appended
    script client_ssl_spoof_https "curl -m $default_timeout -ski -H 'X-Test-Add-Response-Header-Client-SSL-Cipher: SPOOFED' -H 'X-Test-Add-Response-Header-Client-SSL-Cert-Subject: /CN=SPOOFED' -H 'X-Test-Add-Response-Header-Client-SSL-Cert-Issuer: /CN=SPOOFED' -H 'X-Test-Add-Response-Header-Client-SSL-Version: SPOOFED' -H 'X-Test-Add-Response-Header-Client-SSL-Warning: SPOOFED' -H 'X-Test-Add-Response-Header-Client-SSL-Cert-Verify: OK SPOOFED' -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain REGEX "X-Bastion-Remote-Client-SSL-Cert-Verify: FAILED \(self[- ]signed certificate\)"
    contain "X-Bastion-Remote-Client-SSL-Cert-Subject: /CN=testcert"
    contain "X-Bastion-Remote-Client-SSL-Cert-Issuer: /CN=testcert"
    contain REGEX "X-Bastion-Remote-Client-SSL-Version: TLSv1_[23]"
    contain "X-Bastion-Remote-Client-SSL-Warning: Peer certificate not verified"
    nocontain "SPOOFED"
    # the syslog line must have the real values too
    testsuite_proxy_get_tls_syslog client_ssl_spoof_https_syslog
    contain 'verdict="failed"'
    contain REGEX 'reason="self[- ]signed certificate"'
    contain REGEX 'ssl_version="TLSv1_[23]"'
    contain 'cert_subject="/CN=testcert"'
    contain 'cert_issuer="/CN=testcert"'
    nocontain 'SPOOFED'

    # the device must not be able to fake an LWP-internal response either (Client-Warning is used by our
    # downgrade logic): with a fake TLS-like error and a spoofed Client-Warning, we must not downgrade
    script client_warning_spoof "curl -m $default_timeout -ski -H 'X-Bastion-Allow-Downgrade: 1' -H 'X-Test-Add-Response-Header-Status: 500 fake error:0A000102:SSL routines::unsupported protocol' -H 'X-Test-Add-Response-Header-Client-Warning: Internal response' -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 500 fake error"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain 'X-Bastion-Remote-Status: 500 fake error'
    nocontain 'X-Bastion-Downgraded'
    testsuite_proxy_get_tls_syslog client_warning_spoof_syslog
    contain 'port="9443"'
    contain REGEX 'ssl_version="TLSv1_[23]"'
    contain 'downgraded="0"'
    nocontain 'SPOOFED'

    # same, with the Client-Warning injected through a <meta http-equiv> tag of an HTML answer
    script client_warning_meta_spoof "curl -m $default_timeout -ski -H 'X-Bastion-Allow-Downgrade: 1' -H 'X-Test-Html-Meta-Spoof: 1' -H 'X-Test-Add-Response-Header-Status: 500 fake error:0A000102:SSL routines::unsupported protocol' -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 500 fake error"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain 'X-Bastion-Remote-Status: 500 fake error'
    contain REGEX "X-Bastion-Remote-Client-SSL-Cert-Verify: FAILED \(self[- ]signed certificate\)"
    contain "X-Bastion-Remote-Client-SSL-Warning: Peer certificate not verified"
    nocontain 'X-Bastion-Downgraded'
    # the SPOOFED values are in the body of the device's answer, but must not appear in any header
    nocontain '^X-Bastion-Remote-Client-SSL-[^:]+: .*SPOOFED'
    testsuite_proxy_get_tls_syslog client_warning_meta_spoof_syslog
    contain 'verdict="failed"'
    contain REGEX 'reason="self[- ]signed certificate"'
    contain REGEX 'ssl_version="TLSv1_[23]"'
    contain 'downgraded="0"'
    nocontain 'SPOOFED'

    # a header sent twice by the device must not break our answer
    script duplicate_content_type "curl -m $default_timeout -ski -H 'X-Test-Duplicate-Content-Type: 1' -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain 'X-Bastion-Remote-Status: 200'
    contain 'Content-Type: text/plain, text/plain'

    # the device is reached by name: SNI and the certificate check must use this name, not the resolved IP.
    # The chain error is reported first, as it's what LWP would have failed on first.
    script insecure_by_name "curl -m $default_timeout -ski -u '$account0@test@localhost%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    contain 'X-Bastion-Remote-Host: localhost'
    contain 'X-Bastion-Local-Status: 200 OK'
    contain REGEX "X-Bastion-Remote-Client-SSL-Cert-Verify: FAILED \(self[- ]signed certificate\)"
    testsuite_proxy_get_tls_syslog insecure_by_name_syslog
    contain 'host="localhost"'
    contain 'ip="127.0.0.1"'
    contain 'port="9443"'
    contain 'verdict="failed"'
    contain REGEX 'reason="self[- ]signed certificate"'

    # generate 1MB of data
    script one_megabyte "curl -m $default_timeout -vki -H 'X-Test-Add-Response-Header-Content-Type: application/json' -H 'X-Test-Wanted-Response-Size: 1000000' -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: application/json'
    contain 'X-Bastion-Remote-IP: 127.0.0.1'
    contain 'X-Bastion-Request-Length: 0'
    contain 'X-Bastion-Auth-Mode: self/default'
    contain 'X-Bastion-Local-Status: 200 OK'
    contain "X-Bastion-Remote-Client-SSL-Cert-Subject: "
    contain "X-Bastion-Remote-Client-SSL-Cipher: "
    contain "X-Bastion-Remote-Client-SSL-Warning: Peer certificate not verified"
    contain "X-Bastion-Remote-Status: 200"
    contain "X-Bastion-Remote-Server: Net::Server::HTTP/"
    contain "X-Bastion-Egress-Timing: "
    contain "Content-Length: 1000000"
    # the 1M upload can be a bit harsh, wait for the daemon to be available again
    wait_for_proxy_up "waiting for daemon availability after the big download"

    # redirects, with the default allow_redirects policy (same-host)
    # a host-less redirect must be followed
    script redirect_samehost_hostless "curl -m $default_timeout -ski -H 'X-Test-Redirect-To: /redirected' -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain "X-Bastion-Remote-Status: 200 OK"
    contain "Content-Length: 64"
    nocontain 'X-Bastion-Remote-Location: '
    # one TLS connection per hop, hence one syslog line per hop
    testsuite_proxy_get_tls_syslog redirect_samehost_hostless_syslog 2
    nocontain 'host="127\.0\.0\.2"'
    nocontain 'port="9080"'

    # a redirect to the same host and port must be followed
    script redirect_samehost_absolute "curl -m $default_timeout -ski -H 'X-Test-Redirect-To: https://127.0.0.1:9443/redirected' -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain "X-Bastion-Remote-Status: 200 OK"
    contain "Content-Length: 64"
    nocontain 'X-Bastion-Remote-Location: '

    # a redirect to another port must not be followed, and relayed to the client instead
    script redirect_samehost_other_port "curl -m $default_timeout -ski -H 'X-Test-Redirect-To: https://127.0.0.1:9080/redirected' -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 302 Found"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain "X-Bastion-Remote-Status: 302 Found"
    contain "X-Bastion-Remote-Location: https://127.0.0.1:9080/redirected"
    # the redirect is not followed: only our connection to the device is logged
    testsuite_proxy_get_tls_syslog redirect_samehost_other_port_syslog
    contain 'port="9443"'

    # a redirect to another host must not be followed either
    script redirect_samehost_other_host "curl -m $default_timeout -ski -H 'X-Test-Redirect-To: https://127.0.0.2:9443/redirected' -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 302 Found"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain "X-Bastion-Remote-Status: 302 Found"
    contain "X-Bastion-Remote-Location: https://127.0.0.2:9443/redirected"
    testsuite_proxy_get_tls_syslog redirect_samehost_other_host_syslog
    contain 'host="127.0.0.1"'
    nocontain 'host="127\.0\.0\.2"'

    # graceful, zero-downtime reload (SIGHUP): an in-flight request must drain to completion
    # (not be killed), and requests issued during/after the reload must still be served because
    # the listening socket is never closed. The daemon re-execs in place, so the watchdog in
    # target_role.sh (which only restarts it if no process matches) doesn't interfere.
    # The reload also logs to syslog, so ignore that for the code-warning check.
    ignorecodewarn 'osh-http-proxy-daemon'
    script graceful_reload "
        out=\$(mktemp)
        # 1) start a slow request: the fake remote holds the response for 8s, keeping it in-flight
        curl -vki --max-time 40 -H 'X-Test-Response-Delay: 8' -H 'X-Test-Wanted-Response-Size: 54321' -u '$account0@test@127.0.0.1%9443:$proxy_password' 'https://$remote_ip:$remote_proxy_port/test' > \"\$out\" 2>&1 &
        slowpid=\$!
        # 2) give it time to be accepted and connected to the slow remote
        sleep 3
        # 3) gracefully reload the daemon while that request is still in-flight (single-word remote
        #    command, so no shell-quoting headaches; -f matches the daemon, not the worker)
        $r0 pkill -HUP -f osh-http-proxy-daemon
        # 4) a brand new request right after the reload must succeed (socket stayed bound)
        sleep 1
        echo BEGIN_NEW_REQUEST
        # pipe through cat so curl's stdout isn't a TTY: recent curl colorizes header names
        # with ANSI codes otherwise, which would break the literal Content-Length match below
        curl -vki --max-time 15 -u '$account0@test@127.0.0.1%9443:$proxy_password' 'https://$remote_ip:$remote_proxy_port/test' | cat
        echo END_NEW_REQUEST
        # 5) the in-flight request must have completed with its full body, not been cut off
        wait \$slowpid
        echo BEGIN_INFLIGHT_RESULT
        cat \"\$out\"
        echo END_INFLIGHT_RESULT
        rm -f \"\$out\"
    "
    retvalshouldbe 0
    # the new request (no size header -> 64-byte body) was served during/after the reload
    contain 'BEGIN_NEW_REQUEST'
    contain 'Content-Length: 64'
    # the in-flight request (54321-byte body) drained to completion instead of being killed
    contain 'Content-Length: 54321'
    # no refused connection (listener gap) and no truncated/killed in-flight response
    nocontain 'Connection refused'
    nocontain 'Failed to connect'
    nocontain 'Empty reply from server'

    # the daemon must still be healthy after the in-place reload
    script post_reload_health "curl -m $default_timeout -vki https://$remote_ip:$remote_proxy_port/bastion-health-check | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'running nominally'
    contain 'X-Bastion-Local-Status: 200 OK'

    # use a disallowed method
    script forbidden_method "curl -m $default_timeout -vki -X PUT -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 400 Bad Request (method forbidden)'
    contain 'X-Bastion-Local-Status: 400 Bad Request (method forbidden)'
    contain 'Server: The Bastion'
    contain 'X-Bastion-Instance: '
    contain 'X-Bastion-ReqID: '
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'is forbidden by policy'

    # use alternate config to only allow more methods
    success config_swap $r0 "\"cp $opt_remote_etc_bastion/osh-http-proxy-methods.conf $opt_remote_etc_bastion/osh-http-proxy.conf\""

    # when daemon will restart, it'll log stuff, ignore it
    ignorecodewarn 'osh-http-proxy-daemon'
    # pkill doesn't work well under FreeBSD, so do it ourselves for all OSes. loop with SIGKILL
    # until no proxyhttp-owned process remains: a plain SIGTERM lets the daemon shut down
    # gracefully and, on FreeBSD, keep the listen socket bound for several seconds, while any
    # children respawned during the kill race would survive a one-shot snapshot kill. only once
    # the old tree is fully reaped can target_role.sh's watchdog bring up a fresh daemon.
    success force_restart $r0 "\"while ps -U proxyhttp -o pid= | grep -q '[0-9]'; do ps -U proxyhttp -o pid= | xargs -r kill -KILL 2>/dev/null; sleep 0.2; done; true\""
    # then actively wait for the freshly-restarted daemon to actually answer (the old one is
    # guaranteed gone above, so a successful health-check means the new daemon is serving)
    wait_for_proxy_up "waiting for daemon restart"

    # post some data
    script post_data "curl -m $default_timeout -vki -X POST -d somedata -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'X-Bastion-Remote-IP: 127.0.0.1'
    contain 'X-Bastion-Request-Length: 8'
    contain 'X-Bastion-Auth-Mode: self/default'
    contain 'X-Bastion-Local-Status: 200 OK'
    contain "X-Bastion-Remote-Client-SSL-Cert-Subject: "
    contain "X-Bastion-Remote-Client-SSL-Cipher: "
    contain "X-Bastion-Remote-Client-SSL-Warning: Peer certificate not verified"
    contain "X-Bastion-Remote-Status: 200"
    contain "X-Bastion-Remote-Server: Net::Server::HTTP/"
    contain "X-Bastion-Egress-Timing: "
    contain "Content-Length: 8"
    contain "somedata"

    # put some data
    script patch_data "curl -m $default_timeout -vki -X PUT -d somedata -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'X-Bastion-Remote-IP: 127.0.0.1'
    contain 'X-Bastion-Request-Length: 8'
    contain 'X-Bastion-Auth-Mode: self/default'
    contain 'X-Bastion-Local-Status: 200 OK'
    contain "X-Bastion-Remote-Client-SSL-Cert-Subject: "
    contain "X-Bastion-Remote-Client-SSL-Cipher: "
    contain "X-Bastion-Remote-Client-SSL-Warning: Peer certificate not verified"
    contain "X-Bastion-Remote-Status: 200"
    contain "X-Bastion-Remote-Server: Net::Server::HTTP/"
    contain "X-Bastion-Egress-Timing: "
    contain "Content-Length: 8"
    contain "somedata"

    # put some data with no body
    script patch_data_no_body "curl -m $default_timeout -vki -X PUT -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'X-Bastion-Remote-IP: 127.0.0.1'
    contain 'X-Bastion-Request-Length: 0'
    contain 'X-Bastion-Auth-Mode: self/default'
    contain 'X-Bastion-Local-Status: 200 OK'
    contain "X-Bastion-Remote-Client-SSL-Cert-Subject: "
    contain "X-Bastion-Remote-Client-SSL-Cipher: "
    contain "X-Bastion-Remote-Client-SSL-Warning: Peer certificate not verified"
    contain "X-Bastion-Remote-Status: 200"
    contain "X-Bastion-Remote-Server: Net::Server::HTTP/"
    contain "X-Bastion-Egress-Timing: "
    contain "Content-Length: 64"

    # redirects, with the allow_redirects policy set to none
    # use alternate config, no need to restart the daemon as this is handled by the worker
    success config_swap_redirects_none $r0 "\"cp $opt_remote_etc_bastion/osh-http-proxy-redirects-none.conf $opt_remote_etc_bastion/osh-http-proxy.conf\""

    # even a host-less redirect must not be followed, and the target relayed as an absolute URL
    script redirect_none_hostless "curl -m $default_timeout -ski -H 'X-Test-Redirect-To: /redirected' -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 302 Found"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain "X-Bastion-Remote-Status: 302 Found"
    contain "X-Bastion-Remote-Location: https://127.0.0.1:9443/redirected"

    # redirects, with the allow_redirects policy set to any
    # use alternate config, no need to restart the daemon as this is handled by the worker
    success config_swap_redirects_any $r0 "\"cp $opt_remote_etc_bastion/osh-http-proxy-redirects-any.conf $opt_remote_etc_bastion/osh-http-proxy.conf\""

    # a redirect to another host must be followed
    script redirect_any_other_host "curl -m $default_timeout -ski -H 'X-Test-Redirect-To: https://127.0.0.2:9443/redirected' -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain "X-Bastion-Remote-Status: 200 OK"
    contain "Content-Length: 64"
    nocontain 'X-Bastion-Remote-Location: '
    # both hops are logged, each with its own name and IP
    testsuite_proxy_get_tls_syslog redirect_any_other_host_syslog 2
    contain REGEX 'host="127\.0\.0\.1" ip="127\.0\.0\.1" port="9443" enforced="0" verdict="failed"'
    contain REGEX 'host="127\.0\.0\.2" ip="127\.0\.0\.2" port="9443" enforced="0" verdict="failed"'

    # the device password must follow a same-origin redirect (the target requires it)...
    script redirect_any_same_origin_auth "curl -m $default_timeout -ski -H 'X-Test-Require-Auth: 1' -H 'X-Test-Redirect-To: /redirected' -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain "X-Bastion-Remote-Status: 200 OK"
    nocontain 'X-Bastion-Remote-Location: '

    # ... but must not be sent along a cross-origin one: the redirect is followed, and the target answers 401
    script redirect_any_cross_origin_noauth "curl -m $default_timeout -ski -H 'X-Test-Require-Auth: 1' -H 'X-Test-Redirect-To: https://127.0.0.2:9443/redirected' -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 401 Unauthorized"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain "X-Bastion-Remote-Status: 401 Unauthorized"
    nocontain 'X-Bastion-Remote-Location: '

    # but a redirect to a protocol not in allowed_egress_protocols must still be refused:
    # it is not followed, and relayed to the client as is (whatever the LWP version)
    script redirect_any_forbidden_protocol "curl -m $default_timeout -ski -H 'X-Test-Redirect-To: http://127.0.0.1:9080/redirected' -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 302 Found"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain "X-Bastion-Remote-Status: 302 Found"
    contain "X-Bastion-Remote-Location: http://127.0.0.1:9080/redirected"
    testsuite_proxy_get_tls_syslog redirect_any_forbidden_protocol_syslog
    contain 'port="9443"'
    nocontain 'port="9080"'

    # and so must a https => http redirect, even when http is in allowed_egress_protocols
    success config_swap_redirects_any_http $r0 "\"cp $opt_remote_etc_bastion/osh-http-proxy-redirects-any-http.conf $opt_remote_etc_bastion/osh-http-proxy.conf\""

    script redirect_any_https_to_http "curl -m $default_timeout -ski -H 'X-Test-Redirect-To: http://127.0.0.1:9080/redirected' -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 302 Found"
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain "X-Bastion-Remote-Status: 302 Found"
    contain "X-Bastion-Remote-Location: http://127.0.0.1:9080/redirected"

    success config_swap_redirects_any_back $r0 "\"cp $opt_remote_etc_bastion/osh-http-proxy-redirects-any.conf $opt_remote_etc_bastion/osh-http-proxy.conf\""

    # use a disallowed egress method
    script forbidden_egress_protocol "curl -m $default_timeout -vki -H 'X-Bastion-Egress-Protocol: http' -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 400 Bad Request (forbidden egress protocol)'
    contain 'X-Bastion-Local-Status: 400 Bad Request (forbidden egress protocol)'
    testsuite_proxy_check_response
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'not allowed by policy'
    testsuite_proxy_get_tls_syslog forbidden_egress_protocol_syslog 0

    testsuite_proxy_egress_tls "$proxy_password"
    testsuite_proxy_egress_ca_file "$proxy_password"

    # use alternate config to only allow http egress
    success config_swap $r0 "\"cp $opt_remote_etc_bastion/osh-http-proxy-httponly.conf $opt_remote_etc_bastion/osh-http-proxy.conf\""

    # when daemon will restart, it'll log stuff, ignore it
    ignorecodewarn 'osh-http-proxy-daemon'
    # pkill doesn't work well under FreeBSD, so do it ourselves for all OSes (see above for the
    # rationale behind the SIGKILL loop and the active readiness poll)
    success force_restart $r0 "\"while ps -U proxyhttp -o pid= | grep -q '[0-9]'; do ps -U proxyhttp -o pid= | xargs -r kill -KILL 2>/dev/null; sleep 0.2; done; true\""
    wait_for_proxy_up "waiting for daemon restart"

    # when daemon will restart, it'll log stuff, ignore it
    ignorecodewarn 'osh-http-proxy-daemon'
    # http should be allowed now
    script allowed_http_egress "curl -m $default_timeout -vki -H 'X-Bastion-Egress-Protocol: http' -u '$account0@test@127.0.0.1%22:$proxy_password' https://$remote_ip:$remote_proxy_port/test 2>&1 | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 200'
    testsuite_proxy_check_response
    contain 'X-Bastion-Remote-Host: 127.0.0.1'
    contain 'X-Bastion-Remote-IP: 127.0.0.1'
    contain 'X-Bastion-Local-Status: 200 OK'
    nocontain 'WWW-Authenticate: '
    nocontain "X-Bastion-Remote-Client-SSL"
    contain 'SSH-2.0'
    # plain http egress: there's no TLS connection to log
    testsuite_proxy_get_tls_syslog allowed_http_egress_syslog 0

    # with plain http egress, LWP sets no Client-SSL-* header, so the device must not be able to make it
    # look like the connection was encrypted by sending its own
    script client_ssl_spoof_http "curl -m $default_timeout -ski -H 'X-Bastion-Egress-Protocol: http' -H 'X-Test-Add-Response-Header-Client-SSL-Cipher: SPOOFED' -H 'X-Test-Add-Response-Header-Client-SSL-Cert-Subject: /CN=SPOOFED' -H 'X-Test-Add-Response-Header-Client-SSL-Version: SPOOFED' -H 'X-Test-Add-Response-Header-Client-SSL-Warning: SPOOFED' -H 'X-Test-Add-Response-Header-Client-SSL-Cert-Verify: OK SPOOFED' -u '$account0@test@127.0.0.1%9080:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 200 OK'
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    nocontain "X-Bastion-Remote-Client-SSL"
    nocontain "SPOOFED"
    testsuite_proxy_get_tls_syslog client_ssl_spoof_http_syslog 0

    # same, through <meta http-equiv> tags of an HTML answer
    script client_ssl_meta_spoof_http "curl -m $default_timeout -ski -H 'X-Bastion-Egress-Protocol: http' -H 'X-Test-Html-Meta-Spoof: 1' -u '$account0@test@127.0.0.1%9080:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 200'
    testsuite_proxy_check_response
    contain 'X-Bastion-Local-Status: 200 OK'
    contain 'meta spoof'
    nocontain "X-Bastion-Remote-Client-SSL"
    testsuite_proxy_get_tls_syslog client_ssl_meta_spoof_http_syslog 0

    # take this opportunity to test the remote-host header (otherwise, call is the same as above)
    script allowed_http_egress_test_host "curl -m $default_timeout -vki -H 'X-Bastion-Egress-Protocol: http' -u '$account0@test@localhost%22:$proxy_password' https://$remote_ip:$remote_proxy_port/test 2>&1 | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 200'
    testsuite_proxy_check_response
    contain 'X-Bastion-Remote-Host: localhost'
    contain 'X-Bastion-Remote-IP: 127.0.0.1'
    contain 'X-Bastion-Local-Status: 200 OK'
    nocontain 'WWW-Authenticate: '
    nocontain "X-Bastion-Remote-Client-SSL"
    contain 'SSH-2.0'

    # and https disallowed
    script forbidden_https_egress "curl -m $default_timeout -vki -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 400 Bad Request (forbidden egress protocol)'
    contain 'X-Bastion-Local-Status: 400 Bad Request (forbidden egress protocol)'
    testsuite_proxy_check_response
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'not allowed by policy'

    # try an IPv6
    script ipv6 "curl -m $default_timeout -vki -H 'X-Bastion-Egress-Protocol: http' -u '$account0@test@[::1]%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'ERR_IP_VERSION_DISABLED'

    # A failure *inside* _exec_worker_and_get_result() must still yield exactly one HTTP response.
    ignorecodewarn 'osh-http-proxy-daemon'
    script worker_failure "
        $r0 chmod 0000 /opt/bastion/bin/proxy/osh-http-proxy-worker
        curl -m $default_timeout -vki https://$remote_ip:$remote_proxy_port/bastion-health-check | cat
        # restore unconditionally, whatever happened above (FILEMODE 0755, see the worker's header)
        $r0 chmod 0755 /opt/bastion/bin/proxy/osh-http-proxy-worker
    "
    retvalshouldbe 0
    contain 'HTTP/1.0 500 Internal Error (worker returned a non-zero exit value)'
    contain 'Worker returned a non-zero exit value'
    testsuite_proxy_check_response
    nocontain 'WWW-Authenticate: '

    # the worker is restored, so the proxy must be healthy again
    script post_worker_failure_health "curl -m $default_timeout -vki https://$remote_ip:$remote_proxy_port/bastion-health-check | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'running nominally'
    testsuite_proxy_check_response
}

[ "${remote_proxy_port:-0}" != 0 ] && testsuite_proxy
unset -f testsuite_proxy
unset -f testsuite_proxy_check_response
unset -f testsuite_proxy_set_egress_tls
unset -f testsuite_proxy_egress_tls
unset -f testsuite_proxy_set_egress_ca_file
unset -f testsuite_proxy_egress_ca_file
unset -f testsuite_proxy_get_tls_syslog
