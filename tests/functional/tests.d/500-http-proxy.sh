# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_proxy()
{
    # note: we use "curl | cat" to force curl to disable color output, to be grep friendly,
    # as a --no-color or similar option doesn't seem to exist for curl.

    # check that the proxy is up
    script monitoring "curl -ski https://$remote_ip:$remote_proxy_port/bastion-health-check | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'running nominally'

    # and let's go
    script noauth "curl -ski https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 401 Authorization required (no auth provided)'
    contain 'Server: The Bastion'
    contain 'X-Bastion-Instance: '
    contain 'X-Bastion-ReqID: '
    contain 'WWW-Authenticate: Basic realm="bastion"'
    contain 'Content-Type: text/plain'
    contain 'No authentication provided, and authentication is mandatory'

    script bad_auth_format "curl -ski -u test:test https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 400 Bad Request (bad login format)'
    contain 'Server: The Bastion'
    contain 'X-Bastion-Instance: '
    contain 'X-Bastion-ReqID: '
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'Expected an Authorization line with credentials of the form'

    script bad_auth "curl -ski -u test@test@test:test https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
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
    script good_auth_bad_host "curl -ski -u '$account0@test@test.invalid:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 400 Bad Request (ERR_HOST_NOT_FOUND)'
    contain 'Server: The Bastion'
    contain 'X-Bastion-Instance: '
    contain 'X-Bastion-ReqID: '
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'X-Bastion-Remote-IP: test.invalid'
    contain 'X-Bastion-Request-Length: 0'
    contain 'X-Bastion-Local-Status: 400'
    contain 'Content-Type: text/plain'
    contain "Unable to resolve 'test.invalid' (Name or service not known)"

    # change credentials again
    success generate_proxy_password2 $a0 --osh selfGenerateProxyPassword --do-it
    json .command selfGenerateProxyPassword .error_code OK
    local proxy_password2
    proxy_password2=$(get_json | jq -r '.value.password')

    # attempt to use the previous credentials (and fail)
    script bad_auth2 "curl -ski -u test@test@test:test https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 403 Access Denied'
    contain 'Server: The Bastion'
    contain 'X-Bastion-Instance: '
    contain 'X-Bastion-ReqID: '
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'Incorrect username (test) or password (#REDACTED#, length='

    proxy_password="$proxy_password2"

    script good_auth_no_access "curl -ski -u '$account0@test@127.0.0.1:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 403 Access Denied (access denied to remote)'
    contain 'Server: The Bastion'
    contain 'X-Bastion-Instance: '
    contain 'X-Bastion-ReqID: '
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'X-Bastion-Remote-IP: 127.0.0.1'
    contain 'X-Bastion-Request-Length: 0'
    contain 'X-Bastion-Auth-Mode: self/default'
    contain 'X-Bastion-Local-Status: 403'
    contain 'Content-Type: text/plain'
    contain "This account doesn't have access to this user@host tuple (Access denied for $account0 to test@127.0.0.1:443)"

    script good_auth_no_access_other_port "curl -ski -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 403 Access Denied (access denied to remote)'
    contain 'Server: The Bastion'
    contain 'X-Bastion-Instance: '
    contain 'X-Bastion-ReqID: '
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'X-Bastion-Remote-IP: 127.0.0.1'
    contain 'X-Bastion-Request-Length: 0'
    contain 'X-Bastion-Auth-Mode: self/default'
    contain 'X-Bastion-Local-Status: 403'
    contain 'Content-Type: text/plain'
    contain "This account doesn't have access to this user@host tuple (Access denied for $account0 to test@127.0.0.1:9443)"

    # add ourselves access
    success add_personal_access $a0 --osh selfAddPersonalAccess --host 127.0.0.1 --port 9443 --user test --force
    json .command selfAddPersonalAccess .error_code OK

    script missing_egress_pwd "curl -ski -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 412 Precondition Failed (egress password missing)'
    contain 'Server: The Bastion'
    contain 'X-Bastion-Instance: '
    contain 'X-Bastion-ReqID: '
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
    script bad_certificate "curl -ski -H 'X-Bastion-Enforce-Secure: 1' -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    # not all versions of LWP add "(certificate verify failed)" at the end of the below error message, so omit it
    contain "HTTP/1.0 500 Can't connect to 127.0.0.1:9443"
    contain 'Server: The Bastion'
    contain 'X-Bastion-Instance: '
    contain 'X-Bastion-ReqID: '
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'X-Bastion-Remote-IP: 127.0.0.1'
    contain 'X-Bastion-Request-Length: 0'
    contain 'X-Bastion-Auth-Mode: self/default'
    contain 'X-Bastion-Local-Status: 200 OK'
    contain 'Content-Type: text/plain'
    contain "Can't connect to 127.0.0.1:9443"

    script insecure "curl -ski -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    contain 'Server: The Bastion'
    contain 'X-Bastion-Instance: '
    contain 'X-Bastion-ReqID: '
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

    # generate 1MB of data
    script one_megabyte "curl -ski -H 'X-Test-Add-Response-Header-Content-Type: application/json' -H 'X-Test-Wanted-Response-Size: 1000000' -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    contain 'Server: The Bastion'
    contain 'X-Bastion-Instance: '
    contain 'X-Bastion-ReqID: '
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

    # use a disallowed verb
    script forbidden_verb "curl -ski -X OPTIONS -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 400 Bad Request (method forbidden)'
    contain 'Server: The Bastion'
    contain 'X-Bastion-Instance: '
    contain 'X-Bastion-ReqID: '
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'Only GET and POST methods are allowed'

    # post some data
    script post_data "curl -ski -d somedata -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    contain 'Server: The Bastion'
    contain 'X-Bastion-Instance: '
    contain 'X-Bastion-ReqID: '
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

    # try an IPv6
    script ipv6 "curl -ski -u '$account0@test@[::1]%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit ${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'ERR_IP_VERSION_DISABLED'
}

[ "${remote_proxy_port:-0}" != 0 ] && testsuite_proxy
unset -f testsuite_proxy
