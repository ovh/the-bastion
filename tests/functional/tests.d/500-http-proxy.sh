# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2317,SC2086,SC2016,SC2046
# below: convoluted way that forces shellcheck to source our caller
# shellcheck source=tests/functional/launch_tests_on_instance.sh
. "$(dirname "${BASH_SOURCE[0]}")"/dummy

testsuite_proxy_check_headers()
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
    # headers that should always be there
    contain 'Server: The Bastion'
    contain 'X-Bastion-Instance: '
    contain 'X-Bastion-ReqID: '
}

testsuite_proxy()
{
    # note: we use "curl | cat" to force curl to disable color output, to be grep friendly,
    # as a --no-color or similar option doesn't seem to exist for curl.

    # check that the proxy is up
    script monitoring "curl -m $default_timeout -vki https://$remote_ip:$remote_proxy_port/bastion-health-check | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'running nominally'

    # and let's go
    script noauth "curl -m $default_timeout -vki https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    testsuite_proxy_check_headers
    contain 'HTTP/1.0 401 Authorization required (no auth provided)'
    contain 'WWW-Authenticate: Basic realm="bastion"'
    contain 'Content-Type: text/plain'
    contain 'No authentication provided, and authentication is mandatory'

    script bad_auth_format "curl -m $default_timeout -vki -u test:test https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 400 Bad Request (bad login format)'
    testsuite_proxy_check_headers
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
    testsuite_proxy_check_headers
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
    testsuite_proxy_check_headers
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
    testsuite_proxy_check_headers
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain "User name 'te!st' has forbidden characters"

    script good_auth_no_access "curl -m $default_timeout -vki -u '$account0@test@127.0.0.1:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 403 Access Denied (access denied to remote)'
    testsuite_proxy_check_headers
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
    testsuite_proxy_check_headers
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
    testsuite_proxy_check_headers
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
    testsuite_proxy_check_headers
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'X-Bastion-Remote-IP: 127.0.0.1'
    contain 'X-Bastion-Request-Length: 0'
    contain 'X-Bastion-Auth-Mode: self/default'
    contain 'X-Bastion-Local-Status: 200 OK'
    contain 'Content-Type: text/plain'
    contain "Can't connect to 127.0.0.1:9443"

    script insecure "curl -m $default_timeout -vki -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_headers
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
    script one_megabyte "curl -m $default_timeout -vki -H 'X-Test-Add-Response-Header-Content-Type: application/json' -H 'X-Test-Wanted-Response-Size: 1000000' -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain "HTTP/1.0 200 OK"
    testsuite_proxy_check_headers
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

    # use a disallowed method
    script forbidden_method "curl -m $default_timeout -vki -X PUT -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 400 Bad Request (method forbidden)'
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
    testsuite_proxy_check_headers
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
    testsuite_proxy_check_headers
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
    testsuite_proxy_check_headers
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

    # use a disallowed egress method
    script forbidden_egress_protocol "curl -m $default_timeout -vki -H 'X-Bastion-Egress-Protocol: http' -u '$account0@test@127.0.0.1%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 400 Bad Request (forbidden egress protocol)'
    testsuite_proxy_check_headers
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'not allowed by policy'

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
    testsuite_proxy_check_headers
    contain 'X-Bastion-Remote-Host: 127.0.0.1'
    contain 'X-Bastion-Remote-IP: 127.0.0.1'
    contain 'X-Bastion-Local-Status: 200 OK'
    nocontain 'WWW-Authenticate: '
    nocontain "X-Bastion-Remote-Client-SSL"
    contain 'SSH-2.0'

    # take this opportunity to test the remote-host header (otherwise, call is the same as above)
    script allowed_http_egress_test_host "curl -m $default_timeout -vki -H 'X-Bastion-Egress-Protocol: http' -u '$account0@test@localhost%22:$proxy_password' https://$remote_ip:$remote_proxy_port/test 2>&1 | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'HTTP/1.0 200'
    testsuite_proxy_check_headers
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
    testsuite_proxy_check_headers
    nocontain 'WWW-Authenticate: '
    contain 'Content-Type: text/plain'
    contain 'not allowed by policy'

    # try an IPv6
    script ipv6 "curl -m $default_timeout -vki -H 'X-Bastion-Egress-Protocol: http' -u '$account0@test@[::1]%9443:$proxy_password' https://$remote_ip:$remote_proxy_port/test | cat; exit \${PIPESTATUS[0]}"
    retvalshouldbe 0
    contain 'ERR_IP_VERSION_DISABLED'
}

[ "${remote_proxy_port:-0}" != 0 ] && testsuite_proxy
unset -f testsuite_proxy
unset -f testsuite_proxy_check_headers
