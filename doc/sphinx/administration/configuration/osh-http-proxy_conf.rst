===================
osh-http-proxy.conf
===================

 .. note::

    This module is optional, and disabled by default.
    To know more about the HTTP Proxy feature of The Bastion,
    please check the :doc:`/using/http_proxy` section

Option List
===========

HTTP Proxy configuration options
--------------------------------

These options modify the behavior of the HTTP Proxy, an optional module of The Bastion

- `enabled`_
- `port`_
- `ssl_certificate`_
- `ssl_key`_
- `ciphers`_
- `egress_ciphers`_
- `egress_ca_file`_
- `allow_downgrade`_
- `downgraded_egress_ciphers`_
- `insecure`_
- `min_servers`_
- `max_servers`_
- `min_spare_servers`_
- `max_spare_servers`_
- `timeout`_
- `log_request_response`_
- `log_request_response_max_size`_
- `allowed_methods`_
- `allowed_egress_protocols`_
- `allow_redirects`_

Option Reference
================

HTTP Proxy configuration
------------------------

enabled
*******

:Type: ``bool``

:Default: ``false``

Whether the HTTP proxy daemon daemon is enabled or not. If it's not enabled, it'll exit when started.
Of course, if you want to enable this daemon, you should **also** configure your init system to start it
for you. Both sysV-style scripts and systemd unit files are provided.
For systemd, using `systemctl enable osh-http-proxy.service` should be enough.
For sysV-style inits, it depends on the scripts provided for your distro,
but usually `update-rc.d osh-http-proxy defaults` then `update-rc.d osh-http-proxy enable` should
do the trick.

port
****

:Type: ``int, 1024 to 65535``

:Default: ``8443``

The port to listen to. The daemon runs unprivileged (as the 'proxyhttp' user) and never
binds as root, so this must be a non-privileged port (>= 1024). If you need to expose the
proxy on a privileged port such as 443, redirect it to this port at the firewall level
(e.g. an iptables/pf REDIRECT rule).

ssl_certificate
***************

:Type: ``string``

:Default: ``/etc/ssl/certs/ssl-cert-snakeoil.pem``

The file that contains the server SSL certificate in PEM format.
For tests, install the ``ssl-cert`` package and point this configuration item
to the snakeoil certs (which is the default).

ssl_key
*******

:Type: ``string``

:Default: ``/etc/ssl/private/ssl-cert-snakeoil.key``

The file that contains the server SSL key in PEM format.
For tests, install the ``ssl-cert`` package and point this configuration item
to the snakeoil certs (which is the default).

ciphers
*******

:Type: ``string``

:Default: ``""``

:Example: ``"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"``

The ordered list the TLS server ciphers (ingress side), in ``openssl`` classic format. Use ``openssl ciphers``
to see what your system supports, an empty list leaves the choice to your openssl libraries default
values (system-dependent)

egress_ciphers
**************

:Type: ``string``

:Default: ``""``

:Example: ``"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"``

The ordered list the TLS client ciphers (egress side), in ``openssl`` classic format. Use ``openssl ciphers``
to see what your system supports, an empty list leaves the choice to your openssl libraries default
values (system-dependent). Note that this only applies to TLS versions up to 1.2, TLS 1.3 ciphersuites
are configured separately by OpenSSL and are not affected by this setting

egress_ca_file
**************

:Type: ``string``

:Default: ``""``

:Example: ``"/etc/ssl/certs/my-internal-ca.pem"``

Path to a file containing the CA certificates (PEM format) to verify the remote devices' certificates against
(egress side). If empty, the system's default CA store is used. When specified, it's used instead of the
system's default CA store, not in addition to it. As the egress requests are made under the identity
of the bastion account doing the request, this file must be readable by all the bastion accounts
(e.g. root:root with 0644 permissions). If this file is not readable, all the egress
requests are refused (and a warning is logged to syslog), as we never silently fall back to the
default CA store. Note that this is also used to compute the ``X-Bastion-Remote-Client-SSL-Cert-Verify``
diagnostic header when ``insecure`` is enabled

allow_downgrade
***************

:Type: ``bool``

:Default: ``true``

Allow the client to request egress SSL negociation downgrade to TLSv1 if the default negociation fails,
through the ``X-Bastion-Allow-Downgrade`` header. Set to false to ignore this header

downgraded_egress_ciphers
*************************

:Type: ``string``

:Default: ``""``

:Example: ``"DEFAULT:@SECLEVEL=0"``

When the client allows egress SSL negociation downgrade to TLSv1, additionally set this list of ciphers

insecure
********

:Type: ``bool``

:Default: ``false``

Whether to ignore SSL certificate verification for the connection between the bastion and the devices.
Note that even when enabled, the certificate is still verified, but not enforced: the result of
this verification is returned to the client through the ``X-Bastion-Remote-Client-SSL-Cert-Verify``
header, which can help migrating to ``false`` by detecting beforehand which devices would be refused

min_servers
***********

:Type: ``int, 1 to 8192``

:Default: ``8``

Number of child processes to start at launch

max_servers
***********

:Type: ``int, 1 to 8192``

:Default: ``32``

Hard maximum number of child processes that can be active at any given time no matter what
When all workers are occupied, the daemon logs a warning through syslog (at most once per
minute), followed by a recovery message with the saturation duration for reported episodes.
This indicates exhausted capacity, not that connections have necessarily waited.
Monitoring starts afresh on SIGHUP, excluding old workers still draining requests.

min_spare_servers
*****************

:Type: ``int, 1 to 8192``

:Default: ``8``

The daemon will ensure that there is at least this number of children idle & ready to accept
new connections (as long as max_servers is not reached)

max_spare_servers
*****************

:Type: ``int, 1 to 8192``

:Default: ``16``

The daemon will kill *idle* children to keep their number below this maximum when traffic is low

timeout
*******

:Type: ``int, 1 to 3600``

:Default: ``120``

Timeout delay (in seconds) for the connection between the bastion and the devices

log_request_response
********************

:Type: ``bool``

:Default: ``true``

When enabled, the complete response of the device to the request we forwarded will be logged,
otherwise we'll only log the response headers

log_request_response_max_size
*****************************

:Type: ``int, 0 to 2^30 (1 GiB)``

:Default: ``65536``

This option only applies when `log_request_response` is true (see above).
When set to zero, the complete response will be logged in the account's home log directory,
including the body, regardless of its size. If set to a positive integer,
the query response will only be partially logged, with full status and headers but the body only up
to the specified size. This is a way to avoid turning off request response logging completely on
very busy bastions, by ensuring logs growth don't get out of hand, as some responses to queries can
take megabytes, with possibly limited added value to traceability.

allowed_methods
***************

:Type: ``array of strings``

:Default: ``["GET","POST"]``

:Example: ``["GET","POST","PUT","PATCH","DELETE"]``

This array lists the allowed HTTP methods. By default, only GET and POST are allowed.
If required, other methods can be added such as PUT, PATCH, DELETE, etc.

allowed_egress_protocols
************************

:Type: ``array of strings``

:Default: ``["https"]``

:Example: ``["https","http"]``

This array lists the allowed egress protocols. By default, only https is allowed.
If required, plain http egress can be enabled here, which is of course strongly discouraged,
but might be required for your environment if business constraints out of your control force you to.

allow_redirects
***************

:Type: ``string``

:Default: ``"same-host"``

Policy to apply when a remote device answers with an HTTP redirect (a 3xx answer with a ``Location`` header).
Possible values are:

- ``same-host``: the redirect is followed by the bastion only if it points to the same host, port and protocol
  as the original request, which includes host-less redirects (e.g. ``Location: /other/page``).
  The redirected request is always sent to the IP that has been checked against the access lists,
  and only ``GET`` and ``HEAD`` requests are redirected.
- ``none``: redirects are never followed.
- ``any``: redirects are followed regardless of their target host and port, as long as their protocol
  is listed in ``allowed_egress_protocols``, and except ``https`` to ``http`` redirects, which are never
  followed. This is **strongly discouraged**: the redirected request might be sent to another host or port
  than the one that has been checked against the account's or group's access lists,
  and against the ``forbiddenNetworks`` configuration option. The egress device password is only sent
  along when the redirect points to the same protocol, host and port as the original request.
  Only ``GET`` and ``HEAD`` requests are redirected.

When a redirect is not followed, the 3xx answer of the device is returned to the client, with the
redirect target in the ``X-Bastion-Remote-Location`` header. The client can then do a new request
to this target through the bastion, which will go through the usual access checks.

