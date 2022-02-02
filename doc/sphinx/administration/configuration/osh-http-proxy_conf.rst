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
- `insecure`_
- `min_servers`_
- `max_servers`_
- `min_spare_servers`_
- `max_spare_servers`_
- `timeout`_
- `log_request_response`_
- `log_request_response_max_size`_

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

:Type: ``int, 1 to 65535``

:Default: ``8443``

The port to listen to. You can use ports < 1024, in which case privileges will be dropped after binding,
but please ensure your systemd unit file starts the daemon as root in that case.

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

The ordered list the TLS server ciphers, in ``openssl`` classic format. Use ``openssl ciphers``
to see what your system supports, an empty list leaves the choice to your openssl libraries default
values (system-dependent)

insecure
********

:Type: ``bool``

:Default: ``false``

Whether to ignore SSL certificate verification for the connection between the bastion and the devices

min_servers
***********

:Type: ``int, 1 to 512``

:Default: ``8``

Number of child processes to start at launch

max_servers
***********

:Type: ``int, 1 to 512``

:Default: ``32``

Hard maximum number of child processes that can be active at any given time no matter what

min_spare_servers
*****************

:Type: ``int, 1 to 512``

:Default: ``8``

The daemon will ensure that there is at least this number of children idle & ready to accept
new connections (as long as max_servers is not reached)

max_spare_servers
*****************

:Type: ``int, 1 to 512``

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

