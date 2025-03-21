=====
ping
=====

Ping a remote host from the bastion
===================================


.. admonition:: usage
   :class: cmdusage

   --osh ping [--host HOST] [-c COUNT] [-s PKTSZ] [-t TTL] [-w TIMEOUT]

.. program:: ping


.. option:: --host HOST

   Remote host to ping

.. option:: -c COUNT

   Number of pings to send (default: infinite)

.. option:: -s SIZE

   Specify the packet size to send

.. option:: -t TTL

   TTL to set in the ICMP packet (default: OS dependent)

.. option:: -w TIMEOUT

   Exit unconditionally after this amount of seconds (default & max: 86400)

