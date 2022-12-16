============
realmCreate
============

Declare and create a new trusted realm
======================================


.. admonition:: usage
   :class: cmdusage

   --osh realmCreate --realm REALM --from IP1,IP2 [OPTIONS]

.. program:: realmCreate


.. option:: --realm   REALM

   Realm name to create

.. option:: --comment STRING

   An optional comment when creating the realm. Double-quote if you're under a shell.

.. option:: --from

   IP1,IP2   Comma-separated list of outgoing IPs used by the realm we're declaring (i.e. IPs used by the bastion(s) on the other side)

                      the expected format is the one used by the from="" directive on SSH keys (IP and prefixes are supported)
.. option:: --public-key KEY

   Public SSH key to deposit on the bastion to access this realm. If not present,

                      you'll be prompted interactively for it. Use double-quoting if your're under a shell.
