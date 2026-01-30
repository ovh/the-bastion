================
groupSetServers
================

Replace a group's current ACL by a new list
===========================================


.. admonition:: usage
   :class: cmdusage

   --osh groupSetServers --group GROUP [OPTIONS]

.. program:: groupSetServers


.. option:: --group GROUP

   Specify which group to modify the ACL of

.. option:: --dry-run

   Don't actually modify the ACL, just report whether the input contains errors

.. option:: --skip-errors

   Don't abort on STDIN parsing errors, just skip the non-parseable lines


The list of the assets to constitute the new ACL should then be given on ``STDIN``,
respecting the following format: ``[USER@]HOST[:PORT][ COMMENT]``, with ``USER`` and ``PORT`` being optional,
and ``HOST`` being either a hostname, an IP, or an IP block in CIDR notation. The ``COMMENT`` is also optional,
and may contain spaces.

Example of valid lines to be fed through ``STDIN``::

  server12.example.org
  logs@server
  192.0.2.21
  host1.example.net:2222 host1 on secondary sshd with alternate port
  root@192.0.2.0/24 production database cluster
