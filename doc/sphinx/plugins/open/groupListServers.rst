=================
groupListServers
=================

List the servers (IPs and IP blocks) pertaining to a group
==========================================================


.. admonition:: usage
   :class: cmdusage

   --osh groupListServers --group GROUP [--reverse-dns]

.. program:: groupListServers


.. option:: --group GROUP

   List the servers of this group

.. option:: --reverse-dns

   Attempt to resolve the reverse hostnames (SLOW!)

.. option:: --include PATTERN

   Only include servers matching the given PATTERN (see below)

                        This option can be used multiple times to refine results
.. option:: --exclude PATTERN

   Omit servers matching the given PATTERN (see below)

                        This option can be used multiple times.
                        Note that --exclude takes precedence over --include

**Note:** PATTERN supports the ``*`` and ``?`` wildcards.
If PATTERN is a simple string without wildcards, then names containing this string will be considered.
The matching is done on the text output of the command.
