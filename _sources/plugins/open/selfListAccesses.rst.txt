=================
selfListAccesses
=================

Show the list of servers you have access to
===========================================


.. admonition:: usage
   :class: cmdusage

   --osh selfListAccesses [--hide-groups] [--reverse-dns]

.. program:: selfListAccesses


.. option:: --hide-groups

   Don't show the machines you have access to through group rights.

                       In other words, list only your personal accesses.
.. option:: --reverse-dns

   Attempt to resolve the reverse hostnames (SLOW!)

.. option:: --include PATTERN

   Only include accesses matching the given PATTERN (see below)

                        This option can be used multiple times to refine results
.. option:: --exclude PATTERN

   Omit accesses matching the given PATTERN (see below)

                        This option can be used multiple times.
                        Note that --exclude takes precedence over --include

**Note:** PATTERN supports the ``*`` and ``?`` wildcards.
If PATTERN is a simple string without wildcards, then names containing this string will be considered.
The matching is done on the text output of the command.
