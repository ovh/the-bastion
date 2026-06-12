=======================
groupListGuestAccesses
=======================

List the guest accesses to servers of a group specifically granted to an account
================================================================================


.. admonition:: usage
   :class: cmdusage

   --osh groupListGuestAccesses --group GROUP --account ACCOUNT

.. program:: groupListGuestAccesses


.. option:: --group GROUP

   Look for accesses to servers of this GROUP

.. option:: --account ACCOUNT

   Which account to check

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
