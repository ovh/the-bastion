==========
groupList
==========

List the groups available on this bastion
=========================================


.. admonition:: usage
   :class: cmdusage

   --osh groupList [--all] [--exclude|--include PATTERN [--exclude|--include PATTERN ..]]

.. program:: groupList


.. option:: --all

   List all groups, even those to which you don't have access

.. option:: --include PATTERN

   Only list groups that match the given PATTERN (see below)

                        This option can be used multiple times to refine results
.. option:: --exclude PATTERN

   Omit groups that match the given PATTERN string (see below)

                        This option can be used multiple times.
                        Note that --exclude takes precedence over --include

**Note:** PATTERN supports the ``*`` and ``?`` wildcards.
If PATTERN is a simple string without wildcards, then names containing this string will be considered.
