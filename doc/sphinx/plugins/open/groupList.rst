==========
groupList
==========

List the groups available on this bastion
=========================================


.. admonition:: usage
   :class: cmdusage

   --osh groupList [--all] [--exclude|--include WILDCARD [--exclude|--include WILDCARD ..]]

.. program:: groupList


.. option:: --all             

   List all groups, even those to which you don't have access

.. option:: --include WILDCARD

   Only list groups that match the given WILDCARD string, '*' and '?' are recognized,

                        this option can be used multiple times to refine results.
.. option:: --exclude WILDCARD

   Omit groups that match the given WILDCARD string, '*' and '?' are recognized,

                        can be used multiple times. Note that --exclude takes precedence over --include



