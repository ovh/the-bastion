====================
accountListAccesses
====================

View the expanded access list of a given bastion account
========================================================


.. admonition:: usage
   :class: cmdusage

   --osh accountListAccesses --account ACCOUNT [--hide-groups] [--reverse-dns]

.. program:: accountListAccesses


.. option:: --account ACCOUNT

   The account to work on


.. option:: --hide-groups    

   Don't show the machines the accouns has access to through group rights.

                       In other words, list only the account's private accesses.

.. option:: --reverse-dns    

   Attempt to resolve the reverse hostnames (SLOW!)



