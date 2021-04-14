============
accountList
============

List the bastion accounts
=========================


.. admonition:: usage
   :class: cmdusage

   --osh accountList [--account ACCOUNT] [--inactive-only] [--audit]

.. program:: accountList


.. option:: --account ACCOUNT

   Only list the specified account. This is an easy way to check whether the account exists

.. option:: --inactive-only  

   Only list inactive accounts

.. option:: --audit          

   Show more verbose information (SLOW!), you need to be a bastion auditor

.. option:: --include WILDCARD

   Only list accounts that match the given WILDCARD string, '*' and '?' are recognized,

                        this option can be used multiple times to refine results.
.. option:: --exclude WILDCARD

   Omit accounts that match the given WILDCARD string, '*' and '?' are recognized,

                        can be used multiple times. Note that --exclude takes precedence over --include



