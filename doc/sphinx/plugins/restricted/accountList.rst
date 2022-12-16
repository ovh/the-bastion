============
accountList
============

List the bastion accounts
=========================


.. admonition:: usage
   :class: cmdusage

   --osh accountList [OPTIONS]

.. program:: accountList


.. option:: --account ACCOUNT

   Only list the specified account. This is an easy way to check whether the account exists

.. option:: --inactive-only

   Only list inactive accounts

.. option:: --audit

   Show more verbose information (SLOW!), you need to be a bastion auditor

.. option:: --no-password-info

   Don't gather password info in audit mode (makes --audit way faster)

.. option:: --no-output

   Don't print human-readable output (faster, use with --json)

.. option:: --include PATTERN

   Only show accounts whose name match the given PATTERN (see below)

                         This option can be used multiple times to refine results
.. option:: --exclude PATTERN

   Omit accounts whose name match the given PATTERN (see below)

                         This option can be used multiple times.
                         Note that --exclude takes precedence over --include

**Note:** PATTERN supports the ``*`` and ``?`` wildcards.
If PATTERN is a simple string without wildcards, then names containing this string will be considered.
