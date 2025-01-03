============
accountInfo
============

Display some information about an account
=========================================


.. admonition:: usage
   :class: cmdusage

   --osh accountInfo <--account ACCOUNT|--all> [OPTIONS]

.. program:: accountInfo


.. option:: --account ACCOUNT

   The account name to work on

.. option:: --all

   Dump info for all accounts (auditors only), use with ``--json``


.. option:: --with[out]-everything

   Include or exclude all below options, including future ones

.. option:: --with[out]-groups

   Whether to include the groups the account has a role on (SLOW, default: no)

.. option:: --with[out]-mfa-password-info

   Whether to include MFA password info of the account (SLOW, auditors only, default: no)

.. option:: --with[out]-egress-keys

   Whether to include the account's egress keys (SLOW, auditors only, default: no)

Usage examples
==============

Show info about a specific account::

    --osh accountInfo --account jdoe12

Gather info about all accounts, with no extra data except their egress keys::

    --osh accountInfo --all --without-everything --with-egress-keys --json

Gather info about all accounts, including all extra data (and possibly future options)::

    --osh accountInfo --all --with-everything --json

Output example
==============

::

  │ user1 is a bastion admin
  │ user1 is a bastion superowner
  │ user1 is a bastion auditor
  │
  │ user1 has access to the following restricted commands:
  │ - accountCreate
  │ - accountDelete
  │ - groupCreate
  │ - groupDelete
  │
  │ This account is part of the following groups:
  │         testgroup1 Owner GateKeeper ACLKeeper Member     -
  │    gatekeeper-grp2 Owner GateKeeper         -      -     -
  │
  │ This account is active
  │ This account has no TTL set
  │ This account is not frozen
  │ This account has seen recent-enough activity to not be activity-expired
  │ As a consequence, this account can connect to this bastion
  │
  │ Last seen on Thu 2023-03-16 07:51:49 UTC (00:00:00 ago)
  │ Created on Fri 2022-06-17 09:52:50 UTC (271d+21:58:59 ago)
  │ Created by jdoe
  │ Created using The Bastion v3.08.01
  │
  │ Account egress SSH config:
  │ - (default)
  │
  │ PIV-enforced policy for ingress keys on this account is enabled
  │
  │ Account Multi-Factor Authentication status:
  │ - Additional password authentication is not required for this account
  │ - Additional password authentication bypass is disabled for this account
  │ - Additional password authentication is enabled and active
  │ - Additional TOTP authentication is not required for this account
  │ - Additional TOTP authentication bypass is disabled for this account
  │ - Additional TOTP authentication is disabled
  │ - PAM authentication bypass is disabled
  │ - Optional public key authentication is disabled
  │ - MFA policy on personal accesses (using personal keys) on egress side is: password
  │
  │ - Account is immune to idle counter-measures: no
  │ - Maximum number of days of inactivity before account is disabled: (default)
  │
  │ Account PAM UNIX password information (used for password MFA):
  │ - Password is set
  │ - Password was last changed on 2023-01-27
  │ - Password must be changed every 90 days at least
  │ - A warning is displayed 75 days before expiration
  │ - Account will not be disabled after password expiration

