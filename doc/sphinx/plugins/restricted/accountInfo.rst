============
accountInfo
============

Display some information about an account
=========================================


.. admonition:: usage
   :class: cmdusage

   --osh accountInfo --account ACCOUNT

.. program:: accountInfo


.. option:: --account ACCOUNT

   The account name to work on



Output example
==============

::

  ~ user1 is a bastion admin
  ~ user1 is a bastion superowner
  ~ user1 is a bastion auditor
  ~ user1 has access to the following restricted commands:
  ~ - accountCreate
  ~ - accountDelete
  ~ - groupCreate
  ~ - groupDelete
  ~ 
  ~ This account is part of the following groups:
  ~         testgroup1 Owner GateKeeper ACLKeeper Member     -
  ~    gatekeeper-grp2 Owner GateKeeper         -      -     -
  ~ 
  ~ This account is active
  ~ This account is not expired
  ~ As a consequence, this account can connect to this bastion
  ~ 
  ~ This account has already been used at least once
  ~ Last seen on Wed 2020-07-15 12:06:27 UTC (00:00:00 ago)
  ~ 
  ~ Account egress SSH config:
  ~ - (default)
  ~ 
  ~ PIV-enforced policy for ingress keys on this account is enabled
  ~ 
  ~ Account Multi-Factor Authentication status:
  ~ - Additional password authentication is not required for this account
  ~ - Additional password authentication bypass is disabled for this account
  ~ - Additional password authentication is enabled and active
  ~ - Additional TOTP authentication is not required for this account
  ~ - Additional TOTP authentication bypass is disabled for this account
  ~ - Additional TOTP authentication is disabled
  ~ - MFA policy on personal accesses (using personal keys) on egress side is: password

  ~ Account PAM UNIX password information (used for password MFA):
  ~ - Password is set
  ~ - Password was last changed on 2020-04-27
  ~ - Password must be changed every 90 days at least
  ~ - A warning is displayed 75 days before expiration
  ~ - Account will not be disabled after password expiration
