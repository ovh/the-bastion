==============
groupAddOwner
==============

Add the group owner role to an account
======================================


.. admonition:: usage
   :class: cmdusage

   --osh groupAddOwner --group GROUP --account ACCOUNT

.. program:: groupAddOwner


.. option:: --group GROUP

   which group to set ACCOUNT as an owner of

.. option:: --account ACCOUNT

   which account to set as an owner of GROUP


The specified account will be able to manage the owner, gatekeeper
and aclkeeper list of this group. In other words, this account will
have all possible rights to manage the group and delegate some or all
of the rights to other accounts
