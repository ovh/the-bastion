===============
groupAddMember
===============

Add an account to the member list
=================================


.. admonition:: usage
   :class: cmdusage

   --osh groupAddMember --group GROUP --account ACCOUNT

.. program:: groupAddMember


.. option:: --group GROUP    

   which group to set ACCOUNT as a member of

.. option:: --account ACCOUNT

   which account to set as a member of GROUP


The specified account will be able to access all present and future servers
pertaining to this group.
If you need to give a specific and/or temporary access instead,
see ``groupAddGuestAccess``


