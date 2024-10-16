===============
groupDelMember
===============

Remove an account from the members list
=======================================


.. admonition:: usage
   :class: cmdusage

   --osh groupDelMember --group GROUP --account ACCOUNT

.. program:: groupDelMember


.. option:: --group GROUP

   which group to remove ACCOUNT as a member of

.. option:: --account ACCOUNT

   which account to remove as a member of GROUP


The specified account will no longer be able to access all present and future servers
pertaining to this group.
Note that if this account also had specific guest accesses to this group, they may
still apply, see ``groupListGuestAccesses``
