=======================
groupTransmitOwnership
=======================

Transmit your group ownership to somebody else
==============================================


.. admonition:: usage
   :class: cmdusage

   --osh groupTransmitOwnership --group GROUP --account ACCOUNT

.. program:: groupTransmitOwnership


.. option:: --group GROUP    

   which group to set ACCOUNT as an owner of

.. option:: --account ACCOUNT

   which account to set as an owner of GROUP


Note that this command has the same net effect than using ``groupAddOwner``
to add ACCOUNT as an owner, then removing yourself with ``groupDelOwner``


