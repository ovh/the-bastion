=================
adminMaintenance
=================

Manage the bastion maintenance mode
===================================


.. admonition:: usage
   :class: cmdusage

   --osh adminMaintenance <--lock [--message "'reason for maintenance'"]|--unlock>

.. program:: adminMaintenance


.. option:: --lock

   Set maintenance mode: new logins will be disallowed

.. option:: --unlock

   Unset maintenance mode: new logins are allowed and the bastion functions normally

.. option:: --message MESSAGE

   Optionally set a maintenance reason, if you're in a shell, quote it twice.

