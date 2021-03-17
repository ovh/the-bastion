=======
unlock
=======

Unlock all your current sessions
================================


.. admonition:: usage
   :class: cmdusage

   --osh unlock

.. program:: unlock


This command will unlock all your current sessions on this bastion instance,
that were either locked for inactivity timeout or manually locked by you with ``lock``.
Note that this only applies to the bastion instance you're launching this
command on, not on the whole bastion cluster (if you happen to have one).


