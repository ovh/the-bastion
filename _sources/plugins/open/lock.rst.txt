=====
lock
=====

Manually lock all your current sessions
=======================================


.. admonition:: usage
   :class: cmdusage

   --osh lock

.. program:: lock

This command will lock all your current sessions on this bastion instance. Note that this only applies to the bastion instance you're launching this command on, not on the whole bastion cluster (if you happen to have one).

To undo this action, you can use ``--osh unlock`` on the same instance.
