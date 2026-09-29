====================
accountGrantCommand
====================

Grant access to a restricted command
====================================


.. admonition:: usage
   :class: cmdusage

   --osh accountGrantCommand --account ACCOUNT --command COMMAND

.. program:: accountGrantCommand


.. option:: --account ACCOUNT

   Bastion account to work on

.. option:: --command COMMAND

   The name of the OSH plugin to grant (omit to get the list)


Note that accountGrantCommand being a restricted command as any other, you can grant it to somebody else,
but then they'll be able to grant themselves or anybody else to this or any other restricted command.

A specific command that can be granted is ``auditor``, it is not an osh plugin per-se, but activates
more verbose output for several other commands, suitable to audit rights or grants without needing
to be granted (e.g. to groups).
