============
groupDelete
============

Delete a group
==============


.. admonition:: usage
   :class: cmdusage

   --osh groupDelete --group GROUP

.. program:: groupDelete


.. option:: --group GROUP

   Group name to delete

.. option:: --no-confirm

   Skip group name confirmation, but blame yourself if you deleted the wrong group!


This restricted command is able to delete any group. Group owners can however delete
their own groups using the sibling `groupDestroy` command.
