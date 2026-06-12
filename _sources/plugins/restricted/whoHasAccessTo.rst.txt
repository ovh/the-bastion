===============
whoHasAccessTo
===============

List the accounts that have access to a given server
====================================================


.. admonition:: usage
   :class: cmdusage

   --osh whoHasAccessTo --host SERVER [OPTIONS]

.. program:: whoHasAccessTo


.. option:: --host SERVER

   List declared accesses to this server

.. option:: --user USER

   Remote user allowed (if not specified, ignore user specifications)

.. option:: --port PORT

   Remote port allowed (if not specified, ignore port specifications)

.. option:: --ignore-personal

   Don't check accounts' personal accesses (i.e. only check groups)

.. option:: --ignore-group GROUP

   Ignore accesses by this group, if you know GROUP public key is in fact

                          not present on remote server but bastion thinks it is
.. option:: --show-wildcards

   Also list accesses that match because 0.0.0.0/0 is listed in a group or private access,

                          this is disabled by default because this is almost always just noise (see Note below)

Note: This list is what the bastion THINKS is true, which means that if some group has 0.0.0.0/0 in its list,
then it'll show all the members of that group as having access to the machine you're specifying, through this group key.
This is only true if the remote server does have the group key installed, of course, which the bastion
can't tell without trying to connect "right now" (which it won't do).
