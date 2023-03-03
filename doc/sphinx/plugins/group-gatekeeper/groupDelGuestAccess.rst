====================
groupDelGuestAccess
====================

Remove a specific group server access from an account
=====================================================


.. admonition:: usage
   :class: cmdusage

   --osh groupDelGuestAccess --group GROUP --account ACCOUNT [OPTIONS]

.. program:: groupDelGuestAccess


.. option:: --group GROUP

   group to remove guest access from

  --account ACCOUNT name of the other bastion account to remove access from
.. option:: --host HOST|IP

   remove access from this HOST (which must belong to the GROUP)

.. option:: --user USER

   allow connecting to HOST only with remote login USER

.. option:: --user-any

   allow connecting to HOST with any remote login

.. option:: --port PORT

   allow connecting to HOST only to remote port PORT

.. option:: --port-any

   allow connecting to HOST with any remote port

.. option:: --scpup

   allow SCP upload, you--bastion-->server (omit --user in this case)

.. option:: --scpdown

   allow SCP download, you<--bastion--server (omit --user in this case)

.. option:: --sftp

   allow usage of the SFTP subsystem, you<--bastion-->server (omit --user in this case)


This command removes, from an existing bastion account, access to a given server, using the
egress keys of the group. The list of such servers is given by ``groupListGuestAccesses``

If you want to remove member access from an account to all the present and future servers
of the group, using the group key, please use ``groupDelMember`` instead.

If you want to remove access from an account from a group server but using his personal bastion
key instead of the group key, please use ``accountDelPersonalAccess`` instead.

This command is the opposite of ``groupAddGuestAccess``.
