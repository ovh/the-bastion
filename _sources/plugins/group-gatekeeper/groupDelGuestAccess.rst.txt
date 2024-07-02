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

   Specify which group to remove the guest access to ACCOUNT from

.. option:: --account ACCOUNT

   Bastion account remove the guest access from

.. option:: --host HOST|IP|NET/CIDR

   Host(s) to remove access from, either a HOST which will be resolved to an IP immediately,

                             or an IP, or a whole network using the NET/CIDR notation
.. option:: --user USER

   Specify which remote user was allowed to connect as.

                             Globbing characters '*' and '?' are supported, so you can specify a pattern
                             that will be matched against the actual remote user name.
.. option:: --user-any

   Synonym of '--user *', allowed connecting as any remote user.

.. option:: --port PORT

   Remote port that was allowed to connect to

.. option:: --port-any

   Use when access was allowed to any remote port

.. option:: --scpup

   Remove SCP upload right, you--bastion-->server (omit --user in this case)

.. option:: --scpdown

   Remove SCP download right, you<--bastion--server (omit --user in this case)

.. option:: --sftp

   Remove usage of the SFTP subsystem, you<--bastion-->server (omit --user in this case)


This command removes, from an existing bastion account, access to a given server, using the
egress keys of the group. The list of such servers is given by ``groupListGuestAccesses``

If you want to remove member access from an account to all the present and future servers
of the group, using the group key, please use ``groupDelMember`` instead.

If you want to remove access from an account from a group server but using their personal bastion
key instead of the group key, please use ``accountDelPersonalAccess`` instead.

This command is the opposite of ``groupAddGuestAccess``.
