===============
groupDelServer
===============

Remove an IP or IP block from a group's server list
===================================================


.. admonition:: usage
   :class: cmdusage

   --osh groupDelServer --group GROUP --host HOST [OPTIONS]

.. program:: groupDelServer


.. option:: --group GROUP

   Specify which group this machine should be removed from

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

.. option:: --rsync

   Remove usage of rsync through the bastion


This command adds, to an existing bastion account, access to a given server, using the
egress keys of the group. The list of eligible servers for a given group is given by ``groupListServers``

If you want to add member access to an account to all the present and future servers
of the group, using the group key, please use ``groupAddMember`` instead.

If you want to add access to an account to a group server but using their personal bastion
key instead of the group key, please use ``accountAddPersonalAccess`` instead.
