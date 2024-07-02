====================
groupAddGuestAccess
====================

Add a specific group server access to an account
================================================


.. admonition:: usage
   :class: cmdusage

   --osh groupAddGuestAccess --group GROUP --account ACCOUNT [OPTIONS]

.. program:: groupAddGuestAccess


.. option:: --account ACCOUNT

   Name of the other bastion account to add access to, they'll be given access to the GROUP key

.. option:: --group GROUP

   Group to add the guest access to, note that this group should already have access

                             to the USER/HOST/PORT tuple you'll specify with the options below.
.. option:: --host HOST|IP|NET/CIDR

   Host(s) to add access to, either a HOST which will be resolved to an IP immediately,

                             or an IP, or a whole network using the NET/CIDR notation
.. option:: --user USER

   Specify which remote user should be allowed to connect as.

                             Globbing characters '*' and '?' are supported, so you can specify a pattern
                             that will be matched against the actual remote user name.
.. option:: --user-any

   Synonym of '--user *', allows connecting as any remote user.

.. option:: --port PORT

   Remote port allowed to connect to

.. option:: --port-any

   Allow access to any remote port

.. option:: --scpup

   Allow SCP upload, you--bastion-->server (omit --user in this case)

.. option:: --scpdown

   Allow SCP download, you<--bastion--server (omit --user in this case)

.. option:: --sftp

   Allow usage of the SFTP subsystem, you<--bastion-->server (omit --user in this case)

.. option:: --ttl SECONDS|DURATION

   specify a number of seconds after which the access will automatically expire

.. option:: --comment '"ANY TEXT"'

   add a comment alongside this access.

                            If omitted, we'll use the closest preexisting group access' comment as seen in groupListServers

This command adds, to an existing bastion account, access to the egress keys of a group,
but only to accessing one or several given servers, instead of all the servers of this group.

If you want to add complete access to an account to all the present and future servers
of the group, using the group key, please use ``groupAddMember`` instead.

If you want to add access to an account to a group server but using his personal bastion
key instead of the group key, please use ``accountAddPersonalAccess`` instead (his public key
must be on the remote server).

This command is the opposite of ``groupDelGuestAccess``.
