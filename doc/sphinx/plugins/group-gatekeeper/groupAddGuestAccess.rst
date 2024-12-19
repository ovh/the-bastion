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
.. option:: --host HOST|IP|PREFIX/SIZE

   Host(s) to add access to, either a HOST which will be resolved to an IP immediately,

                             or an IP, or a whole netblock using the PREFIX/SIZE notation
  --user USER|PATTERN|*    Specify which remote user should be allowed to connect as.
                             Globbing characters '*' and '?' are supported, so you can specify a pattern
                             that will be matched against the actual remote user name.
                             To allow any user, use '--user *' (you might need to escape '*' from your shell)
  --port PORT|*            Remote port allowed to connect to
                             To allow any port, use '--port *' (you might need to escape '*' from your shell)
.. option:: --protocol PROTO

   Specify that a special protocol should be allowed for this HOST:PORT tuple, note that you

                              must not specify --user in that case. However, for this protocol to be usable under a given
                              remote user, access to the USER@HOST:PORT tuple must also be allowed.
                              PROTO must be one of:
                              scpupload    allow SCP upload, you--bastion-->server
                              scpdownload  allow SCP download, you<--bastion--server
                              sftp         allow usage of the SFTP subsystem, through the bastion
                              rsync        allow usage of rsync, through the bastion
.. option:: --ttl SECONDS|DURATION

   Specify a number of seconds after which the access will automatically expire

.. option:: --comment '"ANY TEXT"'

   Add a comment alongside this access. Quote it twice as shown if you're under a shell.

                            If omitted, we'll use the closest preexisting group access' comment as seen in groupListServers

This command adds, to an existing bastion account, access to the egress keys of a group,
but only to accessing one or several given servers, instead of all the servers of this group.

If you want to add complete access to an account to all the present and future servers
of the group, using the group key, please use ``groupAddMember`` instead.

If you want to add access to an account to a group server but using his personal bastion
key instead of the group key, please use ``accountAddPersonalAccess`` instead (his public key
must be on the remote server).

This command is the opposite of ``groupDelGuestAccess``.
