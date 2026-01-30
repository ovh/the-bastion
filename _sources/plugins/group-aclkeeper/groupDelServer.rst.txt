===============
groupDelServer
===============

Remove an IP or IP block from a group's server list
===================================================


.. admonition:: usage
   :class: cmdusage

   --osh groupDelServer --group GROUP --host HOST --user USER --port PORT [OPTIONS]

.. program:: groupDelServer


.. option:: --group GROUP

   Specify which group this machine should be removed from

.. option:: --host HOST|IP|SUBNET

   Host(s) to remove access from, either a HOST which will be resolved to an IP immediately,

                             or an IP, or a whole subnet using the PREFIX/SIZE notation
  --user USER|PATTERN|*    Specify which remote user was allowed to connect as.
                             Globbing characters '*' and '?' are supported, so you can specify a pattern
                             that will be matched against the actual remote user name.
                             If any user was allowed, use '--user *' (you might need to escape '*' from your shell)
  --port PORT|*            Remote port that was allowed to connect to
                             If any port was allowed, use '--port *' (you might need to escape '*' from your shell)
.. option:: --protocol PROTO

   Specify that a special protocol allowance should be removed from this HOST:PORT tuple, note that you

                              must not specify --user in that case.
                              PROTO must be one of:
                              scpup    allow SCP upload, you--bastion-->server
                              scpdown  allow SCP download, you<--bastion--server
                              sftp     allow usage of the SFTP subsystem, through the bastion
                              rsync    allow usage of rsync, through the bastion

This command adds, to an existing bastion account, access to a given server, using the
egress keys of the group. The list of eligible servers for a given group is given by ``groupListServers``

If you want to add member access to an account to all the present and future servers
of the group, using the group key, please use ``groupAddMember`` instead.

If you want to add access to an account to a group server but using their personal bastion
key instead of the group key, please use ``accountAddPersonalAccess`` instead.
