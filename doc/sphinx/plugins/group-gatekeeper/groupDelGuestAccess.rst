====================
groupDelGuestAccess
====================

Remove a specific group server access from an account
=====================================================


.. admonition:: usage
   :class: cmdusage

   --osh groupDelGuestAccess --group GROUP --account ACCOUNT [OPTIONS]

.. program:: groupDelGuestAccess


.. option:: --account ACCOUNT

   Bastion account remove the guest access from

.. option:: --group GROUP

   Specify which group to remove the guest access to ACCOUNT from

.. option:: --host HOST|IP|SUBNET

   Host(s) to remove access from, either a HOST which will be resolved to an IP immediately,

                                 or an IP, or a whole subnet using the PREFIX/SIZE notation
  --user USER|PATTERN|*        Specify which remote user was allowed to connect as.
                                 Globbing characters '*' and '?' are supported, so you can specify a pattern
                                 that will be matched against the actual remote user name.
                                 If any user was allowed, use '--user *' (you might need to escape '*' from your shell)
  --port PORT|*                Remote port that was allowed to connect to
                                 If any user was allowed, use '--port *' (you might need to escape '*' from your shell)
.. option:: --protocol PROTO

   Specify that a special protocol was allowed for this HOST:PORT tuple, note that you

                                  must not specify --user in that case. However, for this protocol to be usable under a given
                                  remote user, access to the USER@HOST:PORT tuple must also be allowed.
                                  PROTO must be one of:
                                  scpupload    allow SCP upload, you--bastion-->server
                                  scpdownload  allow SCP download, you<--bastion--server
                                  sftp         allow usage of the SFTP subsystem, through the bastion
                                  rsync        allow usage of rsync, through the bastion
.. option:: --proxy-host HOST|IP

   Use this host as a proxy/jump host to reach the target server

.. option:: --proxy-port PORT

   Proxy host port to connect to (mandatory when --proxy-host is specified)

  --proxy-user USER|PATTERN|*  Proxy user to connect as (mandatory when --proxy-host is specified).
                                   Globbing characters '*' and '?' are supported for pattern matching.

This command removes, from an existing bastion account, access to a given server, using the
egress keys of the group. The list of such servers is given by ``groupListGuestAccesses``

If you want to remove member access from an account to all the present and future servers
of the group, using the group key, please use ``groupDelMember`` instead.

If you want to remove access from an account from a group server but using their personal bastion
key instead of the group key, please use ``accountDelPersonalAccess`` instead.

This command is the opposite of ``groupAddGuestAccess``.
