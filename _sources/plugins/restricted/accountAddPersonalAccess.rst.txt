=========================
accountAddPersonalAccess
=========================

Add a personal server access to an account
==========================================


.. admonition:: usage
   :class: cmdusage

   --osh accountAddPersonalAccess --account ACCOUNT --host HOST --user USER --port PORT [OPTIONS]

.. program:: accountAddPersonalAccess


.. option:: --account

   Bastion account to add the access to

.. option:: --host HOST|IP|SUBNET

   Host(s) to add access to, either a HOST which will be resolved to an IP immediately,

                             or an IP, or a whole subnet using the PREFIX/SIZE notation
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
.. option:: --force-key FINGERPRINT

   Only use the key with the specified fingerprint to connect to the server (cf accountListEgressKeys)

.. option:: --force-password HASH

   Only use the password with the specified hash to connect to the server (cf accountListPasswords)

.. option:: --ttl SECONDS|DURATION

   Specify a number of seconds (or a duration string, such as "1d7h8m") after which the access will automatically expire

.. option:: --comment "'ANY TEXT'"

   Add a comment alongside this server. Quote it twice as shown if you're under a shell.


The access will work only if one of the account's personal egress public key has been copied to the remote server.
To get the list of an account's personal egress public keys, see ``accountListEgressKeyss`` and ``selfListEgressKeys``.

Plugin configuration
====================

Options
-------

.. option:: widest_v4_prefix (optional, integer, between 0 and 32)

    When specified, this limits the size of subnets that can be added to an
    ACL, e.g. 24 would not allow prefix lengths wider than /24 (such as /20
    or /16).
    Note that this doesn't prevent users from adding thousands of ACLs to
    cover a wide range of networks, but this helps ensuring ACLs such as
    0.0.0.0/0 can't be added in a single command.

.. option:: self_remote_user_only (optional, boolean)

    When true, this only allows to add ACLs with the remote user being the
    same than the account name, i.e. adding an access to a bastion account
    named "johndoe" can only be done specifying this very account name as
    the remote user name, with ``accountAddPersonalAccess --user johndoe``.

Example
-------

Configuration, in JSON format, must be in :file:`/etc/bastion/plugin.accountAddPersonalAccess.conf`:

.. code-block:: json
   :emphasize-lines: 1

   { "widest_v4_prefix": 24, "self_remote_user_only": true }
