======================
selfAddPersonalAccess
======================

Add a personal server access on your account
============================================


.. admonition:: usage
   :class: cmdusage

   --osh selfAddPersonalAccess --host HOST [OPTIONS]

.. program:: selfAddPersonalAccess


.. option:: --host IP|HOST|IP/MASK

   Server to add access to

.. option:: --user USER

   Remote login to use, if you want to allow any login, use --user-any

.. option:: --user-any

   Allow access with any remote login

.. option:: --port PORT

   Remote SSH port to use, if you want to allow any port, use --port-any

.. option:: --port-any

   Allow access to all remote ports

.. option:: --scpup

   Allow SCP upload, you--bastion-->server (omit --user in this case)

.. option:: --scpdown

   Allow SCP download, you<--bastion--server (omit --user in this case)

.. option:: --sftp

   Allow usage of the SFTP subsystem, you<--bastion-->server (omit --user in this case)

.. option:: --force

   Add the access without checking that the public SSH key is properly installed remotely

.. option:: --force-key FINGERPRINT

   Only use the key with the specified fingerprint to connect to the server (cf selfListEgressKeys)

.. option:: --force-password HASH

   Only use the password with the specified hash to connect to the server (cf selfListPasswords)

.. option:: --ttl SECONDS|DURATION

   Specify a number of seconds (or a duration string, such as "1d7h8m") after which the access will automatically expire

.. option:: --comment "'ANY TEXT'"

   Add a comment alongside this server. Quote it twice as shown if you're under a shell.


Plugin configuration
====================

Options
-------

.. option:: widest_v4_prefix (optional, integer, between 0 and 32)

    When specified, this limits the size of prefixes that can be added to an
    ACL, e.g. 24 would not allow prefixes wider than /24 (such as /20 or
    /16).
    Note that this doesn't prevent users from adding thousands of ACLs to
    cover a wide range of networks, but this helps ensuring ACLs such as
    0.0.0.0/0 can't be added in a single command.

.. option:: self_remote_user_only (optional, boolean)

    When true, this only allows to add ACLs with the remote user being the
    same than the account name, i.e. a bastion account named "johndoe" would
    only be able to use ``selfAddPersonalAccess --user johndoe``.

Example
-------

Configuration, in JSON format, must be in :file:`/etc/bastion/plugin.selfAddPersonalAccess.conf`:

.. code-block:: json
   :emphasize-lines: 1

   { "widest_v4_prefix": 24, "self_remote_user_only": true }
