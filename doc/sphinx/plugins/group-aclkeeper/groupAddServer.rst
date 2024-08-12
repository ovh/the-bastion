===============
groupAddServer
===============

Add an IP or IP block to a group's servers list
===============================================


.. admonition:: usage
   :class: cmdusage

   --osh groupAddServer --group GROUP [OPTIONS]

.. program:: groupAddServer


.. option:: --group GROUP

   Specify which group this machine should be added to

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

.. option:: --rsync

   Allow usage of rsync through the bastion

.. option:: --force

   Don't try the ssh connection, just add the host to the group blindly

.. option:: --force-key FINGERPRINT

   Only use the key with the specified fingerprint to connect to the server (cf groupInfo)

.. option:: --force-password HASH

   Only use the password with the specified hash to connect to the server (cf groupListPasswords)

.. option:: --ttl SECONDS|DURATION

   Specify a number of seconds (or a duration string, such as "1d7h8m") after which the access will automatically expire

.. option:: --comment "'ANY TEXT'"

   Add a comment alongside this server. Quote it twice as shown if you're under a shell.


Examples::

  --osh groupAddServer --group grp1 --host 203.0.113.0/24 --user-any --port-any --force --comment '"a whole network"'
  --osh groupAddServer --group grp2 --host srv1.example.org --user root --port 22
