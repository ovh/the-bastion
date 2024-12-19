===============
groupAddServer
===============

Add an IP or IP block to a group's servers list
===============================================


.. admonition:: usage
   :class: cmdusage

   --osh groupAddServer --group GROUP --host HOST --user USER|* --port PORT|* [OPTIONS]

.. program:: groupAddServer


.. option:: --group GROUP

   Specify which group this machine should be added to

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
                              scpup    allow SCP upload, you--bastion-->server
                              scpdown  allow SCP download, you<--bastion--server
                              sftp     allow usage of the SFTP subsystem, through the bastion
                              rsync    allow usage of rsync, through the bastion
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

  --osh groupAddServer --group grp1 --host 203.0.113.0/24 --user '*' --port '*' --force --ttl 1d12h --comment '"a whole network"'
  --osh groupAddServer --group grp2 --host srv1.example.org --user data --port 22
  --osh groupAddServer --group grp2 --host srv1.example.org --user file --port 22

Example to allow using sftp to srv1.example.org using remote user 'data' or 'file', in addition to the above commands::

  --osh groupAddServer --group grp2 --host srv1.example.org --port 22 --protocol sftp
