======================
selfDelPersonalAccess
======================

Remove a personal server access from your account
=================================================


.. admonition:: usage
   :class: cmdusage

   --osh selfDelPersonalAccess --host HOST [OPTIONS]

.. program:: selfDelPersonalAccess


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

