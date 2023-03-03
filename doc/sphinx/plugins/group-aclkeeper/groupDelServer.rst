===============
groupDelServer
===============

Remove an IP or IP block from a group's server list
===================================================


.. admonition:: usage
   :class: cmdusage

   --osh groupDelServer --group GROUP [OPTIONS]

.. program:: groupDelServer


.. option:: --group GROUP

   Specify which group this machine should be removed from

.. option:: --host HOST|IP|NET/CIDR

   Host(s) we want to remove access to

.. option:: --user USER

   Remote user that was allowed, if any user was allowed, use --user-any

.. option:: --user-any

   Use if any remote login was allowed

.. option:: --port PORT

   Remote SSH port that was allowed, if any port was allowed, use --port-any

.. option:: --port-any

   Use if any remote port was allowed

.. option:: --scpup

   Remove SCP upload right, you--bastion-->server (omit --user in this case)

.. option:: --scpdown

   Remove SCP download right, you<--bastion--server (omit --user in this case)

.. option:: --sftp

   Remove usage of the SFTP subsystem, you<--bastion-->server (omit --user in this case)

