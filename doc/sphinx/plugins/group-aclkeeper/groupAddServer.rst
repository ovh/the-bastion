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

   Specify which group this machine should be added to (it should have the public group key of course)

.. option:: --host HOST|IP|NET/CIDR

   Host(s) to add access to, either a HOST which will be resolved to an IP immediately, or an IP,

                             or a whole network using the NET/CIDR notation
.. option:: --user USER            

   Specify which remote user should be allowed (root, run, etc...)

.. option:: --user-any             

   Allow any remote user (the remote user should still have the public group key in all cases)

.. option:: --port PORT            

   Only allow access to this port (e.g. 22)

.. option:: --port-any             

   Allow access to any port

.. option:: --scpup                

   Allow SCP upload, you--bastion-->server (omit --user in this case)

.. option:: --scpdown              

   Allow SCP download, you<--bastion--server (omit --user in this case)

.. option:: --force                

   Don't try the ssh connection, just add the host to the group blindly

.. option:: --force-key FINGERPRINT

   Only use the key with the specified fingerprint to connect to the server (cf groupInfo)

.. option:: --ttl SECONDS|DURATION 

   Specify a number of seconds (or a duration string, such as "1d7h8m") after which the access will automatically expire

.. option:: --comment '"ANY TEXT'" 

   Add a comment alongside this server


Examples::

  --osh groupAddServer --group grp1 --host 203.0.113.0/24 --user-any --port-any --force --comment '"a whole network"'
  --osh groupAddServer --group grp2 --host srv1.example.org --user root --port 22


