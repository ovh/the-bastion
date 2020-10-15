======================
selfAddPersonalAccess
======================

Remove a personal server access from an account
===============================================


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

.. option:: --force                

   Add the access without checking that the public SSH key is properly installed remotely

.. option:: --force-key FINGERPRINT

   Only use the key with the specified fingerprint to connect to the server (cf selfListEgressKeys)

.. option:: --ttl SECONDS|DURATION 

   Specify a number of seconds (or a duration string, such as "1d7h8m") after which the access will automatically expire

.. option:: --comment "'ANY TEXT'" 

   Add a comment alongside this server. Quote it twice as shown if you're under a shell.



