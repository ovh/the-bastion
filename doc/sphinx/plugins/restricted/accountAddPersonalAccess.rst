=========================
accountAddPersonalAccess
=========================

Add a personal server access to an account
==========================================


.. admonition:: usage
   :class: cmdusage

   --osh accountAddPersonalAccess --account ACCOUNT --host HOST [OPTIONS]

.. program:: accountAddPersonalAccess


.. option:: --account              

   Bastion account to add the access to

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

.. option:: --force-key FINGERPRINT

   Only use the key with the specified fingerprint to connect to the server (cf selfListEgressKeys)

.. option:: --ttl SECONDS|DURATION 

   Specify a number of seconds (or a duration string, such as "1d7h8m") after which the access will automatically expire

.. option:: --comment "'ANY TEXT'" 

   Add a comment alongside this server. Quote it twice as shown if you're under a shell.


The access will work only if one of the account's personal egress public key has been copied to the remote server.
To get the list of an account's personal egress public keys, see ``accountListEgressKeyss`` and ``selfListEgressKeys``.
