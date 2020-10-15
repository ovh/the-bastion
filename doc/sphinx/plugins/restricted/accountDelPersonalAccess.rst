=========================
accountDelPersonalAccess
=========================

Remove a personal server access from an account
===============================================


.. admonition:: usage
   :class: cmdusage

   --osh accountDelPersonalAccess --account ACCOUNT --host HOST [OPTIONS]

.. program:: accountDelPersonalAccess


.. option:: --account             

   Bastion account to remove access from

.. option:: --host IP|HOST|IP/MASK

   Server to remove access from

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



