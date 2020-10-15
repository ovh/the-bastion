====================
groupAddGuestAccess
====================

Add a specific group server access to an account
================================================


.. admonition:: usage
   :class: cmdusage

   --osh groupAddGuestAccess --group GROUP --account ACCOUNT [OPTIONS]

.. program:: groupAddGuestAccess


.. option:: --group GROUP         

   group to add guest access to

.. option:: --account ACCOUNT     

   name of the other bastion account to add access to, he'll be given access to the GROUP key

.. option:: --host HOST|IP        

   add access to this HOST (which must belong to the GROUP)

.. option:: --user USER           

   allow connecting to HOST only with remote login USER

.. option:: --user-any            

   allow connecting to HOST with any remote login

.. option:: --port PORT           

   allow connecting to HOST only to remote port PORT

.. option:: --port-any            

   allow connecting to HOST with any remote port

.. option:: --scpup               

   allow SCP upload, you--bastion-->server (omit --user in this case)

.. option:: --scpdown             

   allow SCP download, you<--bastion--server (omit --user in this case)

.. option:: --ttl SECONDS|DURATION

   Specify a number of seconds after which the access will automatically expire


This command adds, to an existing bastion account, access to the egress keys of a group,
but only to accessing one or several given servers, instead of all the servers of this group.

If you want to add complete access to an account to all the present and future servers
of the group, using the group key, please use ``groupAddMember`` instead.

If you want to add access to an account to a group server but using his personal bastion
key instead of the group key, please use ``accountAddPersonalAccess`` instead (his public key
must be on the remote server).

This command is the opposite of ``groupDelGuestAccess``.


