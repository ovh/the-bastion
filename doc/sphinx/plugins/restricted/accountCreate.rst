==============
accountCreate
==============

Create a new bastion account
============================


.. admonition:: usage
   :class: cmdusage

   --osh accountCreate --account ACCOUNT [OPTIONS]

.. program:: accountCreate


.. option:: --account NAME        

   Account name to create, NAME must contain only valid UNIX account name characters

.. option:: --uid UID             

   Account system UID, also see --uid-auto

.. option:: --uid-auto            

   Auto-select an UID from the allowed range (the upper available one will be used)

.. option:: --always-active       

   This account's activation won't be challenged on connection, even if the bastion is globally

                            configured to check for account activation
.. option:: --osh-only            

   This account will only be able to use OSH commands, and not connecting to machines (ssh or telnet)

.. option:: --immutable-key       

   Deny any subsequent modification of the account key (selfAddKey and selfDelKey are denied)

.. option:: --comment '"STRING"'  

   An optional comment when creating the account. Quote it twice as shown if you're under a shell.

.. option:: --public-key '"KEY"'  

   Account public SSH key to deposit on the bastion, if not present,

                            you'll be prompted interactively for it. Quote it twice as shown if your're under a shell.
.. option:: --no-key              

   Don't prompt for an SSH key, no ingress public key will be installed

.. option:: --ttl SECONDS|DURATION

   Time after which the account will be deactivated (amount of seconds, or duration string such as "4d12h15m")



