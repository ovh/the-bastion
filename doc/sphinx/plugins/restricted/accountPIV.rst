===========
accountPIV
===========

Modify the PIV policy for the ingress keys of an account
========================================================


.. admonition:: usage
   :class: cmdusage

   --osh accountPIV --account ACCOUNT --policy <none|enforce|grace --ttl SECONDS|DURATION>

.. program:: accountPIV


Options:
.. option:: --account ACCOUNT           

   Bastion account to work on

.. option:: --policy  none|enforce|grace

   Changes the PIV policy of account. 'none' disables the PIV enforcement, any SSH key can be used

                                  as long as it respects the bastion policy. 'enforce' enables the PIV enforcement, only PIV keys
                                  can be added as ingress SSH keys. 'grace' enables temporary deactivation of PIV enforcement on
                                  an account, only meaningful when policy is already set to 'enforce' for this account, 'grace'
                                  requires the use of the --ttl option to specify how much time the policy will be relaxed for this
                                  account before going back to 'enforce' automatically.
.. option:: --ttl SECONDS|DURATION      

   For the 'grace' policy, amount of time after which the account will automatically go back to 'enforce'

                                  policy (amount of seconds, or duration string such as "4d12h15m")


