===========
accountPIV
===========

Modify the PIV policy for the ingress keys of an account
========================================================


.. admonition:: usage
   :class: cmdusage

   --osh accountPIV --account ACCOUNT --policy <default|enforce|never|grace --ttl SECONDS|DURATION>

.. program:: accountPIV


.. option:: --account ACCOUNT

   Bastion account to work on

.. option:: --policy  POLICY

   Changes the PIV policy of account. See below for a description of available policies.

.. option:: --ttl SECONDS|DURATION

   For the ``grace`` policy, amount of time after which the account will automatically revert

                            to its previous policy (amount of seconds, or duration string such as "4d12h15m").

Possible POLICY values:
-----------------------

default
   No specific policy is defined for this account, the default bastion policy applies (see the :ref:`ingressRequirePIV` global option).

enforce
   Only verified PIV keys can be added as ingress SSH keys for this account. Note that setting the policy to ``enforce`` also immediately
   disables any non-PIV keys from the account's ingress keys. If no valid PIV key is found, this in effect disables all the keys of said
   account, preventing connection. The disabled keys are still kept so that setting back the policy to ``default`` or ``never`` does restore
   the non-PIV keys.

never
   Regardless of the global configuration of the bastion (see the :ref:`ingressRequirePIV` global option), this account will never be required
   to use only PIV keys. This can be needed for a non-human account if PIV is enabled bastion-wide.

grace
   enables temporary deactivation of PIV enforcement on this account. This is only meaningful when the policy is already set to ``enforce``
   for this account, or if the global :ref:`ingressRequirePIV` option is set to true. This policy requires the use of the ``--ttl`` option to
   specify how much time the policy will be relaxed for this account before going back to its previous policy automatically. This can be
   useful when people forget their PIV-enabled hardware token and you don't want to send them back home.
