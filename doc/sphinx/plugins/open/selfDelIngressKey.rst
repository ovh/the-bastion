==================
selfDelIngressKey
==================

Remove an ingress public key from your account
==============================================


.. admonition:: usage
   :class: cmdusage

   --osh selfDelIngressKey [--id-to-delete ID] [--fingerprint-to-delete FP]

.. program:: selfDelIngressKey


.. option:: --id-to-delete ID

   Directly specify key id to delete (CAUTION!), you can get id with selfListIngressKeys

.. option:: --fingerprint-to-delete FP

   Directly specify the fingerprint of the key to delete (CAUTION!)


If none of these options are specified, you'll be prompted interactively.
