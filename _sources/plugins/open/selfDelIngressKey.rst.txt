==================
selfDelIngressKey
==================

Remove an ingress public key from your account
==============================================


.. admonition:: usage
   :class: cmdusage

   --osh selfDelIngressKey [--id-to-delete|-l ID] [--fingerprint-to-delete|-f FP]

.. program:: selfDelIngressKey


.. option:: -l, --id-to-delete ID

   Directly specify key id to delete (CAUTION!), you can get id with selfListIngressKeys

.. option:: -f, --fingerprint-to-delete FP

   Directly specify the fingerprint of the key to delete (CAUTION!)


If none of these options are specified, you'll be prompted interactively.
