==================
selfDelIngressKey
==================

Remove an ingress public key from your account
==============================================


.. admonition:: usage
   :class: cmdusage

   --osh selfDelIngressKey [--line-number-to-delete|-l NB] [--fingerprint-to-delete|-f FP]

.. program:: selfDelIngressKey


.. option:: -l, --line-number-to-delete NB

   Directly specify the line number to delete (CAUTION!), you can get the line numbers with selfListIngressKeys

.. option:: -f, --fingerprint-to-delete FP

   Directly specify the fingerprint of the key to delete (CAUTION!)


If none of these options are specified, you'll be prompted interactively.


