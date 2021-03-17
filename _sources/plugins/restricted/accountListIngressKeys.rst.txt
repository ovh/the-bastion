=======================
accountListIngressKeys
=======================

List the public ingress keys of an account
==========================================


.. admonition:: usage
   :class: cmdusage

   --osh accountListIngressKeys --account ACCOUNT

.. program:: accountListIngressKeys


.. option:: --account ACCOUNT

   Account to list the keys of


The keys listed are the public ingress SSH keys tied to this account.
Their private counterpart should be detained only by this account's user,
so that they can to authenticate themselves to this bastion.


