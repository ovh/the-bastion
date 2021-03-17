======================
accountListEgressKeys
======================

List the public egress keys of an account
=========================================


.. admonition:: usage
   :class: cmdusage

   --osh accountListEgressKeys --account ACCOUNT

.. program:: accountListEgressKeys


.. option:: --account ACCOUNT

   Account to display the public egress keys of


The keys listed are the public egress SSH keys tied to this account.
They can be used to gain access to another machine from this bastion,
by putting one of those keys in the remote machine's ``authorized_keys`` file,
and adding this account access to this machine with ``accountAddPersonalAccess``.


