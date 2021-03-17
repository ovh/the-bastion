===================
selfListEgressKeys
===================

List the public egress keys of your account
===========================================


.. admonition:: usage
   :class: cmdusage

   --osh selfListEgressKeys

.. program:: selfListEgressKeys


The keys listed are the public egress SSH keys tied to your account.
They can be used to gain access to another machine from this bastion,
by putting one of those keys in the remote machine's ``authorized_keys`` file,
and adding yourself access to this machine with ``selfAddPersonalAccess``.


