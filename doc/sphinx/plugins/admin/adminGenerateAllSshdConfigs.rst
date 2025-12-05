============================
adminGenerateAllSshdConfigs
============================

Generate sshd port forwarding configs for all accounts
======================================================


.. admonition:: usage
   :class: cmdusage

   --osh adminGenerateAllSshdConfigs

.. program:: adminGenerateAllSshdConfigs


This command will regenerate the sshd port forwarding configuration for all accounts.
If this bastion is a slave (readOnlySlaveMode), all port forwarding entries will be removed.
