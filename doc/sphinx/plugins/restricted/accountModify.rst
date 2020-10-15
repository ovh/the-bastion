==============
accountModify
==============

Modify an account configuration
===============================


.. admonition:: usage
   :class: cmdusage

   --osh accountModify --account ACCOUNT [--option value [--option value [...]]]

.. program:: accountModify


.. option:: --account ACCOUNT                        

   Bastion account to work on

.. option:: --pam-auth-bypass yes|no                 

   Enable or disable PAM auth bypass for this account in addition to pubkey auth (default is 'no'),

                                                in that case sshd will not rely at all on PAM auth and /etc/pam.d/sshd configuration. This
                                                does not change the behaviour of the code, just the PAM auth handled by SSH itself
.. option:: --mfa-password-required yes|no|bypass    

   Enable or disable UNIX password requirement for this account in addition to pubkey auth (default is 'no'),

                                                this overrides the global bastion configuration 'accountMFAPolicy'. If 'bypass' is specified,
                                                no password will ever be asked, even for groups or plugins explicitly requiring it
.. option:: --mfa-totp-required yes|no|bypass        

   Enable or disable TOTP requirement for this account in addition to pubkey auth (default is 'no'),

                                                this overrides the global bastion configuration 'accountMFAPolicy'. If 'bypass' is specified,
                                                no OTP will ever be asked, even for groups or plugins explicitly requiring it
.. option:: --egress-strict-host-key-checking POLICY 

   Modify the egress SSH behavior of this account regarding StrictHostKeyChecking (see man ssh_config),

                                               POLICY can be 'yes', 'no', 'ask', 'default' or 'bypass'
.. option:: --personal-egress-mfa-required POLICY    

   Enforce UNIX password requirement, or TOTP requirement, or any MFA requirement, when connecting to a server

                                               using the personal keys of the account, POLICY can be 'password', 'totp', 'any' or 'none'
.. option:: --always-active yes|no                   

   Set or unset the account as always active (i.e. disable the check of the 'active' status on this account)

.. option:: --idle-ignore yes|no                     

   If enabled, this account is immune to the idleLockTimeout and idleKillTimeout bastion-wide policy



