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

   Modify the egress SSH behavior of this account regarding ``StrictHostKeyChecking`` (see `man ssh_config`),

                                               POLICY can be 'yes', 'accept-new', 'no', 'ask', 'default' or 'bypass'.
                                               'bypass' means setting ``StrictHostKeyChecking=no`` and ``UserKnownHostsFile=/dev/null``,
                                               which will permit egress connections in all cases, even when host keys change all the time on the same target.
                                               This effectively suppress the host key checking entirely. Please don't enable this blindly.
                                               'default' will remove this account's ``StrictHostKeyChecking`` setting override.
                                               All the other policies carry the same meaning that what is documented in `man ssh_config`.
.. option:: --personal-egress-mfa-required POLICY

   Enforce UNIX password requirement, or TOTP requirement, or any MFA requirement, when connecting to a server

                                               using the personal keys of the account, POLICY can be 'password', 'totp', 'any' or 'none'
.. option:: --always-active yes|no

   Set or unset the account as always active (i.e. disable the check of the 'active' status on this account)

.. option:: --idle-ignore yes|no

   If enabled, this account is immune to the idleLockTimeout and idleKillTimeout bastion-wide policy

.. option:: --max-inactive-days DAYS

   Set account expiration policy, overriding the global bastion configuration 'accountMaxInactiveDays'.

                                               Setting this option to zero disables account expiration. Setting this option to -1 removes this account
                                               expiration policy, i.e. the global bastion setting will apply.
.. option:: --osh-only yes|no

   If enabled, this account can only use ``--osh`` commands, and can't connect anywhere through the bastion

.. option:: --pubkey-auth-optional yes|no

   Make the public key optional on ingress for the account (default is 'no').

                                               When enabled the public key part of the authentication becomes optional when a password and/or TOTP is defined,
                                               allowing to login with just the password/TOTP. If no password/TOTP is defined then the public key is the only way to authenticate,
                                               because some form of authentication is always required.
                                               When disabled, the public key is always required.
                                               Egress is not affected.
