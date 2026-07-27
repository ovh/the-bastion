============
groupCreate
============

Create a group
==============


.. admonition:: usage
   :class: cmdusage

   --osh groupCreate --group GROUP --owner ACCOUNT <--algo ALGO --size SIZE [--encrypted]|--no-key> [OPTIONS]

.. program:: groupCreate


.. option:: --group

   Group name to create


.. option:: --owner

   Preexisting bastion account to assign as owner (can be you)


.. option:: --encrypted

   Add a passphrase to the key. Beware that you'll have to enter it for each use.
   Do NOT add the passphrase after this option, you'll be prompted interactively for it.


.. option:: --algo

   Specifies the algo of the key, either rsa, ecdsa or ed25519.

.. option:: --size

   Specifies the size of the key to be generated.
   For RSA, choose between 2048 and 8192 (4096 is good).
   For ECDSA, choose either 256, 384 or 521.
   For ED25519, size is always 256.


.. option:: --no-key

   Don't generate an egress SSH key at all for this group


The following options set the configuration of the newly created group, they're optional and have
the exact same meaning as their counterparts of the `groupModify` command, which can be used to
modify them afterwards (if you're an owner of the group):

.. option:: --mfa-required      password|totp|any|none

   Enforce UNIX password requirement, or TOTP requirement, or any MFA requirement, when connecting to a server of the group

.. option:: --idle-lock-timeout DURATION|0|-1

   Overrides the global setting (`idleLockTimeout`), to the specified duration. If set to 0, disables `idleLockTimeout` for
   this group. If set to -1, remove this group override and use the global setting instead.

.. option:: --idle-kill-timeout DURATION|0|-1

   Overrides the global setting (`idleKillTimeout`), to the specified duration. If set to 0, disables `idleKillTimeout` for
   this group. If set to -1, remove this group override and use the global setting instead.

.. option:: --guest-ttl-limit   DURATION

   This group will enforce TTL setting, on guest access creation, to be set, and not to a higher value than DURATION,
   set to zero to allow guest accesses creation without any TTL set (default)


Note that `--idle-lock-timeout` and `--idle-kill-timeout` will NOT be applied for catch-all groups (having 0.0.0.0/0 in their server list).

If a server is in exactly one group an account is a member of, then its values of `--idle-lock-timeout` and `--idle-kill-timeout`, if set,
will prevail over the global setting. The global setting can be seen with `--osh info`.

Otherwise, the most restrictive setting (i.e. the one with the lower strictly positive duration) between
all the considered groups and the global setting, will be used.

A quick overview of the different algorithms:

.. code-block:: none

   Ed25519      : robustness[###] speed[###]
   ECDSA        : robustness[##.] speed[###]
   RSA          : robustness[#..] speed[#..]

This table is meant as a quick cheat-sheet, you're warmly advised to do
your own research, as other constraints may apply to your environment.
