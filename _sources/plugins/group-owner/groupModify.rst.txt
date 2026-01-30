============
groupModify
============

Modify the configuration of a group
===================================


.. admonition:: usage
   :class: cmdusage

   --osh groupModify --group GROUP [--mfa-required password|totp|any|none] [--guest-ttl-limit DURATION]

.. program:: groupModify


.. option:: --group             GROUP

   Name of the group to modify

.. option:: --mfa-required      password|totp|any|none

   Enforce UNIX password requirement, or TOTP requirement, or any MFA requirement, when connecting to a server of the group

  --idle-lock-timeout DURATION|0|-1            Overrides the global setting (`idleLockTimeout`), to the specified duration. If set to 0, disables `idleLockTimeout` for
                                                 this group. If set to -1, remove this group override and use the global setting instead.
  --idle-kill-timeout DURATION|0|-1            Overrides the global setting (`idleKillTimeout`), to the specified duration. If set to 0, disables `idleKillTimeout` for
                                                 this group. If set to -1, remove this group override and use the global setting instead.
.. option:: --guest-ttl-limit   DURATION

   This group will enforce TTL setting, on guest access creation, to be set, and not to a higher value than DURATION,

                                                 set to zero to allow guest accesses creation without any TTL set (default)

Note that `--idle-lock-timeout` and `--idle-kill-timeout` will NOT be applied for catch-all groups (having 0.0.0.0/0 in their server list).

If a server is in exactly one group an account is a member of, then its values of `--idle-lock-timeout` and `--idle-kill-timeout`, if set,
will prevail over the global setting. The global setting can be seen with `--osh info`.

Otherwise, the most restrictive setting (i.e. the one with the lower strictly positive duration) between
all the considered groups and the global setting, will be used.
