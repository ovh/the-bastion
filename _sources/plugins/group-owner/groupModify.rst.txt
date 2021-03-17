============
groupModify
============

Modify the configuration of a group
===================================


.. admonition:: usage
   :class: cmdusage

   --osh groupModify --group GROUP [--mfa-required password|totp|any|none] [--guest-ttl-limit DURATION]

.. program:: groupModify


.. option:: --group            GROUP                  

   Name of the group to modify

.. option:: --mfa-required     password|totp|any|none 

   Enforce UNIX password requirement, or TOTP requirement, or any MFA requirement, when connecting to a server of the group

.. option:: --guest-ttl-limit  DURATION               

   This group will enforce TTL setting, on guest access creation, to be set, and not to a higher value than DURATION,

                                                set to zero to allow guest accesses creation without any TTL set (default)


