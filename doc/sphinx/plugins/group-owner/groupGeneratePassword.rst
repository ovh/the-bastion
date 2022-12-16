======================
groupGeneratePassword
======================

Generate a new egress password for the group
============================================


.. admonition:: usage
   :class: cmdusage

   --osh groupGeneratePassword --group GROUP [--size SIZE] --do-it

.. program:: groupGeneratePassword


.. option:: --group GROUP

   Specify which group you want to generate a password for

.. option:: --size  SIZE

   Specify the number of characters of the password to generate

.. option:: --do-it

   Required for the password to actually be generated, BEWARE: please read the note below


Generate a new egress password to be used for ssh or telnet

NOTE: this is only needed for devices that don't support key-based SSH,
in most cases you should ignore this command completely, unless you
know that devices you need to access only support telnet or password-based SSH.

BEWARE: once a new password is generated this way, it'll be set as the new
egress password to use right away for the group, for any access that requires it.
A fallback mechanism exists that will auto-try the previous password if this one
doesn't work, but please ensure that this new password is deployed on the remote
devices as soon as possible.
