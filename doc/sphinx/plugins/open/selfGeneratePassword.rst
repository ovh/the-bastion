=====================
selfGeneratePassword
=====================

Generate a new egress password for your account
===============================================


.. admonition:: usage
   :class: cmdusage

   --osh selfGeneratePassword [--size SIZE] --do-it

.. program:: selfGeneratePassword


.. option:: --size SIZE

   Specify the number of characters of the password to generate

.. option:: --do-it    

   Required for the password to actually be generated, BEWARE: please read the note below


This plugin generates a new egress password to be used for ssh or telnet

NOTE: this is only needed for devices that don't support key-based SSH,
in most cases you should ignore this command completely, unless you
know that devices you need to access only support telnet or password-based SSH.

BEWARE: once a new password is generated this way, it'll be set as the new
egress password to use right away for your account, for any access that requires it.
A fallback mechanism exists that will auto-try the previous password if this one
doesn't work, but please ensure that this new password is deployed on the remote
devices as soon as possible.


