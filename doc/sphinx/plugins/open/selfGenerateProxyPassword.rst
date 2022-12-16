==========================
selfGenerateProxyPassword
==========================

Generate a new ingress password to use the bastion HTTPS proxy
==============================================================


.. admonition:: usage
   :class: cmdusage

   --osh selfGenerateProxyPassword [--size SIZE] --do-it

.. program:: selfGenerateProxyPassword


.. option:: --size SIZE

   Size of the password to generate

.. option:: --do-it

   Required for the password to actually be generated, BEWARE: please read the note below


This plugin generates a new ingress password to use the bastion HTTPS proxy.

NOTE: this is only needed for devices that only support HTTPS API and not ssh,
in most cases you should ignore this command completely, unless you
know that devices you need to access are using an HTTPS API.

BEWARE: once a new password is generated this way, it'll be set as the new
HTTPS proxy ingress password to use right away for your account.
