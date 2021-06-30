=====
info
=====

Displays some information about this bastion instance
=====================================================


.. admonition:: usage
   :class: cmdusage

   --osh info

.. program:: info

Output example
==============

::

  ~ You are user1
  ~ 
  ~ Your alias to connect to this bastion is:
  ~ alias bastion='ssh user1@testbastion.example.org -p 22 -t -- '
  ~ Your alias to connect to this bastion with MOSH is:
  ~ alias bastionm='mosh --ssh="ssh -p 22 -t" user1@testbastion.example.org -- '
  ~ 
  ~ Multi-Factor Authentication (MFA) on your account:
  ~ - Additional password authentication is not required
  ~ - Additional password authentication bypass is disabled
  ~ - Additional password authentication is enabled and active
  ~ - Additional TOTP authentication is not required
  ~ - Additional TOTP authentication bypass is disabled
  ~ - Additional TOTP authentication is disabled
  ~ 
  ~ I am testbastion-a.example.org, aka bastion
  ~ I have 42 registered accounts and 46 groups
  ~ I am a MASTER, which means I accept modifications
  ~ The networks I'm able to connect you to on the egress side are: all
  ~ The networks that are explicitly forbidden on the egress side are: none
  ~ My egress connection IP to remote servers is 192.0.2.45/32
  ~ ...don't forget to whitelist me in your firewalls!
  ~ 
  ~ The following policy applies on this bastion:
  ~ - The interactive mode (-i) is ENABLED
  ~ - The support of mosh is ENABLED
  ~ - Account expiration is DISABLED
  ~ - Keyboard input idle time for session locking is DISABLED
  ~ - Keyboard input idle time for session killing is DISABLED
  ~ - The forced "from" prepend on ingress keys is DISABLED
  ~ - The following algorithms are allowed for ingress SSH keys: rsa, ecdsa, ed25519
  ~ - The RSA key size for ingress SSH keys must be between 2048 and 8192 bits
  ~ - The following algorithms are allowed for egress SSH keys: rsa, ecdsa, ed25519
  ~ - The RSA key size for egress SSH keys must be between 2048 and 8192 bits
  ~ - The Multi-Factor Authentication (MFA) policy is ENABLED
  ~ 
  ~ Here is your excuse for anything not working today:
  ~ BOFH excuse #444:
  ~ overflow error in /dev/null

