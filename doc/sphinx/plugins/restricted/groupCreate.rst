============
groupCreate
============

Create a new bastion group
==========================


.. admonition:: usage
   :class: cmdusage

   --osh groupCreate --group NAME --owner ACCOUNT --algo ALGO --size SIZE [OPTIONS]

.. program:: groupCreate


.. option:: --group NAME

   Group name to create, NAME must contain only valid UNIX group name characters

.. option:: --owner ACCOUNT

   Account to set as the group owner, this account will have complete rights to manage the group

.. option:: --algo ALGO

   Specifies the algo of the key, usually either rsa, ecdsa or ed25519. Note that the available algorithms depend on the OS the bastion is running on, along with its configuration policies

.. option:: --size SIZE

   Specifies the size of the key to be generated.
   For RSA, choose between 2048 and 8192 (any value above 4096 is probably not very useful).
   For ECDSA, choose either 256, 384 or 521.
   For ED25519, size is always 256.

.. option:: --encrypted

   When specified, a passphrase will be prompted for the new key, and the private key will be stored encrypted on the bastion. Note that the passphrase will be required each time you want to use the key.

.. option:: --no-key

   No egress key pair will be generated. In that case, omit ``--algo`` and ``--size``.

Algorithms guideline
====================

A quick overview of the different algorithms::

  +---------+------+-----------+---------+-----------------------------------------+
  | algo    | size | strength  | speed   | compatibility                           |
  +=========+======+===========+=========+=========================================+
  | DSA     |  any | 0         | n/a     | obsolete, do not use                    |
  | RSA     | 2048 | **        | **      | works everywhere                        |
  | RSA     | 4096 | ***       | *       | works almost everywhere                 |
  | ECDSA   |  521 | ****      | *****   | OpenSSH 5.7+ (debian 7+, ubuntu 12.04+) |
  | ED25519 |  256 | *****     | *****   | OpenSSH 6.5+ (debian 8+, ubuntu 14.04+) |
  +---------+------+-----------+---------+-----------------------------------------+

This table is meant as a quick cheat-sheet, you're warmly advised to do your own research, as other constraints may apply to your environment.
