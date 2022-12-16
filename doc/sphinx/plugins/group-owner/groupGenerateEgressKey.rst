=======================
groupGenerateEgressKey
=======================

Create a new public + private key pair for a group
==================================================


.. admonition:: usage
   :class: cmdusage

   --osh groupGenerateEgressKey --group GROUP --algo ALGO --size SIZE [--encrypted]

.. program:: groupGenerateEgressKey


.. option:: --group GROUP

   Group name to generate a new egress key for.


.. option:: --algo ALGO

   Specifies the algo of the key, either rsa, ecdsa or ed25519.


.. option:: --size SIZE

   Specifies the size of the key to be generated.

                   For RSA, choose between 2048 and 8192 (4096 is good).
                   For ECDSA, choose either 256, 384 or 521.
                   For ED25519, size is always 256.

.. option:: --encrypted

   If specified, a passphrase will be prompted for the new key


Note that the actually available algorithms on a bastion depend on the underlying OS and the configured policy.

A quick overview of the different algorithms::


  +---------+------+----------+-------+-----------------------------------------+
  | algo    | size | strength | speed | compatibility                           |
  +=========+======+==========+=======+=========================================+
  | DSA     |  any | 0        | n/a   | obsolete, do not use                    |
  | RSA     | 2048 | **       | **    | works everywhere                        |
  | RSA     | 4096 | ***      | *     | works almost everywhere                 |
  | ECDSA   |  521 | ****     | ***** | OpenSSH 5.7+ (Debian 7+, Ubuntu 12.04+) |
  | Ed25519 |  256 | *****    | ***** | OpenSSH 6.5+ (Debian 8+, Ubuntu 14.04+) |
  +---------+------+----------+-------+-----------------------------------------+

This table is meant as a quick cheat-sheet, you're warmly advised to do
your own research, as other constraints may apply to your environment.
