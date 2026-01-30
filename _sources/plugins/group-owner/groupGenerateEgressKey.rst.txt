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
                   For Ed25519, size is always 256.

.. option:: --encrypted

   If specified, a passphrase will be prompted for the new key



A quick overview of the different algorithms:

.. code-block:: none

   Ed25519      : robustness[###] speed[###]
   ECDSA        : robustness[##.] speed[###]
   RSA          : robustness[#..] speed[#..]

This table is meant as a quick cheat-sheet, you're warmly advised to do
your own research, as other constraints may apply to your environment.
