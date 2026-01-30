============
groupCreate
============

Create a group
==============


.. admonition:: usage
   :class: cmdusage

   --osh groupCreate --group GROUP --owner ACCOUNT <--algo ALGO --size SIZE [--encrypted]|--no-key>

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



A quick overview of the different algorithms:

.. code-block:: none

   Ed25519      : robustness[###] speed[###]
   ECDSA        : robustness[##.] speed[###]
   RSA          : robustness[#..] speed[#..]

This table is meant as a quick cheat-sheet, you're warmly advised to do
your own research, as other constraints may apply to your environment.
