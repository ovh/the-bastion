==================
selfAddIngressKey
==================

Add a new ingress public key to your account
============================================


.. admonition:: usage
   :class: cmdusage

   --osh selfAddIngressKey [--public-key '"ssh key text"'] [--piv]

.. program:: selfAddIngressKey


.. option:: --public-key KEY

   Your new ingress public SSH key to deposit on the bastion, use double-quoting if your're under a shell.

                      If this option is not specified, you'll be prompted interactively for your public SSH key. Note that you
                      can also pass it through STDIN directly. If the policy of this bastion allows it, you may prefix the key
                      with a 'from="IP1,IP2,..."' snippet, a la authorized_keys. However the policy might force a configured
                      'from' prefix that will override yours, or be used if you don't specify it yourself.
.. option:: --piv

   Add a public SSH key from a PIV-compatible hardware token, along with its attestation certificate and key

                      certificate, both in PEM format. If you specified --public-key, then the attestation and key certificate are
                      expected on STDIN only, otherwise the public SSH key, the attestation and key certificate are expected on STDIN.
