========
Features
========

.. note::
   This aims to be a quick overview of the main supported features of The Bastion, focusing on use cases.
   For a better introduction about the basic features, please refer to the front page of the documentation.

.. warning::
   Documentation might not be present yet for all the features below.

- Personal and group access schemes with group roles delegation to ensure teams autonomy without security trade-offs
- SSH protocol break between the ingress and egress connections (see other :doc:`security measures<security>`)
- Self-reliance achieved through virtually no external dependencies (see other :doc:`security measures<security>`)
- Interactive session recording (in standard ``ttyrec`` files)
- Non-interactive session recording (`stdout` and `stderr` through ``ttyrec``)
- Extensive logging support through `syslog` for easy SIEM consumption
- Supports `MOSH <https://github.com/mobile-shell/mosh>`_ on the ingress connection side
- Supports ``scp`` passthrough, to upload and/or download files from/to remote servers
- Supports ``netconf`` SSH subsystem passthrough
- Supports Yubico PIV keys
  `attestation checking <https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html>`_ and enforcement
  on the ingress connection side
- Supports realms, to create a trust between two bastions of possibly two different companies,
  splitting the authentication and authorization phases while still enforcing local policies
- Supports SSH password autologin on the egress side for legacy devices not supporting pubkey authentication,
  while still forcing proper pubkey authentication on the ingress side
- Supports telnet password autologin on the egress side for ancient devices not supporting SSH,
  while still forcing proper SSH pubkey authentication on the ingress side
- Supports HTTPS proxying with man-in-the-middle authentication and authorization handling,
  for ingress and egress password decoupling (mainly useful for network device APIs)
