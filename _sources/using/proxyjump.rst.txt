=================
Egress proxy jump
=================

.. contents::

Introduction
============

Sometimes the server you need to reach can't be accessed directly from the bastion, network-wise,
but only through an intermediate SSH *jump host*. The Bastion can hop through such a jump host to
reach the final server, while keeping all its usual guarantees: authentication, authorization,
traceability and session recording still apply, exactly as they would for a direct egress connection.

.. note::

   This is **not** the same as using The Bastion itself as an ``ssh -J`` / ``ProxyCommand`` jump host
   from your local client: that doesn't work, by design (see :ref:`faq_jumphost`).
   Here it's the other way around: it's the *bastion* that uses a jump host, on its **egress** side,
   to reach a server it couldn't reach directly.

How it works
============

When connecting through a jump host, the bastion keeps its usual *ingress/egress* protocol break, and
simply adds an intermediate network relay on the egress side:

- the **ingress** connection (you → bastion) is unchanged, and authenticated with your personal ingress key;
- the **egress** connection (bastion → target server) is established *through* the jump host, using a pure
  TCP forward (``ssh -W``) on the jump host. The bastion authenticates to **both** the jump host and the
  target server, using the same egress key (your personal egress key, or a group egress key you're a member of).

A few consequences worth keeping in mind:

- the egress public key (personal or group) must be installed **on both** the jump host (for the *proxy user*)
  and the target server (for the *remote user*);
- the jump host is only a network relay: it doesn't need to be another bastion, and it never sees the cleartext
  of your session: it merely forwards the encrypted bastion-to-target egress connection;
- both hops are subject to the bastion's egress network policy: if you've configured ``forbiddenNetworks``,
  ``allowedNetworks`` or ``ingressToEgressRules``, the jump host must satisfy them too, not just the final target.

Enabling the feature
====================

For safety, egress proxy jump is disabled by default. A bastion admin must set ``egressProxyJumpAllowed`` to
``true`` in the :doc:`/administration/configuration/bastion_conf`.

Granting access through a jump host
===================================

The jump host is part of the access itself: an access *to a server, through a given jump host* is distinct
from a direct access to the same server. You declare it by adding three options to the usual access-granting
commands:

- ``--proxy-host HOST|IP``: the jump host to reach the server through;
- ``--proxy-port PORT``: the jump host's SSH port (becomes mandatory once ``--proxy-host`` is specified);
- ``--proxy-user USER``: the user to connect as on the jump host (also mandatory with ``--proxy-host``).

This works just like declaring a regular access, either as a
:ref:`personal access <accessManagementPersonalAccesses>` (with :doc:`/plugins/restricted/selfAddPersonalAccess`
or :doc:`/plugins/restricted/accountAddPersonalAccess`) or as a
:ref:`group access <accessManagementGroupAccesses>` (with :doc:`/plugins/group-aclkeeper/groupAddServer`, or
:doc:`/plugins/group-gatekeeper/groupAddGuestAccess` for a guest access). The matching ``Del`` commands accept
the same options to remove such an access.

For example, to grant a group access to ``server.example.org`` reachable through the jump host
``jump.example.org``, connecting there as the ``relay`` user:

.. code-block:: none
   :emphasize-lines: 1,2

   bssh --osh groupAddServer --group mygroup --host server.example.org --port 22 --user admin \
        --proxy-host jump.example.org --proxy-port 22 --proxy-user relay

Unless you pass ``--force``, the bastion runs a real connectivity test *through the jump host* before adding
the access, so the egress key must already be installed on both hops at that point.

Connecting through the jump host
================================

Once the access is granted, specify the jump host at connection time with the ``-J`` option, using the familiar
``[user@]host[:port]`` syntax (the ``user`` and ``port`` parts are optional, and default to your remote user and
port ``22`` respectively):

.. code-block:: none
   :emphasize-lines: 1

   bssh -J relay@jump.example.org admin@server.example.org

The jump host you provide must match the one granted in the access: connecting through a different jump host, or
without a jump host when one is required, is denied just like any other unauthorized access.

.. note::

   Password autologin (reaching a target with a stored egress password rather than an egress key) is not
   currently supported through a jump host, this might change in the future.

File transfers
--------------

``scp`` transfers can go through a jump host too: pass the same ``-J`` option to the ``scp`` wrapper described in
:doc:`/using/sftp_scp_rsync`. Egress proxy jump is not currently supported for ``sftp`` or ``rsync``.
