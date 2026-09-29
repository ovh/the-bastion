======
Realms
======

.. contents::

Introduction
============

A **realm** is a trust relationship established between two bastions, possibly operated by two
different teams or even two different companies. It allows the accounts of a *remote* bastion to be
granted accesses on your *local* bastion, without having to create a local account for each of them,
and without your local bastion ever seeing their ingress keys, passwords or second factors.

The key idea is that realms **split the authentication and the authorization phases** between the two
bastions:

- The **remote** bastion handles **authentication**: it knows who the user is, because the user owns
  a real account there, with their ingress key, their MFA, their PIV policy, and so on. This is where
  the user actually logs in.
- Your **local** bastion handles **authorization**: it decides what a given remote account is allowed
  to access, using the exact same group- and access-management mechanisms you already use for your
  local accounts.

This is especially useful when you need to give a partner, a supplier, or another team controlled
access to a subset of your infrastructure: you delegate the burden of authenticating their people and
managing the lifecycle of each of their accounts to *their* bastion, while keeping full control
over *what* they can reach, and full traceability of *what* they did, on yours.

.. note::

   The two perspectives are easy to mix up, so we fix the vocabulary once here and use it consistently
   throughout the page:

   - The **local** bastion is *yours*: the one that **declares** the realm, hosts the ``realm_<name>``
     shared account and the target infrastructure, and decides *what* remote accounts may reach
     (**authorization**).
   - The **remote** bastion is the *other* one (``ACME`` in the examples below): the one whose users
     have real accounts, and which vouches for *who* they are (**authentication**).
   - A remote user, once seen through the realm on your local bastion, is called a *citizen of the
     realm* and is referred to everywhere as ``<realm>/<account>`` (e.g. ``acme/jdoe``).

   In the shell examples, the command prefix tells you which bastion the command runs against:
   ``bssh`` is *your* (local) bastion, and ``acmebssh`` is ACME's (remote) bastion.

How it works
============

On the local bastion, a realm is materialized by a single special **shared account**, named
``realm_<name>``. It is created with :doc:`/plugins/restricted/realmCreate` and is not a regular
account: it can't connect anywhere by itself, and it only exists to receive incoming connections from
the remote bastion.

When a user (say ``jdoe``) of the remote bastion connects through it to your ``realm_<name>`` account,
the following happens:

- The remote bastion authenticates ``jdoe`` locally, the usual way (ingress key, MFA, ...).
- It then opens an egress connection to your local bastion, logging in as the ``realm_<name>`` account,
  using the **egress group key** registered when the realm was created.
- It transparently passes along the real account name (``jdoe``) and authentication details (such as
  which MFA factors were validated) using the SSH environment, which your local bastion reads.
- Your local bastion therefore knows it's dealing with ``jdoe``, *as seen from* the ``<name>`` realm,
  and refers to this account as ``<name>/jdoe`` everywhere: in the access checks, in the logs, and in
  the ttyrec session recordings.

The whole point is that the connection is *split in two halves* across the trust boundary: the remote
bastion answers "**who** is this user?" (authentication), and your local bastion answers "**what** may
this user reach?" (authorization). The two bastions communicate the user's identity and whether they
already passed MFA, over the SSH environment of the realm connection:

.. code-block:: text

     REMOTE bastion (ACME's)          |  LOCAL bastion (yours)
     "who is the user?" (AuthN)       |  "what may they reach?" (AuthZ)
                                      |
   jdoe                               |
    '--> (1) authenticate jdoe        |
         |   (key; + MFA/PIV if       |
         |    ACME requires it)       |
         |                            |
        (2) jdoe must be in the       |
         |   group backing the realm  |
         |                            |
        (3) egress SSH as realm_acme, |
         |   handing over the SSH env:|
         |     LC_BASTION = jdoe      |
         |     LC_BASTION_DETAILS=... |
         |                            |
         '==== SSH: trust boundary ===+=> (4) arrives as realm_acme;
                                      |      LC_BASTION -> "acme/jdoe"
                                      |      (a citizen of the realm)
                                      |
                                      |  (5) authorize acme/jdoe with
                                      |      your own groups & accesses
                                      |
                                      |  (6) MFA needed here? if already
                                      |      validated on ACME's side,
                                      |      don't ask again
                                      |
                                      |  (7) egress to target --> server

From there on, ``<name>/jdoe`` is treated almost exactly like a local account would be: it can only
reach the servers it has been explicitly granted access to, and every action is logged and recorded.

.. warning::

   The ``realm_`` account name prefix is reserved: you can't create a regular account or a group whose
   name starts with ``realm_``.

Setting up a realm
==================

Setting up a realm requires a few steps on each side. In the following example, the people from a
partner company we'll call **ACME** need access to some of your servers; your own bastion is reachable
at ``bastion.example.org``. We'll create a realm named ``acme`` on your local bastion, named after
*them*, the incoming side, so that ACME's accounts can be granted accesses just like your own.

On the remote bastion (ACME's side)
-----------------------------------

The remote bastion connects to yours using the egress key of one of its **regular groups**. ACME
therefore dedicates a group to this purpose (or creates a new one): the egress key of that group is
what your bastion will trust.

This is an ordinary group on ACME's bastion, and its name is entirely ACME's choice: it has nothing to
do with the ``acme`` realm name *you* picked on your side. A useful convention is to name it after the
*destination*, mirroring how you named the realm after the *source*. Here ACME calls it
``example-partner``, since its members are the ACME people allowed to reach your ``example.org``
bastion:

.. code-block:: shell
   :emphasize-lines: 1

   acmebssh --osh groupCreate --group example-partner --algo ed25519 --owner alice

The members of this group on ACME's bastion are the people who'll be able to reach your local bastion
through the realm. ACME's gatekeepers add them as usual:

.. code-block:: shell
   :emphasize-lines: 1

   acmebssh --osh groupAddMember --group example-partner --account jdoe

ACME then needs to retrieve the **public** part of this group's egress key, and the egress **IPs** of
their bastion (the addresses your bastion will see incoming connections from). The public key can be
obtained with :doc:`/plugins/open/groupInfo`:

.. code-block:: shell
   :emphasize-lines: 1

   acmebssh --osh groupInfo --group example-partner

ACME communicates both the egress public key and their egress IP(s) to you. They'll also need to
declare your local bastion as a server of that group, so that their members can connect to it (see
:ref:`below <realms_connecting>`).

On the local bastion (your side)
--------------------------------

As a bastion admin with access to the restricted :doc:`/plugins/restricted/realmCreate` command, you
declare the realm, registering ACME's egress group public key and the IPs their bastion connects from:

.. code-block:: shell
   :emphasize-lines: 1

   bssh --osh realmCreate --realm acme --from 203.0.113.0/24 --public-key "ssh-ed25519 AAAAC3Nza... acme_egress_key"

- ``--realm`` is the local name you give to this realm (here, ``acme``).
- ``--from`` is the comma-separated list of egress IPs (or CIDR blocks) used by ACME's bastion; it uses
  the same syntax as the ``from=`` directive of SSH keys, and ensures the realm key can only be used
  from ACME's bastion.
- ``--public-key`` is the egress **group** public key ACME gave you. If you omit it, you'll be prompted
  to paste it interactively.

That's it: the ``realm_acme`` shared account now exists on your bastion.

.. note::

   There is no ``realmModify`` command. If you need to change the trusted key or the ``--from`` IPs of
   an existing realm, delete it with :doc:`/plugins/restricted/realmDelete` and recreate it.

Granting accesses to realm accounts
-----------------------------------

A realm by itself grants nothing: ACME's accounts can land on your bastion, but won't be able to reach
any server until you explicitly authorize them, exactly as you would for a local account. The only
difference is that you refer to a remote account using its realm-qualified name ``acme/jdoe`` instead
of a plain account name.

For example, to add ``jdoe`` from the ``acme`` realm as a member of one of your groups, your
gatekeeper would run:

.. code-block:: shell
   :emphasize-lines: 1

   bssh --osh groupAddMember --group prod_routers --account acme/jdoe

The same realm-qualified name works for guest accesses
(:doc:`/plugins/group-gatekeeper/groupAddGuestAccess`) and, where relevant, for personal accesses.
You can review what a given realm account is allowed to reach with the usual command:

.. code-block:: shell
   :emphasize-lines: 1

   bssh --osh accountListAccesses --account acme/jdoe

.. _realms_connecting:

Connecting through a realm
==========================

From ACME's point of view, your local bastion is simply a server reachable through their dedicated
group. Their aclkeeper adds it to the group, specifying the ``realm_acme`` account as the remote user:

.. code-block:: shell
   :emphasize-lines: 1

   acmebssh --osh groupAddServer --host bastion.example.org --port 22 --user realm_acme --group example-partner

ACME's members can now connect to your bastion through theirs, and end up in your bastion's shell as a
citizen of the realm. They can run osh commands, or bounce to the servers you granted them:

.. code-block:: shell
   :emphasize-lines: 1

   acmebssh realm_acme@bastion.example.org --osh info
   ---------------------------------------------------------------------------------------
   You are now connected to bastion.example.org. Welcome, jdoe, citizen of the acme realm!
   ---------------------------------------------------------------------------------------

Note that ``jdoe`` never gets a local account, an ingress key, or a password on your bastion: their
authentication happened entirely on ACME's bastion.

Inspecting realms
=================

You can list the realms declared on your bastion with :doc:`/plugins/restricted/realmList`:

.. code-block:: shell
   :emphasize-lines: 1

   bssh --osh realmList

To see which remote accounts of a given realm are known (i.e. have been granted at least one access),
use :doc:`/plugins/restricted/realmInfo`:

.. code-block:: shell
   :emphasize-lines: 1

   bssh --osh realmInfo --realm acme
   => realm information
   --------------------------------------------------------------------------------
   ~ The following accounts from realm acme are known:
   ~ - jdoe               [2 accesses]
   ~ - asmith             [1 accesses]
   ~
   ~ To get their access list, use --osh accountListAccesses --account acme/account_name_here

The :doc:`/plugins/restricted/whoHasAccessTo` command is also realm-aware: when checking who can reach
a given server, the realm accounts that have access to it are listed using their ``realm/account``
name.

MFA and realms
==============

Realms cooperate with :doc:`Multi-Factor Authentication </administration/mfa>`. When a remote account
validates MFA on its own (remote) bastion, that fact is securely transmitted to your local bastion as
part of the realm connection. This means that:

- If your local policy (or a group/access policy) requires MFA, and the user already validated a
  matching factor on the remote bastion, they won't be asked to do it again. The bastion will inform
  them with a message such as ``... you already validated MFA on the bastion you're coming from.``
- The remote account is never required to set up MFA *on your bastion*: it has no real account there to
  attach a second factor to. The trust is delegated to the remote bastion, which is responsible for
  enforcing its own MFA policy.

If you require a strong guarantee that incoming realm users have validated a second factor, make sure
the remote bastion enforces MFA on its side, for instance by requiring it on the group whose egress key
backs the realm.

Removing a realm
================

To revoke the trust relationship entirely, delete the realm with
:doc:`/plugins/restricted/realmDelete`:

.. code-block:: shell
   :emphasize-lines: 1

   bssh --osh realmDelete --realm acme

This removes the ``realm_acme`` shared account, so the remote bastion can no longer connect. As with
any account deletion, this also revokes all the accesses that were granted to that realm's accounts.
