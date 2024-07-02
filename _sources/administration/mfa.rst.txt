===========================
Multi-Factor Authentication
===========================

.. contents::

Introduction
============

Flavors
*******

The Bastion supports two flavors of Multi-Factor Authentication (MFA, sometimes called 2FA):

- `Immediate MFA`, mandatory on a per-account basis during the SSH authentication phase on the ingress side,
  done by the system even before executing the bastion code, regardless of which actions (plugin calls,
  remote connection, ...) are to be done by the account currently being authenticated

- `JIT MFA`, done after the authentication phase, by the bastion code, conditionally (*just-in-time*), when
  an action that is about to be done requires it by (configurable) policy

Each of these methods and their differences are detailed below, so you can choose the one that fits your environment.

Supported additional factors
****************************

The first factor is always the SSH publickey. Two additional factors are supported:

- `password`, in which case a password is attached to the account. This password's policy is configurable through
  :ref:`administration/configuration/bastion_conf:mfapasswordmindays`,
  :ref:`administration/configuration/bastion_conf:mfapasswordmaxdays`,
  :ref:`administration/configuration/bastion_conf:mfapasswordwarndays`,
  :ref:`administration/configuration/bastion_conf:mfapasswordinactivedays`.

- `TOTP`, aka "Time-based One-Time Password", which requires a smartphone app and generates a new pin-code every
  60 seconds.

Immediate MFA
=============

This method implements MFA directly using PAM during the initial SSH authentication phase, on the ingress
side, e.g. when accounts are connecting to the bastion. This entirely resides on SSH/PAM and doesn't even depend
on The Bastion code (appart from the setup side of the additional factor for each account).

.. note::

   Use this method if you want to enable MFA for some or all accounts unconditionally, regardless of which action
   they're about to conduct on The Bastion (i.e. use an ``--osh`` command, or attempt to connect somewhere,
   or just display the help). If you want to enable MFA only for some precise ``--osh`` commands or some remote hosts,
   you'll want to use :ref:`jit_mfa` instead.

This method requires proper configuration of both the SSH server, and PAM. The included templates of
:file:`/etc/ssh/sshd_config` and :file:`/etc/pam.d/ssh` files do support it out of the box.

Detailed explanation of the SSH server and PAM configuration
************************************************************

This works by modifying the ``AuthenticationMethods`` in :file:`sshd_config` to add ``keyboard-interactive:pam``,
which instructs the SSH server to rely on PAM for part of the authentication phase. Then, the PAM file defines
several authentications methods, which include several factors that can be configured per-account.

.. note::

   You can skip this subsection if you're not interested in how this works exactly, but mainly want to know how
   to setup MFA. If you're using the included :file:`sshd_config` and :file:`pam.d/ssh` templates unmodified,
   which you are if you've followed the installation section, this will just work out of the box so you may skip
   over the details and jump to :ref:`immediate_mfa_howto`.

sshd_config snippet
-------------------

Let's take the last few lines of the :file:`ssh_config` file and explain them step by step. These are where the
MFA logic is implemented. We've left the comments that can be found in the template, for clarity.

.. code-block:: shell

   # If 2FA has been configured for root, we force pubkey+PAM for it. If this is the case
   # on your system, uncomment the next two lines (see
   # https://ovh.github.io/the-bastion/installation/advanced.html#fa-root-authentication)
   #Match User root
   #    AuthenticationMethods publickey,keyboard-interactive:pam

As explained in the comments within the file, this section (commented by default) refers to the MFA that can be
configured on the ``root`` account to protect The Bastion's own system. This is out of the scope of this documenation
section, as we're focusing on the users MFA here, so refer to the :ref:`installation/advanced:2fa root authentication`
section if that's what you want to achieve.

.. code-block:: shell

   # Unconditionally skip PAM auth for members of the bastion-nopam group
   Match Group bastion-nopam
       AuthenticationMethods publickey

The snipper above tells the SSH server to NOT rely on PAM (hence disable MFA) for accounts that are part of the
``bastion-nopam`` group. This is an internal group that is used for accounts whose MFA setup has been set to
bypass PAM authentication, with the following command:

.. code-block:: none
   :emphasize-lines: 1

   bssh --osh accountModify --account robot-sync --pam-auth-bypass yes
   ╭──ac777d06bec9───────────────────────────────────────────the-bastion-3.12.00───
   │ ▶ modify the configuration of an account
   ├───────────────────────────────────────────────────────────────────────────────
   │ Bypassing sshd PAM auth usage for this account...
   │ ... done, this account will no longer use PAM for authentication
   ╰────────────────────────────────────────────────────────────</accountModify>───

This way, the account ``robot-sync`` will fall into the above configuration section ``Match`` case and end up
only using classic ``publickey`` authentication, hence no MFA. As MFA is only meaningful for humans, use this setting
for accounts that are used by any automated process you might have that interact with the bastion (for example using
its :doc:`/using/api`).

.. code-block:: shell

   # if in one of the mfa groups AND the osh-pubkey-auth-optional group, use publickey+pam OR pam
   Match Group mfa-totp-configd,mfa-password-configd Group osh-pubkey-auth-optional
       AuthenticationMethods publickey,keyboard-interactive:pam keyboard-interactive:pam

The snippet above tells SSH that for accounts having an authentication factor configured, namely either a TOTP or
a password, and having the "public key is optional" flag, set by ``--osh accountModify --pubkey-auth-optional``,
implies that those accounts can either authenticate through public key and an additional factor (through PAM),
or through PAM only. In essence these accounts may use only a password, or a TOTP, or both, without having a
public key in addition to the other factors. Hence, this is not MFA per-se, but is an additional functionaly available
should you need this in your environment. You may remove (or comment) the two lines above if you're confident you'll
never require the `pubkey-auth-optional` feature.

.. code-block:: shell

   # if in one of the mfa groups, use publickey AND pam
   Match Group mfa-totp-configd,mfa-password-configd
       AuthenticationMethods publickey,keyboard-interactive:pam

The snippet above is the core of the mandatory MFA configuration of the SSH server: it instructs the SSH server to
authenticate accounts that have at least one MFA factor configured with their public key first, then hand over the
authentication phase to PAM to check the additional factors.

.. code-block:: shell

   # by default, always ask the publickey (no PAM)
   Match All
       AuthenticationMethods publickey

Finally, the snippet above is for the general case, i.e. accounts not having MFA configured, in which case they're
authenticated using their public key only.

PAM ssh snippet
---------------

The template is `heavily commented<https://github.com/ovh/the-bastion/blob/master/etc/pam.d/sshd.debian12>`, line by line, please have a look at it if you want to know more.

.. _immediate_mfa_howto:

How to use Immediate MFA
************************

If you want to setup immediate MFA, you'll need to setup the SSH server and PAM configurations correctly, as explained
above. If you installed the provided templates for both (which is the default), you're good to go.

You may want either to enable MFA for *all* the accounts existing on your bastion, or only a subset of these users,
read on the proper section below for each case.

Requiring all users to setup their MFA
--------------------------------------

To ensure no user can use their account without configuring their MFA first, you have to set the ``accountMFAPolicy``
option of :file:`bastion.conf` to either ``any-required``, ``totp-required`` or ``password-required``. Detailed
information about this configuration setting is available
:ref:`here <administration/configuration/bastion_conf:accountmfapolicy>`.

When this setting is configured to any of the 3 above values, no interaction will be allowed on the bastion (such as
using plugins or connecting to a remote asset) as long as the user didn't set up their MFA:

.. code-block:: none

    bssh --osh selfListAccesses
    │ 
    │ ⛔ Sorry johndoe, but you need to setup the Multi-Factor Authentication before using this bastion, please use either the `--osh selfMFASetupPassword' or the `--osh selfMFASetupTOTP' option, at your discretion, to do so

The only allowed ``--osh`` commands allowed in such a case are ``help``, ``info`` and the two ones referenced in the
above error message, precisely to be able to setup the MFA on the account.

In this mode, if you want to exclude a few accounts from requiring MFA (if you have accounts that are used by
automation or any other M2M workflow), you can do so using ``accountModify --pam-auth-bypass yes``.

.. _immediate_mfa_subset_users:

Requiring only a subset of users to setup their MFA
---------------------------------------------------

If instead of forcing all users to require MFA, you want to require a precise subset of users to have MFA, you should
leave the ``accountMFAPolicy`` to ``enabled``, and set the requirement flag on a per-account basis. This can be
done using ``accountModify --mfa-password-required yes`` and/or ``accountModify --mfa-totp-required yes``. If you
set both flags on the same account, the bastion will require both factors to be set and provided on authentication,
in addition to publickey authentication. In this case, 3 authentication factors would be required. This is why we
call it *MFA* instead of *2FA*: the number of additional factors you want is configurable.

.. _jit_mfa:

JIT MFA
=======

This method implements MFA checking right before an action is allowed, depending on the bastion policy, instead of
requiring it at the ingress authentication stage.

.. note::

   Use this method if you want to enable MFA on a per-action basis. In this case, The Bastion will decide whether
   providing additional authentication factors is required right before a specific action is requested (such as
   connection to a given remote asset, or execution of a subset of ``--osh`` commands).
   You may also want to use this method if for some reason you can't setup the :file:`sshd_config` file
   as required by the *Immediate MFA* method

Note that the different ways detailed below can be cumulated: you might want to enable MFA for a few plugins, along
with enabling it for sensitive remote hosts present in specific bastion groups, in addition to a few sensitive
accounts that would require it no matter what.

.. _jit_mfa_sshd_config:

Proper setup of sshd_config
***************************

To use `JIT MFA`, your first have to disable `Immediate MFA`, as is the default if you're using the provided
configuration template for your SSH server (which you are if you followed the default installation steps).
You'll need to comment out two lines within the :file:`/etc/ssh/sshd_config` file, these are located near the
end of the file:

.. code-block:: shell

   # if in one of the mfa groups, use publickey AND pam
   #Match Group mfa-totp-configd,mfa-password-configd
   #    AuthenticationMethods publickey,keyboard-interactive:pam

You'll need to reload the SSH daemon for this to be taken into account. The next subsections explain how to setup
policies depending on the actions you want to protect through `JIT MFA`.

On a per-plugin basis
*********************

First ensure you've followed the :ref:`jit_mfa_sshd_config`.

To force MFA for a plugin, you may add the ``mfa_required`` option to its configuration. This configuration parameter
allows 4 values:

- `any`, in which case MFA is required with any supported factor (currently either password or TOTP)
- `password`, in which case a password is required in addition to publickey authentication
- `totp`, in which case a TOTP is required in addition to publickey authentication
- `none`, in which case no MFA is required (which is the default if the ``mfa_required`` setting is omitted)

To enable MFA for the ``adminSudo`` plugin, for example, you may add:

.. code-block:: shell

   {
      "mfa_required": "any"
   }

to the :file:`/etc/bastion/plugin.adminSudo.conf` file. Please ensure that this file is readable by the
``bastion-users`` system group (as all :file:`/etc/bastion/plugin.*.conf` files should be), so that the code running
under the bastion users permissions can read it.

When configured like this, usage of the adminSudo plugin, in our example, will trigger the validation of additional
authentication factors.
Note that for this to work, you must have the :file:`/etc/pam.d/ssh` file set up correctly,
as we're using PAM for this. The provided template is advised, and you're already using it if you followed the
default installation steps.
If you are not sure you're using the provided template, you may compare your current :file:`/etc/pam.d/ssh` file
with the proper template for your distro, which can be found in :file:`/opt/bastion/etc/pam.d/sshd.*`.

As you see, the MFA phase will be fired up for this plugin, but not for the ``info`` plugin for example:

.. code-block:: none
   :emphasize-lines: 1,7

   bssh --osh adminSudo
   As this is required to run this plugin, entering MFA phase for johndoe.
   Your account has Multi-Factor Authentication enabled, an additional authentication factor is required (password).
   Your password expires on 2023/10/31, in 89 days
   Password: ^C

   bssh --osh info
   ╭──ac777d06bec9───────────────────────────────────────────the-bastion-3.12.00───
   │ ▶ information
   ├───────────────────────────────────────────────────────────────────────────────
   │ You are johndoe
   [...]

On a per-group basis
********************

First ensure you've followed the :ref:`jit_mfa_sshd_config`.

If you want to ensure that MFA is required to connect to a remote host through a bastion group,
you should tag this group to require MFA. To do this, use the ``groupModify`` command:

.. code-block:: none
   :emphasize-lines: 1,9,18

   guybrush@bastion1(master)> groupModify --group securegroup --mfa-required any
   ╭──ac777d06bec9───────────────────────────────────────────the-bastion-3.12.00───
   │ ▶ modify the configuration of a group
   ├───────────────────────────────────────────────────────────────────────────────
   │ Modifying mfa-required policy of group...
   │ ... done, policy is now: any
   ╰──────────────────────────────────────────────────────────────</groupModify>───

   guybrush@bastion1(master)> groupInfo --group securegroup
   ╭──ac777d06bec9───────────────────────────────────────────the-bastion-3.12.00───
   │ ▶ group info
   ├───────────────────────────────────────────────────────────────────────────────
   │ Group securegroup's Owners are: guybrush
   [...]
   │ ❗ MFA Required: when connecting to servers of this group, users will be asked for an additional authentication factor
   [...]

   guybrush@bastion1(master)> ssh root@127.1.2.3
   │ Welcome to bastion1, guybrush, your last login was 00:00:27 ago (Wed 2023-08-02 15:36:03 UTC) from 172.17.0.1(172.17.0.1)
   [...]

    will try the following accesses you have: 
     - group-member of securegroup with ED25519-256 key SHA256:94yETEnnWUy9yTG1dgAdXgunq6zzJPjlddFXjUH0Czw [2023/03/03]  (MFA REQUIRED: ANY)

   As this is required for this host, entering MFA phase for guybrush.
   Your account has Multi-Factor Authentication enabled, an additional authentication factor is required (password).
   Your password expires on 2023/10/31, in 89 days
   Password: 

As you see, after setting the flag on the group, attempting to access an asset that is part of the group (see
``groupListServers``) will require MFA.

.. note::

   If an account has access to an asset via several groups, MFA will be required if at least one group requires it.
   Hence, a good way to ensure that all connections to an asset will require MFA would be to list the
   SSH keys on the remote server, match those to groups on the bastion, and ensure they all have ``--mfa-required`` enabled.

On a per-account basis
**********************

You may also use this method to enable MFA on a per-account basis (as is possible with the `Immediate MFA` method).

To do this, you should follow the same steps than are outlined in the :ref:`immediate_mfa_subset_users` subsection of the `Immediate MFA` setup.

The only difference will be in your :file:`sshd_config` file, as for `JIT MFA` your should ensure you've followed the :ref:`jit_mfa_sshd_config`.

In the case of `Immediate MFA`, the uncommented :file:`sshd_config` file block asks the SSH server to hand over authentication to PAM, hereby
requiring MFA at the authentication phase. For the `JIT MFA` on a per-account basis, this configuration is disabled, but the bastion code, after the
authentication phase is over, verifies whether the account requires to provide additional authentication factors, and triggers a PAM call if this
is the case.

Bypassing MFA for automated workflows
*************************************

If you have accounts that are used for automation, you'll want to exclude them from requiring MFA.

To do this, use ``--osh accountModify --mfa-password-required bypass --mfa-totp-required bypass``. Accounts
with this setting will no longer require to enter additional credentials even when the policy of `JIT MFA` would
require them to.

Additional information
======================

MFA and interactive mode
************************

When using the interactive mode, and `JIT MFA`, attempting to conduct an action that requires MFA will trigger the MFA authentication phase, as expected.

However, when multiple MFA-required operations are to be done back to back, as is often the case when interactive mode
is used, the MFA authentication phase will be triggered for each and every action, which can be cumbersome.

As long as :ref:`administration/configuration/bastion_conf:interactivemodeproactivemfaenabled` is true, users can use the **mfa** command in interactive
mode, to trigger the MFA authentication phase proactively, and enter an elevated session that will not require to enter MFA again. This elevated session
will expire after :ref:`administration/configuration/bastion_conf:interactivemodeproactivemfaexpiration` seconds (15 minutes by default). Users can exit
the elevated session manually by typing **nomfa**.

Here is how it looks like:

.. code-block:: none
   :emphasize-lines: 1,8,12,18,24,27

   bssh -i

   Welcome to bastion1 interactive mode, type `help' for available commands.
   You can use <tab> and <tab><tab> for autocompletion.
   You'll be disconnected after 60 seconds of inactivity.
   Loading... 90 commands and 0 autocompletion rules loaded.

   guybrush@bastion1(master)> mfa
   As proactive MFA validation has been requested, entering MFA phase.
   Your account has Multi-Factor Authentication enabled, an additional authentication factor is required (password).
   Your password expires on 2023/10/31, in 88 days
   Password: 
   pamtester: successfully authenticated
   Proactive MFA enabled, any command requiring MFA from now on will not ask you again.
   This mode will expire in 00:15:00 (Thu 2023-08-03 12:35:08 UTC)
   To exit this mode manually, type 'nomfa'.

   guybrush@bastion1(master)[MFA-OK]> groupAddServer
   ╭──ac777d06bec9───────────────────────────────────────────the-bastion-3.12.00───
   │ ▶ adding a server to a group
   ├───────────────────────────────────────────────────────────────────────────────
   [...]

   guybrush@bastion1(master)[MFA-OK]> nomfa
   Your proactive MFA validation has been forgotten.

   guybrush@bastion1(master)> 


As you seen, once ``mfa`` has been entered and the MFA validated, the prompt changes to ``[MFA-OK]`` implying that
any command usually requiring MFA will not ask for it again (such as ``groupAddServer`` in the above example, as
we've configured it to). We then explicitely exit the MFA elevated session by entering ``nomfa``.

MFA and --osh batch
*******************

The :doc:`/plugins/open/batch` plugin is useful to enter several ``--osh`` commands in a batch way. However, if
any of those commands require MFA, it would ask us repeatedly for our MFA, which can be cumbersome.

To avoid this behavior, and if you know that some of the commands you want to use in batch more will require MFA,
you may use the ``--proactive-mfa`` option to the bastion, which will ask for your MFA *before* executing the
:doc:`/plugins/open/batch` plugin, and any command requiring MFA will not ask for it again:

.. code-block:: none
   :emphasize-lines: 1,6

   bssh --proactive-mfa --osh batch

   As proactive MFA has been requested, entering MFA phase for guybrush.
   Your account has Multi-Factor Authentication enabled, an additional authentication factor is required (password).
   Your password expires on 2023/11/01, in 89 days
   Password: 
   pamtester: successfully authenticated
   ╭──ac777d06bec9───────────────────────────────────────────the-bastion-3.12.00───
   │ ▶ batch
   ├───────────────────────────────────────────────────────────────────────────────
   │ Feed me osh commands line by line on stdin, I'll execute them sequentially.
   │ Use 'exit', 'quit' or ^D to stop.
   │ --- waiting for input
   [...]

