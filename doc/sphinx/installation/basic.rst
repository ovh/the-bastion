==================
Basic Installation
==================

If you are just upgrading from a previous version, please read :doc:`upgrading<upgrading>` instead.

0. Got Puppet?
==============

We published a Puppet module to handle The Bastion configuration and prerequisites.
The GitHub repo is `here <https://github.com/ovh/puppet-thebastion>`_ and our module has been published to
`the Puppet forge <https://forge.puppet.com/modules/goldenkiwi/thebastion>`_.
Of course, its usage is completely optional, but if you choose to use it,
some of the below steps will be done by Puppet. Hence, you might want to only consider the following steps:

- :ref:`install-basic_operating-system`
- :ref:`install-basic_get-the-code`
- :ref:`install-basic_encrypt-home`
- (Run Puppet)
- :ref:`install-basic_first-account`

.. _install-basic_operating-system:

1. Operating system
===================

.. warning::

   The Bastion expects to be the only main service running on the server,
   please see :ref:`this FAQ entry <faq_existing_server>` for more information.

The following Linux distros are tested with each release, but as this is a security product,
you are *warmly* advised to run it on the latest up-to-date stable version of your favorite OS:

- Debian 12 (Bookworm), 11 (Bullseye), 10 (Buster)
- RockyLinux 8.x, 9.x
- Ubuntu LTS 24.04, 22.04, 20.04
- OpenSUSE Leap 15.6\*

\*: Note that these versions have no out-of-the-box MFA support, as they lack packaged versions of ``pamtester``,
``pam-google-authenticator``, or both. Of course, you may compile those yourself.
Any other so-called `modern` Linux version are not tested with each release,
but should work with no or minor adjustments.

The following OS are also tested with each release:

- FreeBSD/HardenedBSD 14.2\*\*

\*\*: Note that these have partial MFA support, due to their reduced set of available ``pam`` plugins.
Support for either an additional password or TOTP factor can be configured, but not both at the same time.
The code is actually known to work on FreeBSD/HardenedBSD 10+, but it's only regularly tested under 14.2.

Other BSD variants, such as OpenBSD and NetBSD, are unsupported as they have a severe limitation over the maximum
number of supplementary groups, causing problems for group membership and restricted commands checks,
as well as no filesystem-level ACL support and missing PAM support (hence no MFA).

In any case, you are expected to install this on a properly secured machine (including, but not limited to:
``iptables``/``pf``, reduced-set of installed software and daemons, general system hardening, etc.).
If you use Debian, following the `CIS Hardening guidelines <https://www.cisecurity.org/benchmark/debian_linux/>`_ is
a good start. We have `a tool <https://github.com/ovh/debian-cis>`_ to check for compliance against these guidelines.
If you use Debian and don't yet have your own hardened template, this script should help you getting up to speed,
and ensuring your hardened host stays hardened over time, through a daily audit you might want to setup through cron.

Great care has been taken to write secure, tested code, but of course this is worthless if your machine
is a hacker highway. Ensuring that all the layers below the bastion code (the operating system
and the hardware it's running on) is your job.

2. Connect to your server as root
=================================

You'll need to be connected to your server as root to perform the installation. If you're using root password
authentication through SSH to do so, note that during the installation, as the SSH server configuration
will be hardened, the SSH password authentication will be disabled server-wide.

Hence, to access your server, please set up an SSH public key authentication instead of a password authentication,
and do so before proceeding with the next steps. Otherwise you might lose access to your own server once the
SSH hardening will be in effect, as password authentication will then be disabled.

.. _install-basic_get-the-code:

3. Get the code
===============

The bastion code usually lives under ``/opt/bastion``.
You can either use ``git clone`` directly, or get the tarball of the latest release.

- Using :command:`git`:

.. code-block:: shell

  git clone https://github.com/ovh/the-bastion /opt/bastion
  git -C /opt/bastion checkout $(git -C /opt/bastion tag | tail -1)

- Using the tarball:

Get the tarball of the latest release, which can be found
`there <https://github.com/ovh/the-bastion/releases/latest>`_, then untar it:

.. code-block:: shell

  mkdir -p /opt/bastion
  tar -C /opt/bastion -zxf v__VERSION__.tar.gz

The code supports being hosted somewhere else on the filesystem hierarchy, but this is discouraged as you might
need to adjust a lot of configuration files (notably sudoers.d, cron.d, init.d) that needs an absolute path.
You should end up with directories such as ``bin``, ``lib``, etc. directly under ``/opt/bastion``.

.. _install-basic_install-packages:

4. Install the needed packages
==============================

For the supported Linux distros (see above), you can simply run:

.. code-block:: shell

   /opt/bastion/bin/admin/packages-check.sh -i

You can add other parameters to install optional packages, depending on your environment:

- ``-s`` to install ``syslog-ng`` (advised, we have templates files for it)
- ``-d`` to install packages needed for developing the software (useless in production)

You'll also need our version of ttyrec, `ovh-ttyrec <https://github.com/ovh/ovh-ttyrec>`_.
To get and install the precompiled binary that will work for your OS and architecture, you can use this script:

.. code-block:: shell

   /opt/bastion/bin/admin/install-ttyrec.sh -a

This will detect your distro, then download and either install the ``.deb`` or ``.rpm`` package
for `ovh-ttyrec <https://github.com/ovh/ovh-ttyrec>`_. If your distro doesn't handle those package types,
it'll fallback to installing precompiled static binaries.
Of course you can package it yourself and make it available to your own internal repositories instead of installing it this way.

If you plan to use the PIV functionalities of The Bastion,
you'll also need to install the ``yubico-piv-checker`` `helper tool <https://github.com/ovh/yubico-piv-checker>`_.

You may also want to install ``the-bastion-mkhash-helper`` `tool <https://github.com/ovh/the-bastion-mkhash-helper>`_
if you want to be able to generate so-called type 8 and type 9 password hashes.

.. code-block:: shell

   /opt/bastion/bin/admin/install-yubico-piv-checker.sh -a
   /opt/bastion/bin/admin/install-mkhash-helper.sh -a

.. _install-basic_encrypt-home:

5. Encrypt /home
================

Strictly speaking, this step is optional, but if you skip it, know that all the SSH private keys and session
recordings will be stored unencrypted on the ``/home`` partition.
Of course, if partition encryption is already handled by the OS template you use,
or if the storage layer of your OS is encrypted by some other mean, you may skip this section.

First, generate a secure password on your desk (but not too complicated so it can be typed
on a console over your hypervisor over a VDI over VPN over 4G in the dark at 3am on a Sunday)
and save it to a secure location: ``pwgen -s 10``.

Then you can use the helper script to do this, it'll guide you through the process.
When prompted for a passphrase, enter the one chosen just before:

.. code-block:: shell

    /opt/bastion/bin/admin/setup-encryption.sh

If you get a cryptsetup error, you might need to add ``--type luks1`` to the ``cryptsetup luksFormat`` command
in the script. It can happen if your kernel doesn't have the necessary features enabled for LUKS2.

.. warning::

    Once you have setup encryption, **do not forget** to ensure that the keys backup script has encryption enabled,
    otherwise the backups will be stored unencrypted in ``/root/backups``,
    which would make your ``/home`` encryption moot.
    This is not covered here because you can do it later, just don't forget it:
    it's in the :doc:`advanced installation<advanced>` section.

.. _install-basic_setup:

6. Setup bastion and system configuration
=========================================

The following script will do that for you. There are several possibilities here.

- If you're installing a new machine (nobody is using it as a bastion yet), then you can regenerate brand new
  host keys and directly harden the ssh configuration without any side effect:

.. code-block:: shell

    /opt/bastion/bin/admin/install --new-install

- If you're upgrading an existing machine (from a previous version of this software),
  and there are already some people using it as a bastion, then if you change the host keys,
  they'll have to acknowledge the change when connecting, i.e. this is not transparent at all.
  To avoid doing that and not touching either the ssh config or the host keys, use this:

.. code-block:: shell

    /opt/bastion/bin/admin/install --upgrade

If you used ``--upgrade``, then you are **warmly** advised to harden the configuration yourself,
using our templates as a basis. For example, if you're under Debian 11:

.. code-block:: shell

    vimdiff /opt/bastion/etc/ssh/ssh_config.debian11 /etc/ssh/ssh_config
    vimdiff /opt/bastion/etc/ssh/sshd_config.debian11 /etc/ssh/sshd_config

There are other templates available in the same directory, for the other supported distros.

- If you want to have a fine-grained control of what is managed by the installation script,
  and what is managed by yourself (or any configuration automation system you may have), you can review all the fine-grained options:

.. code-block:: shell

    /opt/bastion/bin/admin/install --help

.. _install-basic_review-config:

7. Review the configuration
===========================

Base configuration files have been copied, you should review the main configuration and modify it to your needs:

.. code-block:: shell

    vim /etc/bastion/bastion.conf

.. _install-basic_perl-check:

8. Check that the code works on your machine
============================================

This script will verify that all required modules are installed:

.. code-block:: shell

    /opt/bastion/bin/dev/perl-check.sh

.. note::

   If you're installing this instance to restore a backup, you may stop here and resume the
   standard :doc:`/installation/restoring_from_backup` procedure.

.. _install-basic_first-account:

9. Manually create our first bastion account
============================================

Just launch this script, replacing *USERNAME* by the username you want to use:

.. code-block:: shell

   /opt/bastion/bin/admin/setup-first-admin-account.sh USERNAME auto

You'll just need to specify the public SSH key to add to this new account.
It'll be created as a bastion admin, and all the restricted commands will be granted.

.. note::

   This command will also give you a so-called *bastion alias*, this is the command you'll routinely use to
   connect to the bastion, and to your infrastructures through it, replacing in effect your previous usage
   of the `ssh` command. The alias name advertised on account creation is configurable in ``bastion.conf``,
   and of course the users can rename it as they see fit, but it's advised to keep this command short,
   as people will use it a lot.

If you want to create other admin accounts, you can repeat the operation.
All the other accounts should be created by a bastion admin (or more precisely,
by somebody granted to the *accountCreate* command), using the bastion own commands.
But more about this in the section *Using the bastion*.

You may head over to the **USAGE** section on the left menu, but please read the warning below first.

.. warning::
   Note that even if your bastion should now be functional, proper setup for a production-level environment
   is not done yet: for example, you don't have any backup system in place! Please ensure you follow the
   :doc:`advanced installation<advanced>` documentation and carely consider each step (by either completing it
   or deciding that it's not mandatory for your use case), before considering your installation complete.

