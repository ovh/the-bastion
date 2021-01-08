==================
Basic Installation
==================

If you are just upgrading from a previous version, please read :doc:`upgrading<upgrading>` instead.

0. Got Puppet?
==============

We published a Puppet module to handle The Bastion configuration and prerequisites. The GitHub repo is `here <https://github.com/ovh/puppet-thebastion>`_ and our module has been published to `the Puppet forge <https://forge.puppet.com/modules/goldenkiwi/thebastion>`_. Of course, its usage is completely optional, but if you choose to use it, some of the below steps will be done by Puppet. Hence, you might want to only consider the following steps:

- :ref:`install-basic_operating-system`
- :ref:`install-basic_get-the-code`
- :ref:`install-basic_encrypt-home`
- (Run Puppet)
- :ref:`install-basic_first-account`

.. _install-basic_operating-system:

1. Operating system
===================

.. warning::

   The Bastion expects to be the only main service running on the server, please see :ref:`this FAQ entry <faq_existing_server>` for more information.

The following Linux distros are tested with each release, but as this is a security product, you are *warmly* advised to run it on the latest up-to-date stable version of your favorite OS:

- Debian 10 (Buster), 9 (Stretch), 8 (Jessie)
- RHEL/CentOS 8.x (8.3.2011, 8.2.2004, 8.1.1911), 7.x (7.9.2009, 7.8.2003, 7.7.1908)
- Ubuntu LTS 20.04, 18.04, 16.04, 14.04\*
- OpenSUSE Leap 15.2\*, 15.1\*, 15.0\*\*

\*: Note that these versions have no out-of-the-box MFA support, as they lack packaged versions of ``pamtester``, ``pam-google-authenticator``, or both. Of course, you may compile those yourself.
Any other so-called `modern` Linux version are not tested with each release, but should work with no or minor adjustments.

\*\*: OpenSUSE Leap 15.0 randomly hits a segfault when `updating system packages <https://bugzilla.opensuse.org/show_bug.cgi?id=1146027>`_, we had to remove it from our automated tests workflow.

The following OS are also tested with each release:

- FreeBSD/HardenedBSD 12.1\*\*\*

\*\*\*: Note that these have partial MFA support, due to their reduced set of available ``pam`` plugins. Support for either an additional password or TOTP factor can be configured, but not both at the same time. The code is actually known to work on FreeBSD/HardenedBSD 10+, but it's only regularly tested under 12.1.

Other BSD variants partially work but are unsupported and discouraged as they have a severe limitation over the maximum number of supplementary groups (causing problems for group membership and restricted commands checks), no filesystem-level ACL support and missing MFA:

- OpenBSD 5.4+
- NetBSD 7+

In any case, you are expected to install this on a properly secured machine (including, but not limited to: ``iptables``/``pf``, reduced-set of installed software and daemons, general system hardening, etc.). If you use Debian, following the CIS Hardening guidelines is a good start.

Great care has been taken to write secure, tested code, but of course this is worthless if your machine is a hacker highway. Ensuring that all the layers below the bastion code (the operating system and the hardware it's running on) is your job.

.. _install-basic_get-the-code:

2. Get the code
===============

The bastion code usually lives under ``/opt/bastion``.
You can either use ``git clone`` directly, or get the tarball of the latest release.

- Using :command:`git`:

.. code-block:: shell

  git clone https://github.com/ovh/the-bastion /opt/bastion
  git -C /opt/bastion checkout $(git -C /opt/bastion tag | tail -1)

- Using the tarball:

Get the tarball of the latest release, which can be found `there <https://github.com/ovh/the-bastion/releases/latest>`_, then untar it:

.. code-block:: shell

  test -d /opt/bastion || mkdir -p /opt/bastion
  tar -C /opt/bastion v__VERSION__.tar.gz

The code supports being hosted somewhere else on the filesystem hierarchy, but this is discouraged as you might need to adjust a lot of configuration files (notably sudoers.d, cron.d, init.d) that needs an absolute path.
You should end up with directories such as ``bin``, ``lib``, etc. directly under ``/opt/bastion``.

.. _install-basic_install-packages:

3. Install the needed packages
==============================

For the supported Linux distros (see above), you can simply run:

.. code-block:: shell

   /opt/bastion/bin/admin/packages-check.sh -i

You can add other parameters to install optional packages, depending on your environment:

- ``-s`` to install ``syslog-ng`` (advised, we have templates files for it)
- ``-d`` to install packages needed for developing the software (useless in production)
- ``-t`` to install ``ovh-ttyrec``

Note that ``-t`` makes the assumption that you have compiled and made available ``ovh-ttyrec`` to your distro repositories. If you haven't, you can use the following helper:

.. code-block:: shell

   /opt/bastion/bin/admin/install-ttyrec.sh -a

This will detect your distro, then download and either install the ``.deb`` or ``.rpm`` package for `ovh-ttyrec <https://github.com/ovh/ovh-ttyrec>`_. If your distro doesn't handle those package types, it'll fallback to installing precompiled static binaries. Of course you can package it yourself and make it available to your own internal repositories instead of installing it this way.

If you plan to use the PIV functionalities of The Bastion, you'll also need to install the ``yubico-piv-checker`` `helper tool <https://github.com/ovh/yubico-piv-checker>`_:

.. code-block:: shell

   /opt/bastion/bin/admin/install-yubico-piv-checker.sh -a

.. _install-basic_encrypt-home:

4. Encrypt /home
================

Strictly speaking, this step is optional, but if you skip it, know that all the SSH private keys and session recordings will be stored unencrypted on the ``/home`` partition. Of course, if partition encryption is already handled by the OS template you use, or if the storage layer of your OS is encrypted by some other mean, you may skip this section.

First, generate a secure password on your desk (but not too complicated so it can be typed on a console over your hypervisor over a VDI over VPN over 4G in the dark at 3am on a Sunday) and save it to a secure location: ``pwgen -s 10``.

Then you can use the helper script to do this, it'll guide you through the process: When prompted for a passphrase, enter the one chosen just before.

.. code-block:: shell

    /opt/bastion/bin/admin/setup-encryption.sh

If you get a cryptsetup error, you might need to add ``--type luks1`` to the ``cryptsetup luksFormat`` command in the script. It can happen if your kernel doesn't have the necessary features enabled for LUKS2.

.. warning::

    Once you have setup encryption, **do not forget** to ensure that the keys backup script has encryption enabled, otherwise the backups will be stored unencrypted in ``/root/backups``, which would make your ``/home`` encryption moot. This is not covered here because you can do it later, just don't forget it: it's in the :doc:`advanced installation<advanced>` section.

.. _install-basic_setup:

5. Setup bastion and system configuration
=========================================

The following script will do that for you. There are several possibilities here.

- If you're installing a new machine (nobody is using it as a bastion yet), then you can regenerate brand new host keys and directly harden the ssh configuration without any side effect:

.. code-block:: shell

    /opt/bastion/bin/admin/install --new-install

- If you're upgrading an existing machine (from a previous version of this software), and there are already some people using it as a bastion, then if you change the host keys, they'll have to acknowledge the change when connecting, i.e. this is not transparent at all. To avoid doing that and not touching either the ssh config or the host keys, use this:

.. code-block:: shell

    /opt/bastion/bin/admin/install --upgrade

If you used ``--upgrade``, then you are **warmly** advised to harden the configuration yourself, using our templates as a basis. For example, if you're under Debian 10:

.. code-block:: shell

    vimdiff /opt/bastion/etc/ssh/ssh_config.debian10 /etc/ssh/ssh_config
    vimdiff /opt/bastion/etc/ssh/sshd_config.debian10 /etc/ssh/sshd_config

There are other templates available in the same directory, for the other supported distros.

- If you want to have a fine-grained control of what is managed by the installation script, and what is managed by yourself (or any configuration automation system you may have), you can review all the fine-grained options:

.. code-block:: shell

    /opt/bastion/bin/admin/install --help

.. _install-basic_review-config:

6. Review the configuration
===========================

Base configuration files have been copied, you should review the main configuration and modify it to your needs:

.. code-block:: shell

    vim /etc/bastion/bastion.conf

.. _install-basic_perl-check:

7. Check that the code works on your machine
============================================

This script will verify that all required modules are installed:

.. code-block:: shell

    /opt/bastion/bin/dev/perl-check.sh

.. _install-basic_first-account:

8. Manually create our first bastion account
============================================

Just launch this script, replacing *USERNAME* by the username you want to use:

.. code-block:: shell

    /opt/bastion/bin/admin/setup-first-admin-account.sh USERNAME auto

You'll just need to specify the public SSH key to add to this new account. It'll be created as a bastion admin, and all the restricted commands will be granted.

.. note::

    This command will also give you a so-called *bastion alias*, this is the command you'll routinely use to connect to the bastion, and to your infrastructures through it, replacing in effect your previous usage of the `ssh` command. The alias name advertised on account creation is configurable in ``bastion.conf``, and of course the users can rename it as they see fit, but it's advised to keep this command short, as people will use it a lot.

If you want to create other admin accounts, you can repeat the operation. All the other accounts should be created by a bastion admin (or more precisely, by somebody granted to the *accountCreate* command), using the bastion own commands. But more about this in the section *Using the bastion*.

Now that your bastion is installed, you can either check the :doc:`advanced installation<advanced>` documentation, or head over to the :doc:`using the bastion<../using/index>` section.
