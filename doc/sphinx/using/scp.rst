===========
SCP support
===========

.. contents::

Introduction
============

The Bastion's main goal is to secure ``ssh`` connections. However, one might also want to use ``scp`` through it.

Its use is supported through the :doc:`/plugins/open/scp` bastion plugin, and documented as part of all the plugins. This additional documentation section gives some examples and outlines some common configuration errors.

Prerequisites
=============

The use of SCP through the bastion requires an SCP program than supports the **-S** option, and a shell to run the wrapper. This is the case on all operating systems using OpenSSH such as Linux or \*BSD.

If you're running under Microsoft Windows, you might want to setup either a Linux VM, or a WSL (Windows Subsystem for Linux) environment, to have the OpenSSH version of **scp** and a working POSIX-style shell.

Note that it won't work with Windows GUI apps, because there's no way to specify a wrapper (through **-S**), and no shell. For example, it won't work under WinSCP.

Also note that only SCP is supported, *not SFTP*.

Basic usage
===========

Please check the :doc:`/plugins/open/scp` documentation to see how to use it.

Access model
============

.. note::

   Currently, to be able to use SCP with a remote server, you first need to have a declared SSH access to it. This might change in a future version.

Error message 1
---------------

This is briefly explained in the :doc:`/plugins/open/scp` documentation, but having access rights to SSH to a machine is not enough to have the right to SCP to or from it. If you have the following error, then this is your problem:

::

    Sorry, you seem to have access through ssh and through scp but by different and distinct means (distinct keys).
    The intersection between your rights for ssh and for scp needs to be at least one.

When this happens, it means that you have at least one declared SSH access to this machine (through one or several groups, or through personal accesses). You also have at least one declared SCP access to it. However **both accesses are declared through different means**, and more precisely different SSH keys. For example:

- You are a member of a group having this machine on one hand, and you have a declared SCP access to this machine using a personal access on the other hand. For SSH, the group key would be used, but for SCP, your personal key would be used. However, for technical reasons (that might be lifted in a future version), your SSH and SCP access must be declared with the same key, so in other words, using the same access mean (same group, or personal access).

- You are a member of group **A** having this machine, but SCP access is declared in group **B**. In that case, as previously, as two different keys are used, this won't work.

To declare an SCP access, in addition to a preexisting SSH access, you should use either:

- :doc:`/plugins/group-aclkeeper/groupAddServer`, if the SSH access is part of a group

- :doc:`/plugins/restricted/selfAddPersonalAccess` or :doc:`/plugins/restricted/accountAddPersonalAccess`, if the SSH access is personal (tied to an account)

In both cases, where you would use the ``--user`` option to the command, to specify the remote user to use for the SSH access being declared, you should replace it by either ``--scp-down`` or ``--scp-up``, to specify that you're about to add an SCP access (not an SSH one), and which direction you want to allow. You can allow both directions by using the command first with ``--scp-down``, then with ``--scp-up``.

For example, this is a valid command to add SCP access to a machine which is part of a group:

::

   bssh --osh groupAddServer --group mygroup --host scpserver.example.org --port 22 --scp-up

Error message 2
---------------

If you have the following message:

::

    Sorry, but you don't seem to have access to HOST:IP

Then it means that you don't even have SSH access to this machine. In that case, somebody should grant you access, either by adding you to a group having this machine (:doc:`/plugins/group-gatekeeper/groupAddMember`) or by adding this machine to your personal accesses (:doc:`/plugins/restricted/accountAddPersonalAccess` or :doc:`/plugins/restricted/selfAddPersonalAccess`).
