=====
sftp
=====

Transfer files from/to remote servers using sftp through the bastion
====================================================================

.. note::

   This plugin generates a valid helper script for you to use the bastion over scp, read below to learn how to use it.

To be able to use ``sftp`` over the bastion, you need to have a helper script that is specific
to your account on the bastion. This plugin's job is to generate it for you.
You can simply run it, and follow the guidelines.

Once this is done, you'll be able to ``sftp`` through the bastion by adding ``-S SFTP_SCRIPT`` to your
regular ``sftp`` command, where ``SFTP_SCRIPT`` is the location of the script you've just generated.

For example::

   sftp -S ~/sftp_bastion login@server

.. note::

   If you're getting the 'subsystem request failed on channel 0' error, it usually means that
   sftp is not enabled on the remote server, as this is not always enabled by default, depending
   on the distro you're using.

Please note that you need to be granted for uploading or downloading files
with SFTP to/from the remote host, in addition to having the right to SSH to it.
For a group, the right should be added with ``--sftp`` of the :doc:`/plugins/group-aclkeeper/groupAddServer` command.
For a personal access, the right should be added with ``--sftp`` of the :doc:`/plugins/restricted/selfAddPersonalAccess` command.
:doc:`/plugins/open/selfListEgressKeys`

You'll find more information and examples in :doc:`/using/sftp_scp`.
