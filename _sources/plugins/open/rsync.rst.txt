======
rsync
======

Transfer files from/to remote servers using rsync through the bastion
=====================================================================

.. note::

   This plugin should not be called manually, but passed as the --rsh option to rsync.

Usage examples
--------------

To transfer all files from ``/srcdir`` to the ``remotehost``'s ``/dest/`` directory::

   rsync -va --rsh "ssh -T BASTION_USER@BASTION_HOST -p BASTION_PORT -- --osh rsync --" /srcdir remoteuser@remotehost:/dest/

The ``-va`` options are just examples, you can use any option of ``rsync`` that you see fit.

To transfer all remote files from ``/srcdir`` to the local ``/dest`` directory::

   rsync -va --rsh "ssh -T BASTION_USER@BASTION_HOST -p BASTION_PORT -- --osh rsync --" remoteuser@remotehost:/srcdir /dest/

Please note that you need to be granted for uploading or downloading files
with ``rsync`` to/from the remote host, in addition to having the right to SSH to it.
For a group, the right should be added with ``--protocol rsync`` of the :doc:`/plugins/group-aclkeeper/groupAddServer` command.
For a personal access, the right should be added with ``--protocol rsync`` of the :doc:`/plugins/restricted/selfAddPersonalAccess` command.
:doc:`/plugins/open/selfListEgressKeys`

You'll find more information and examples in :doc:`/using/sftp_scp_rsync`.
