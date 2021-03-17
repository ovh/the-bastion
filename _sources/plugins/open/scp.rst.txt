====
scp
====

Transfer files from/to remote servers through the bastion
=========================================================

.. note::

   This plugin generates a valid helper script for you to use the bastion over scp, read below to learn how to use it.

To be able to use ``scp`` over the bastion, you need to have a helper script that is specific to your account on the bastion. This plugin's job is to generate it for you. You can simply run it, and follow the guidelines.

Once this is done, you'll be able to ``scp`` through the bastion by adding ``-S SCP_SCRIPT`` to your regular scp command, where ``SCP_SCRIPT`` is the location of the script you've just generated.

For example, to upload a file::

   scp -S SCP_SCRIPT localfile login@server:/dest/folder/

Or to recursively download a folder contents::

   scp -S SCP_SCRIPT -r login@server:/src/folder/ /tmp/

Please note that you need to be granted for uploading or downloading files
with SCP to/from the remote host, in addition to having the right to SSH to it.
For a group, the right should be added with --scpup/--scpdown of the groupAddServer command.
For a personal access, the right should be added with --scpup/--scpdown of the selfAddPersonalAccess command.

