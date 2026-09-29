====
scp
====

Transfer files from/to remote servers using scp through the bastion
===================================================================

.. note::

   This plugin generates a shell script for you to use the bastion over scp, read below to learn how to use it.

To be able to use ``scp`` over the bastion, you'll have to use a shell script that is specific
to your account on the bastion. This plugin's job is to generate it for you.
You can simply run it, and follow the guidelines.

Once this is done, you'll be able to ``scp`` through the bastion by replacing your calls to ``scp``
by calls to the generated script. Usually the script will be named ``scp-via-bastion`` (with 'bastion'
being replaced by the actual bastion name), and you can use it with the same parameters that are
accepted by the regular ``scp`` command.

For example, to upload a file::

   ~/scp-via-bastion localfile login@server:/dest/folder/

Or to recursively download a folder contents::

   ~/scp-via-bastion -r login@server:/src/folder/ /tmp/

You can also use other usual scp options with it, just run the script with no option to get the list::

   Usage: ./scp-via-bastion [-p] [-q] [-r] [-T] [-v] [-l limit] [-i identity_file] [-P port] [-o ssh_option] source target

Please note that you need to be granted for uploading or downloading files
with scp to/from the remote host, in addition to having the right to SSH to it.
For a group, the right should be added with ``--protocol scpupload``/``--protocol scpdownload`` of the :doc:`/plugins/group-aclkeeper/groupAddServer` command.
For a personal access, the right should be added with ``--protocol scpupload``/``--protocol scpdownload`` of the :doc:`/plugins/restricted/selfAddPersonalAccess` command.

You'll find more information and examples in :doc:`/using/sftp_scp_rsync`.
