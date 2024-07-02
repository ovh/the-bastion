=====================
Restoring from backup
=====================

In this section, we'll detail how to restore a bastion's main data from a backup.

This can be useful in two main cases:

- When an account with high privileges has deleted or altered by mistake a great amount of accounts or groups, up
  to a point where it's operationally easier to just restore the settings, accounts, groups and keys from the latest
  available backup

- When you are not in an :ref:`HA setup <installadv_ha>` and your only
  instance is down and can't be brought back up in a timely manner.

Note that if you are in a HA setup and you need to add a new node (regardless of the fact that you're replacing
a failed node or not), you don't need to restore from backup: you can simply follow the HA setup procedure so
that your new node is synced with your main node.

Prerequisites
=============

First, you obviously must have a backup at hand, which should be the case if you followed the
:ref:`installadv_backup` section when you first installed the instance you want to restore.

If the backup is encrypted with GPG (it should be), you must have access to the corresponding GPG private key and
its passphrase.

You must ensure that the new server you're setting up has the same OS release than the one the backup file
comes from, as we'll overwrite the new server's accounts and groups files with the backed up versions.
This could cause adverse effects if the distro or release differ, although the restore script won't stop
you from doing so (it'll even help you adjust the discrepancies if needed, but again, this is strongly discouraged).

Steps
=====

Installation
------------

On the new server you want to deploy the backup to, you must first follow the standard :doc:`/installation/basic`
procedure, up to and including the *Check that the code works on your machine* step.

Once done, you may proceed to the next steps below.

GPG key and backup archive import
---------------------------------

On the server you've just installed, you'll need to import the private GPG key that was used to encrypt the backup, and
you'll also need to fetch the backup archive itself. It's a good practice to NOT decrypt the backup archive prior to
transferring it to the new server. This way, you're sure that the credentials and keys contained in the backup have
not been compromised.

To import the GPG key, just run:

.. code-block:: shell
   :emphasize-lines: 1

   gpg --import

And paste the private GPG key corresponding to the backup so that it gets imported into root's keyring.

Alternatively, you can put the private GPG key in a temporary file, and import it this way:

.. code-block:: shell
   :emphasize-lines: 1

   gpg --import < /tmp/backupkey.asc

You may now import the backup archive, which usually has a name matching the :file:`backup-YYYY-MM-DD.tar.gz.gpg` format.
You can use ``scp``, ``sftp`` or any other method to get this file onto the server, at any location you see fit. We'll use
:file:`/root` as location for the rest of this documentation, as this is guaranteed to only be readable by root,
hence not compromising the keys and credentials.

Decrypt and extract accounts and groups
---------------------------------------

Now, you can decrypt the backup archive:

.. code-block:: shell
   :emphasize-lines: 1

   gpg -d /root/backup-YYYY-MM-DD.tar.gz.gpg > /root/backup-decrypted.tar.gz
   gpg: encrypted with 4096-bit RSA key, ID F50BFFC49143C821, created 2021-03-27
      "Bastion Administrators <bastions.admins@example.org>"

You'll have to input the GPG private key passphrase when asked to.

Then, check whether the archive seems okay:

.. code-block:: shell
   :emphasize-lines: 1

   tar tvzf /root/backup-decrypted.tar.gz

You should see a long list of files, most under the :file:`/home` hierarchy.

We now need to extract the backed up :file:`/etc/passwd` and :file:`/etc/group` files, to ensure the new
instance we're setting up has its UIDs/GIDs synced with the system we're restoring:

.. code-block:: shell
   :emphasize-lines: 1

   tar xvzf /root/backup-decrypted.tar.gz -C /root --strip-components=1 etc/passwd etc/group
   etc/group
   etc/passwd

We now have the two original accounts and groups lists in :file:`/root`, and we can proceed to check
whether the UIDs and GIDs are in sync.

Ensuring the UIDs/GIDs are in sync
----------------------------------

This procedure is the same than when setting up a slave instance bastion,
please follow the corresponding :ref:`step there<installadv_ha_uidgidsync>` and come
back to this documentation when it's done.

.. note::

   The referenced step above asks you to reboot at the end, please ensure you've done it before
   continuing with the rest of the procedure below.

Restoring
---------

Now that we know the UIDs/GIDs are synced, we can proceed with the full restore:

.. code-block:: shell
   :emphasize-lines: 1

   tar -C / --preserve-permissions --preserve-order --overwrite --acls --numeric-owner -xzvf /root/backup-decrypted.tar.gz

.. note::

   If you're getting errors such as 'Warning: Cannot acl_from_text: Invalid argument', please ensure that your
   filesystem supports ACLs and is mounted with ACL support, otherwise ``tar`` can't restore ACLs from the backup.

Back to production
------------------

As the configuration of the SSH daemon has also been restored, you might want to restart it so that it
picks up the new configuration:

.. code-block:: shell
   :emphasize-lines: 1

   service ssh restart

Once this is done, all the accounts that were present in the backup should be working. After ensuring this is the case,
you may put the server put back in production.
