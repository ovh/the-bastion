======================
osh-encrypt-rsync.conf
======================

.. note::

   The osh-encrypt-rsync script is called by cron and is responsible for encrypting
   and optionally pushing the recorded ``ttyrec`` files to a distant server, along
   with the user logs (``/home/*/*.log``) and user sqlite files (``/home/*/*.sqlite``).
   The global log and sqlite files are also handled (located in ``/home/logkeeper/``).
   Note that logs sent through syslog are NOT managed by this script.

.. warning::

   If left unconfigured, this script won't do anything, and the recorded ``ttyrec`` files,
   along with the log and sqlite files won't be encrypted or moved out from the server.
   This might not be a problem for low-traffic bastions or if you have plenty of storage available, though.

Option List
===========

Logging options
---------------

These options configure the way the script logs its actions

- `logfile`_
- `syslog_facility`_
- `verbose`_

Encryption and signing options
------------------------------

These options configure how the script uses GPG to encrypt and sign the ttyrec files

- `signing_key`_
- `signing_key_passphrase`_
- `recipients`_
- `encrypt_and_move_to_directory`_
- `encrypt_and_move_ttyrec_delay_days`_
- `encrypt_and_move_user_logs_delay_days`_
- `encrypt_and_move_user_sqlites_delay_days`_

Push files to a remote destination options
------------------------------------------

These options configure the way the script uses rsync to optionally push the encrypted files out of the server

- `rsync_destination`_
- `rsync_rsh`_
- `rsync_delay_before_remove_days`_

Option Reference
================

Logging
-------

logfile
*******

:Type: ``string, path to a file``

:Default: ``""``

File where the logs will be written to (don't forget to configure ``logrotate``!).
Note that using this configuration option, the script will directly write to the file, without using syslog.
If empty, won't log directly to any file.

syslog_facility
***************

:Type: ``string``

:Default: ``"local6"``

The syslog facility to use for logging the script output.
If set to the empty string, we'll not log through syslog at all.
If this configuration option is missing from your config file altogether,
the default value will be used (local6), which means that we'll log to syslog.

verbose
*******

:Type: ``int >= 0``

:Default: ``0``

The verbosity level of the logs produced by the script
0: normal (default)
1: log more information about what is happening
2: log debug-level information

Encryption and signing
----------------------

signing_key
***********

:Type: ``string, GPG key ID in short or long format``

:Default: ``(none), setting a value is mandatory``

ID of the GPG key used to sign the ttyrec files.
The key must be in the local root keyring, check it with ``gpg --list-secret-keys``

signing_key_passphrase
**********************

:Type: ``string``

:Default: ``(none), setting a value is mandatory``

This passphrase should be able to unlock the ``signing_key`` defined above.
As a side note, please ensure this configuration file only readable by root (0640),
to protect this passphrase. As a security measure,
the script will refuse to read the configuration otherwise.

recipients
**********

:Type: ``array of array of strings, a string being a GPG key ID in short or long format``

:Default: ``(none), setting a value is mandatory``

The ttyrecs will be encrypted with those GPG keys, possibly using multi-layer GPG encryption.
Each sub-array is a layer, the first sub-array being the first encryption layer (which is also the last one for decryption)
To completely decrypt a ttyrec, one would need at least one key of each layer.
To encrypt only to a single layer and to only one key, simply use [ [ "KEYID" ] ].
To encrypt to a single layer but with 3 keys being able to decrypt the ttyrec, use [ [ "KEY1", "KEY2", "KEY3" ] ], etc.
A common use of multi-layer encryption is to have the first layer composed of the auditors' GPG keys, and
the second layer composed of the sysadmins' GPG keys. During an audit, the sysadmins would get the ttyrec encrypted file,
decrypt the second encryption layer (the first for decryption), and handle the now only auditor-protected file to the auditors.
All public keys must be in the local root keyring (gpg --list-keys).
Don't forget to trust those keys "ultimately" in root's keyring, too (gpg --edit-key ID)

encrypt_and_move_to_directory
*****************************

:Type: ``string, a valid directory name``

:Default: ``"/home/.encrypt"``

After encryption (and compression), move ttyrec, user sqlite and user log files to subdirs of this directory.
It'll be created if it doesn't exist yet.
You may want this directory to be the mount point of a remote filer, if you wish.
If you change this, it's probably a good idea to ensure that the path is excluded from the
master/slave synchronization, in ``/etc/bastion/osh-sync-watcher.rsyncfilter``.
This is already the case for the default value.

encrypt_and_move_ttyrec_delay_days
**********************************

:Type: ``int > 0, or -1``

:Default: ``14``

Don't touch ttyrec files that have a modification time more recent than this amount of days.
The files won't be encrypted nor moved yet, and will still be readable by the ``selfPlaySession`` command.
You can set this to a (possibly) much higher value, the only limit is the amount of disk space you have.
If set to -1, the ttyrec files will never get encrypted or moved by this script.
The eligible files will be encrypted and moved to ``encrypt_and_move_to_directory``.
NOTE: The old name of this option is `encrypt_and_move_delay_days`.
If it is found in your configuration file and `encrypt_and_move_ttyrec_delay_days` is not,
then the value of `encrypt_and_move_delay_days` will be used instead of the default.

encrypt_and_move_user_logs_delay_days
*************************************

:Type: ``int >= 31, or -1``

:Default: ``31``

Don't touch user log files (``/home/*/*.log``) that have been modified more recently than this amount of days.
The bare minimum is 31 days, to ensure we're not moving a current-month file.
You can set this to a (possibly) much higher value, the only limit is the amount of disk space you have.
If set to -1, the user log files will never get encrypted or moved by this script.
The eligible files will be encrypted and moved to ``encrypt_and_move_to_directory``.

encrypt_and_move_user_sqlites_delay_days
****************************************

:Type: ``int >= 31, or -1``

:Default: ``31``

Don't touch user sqlite files (``/home/*/*.sqlite``) that have been modified more recently than this amount of days.
The files won't be encrypted nor moved yet, and will still be usable by the ``selfListSessions`` command.
The bare minimum is 31 days, to ensure we're not moving a current-month file.
You can set this to a (possibly) much higher value, the only limit is the amount of disk space you have.
If set to -1, the user sqlite files will never get encrypted or moved by this script.
The eligible files will be encrypted and moved to ``encrypt_and_move_to_directory``.

Push files to a remote destination
----------------------------------

rsync_destination
*****************

:Type: ``string``

:Default: ``""``

:Example: ``"user@remotebackup.example.org:/remote/dir"``

The value of this option will be passed to ``rsync`` as the destination.
Note that the source of the rsync is already configured above, as the ``encrypt_and_move_to_directory``.
We only rsync the files that have already been encrypted and moved there.
If this option is empty, this will **disable** ``rsync``, meaning that the ttyrec files will be encrypted,
but not moved out of the server. In other words, the files will pile up in ``encrypt_and_move_to_directory``,
which can be pretty okay in you have enough disk space.

rsync_rsh
*********

:Type: ``string``

:Default: ``""``

:Example: ``"ssh -p 222 -i /root/.ssh/id_ed25519_backup"``

The value of this option will be passed to ``rsync``'s ``--rsh`` option.
This is useful to specify an SSH key or an alternate SSH port for example.
This option is ignored when ``rsync`` is disabled (i.e. when ``rsync_destination`` is empty).

rsync_delay_before_remove_days
******************************

:Type: ``int >= 0, or -1``

:Default: ``0``

After encryption/compression, and successful rsync of ``encrypt_and_move_to_directory`` to remote,
wait for this amount of days before removing the encrypted/compressed files locally.
Specify 0 to remove the files as soon as they're transferred.
This option is ignored when ``rsync`` is disabled (i.e. when ``rsync_destination`` is empty).
Note that if rsync is enabled (see ``rsync_destination`` above), we'll always sync the files present in
``encrypt_and_move_to_directory`` as soon as we can, to ensure limitation of logs data loss in case of
catastrophic failure of the server. The ``rsync_delay_before_remove_days`` option configures the number
of days after we remove the files locally, but note that these have already been transferred remotely
as soon as they were present in ``encrypt_and_move_to_directory``.
To rsync the files remotely but never delete them locally, set this to -1.

