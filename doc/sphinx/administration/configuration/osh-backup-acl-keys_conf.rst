==================================
osh-backup-acl-keys.conf reference
==================================

.. note::

   The osh-backup-acl-keys script is called by cron and is responsible for backing up
   the bastion configuration, users & groups lists, credentials, and everything needed
   to be able to restore a functioning bastion from scratch.

.. warning::

   If left unconfigured, this script won't do anything, and you won't have backups,
   unless this task is handled by some other external system.

Option List
===========

Logging options
---------------

These options configure the way the script logs its actions

- `LOGFILE`_
- `LOG_FACILITY`_

Backup policy options
---------------------

These options configure the backup policy to apply

- `DESTDIR`_
- `DAYSTOKEEP`_
- `GPGKEYS`_

Remote backup options
---------------------

These options configure how the script should push the encrypted backups to a remote system

- `PUSH_REMOTE`_
- `PUSH_OPTIONS`_

Option Reference
================

Logging
-------

LOGFILE
*******

:Type: ``string, path to a file``

:Default: ``""``

File where the logs will be written to (don't forget to configure ``logrotate``!). Note that using this configuration option, the script will directly write to the file, without using syslog. If empty, won't log directly to any file.

LOG_FACILITY
************

:Type: ``string``

:Default: ``"local6"``

The syslog facility to use for logging the script output. If set to the empty string, we'll not log through syslog at all. If this configuration option is missing from your config file altogether, the default value will be used (local6), which means that we'll log to syslog.

Backup policy
-------------

DESTDIR
*******

:Type: ``path to a folder``

:Default: ``""``

:Example: ``"/root/backups"``

Folder where to put the backup artefacts (``.tar.gz`` files). This folder will be created if needed. If empty or omitted, the script won't run: this option is mandatory.

DAYSTOKEEP
**********

:Type: ``int > 0``

:Default: ``90``

Number of days to keep the old backups on the filesystem before deleting them.

GPGKEYS
*******

:Type: ``string, space-separated list of GPG keys IDs``

:Default: ``""``

:Example: ``"41FDB9C7 DA97EFD1 339483FF"``

List of public GPG keys to encrypt to (see ``gpg --list-keys``), these must be separated by spaces. Note that if this option is empty or omitted, backup artefacts will NOT be encrypted!

Remote backup
-------------

PUSH_REMOTE
***********

:Type: ``string``

:Default: ``""``

:Example: ``"push@1.2.3.4:~/backup/"``

The ``scp`` remote host push backups to. If empty or missing, won't push backups. This will also be the case if the ``GPGKEYS`` option above is empty or missing, because we will never push unencrypted backups. Don't forget to put a trailing ``/`` (except if you want to push to the remote ``$HOME``, in which case ending with a simple ``:`` works, as per standard ``scp``).

PUSH_OPTIONS
************

:Type: ``string``

:Default: ``""``

:Example: ``"-i $HOME/.ssh/id_backup"``

Additional options to pass to ``scp``, if needed.

