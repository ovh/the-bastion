=========================
osh-orphaned-homedir.conf
=========================

 .. note::

    This script is called by cron and is responsible for clearing up
    orphaned home directories on secondary bastions.
    Indeed, once the user has been deleted, a few files may remain,
    such as logs, so this script handles the proper archiving
    of these sparse files, before removing the orphaned home directory.

Option List
===========

Logging & activation options
----------------------------

Script logging configuration and script activation

- `LOGFILE`_
- `LOG_FACILITY`_
- `ENABLED`_

Option Reference
================

Logging & activation
--------------------

LOGFILE
*******

:Type: ``string, path to a file``

:Default: ``""``

File where the logs will be written to (don't forget to configure ``logrotate``!).
Note that using this configuration option, the script will directly write to the file, without using syslog.
If empty, won't log directly to any file.

LOG_FACILITY
************

:Type: ``string``

:Default: ``"local6"``

The syslog facility to use for logging the script output.
If set to the empty string, we'll not log through syslog at all.
If this configuration option is missing from your config file altogether,
the default value will be used (local6), which means that we'll log to syslog.

ENABLED
*******

:Type: ``0 or 1``

:Default: ``1``

If set to 1, the script is enabled and will run when started by crond.

