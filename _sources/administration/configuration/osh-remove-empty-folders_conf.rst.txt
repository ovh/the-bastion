=============================
osh-remove-empty-folders.conf
=============================

 .. note::

    This script is called by cron and is responsible for getting rid of empty
    folders in the ``ttyrec/`` directory of users homes, which may contain a
    high amount of empty folders for busy users connecting to a lot of
    different servers, as we create one folder per destination IP.
    Of course, this script will only remove empty folders, never actual files.

Option List
===========

Logging & activation options
----------------------------

Script logging configuration and script activation

- `LOGFILE`_
- `LOG_FACILITY`_

Behavior options
----------------

These options govern the behavior of the script

- `ENABLED`_
- `MTIME_DAYS`_

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

Behavior
--------

ENABLED
*******

:Type: ``0 or 1``

:Default: ``1``

If set to 1, the script is enabled and will attempt to garbage-collect empty directories located
in ``/home/*/ttyrec``. If set to anything else, the script is considered disabled and will not run.

MTIME_DAYS
**********

:Type: ``int, >= 0``

:Default: ``1``

The amount of days the empty folder must have been empty before considering a removal. You probably
don't need to change the default value, unless you want to ensure that a given folder has not been
used since some time before removing it (this has no impact as folders are re-created as needed).

