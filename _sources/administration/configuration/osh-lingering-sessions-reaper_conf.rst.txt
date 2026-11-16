==================================
osh-lingering-sessions-reaper.conf
==================================

 .. note::

    This script is called by cron and is responsible for terminating
    lingering sessions that no longer have any tty attached nor parent PID,
    and have been running for some time.

Option List
===========

Logging & activation options
----------------------------

Script logging configuration and script activation

- `LOGFILE`_
- `LOG_FACILITY`_
- `ENABLED`_

Main options
------------

These options govern the behavior of the script

- `MAX_AGE`_

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

Main
----

MAX_AGE
*******

:Type: ``int >= 0``

:Default: ``86400``

The minimum number of seconds a session must have been opened before
being considered as possibly a lingering orphan session.
Still alive sessions, even older than MAX_AGE seconds, will be kept.

