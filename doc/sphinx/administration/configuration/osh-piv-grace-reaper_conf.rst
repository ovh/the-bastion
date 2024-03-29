=========================
osh-piv-grace-reaper.conf
=========================

 .. note::

   This script is called by cron and is responsible for removing temporary
   grace periods on PIV policies, once they expire. If you don't use PIV keys,
   this script won't do anything (see :doc:`/using/piv`).

Option List
===========

Logging & activation options
----------------------------

Script logging configuration and script activation

- `syslog_facility`_
- `enabled`_

Option Reference
================

Logging & activation
--------------------

syslog_facility
***************

:Type: ``string``

:Default: ``local6``

The syslog facility to use for logging the script output.
If set to the empty string, we'll not log through syslog at all.
If this configuration option is missing from your config file altogether,
the default value will be used (local6), which means that we'll log to syslog.

enabled
*******

:Type: ``bool``

:Default: ``true``

If not set to `true` (or a true value), the script will not run.

