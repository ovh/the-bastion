=================================
osh-cleanup-guest-key-access.conf
=================================

 .. note::

   This script is called by cron and is responsible for cleaning up dangling
   accesses to group keys for group guests that no longer have access to any
   server of the group. This happens when the last access a guest have on a
   group has a TTL, and this TTL expires.
   This is a basic background task of The Bastion, hence there is not much
   to configure. You can still disable this script below, if needs be.

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

