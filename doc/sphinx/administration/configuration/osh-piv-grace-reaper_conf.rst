===================================
osh-piv-grace-reaper.conf reference
===================================

.. note::

   The osh-piv-grace-reaper script is called by cron and is responsible for removing
   temporary grace periods on PIV policies, once they expire. If you don't use PIV keys,
   this script won't do anything (see :doc:`/using/piv`).

Option List
===========

Logging options
---------------

These options configure the way the script logs its actions

- `SyslogFacility`_

Option Reference
================

Logging
-------

SyslogFacility
**************

:Type: ``string``

:Default: ``local6``

The syslog facility to use for logging the script output. If set to the empty string, we'll not log through syslog at all. If this configuration option is missing from your config file altogether, the default value will be used (local6), which means that we'll log to syslog.

