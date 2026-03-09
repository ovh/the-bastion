===================
osh-sync-watcher.sh
===================

 .. note::

    This daemon is responsible for ensuring secondary bastions
    are synced up to their primary at all times.
    If you don't have such HA setup, you can ignore this config file.
    For more information, refer to
    :ref:`installation/advanced:clustering (high availability)`.

Option List
===========

Logging options
---------------

These options configure the way the script logs its actions

- `logdir`_
- `syslog`_

Daemon setup options
--------------------

These options configure whether the synchronization daemon is enabled

- `enabled`_
- `timeout`_

Remote synchronization options
------------------------------

These options configure how the primary bastion should push its configuration to the secondaries

- `rshcmd`_
- `remoteuser`_
- `remotehostlist`_

Option Reference
================

Logging
-------

logdir
******

:Type: ``string``

:Default: ``""``

Directory where the logs will be written to. Note that using this configuration option, the script will directly write to a file, without using syslog. If empty, won't log directly to a file.

syslog
******

:Type: ``string``

:Default: ``"local6"``

The syslog facility to use for logging the script output. If set to the empty string, we'll not log through syslog at all. If this configuration option is missing from your config file altogether, the default value will be used (local6), which means that we'll log to syslog.

Daemon setup
------------

enabled
*******

:Type: ``int``

:Default: ``0``

If set to anything else than ``1``, the daemon will refuse to start (e.g. you don't have secondary bastions). You can set this to ``1`` when you've configured and tested the primary/secondaries setup.

timeout
*******

:Type: ``int > 0``

:Default: ``120``

The maximum delay, in seconds, after which we'll forcefully synchronize our data to the secondaries, even if no change was detected.

Remote synchronization
----------------------

rshcmd
******

:Type: ``string``

:Default: ``""``

:Example: ``"ssh -q -i /root/.ssh/id_master2slave -o StrictHostKeyChecking=accept-new"``

This value will be passed as the ``--rsh`` parameter of ``rsync`` (don't use ``-p`` to specify the port here, use the ``remotehostlist`` config below instead), this can be used to specify which SSH key to use, for example. NOTE THAT THIS OPTION IS MANDATORY (if you don't have anything to specify here, you can just say ``ssh``). If you followed the standard installation procedure, the "example" value specified below will work.

remoteuser
**********

:Type: ``string``

:Default: ``"bastionsync"``

The remote user to connect as, using ``ssh`` while rsyncing to secondaries. You probably don't need to change this.

remotehostlist
**************

:Type: ``space-separated list of strings, each string being either 'ip' or 'ip:port'``

:Default: ``""``

:Example: ``"192.0.2.17 192.0.2.12:2244"``

The list of the secondary bastions to push our data to. If this list is empty, the daemon won't do anything.

