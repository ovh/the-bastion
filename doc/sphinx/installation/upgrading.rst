=========
Upgrading
=========

General upgrade instructions
============================

- First, check below if there are specific upgrade instructions for your version.

- When you're ready, update the code, if you're using ``git``, you can checkout the latest tag:

.. code-block:: shell

    ( umask 0022 && cd /opt/bastion && git fetch && git checkout $(git tag | tail -1) )

- Run the install script in upgrade mode, so it can make adjustments to the system needed for the new version:

.. code-block:: shell

    /opt/bastion/bin/admin/install --upgrade

Note that if you're using an infrastructure automation tool such as Puppet, Ansible, Chef, and don't want the update script to touch some files that you manage yourself, you can use ``--managed-upgrade`` instead of ``--upgrade``. See the ``--help`` for a more fine-grained upgrade path if needed.

Version-specific upgrade instructions
=====================================

v3.02.00 - 2021/02/01
*********************

The upgrade path from the preceding version is straightforward, however there are a few changes that you might want to be aware of before hitting the upgrade button:

The main configuration file now supports proper booleans
--------------------------------------------------------

For a lot of configuration options, previously you would specify "1" to enable a feature, and "0" to disable it. This has been changed to use proper *true* and *false* json values in :file:`/etc/bastion/bastion.conf`. Of course, backward compatibility with "0" and "1" will always be kept, so no breakage is to be expected for this version or future ones even if you keep your configuration untouched.

Logs have been enhanced
-----------------------

All connections and plugin executions emit two logs, an *open* and a *close* log. We now add all the details of the connection to the *close* logs, those that were previously only available in the corresponding *open* log. This way, it is no longer required to correlate both logs with their uniqid to have all the data: the *close* log should suffice. The *open* log is still there if for some reason the *close* log can't be emitted (kill -9, system crash, etc.), or if the *open* and the *close* log are several hours, days or months appart.

An additional field **duration** has been added to the *close* logs, this represents the number of seconds (with millisecond precision) the connection lasted.

Two new fields **globalsql** and **accountsql** have been added to the *open*-type logs. These will contain either `ok` if we successfully logged to the corresponding log database, `no` if it is disabled, or `error $aDetailedMessage` if we got an error trying to insert the row. The *close*-type log also has the new **accountsql_close** field, but misses the **globalsql_close** field as we never update the global database on this event. On the *close* log, we can also have the value **missing**, indicating that we couldn't update the access log row in the database, as the corresponding *open* log couldn't insert it.

The **ttyrecsize** log field for the *close*-type logs has been removed, as it was never completely implemented, and contains bogus data if ttyrec log rotation occurs. It has also been removed from the sqlite log databases.

The *open* and *close* events are now pushed to our own log files, in addition to syslog, if logging to those files is enabled (see :ref:`enableGlobalAccessLog` and :ref:`enableAccountAccessLog`), previously the *close* events were only pushed to syslog.

The :file:`/home/osh.log` file is no longer used for :ref:`enableGlobalAccessLog`, the global log is instead written to :file:`/home/logkeeper/global-log-YYYYMM.log`.

The global sql file, enabled with :ref:`enableGlobalSqlLog`, is now split by year-month instead of by year, to :file:`/home/logkeeper/global-log-YYYYMM.sqlite`.

v3.01.03 - 2020/12/15
*********************

No specific upgrade instructions.

v3.01.02 - 2020/12/08
*********************

No specific upgrade instructions.

v3.01.01 - 2020/12/04
*********************

No specific upgrade instructions.

v3.01.00 - 2020/11/20
*********************

A new bastion.conf option was introduced: *interactiveModeByDefault*. If not present in your config file, its value defaults to 1 (true), which changes the behavior of The Bastion when a user connects without specifying any command. When this happens, it'll now display the help then drop the user into interactive mode (if this mode is enabled), instead of displaying the help and aborting with an error message. Set it to 0 (false) if you want to keep the previous behavior.

An SELinux module has been added in this version, to ensure TOTP MFA works correctly under systems where SELinux is on enforcing mode. This module will be installed automatically whenever SELinux is detected on the system. If you don't want to use this module, specify `--no-install-selinux-module` on your `/opt/bastion/bin/admin/install` upgrade call (please refer to the generic upgrade instructions for more details).

v3.00.02 - 2020/11/16
*********************

No specific upgrade instructions.

v3.00.01 - 2020/11/06
*********************

If you previously installed ``ttyrec`` using the now deprecated ``build-and-install-ttyrec.sh`` script, you might want to know that since this version, the script has been replaced by ``install-ttyrec.sh``, which no longer builds in-place, but prefers downloading and installing prebuild ``rpm`` or ``deb`` packages.

If you previously built and installed ``ttyrec`` manually, and want to use the new packages instead, you might want to manually uninstall your previously built ttyrec program (remove the binaries that were installed in ``/usr/local/bin``), and call ``install-ttyrec.sh -a`` to download and install the proper package instead.

This is not mandatory and doesn't change anything from the software point of view.


v3.00.00 - 2020/10/30
*********************

Initial public version, no specific upgrade instructions.
