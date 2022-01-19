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

Note that if you're using an infrastructure automation tool such as Puppet, Ansible, Chef,
and don't want the update script to touch some files that you manage yourself,
you can use ``--managed-upgrade`` instead of ``--upgrade``.
See the ``--help`` for a more fine-grained upgrade path if needed.

Version-specific upgrade instructions
=====================================

v3.08.01 - 2022/01/19
*********************

The upgrade path from the preceding version is straightforward, however you might want to know that there is
a new satellite script: ``osh-remove-empty-folders.sh``, run by cron and enabled by default,
whose job is to garbage-collect empty folders that may be piling up in busy users' homes,
under their ``ttyrec`` folder.

You can find more information in `the documentation 
<https://ovh.github.io/the-bastion/administration/configuration/osh-remove-empty-folders_conf.html>`_, the script
is enabled by default because it can do no harm.

v3.08.00 - 2022/01/04
*********************

This version replaces usage of GnuPG 1.x by GnuPG 2.x for the backup/encrypt/rsync satellite scripts, namely:

- ``bin/cron/osh-backup-acl-keys.sh``
- ``bin/cron/osh-encrypt-rsync.pl``

These are optionally used to help you backup your system, and encrypt/move out ttyrec files.
If you don't use these scripts and never configured them as seen in the :doc:`/installation/advanced` section,
then you have nothing to do.

The script ``setup-gpg.sh`` will now create an Ed25519 key by default, instead of a 4K RSA key.
This type of key is usually seen as more secure (elliptic curve cryptography), and faster than RSA keys.
If you have already configured your system, then the above scripts will continue using the previously generated
RSA key, unless you generate a new key and reference it in the scripts configuration files.

If you want to generate new Ed25519 keys instead of using your preexisting RSA keys, you may proceed
to the :ref:`Ed25519 section below <upgrading_ed25519>`.

Otherwise, on the first run, GnuPG 2.x should transparently import the 1.x keyring.
To verify that it worked correctly, you may want to try:

.. code-block:: shell

   /opt/bastion/bin/cron/osh-encrypt-rsync.pl --config-test

If you see *Config test passed*, and you're okay using your preexisting 4K RSA key, then you may stop here.

If the test fails, and you know that before upgrading, this script worked correctly, then you might need to
manually import the GnuPG 1.x public keys:

.. code-block:: shell

   gpg1 --armor --export | gpg --import

Then, try again:

.. code-block:: shell

   /opt/bastion/bin/cron/osh-encrypt-rsync.pl --config-test

If you don't see any errors here, you're done.

If you still see errors, then you might need to manually import the private key:

.. code-block:: shell

   gpg1 --armor --export-secret-keys | gpg --import

You may get asked for a password for the bastion secret key, which should be found in
``/etc/bastion/osh-encrypt-rsync.conf.d/50-gpg-bastion-key.conf`` if you previously used the script to generate it.

A last config test should now work:

.. code-block:: shell

   /opt/bastion/bin/cron/osh-encrypt-rsync.pl --config-test

If you prefer to generate Ed25519 keys instead, then you can proceed to the next section.

.. _upgrading_ed25519:

Ed25519
-------

If you want to replace your RSA key by an Ed25519 one (which is optional), then you don't need to import the
GnuPG 1.x keys as outlined above but you may run instead:

.. code-block:: shell

   /opt/bastion/bin/admin/setup-gpg.sh generate --overwrite

Once the key has been generated, you may also want to generate a new admin key, by following this
:ref:`section <installation/advanced:Generating and importing the admins GPG key>` of the Advanced Installation documentation.
Note that you'll need to use the ``--overwrite`` parameter when importing:

.. code-block:: shell

   /opt/bastion/bin/admin/setup-gpg.sh import --overwrite

Once done, a config test should work:

.. code-block:: shell

   /opt/bastion/bin/cron/osh-encrypt-rsync.pl --config-test

v3.07.00 - 2021/12/13
*********************

No specific upgrade instructions.

v3.06.00 - 2021/10/15
*********************

The ``sshd_config`` templates have been modified to reflect the changes needed to use
the new ``--pubkey-auth-optional`` parameter of :doc:`/plugins/restricted/accountModify`
(`#237 <https://github.com/ovh/the-bastion/pull/237>`_).
If you want to use it, don't forget to review your ``sshd_config`` and modify it accordingly:
the templates can be found in ``etc/ssh/``.

Note that misconfiguring `sshd` and `pam` together could at worst entirely disable sshd authentication.
If you have a custom configuration, different from the templates we provide, please double-check
that such corner case is not possible by design.
A good way to ensure this is to review the `pam` configuration and ensure that there is no execution
flow that pushes a `pam_success` value to the pam stack without requiring any form of authentication.

v3.05.01 - 2021/09/22
*********************

In the configuration of the ``osh-backup-acl-keys`` script, a signing key can now be specified so that the backups
are signed by the bastion key in addition to being encrypted to the admin(s) key(s).
By default, the behaviour is the same as before: encrypt but don't sign.

v3.05.00 - 2021/09/14
*********************

The maximum length of accounts is now 28 characters up from 18 characters previously.
If you have setup a HA cluster with several bastion instances synchronized together, note that accounts longer
than 18 characters will not be deemed as valid on not-yet upgraded instances of a cluster.

v3.04.00 - 2021/07/02
*********************

The upgrade path from the preceding version is straightforward, however there are a few changes
that you might want to be aware of before hitting the upgrade button:

- Some EOL OSes have been dropped: Debian 8, Ubuntu 14.04, OpenSUSE 15.0 and 15.1.
  This means that while the software might still work, theses OSes are no longer part of the tests
  and might break in any future upgrade.

- The default logging level of the :doc:`/using/http_proxy` has been decreased. If you want to keep full requests
  and responses logging, check the :doc:`log_request_response and log_request_response_max_size
  </administration/configuration/osh-http-proxy_conf>` configuration options.

v3.03.01 - 2021/03/25
*********************

No specific upgrade instructions.

v3.03.00 - 2021/02/22
*********************

No specific upgrade instructions.

v3.02.00 - 2021/02/01
*********************

The upgrade path from the preceding version is straightforward, however there are a few changes
that you might want to be aware of before hitting the upgrade button:

The main configuration file now supports proper booleans
--------------------------------------------------------

For a lot of configuration options, previously you would specify "1" to enable a feature, and "0" to disable it.
This has been changed to use proper *true* and *false* json values in :file:`/etc/bastion/bastion.conf`.
Of course, backward compatibility with "0" and "1" will always be kept, so no breakage is to be expected
for this version or future ones even if you keep your configuration untouched.

Logs have been enhanced
-----------------------

All connections and plugin executions emit two logs, an *open* and a *close* log.
We now add all the details of the connection to the *close* logs, those that were previously only available
in the corresponding *open* log. This way, it is no longer required to correlate both logs with their uniqid
to have all the data: the *close* log should suffice.
The *open* log is still there if for some reason the *close* log can't be emitted (kill -9, system crash, etc.),
or if the *open* and the *close* log are several hours, days or months appart.

An additional field **duration** has been added to the *close* logs,
this represents the number of seconds (with millisecond precision) the connection lasted.

Two new fields **globalsql** and **accountsql** have been added to the *open*-type logs.
These will contain either `ok` if we successfully logged to the corresponding log database,
`no` if it is disabled, or `error $aDetailedMessage` if we got an error trying to insert the row.
The *close*-type log also has the new **accountsql_close** field, but misses the **globalsql_close** field as
we never update the global database on this event.
On the *close* log, we can also have the value **missing**, indicating that we couldn't update the access log row
in the database, as the corresponding *open* log couldn't insert it.

The **ttyrecsize** log field for the *close*-type logs has been removed, as it was never completely implemented,
and contains bogus data if ttyrec log rotation occurs. It has also been removed from the sqlite log databases.

The *open* and *close* events are now pushed to our own log files, in addition to syslog, if logging to those files
is enabled (see :ref:`enableGlobalAccessLog` and :ref:`enableAccountAccessLog`),
previously the *close* events were only pushed to syslog.

The :file:`/home/osh.log` file is no longer used for :ref:`enableGlobalAccessLog`, the global log
is instead written to :file:`/home/logkeeper/global-log-YYYYMM.log`.

The global sql file, enabled with :ref:`enableGlobalSqlLog`, is now split by year-month instead of by year,
to :file:`/home/logkeeper/global-log-YYYYMM.sqlite`.

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

A new bastion.conf option was introduced: *interactiveModeByDefault*. If not present in your config file,
its value defaults to 1 (true), which changes the behavior of The Bastion when a user connects
without specifying any command.
When this happens, it'll now display the help then drop the user into interactive mode (if this mode is enabled),
instead of displaying the help and aborting with an error message.
Set it to 0 (false) if you want to keep the previous behavior.

An SELinux module has been added in this version, to ensure TOTP MFA works correctly under systems where SELinux
is on enforcing mode. This module will be installed automatically whenever SELinux is detected on the system.
If you don't want to use this module, specify `--no-install-selinux-module` on your `/opt/bastion/bin/admin/install`
upgrade call (please refer to the generic upgrade instructions for more details).

v3.00.02 - 2020/11/16
*********************

No specific upgrade instructions.

v3.00.01 - 2020/11/06
*********************

If you previously installed ``ttyrec`` using the now deprecated ``build-and-install-ttyrec.sh`` script,
you might want to know that since this version, the script has been replaced by ``install-ttyrec.sh``,
which no longer builds in-place, but prefers downloading and installing prebuild ``rpm`` or ``deb`` packages.

If you previously built and installed ``ttyrec`` manually, and want to use the new packages instead,
you might want to manually uninstall your previously built ttyrec program (remove the binaries that were installed
in ``/usr/local/bin``), and call ``install-ttyrec.sh -a`` to download and install the proper package instead.

This is not mandatory and doesn't change anything from the software point of view.

v3.00.00 - 2020/10/30
*********************

Initial public version, no specific upgrade instructions.
