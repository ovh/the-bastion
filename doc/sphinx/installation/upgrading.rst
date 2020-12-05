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

v3.01.01
********

No specific upgrade instructions.

v3.01.00
********

A new bastion.conf option was introduced: *interactiveModeByDefault*. If not present in your config file, its value defaults to 1 (true), which changes the behavior of The Bastion when a user connects without specifying any command. When this happens, it'll now display the help then drop the user into interactive mode (if this mode is enabled), instead of displaying the help and aborting with an error message. Set it to 0 (false) if you want to keep the previous behavior.

An SELinux module has been added in this version, to ensure TOTP MFA works correctly under systems where SELinux is on enforcing mode. This module will be installed automatically whenever SELinux is detected on the system. If you don't want to use this module, specify `--no-install-selinux-module` on your `/opt/bastion/bin/admin/install` upgrade call (please refer to the generic upgrade instructions for more details).

v3.00.02
********

No specific upgrade instructions.

v3.00.01
********

If you previously installed ``ttyrec`` using the now deprecated ``build-and-install-ttyrec.sh`` script, you might want to know that since this version, the script has been replaced by ``install-ttyrec.sh``, which no longer builds in-place, but prefers downloading and installing prebuild ``rpm`` or ``deb`` packages.

If you previously built and installed ``ttyrec`` manually, and want to use the new packages instead, you might want to manually uninstall your previously built ttyrec program (remove the binaries that were installed in ``/usr/local/bin``), and call ``install-ttyrec.sh -a`` to download and install the proper package instead.

This is not mandatory and doesn't change anything from the software point of view.


v3.00.00
********

Initial public version, no specific upgrade instructions.
