=========
Upgrading
=========

General upgrade instructions
============================

- Update the code, if you're using ``git``, you can checkout the latest tag:

.. code-block:: shell

    ( umask 0022 && cd /opt/bastion && git fetch && git checkout $(git tag | tail -1) )

- Run the install script in upgrade mode, so it can make adjustments to the system needed for the new version:

.. code-block:: shell

    /opt/bastion/bin/admin/install --upgrade

Note that if you're using a infrastructure automation tool such as Puppet, Ansible, Chef, and don't want the update script to touch some files that you manage yourself, you can use ``--upgrade-managed``. See the ``--help`` for a more fine-grained upgrade path if needed.

- Install any missing newly needed system package:

.. code-block:: shell

    /opt/bastion/bin/admin/packages-check.sh

- Check the configuration for new parameters or options you may want to adjust

.. code-block:: shell

    for f in /opt/bastion/etc/bastion/*.dist; do vimdiff $f /etc/bastion/$(basename $f .dist); done

- If you have some power-users and you want them to have access to any new restricted plugin this new version might have, you can run for those accounts:

.. code-block:: shell

    /opt/bastion/bin/admin/grant-all-restricted-commands-to.sh ACCOUNTNAME

Note that this is done automatically for bastion admins.

Version-specific upgrade instructions
=====================================

v3.00.00
********

Initial public version, no specific upgrade instructions
