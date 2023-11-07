=====================================
Welcome to The Bastion documentation!
=====================================

.. warning::

   This documentation is in a WIP status, some edges might be rough!

Wait, what's a bastion exactly? (in 140-ish characters)
=======================================================

A so-called **bastion** is a machine used as a single entry point by operational teams (such as sysadmins, developers, devops, database admins, etc.) to securely connect to other machines of an infrastructure, usually using `ssh`.

The bastion provides mechanisms for *authentication*, *authorization*, *traceability* and *auditability* for the whole infrastructure.

Just yet another SSH relayhost/jumphost/gateway?
************************************************

No, The Bastion is an entirely different beast.

The key technical difference between those and The Bastion is that it strictly stands between you and the remote server, operating a protocol break in the process, which enables unique features such as tty recording, proper access auditability, builtin access and groups management commands, delegation of responsibilities all the way through, etc.

Advanced uses even include doing other things than just SSHing to a remote server.

Those wouldn't be possible with a "simple" jumphost. More technical details on the difference :ref:`here <faq_jumphost>`.

OK, tell me more!
=================

This documentation is organized in several sections. The first one is a **PRESENTATION** of the main functionalities, principles, and use cases of the bastion.

The second section explains the **INSTALLATION** procedure, including how to set up a quick playground using Docker if you want to get your hands dirty quickly.

The third section focuses on the **USAGE** of the bastion, from the perspective of the different roles, such as bastion users, group owners, bastion admins, etc.

The fourth section is about the proper **ADMINISTRATION** of the bastion itself. If you're about to be the person in charge of managing the bastion for your company, you want to read that one carefully!

The fifth section is about **DEVELOPMENT** and how to write code for the bastion. If you'd like to contribute, this is the section to read!

The sixth section is the complete reference of all the **PLUGINS** that are the commands used to interact with the bastion accounts, groups, accesses, credentials, and more.

The unavoidable and iconic FAQ is also available under the **PRESENTATION** section.

.. toctree::
   :maxdepth: 2
   :caption: Presentation

   presentation/principles
   presentation/features
   presentation/security
   faq

.. toctree::
   :maxdepth: 2
   :caption: Installation

   installation/basic
   installation/advanced
   installation/upgrading
   installation/docker
   installation/restoring_from_backup

.. toctree::
   :maxdepth: 2
   :caption: Usage

   using/basics/index
   using/piv
   using/sftp_scp
   using/http_proxy
   using/api
   using/specific_ssh_clients_tutorials/index

.. toctree::
   :maxdepth: 2
   :caption: Administration

   administration/configuration/index
   administration/logs
   administration/mfa
   administration/security_advisories

.. toctree::
   :maxdepth: 2
   :caption: Development

   development/setup
   development/tests

.. _plugins:

.. toctree::
   :maxdepth: 2
   :caption: Plugins

   plugins/admin/index.rst
   plugins/group-aclkeeper/index.rst
   plugins/group-gatekeeper/index.rst
   plugins/group-owner/index.rst
   plugins/open/index.rst
   plugins/restricted/index.rst

Indices and tables
==================

* :ref:`genindex`
* :ref:`search`
