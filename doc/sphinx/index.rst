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

This documentation is organized in several sections. The first one is a :doc:`presentation<presentation/index>` of the main functionalities, principles, and use cases of the bastion.

The second section explains how to :doc:`get the bastion running<installation/index>`, including how to set up a quick playground using Docker if you want to get your hands dirty quickly.

The third section focuses on :doc:`how to use<using/index>` the bastion, from the perspective of the different roles, such as bastion users, group owners, bastion admins, etc.

.. toctree::
   :maxdepth: 2
   :caption: Table of contents

   presentation/index
   installation/index
   using/index
   plugins/index
   faq

Indices and tables
==================

* :ref:`genindex`
* :ref:`search`
