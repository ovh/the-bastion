======
clush
======

Launch a remote command on several machines sequentially (clush-like)
=====================================================================


.. admonition:: usage
   :class: cmdusage

   --osh clush [OPTIONS] --command '"remote command"'

.. program:: clush


.. option:: --list HOSTLIST

   Comma-separated list of the hosts (hostname or IP) to run the command on

.. option:: --user USER

   Specify which remote user should we use to connect (default: BASTION_ACCOUNT)

.. option:: --port PORT

   Specify which port to connect to (default: 22)

.. option:: --step-by-step

   Pause before running the command on each host

.. option:: --no-pause-on-failure

   Don't pause if the remote command failed (returned exit code != 0)

.. option:: --no-confirm

   Skip confirmation of the host list and command

.. option:: --command '"remote cmd"'

   Command to be run on the remote hosts. If you're in a shell, quote it twice as shown.

