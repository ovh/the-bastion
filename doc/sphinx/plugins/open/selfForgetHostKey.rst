==================
selfForgetHostKey
==================

Forget a known host key from your bastion account
=================================================


.. admonition:: usage
   :class: cmdusage

   --osh selfForgetHostKey [--host HOST] [--port PORT]

.. program:: selfForgetHostKey


.. option:: --host HOST

   Host to remove from the known_hosts file

.. option:: --port PORT

   Port to look for in the known_hosts file (default: 22)


This command is useful to remove the man-in-the-middle warning when a key has changed,
however please verify that the host key change is legit before using this command.
The warning SSH gives is there for a reason.


