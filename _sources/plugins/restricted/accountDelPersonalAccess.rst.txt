=========================
accountDelPersonalAccess
=========================

Remove a personal server access from an account
===============================================


.. admonition:: usage
   :class: cmdusage

   --osh accountDelPersonalAccess --account ACCOUNT --host HOST --user USER --port PORT [OPTIONS]

.. program:: accountDelPersonalAccess


.. option:: --account

   Bastion account to remove access from

.. option:: --host HOST|IP|SUBNET

   Host(s) to remove access from, either a HOST which will be resolved to an IP immediately,

                             or an IP, or a whole subnet using the PREFIX/SIZE notation
  --user USER|PATTERN|*    Specify which remote user was allowed to connect as.
                             Globbing characters '*' and '?' are supported, so you can specify a pattern
                             that will be matched against the actual remote user name.
                             If any user was allowed, use '--user *' (you might need to escape '*' from your shell)
  --port PORT|*            Remote port that was allowed to connect to
                             If any port was allowed, use '--port *' (you might need to escape '*' from your shell)
.. option:: --protocol PROTO

   Specify that a special protocol allowance should be removed from this HOST:PORT tuple, note that you

                              must not specify --user in that case.
                              PROTO must be one of:
                              scpupload    allow SCP upload, you--bastion-->server
                              scpdownload  allow SCP download, you<--bastion--server
                              sftp         allow usage of the SFTP subsystem, through the bastion
                              rsync        allow usage of rsync, through the bastion
