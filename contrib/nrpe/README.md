NRPE Probes
===========

A few NRPE probes are available in the ``probes/`` subdirectory.

Some of these probes might need to have elevated rights, an example of sudoers file is included.

You might want to also use the nice ``check_logfiles`` probe, courtesy of
Consol Labs (https://labs.consol.de/nagios/check_logfiles/index.html), to ensure
that the cron scripts behave correctly and that no error is happening during the backup process,
the encrypt & rsync process, the HA synchronization daemon, etc.

The configuration of the ``check_logfiles`` probe can be found in ``etc/nagios/plugins.d``.

The bastion-side NRPE daemon configuration for these probes can be found in the ``etc/nagios/nrpe.d``.
