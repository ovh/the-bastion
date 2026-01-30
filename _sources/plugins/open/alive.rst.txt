======
alive
======

Ping a host and exit as soon as it answers
==========================================


This command can be used to monitor a host that is expected to go back online soon.
Note that if you want to ssh to it afterwards, you can simply use the ``--wait`` main option.

.. admonition:: usage
   :class: cmdusage

   --osh alive [--host] HOSTNAME

.. program:: alive


.. option:: --host HOSTNAME

   hostname or IP to ping

