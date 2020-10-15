===
nc
===

Check whether a remote TCP port is open
=======================================


.. admonition:: usage
   :class: cmdusage

   --osh nc [--host] HOST [--port] PORT [-w TIMEOUT]

.. program:: nc


.. option:: --host HOST

   Host or IP to attempt to connect to

.. option:: --port PORT

   TCP port to attempt to connect to

.. option:: -w SECONDS 

   Timeout in seconds (default: 3)



Note that this is not a full-featured ``netcat``, we just test whether a remote port is open. There is no way to exchange data using this command.
