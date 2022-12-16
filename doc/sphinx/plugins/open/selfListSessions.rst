=================
selfListSessions
=================

List the few past sessions of your account
==========================================


.. admonition:: usage
   :class: cmdusage

   --osh selfListSessions [OPTIONS]

.. program:: selfListSessions


.. option:: --detailed

   Display more information about each session

.. option:: --limit LIMIT

   Limit to LIMIT results

.. option:: --id ID

   Only sessions having this ID

.. option:: --type TYPE

   Only sessions of specified type (ssh, osh, ...)

.. option:: --allowed

   Only sessions that have been allowed by the bastion

.. option:: --denied

   Only sessions that have been denied by the bastion

.. option:: --after WHEN

   Only sessions that started after WHEN,

                           WHEN can be a TIMESTAMP, or YYYY-MM-DD[@HH:MM:SS]
.. option:: --before WHEN

   Only sessions that started before WHEN,

                           WHEN can be a TIMESTAMP, or YYYY-MM-DD[@HH:MM:SS]
.. option:: --host HOST

   Only sessions connecting to remote HOST

.. option:: --to-port PORT

   Only sessions connecting to remote PORT

.. option:: --user USER

   Only sessions connecting using remote USER

.. option:: --via HOST

   Only sessions that connected through bastion IP HOST

.. option:: --via-port PORT

   Only sessions that connected through bastion PORT


Note that only the sessions that happened on this precise bastion instance will be shown,
not the sessions from its possible cluster siblings.
