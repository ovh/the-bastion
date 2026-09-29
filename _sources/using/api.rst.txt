========
JSON API
========

.. contents::

Introduction
============

The Bastion has a JSON API that can be used to interact with :ref:`plugins`.

Instead of exposing a specific HTTPS port for this API, The Bastion leverages its already exposed protocol, SSH,
to expose its API through it. The rationale is:

- Avoid exposing a new port and a new protocol (HTTPS) to avoid widening the attack surface
- Leverage the pre-existing authentication and user isolation mechanisms implemented by The Bastion behind SSH

This API is implemented for all :ref:`plugins <plugins>`, and can be enabled by the ``--json*`` series of options.

.. note::

   Within this page, the ``bssh`` bastion alias we usually use through the documentation is replaced by
   explicit ``ssh`` commands, to emphasize the fact that as we're doing M2M calls,
   there would be no terminal involved, hence we shouldn't use the ``-t`` SSH option to connect to the bastion
   (as is the case with the ``bssh`` alias).

Adding either ``--json``, ``--json-pretty`` or ``--json-greppable`` to your ``--osh`` commands enable
the JSON API output. Here is an example of each one below.

Examples
========

Using --json-pretty
-------------------

Let's start with ``--json-pretty``:

.. code-block:: shell
   :emphasize-lines: 1

   ssh robot-group@bastion1.example.org -- --osh groupListServers --group mygroup --json-pretty
   ╭──ac777d06bec9───────────────────────────────────────────the-bastion-3.12.00───
   │ ▶ list of servers pertaining to the group
   ├───────────────────────────────────────────────────────────────────────────────
   │        IP PORT  USER      ACCESS-BY ADDED-BY   ADDED-AT
   │ --------- ---- ----- -------------- -------- ----------
   │ 127.1.2.3   22 (any) mygroup(group)  johndoe 2023-07-31
   │
   │ 1 accesses listed

   JSON_START
   {
      "command" : "groupListServers",
      "value" : [
         {
            "port" : "22",
            "expiry" : null,
            "forcePassword" : null,
            "forceKey" : null,
            "addedBy" : "johndoe",
            "userComment" : null,
            "comment" : null,
            "user" : null,
            "ip" : "127.1.2.3",
            "addedDate" : "2023-07-31 08:56:05",
            "reverseDns" : null
         }
      ],
      "error_code" : "OK",
      "error_message" : "OK"
   }

   JSON_END
   ╰─────────────────────────────────────────────────────────</groupListServers>───

As you see, adding ``--json-pretty`` to the command enables output of additional text that can be parsed as JSON.
This option is the most human-readable one, and encloses the JSON output between two anchors, namely
``JSON_START`` and ``JSON_END``. All the text output out of these anchors can be ignored for the JSON API parsing.

Here is an example of parsing using simple shell commands:

.. code-block:: shell
   :emphasize-lines: 1,2

   ssh robot-group@bastion1.example.org -- --osh groupListServers --group mygroup --json-pretty --quiet | \
     awk '/^JSON_END\r?$/ {if(P==1){exit}} { if(P==1){print} } /^JSON_START\r?$/ {P=1}' | jq .
   {
     "error_code": "OK",
     "error_message": "OK",
     "value": [
       {
         "userComment": null,
         "reverseDns": null,
         "expiry": null,
         "user": null,
         "forceKey": null,
         "addedDate": "2023-07-31 08:56:05",
         "port": "22",
         "addedBy": "johndoe",
         "ip": "127.1.2.3",
         "forcePassword": null,
         "comment": null
       }
     ],
     "command": "groupListServers"
   }

Note that we use ``--quiet``, which removes some text that is only useful to humans, and it also disables colors
in the output. In any case, the JSON API output between the anchors never has colors enabled.

Using --json
------------

This option uses the same anchors than ``--json-pretty``, but doesn't prettify the JSON, so the output
is more compact:

.. code-block:: shell
   :emphasize-lines: 1

   ssh robot-group@bastion1.example.org -- --osh groupListServers --group mygroup --json
   ---ac777d06bec9-------------------------------------------the-bastion-3.12.00---
   => list of servers pertaining to the group
   --------------------------------------------------------------------------------
   ~        IP PORT  USER          ACCESS-BY ADDED-BY   ADDED-AT
   ~ --------- ---- ----- ------------------ -------- ----------
   ~ 127.1.2.3   22 (any)     mygroup(group)  johndoe 2023-07-31
   ~ 
   ~ 1 accesses listed

   JSON_START
   {"error_code":"OK","error_message":"OK","value":[{"forcePassword":null,"expiry":null,"port":"22","addedBy":"johndoe","ip":"127.1.2.3","userComment":null,"addedDate":"2023-07-31 08:56:05","user":null,"reverseDns":null,"comment":null,"forceKey":null}],"command":"groupListServers"}
   JSON_END

As the anchors are the same, the parsing can be done with the same logic as above:

.. code-block:: shell
   :emphasize-lines: 1,2

   ssh robot-group@bastion1.example.org -- --osh groupListServers --group mygroup --json --quiet | \
     awk '/^JSON_END\r?$/ {if(P==1){exit}} { if(P==1){print} } /^JSON_START\r?$/ {P=1}' | jq .
   {
     "error_code": "OK",
     "error_message": "OK",
     "value": [
       {
         "userComment": null,
         "reverseDns": null,
         "expiry": null,
         "user": null,
         "forceKey": null,
         "addedDate": "2023-07-31 08:56:05",
         "port": "22",
         "addedBy": "johndoe",
         "ip": "127.1.2.3",
         "forcePassword": null,
         "comment": null
       }
     ],
     "command": "groupListServers"
   }

Using --json-greppable
----------------------

This is a variant of the ``--json`` option, but instead of relying on ``JSON_START`` and ``JSON_END`` anchors,
which works for both ``--json`` and ``--json-pretty`` modes, here the JSON output is packed on one line,
starting with the ``JSON_OUTPUT=`` anchor.
You may use the option that is the easier for you to parse in your script or calling program.

.. code-block:: shell
   :emphasize-lines: 1

   ssh robot-group@bastion1.example.org -- --osh groupListServers --group mygroup --json--greppable
   ---ac777d06bec9-------------------------------------------the-bastion-3.12.00---
   => list of servers pertaining to the group
   --------------------------------------------------------------------------------
   ~        IP PORT  USER          ACCESS-BY ADDED-BY   ADDED-AT
   ~ --------- ---- ----- ------------------ -------- ----------
   ~ 127.1.2.3   22 (any)     mygroup(group)  johndoe 2023-07-31
   ~ 
   ~ 1 accesses listed

   JSON_OUTPUT={"error_code":"OK","command":"groupListServers","error_message":"OK","value":[{"reverseDns":null,"userComment":null,"user":null,"forceKey":null,"port":"22","addedDate":"2023-07-31 08:56:05","expiry":null,"addedBy":"johndoe","ip":"127.1.2.3","comment":null,"forcePassword":null}]}
   ----------------------------------------------------------</groupListServers>---

Here is an example of parsing using simple shell commands:

.. code-block:: shell
   :emphasize-lines: 1,2

   ssh robot-group@bastion1.example.org -- --osh groupListServers --group mygroup --json-greppable --quiet | \
     grep ^JSON_OUTPUT= | cut -d= -f2- | jq .
   {
     "error_code": "OK",
     "error_message": "OK",
     "value": [
       {
         "userComment": null,
         "reverseDns": null,
         "expiry": null,
         "user": null,
         "forceKey": null,
         "addedDate": "2023-07-31 08:56:05",
         "port": "22",
         "addedBy": "johndoe",
         "ip": "127.1.2.3",
         "forcePassword": null,
         "comment": null
       }
     ],
     "command": "groupListServers"
   }


JSON payload format
===================

The JSON payload is always a hash with 4 keys: ``error_code``, ``error_message``, ``value`` and ``command``,
as you may have witnessed from the examples above.

These keys are detailed below.

command
-------

The associated value is a string, containing the name of the command (plugin) that generated this output.

error_code
----------

The associated value is an always-uppercase string. You should look at the prefix of this string to know
whether the command was a success or not. The value is never ``null`` and always matches the following regex:
``^(OK|KO|ERR)[A-Z0-9_]*$``. The possible prefixes are either:

- ``OK``: the command has succeeded
- ``KO``: the command did not succeed
- ``ERR``: the command encountered an error, more information should be available in the ``error_message`` field,
  the ``value`` field will most likely be ``null``

Examples of such values include: ``KO_ACCESS_DENIED``, ``OK``, ``OK_NO_CHANGE``, ``ERR_MEMBER_CANNOT_BE_GUEST``.

You should rely on these error codes in the code using The Bastion's API to take decisions.

error_message
-------------

The associated value is a string, intended for human reading. It gives more details about the returned ``error_code``,
but is not intended to be parsed by your code, as it may change without notice from version to version. If there is no
specific ``error_message`` for a given case, the value will be the same than the one for ``error_code``, hence this
field is guaranteed to always exist and never be ``null``.

value
-----

The data associated to the key ``value`` is entirely dependent on ``command``, and can be a nested structure of
hashes and/or arrays. This is the actual data payload returned by the command you've invoked. Note that ``value``
can also be ``null``, particularly if the ``error_code`` doesn't start with the ``OK`` prefix.

Good practices
==============

If you're intending interaction with The Bastion API, it's a good idea to have accounts dedicated to this, to have
a clear distinction between human SSH usage and automated API calls. Additionally, if your automation will only
use such accounts to call plugins (``--osh`` commands), you might want to create such accounts with the ``--osh-only``
parameter to ``accountCreate``, this guarantees that such accounts will never be able to use The Bastion to connect
to other infrastructures (e.g. using SSH) even if granted to.
