Writing tests
=============

.. contents::

When modifying code, adding features or fixing bugs, you're expected to write one or more tests to ensure that
the feature your adding works correctly, or that the bug you've fixed doesn't come back.

Integration tests modules live in the :file:`tests/functional/tests.d` folder.
You may either add a new file to test your feature, or modify an existing file.

These modules are shell scripts, and are sourced by the main integration test engine. Having a look at one of
these modules will help you understand how they work, the :file:`tests/functional/tests.d/320-base.sh` is a good
example you might want to look at.

Example
-------

Here is a simple test taken from :file:`320-base.sh`:

.. code-block:: none
   :caption: a simple test

   success   help2     $a0 --osh help
   contain "OSH help"
   json .error_code OK .command help .value null

A complete reference of such commands can be found below, but let's explain this example in a few words:

The command ``success`` implies that we're running a new test command, and that we expect it to work (we might
also want to test invalid commands and ensure they fail as they should).
The tester docker will connect to the target docker (that is running the bastion code) as a bastion user, and
run the ``--osh help`` command there. This is expected to exit with a code indicating success (0),
otherwise this test fails.

The output of the command, once run on the bastion, should contain the text ``OSH help``, or the test will fail.

In the JSON output (see :doc:`/using/api`) of this command, we expect to find the ``error_code`` field set to ``OK``,
the ``command`` field set to ``help``, and the ``value`` field set to ``null``, or the test will fail.

Running just this test will yield the following output:

.. code-block:: none
   :caption: a simple test output

   00m04 [--] *** [0010/0021] 320-base::help2 (timeout --foreground 30 ssh -F /tmp/bastiontest.pgoA5h/ssh_config -i /tmp/bastiontest.pgoA5h/account0key1file user.5000@bastion_debian10_target -p 22 -- --json-greppable --osh help)
   00m05 [--] [ OK ] RETURN VALUE (0)
   00m05 [--] [ OK ] MUST CONTAIN (OSH help)
   00m05 [--] [ OK ] JSON VALUE (.error_code => OK) [  ]
   00m05 [--] [ OK ] JSON VALUE (.command => help) [  ]
   00m05 [--] [ OK ] JSON VALUE (.value => null) [  ]

As you can see, this simple test actually checked 5 things: the return value, whether the output text contained
a given string, and 3 fields of the JSON output.

Reference
---------

These are functions that are defined by the integration test engine and should be used in the test modules.

Launch a test
*************

run
+++

.. admonition:: syntax
   :class: cmdusage

   - run <name> <command>

This function runs a new test named ``<name>``, which will execute ``<command>`` on the tester docker.
Usually ``<command>`` will connect to the target docker (running the bastion code) using one of the test accounts,
and run a command there.

A few accounts are preconfigured:

- The main account ("account 0"): this one is guaranteed to always exist at all times, and is a bastion admin.
  There are a few variables that can be referenced to use this account:

  - ``$a0`` is the ssh command-line to connect to the remote bastion as this account
  - ``$account0`` is the account name, to be used in parameters of ``--osh`` commands where needed

- A few secondary accounts that are created, deleted, modified during the tests:

  - ``$a1``, ``$a2`` and ``$a3`` are the ssh command-lines to connect to the remote bastion as these accounts
  - ``$account1``, ``$account2`` and ``$account3`` are the accounts names

- Another special non-bastion-account command exists:

  - ``$r0`` is the required command-line to directly connect to the remote docker on which the bastion code is running,
    as root, with a bash shell. Only use this to modify the remote bastion files, such as config files, between tests

A few examples follow:

.. code-block:: none
   :caption: running a few test commands

   run test1 $a0 --osh info
   run test2 $a0 --osh accountInfo --account $account1
   run test3 $a1 --osh accountDelete --account $account2

Note that the ``run`` function just runs the given command, but doesn't check whether it exited normally, you'll
need other functions to verify this, see below.

success
+++++++

.. admonition:: syntax
   :class: cmdusage

   - success <name> <command>

This function is exactly the same as the ``run`` command above, except that it expects the given ``<command>`` to
return a valid error code (zero). Most of the time, you should be using this instead of ``run``, except if you're
expecting the command to fail, in which case you should use ``run`` + ``retvalshouldbe``, see below.

plgfail
+++++++

.. admonition:: syntax
   :class: cmdusage

   - plgfail <name> <command>

This function is exactly the same as the ``run`` command above, except that it expects the given ``<command>`` to
return an error code of 100, which is the standard exit value when an osh command fails.

This function is equivalent to using ``run`` followed by ``retvalshouldbe 100`` (see below).

Verify a test validity
**********************

retvalshouldbe
++++++++++++++

.. admonition:: syntax
   :class: cmdusage

   - retvalshouldbe <value>

Verify that the return value of a test launched right before with the ``run`` function is ``<value>``.
You should use this if you expect the previous test to return a non-zero value.

Note that the ``success`` function is equivalent to using ``run`` followed by ``retvalshouldbe 0``.

contain
+++++++

.. admonition:: syntax
   :class: cmdusage

   - contain <text>
   - contain REGEX <regex>

This function verifies that the output of the test contains a given ``<text>``. If you need to use a regex
to match the output, you can use the ``contain REGEX`` construction, followed by the regex.

nocontain
+++++++++

.. admonition:: syntax
   :class: cmdusage

   - nocontain <text>
   - nocontain REGEX <regex>

This function does the exact opposite of the ``contain`` function just above, and ensure that a given text
or regex is NOT present in the output.

json
++++

.. admonition:: syntax
   :class: cmdusage

   - json <field1> <value1> [<field2> <value2> ...]

This function checks the JSON API output of the test, and validates that it contains the correct value for each
specified field. The ``<fieldX>`` entries must be valid `jq` filters.
