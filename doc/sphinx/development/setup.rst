Environment setup
=================

.. contents::

This documentation section outlines the few steps needed to build a development environment for The Bastion,
easing code modification, tests, checks, and ultimately, pull requests.

Available tools
***************

The provided :file:`docker/devenv/run-tool.sh` script will build a development docker for you, under which it'll
run several tools. Your local git folder will be mounted as a volume inside this docker so that it can
access the files, and potentially modify them (such as for ``perltidy``).

The supported tools are as follows:

.. code-block:: none
   :emphasize-lines: 1

   Usage: ./docker/devenv/run-tool.sh COMMAND [OPTIONS]

     COMMAND may be one of the following:

     tidy       [FILES..] runs perltidy on several or all the Perl source files, modifying them if needed
     tidycheck  [FILES..] runs perltidy in dry-run mode, and returns an error if files are not tidy
     perlcritic           runs perlcritic on all the Perl source files
     shellcheck [FILES..] runs shellcheck on all the shell source files
     lint                 runs tidy, perlcritic and shellcheck on all files in one command
     doc                  generates the documentation
     sphinx-view-objects  shows the named objects of the Sphinx documentation that can be referenced
     rebuild              forces the rebuild of the devenv docker image that is needed to run all the above commands
     run <COMMAND>        spawn an interactive shell to run any arbitrary command in the devenv docker
     doc-serve <PORT>     starts a local HTTP python server on PORT to view generated documentation

Before submitting a pull request, you'll need at minimum to run ``lint``. It might be a good idea to setup a
git pre-commit hook to do this on modified files, see below.

Git pre-commit hook
*******************

Some lint checks are enforced through GitHub Actions, but it'll save you a lot of back-and-forth if you ensure that
these checks are passing locally on your development environment.

To this effect, you'll need to setup pre-commit hooks on your local copy of the git repository, so that your code
is automatically checked by ``perlcritic``, ``perltidy`` and ``shellcheck`` each time you commit.

If you previously cloned the repository with such a command:

.. code-block:: none
   :emphasize-lines: 1

   git clone https://github.com/ovh/the-bastion

Then you can copy the provided :file:`pre-commit` script into your local :file:`.git` folder:

.. code-block:: none
   :emphasize-lines: 1

   cp contrib/git/pre-commit .git/hooks/pre-commit

To verify that it works checkout a new test branch and add two dummy files like this:

.. code-block:: none
   :emphasize-lines: 1-5

   git checkout -B mybranch
   printf "%b" "#! /usr/bin/env bash\nunused=1\n" > bin/shell/dummy.sh
   printf "%b" "#! /usr/bin/env perl\nsub dummy { 1; };\n" > lib/perl/dummy.pm
   git add bin/shell/dummy.sh lib/perl/dummy.pm
   git commit -m dummy

   *** Checking shell files syntax using system shellcheck
   `-> bin/shell/dummy.sh

   In bin/shell/dummy.sh line 2:
   unused=1
   ^----^ SC2034: unused appears unused. Verify use (or export if used externally).

   `-> [ERR.] 

   ERROR: shell-check failed on bin/shell/dummy.sh
   *** Checking perl tidiness
   `-> lib/perl/dummy.pm
   ./lib/perl/dummy.pm ./lib/perl/dummy.pm.tdy differ: char 38, line 2
   --- ./lib/perl/dummy.pm 2023-10-03 08:19:55.605950307 +0000
   +++ ./lib/perl/dummy.pm.tdy     2023-10-03 08:20:43.618577295 +0000
   @@ -1,2 +1,2 @@
    #! /usr/bin/env perl
   -sub dummy { 1; };
   +sub dummy { 1; }

   ERROR: perl tidy failed on lib/perl/dummy.pm

   !!! COMMIT ABORTED !!!
   If you want to commit nevertheless, use -n.

As you see, the checks are running before the commit is validated and abort it should any check fail.

Running integration tests
*************************

Using Docker
------------

Functional tests use ``Docker`` to spawn an environment matching a bastion install.
One of the docker instances will be used as client, which will connect to the other instance
which is used as the bastion server. The client instance sends commands to the server instance
and tests the return values against expected output.

To test the current code, use the following script, which will run ``docker build`` and launch the tests:

.. code-block:: none
   :emphasize-lines: 1

   tests/functional/docker/docker_build_and_run_tests.sh <TARGET>

Where target is one of the supported OSes. Currently only Linux targets are supported.
You'll get a list of the supported targets by calling the command without argument.

For example, if you want to test it under Debian (which is a good default OS if you don't have any preference):

.. code-block:: none
   :emphasize-lines: 1

   tests/functional/docker/docker_build_and_run_tests.sh debian12

The full tests usually take 25 to 50 minutes to run, depending on your hardware specs.
If you want to launch only a subset of the integration tests, you may specify it:

.. code-block:: none
   :emphasize-lines: 1

   tests/functional/docker/docker_build_and_run_tests.sh debian12 --module=320-base.sh

Other options are supported, and passed through as-is to the underlying test script, use ``--help`` as below to
get the list (the output in this documentation might not be up to date, please actually launch it yourself
to get up-to-date information):

.. code-block:: none
   :emphasize-lines: 1

   tests/functional/launch_tests_on_instance.sh --help

   Usage: /home/user/bastion/tests/functional/launch_tests_on_instance.sh [OPTIONS] <IP> <SSH_Port> <HTTP_Proxy_Port_or_Zero> <Remote_Admin_User_Name> <Admin_User_SSH_Key_Path> <Root_SSH_Key_Path>

   Test Options:
       --skip-consistency-check   Speed up tests by skipping the consistency check between every test
       --no-pause-on-fail         Don't pause when a test fails
       --log-prefix=X             Prefix all logs by this name
       --module=X                 Only test this module (specify a filename found in `functional/tests.d/`), can be specified multiple times

   Remote OS directory locations:
       --remote-etc-bastion=X     Override the default remote bastion configuration directory (default: /etc/bastion)
       --remote-basedir=X         Override the default remote basedir location (default: /home/user/bastion)

   Specifying features support of the underlying OS of the tested bastion:
       --has-ed25519=[0|1]        Ed25519 keys are supported (default: 1)
       --has-mfa=[0|1]            PAM is usable to check passwords and TOTP (default: 1)
       --has-mfa-password=[0|1]   PAM is usable to check passwords (default: 0)
       --has-pamtester=[0|1]      The `pamtester` binary is available, and PAM is usable (default: 1)
       --has-piv=[0|1]            The `yubico-piv-tool` binary is available (default: 1)

Without Docker
--------------

.. note::

   This method is discouraged, prefer using the Docker method above when possible

You can test the code against a BSD (or any other OS) without using Docker, by spawning a server
under the target OS (for example, on a VM), and installing the bastion on it.

Then, from another machine, run:

.. code-block:: none
   :emphasize-lines: 1

   test/functional/launch_tests_on_instance.sh <IP> <port> <remote_user_name> <ssh_key_path> [outdir]

Where ``IP`` and ``port`` are the information needed to connect to the remote server to test,
``remote_user_name`` is the name of the account created on the remote bastion to use for the tests,
and ``ssh_key_path`` is the private SSH key path used to connect to the account.
The ``outdir`` parameter is optional, if you want to keep the raw output of each test.

This script is also the script used by the Docker client instance,
so you're sure to get the proper results even without using Docker.

Please do **NOT** run any of those tests on a production bastion!
