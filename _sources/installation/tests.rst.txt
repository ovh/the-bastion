=============
Running Tests
=============

Using Docker
============

Functional tests use ``Docker`` to spawn an environment matching a bastion install.

One of the docker instances will be used as client, which will connect to the other instance which is used as the bastion server.

The client instance sends commands to the server instance and tests the return values against expected output.

To test the current code, put it on a machine with docker installed, and use the following script, which will run docker build and launch the tests:

    ``tests/functional/docker/docker_build_and_run_tests.sh <TARGET>``

Where target is one of the supported OSes. Currently only Linux targets are supported.
You'll get a list of the supported targets by calling the command without argument.

Without Docker
==============

You can however still test the code against a BSD (or any other OS) without using Docker, by spawning a server under the target OS, and installing the bastion on it.

Then, from another machine, run:

    ``test/functional/launch_tests_on_instance.sh <IP> <port> <remote_user_name> <ssh_key_path> [outdir]``

Where ``IP`` and ``port`` are the information needed to connect to the remote server to test, ``remote_user_name`` is the name of the account created on the remote bastion to use for the tests, and ``ssh_key_path`` is the private SSH key path used to connect to the account. The ``outdir`` parameter is optional, if you want to keep the raw output of each test.

This script is also the script used by the Docker client instance, so you're sure to get the proper results even without using Docker.

Please do **NOT** run any of those tests on a production bastion!
