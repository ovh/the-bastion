====================
Sandbox using Docker
====================

This is a good way to test The Bastion within seconds, but :ref:`read the FAQ <faq_docker>`
if you're serious about using containerization in production.

The sandbox image is available for the following architectures: ``linux/386``, ``linux/amd64``, ``linux/arm/v6``,
``linux/arm/v7``, ``linux/arm64``, ``linux/ppc64le``, ``linux/s390x``.

- Let's run the docker image:

.. code-block:: shell

    docker run -d -p 22 --name bastiontest ovhcom/the-bastion:sandbox

- Or, if you prefer building the docker image yourself, you can: use the two commands below.
  Of course, if you already typed the ``docker run`` command above, you can skip the following commands:

.. code-block:: shell

    docker build -f docker/Dockerfile.debian10 -t bastion:debian10 .
    docker run -d -p 22 --name bastiontest bastion:debian10

- Configure the first administrator account (get your public SSH key ready)

.. code-block:: shell

    docker exec -it bastiontest /opt/bastion/bin/admin/setup-first-admin-account.sh poweruser auto

- We're now up and running with the default configuration!
  Let's setup a handy bastion alias, and test the ``info`` command:

.. code-block:: shell

    PORT=$(docker port bastiontest | cut -d: -f2)
    alias bastion="ssh poweruser@127.0.0.1 -tp $PORT -- "
    bastion --osh info

- It should greet you as being a bastion admin, which means you have access to all commands.
  Let's enter interactive mode:

.. code-block:: shell

    bastion -i

- This is useful to call several ``--osh`` plugins in a row. Now we can ask for help to see all plugins:

.. code-block:: shell

    $> help

- If you have a remote machine you want to try to connect to through the bastion, fetch your egress key:

.. code-block:: shell

    $> selfListEgressKeys

- Copy this public key to the remote machine's ``authorized_keys`` under the ``.ssh/`` folder
  of the account you want to connect to, then:

.. code-block:: shell

    $> selfAddPersonalAccess --host <remote_host> --user <remote_account_name> --port-any
    $> ssh <remote_account_name>@<remote_host>

- Note that you can connect directly without using interactive mode, with:

.. code-block:: shell

    bastion <remote_account_name>@<remote_machine_host_or_ip>

That's it! You can head over to the **USAGE** section on the left menu for more information.
Be sure to check the help of the bastion with ``bastion --help``,
along with the help of each osh plugin with ``bastion --osh command --help``.

Also don't forget to customize your ``bastion.conf`` file,
which can be found in ``/etc/bastion/bastion.conf`` (for Linux).
