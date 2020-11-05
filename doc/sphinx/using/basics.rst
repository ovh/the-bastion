==========
The basics
==========

We make the assumption here that you already have a bastion account:

- either you're one of the admins who just :doc:`installed<../installation/basic>` it, or
- one of the admins created an account for you

If you are an admin and want to create accounts for your users, this is explained :doc:`here<accounts>`.

First steps
===========

Bastion alias
*************

You should setup a *bastion alias* to make it easy to connect to the bastion. An example of the proper alias to use for your account is given to the bastion administrator when s/he creates your account, and is usually something along the lines of:

.. code-block:: shell

    alias bssh='ssh -t myname@the-bastion.example.org --'

Of course, you can modify it as you see fit, for example adding the ``-i`` argument to specify the private SSH key to use to connect to the bastion. You can use any name as the alias, but it's advised to keep it short, as you'll use it quite often.

For the remaining of this documentation, we'll assume your bastion alias is `bssh`.

You can do to categories of things on the bastion:

- Connect to infrastructures through it
- Interact with the bastion itself, for example to manage your account, and/or groups, through so-called *plugins*, also named *osh commands*

Plugins
*******

We'll start by using the ``info`` plugin, to verify that your bastion access works correctly:

.. code-block:: shell
   :emphasize-lines: 1

   $ bssh --osh info
   *------------------------------------------------------------------------------*
   |THIS IS A PRIVATE COMPUTER SYSTEM, UNAUTHORIZED ACCESS IS STRICTLY PROHIBITED.|
   |ALL CONNECTIONS ARE LOGGED. IF YOU ARE NOT AUTHORIZED, DISCONNECT NOW.        |
   *------------------------------------------------------------------------------*
   Enter PIN for 'PIV Card Holder pin (PIV_II)':
   ---the-bastion.example.org----------------------------the-bastion-2.99.99-rc9---
   => information
   --------------------------------------------------------------------------------
   ~ You are johndoe
   ~ You are a bastion auditor!
   ~ Look at you, you are a bastion superowner!
   ~ Woosh, you are even a bastion admin!
   ~
   ~ Your alias to connect to this bastion is:
   ~ alias bssh='ssh johndoe@the-bastion.example.org -p 22 -t -- '
   ~ Your alias to connect to this bastion with MOSH is:
   ~ alias bsshm='mosh --ssh="ssh -p 22 -t" johndoe@the-bastion.example.org -- '
   ~
   ~ [...]
   ~
   ~ Here is your excuse for anything not working today:
   ~ BOFH excuse #46:
   ~ waste water tank overflowed onto computer
   ----------------------------------------------------------------------</info>---
   Connection to the-bastion.example.org closed.

Congratulations, you've just used your first command on the bastion!

You can get a list of all the plugins you can use by saying:

.. code-block:: shell

   $ bssh --osh help

The list will depend on your access level on the bastion, as some commands are restricted. You can have more information about any command by using ``--help`` with it:

.. code-block:: shell

   $ bssh --osh selfAddIngressKey --help

See :doc:`here <plugins>` for more information about the plugins.

Instead of using ``--osh`` to call plugins, you can enter the special *interactive mode*, by saying:

.. code-block:: shell

   $ bssh -i

In this mode, you can directly enter commands, and also use auto-completion features with the ``<TAB>`` key. You can start by just typing ``help``, which is the equivalent of saying ``bssh --osh help``. For security reasons, the interactive mode will disconnect you after a given amount of idle-time.

Setting up access to a server
*****************************

This section assumes that you have a server you want to secure access to, using the bastion. We'll call it *server42.example.org*, with IP 198.51.100.42. To do this, we'll use the **selfAddAccess** command.

Let's use the interactive mode to get the auto-completion features:

.. code-block:: shell
   :emphasize-lines: 1

   $ bssh -i
   Enter PIN for 'PIV Card Holder pin (PIV_II)': 

   Welcome to bssh interactive mode, type `help' for available commands.
   You can use <tab> and <tab><tab> for autocompletion.
   You'll be disconnected after 60 seconds of inactivity.
   Loading... 88 commands and 341 autocompletion rules loaded.

   bssh(master)> 

You can enter the first few characters of the command, then use ``<TAB>`` to help you complete it, then use ``<TAB>`` again to show you the required arguments. The complete command would be as follows:

.. code-block:: shell
   :emphasize-lines: 1

   bssh(master)> selfAddPersonalAccess --host 198.51.100.42 --port 22 --user root
   ---the-bastion.example.org----------------------------the-bastion-2.99.99-rc9---
   => adding private access to a server on your account
   --------------------------------------------------------------------------------
   ~ Testing connection to root@198.51.100.42, please wait...
   Warning: Permanently added '198.51.100.42' (ECDSA) to the list of known hosts.
   root@198.51.100.42: Permission denied (publickey).
   ~ Note: if you still want to add this access even if it doesn't work, use --force
   ~ Couldn't connect to root@198.51.100.42 (ssh returned error 255). Hint: did you add the proper public key to the remote's authorized_keys?
   -----------------------------------------------------</selfAddPersonalAccess>---
   bssh(master)> 

You'll notice that it didn't work. This is because first, you need to add your *personal egress key* to the remote machine's *authorized_keys* file. If this seems strange, here is :doc:`how it works <../presentation/principles>`. To get your *personal egress key*, you can use this command:

.. code-block:: shell
   :emphasize-lines: 1

   bssh(master)> selfListEgressKeys
   ---the-bastion.example.org----------------------------the-bastion-2.99.99-rc9---
   => the public part of your personal bastion key
   --------------------------------------------------------------------------------
   ~ You can copy one of those keys to a remote machine to get access to it through your account
   ~ on this bastion, if it is listed in your private access list (check selfListAccesses)
   ~  
   ~ Always include the from="198.51.100.1/32" part when copying the key to a server!
   ~  
   ~ fingerprint: SHA256:rMpoCaYPSfRqmOBFOJvEr5uLqxYjqYtRDgUoqUwH2nA (ED25519-256) [2019/07/11]
   ~ keyline follows, please copy the *whole* line:
   from="198.51.100.1/32" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILnY2NQTKsTDxgcaTE6vHVm9FIbud1rJcYQ/4xUyr+DK johndoe@bssh:1562861572
   --------------------------------------------------------</selfListEgressKeys>---

Now that you have it, you can push this public key (the line starting with the *from=*) to the remote server's root authorized_keys, i.e. ``/root/.ssh/authorized_keys``. Now, you can add your access properly:

.. code-block:: shell
   :emphasize-lines: 1

   bssh(master)> selfAddPersonalAccess --host 198.51.100.42 --port 22 --user root
   ---the-bastion.example.org----------------------------the-bastion-2.99.99-rc9---
   => adding private access to a server on your account
   --------------------------------------------------------------------------------
   ~ Testing connection to root@198.51.100.42, please wait...
   Warning: Permanently added '198.51.100.42' (ECDSA) to the list of known hosts.
   ~ Access to root@198.51.100.42:22 successfully added
   -----------------------------------------------------</selfAddPersonalAccess>---
   bssh(master)> 

All seems in order! Can we see this access we just created?

.. code-block:: shell
   :emphasize-lines: 1

   bssh(master)> selfListAccesses
   ---the-bastion.example.org----------------------------the-bastion-2.99.99-rc9---
   => your access list
   --------------------------------------------------------------------------------
   ~ Dear johndoe, you have access to the following servers:
   ~ IP               PORT     USER    ACCESS-BY   ADDED-BY      ADDED-AT
   ~ 198.51.100.42      22     root    personal     johndoe    2020-05-01
   -----------------------------------------------------</selfListAccesses>---
   bssh(master)> 

Connecting to a server and reviewing the session
************************************************

Good! Let's try to connect now!

.. code-block:: shell
   :emphasize-lines: 1

   bssh(master)> ssh root@198.51.100.42
   ~ Welcome to the-bastion, johndoe, your last login was 00:13:37 ago (Fri 2020-08-28 13:07:43 UTC) from 192.0.2.11(proxy-11.example.org)

   proxy-11.example.org:40610 => johndoe@the-bastion.example.org:22 => root@server42.example.org:22 ...
    allowed ... log on(/home/johndoe/ttyrec/198.51.100.42/2020-08-28.13-07-45.497020.fb00e1957b22.johndoe.root.198.51.100.42.22.ttyrec)
   
    will try the following accesses you have: 
     - personal access with ED25519-256 key SHA256:rMpoCaYPSfRqmOBFOJvEr5uLqxYjqYtRDgUoqUwH2nA [2019/07/11]

   Connecting...

   root@server42:~# id
   uid=0(root) gid=0(root) groups=0(root),2(bin)
   root@server42:~#

We're now connected to server42, and can do our work as usual. Note that to connect to server42, one can directly use:

.. code-block:: shell

   $ bssh root@198.51.100.42

Where `bssh` is the bastion alias we've just set up above, no need to enter interactive mode first of course.

When we've done with server42, let's see if everything was correctly recorded:

.. code-block:: shell
   :emphasize-lines: 1

   bssh(master)> selfListSessions --type ssh --detailed
   ---bst-dev-a.bastions.ovh.net------------------the-bastion-2.99.99-rc9.2-ovh1---
   => your past sessions list
   --------------------------------------------------------------------------------
   ~ The list of your 100 past sessions follows:
   ~
   f4cca44a848e [2020/08/26@09:28:57 - 2020/08/26@09:29:57 (         60.0)] type ssh from 192.0.2.11:33450(proxy-11.example.org) via johndoe@198.51.100.1:22 to root@198.51.100.42:22(server42.example.org) returned 0
   ----------------------------------------------------------</selfListSessions>---

The first column is the unique identifier of the connection (or osh command).
Let's see what we did exactly during this session:


.. code-block:: shell
   :emphasize-lines: 1

   bssh(master)> selfPlaySession --id f4cca44a848e
   ---bst-dev-a.bastions.ovh.net------------------the-bastion-2.99.99-rc9.2-ovh1---
   => replay a past session
   --------------------------------------------------------------------------------
   ~       ID: f4cca44a848e
   ~  Started: 2020/08/26 09:28:57
   ~    Ended: 2020/08/26 09:29:57
   ~ Duration: 0d+00:01:00.382820
   ~     Type: ssh
   ~     From: 192.0.2.11:33450 (proxy-11.example.org)
   ~      Via: johndoe@198.51.100.1:22
   ~       To: root@198.51.100.42:22 (server42.example.org)
   ~  RetCode: 0
   ~ 
   ~ Press '+' to play faster
   ~ Press '-' to play slower
   ~ Press '1' to restore normal playing speed
   ~ 
   ~ When you're ready to replay session 9f352fd4b85c, press ENTER.
   ~ Starting from the next line, the Total Recall begins. Press CTRL+C to jolt awake.

Now that you've connected to your first server, using a personal access, you may want to check out the groups access management, or directly dive into the Bastion plugins.
