======
batch
======

Run a batch of osh commands fed through STDIN
=============================================


.. admonition:: usage
   :class: cmdusage

   --osh batch

.. program:: batch


**Examples:**

(replace ``bssh`` by your bastion alias)

- run 3 simple commands in a oneliner:

::

  printf "%b\n%b\n%b" info selfListIngressKeys selfListEgressKeys | bssh --osh batch

- run a lot of commands written out line by line in a file:

::

  bssh --osh batch < cmdlist.txt

- add 3 users to a group:

::

  for i in user1 user2 user3; do echo "groupAddMember --account $i --group grp4"; done | bssh --osh batch


