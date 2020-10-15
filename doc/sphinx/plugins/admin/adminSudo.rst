==========
adminSudo
==========

Impersonate another user
========================


.. admonition:: usage
   :class: cmdusage

   --osh adminSudo -- --sudo-as ACCOUNT <--sudo-cmd PLUGIN -- [PLUGIN specific options...]>

.. program:: adminSudo


.. option:: --sudo-as ACCOUNT

   Specify which bastion account we want to impersonate

.. option:: --sudo-cmd PLUGIN

   --osh command we want to launch as the user (see --osh help)


Example::

  --osh adminSudo -- --sudo-as user12 --sudo-cmd info -- --name somebodyelse

Don't forget the double-double-dash as seen in the example above: one after the plugin name,
and another one to separate adminSudo options from the options of the plugin to be called.


