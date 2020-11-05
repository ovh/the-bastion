=====
help
=====

I'm So Meta, Even This Acronym
==============================


.. admonition:: usage
   :class: cmdusage

   --osh help

.. program:: help



Displays help about the available plugins callable with ``--osh``.

If you need help on a specific plugin, you can use ``--osh PLUGIN --help``, replacing ``PLUGIN`` with the actual plugin name.

Note that if you want some help about the bastion (and not specifically about the plugins), you should use ``--help`` (without ``--osh``).

Colors
======

You'll notice that plugins are highlighted in different colors, these indicate the access level needed to run the plugin. Note that plugins you don't have access to are simply omitted.

- green (``open``): these plugins can be called by anybody
- blue (``restricted``): these plugins can only be called by users having the specific right to call them. This right is granted per plugin by the ``accountGrantCommand`` plugin
- orange (``group-gatekeeper`` and ``group-aclkeeper``): these plugins can either be called by group gatekeepers or group aclkeepers. For clarity, the same color has been used for both cases
- purple (``group-owner``): these plugins can only be called by group owners
- red (``admin``): these plugins can only be called by bastion admins
