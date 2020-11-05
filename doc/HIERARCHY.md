man 7 hier
==========

The OVH::Bastion directory hierarchy is organized as follows:

- bin
  - bin/admin: scripts that are supposed to be launched manually by an admin where needed
  - bin/cron: scripts that are launched from cronjobs
  - bin/proxy: the http proxy daemon and worker live here
  - bin/dev: scripts that are useful when developing for the bastion
  - bin/helper: modules that are called under sudo by the plugins, to execute privileged operations
  - bin/plugin: base directory (must not contain any files) of the plugins that can be used with —osh
    - bin/plugin/admin: plugins that can only be launched by bastion admins
    - bin/plugin/group-aclkeeper: plugins that can only be launched by group aclkeepers
    - bin/plugin/group-gatekeeper: plugins that can only be launched by group gatekeepers
    - bin/plugin/group-owner: plugins that can only be launched by group owners
    - bin/plugin/open: plugins that can be launched by any user
    - bin/plugin/restricted: plugins that can be launched only by users that are explicitly granted on said plugins
  - bin/shell: where resides the main script that is declared as the shell of the bastion users, with some of its helpers
  - bin/sudogen: where resides the helper script that generate group and account sudoers files
  - bin/other: other helper scripts for various tasks
- contrib: placeholder directory with a readme file that references other repositories of interest when integrating the bastion in your company
- doc: sysadmin-proof documentation folder, the main Markdown files you need are there, just one `view` apart
  - doc/sphinx: more complete documentation using the `sphinx` documentation system, the built version is viewable on https://ovh.github.io/the-bastion/
- docker: where the Dockerfiles reside
- etc: contains all the template configuration files that will be installed on your system (depending on your `install` options)
- install: where optional modules can push their install script to be called by the main install script
- lib
  - lib/perl: where all the Perl libraries live, used everywhere in the main code
  - lib/shell: where all the Bash libraries live, usually sourced by Bash scripts
- tests
  - tests/functional: contains all the tools to manage the functional testing framework
  - tests/unit: where the unit tests live
