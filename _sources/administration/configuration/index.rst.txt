===================
Configuration files
===================

Main configuration files
========================

These config files should be reviewed and adapted for the environment in which
you're deploying The Bastion. The doc:`bastion_conf` is the only one that is
mandatory to get you started. You should however review the other ones before
going into production.

.. toctree::
   :maxdepth: 1

   bastion_conf
   osh-backup-acl-keys_conf
   osh-encrypt-rsync_conf
   osh-sync-watcher_sh
   osh-http-proxy_conf

Configuration files for satellite scripts
=========================================

These config files govern the behavior of satellite scripts that handle
background tasks of The Bastion. Most of the time, there is no need to alter
the configuration as sane defaults are already built in.

.. toctree::
   :maxdepth: 1

   osh-piv-grace-reaper_conf
   osh-remove-empty-folders_conf
   osh-cleanup-guest-key-access_conf
   osh-lingering-sessions-reaper_conf
   osh-orphaned-homedir_conf
