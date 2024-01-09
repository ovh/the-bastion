#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
#
# This script removes the orphaned and/or old tmp files and directories
# that might be left by plugins run from accounts that no longer exist

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

# set error trap, read config, setup logging, exit early if script is disabled, etc.
script_init osh-cleanup-tmp-files config_optional check_secure_lax

# first, handle the top-level /tmp directories that are orphaned

# Counting the number of orphaned top-level tmp directories...
nbdirs_before=$(find /tmp/ -mindepth 1 -maxdepth 1 -type d \( -nouser -o -nogroup \) -print | wc -l)

_log "We have $nbdirs_before orphaned top-level directories, deleting if any..."
find /tmp/ -mindepth 1 -maxdepth 1 -type d \( -nouser -o -nogroup \) -print0 | xargs -r0 -- rm -rf --

# Counting the number of directories after the cleanup...
nbdirs_after=$(find /tmp/ -mindepth 1 -maxdepth 1 -type d \( -nouser -o -nogroup \) -print | wc -l)

_log "Finally deleted $((nbdirs_before - nbdirs_after)) orphaned directories in this run"

# second, handle old well-known top-level /tmp directories that may have been left behind

# Counting the number of old well-known top-level tmp directories...
nbdirs_before=$(find /tmp/ -mindepth 1 -maxdepth 1 -type d -mtime +14 -name "chroot-*" -print | wc -l)

_log "We have $nbdirs_before old well-known top-level directories, deleting if any..."
find /tmp/ -mindepth 1 -maxdepth 1 -type d -mtime +14 -name "chroot-*" -print0 | xargs -r0 -- rm -rf --

# Counting the number of directories after the cleanup...
nbdirs_after=$(find /tmp/ -mindepth 1 -maxdepth 1 -type d -mtime +14 -name "chroot-*" -print | wc -l)

_log "Finally deleted $((nbdirs_before - nbdirs_after)) orphaned directories in this run"

exit_success
