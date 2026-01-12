#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
#
# This scripts removes the empty folders that may pile up in each users' home
# directory, under the ttyrec/ folder. As every server they connect to has its
# own folder there (1 IP = 1 folder), and as ttyrecs are rotated and moved out by
# the `osh-encrypt-rsync.pl` script, we might end up with a lot of empty
# subfolders there. This is especially true for users that tend to connect to
# a lot of different servers (maybe to never connect there again) over the course of time.

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

# default config values for this script
MTIME_DAYS=1

# set error trap, read config, setup logging, exit early if script is disabled, etc.
script_init osh-remove-empty-folders config_optional check_secure_lax

# first, we list all the directories to get a count
_log "Counting the number of directories before the cleanup..."
# shellcheck disable=SC2086
nbdirs_before=$(find $FIND_EGREP_POSITIONAL_BEFORE /home/ -mindepth 3 -maxdepth 3 -type d \
    $FIND_EGREP_POSITIONAL_AFTER -regex '^/home/[^/]+/ttyrec/[0-9.]+$' -print | wc -l)

_log "We have $nbdirs_before directories, removing empty ones..."
# then we pass them all through rmdir, it'll just fail on non-empty ones.
# this is (way) faster than trying to be smart and listing each and every directory's contents first.
# shellcheck disable=SC2086
find $FIND_EGREP_POSITIONAL_BEFORE /home/ -mindepth 3 -maxdepth 3 -type d \
    -mtime +$MTIME_DAYS $FIND_EGREP_POSITIONAL_AFTER -regex '^/home/[^/]+/ttyrec/[0-9.]+$' -print0 | \
    xargs -r0 rmdir -- 2>/dev/null

# finally, see how many directories remain
_log "Counting the number of directories after the cleanup..."
# shellcheck disable=SC2086
nbdirs_after=$(find $FIND_EGREP_POSITIONAL_BEFORE /home/ -mindepth 3 -maxdepth 3 -type d \
    $FIND_EGREP_POSITIONAL_AFTER -regex '^/home/[^/]+/ttyrec/[0-9.]+$' -print | wc -l)

_log "Finally deleted $((nbdirs_before - nbdirs_after)) directories in this run"

# note that there is a slight TOCTTOU in the counting, as some external process might actually *add*
# directories so our count might be slightly wrong, but as this is just for logging sake, this is not an issue

exit_success
