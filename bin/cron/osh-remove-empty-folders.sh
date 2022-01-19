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

trap "_err 'Unexpected termination!'" EXIT

# setting default values
LOGFILE=""
LOG_FACILITY="local6"
ENABLED=1
MTIME_DAYS=1

# building config files list
config_list=''
if [ -f "$BASTION_ETC_DIR/osh-remove-empty-folders.conf" ]; then
    config_list="$BASTION_ETC_DIR/osh-remove-empty-folders.conf"
fi
if [ -d "$BASTION_ETC_DIR/osh-remove-empty-folders.conf.d" ]; then
    config_list="$config_list $(find "$BASTION_ETC_DIR/osh-remove-empty-folders.conf.d" -mindepth 1 -maxdepth 1 -type f -name "*.conf" | sort)"
fi

if [ -z "$config_list" ]; then
    exit_fail "No configuration loaded, aborting"
fi

# load the config files only if they're owned by root:root and mode is o-rwx
for file in $config_list; do
    if check_secure "$file"; then
        # shellcheck source=etc/bastion/osh-remove-empty-folders.conf.dist
        . "$file"
    else
        exit_fail "Configuration file not secure ($file), aborting."
    fi
done

# shellcheck disable=SC2153
if [ -n "$LOGFILE" ] ; then
    exec &>> >(tee -a "$LOGFILE")
fi

if [ "$ENABLED" != 1 ]; then
    exit_success "Script is disabled"
fi

# first, we list all the directories to get a count
_log "Counting the number of directories before the cleanup..."
nbdirs_before=$(find /home/ -mindepth 3 -maxdepth 3 -type d -regextype egrep -regex '^/home/[^/]+/ttyrec/[0-9.]+$' -print | wc -l)

_log "We have $nbdirs_before directories, removing empty ones..."
# then we pass them all through rmdir, it'll just fail on non-empty ones.
# this is (way) faster than trying to be smart and listing each and every directory's contents first.
find /home/ -mindepth 3 -maxdepth 3 -type d -mtime +$MTIME_DAYS -regextype egrep -regex '^/home/[^/]+/ttyrec/[0-9.]+$' -print0 | xargs -r0 rmdir -- 2>/dev/null

# finally, see how many directories remain
_log "Counting the number of directories after the cleanup..."
nbdirs_after=$(find /home/ -mindepth 3 -maxdepth 3 -type d -regextype egrep -regex '^/home/[^/]+/ttyrec/[0-9.]+$' -print | wc -l)

_log "Finally deleted $((nbdirs_before - nbdirs_after)) directories in this run"

# note that there is a slight TOCTTOU in the counting, as some external process might actually *add*
# directories so our count might be slightly wrong, but as this is just for logging sake, this is not an issue

exit_success "Done"
