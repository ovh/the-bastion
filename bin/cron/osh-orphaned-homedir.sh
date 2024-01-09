#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
set -e
umask 077

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

# default config values for this script
:

# set error trap, read config, setup logging, exit early if script is disabled, etc.
script_init osh-orphaned-homedir config_optional check_secure_lax

# first, verify that we're not a master instance, if this is the case, do nothing
set +e
perl -e '
use strict;
use warnings;

use File::Basename;
use lib "'"$basedir"'/lib/perl";
use OVH::Bastion;

my $c = OVH::Bastion::load_configuration() or exit(101);
exit(102) if not exists $c->value->{readOnlySlaveMode};
exit($c->value->{readOnlySlaveMode} ? 0 : 100);
'; ret=$?
set -e

case $ret in
    0)   _log "Checking orphaned home directories..."; role=slave;;
    100) _log "We're a master instance, just check for orphaned lastlog files"; role=master;;
    101) exit_fail "Couldn't load the main bastion configurationg, aborting";;
    102) exit_fail "Invalid main bastion configuration, aborting";;
    *)   exit_fail "Unknown return code ($ret), aborting";;
esac

mkdir -p "/home/oldkeeper/orphaned"

while IFS= read -r -d '' dir
do
    # just in case, check ourselves again that the folder's UID/GID don't resolve
    set +e
    uid=$(get_file_uid_compat "$dir")
    gid=$(get_file_gid_compat "$dir")
    user=$(getent passwd "$uid")
    group=$(getent group "$gid")
    set -e
    if [ -n "$user" ] || [ -n "$group" ]; then
        # wow, `find' lied to us?!
        exit_fail "Would have archived $dir, but it seems the user ($uid=$user) or the group ($gid=$group) actually still exists (!), aborting the script"
    fi

    if [ "$role" = "master" ]; then
        # on masters, due to race conditions between scripts and hosts, we might have deleted the account, then
        # got one of our slaves to synchronize back the lastlog of the account onto us, before the slave
        # gets synced itself to have the account removed locally.
        #
        # when this happens, we end up with a home directory with only one file in it: lastlog. check for this.
        # also cap to 10 because we mainly need to know whether there is more than the 'lastlog' file or not.
        files=$(find "$dir" -mindepth 1 | head -n 10)
        if [ "$files" = "$dir/lastlog" ]; then
            _log "Found orphaned lastlog file in $dir/lastlog, removing it"
            rm -f -- "$dir/lastlog"
            rmdir -- "$dir"
        fi
        # this is the only case we need to handle on a master
        continue
    fi

    archive="/home/oldkeeper/orphaned/$(basename "$dir").at-$(date +%s).by-orphaned-homedir-script.tar.gz"
    _log "Found orphaned $dir [$(ls -ld "$dir")], archiving..."
    chmod 0700 /home/oldkeeper/orphaned
    if [ "$OS_FAMILY" = "Linux" ]; then
        find "$dir" -mindepth 1 -maxdepth 1 -type f -name "*.log" -print0 | xargs -r0 chattr -a
    fi

    # remove empty directories if we have some
    find "$dir" -type d -delete 2>/dev/null || true
    acls_param=''
    [ "$OS_FAMILY" = "Linux"   ] && acls_param='--acls'
    [ "$OS_FAMILY" = "FreeBSD" ] && acls_param='--acls'

    set +e
    tar czf "$archive" $acls_param --one-file-system -p --remove-files --exclude=ttyrec "$dir" 2>/dev/null; ret=$?
    set -e

    if [ $ret -ne 0 ]; then
        # $? can be 2 if we can't delete because ttyrec dir remains so it might not be a problem
        if [ $ret -eq 2 ] && [ -s "$archive" ] && [ -d "$dir" ] && [ "$(find "$dir" -name ttyrec -prune -o -print | wc -l)" = 1 ]; then
            # it's ok. we chown all to root to avoid orphan UID/GID and we let the backup script take care of those
            # if we still have files under $dir/ttyrec, chown all them to root:root to avoid orphan UID/GID,
            # and just wait for them to be encrypted/rsynced out of the bastion by the usual ttyrec archiving script
            _log "Archived $dir to $archive"
            chmod 0 "$archive"

            chown -R root:root "$dir"
            _warn "Some files remain in $dir, we chowned everything to root"
        else
            _err "Couldn't archive $dir to $archive"
        fi
    else
        _log "Archived $dir to $archive"
        chmod 0 "$archive"
    fi
done < <(find /home/ -mindepth 1 -maxdepth 1 -type d -nouser -nogroup -mmin +3 -print0)

# there are also temporary files that might not be cleaned when an account disappears,
# so check for those here
[ -d /run/faillock ] && find /run/faillock -xdev -nouser -type f -delete

exit_success
