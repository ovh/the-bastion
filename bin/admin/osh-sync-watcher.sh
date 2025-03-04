#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:

PIDFILE=/var/run/osh-sync-watcher.pid

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

configfile="$BASTION_ETC_DIR/osh-sync-watcher.sh"
if [ ! -e "$configfile" ] ; then
    # to allow for smooth upgrades, look for the old file name if new is not found
    configfile="$BASTION_ETC_DIR/sync-watcher.sh"
    if [ ! -e "$configfile" ] ; then
        echo "No configuration found, exiting"
        exit 0
    fi
fi

rsyncfilterfile="$BASTION_ETC_DIR/osh-sync-watcher.rsyncfilter"
if [ ! -e "$rsyncfilterfile" ] ; then
    # to allow for smooth upgrades, look for the old file name if new is not found
    rsyncfilterfile="$BASTION_ETC_DIR/sync-watcher-rsync.filter"
    if [ ! -e "$rsyncfilterfile" ] ; then
        echo "No rsync filter file found, exiting"
        exit 0
    fi
fi

# set default values
logdir=""
syslog="local6"
enabled=0
timeout=120
rshcmd=""
remoteuser="bastionsync"
remotehostlist=""
# old deprecated config param:
remotehost=""

# load configuration
# shellcheck source=etc/bastion/osh-sync-watcher.sh.dist
. "$configfile"

# if a logdir is defined, tail to the log
# shellcheck disable=SC2154
if [ -n "$logdir" ]; then
    mkdir -p "$logdir"
    exec &>> >(tee -a "$logdir/osh-sync-watcher.log")
fi

# if a syslog facility is defined, set the proper variable
# so that _log _warn and _err do log to syslog,
# also don't talk on stdout
if [ -n "$syslog" ]; then
    LOG_FACILITY="$syslog"
    LOG_QUIET=1
fi

if [ "$enabled" != "1" ] ; then
        _log "Script is not enabled (review the config in $configfile if needed)"
        exit 0
fi

# check that rshcmd is not empty after loading the config
if [ -z "$rshcmd" ]; then
    _err "The 'rshcmd' mandatory config value is empty, please review the configuration ($configfile)"
    exit 1
fi

# is another copy of myself still running ?
if [ -e "$PIDFILE" ] ; then
    oldpid=$(head -1 "$PIDFILE")
    if kill -0 -- "$oldpid" ; then
        _log "Another copy of myself is running ($oldpid), exiting"
        exit 0
    else
        _log "Another copy of myself apparently died ($oldpid), cleaning up"
    fi
fi
# shellcheck disable=SC2064
trap "rm -f $PIDFILE" EXIT
rm -f "$PIDFILE"
# race condition here ... but /var/run is writable only by root
echo "$$" > "$PIDFILE"

while :
do
        _log "Watching for changes (timeout: $timeout)..."
        # we'll cap to the max allowed
        maxfiles=$(test -r /proc/sys/fs/inotify/max_user_watches && cat /proc/sys/fs/inotify/max_user_watches || echo 4096)
        {
            # account/group creation/deletion:
            echo /etc/passwd
            echo /etc/group
            echo /home/allowkeeper
            echo /home/keykeeper
            echo /home/passkeeper
            # all allowed.ip files of bastion groups:
            for grouphome in $(getent group | grep -Eo '^key[a-zA-Z0-9_-]+' | grep -Ev -- '-(aclkeeper|gatekeeper|owner)$' | sed 's=^=/home/='); do
                test -e "$grouphome/allowed.ip" && echo "$grouphome/allowed.ip"
            done
            # all authorized_keys files of bastion accounts:
            for accounthome in $(getent passwd | grep ":$basedir/bin/shell/osh.pl\$" | cut -d: -f6); do
                test -f "$accounthome/$AK_FILE" && echo "$accounthome/$AK_FILE"
            done
        } | head -"$maxfiles" | timeout "$timeout" inotifywait -e close_write -e moved_to -e create -e delete -e delete_self --quiet --recursive --csv --fromfile - ; ret=$?
        if [ "$ret" = 124 ] ; then
                _log "... timed out, syncing just in case!"
        elif [ "$ret" = 0 ] ; then
                _log "... got event, syncing in 3 secs!"
                sleep 3
        else
                _warn "... got weird return value $ret (maxfiles=$maxfiles); sleeping a bit..."
                sleep "$timeout"
        fi
        # sanity check myself before
        if [ ! -d /home/allowkeeper ] || ! [ -d /home/keykeeper ] || ! [ -d /home/logkeeper ] || \
          [ "$(find /home -mindepth 2 -maxdepth 2 -type f -name lastlog 2>/dev/null | wc -l)" = 0 ] ; then
            _log "Own sanity check failed (maybe I'm locked?), not syncing and sleeping"
            sleep "$timeout"
            continue
        fi
        # /sanity
        _log "Starting sync!"
        # shellcheck disable=SC2154
        [ -z "$remotehostlist" ] && remotehostlist="$remotehost"
        # shellcheck disable=SC2206
        remotehosts=( $remotehostlist )
        remotehostslen=${#remotehosts[@]}
        nberrs=0
        for i in "${!remotehosts[@]}"
        do
            remote=${remotehosts[i]}
            if echo "$remote" | grep -q ':'; then
                remoteport=$(echo "$remote" | cut -d: -f2)
                remote=$(echo "$remote" | cut -d: -f1)
            else
                remoteport=22
            fi

            _log "$remote: [Server $((i+1))/$remotehostslen - Step 1/3] syncing needed data..."
            rsync -vaA --numeric-ids --delete --filter "merge $rsyncfilterfile" --rsh "$rshcmd -p $remoteport" / "$remoteuser@$remote:/"; ret=$?
            _log "$remote: [Server $((i+1))/$remotehostslen - Step 1/3] sync ended with return value $ret"
            if [ "$ret" != 0 ]; then (( ++nberrs )); fi

            _log "$remote: [Server $((i+1))/$remotehostslen - Step 2/3] syncing lastlog files from master to slave, only if master version is newer..."
            rsync -vaA --numeric-ids --update --include '/' --include '/home/' --include '/home/*/' --include '/home/*/lastlog' \
                --exclude='*' --rsh "$rshcmd -p $remoteport" / "$remoteuser@$remote:/"; ret=$?
            _log "$remote: [Server $((i+1))/$remotehostslen - Step 2/3] sync ended with return value $ret"
            if [ "$ret" != 0 ]; then (( ++nberrs )); fi

            _log "$remote: [Server $((i+1))/$remotehostslen - Step 3/3] syncing lastlog files from slave to master, only if slave version is newer..."
            find /home -mindepth 2 -maxdepth 2 -type f -name lastlog | rsync -vaA --numeric-ids --update --prune-empty-dirs --include='/' \
                --include='/home' --include='/home/*/' --include-from=- --exclude='*' --rsh "$rshcmd -p $remoteport" "$remoteuser@$remote:/" /; ret=$?
            _log "$remote: [Server $((i+1))/$remotehostslen - Step 3/3] sync ended with return value $ret"
            if [ "$ret" != 0 ]; then (( ++nberrs )); fi
        done

        if [ "$nberrs" = 0 ]; then
            _log "All secondaries have been synchronized successfully"
        else
            _err "Encountered $nberrs error(s) while synchronizing, see above"
        fi
done
