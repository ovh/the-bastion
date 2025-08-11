#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
set -e

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

# default config values for this script
MAX_AGE=86400

# set error trap, read config, setup logging, exit early if script is disabled, etc.
script_init osh-lingering-sessions-reaper config_optional check_secure_lax

_log "Terminating lingering sessions..."

# 1. kill ttyrec processes running for more than MAX_AGE that don't have any tty
tokill=''
nb=0
# shellcheck disable=SC2162
while read etimes pid tty comm
do
    if [ "$comm" = ttyrec ] && [ "$tty" = "?" ] && [ "$etimes" -gt "$MAX_AGE" ]; then
        tokill="$tokill $pid"
        (( ++nb ))
    fi
done < <(ps ax -o etimes,pid,tty,comm)
if [ -n "$tokill" ]; then
    # add || true to avoid script termination due to TOCTTOU and set -e
    # shellcheck disable=SC2086
    kill $tokill || true
    _log "Terminated $nb orphan ttyrec sessions (pids$tokill)"
fi

# 2. kill *user* (non-root) sshd processes running for more than MAX_AGE that don't have any tty and no children
tokill=''
nb=0
# shellcheck disable=SC2162
while read etimes pid tty user comm
do
    if [ "$comm" = sshd ] && [ "$tty" = "?" ] && [ "$user" != "root" ] && [ "$etimes" -gt "$MAX_AGE" ]; then
        # shellcheck disable=SC2009
        if ! ps ax -o ppid | grep -Fxq "$pid"; then
            tokill="$tokill $pid"
            (( ++nb ))
        fi
    fi
done < <(ps ax -o etimes,pid,tty,user,comm)
if [ -n "$tokill" ]; then
    # add || true to avoid script termination due to TOCTTOU and set -e
    # shellcheck disable=SC2086
    kill $tokill || true
    _log "Terminated $nb orphan sshd sessions (pids$tokill)"
fi

# 3. kill lingering bastion plugins running for more than MAX_AGE that don't have any tty and whose ppid is init (1)
tokill=''
nb=0
pidlist=$(pgrep -f "perl $basedir/bin/plugin" | tr "\\n" "," | sed -e s/,$//)
if [ -n "$pidlist" ]; then
    # shellcheck disable=SC2162
    while read etimes pid tty ppid
    do
        if [ "$tty" = "?" ] && [ "$ppid" = 1 ] && [ "$etimes" -gt "$MAX_AGE" ]; then
            tokill="$tokill $pid"
            (( ++nb ))
        fi
    done < <(ps -o etimes,pid,tty,ppid -p "$pidlist")
    if [ -n "$tokill" ]; then
        # add || true to avoid script termination due to TOCTTOU and set -e
        # shellcheck disable=SC2086
        kill $tokill || true
        _log "Terminated $nb orphan plugins (pids$tokill)"
    fi
fi

exit_success
