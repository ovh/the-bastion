#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
set -e

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

LOG_FACILITY=local6

trap "_err 'Unexpected termination!'" EXIT

_log "Terminating lingering sessions..."

tokill=''
nb=0
# shellcheck disable=SC2162
while read etimes pid tty
do
    if [ "$tty" = "?" ] && [ "$etimes" -gt 86400 ]; then
        tokill="$tokill $pid"
        (( nb++ ))
    fi
done < <(ps -C ttyrec -o etimes,pid,tty --no-header)
if [ -n "$tokill" ]; then
    # shellcheck disable=SC2086
    kill $tokill
    _log "Terminated $nb orphan ttyrec sessions (pids$tokill)"
fi

tokill=''
nb=0
# shellcheck disable=SC2162
while read etimes pid tty user
do
    if [ "$tty" = "?" ] && [ "$user" != "root" ] && [ "$etimes" -gt 86400 ]; then
        if [ "$(ps --no-header --ppid "$pid" | wc -l)" = 0 ]; then
            tokill="$tokill $pid"
            (( nb++ ))
        fi
    fi
done < <(ps -C sshd --no-header -o etimes,pid,tty,user)
if [ -n "$tokill" ]; then
    # shellcheck disable=SC2086
    kill $tokill
    _log "Terminated $nb orphan sshd sessions (pids$tokill)"
fi

_log "Done"
trap - EXIT
