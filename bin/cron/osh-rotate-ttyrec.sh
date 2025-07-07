#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
set -e

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

# default config values for this script
:

# set error trap, read config, setup logging, exit early if script is disabled, etc.
script_init osh-rotate-ttyrec config_optional check_secure_lax

if [ "$1" = "--big-only" ]; then
    _log "Rotating big ttyrec files..."
    tokill=''
    nb=0
    # shellcheck disable=SC2034
    while read -r command pid user fd type device size node name
    do
        if echo "$size" | grep -qE '^[0-9]+$' && [ "$size" -gt 100000000 ]; then
            tokill="$tokill $pid"
            (( ++nb ))
        fi
    done < <(lsof -a -n -c ttyrec -- /home/ 2>/dev/null)
    if [ -n "$tokill" ]; then
        _log "Rotating $nb big ttyrec files..."
        # add || true to avoid script termination due to TOCTTOU and set -e
        # shellcheck disable=SC2086
        kill -USR1 $tokill || true
    fi
else
    _log "Rotating all ttyrec files..."
    if pkill -USR1 ttyrec; then
        _log "Rotation done"
    else
        _log "No ttyrec files to rotate"
    fi
fi

exit_success
