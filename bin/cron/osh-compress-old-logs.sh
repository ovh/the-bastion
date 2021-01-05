#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

LOG_FACILITY=local6

trap "_err 'Unexpected termination!'" EXIT

_log "Compressing old sqlite databases..."

while IFS= read -r -d '' sqlite
do
    _log "Working on $sqlite..."
    if ! gzip "$sqlite"; then
        _log "Error while trying to compress $sqlite"
    fi
done < <(find /home/ -mindepth 2 -maxdepth 2 -type f -name "*-log-??????.sqlite" -mtime +31 -print0)

# also compress homedir logs that haven't been touched since 30 days, every day
while IFS= read -r -d '' log
do
    _log "Working on $log..."
    command -v chattr >/dev/null && chattr -a "$log"
    if ! gzip "$log"; then
        _log "Error while trying to compress $log"
    fi
done < <(find /home/ -mindepth 2 -maxdepth 2 -type f -name "*-log-??????.log" -mtime +31 -print0)

if command -v chattr >/dev/null; then
    # then protect back all the logs
    _log "Setting +a back on all the logs"
    find /home/ -mindepth 2 -maxdepth 2 -type f -name "*-log-??????.log" -print0 | xargs -r0 chattr +a --
fi

_log "Done"
trap - EXIT
