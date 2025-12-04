#!/bin/sh
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
if [ "$USER" != "bastionsync" ]; then
    echo "Unexpected user, aborting" >&2
    exit 2
fi
if [ -z "$SSH_CONNECTION" ]; then
    echo "Bad environment, aborting" >&2
    exit 3
fi
if [ "$1" != "-c" ]; then
    echo "Interactive session denied, aborting" >&2
    exit 4
fi
shift
# shellcheck disable=SC2068
set -- $@
if [ "$1 $2" != "rsync --server" ]; then
    echo "Only rsync is allowed, aborting" >&2
    exit 5
fi
shift
shift
if ! cd /; then
    echo "Failed to chdir /, aborting" >&2
    exit 6
fi
exec /usr/bin/sudo -- /usr/bin/rsync --server "$@"