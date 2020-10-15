#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

unset dockertag
if [ "$1" = "docker" ]; then
    dockertag=v0.7.1
fi
if [ -n "$2" ]; then
    dockertag="$2"
fi

(( fails=0 ))
if [ -n "$dockertag" ]; then
    action_doing "Checking shell files syntax using shellcheck:$dockertag docker"
else
    action_doing "Checking shell files syntax"
fi

cd "$basedir" || exit 254
for i in $(find . -type f ! -name "*.swp" -print0 | xargs -r0 grep -l 'set filetype=sh')
do
    action_detail "${BLUE}$i${NOC}"
    if [ -n "$dockertag" ]; then
        docker run --rm -v "$PWD:/mnt" "koalaman/shellcheck:$dockertag" -Calways -W 0 -x -o deprecate-which,avoid-nullary-conditions,add-default-case "$i"; ret=$?
    else
        shellcheck -x "$i"; ret=$?
    fi
    if [ "$ret" != 0 ]; then
        (( fails++ ))
    fi
done

if [ "$fails" -ne 0 ] ; then
    action_error "Got $fails errors"
else
    action_done "success"
fi
exit "$fails"
