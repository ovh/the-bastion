#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

cd "$basedir" || exit 254

# $1:
# - docker, use shellcheck's docker
# - system, use any installed shellcheck, this is the default if not specified
# - anything_else, attempt to use shellcheck's docker with this tag

# $2:
# - (empty), check all known shell files
# - anything_else, check only this file

if [ "${1:-system}" = system ]; then
    unset dockertag
elif [ "$1" = docker ]; then
    dockertag=v0.8.0
else
    dockertag="$1"
fi

shellcheck_opts="-Calways -W 0 -x -o deprecate-which,avoid-nullary-conditions,add-default-case"

run_shellcheck() {
    local ret
    action_detail "${BLUE}$1${NOC}"
    if [ -n "${dockertag:-}" ]; then
        # shellcheck disable=SC2086
        docker run --rm -v "$PWD:/mnt" "koalaman/shellcheck:$dockertag" $shellcheck_opts "$1"; ret=$?
    else
        # shellcheck disable=SC2086
        shellcheck $shellcheck_opts "$1"; ret=$?
    fi
    return $ret
}

(( fails=0 )) || true
if [ -n "${dockertag:-}" ]; then
    action_doing "Checking shell files syntax using shellcheck:$dockertag docker"
else
    action_doing "Checking shell files syntax using system shellcheck"
fi

for i in $(find ${2:-bin contrib docker install lib tests} -type f \
            ! -name "*.swp" ! -name "*.orig" ! -name "*.rej" ! -name "$(basename "$0")" -print0 \
            | xargs -r0 grep -l 'set filetype=sh' | sort)
do
    run_shellcheck "$i"; ret=$?
    if [ $ret != 0 ]; then
        (( fails++ ))
    fi
    if [ $ret = 3 ] || [ $ret = 4 ]; then
        echo "${RED}WARNING: your shellcheck seems too old (code $ret), please upgrade it or use a more recent docker tag!${NOC}" >&2
    fi
done

if [ "$fails" -ne 0 ] ; then
    action_error "Got $fails errors"
else
    action_done "success"
fi
exit "$fails"
