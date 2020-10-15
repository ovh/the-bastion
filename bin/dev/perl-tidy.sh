#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

cd "$basedir" || exit 1

if [ "$1" = "test" ]; then
    params=""
    action_doing "Checking perl tidiness"
else
    params="--backup-and-modify-in-place --backup-file-extension=/tidybak"
    action_doing "Tidying perl files"
fi

# shellcheck disable=SC2086
find . -type f ! -name "*.tdy" ! -name "*.ERR" ! -name "$(basename $0)" -print0 | \
    xargs -r0 grep -l 'set filetype=perl' -- | \
    xargs -r perltidy --paren-tightness=2 --square-bracket-tightness=2 --brace-tightness=2 --maximum-line-length=180 $params

bad=""
nbbad=0

if [ "$1" = "test" ]; then
    while IFS= read -r -d '' tdy
    do
        file=${tdy/.tdy/}
        if ! cmp "$file" "$tdy"; then
            diff -u "$file" "$tdy"
            bad="$bad $file"
            nbbad=$(( nbbad + 1 ))
            action_error "... $file is not tidy!"
        fi
        rm -f "$tdy"
    done <   <(find . -name "*.tdy" -type f -print0)

    if [ "$nbbad" = 0 ]; then
        action_done ""
    else
        action_error "Found $nbbad untidy files"
    fi
else
    action_done ""
fi

exit $nbbad
