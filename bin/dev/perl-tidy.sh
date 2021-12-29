#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
set -ueo pipefail

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

cd "$basedir" || exit 254

# $1:
# - tidy, actually tidy the files in place
# - test, tell whether the files are tidy without modifying them in place

# $2:
# - (empty), tidy all files
# - anything_else, tidy this file

if [ "${1:-}" = "test" ]; then
    params=""
    action_doing "Checking perl tidiness"
elif [ "${1:-}" = "tidy" ]; then
    params="--backup-and-modify-in-place --backup-file-extension=/tidybak"
    action_doing "Tidying perl files"
else
    echo "Usage: $0 <test|tidy> [one_file_name]" >&2
    exit 1
fi

params="$params \
    --paren-tightness=2 \
    --square-bracket-tightness=2 \
    --brace-tightness=2 \
    --maximum-line-length=180 \
"

if [ -z "${2:-}" ]; then
    # run on all perl files
    # shellcheck disable=SC2086
    find . -type f ! -name "*.tdy" ! -name "*.ERR" ! -name "$(basename "$0")" -print0 | \
        xargs -r0 grep -l 'set filetype=perl' -- | \
        xargs -r perltidy $params
else
    # run on only one file
    action_detail "${BLUE}$2${NOC}"
    # shellcheck disable=SC2086
    perltidy $params "$2"
fi

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
