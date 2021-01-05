#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

action_doing "Checking list of needed Perl modules..."

missing=""

# shellcheck disable=SC2013
for module in $(grep -RhEw '(use|require) ([a-zA-Z][a-zA-Z0-9_:]+)' "$basedir/lib/perl/" "$basedir/bin/" | \
    grep -v -e '"' -e "'" -e '# pragma optional module' -e OVH:: | \
    sed -re 's/#.*//' | \
    grep -Eo '(use|require) ([a-zA-Z][a-zA-Z0-9_:]+)' | \
    awk '{print $2}' | \
    sort -u | \
    grep -Ev '^[a-z0-9_]+$')
do
    if [ "$1" != "corelist" ]; then
        action_detail "$module"
        if ! perl -M"$module" -e 1; then
            action_detail "... failed!"
            missing="$missing $module"
        fi
    else
        if corelist "$module" | grep -q 'not in CORE'; then
            action_detail "$module"
        fi
    fi
done

if [ -n "$missing" ]; then
    action_error "Missing modules:$missing"
else
    # shellcheck disable=SC2119
    action_done
fi
