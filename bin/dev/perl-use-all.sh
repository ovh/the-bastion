#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

# shellcheck disable=SC2013
modules=$(
    grep -RhEw '(use|require) ([a-zA-Z][a-zA-Z0-9_:]+)' "$basedir/lib/perl/" "$basedir/bin/" | \
    grep -v -e '"' -e "'" -e '# pragma optional module' -e OVH:: | \
    sed -re 's/#.*//' | \
    grep -Eo '(use|require) ([a-zA-Z][a-zA-Z0-9_:]+)' | \
    awk '{print $2}' | \
    sort -u | \
    grep -Ev '^[a-z0-9_]+$'
)

if [ "$1" = "corelist" ]; then
    action_doing "Computing list of non-CORE needed Perl modules..."
    # shellcheck disable=SC2086
    for module in $(corelist $modules | awk '/was not in CORE/ {print $1}' | sort); do
        action_detail "$module"
    done
else
    action_doing "Checking whether all required modules are installed..."
    perlcmdline="perl "
    for module in $modules; do
        action_detail "$module"
        perlcmdline="$perlcmdline -M$module"
    done
    perlcmdline="$perlcmdline -e 1"

    if ! $perlcmdline; then
        action_error "Some modules are missing!"
        exit 1
    else
        action_done ""
    fi
fi
