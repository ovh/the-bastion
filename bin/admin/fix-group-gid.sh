#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# This script ensures that GIDs of bastion groups (including their group system
# roles) are higher than the configured groupGidMin value.
# It shifts group GIDs from the low range (where they may collide with reserved
# account UIDs) to the high range defined by groupGidMin.
set -e

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

MINGID=$(perl -I"$basedir/lib/perl" -MOVH::Bastion -e 'print OVH::Bastion::config("groupGidMin")->value')

if [ -n "$2" ] || [ -z "$1" ] ; then
    echo "Usage: $0 <groupname|ALL>"
    exit 2
fi

fail()
{
    echo "Error, will not proceed: $*"
    exit 1
}

really_run_commands=0
something_to_do=0

_run()
{
    something_to_do=1
    if [ "$really_run_commands" = "1" ] ; then
        echo "Executing: $*"
        read -r ___
        "$@"
    else
        echo "DRY RUN: would execute: $*"
    fi
}

next_available_gid=$((MINGID + 1))
find_next_available_gid()
{
    while getent group "$next_available_gid" >/dev/null; do
        next_available_gid=$((next_available_gid + 1))
    done
}

change_gid()
{
    group="$1"
    type="$2"

    maingroup=$(echo "$group" | sed -re 's/-(aclkeeper|gatekeeper|owner)//g')

    if [ "$type" != secondary ]; then
        getent passwd "$group" >/dev/null  || fail  "user $group doesn't exist"
    fi
    if [ "$type" != secondary ]; then
        getent group  "$group" >/dev/null  || fail "group $group doesn't exist"
    else
        getent group  "$group" >/dev/null  || return
    fi

    oldgid=$(getent group "$group" | awk -F: '{print $3}')

    [ "$oldgid" -ge "$MINGID" ] && return

    find_next_available_gid
    newgid=$next_available_gid

    _run group_change_gid_compat "$group" "$newgid"
    tocheck=""
    for dir in "/home/$group" "/home/keykeeper/$group" "/home/$maingroup" "/home/keykeeper/$maingroup"; do
        test -d "$dir" && tocheck="$tocheck $dir"
    done
    if [ -n "$tocheck" ]; then
        # shellcheck disable=SC2086
        _run find $tocheck -gid "$oldgid" -exec chgrp "$group" '{}' \;
    fi

    if command -v getfacl >/dev/null && command -v setfacl >/dev/null; then
        ( cd / ; _run sh -c "getfacl /home/$maingroup 2>/dev/null | sed -re 's/:$oldgid:/:$group:/' | setfacl --restore=-" )
    fi
}

batchrun()
{
    something_to_do=0
    change_gid "key$from"
    change_gid "key$from-gatekeeper" secondary
    change_gid "key$from-aclkeeper"  secondary
    change_gid "key$from-owner"      secondary
}

main()
{
    from=$(echo "$from" | sed -re 's/^key//')

    if [ "$from" = "keeper" ] || [ "$from" = "reader" ]; then
        echo "$from: special group, skipping."
        return
    fi

    really_run_commands=0
    batchrun

    if [ "$something_to_do" = 0 ]; then
        echo "$from: nothing to do."
        return
    fi

    if [ -z "${DRY_RUN:-}" ] || [ "$DRY_RUN" = 0 ]; then
        echo
        echo "$group: OK to proceed? (CTRL+C to abort). You'll still have to validate each commands I'm going to run"
        # shellcheck disable=SC2034
        read -r ___
        really_run_commands=1
        batchrun
        echo "$group: done."
    fi
}

if [ "$1" = "ALL" ]; then
    groups=$(getent group | grep "^key" | cut -d: -f1 | grep -Ev -- '-(aclkeeper|gatekeeper|owner)$')
    for from in $groups
    do
        main
    done
else
    from="$1"
    main
fi

