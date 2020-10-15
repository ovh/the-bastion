#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
set -e

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

account="$1"
if [ -z "$account" ] ; then
    echo "Usage: $0 ACCOUNT" >&2
    exit 1
fi

action_doing "Granting all restricted commands to $account"

if ! getent passwd "$account" >/dev/null ; then
    action_error "Account $account not found"
    exit 2
fi

if ! getent passwd "$account" | grep -q /osh.pl$ ; then
    action_error "Account $account doesn't seem to be a bastion account"
    exit 4
fi

if ! cd "$basedir"/bin/plugin/restricted; then
    action_error "Error trying to access the restricted plugins directory"
    exit 3
fi

allok=1
for group in auditor $(ls)
do
    echo "$group" | grep -Fq . && continue
    group="osh-$group"
    if getent group "$group" >/dev/null ; then
        if getent group "$group" | grep -qE ":$account$|:$account,|,$account,|,$account$" ; then
            action_detail "Account was already in group $group"
        else
            if add_user_to_group_compat "$account" "$group" ; then
                action_detail "Account added to group $group"
            else
                action_error "Error adding user... continuing anyway"
                allok=0
            fi
        fi
    else
        action_error "group $group doesn't exist, ignoring"
        allok=0
    fi
done

if [ "$allok" = 1 ] ; then
    action_done "$account has been granted to all restricted commands"
    exit 0
else
    action_warn "Got some errors adding $account to all restricted commands"
    exit 1
fi
