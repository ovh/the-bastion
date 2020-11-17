#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck disable=SC2119
set -e

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

type="$1"
name="$2"

die_usage() {
    echo "Usage: $0 <account|group> [name]" >&2
    exit 1
}

generate_account_sudoers()
{
    account="$1"
    if ! getent passwd "$account" | grep -q ":$basedir/bin/shell/osh.pl$"; then
        action_error "$account is not a bastion account"
        return 1
    fi
    dst="$SUDOERS_DIR/osh-account-$account"
    if [ -e "$dst" ]; then
        action_detail "... overwriting $dst"
    else
        action_detail "... generating $dst"
    fi
    # normalized account only contain [A-Z0-9_], case sensitive
    normalized_account=$(sed -re 's/[^A-Z0-9_]/_/gi' <<< "$account")
    # as we're reducing the amount of possible chars in normalized_account
    # we could have collisions: use MD5 to generate a uniq suffix
    account_suffix=$(md5sum_compat - <<< "$account" | cut -c1-6)
    normalized_account="${normalized_account}_${account_suffix}"
    # lowercase is prohibited
    normalized_account=$(tr '[:lower:]' '[:upper:]' <<< "$normalized_account")
    # to avoid race conditions between this generation and master/slave sync,
    # first prepare our file as a .tmp (sudo ignores files containing a '.')
    touch "${dst}.tmp"
    chmod 0440 "${dst}.tmp"
    {
        echo "# generated from install script"
        for template in $(find "$basedir/etc/sudoers.account.template.d/" -type f | sort)
        do
            echo
            echo "# $template:"
            perl -pe "s!%ACCOUNT%!$account!g;s!%NORMACCOUNT%!$normalized_account!g;s!%BASEPATH%!$basedir!g" "$template"
        done
    } > "${dst}.tmp"
    # then move the file to its final name (potentially overwriting a previous file of the same name)
    mv -f "${dst}.tmp" "$dst"
    return 0
}

generate_group_sudoers()
{
    group="$1"
    if ! test -f "/home/$group/allowed.ip"; then
        action_error "$group doesn't seem to be a valid bastion group"
        return 1
    fi
    if ! getent group "$group-gatekeeper" >/dev/null; then
        action_error "$group doesn't have a $group-gatekeeper counterpart"
        return 1
    fi
    dst="$SUDOERS_DIR/osh-group-$group"
    if [ -e "$dst" ]; then
        action_detail "... overwriting $dst"
    else
        action_detail "... generating $dst"
    fi
    # to avoid race conditions between this generation and master/slave sync,
    # first prepare our file as a .tmp (sudo ignores files containing a '.')
    touch "${dst}.tmp"
    chmod 0440 "${dst}.tmp"
    {
        echo "# generated from install script"
        for template in $(find "$basedir/etc/sudoers.group.template.d/" -type f | sort)
        do
            echo
            echo "# $template:"
            perl -pe "s!%GROUP%!$group!g;s!%BASEPATH%!$basedir!g" "$template"
        done
    } > "${dst}.tmp"
    # then move the file to its final name (potentially overwriting a previous file of the same name)
    mv -f "${dst}.tmp" "$dst"
    return 0
}

if [ -z "$type" ]; then
    die_usage
fi

nbfailed=0
if [ "$type" = group ]; then
    if [ -z "$name" ]; then
        action_doing "Regenerating all groups sudoers files from templates"
        for group in $(getent group | cut -d: -f1 | grep -- '-gatekeeper$' | sed -e 's/-gatekeeper$//'); do
            generate_group_sudoers "$group" || nbfailed=$((nbfailed + 1))
        done
    else
        action_doing "Regenerating group '$name' sudoers file from templates"
        generate_group_sudoers "$name" || nbfailed=$((nbfailed + 1))
    fi
    if [ "$nbfailed" != 0 ]; then
        action_error "Failed generating $nbfailed sudoers"
    else
        action_done
    fi
    exit $nbfailed
elif [ "$type" = account ]; then
    if [ -z "$name" ]; then
        action_doing "Regenerating all accounts sudoers files from templates"
        for account in $(getent passwd | grep ":$basedir/bin/shell/osh.pl$" | cut -d: -f1); do
            generate_account_sudoers "$account"|| nbfailed=$((nbfailed + 1))
        done
    else
        action_doing "Regenerating account '$name' sudoers file from templates"
        generate_account_sudoers "$name"|| nbfailed=$((nbfailed + 1))
    fi
    if [ "$nbfailed" != 0 ]; then
        action_error "Failed generating $nbfailed sudoers"
    else
        action_done
    fi
    exit $nbfailed
fi

die_usage
