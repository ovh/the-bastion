#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck disable=SC2119
set -e

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

action="$1"
type="$2"
name="$3"

die_usage() {
    echo "Usage: $0 <create|delete> <account|group> [name]" >&2
    exit 1
}

manage_account_sudoers()
{
    todo="$1"
    account="$2"

    # for accounts containing a ".", we need to do a little transformation
    # as files containing a dot are ignored by sudo
    normalized_account=$(sed -re 's/[^A-Z0-9_]/_/gi' <<< "$account")
    # as we're reducing the amount of possible chars in normalized_account
    # we could have collisions: use MD5 to generate a uniq suffix
    account_suffix=$(md5sum_compat - <<< "$account" | cut -c1-6)
    normalized_account="${normalized_account}_${account_suffix}"
    dst="$SUDOERS_DIR/osh-account-$normalized_account"

    # for delete, don't check if account is valid:
    # our caller might be in the process of deleting it
    if [ "$todo" = delete ]; then
        action_detail "... deleting $dst"
        rm -f "$dst"
        return $?
    fi

    # otherwise, for create, we expect the account to exist
    if ! getent passwd "$account" | grep -q ":$basedir/bin/shell/osh.pl$"; then
        action_error "$account is not a bastion account"
        return 1
    fi

    if [ -e "$dst" ]; then
        action_detail "... overwriting $dst"
    else
        action_detail "... generating $dst"
    fi

    # within the sudoers file, for variables, lowercase is prohibited,
    # names can only contain [A-Z0-9_], case sensitive, so we got a step further
    normalized_account=$(tr '[:lower:]' '[:upper:]' <<< "$normalized_account")
    # to avoid race conditions between this generation and master/slave sync,
    # first prepare our file as a .tmp (sudo ignores files containing a '.')
    touch "${dst}.tmp"
    chmod 0440 "${dst}.tmp"
    {
        echo "# generated from install script"
        echo "# ACCOUNTNAME=$account"
        for template in $(find "$basedir/etc/sudoers.account.template.d/" -type f -name "*.sudoers" | sort)
        do
            # if $template has two dots, then it's of the form XXX-name.$os.sudoers,
            # in that case we only include this template if $os is our current OS
            if [ "$(basename "$template" | cut -d. -f3)" = "sudoers" ]; then
                if [ "$(basename "$template" | cut -d. -f2 | tr '[:upper:]' '[:lower:]')" != "$(echo "$OS_FAMILY" | tr '[:upper:]' '[:lower:]')" ]; then
                    # not the same OS, skip it
                    continue
                fi
            fi
            echo
            echo "# $template:"
            perl -pe "s!%ACCOUNT%!$account!g;s!%NORMACCOUNT%!$normalized_account!g;s!%BASEPATH%!$basedir!g" "$template"
        done
    } > "${dst}.tmp"
    # then move the file to its final name (potentially overwriting a previous file of the same name)
    mv -f "${dst}.tmp" "$dst"
    # if we have a OLD_SUDOERS file defined, remove the filename from it
    if [ -n "$OLD_SUDOERS" ]; then
        sed_compat "/$(basename "$dst")$/d" "$OLD_SUDOERS"
    fi
    return 0
}

manage_group_sudoers()
{
    todo="$1"
    group="$2"

    # for groups containing a ".", we need to do a little transformation
    # as files containing a dot are ignored by sudo
    normalized_group=$(sed -re 's/[^A-Z0-9_]/_/gi' <<< "$group")
    # as we're reducing the amount of possible chars in normalized_group
    # we could have collisions: use MD5 to generate a uniq suffix
    group_suffix=$(md5sum_compat - <<< "$group" | cut -c1-6)
    normalized_group="${normalized_group}_${group_suffix}"
    dst="$SUDOERS_DIR/osh-group-$normalized_group"

    # for delete, don't check if the group is valid:
    # our caller might be in the process of deleting it
    if [ "$todo" = delete ]; then
        action_detail "... deleting $dst"
        rm -f "$dst"
        return $?
    fi

    # for create, we expect the group to exist
    if ! test -f "/home/$group/allowed.ip"; then
        action_error "$group doesn't seem to be a valid bastion group"
        return 1
    fi

    if [ -e "$dst" ]; then
        action_detail "... overwriting $dst"
    else
        action_detail "... generating $dst"
    fi

    # within the sudoers file, for variables, lowercase is prohibited,
    # names can only contain [A-Z0-9_], case sensitive, so we got a step further
    normalized_group=$(tr '[:lower:]' '[:upper:]' <<< "$normalized_group")
    # to avoid race conditions between this generation and master/slave sync,
    # first prepare our file as a .tmp (sudo ignores files containing a '.')
    touch "${dst}.tmp"
    chmod 0440 "${dst}.tmp"
    {
        echo "# generated from install script"
        echo "# GROUPNAME=$group"
        for template in $(find "$basedir/etc/sudoers.group.template.d/" -type f | sort)
        do
            echo
            echo "# $template:"
            perl -pe "s!%GROUP%!$group!g;s!%BASEPATH%!$basedir!g" "$template"
        done
    } > "${dst}.tmp"
    # then move the file to its final name (potentially overwriting a previous file of the same name)
    mv -f "${dst}.tmp" "$dst"
    # if we have a OLD_SUDOERS file defined, remove the filename from it
    if [ -n "$OLD_SUDOERS" ]; then
        sed_compat "/$(basename "$dst")$/d" "$OLD_SUDOERS"
    fi
    return 0
}

if [ -z "$type" ]; then
    die_usage
fi

nbfailed=0
if [ "$type" = group ]; then
    if [ -z "$name" ]; then
        if [ "$action" = create ]; then
            action_doing "Regenerating all groups sudoers files from templates"
            for group in $(getent group | cut -d: -f1 | grep -- '-gatekeeper$' | sed -e 's/-gatekeeper$//' | sort); do
                manage_group_sudoers create "$group" || nbfailed=$((nbfailed + 1))
            done
        elif [ "$action" = delete ]; then
            echo "Cowardly refusing to delete all group sudoers, a man needs a name" >&2
            die_usage
        fi
    else
        if [ "$action" = create ]; then
            action_doing "Regenerating group '$name' sudoers file from templates"
            manage_group_sudoers create "$name" || nbfailed=$((nbfailed + 1))
        elif [ "$action" = delete ]; then
            action_doing "Deleting group '$name' sudoers file"
            manage_group_sudoers delete "$name"
        fi
    fi
    if [ "$nbfailed" != 0 ]; then
        action_error "Failed generating $nbfailed sudoers"
    else
        action_done
    fi
    exit $nbfailed
elif [ "$type" = account ]; then
    if [ -z "$name" ]; then
        if [ "$action" = create ]; then
            action_doing "Regenerating all accounts sudoers files from templates"
            for account in $(getent passwd | grep ":$basedir/bin/shell/osh.pl$" | cut -d: -f1 | sort); do
                manage_account_sudoers create "$account"|| nbfailed=$((nbfailed + 1))
            done
        elif [ "$action" = delete ]; then
            echo "Cowardly refusing to delete all account sudoers, a man needs a name" >&2
            die_usage
        fi
    else
        if [ "$action" = create ]; then
            action_doing "Regenerating account '$name' sudoers file from templates"
            manage_account_sudoers create "$name"|| nbfailed=$((nbfailed + 1))
        elif [ "$action" = delete ]; then
            action_doing "Deleting account '$name' sudoers file"
            manage_account_sudoers delete "$name"
        fi
    fi
    if [ "$nbfailed" != 0 ]; then
        action_error "Failed generating $nbfailed sudoers"
    else
        action_done
    fi
    exit $nbfailed
else
    echo "Invalid type specified" >&2
    die_usage
fi
