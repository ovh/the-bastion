#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
set -e

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

if [ -z "$2" ] || [ -n "$3" ]; then
    echo "Usage: $0 <NAME> <UID>"
    echo "Note: UID can be the special value 'AUTO'"
    exit 1
fi

if [ "$2" = AUTO ] || [ "$2" = auto ]; then
    USER=root HOME=/root "$basedir/bin/plugin/restricted/accountCreate" '' '' '' '' --uid-auto --account "$1"
else
    USER=root HOME=/root "$basedir/bin/plugin/restricted/accountCreate" '' '' '' '' --uid "$2" --account "$1"
fi

"$basedir"/bin/admin/grant-all-restricted-commands-to.sh "$1"

add_user_to_group_compat "$1" "osh-admin"

sed_compat 's/^"adminAccounts": \[\]/"adminAccounts": ["'"$1"'"]/' "$BASTION_ETC_DIR/bastion.conf"
