#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

from=$1
to=$2

if [ -n "$3" ] || [ -z "$2" ] ; then
    echo "Usage: $0 original_account_name new_account_name"
    exit 2
fi

fail()
{
    echo "Error, will not proceed: $*"
    exit 1
}

really_run_commands=0

finalret=0
_run()
{
    local ret
    if [ "$really_run_commands" = "1" ] ; then
        echo "Executing: $*"
        "$@"; ret=$?
        echo "... return code: $ret"
        if [ "$ret" -ne 0 ]; then
            (( ++finalret ))
        fi
    else
        echo "DRY RUN: would execute: $*"
    fi
}

batchrun()
{
# first, rename the main account group
getent group "$from" >/dev/null  || fail "group $from doesn't exist"
getent group "$to"   >/dev/null  && fail "group $to already exists"
if [ "$OS_FAMILY" = FreeBSD ]; then
    _run pw groupmod -n "$from" -l "$to"
else
    _run groupmod -n "$to" "$from"
fi

# then, rename the account itself
getent passwd "$from" >/dev/null || fail "user $from doesn't exist"
getent passwd "$to"   >/dev/null && fail "user $to already exists"
test -d "/home/$from" || fail "directory /home/$from doesn't exist"
test -d "/home/$to"   && fail "directory /home/$to already exists"
if [ "$OS_FAMILY" = FreeBSD ]; then
    # FreeBSD doesn't move the home on rename, do it ourselves
    _run mv -v "/home/$from" "/home/$to"
    _run pw usermod -n "$from" -d /home/"$to" -l "$to"
else
    _run usermod -m -d /home/"$to" -l "$to" "$from"
fi

# then, rename all other groups linked to the account (appart from the main one already done)
# shellcheck disable=SC2043
for suffix in tty; do
    if getent group "$from-$suffix" >/dev/null ; then
        getent group "$to-$suffix"   >/dev/null && fail "group $to-$suffix already exists"
        if [ "$OS_FAMILY" = FreeBSD ]; then
            _run pw groupmod -n "$from-$suffix" -l "$to-$suffix"
        else
            _run groupmod -n "$to-$suffix" "$from-$suffix"
        fi
    fi
done

# now handle the allowkeeper folder of the account
test -d "/home/allowkeeper/$from" || fail "directory /home/allowkeeper/$from doesn't exist"
test -d "/home/allowkeeper/$to"   && fail "directory /home/allowkeeper/$to already exists"
_run mv -v "/home/allowkeeper/$from" "/home/allowkeeper/$to"

# if the account has passwords, handle them: filenames contain the account name
passdir="/home/$from/pass"
[ "$really_run_commands" = "1" ] && passdir="/home/$to/pass"
if [ -d "$passdir" ]; then
    pushd "$passdir" >/dev/null || exit 1
    # shellcheck disable=SC2044
    for passfile in $(find . -type f -name "$from" -print -o -type f -name "$from.*" -print)
    do
        _run mv -v "$passfile" "${passfile/$from/$to}"
    done
    popd >/dev/null || exit 1
fi

# finally, regenerate the account's sudoers
_run "$basedir"/bin/sudogen/generate-sudoers.sh create account "$to"
_run "$basedir"/bin/sudogen/generate-sudoers.sh delete account "$from"
}


really_run_commands=0
batchrun
echo
echo "OK to proceed? (CTRL+C to abort)"
# shellcheck disable=SC2034
read -r ___
really_run_commands=1
batchrun
echo "Done."
exit $finalret
