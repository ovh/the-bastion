#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

from=$1
to=$2

if [ -n "$3" ] || [ -z "$2" ] ; then
    echo "Usage: $0 original_group_name new_group_name"
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
getent group "key$from" >/dev/null  || fail "group key$from doesn't exist"
getent group "key$to"   >/dev/null  && fail "group key$to already exists"
if [ "$OS_FAMILY" = FreeBSD ]; then
    _run pw groupmod -n "key$from" -l "key$to"
else
    _run groupmod -n "key$to" "key$from"
fi


getent passwd "key$from" >/dev/null || fail "user key$from doesn't exist"
getent passwd "key$to"   >/dev/null && fail "user key$to already exists"
test -d "/home/key$from" || fail "directory /home/key$from doesn't exists"
test -d "/home/key$to"   && fail "directory /home/key$to already exists"
if [ "$OS_FAMILY" = FreeBSD ]; then
    # FreeBSD doesn't move the home on rename, do it ourselves
    _run mv -v "/home/key$from" "/home/key$to"
    _run pw usermod -n "key$from" -d /home/"key$to" -l "key$to"
else
    _run usermod -m -d /home/"key$to" -l "key$to" "key$from"
fi

for suffix in gatekeeper aclkeeper owner; do
    if getent group "key$from-$suffix" >/dev/null ; then
        getent group "key$to-$suffix"   >/dev/null && fail "group key$to-$suffix already exists"
        if [ "$OS_FAMILY" = FreeBSD ]; then
            _run pw groupmod -n "key$from-$suffix" -l "key$to-$suffix"
        else
            _run groupmod -n "key$to-$suffix" "key$from-$suffix"
        fi
    fi
done

test -d "/home/keykeeper/key$from" || fail "directory /home/keykeeper/key$from doesn't exists"
test -d "/home/keykeeper/key$to"   && fail "directory /home/keykeeper/key$to already exists"
_run mv -v "/home/keykeeper/key$from" "/home/keykeeper/key$to"

keykeeper="/home/keykeeper/key$from"
[ "$really_run_commands" = "1" ] && keykeeper="/home/keykeeper/key$to"
# shellcheck disable=SC2044
for key in $(find "$keykeeper"/ -type f -name "id_*$from*" ! -name "*.pub")
do
    test -e "$key" || continue
    test -e "$key.pub" || fail "file $key.pub doesn't exist"
    keyto=$(echo "$key" | sed -re "s/(id_.*)$from/\\1$to/")
    test -e "$keyto"     && fail "file $keyto already exists"
    test -e "$keyto.pub" && fail "file $keyto.pub already exists"
    _run mv -v "$key" "$keyto"
    _run mv -v "$key.pub" "$keyto.pub"
done

for account in /home/allowkeeper/*/
do
    fromfile="$account/allowed.partial.$from"
    tofile="$account/allowed.partial.$to"
    test -e "$fromfile" || continue
    test -e "$tofile" && fail "file $tofile already exists"
    _run mv -v "$fromfile" "$tofile"
done

for account in /home/allowkeeper/*/
do
    fromfile="$account/allowed.ip.$from"
    tofile="$account/allowed.ip.$to"
    test -L "$fromfile" || continue
    test -e "$tofile" && fail "file $tofile already exists"
    _run rm -vf "$fromfile"
    _run ln -vs "/home/key$to/allowed.ip" "$tofile"
done

_run "$basedir"/bin/sudogen/generate-sudoers.sh create group "key$to"
_run "$basedir"/bin/sudogen/generate-sudoers.sh delete group "key$from"
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
