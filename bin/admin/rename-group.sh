#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
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

_run()
{
    if [ "$really_run_commands" = "1" ] ; then
        echo "Executing: $*"
        read -r ___
        "$@"
    else
        echo "DRY RUN: would execute: $*"
    fi
}

batchrun()
{
getent group "key$from" >/dev/null  || fail "group key$from doesn't exist"
getent group "key$to"   >/dev/null  && fail "group key$to already exists"
_run groupmod -n "key$to" "key$from"

getent passwd "key$from" >/dev/null || fail "user key$from doesn't exist"
getent passwd "key$to"   >/dev/null && fail "user key$to already exists"
_run usermod -l "key$to" "key$from"

if getent group "key$from-gatekeeper" >/dev/null ; then
    # key$from-gatekeeper might not exist if the group name was too long from the beginning
    getent group "key$to-gatekeeper"   >/dev/null && fail "group key$to-gatekeeper already exists"
    _run groupmod -n "key$to-gatekeeper" "key$from-gatekeeper"
fi

if getent group "key$from-owner" >/dev/null ; then
    # key$from-owner sometimes doesn't exist for old groups, so nevermind
    getent group "key$to-owner" >/dev/null && fail "group key$to-owner already exists"
    _run groupmod -n "key$to-owner" "key$from-owner"
fi

test -d "/home/key$from" || fail "directory /home/key$from doesn't exists"
test -d "/home/key$to"   && fail "directory /home/key$to already exists"
_run mv -v "/home/key$from" "/home/key$to"

test -d "/home/keykeeper/key$from" || fail "directory /home/keykeeper/key$from doesn't exists"
test -d "/home/keykeeper/key$to"   && fail "directory /home/keykeeper/key$to already exists"
_run mv -v "/home/keykeeper/key$from" "/home/keykeeper/key$to"

if test -e "/etc/sudoers.d/osh-group-key$from" ; then
    # if exists, will move it
    test -e "/etc/sudoers.d/osh-group-key$to" && fail "file /etc/sudoers.d/osh-group-key$to already exists"
    _run mv -v "/etc/sudoers.d/osh-group-key$from" "/etc/sudoers.d/osh-group-key$to"
    _run sed -i -re "s/key$from/key$to/g" "/etc/sudoers.d/osh-group-key$to"
fi

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
}


really_run_commands=0
batchrun
echo
echo "OK to proceed ? (CTRL+C to abort). You'll still have to validate each commands I'm going to run"
# shellcheck disable=SC2034
read -r ___
really_run_commands=1
batchrun
echo "Done."
