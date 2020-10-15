#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
account=$1
toggle=$2

_help()
{
    echo "$0 <account> <on|off>"
    exit 1
}

[ -z "$toggle" ] && _help

if [ ! -d "/home/$account" ] ; then
    echo "/home/$account not found"
    exit 1
fi

if [ "$toggle" = on ] ; then
    echo yes > "/home/$account/config.debug"
    chown "$account":"$account" "/home/$account/config.debug"
    echo "debug enabled for $account"
elif [ "$toggle" = off ] ; then
    rm -f "/home/$account/config.debug"
    echo "debug disabled for $account"
else
    echo "Unknown toggle ($toggle)"
    _help
fi

exit 0
