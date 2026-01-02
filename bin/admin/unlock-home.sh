#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
CONFIGFILE=/etc/bastion/luks-config.sh
# shellcheck source=etc/bastion/luks-config.sh.dist
. "$CONFIGFILE"

update_banner()
{
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl stop osh-seal-banner.service; then
            echo "SSH banner updated"
        else
            echo "Warning: Could not stop osh-seal-banner service"
        fi
    else
        if service osh-seal-banner stop; then
            echo "SSH banner updated"
        else
            echo "Warning: Could not stop osh-seal-banner service"
        fi
    fi
}

# helper to start a service
startsvc()
{
    local unit="$1"
    if command -v systemctl >/dev/null 2>&1; then
        local is_enabled
        is_enabled="$(systemctl is-enabled "$unit.service")"
        if [ "$is_enabled" = "enabled" ]; then
            if systemctl start "$unit.service"; then
                echo "Service $unit started"
            else
                echo "Warning: service $unit start failed, you might want to start it manually if needed"
            fi
        else
            echo "Service $unit is-enabled returned '$is_enabled', not starting it"
        fi
    else
        echo "No systemctl found, not attempting to start $unit"
    fi
}

do_mount()
{
    mount "$MOUNTPOINT"; ret=$?
    if [ $ret -eq 0 ] ; then
        echo "Success!"
        do_mount_post
    else
        echo "Failure... is $MOUNTPOINT correctly specified in /etc/fstab?"
    fi
    exit $ret
}

do_mount_post()
{
    # Stop the banner seal service to ensure banner is in unsealed state
    update_banner
    # Start other services (will only do something if they're enabled)
    startsvc osh-sync-watcher
    startsvc osh-http-proxy
}

if [ -z "$DEV_ENCRYPTED" ] || [ -z "$UNLOCKED_NAME" ] || [ -z "$MOUNTPOINT" ] || [ ! -d "$MOUNTPOINT" ] || [ ! -b "$DEV_ENCRYPTED" ] ; then
    echo "Not configured or badly configured (check $CONFIGFILE), nothing to do."
    exit 0
fi

if [ -e "$MOUNTPOINT/allowkeeper" ] && mountpoint -q /home ; then
    echo "Already unlocked and mounted"
    do_mount_post
    exit 0
fi

DEV_UNLOCKED="/dev/disk/by-id/dm-name-$UNLOCKED_NAME"
if [ -e "$DEV_UNLOCKED" ] ; then
    echo "Already unlocked ($DEV_UNLOCKED), mounting..."
    do_mount
fi

echo "Mounting $DEV_ENCRYPTED as $UNLOCKED_NAME"
cryptsetup luksOpen "$DEV_ENCRYPTED" "$UNLOCKED_NAME"
sleep 1
if [ -e "$DEV_UNLOCKED" ] ; then
    echo "Mounting..."
    do_mount
else
    echo "Partition still encrypted, bad password?"
    exit 1
fi

