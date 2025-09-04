#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
set -e
umask 077

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

action_doing "Checking whether the proper tools are installed"
if ! command -v rsync >/dev/null || ! command -v cryptsetup >/dev/null; then
    action_error "Missing rsync or cryptsetup, aborting"
    exit 1
else
    action_done
fi

action_doing "Installing luks-config.sh template if needed"
if ! [ -f "/etc/bastion/luks-config.sh" ]; then
    mkdir -p /etc/bastion
    if ! cp "$basedir/etc/bastion/luks-config.sh.dist" "/etc/bastion/luks-config.sh"; then
        action_error "Error copying $basedir/etc/bastion/luks-config.sh.dist to /etc/bastion/luks-config.sh, aborting"
        exit 1
    else
        action_done "installed"
    fi
else
    action_done "already installed"
fi

action_doing "Checking whether /home is a separate partition"
home_block_device=$(awk '/ \/home / {print $1}' /proc/mounts)
if [ -n "$home_block_device" ] && [ -e "$home_block_device" ]; then
    action_done "found $home_block_device"
else
    action_error "No, aborting"
    exit 1
fi

action_doing "Checking whether /home is in /etc/fstab"
if grep -qE '[[:space:]]/home[[:space:]]' /etc/fstab; then
    action_done "$(grep '[[:space:]]/home[[:space:]]' /etc/fstab)"
else
    action_error "No, aborting"
    exit 1
fi

action_doing "Checking whether we can umount /home"
if umount /home; then
    action_done
else
    action_error "No, aborting"
    exit 1
fi

action_doing "Checking whether we can remount /home"
if mount /home; then
    action_done
else
    action_error "No, aborting"
    exit 1
fi

action_doing "Checking used space in /home"
home_used_mb=$(df -m /home | awk '{ print $3 }' | tail -n1)
if [ -n "$home_used_mb" ]; then
    action_done "$home_used_mb MiB"
else
    action_error "Couldn't get the /home used space"
    exit 1
fi

action_doing "Checking available space in /"
slash_available_mb=$(df -m / | awk '{ print $4 }' | tail -n1)
if [ -n "$slash_available_mb" ]; then
    action_done "$slash_available_mb MiB"
else
    action_error "Couldn't get the / available space"
    exit 1
fi

action_doing "Checking whether there is enough available space in / to hold /home contents temporarily"
if [ "$slash_available_mb" -gt "$home_used_mb" ]; then
    action_done
else
    action_error "Not enough free space in /"
    exit 1
fi

action_doing "Creating temporary /tmphome"
# silently try to delete it just in case it exists but is empty
if [ -d /tmphome ]; then
    rmdir /tmphome 2>/dev/null || true
fi
if [ -e /tmphome ]; then
    action_error "/tmphome already exists! Aborting"
    exit 1
else
    mkdir /tmphome
    if [ ! -d /tmphome ]; then
        action_error "Couldn't create /tmphome!"
        exit 1
    else
        action_done
    fi
fi

action_doing "Rsyncing /home to /tmphome"
if rsync -vaPHAX --exclude='lost+found' /home/ /tmphome/; then
    action_done
else
    action_error "Rsync failed, aborting!"
    rm -Rf /tmphome
    exit 1
fi

action_doing "Rsync done, here are some details:"
action_detail "ls /home   : $(cd /home ; find . | tr '\n' ' ')"
action_detail "ls /tmphome: $(cd /tmphome ; find . | tr '\n' ' ')"
action_detail "du -shc /home   : $(du -shc /home | grep total)"
action_detail "du -shc /tmphome: $(du -shc /tmphome | grep total)"
action_detail ""
action_detail "Does this look reasonable? [CTRL+C if not]"

# shellcheck disable=SC2034
read -r _dummy

action_doing "Umounting /home"
if umount /home; then
    action_done
else
    action_error "Couldn't umount /home, aborting"
    rm -Rf /tmphome
    exit 1
fi

action_doing "Erasing /home block device and encrypting it (last chance to cancel!)"
action_detail "You should generate a strong password on your desk, with e.g. \`pwgen -s 10\`"
if cryptsetup luksFormat "$home_block_device"; then
    action_done
else
    action_error "Cryptsetup failed, aborting"
    mount /home && rm -Rf /tmphome
    exit 1
fi

action_doing "Opening newly encrypted block device"
if cryptsetup luksOpen "$home_block_device" home; then
    action_done
else
    action_error "Opening failed, aborting! Your /home partition is no longer valid, fix it manually! ($home_block_device)"
    exit 1
fi

action_doing "Creating a new filesystem on top of the encrypted block device"
if mkfs.ext4 -T news -L home -M /home /dev/disk/by-id/dm-name-home; then
    action_done
else
    action_error "Filesystem creation failed, aborting! Your /home partition is no longer valid, fix it manually! ($home_block_device)"
    exit 1
fi

action_doing "Setting up /etc/bastion/luks-config.sh with encrypted block device"
if sed -i -re "s;^DEV_ENCRYPTED=.*;DEV_ENCRYPTED=$home_block_device;" /etc/bastion/luks-config.sh; then
    action_done
else
    action_error "Couldn't modify /etc/bastion/luks-config.sh, please do it manually, continuing"
fi

action_doing "Setting up /etc/fstab with encrypted block device"
newfstab=$(mktemp)
grep -Ev "[[:space:]]/home[[:space:]]" /etc/fstab > "$newfstab"
echo "# added by $(basename "$0") on $(date)" >> "$newfstab"
echo "/dev/disk/by-id/dm-name-home /home ext4 defaults,errors=remount-ro,noauto,nosuid,noexec,nodev 0 0" >> "$newfstab"
cat "$newfstab" > /etc/fstab
rm -f "$newfstab"
action_done

action_doing "Remounting /home after encryption"
if command -v systemctl >/dev/null 2>&1; then
    if systemctl daemon-reload; then
        action_done "systemd daemon-reload successful"
    else
        action_error "systemd daemon-reload failed"
        exit 1
    fi
fi
if mount /home; then
    action_done
else
    action_error "Error while remounting home, aborting!"
    exit 1
fi

action_doing "Rsyncing back /home contents"
if rsync -vaPHAX --remove-source-files --exclude='lost+found' /tmphome/ /home/; then
    action_done
else
    action_error "Rsync failed, aborting!"
    exit 1
fi

action_doing "Removing /tmphome"
if find /tmphome -depth -type d -empty -delete; then
    action_done
else
    action_error "Error while removing /tmphome, continuing anyway"
fi

action_doing "Testing whether we can properly unlock /home after boot"
if umount /home; then
    if cryptsetup luksClose home; then
        if /opt/bastion/bin/admin/unlock-home.sh; then
            action_done
        else
            action_error "Error with unlock-home.sh, ignoring"
        fi
    else
        action_error "Couldn't luksClose home, ignoring"
    fi
else
    action_error "Couldn't umount /home to run the test, ignoring"
fi

[ ! -e /root/unlock-home.sh ] && ln -s /opt/bastion/bin/admin/unlock-home.sh /root/

