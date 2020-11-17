#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# This entrypoint is ONLY for instances to run functional tests on
# DO NOT USE IN PROD (check docker/ under main dir for that)
set -e

basedir=$(readlink -f "$(dirname "$0")"/../../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

# do we have a key?
if [ -n "$USER_PUBKEY_B64" ]; then
    user_pubkey=$(base64 -d <<< "$USER_PUBKEY_B64")
fi
if [ -n "$ROOT_PUBKEY_B64" ]; then
    root_pubkey=$(base64 -d <<< "$ROOT_PUBKEY_B64")
fi
if [ -z "$user_pubkey" ] ; then
    echo "Missing ENV user_pubkey (or USER_PUBKEY_B64), aborting" >&2
    exit 1
elif [ -z "$root_pubkey" ] ; then
    echo "Missing ENV root_pubkey (or ROOT_PUBKEY_B64), aborting" >&2
    exit 1
elif [ -z "$TARGET_USER" ]; then
    echo "Missing ENV TARGET_USER, aborting" >&2
fi

# modify default ssh/sshd configs
tmpf=$(mktemp -t bastion.XXXXXXXX)
grep -Evi '^(stricthostkeychecking) '   /etc/ssh/ssh_config  > "$tmpf" || true
cat "$tmpf" > /etc/ssh/ssh_config
grep -Evi '^(port|authorizedkeysfile) ' /etc/ssh/sshd_config > "$tmpf" || true
cat "$tmpf" > /etc/ssh/sshd_config
rm -f "$tmpf"
echo "StrictHostKeyChecking no" >> /etc/ssh/ssh_config
echo "Port 22"                  >> /etc/ssh/sshd_config
echo "Port 226"                 >> /etc/ssh/sshd_config

# put the root pubkey on the root account
[ -d "$UID0HOME/.ssh" ] || mkdir "$UID0HOME/.ssh"
echo "$root_pubkey" >> "$UID0HOME/.ssh/authorized_keys"
# also unlock the root account, which can sometimes prevent us connecting through SSH (CentOS 8)
if [ "$OS_FAMILY" = Linux ]; then
    usermod -U "$UID0"
fi

HOME="$UID0HOME" USER="$UID0" "$basedir"/bin/plugin/restricted/accountCreate       '' '' '' '' --uid 5000 --account "$TARGET_USER" --public-key "$user_pubkey FOR_TESTS_ONLY"
HOME="$UID0HOME" USER="$UID0" "$basedir"/bin/plugin/restricted/accountGrantCommand '' '' '' '' --account "$TARGET_USER" --command accountGrantCommand

# add an account with local shell access (to mimic a remote server)
useradd_compat test-shell_ "" "" /bin/sh
test -d ~test-shell_/.ssh || mkdir ~test-shell_/.ssh
# and copy the bastion pubkey of the bastion account we created
cat /home/"$TARGET_USER"/.ssh/id_*.pub > ~test-shell_/.ssh/authorized_keys
# add it to the bastion-nopam group
add_user_to_group_compat test-shell_ bastion-nopam

# install a fake ttyrec just so that our connection tests work
if [ ! -e /usr/bin/ttyrec ] ; then
    "$basedir"/bin/admin/install --nothing --no-wait --install-fake-ttyrec
fi

# if we have other specific scripts to run, run them
if [ -d "$basedir/tests/functional/docker/target_role.d/" ]; then
    while IFS= read -r -d '' script
    do
        echo "### running $script"
        # shellcheck disable=SC1090
        if ! . "$script"; then
            echo "ERROR while running $script, bailing out..." >&2
            exit 1
        fi
    done < <(find "$basedir/tests/functional/docker/target_role.d/" -mindepth 1 -maxdepth 1 -type f -name "*.sh" -print0)
fi

# now OS-specific things

if [ "$OS_FAMILY" = Linux ] ; then

    test -x /etc/init.d/ssh       && /etc/init.d/ssh start
    test -x /etc/init.d/syslog-ng && /etc/init.d/syslog-ng start

    if [ -e /etc/redhat-release ]; then
        # centos has systemd and it doesn't work well under docker
        # so we have to start the daemon manually :|
        /usr/sbin/sshd
        /usr/sbin/syslog-ng -F -p /var/run/syslogd.pid & disown
    fi
    if [ -f /etc/os-release ] && grep -q suse /etc/os-release; then
        /usr/sbin/sshd-gen-keys-start
        /usr/sbin/sshd
        sed -i -re 's/s_src/src/' /etc/syslog-ng/conf.d/20-bastion.conf
        /usr/sbin/syslog-ng-service-prepare
        /usr/sbin/syslog-ng
    fi

elif [ "$OS_FAMILY" = OpenBSD ] || [  "$OS_FAMILY" = FreeBSD ] || [ "$OS_FAMILY" = NetBSD ] ; then

    # setup some 127.0.0.x IPs (needed for our tests)
    # this automatically works under Linux on lo
    i=2
    while [ $i -lt 20 ] ; do
        ifconfig lo0 127.0.0.$i netmask 255.0.0.0 alias
        (( i++ ))
    done
    ifconfig lo0 127.7.7.7 netmask 255.0.0.0 alias

    set +e
    for st in restart onestart
    do
        test -x /etc/rc.d/sshd      && /etc/rc.d/sshd $st
        test -x /etc/rc.d/syslog_ng && /etc/rc.d/syslog_ng $st
        test -x /usr/local/etc/rc.d/syslog-ng && /usr/local/etc/rc.d/syslog-ng $st
    done
    set -e
fi

if [ -n "$NO_SLEEP" ]; then
    exit 0
fi

echo "Now sleeping forever (docker mode)"
while : ; do
    sleep 3600
done
