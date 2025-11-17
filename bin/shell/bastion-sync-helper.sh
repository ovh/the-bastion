#!/bin/sh
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
if [ "$USER" != "bastionsync" ]; then
    echo "Unexpected user, aborting" >&2
    exit 2
fi
if [ -z "$SSH_CONNECTION" ]; then
    echo "Bad environment, aborting" >&2
    exit 3
fi
if [ "$1" != "-c" ]; then
    echo "Interactive session denied, aborting" >&2
    exit 4
fi
shift
# shellcheck disable=SC2068
set -- $@

if [ "$1 $2" = "rsync --server" ]; then
    shift
    shift
    if ! cd /; then
        echo "Failed to chdir /, aborting" >&2
        exit 6
    fi
    exec /usr/bin/sudo -- /usr/bin/rsync --server "$@"

# TODO: make this less cursed
elif [ "$1" = "test" ] && [ "$2" = "-d" ] && [ "$3" = "/etc/ssh/sshd_config.forward.d" ]; then
    exec test -d /etc/ssh/sshd_config.forward.d
elif [ "$*" = "test -d /etc/ssh/sshd_config.forward.d" ]; then
    exec test -d /etc/ssh/sshd_config.forward.d
elif [ "$*" = "sudo /bin/systemctl reload sshd" ]; then
    exec /usr/bin/sudo /bin/systemctl reload sshd
elif [ "$*" = "sudo /usr/bin/systemctl reload sshd" ]; then
    exec /usr/bin/sudo /usr/bin/systemctl reload sshd
elif [ "$*" = "sudo /bin/systemctl reload ssh" ]; then
    exec /usr/bin/sudo /bin/systemctl reload ssh
elif [ "$*" = "sudo /usr/bin/systemctl reload ssh" ]; then
    exec /usr/bin/sudo /usr/bin/systemctl reload ssh
elif [ "$*" = "sudo /usr/sbin/service ssh reload" ]; then
    exec /usr/bin/sudo /usr/sbin/service ssh reload
elif [ "$*" = "sudo /usr/sbin/service sshd reload" ]; then
    exec /usr/bin/sudo /usr/sbin/service sshd reload
elif [ "$*" = "sudo /etc/init.d/ssh reload" ]; then
    exec /usr/bin/sudo /etc/init.d/ssh reload
elif [ "$*" = "sudo /etc/init.d/sshd reload" ]; then
    exec /usr/bin/sudo /etc/init.d/sshd reload
else
    echo "Only rsync and sshd reload commands are allowed, aborting" >&2
    exit 5
fi