#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
if [ "$(uname -s)" = Linux ] ; then
    test -x /etc/init.d/ssh       && /etc/init.d/ssh       start
    test -x /etc/init.d/syslog-ng && /etc/init.d/syslog-ng start
else
    # for BSD
    test -x /etc/rc.d/sshd && /etc/rc.d/sshd onestart
fi

if [ "$1" = "--sandbox" ]; then
    echo "The Bastion sandbox container is running, you can now connect to its port 22 (probably remapped to another port on the host)"
fi
while : ; do
    sleep 3600
done
