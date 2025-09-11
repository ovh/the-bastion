#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
if [ "$(uname -s)" = Linux ] ; then
    test -x /etc/init.d/ssh       && /etc/init.d/ssh       start
    test -x /etc/init.d/syslog-ng && /etc/init.d/syslog-ng start
else
    # for BSD
    test -x /etc/rc.d/sshd && /etc/rc.d/sshd onestart
fi

# If the container was committed and pushed to a registry and later retrieved,
# the extended ACLs on the filesystem may have silently disappeared,
# as the registry storage may not support them.
# cf https://forums.docker.com/t/setfacl-very-long-setting/131897
# Ensure we repair/restore them before opening the SSH service:
/opt/bastion/bin/admin/install --minimal

if [ "$1" = "--sandbox" ]; then
    echo "The Bastion sandbox container is running, you can now connect to its port 22 (probably remapped to another port on the host)"
fi
while : ; do
    sleep 3600
done
