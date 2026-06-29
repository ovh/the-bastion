#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# Entrypoint for the slim SSH boxes (docker/Dockerfile.sshslim) used by the
# functional tests to play the "jumphost" and "remoteserver" roles sitting
# behind the bastion. These are plain sshd boxes with NO bastion code: this
# script is bind-mounted and run as the entrypoint at `docker run` time.
#
# Env:
#   ROOT_PUBKEY_B64  base64 of the root public key, so the tester can root-SSH
#                    in to push the bastion egress keys into the test users'
#                    authorized_keys at test time (mimicking real remote setup)
#   SSHHOST_ROLE     a label (e.g. "jumphost"/"remoteserver") written to
#                    /sshhost-role, so tests can assert which box a connection
#                    actually landed on
#   SSHHOST_USERS    space-separated list of unprivileged login users to create
set -eu

if [ -z "${ROOT_PUBKEY_B64:-}" ]; then
    echo "sshhost_role: missing ROOT_PUBKEY_B64, aborting" >&2
    exit 1
fi

# allow the tester to log in as root by key, to configure us at test time
mkdir -p /root/.ssh
chmod 700 /root/.ssh
base64 -d <<< "$ROOT_PUBKEY_B64" > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# create the requested unprivileged login users, each with an (initially empty)
# authorized_keys owned by themselves: the tests append the bastion egress keys
# to these later, over the root SSH session
# shellcheck disable=SC2086
for u in ${SSHHOST_USERS:-}; do
    if ! id "$u" >/dev/null 2>&1; then
        useradd --create-home --shell /bin/sh "$u"
    fi
    # a freshly-created user has a locked password ('!' in shadow); with sshd's default UsePAM=no
    # that makes sshd refuse even pubkey logins ("account is locked"). Empty the password field so
    # the account is unlocked (pubkey-only; password auth is disabled in sshd_config anyway).
    passwd -d "$u" >/dev/null 2>&1 || true
    home=$(getent passwd "$u" | cut -d: -f6)
    mkdir -p "$home/.ssh"
    touch "$home/.ssh/authorized_keys"
    chown -R "$u:$u" "$home/.ssh"
    chmod 700 "$home/.ssh"
    chmod 600 "$home/.ssh/authorized_keys"
done

# leave a marker so tests can assert which box a connection actually reached. It's prefixed with a
# distinctive token so a test grepping for it can't false-match on the role word appearing elsewhere
# (e.g. the bastion prints the target's hostname, which contains "remoteserver").
echo "proxyjump-test-landed-on=${SSHHOST_ROLE:-unknown}" > /sshhost-role
chmod 644 /sshhost-role

# minimal sshd config: root login by key only, relaxed StrictModes (throwaway
# test box, authorized_keys is written by root), and TCP forwarding left on (the
# jumphost role needs it for the bastion's `ssh -W` to reach the remoteserver)
cat > /etc/ssh/sshd_config <<'EOF'
Port 22
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
StrictModes no
AllowTcpForwarding yes
AcceptEnv LANG LC_*
Subsystem sftp internal-sftp
EOF

# generate host keys and run sshd in the foreground (keeps the container alive)
ssh-keygen -A
mkdir -p /run/sshd
echo "sshhost_role: starting sshd (role=${SSHHOST_ROLE:-unknown} users=[${SSHHOST_USERS:-}])"
exec /usr/sbin/sshd -D -e
