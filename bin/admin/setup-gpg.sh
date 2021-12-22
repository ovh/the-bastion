#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
set -e
umask 077

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

do_generate()
{
    rsync_conf="$BASTION_ETC_DIR/osh-encrypt-rsync.conf.d/50-gpg-bastion-key.conf"
    if [ -e "$rsync_conf" ]; then
        if [ "$1" = "--overwrite" ]; then
            echo "$rsync_conf already exists, but overwriting as asked!"
        else
            echo "$rsync_conf already exists, aborting!" >&2
            exit 1
        fi
    fi
    mkdir -p "$BASTION_ETC_DIR/osh-encrypt-rsync.conf.d"

    sign_key_pass=$(perl -e '$p .= chr(int(rand(93))+33) for (1..16); $p =~ s{["\\]}{~}g; print "$p"')

    echo "Detecting GnuPG version..."
    if gpg --dump-options | grep -q -- --quick-generate-key; then
        echo "GnuPG >= v2.1, generating the GPG signing key..."
        keyname="Bastion signing key ed25519 <root@$(hostname)>"
        gpg --batch --pinentry-mode loopback --passphrase-fd 0 --quick-generate-key "$keyname" ed25519 sign 0 <<< "$sign_key_pass"
    else
        echo "GnuPG < v2.1, generating the GPG signing key..."
        keyname="Bastion signing key rsa4k <root@$(hostname)>"
        printf "Key-Type: RSA\\nKey-Length: 4096\\nSubkey-Type: RSA\\nSubkey-Length: 4096\\nName-Real: Bastion signing key rsa4k\\nName-Email: %s\\nExpire-Date: 0\\nPassphrase: %s\\n%%echo Generating GPG key, it'll take some time.\\n%%commit\\n%%echo done\\n" "root@$(hostname)" "$sign_key_pass" | gpg --gen-key --batch
    fi

    # get the id of the key we just generated
    gpgid=$(gpg --with-colons --list-keys "$keyname" | awk -F: '/^pub:/ { print $5; exit; }')

    if [ -z "$gpgid" ]; then
        echo "Error while generating key, couldn't find the ID in gpg --list-keys :(" >&2
        gpg --list-keys >&2
        return 1
    fi

    echo "The key we just generated has the following ID: $gpgid"

    cat > "$rsync_conf" <<EOF
# autogenerated with $0 at $(date)
# using: $(gpg --version 2>&1 | head -n1)
{
    "signing_key_passphrase": "$sign_key_pass",
    "signing_key": "$gpgid"
}
EOF
    chown "$UID0":"$GID0" "$rsync_conf"
    chmod 600 "$rsync_conf"

    echo
    echo "Configuration file $rsync_conf updated:"
    echo "8<---8<---8<---8<---8<---8<--"
    cat "$rsync_conf"
    echo "--->8--->8--->8--->8--->8--->8"

    echo
    echo Done.
}

do_import()
{
    rsync_conf="$BASTION_ETC_DIR/osh-encrypt-rsync.conf.d/50-gpg-admins-key.conf"
    if [ -e "$rsync_conf" ]; then
        if [ "$1" = "--overwrite" ]; then
            echo "$rsync_conf already exists, but overwriting as asked!"
        else
            echo "$rsync_conf already exists, aborting!" >&2
            exit 1
        fi
    fi
    mkdir -p "$BASTION_ETC_DIR/osh-encrypt-rsync.conf.d"
    backup_conf="$BASTION_ETC_DIR/osh-backup-acl-keys.conf.d/50-gpg.conf"
    if [ -e "$backup_conf" ]; then
        if [ "$1" = "--overwrite" ]; then
            echo "$backup_conf already exists, but overwriting as asked!"
        else
            echo "$backup_conf already exists, aborting!" >&2
            exit 1
        fi
    fi
    mkdir -p "$BASTION_ETC_DIR/osh-backup-acl-keys.conf.d"

    keys_before=$(mktemp)
    # shellcheck disable=SC2064
    trap "rm -f $keys_before" EXIT INT
    gpg --with-colons --list-keys | grep ^pub: | awk -F: '{print $5}' > "$keys_before"
    echo "Paste the admins public GPG key (use ^D, aka CTRL+D, when you're done):"
    gpg --import
    newkey=''
    for key in $(gpg --with-colons --list-keys | grep ^pub: | awk -F: '{print $5}'); do
        grep -qw "$key" "$keys_before" || newkey="$key"
    done
    if [ -z "$newkey" ]; then
        echo "Couldn't find which key you imported (did it exist already?), aborting" >&2
        return 1
    fi
    echo "Found generated key with ID: $newkey"
    fpr=$(gpg --with-colons --fingerprint --list-keys "$newkey" | awk -F: '/^fpr:/ {print $10 ; exit}')
    if [ -z "$fpr" ]; then
        echo "Couldn't find the fingerprint of the generated key $newkey, aborting" >&2
        return 1
    fi
    echo "Found generated key fingerprint: $fpr"
    echo "Trusting this key..."
    gpg --import-ownertrust <<< "$fpr:6:"

    cat > "$rsync_conf" <<EOF
# autogenerated with $0 at $(date)
# using: $(gpg --version 2>&1 | head -n1)
{
    "recipients": [
        [ "$newkey" ]
    ]
}
EOF
    chown "$UID0":"$GID0" "$rsync_conf"
    chmod 600 "$rsync_conf"

    echo
    echo "Configuration file $rsync_conf updated:"
    echo "8<---8<---8<---8<---8<---8<--"
    cat "$rsync_conf"
    echo "--->8--->8--->8--->8--->8--->8"

    cat > "$backup_conf" <<EOF
# autogenerated with $0 at $(date)
# using: $(gpg --version 2>&1 | head -n1)
GPGKEYS='$newkey'
EOF
    chown "$UID0":"$GID0" "$backup_conf"
    chmod 600 "$backup_conf"

    echo
    echo "Configuration file $backup_conf updated:"
    echo "8<---8<---8<---8<---8<---8<--"
    cat "$backup_conf"
    echo "--->8--->8--->8--->8--->8--->8"

    echo
    echo Done.

}

do_usage()
{
    cat <<EOF
Usage: $0 <import|generate> [--overwrite]

Use generate to generate a new GPG key pair for bastion signing
Use import to import the administrator GPG key you've generated on your desk (ttyrecs, keys and acls backups will be encrypted to it)

Only use --overwrite if you know what you're doing (it'll ignore any pre-existing configuration or key)

EOF
}

case "$1" in
    import|--import)     shift; do_import   "$@"; exit $?;;
    generate|--generate) shift; do_generate "$@"; exit $?;;
    "") do_usage; exit 0;;
    *) echo "Unknown command '$1'" >&2; echo; do_usage; exit 1;;
esac

exit 0
