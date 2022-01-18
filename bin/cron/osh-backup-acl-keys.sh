#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
set -e
umask 077

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

trap "_err 'Unexpected termination!'" EXIT

# setting default values
LOGFILE=""
LOG_FACILITY="local6"
DESTDIR=""
DAYSTOKEEP="90"
GPGKEYS=""
SIGNING_KEY=""
SIGNING_KEY_PASSPHRASE=""
PUSH_REMOTE=""
PUSH_OPTIONS=""

# building config files list
config_list=''
if [ -f "$BASTION_ETC_DIR/osh-backup-acl-keys.conf" ]; then
    config_list="$BASTION_ETC_DIR/osh-backup-acl-keys.conf"
fi
if [ -d "$BASTION_ETC_DIR/osh-backup-acl-keys.conf.d" ]; then
    config_list="$config_list $(find "$BASTION_ETC_DIR/osh-backup-acl-keys.conf.d" -mindepth 1 -maxdepth 1 -type f -name "*.conf" | sort)"
fi

if [ -z "$config_list" ]; then
    exit_fail "No configuration loaded, aborting"
fi

# load the config files only if they're owned by root:root and mode is o-rwx
for file in $config_list; do
    if check_secure "$file"; then
        # shellcheck source=etc/bastion/osh-backup-acl-keys.conf.dist
        . "$file"
    else
        exit_fail "Configuration file not secure ($file), aborting."
    fi
done

# shellcheck disable=SC2153
if [ -n "$LOGFILE" ] ; then
    exec &>> >(tee -a "$LOGFILE")
fi

if [ -z "$DESTDIR" ] ; then
    exit_fail "$0: Missing DESTDIR in configuration, aborting."
fi

if ! echo "$DAYSTOKEEP" | grep -Eq '^[0-9]+$' ; then
    exit_fail "$0: Invalid specified DAYSTOKEEP value ($DAYSTOKEEP), aborting."
fi

_log "Starting backup..."

mkdir -p "$DESTDIR"

tarfile="$DESTDIR/backup-$(date +'%Y-%m-%d').tar.gz"
_log "Creating $tarfile..."
supp_entries=""
for entry in /root/.gnupg /root/.ssh /var/otp /etc/master.passwd /etc/pwd.db /etc/spwd.db \
    /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/bastion /usr/local/etc/bastion
do
    [ -e "$entry" ] && supp_entries="$supp_entries $entry"
done

maxtries=50
for try in $(seq 1 $maxtries)
do
    # tar may output unimportant warnings to stderr, so we don't want to get noisy
    # if it exits with 0: save its stderr in a tmpfile, and cat it to stderr only if it returns != 0
    tarstderr=$(mktemp)
    set +e
    # SC2086: we don't want to quote $supp_entries, we want it expanded
    # shellcheck disable=SC2086
    tar czf "$tarfile" -p --xattrs --acls --one-file-system --numeric-owner \
        --exclude=".encrypt" \
        --exclude="ttyrec" \
        --exclude="*.sqlite" \
        --exclude="*.log" \
        --exclude="*.ttyrec" \
        --exclude="*.gpg" \
        --exclude="*.gz" \
        --exclude="*.zst" \
        /home/ /etc/ssh $supp_entries 2>"$tarstderr"; ret=$?
    set -e
    if [ $ret -eq 0 ]; then
        _log "File created"
        rm -f "$tarstderr"
        break
    else
        # special case: if a file changed/removed while we were reading it, tar fails, in that case: retry
        if [ $ret -eq 1 ] && grep -q -e 'changed as we read it' -e 'removed before we read it' "$tarstderr"; then
            _log "Transient tar failure (try $try):"
            while read -r line; do
                _log "tar: $line"
            done < "$tarstderr"
            rm -f "$tarstderr"
            _log "Retrying after $try seconds..."
            sleep "$try"
            continue
        fi
        _err "Error while creating file (sysret=$ret)"
        while read -r line; do
            _err "tar: $line"
        done < "$tarstderr"
        rm -f "$tarstderr"
        exit_fail
    fi
done
if [ "$try" = "$maxtries" ]; then
    exit_fail "Failed creating tar archive after $maxtries tries!"
fi

encryption_worked=0
if [ -n "$GPGKEYS" ] ; then
    cmdline="--encrypt --batch --trust-model always"

    # this only exists on recent gnupg versions (>= 2.1)
    if gpg --dump-options | grep -q -- --pinentry-mode; then
        cmdline="$cmdline --pinentry-mode loopback"
    fi

    sign=0
    if [ -n "$SIGNING_KEY" ] && [ -n "$SIGNING_KEY_PASSPHRASE" ]; then
        sign=1
        cmdline="$cmdline --sign --local-user $SIGNING_KEY"
    fi
    for recipient in $GPGKEYS
    do
        cmdline="$cmdline -r $recipient"
    done

    # just in case, encrypt all .tar.gz files we find in $DESTDIR
    while IFS= read -r -d '' file
    do
        if [ "$sign" = 1 ]; then
            _log "Encrypting & signing $file..."
        else
            _log "Encrypting $file..."
        fi
        rm -f "$file.gpg" # if the gpg file already exists, remove it

        # shellcheck disable=SC2086
        if [ "$sign" = 1 ]; then
            gpg $cmdline --passphrase-fd 0 "$file" <<< "$SIGNING_KEY_PASSPHRASE"; ret=$?
        else
            gpg $cmdline "$file"; ret=$?
        fi

        if [ "$ret" = 0 ]; then
            encryption_worked=1
            if command -v shred >/dev/null; then
                shred -u "$file"
            else
                rm -f "$file"
            fi
        else
            _err "Encryption failed"
        fi
    done < <(find "$DESTDIR/" -mindepth 1 -maxdepth 1 -type f -name 'backup-????-??-??.tar.gz' -print0)
else
    _warn "$tarfile will not be encrypted! (no GPGKEYS specified)"
fi

# push to remote if needed
if [ -n "$PUSH_REMOTE" ] && [ "$encryption_worked" = 1 ] && [ -r "$tarfile.gpg" ] ; then
    _log "Pushing backup file ($tarfile.gpg) remotely..."
    set +e
    # shellcheck disable=SC2086
    scp $PUSH_OPTIONS "$tarfile.gpg" "$PUSH_REMOTE"; ret=$?
    set -e
    if [ $ret -eq 0 ]; then
        _log "Push done"
    else
        _err "Push failed (sysret=$ret)"
    fi
fi

# cleanup
_log "Cleaning up old backups..."
find "$DESTDIR/" -mindepth 1 -maxdepth 1 -type f -name 'backup-????-??-??.tar.gz'     -mtime +"$DAYSTOKEEP" -delete
find "$DESTDIR/" -mindepth 1 -maxdepth 1 -type f -name 'backup-????-??-??.tar.gz.gpg' -mtime +"$DAYSTOKEEP" -delete

_log "Done"
trap - EXIT
exit 0
