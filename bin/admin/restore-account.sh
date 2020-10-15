#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
account="$1"
backup_path="$2"

if [ -z "$backup_path" ] || [ -n "$3" ]; then
    echo "Restores a deleted account's data."
    echo "The account must have been re-created first."
    echo "WARNING: the newly created account information will be overwritten (keys, accesses)"
    echo
    echo "Usage: $0 <account> <backup_path>"
    echo "Example: $0 johndoe /home/oldkeeper/accounts/johndoe.at-1502153197.by-admin"
    exit 1
fi

if ! getent passwd "$account" >/dev/null ; then
    echo "Account '$account' doesn't seem to exist, you must re-create it first"
    exit 2
fi
homedir=$(getent passwd "$account" | cut -d: -f6)
if [ -z "$homedir" ] || ! [ -d "$homedir" ]; then
    echo "Account '$account's homedir doesn't seem to exist ($homedir)"
    exit 2
fi

if [ ! -d "$backup_path" ]; then
    echo "Backup path '$backup_path' doesn't exist or is not a folder!"
    exit 2
fi

if [ ! -d "$backup_path/allowkeeper" ] || ! [ -d "$backup_path/$account-home" ] ; then
    echo "Backup path '$backup_path' doesn't seem to be a valid backup path!"
    exit 2
fi

echo "Here is the contents of the allowkeeper dir of $account:"
find "/home/allowkeeper/$account/"
echo "Here is the contents of the current homedir of $account:"
find "$homedir/"
echo
echo -n "This will be replaced, does this look reasonable (y/n) ? "
read -r ans
if [ "$ans" != "y" ]; then
    echo "Aborting."
    exit 3
fi

chattr -a "$homedir"/*.log
mkdir "$homedir"/before-restore
chmod 0 "$homedir"/before-restore
find "$homedir" -mindepth 1 -maxdepth 1 ! -name before-restore -print0 | xargs -r0 mv -v -t "$homedir"/before-restore
rsync -vaP "$backup_path/$account-home/" "$homedir/"
chown -R "$account:$account" "$homedir/"
chattr +a "$homedir"/*.log
rsync -vaP --delete "$backup_path"/allowkeeper/ "/home/allowkeeper/$account/"

echo "New allowkeeper info is as follows:"
ls -l "/home/allowkeeper/$account/"

echo
echo "Done."
