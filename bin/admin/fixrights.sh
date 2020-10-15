#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
set -e

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

action_doing "Adjusting rights on $basedir"
if [ ! -w "$basedir" ]; then
    action_error "$basedir is not writable"
    exit 1
fi

# we must ensure that all basedir parents are at least o+x
parent="$basedir"
while [ -n "$parent" ];
do
    chmod o+x "$parent"
    parent=$(echo "$parent" | sed -re 's=/+[^/]+$==')
done

find "$basedir" -name .git -prune -o -print0 | xargs -r0 chown "$UID0:$GID0"
chmod o+x "$basedir"
find "$basedir" -name .git -prune -o -type d -print0 | xargs -r0 chmod 0755
find "$basedir" -name .git -prune -o -name contrib -prune -o -type f -print0 | xargs -r0 chmod 0644
find "$basedir"/bin/ ! -name "*.json" -print0 | xargs -r0 chmod 0755
chmod 0644 "$basedir"/bin/dev/perlcriticrc
chmod 0700 "$basedir"/bin/admin/install
chmod 0700 "$basedir"/contrib
chmod 0700 "$basedir"/bin/sudogen

while IFS= read -r -d '' file
do
    filemode=$(awk '/# FILEMODE / { print $3; exit; }' "$file")
    fileown=$(awk '/# FILEOWN / { print $3":"$4; exit; }' "$file")
    if [ -z "$filemode" ] && [ -z "$fileown" ]; then
        action_error "Missing info for $file"
    else
        action_detail "$filemode $fileown $file"
        chmod -- "$filemode" "$file"
        chown -- "$fileown" "$file"
    fi
done < <(find "$basedir/bin/helper" -type f -print0)

chmod 0755 "$basedir"/docker/entrypoint.sh \
    "$basedir"/tests/functional/docker/docker_build_and_run_tests.sh \
    "$basedir"/tests/functional/docker/docker_build_and_run_tests_all.sh \
    "$basedir"/tests/functional/launch_tests_on_instance.sh \
    "$basedir"/tests/functional/docker/target_role.sh \
    "$basedir"/tests/functional/docker/tester_role.sh \
    "$basedir"/tests/functional/fake_ttyrec.sh \
    "$basedir"/tests/unit/run.pl

while IFS= read -r -d '' plugin
do
    groupname=$(basename "$plugin")
    getent group "osh-$groupname" >/dev/null || continue
    chown "$UID0:osh-$groupname" "$plugin"
    chmod 0750 "$plugin"
done < <(find "$basedir/bin/plugin/restricted/" ! -name "*.json" -print0)

action_done ""
