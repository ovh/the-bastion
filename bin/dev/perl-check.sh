#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

# skip this script entirely if asked
[ "$1" = "--test-quick" ] && [ "$2" = 1 ] && exit 0

cmdline='-Mstrict -Mwarnings'
(( fails=0 ))
action_doing "Checking perl files syntax"
for i in $(find "$basedir"/bin -type f ! -name "*.orig") $(find "$basedir"/lib/perl -type f -name "*.pm") $(find "$basedir"/lib/perl -type f -name "*.inc")
do
    i=$(readlink -f "$i")
    if head -n1 "$i" | grep -Eq '/perl|/env perl' || head -n2 "$i" | grep -Eq '^package ' ; then
        # FIXME remove below block when we get rid of GnuPG perl module in below script
        if [ "$i" = "$basedir/bin/cron/osh-encrypt-rsync.pl" ] && echo "$DISTRO_LIKE" | grep -qw -e rhel -e suse; then
            action_detail "${BLUE}$i${NOC}: skipping"
            continue
        fi
        action_detail "${BLUE}$i${NOC}"
        if grep -q -- 'perl -T' "$i"; then
            # shellcheck disable=SC2086
            perl $cmdline -Tc "$i" 2>&1 | grep -v OK$
        else
            # shellcheck disable=SC2086
            perl $cmdline -c  "$i" 2>&1 | grep -v OK$
        fi
        [ "${PIPESTATUS[0]}" -ne 0 ] && (( fails++ ))
        [ -n "$DEBUG" ] || continue
        grep -q '^use warnings' "$i" && echo "(spurious use warnings in $i)"
        grep -q '^use strict'   "$i" && echo "(spurious use strict in $i)"
        grep -q '^use common::sense;' "$i" || echo "(missing common::sense in $i)"
    fi
done
if [ -x "$basedir/bin/dev/perl-use-all.pl" ] ; then
    action_detail "Trying to \`use' all required perl modules"
    "$basedir/bin/dev/perl-use-all.pl" || (( fails++ ))
fi

if [ "$fails" -ne 0 ] ; then
    action_error "Got $fails errors"
else
    action_done "success"
fi
exit "$fails"
