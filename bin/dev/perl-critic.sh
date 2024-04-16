#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

cd "$basedir" || exit 1

action_doing "Checking perlcritic"
# shellcheck disable=SC2086
perlcritic --color -q -p "$(dirname "$0")"/perlcriticrc bin contrib docker install lib tests; ret1=$?
perlcritic --color -q -p "$(dirname "$0")"/perlcriticrc lib/perl/OVH/Bastion/*.inc; ret2=$?
if [ "$ret1" = 0 ] && [ "$ret2" = 0 ]; then
    # shellcheck disable=SC2119
    action_done
else
    action_error "perlcritic found errors"
    exit 1
fi
