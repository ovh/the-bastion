#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

cd "$basedir" || exit 1

action_doing "Checking perlcritic"
# shellcheck disable=SC2086
perlcritic --color -q -p "$(dirname "$0")"/perlcriticrc .; ret=$?
if [ "$ret" = 0 ]; then
    # shellcheck disable=SC2119
    action_done
else
    action_error "perlcritic found errors"
    exit 1
fi
