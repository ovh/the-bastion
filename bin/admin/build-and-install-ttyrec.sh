#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
set -e

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

TTYREC_ARCHIVE_URL='https://github.com/ovh/ovh-ttyrec/archive/master.zip'

action_doing "Detecting OS..."
action_detail "Found $OS_FAMILY"
if [ "$OS_FAMILY" = Linux ]; then
    action_detail "Found distro $LINUX_DISTRO version $DISTRO_VERSION (major $DISTRO_VERSION_MAJOR), distro like $DISTRO_LIKE"
fi
action_done

if echo "$DISTRO_LIKE" | grep -q -w debian; then
    list="make gcc unzip wget"
    if [ "$LINUX_DISTRO" = debian ] && [ "$DISTRO_VERSION_MAJOR" -ge 9 ]; then
        list="$list libzstd-dev"
    elif [ "$LINUX_DISTRO" = ubuntu ] && [ "$DISTRO_VERSION_MAJOR" -ge 16 ]; then
        list="$list libzstd-dev"
    fi
    apt-get update
    # shellcheck disable=SC2086
    apt-get install -y $list
    # shellcheck disable=SC2086
    cleanup() {
        apt-get remove --purge -y $list
        apt-get autoremove --purge -y
    }
elif echo "$DISTRO_LIKE" | grep -q -w rhel; then
    yum install -y gcc make unzip wget
    cleanup() { yum remove -y gcc make unzip wget; }
elif echo "$DISTRO_LIKE" | grep -q -w suse; then
    zypper install -y gcc make libzstd-devel-static unzip wget
    cleanup() { zypper remove -y -u gcc make libzstd-devel-static unzip wget; }
else
    echo "This script doesn't support this OS yet ($DISTRO_LIKE)" >&2
    exit 1
fi

cd /tmp
wget "$TTYREC_ARCHIVE_URL"
unzip master.zip
cd ovh-ttyrec-master
./configure
make
make install
cleanup

if ttyrec -V; then
    action_done "ttyrec correctly installed"
else
    action_error "couldn't install ttyrec"
fi
