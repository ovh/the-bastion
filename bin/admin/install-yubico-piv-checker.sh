#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
set -e

PROGRAM_NAME=yubico-piv-checker
RELEASE_API_URL="https://api.github.com/repos/ovh/$PROGRAM_NAME/releases"

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/install.inc
. "$basedir"/lib/shell/install.inc

set_download_url_package() {
    type="$1"
    case "$type" in
        rpm) set_download_url "/${PROGRAM_NAME}-.+\\.$archre\\.rpm$";;
        deb) set_download_url "/${PROGRAM_NAME}_.+_$archre\\.deb$";;
        *) exit 1;;
    esac
}

action_static() {
    set_archre
    os=$(uname -s | tr '[:upper:]' '[:lower:]')

    set_download_url "/${PROGRAM_NAME}.*_${os}_${archre}\\.tar\\.gz$"
    prepare_temp_folder

    _download "$url"
    # we have just one archive file in the current temp directory
    # shellcheck disable=SC2035
    tar xzf *.tar.gz
    action_done

    action_doing "Installing files"
    for file in $PROGRAM_NAME; do
        action_detail "/usr/local/bin/$file"
        install -m 0755 "$file" /usr/local/bin/
    done
    action_done

    cd /
}

# only used when/if the API is down and we're in CI mode
default_urls() {
    local ver="1.0.0"
    local list="
        -${ver}.aarch64.rpm
        -${ver}.armv7hnl.rpm
        -${ver}.armv6l.rpm
        -${ver}.i386.rpm
        -${ver}.mips64el.rpm
        -${ver}.ppc64le.rpm
        -${ver}.s390x.rpm
        -${ver}.x86_64.rpm
        _${ver}_amd64.deb
        _${ver}_arm64.deb
        _${ver}_armel.deb
        _${ver}_armhf.deb
        _${ver}_darwin_amd64.tar.gz
        _${ver}_freebsd_386.tar.gz
        _${ver}_freebsd_amd64.tar.gz
        _${ver}_freebsd_arm64.tar.gz
        _${ver}_freebsd_armv5.tar.gz
        _${ver}_freebsd_armv7.tar.gz
        _${ver}_i386.deb
        _${ver}_linux_386.tar.gz
        _${ver}_linux_amd64.tar.gz
        _${ver}_linux_arm64.tar.gz
        _${ver}_linux_armv5.tar.gz
        _${ver}_linux_armv7.tar.gz
        _${ver}_linux_mips64le_hardfloat.tar.gz
        _${ver}_linux_ppc64le.tar.gz
        _${ver}_linux_s390x.tar.gz
        _${ver}_mips64el.deb
        _${ver}_netbsd_386.tar.gz
        _${ver}_netbsd_amd64.tar.gz
        _${ver}_netbsd_armv5.tar.gz
        _${ver}_netbsd_armv7.tar.gz
        _${ver}_openbsd_386.tar.gz
        _${ver}_openbsd_amd64.tar.gz
        _${ver}_openbsd_arm64.tar.gz
        _${ver}_openbsd_armv5.tar.gz
        _${ver}_openbsd_armv7.tar.gz
        _${ver}_ppc64le.deb
        _${ver}_s390x.deb
        _${ver}_windows_amd64.tar.gz"
    for suffix in $list
    do
        echo "https://github.com/ovh/yubico-piv-checker/releases/download/v${ver}/yubico-piv-checker${suffix}"
    done
}

install_main "$@"
