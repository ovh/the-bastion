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

    if [ "$arch" = "x86_64" ] || [ "$arch" = "amd64" ]; then
        set_download_url "/${PROGRAM_NAME}.*_${os}_(x86_|amd)64\\.tar\\.gz$"
    else
        set_download_url "/${PROGRAM_NAME}.*_${os}_$arch\\.tar\\.gz$"
    fi
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

install_main "$@"
