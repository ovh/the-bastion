# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash

# common parts of install-{ttyrec,yubico-piv-checker,the-bastion-mkhash-helper}.sh

# shellcheck source=lib/shell/functions.inc disable=SC2128
. "$(dirname "$BASH_SOURCE")"/functions.inc

install_usage() {
    cat <<EOF
Options:
    -s   Download and install precompiled $PROGRAM_NAME static binaries in /usr/local/bin
    -d   Download the prebuilt Debian package, and install it (for Debian, Ubuntu and derivatives)
    -r   Download the prebuild RPM package, and install it (for RHEL, CentOS and derivatives)
    -a   Automatically detect the OS to install the proper package type, fallback to static binaries if no package applies
    -h   Show this help
EOF
}

set_download_url() {
    local pattern="$1"
    local verbosity=""

    action_doing "Looking for download tool..."
    if command -v wget >/dev/null; then
        action_done wget
        verbosity="-q"
        [ "$CI" = true ] && verbosity="-v"
        _apicall() {
            wget $verbosity -O - --header="Accept: application/vnd.github.v3+json" "$1" || true
        }
        _download() {
            # shellcheck disable=SC2317,SC2086
            wget $verbosity "$1"
        }
    elif command -v fetch >/dev/null; then
        action_done fetch
        [ "$CI" = true ] && verbosity="-v"
        _apicall() {
            fetch $verbosity -o - "$1" || true
        }
        _download() {
            # shellcheck disable=SC2317,SC2086
            fetch $verbosity "$1"
        }
    elif command -v curl >/dev/null; then
        action_done curl
        verbosity="-s"
        [ "$CI" = true ] && verbosity="-v"
        _apicall() {
            curl $verbosity -L -H 'Accept: application/vnd.github.v3+json' "$1" || true
        }
        _download() {
            # shellcheck disable=SC2317,SC2086
            curl $verbosity -L -O "$1"
        }
    else
        action_error "Couldn't find wget, curl nor fetch"
        exit 1
    fi
    action_doing "Getting latest release for arch $arch..."
    payload=$(mktemp)

    # shellcheck disable=SC2034
    for try in 1 2; do

        if [ "$USE_DEFAULT_URLS" = 1 ]; then
            urls="$(default_urls)"
        else
            _apicall "$RELEASE_API_URL" > "$payload"

            if [ ! -s "$payload" ]; then
                action_error "API returned an empty body, did we hit the query limit? Auto-retrying with hardcoded URLs"
                USE_DEFAULT_URLS=1
                continue
            fi

            if command -v jq >/dev/null; then
                # If we have jq, we can do it properly
                urls="$(jq -r '.[0].assets|.[]|.browser_download_url' < "$payload" || true)"
            elif perl -MJSON -e 1 2>/dev/null; then
                # If we don't, there's a good chance we have Perl with the JSON module, use it
                urls="$(perl -MJSON -e 'undef $/; $d=decode_json(<>); exit if ref $d ne "ARRAY"; foreach(@{ $d->[0]{assets} || [] }) { print $_->{browser_download_url}."\n" }' "$payload")"
            else
                # Otherwise, go the ugly way, don't bother the user in installing jq just for this need
                urls="$(grep -Eo 'https://[a-z0-9./_-]+' "$payload")"
            fi
        fi

        url="$(echo "$urls" | grep -E "$pattern" | head -n1)"

        if [ -n "$url" ]; then
            # success
            action_detail "$url"
            test -f "$payload" && rm -f "$payload"
            return 0
        elif [ -z "$urls" ]; then
            action_error "Couldn't find any URL in the returned body, did we hit the query limit? Body follows:"
            cat "$payload"
            action_error "Auto-retrying with hardcoded URLs"
            USE_DEFAULT_URLS=1
            continue
        else
            action_error "Couldn't find a proper URL for your architecture ($arch), looked for pattern '$pattern'. You may have to compile $PROGRAM_NAME yourself!"
            action_detail "Maybe the release asset naming pattern has changed and we're not aware, if you think one of the packages below match your OS & arch, you may download & install them manually:"
            for line in $urls; do
                action_detail "$line"
            done
            test -f "$payload" && rm -f "$payload"
            exit 1
        fi
    done

    # unreachable code, but fail just in case
    exit 1
}

prepare_temp_folder() {
    tmpfolder=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "test -d '$tmpfolder' && rm -rf -- '$tmpfolder'" EXIT
    cd "$tmpfolder" || exit 1
}

# shellcheck disable=SC2034
set_archre() {
    if command -v dpkg >/dev/null; then
        arch=$(dpkg --print-architecture)
    elif command -v rpm >/dev/null; then
        arch=$(rpm -E '%{_arch}')

        # in some cases, %{_arch} is not defined, so the macro isn't expanded,
        # we have to find it ourselves
        if [ "$arch" = "%{_arch}" ]; then
            arch=$(rpm --showrc | grep "^install arch" | awk '{print $4}')
        fi
    else
        arch=$(uname -m)
    fi

    if [ "$arch" = "x86_64" ] || [ "$arch" = "amd64" ]; then
        archre="(x86_|amd)64"
    elif [ "$arch" = "ppc64el" ]; then
        archre="ppc64(le|el)"
    else
        archre="$arch"
    fi
}

action_package() {
    type="$1"
    case "$type" in
        deb)
            if ! command -v dpkg >/dev/null; then
                echo "Couldn't find dpkg, aborting" >&2
                exit 1
            fi;;
        rpm)
            if ! command -v rpm >/dev/null; then
                echo "Couldn't find rpm, aborting" >&2
                exit 1
            fi;;
        *) echo "Unsupported package type $type" >&2; exit 1;;
    esac

    set_archre
    set_download_url_package "$type"
    prepare_temp_folder
    _download "$url"

    action_done

    action_doing "Installing package"
    case "$type" in
        deb) dpkg -i  -- *.deb; ret=$?;;
        rpm) rpm -Uvh -- *.rpm; ret=$?;;
        *) exit 1;;
    esac

    if [ "$ret" = 0 ]; then
        action_done
    else
        action_error
    fi

    cd /
}

action_auto() {
    action_doing "Detecting OS..."
    action_detail "Found $OS_FAMILY"
    if [ "$OS_FAMILY" = Linux ]; then
        action_detail "Found distro $LINUX_DISTRO version $DISTRO_VERSION (major $DISTRO_VERSION_MAJOR), distro like $DISTRO_LIKE"
    fi
    action_done

    case "$DISTRO_LIKE" in
        *debian*) action_package deb;;
        *rhel*)   action_package rpm;;
        *suse*)   action_package rpm;;
        freebsd)  action_static;;
        *)
            if [ "$OS_FAMILY" = Linux ]; then
                action_static
            else
                echo "This script doesn't support this OS yet ($OS_FAMILY/$DISTRO_LIKE)" >&2
                exit 1
            fi;;
    esac
}

install_main() {
    if [ "$OS_FAMILY" != "Linux" ] && [ "$OS_FAMILY" != "FreeBSD" ]; then
        echo "Sorry, your OS ($OS_FAMILY) is not supported." >&2
        exit 1
    fi

    # in CI mode, delay a random amount of time, to avoid getting blocked
    # when several runs are started in parallel
    if [ "$CI" = true ]; then
        amount=$(( RANDOM % 10 * 3 ))
        action_doing "Sleeping $amount seconds in CI mode..."
        sleep $amount
        action_done
    fi

    while getopts :sdrah arg; do
        case "$arg" in
            s) action_static;      exit 0;;
            d) action_package deb; exit 0;;
            r) action_package rpm; exit 0;;
            a) action_auto;        exit 0;;
            h) install_usage;      exit 0;;
            *) echo "Invalid option: -$OPTARG"; usage; exit 1;;
        esac
    done
    install_usage
}
