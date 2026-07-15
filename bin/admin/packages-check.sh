#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
set -e

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

opt_dev=0
opt_install=0
opt_syslogng=0
while builtin getopts "distv" opt; do
    # shellcheck disable=SC2154
    case "$opt" in
        "d") opt_dev=1;;
        "i") opt_install=1;;
        "s") opt_syslogng=1;;
        *)  echo "Error $opt"; exit 1;;
    esac
done

action_doing "Detecting OS..."
action_detail "Found $OS_FAMILY"
if [ "$OS_FAMILY" = Linux ]; then
    action_detail "Found distro $LINUX_DISTRO version $DISTRO_VERSION (major $DISTRO_VERSION_MAJOR), distro like $DISTRO_LIKE"
fi
action_done

action_doing "Checking the list of installed packages..."
if echo "$DISTRO_LIKE" | grep -q -w debian; then
    wanted_list="libcommon-sense-perl libjson-perl libnet-netmask-perl libnet-ip-perl \
                libnet-dns-perl libdbd-sqlite3-perl libterm-readkey-perl libdatetime-perl \
                fortunes-bofh-excuses sudo fping \
                xz-utils sqlite3 binutils acl libtimedate-perl gnupg rsync \
                libjson-xs-perl inotify-tools lsof curl libterm-readline-gnu-perl \
                libwww-perl libdigest-sha-perl libnet-ssleay-perl \
                libnet-server-perl cryptsetup mosh expect openssh-server locales \
                coreutils bash libcgi-pm-perl iputils-ping tar libtext-template-perl \
                liblinux-prctl-perl libpam-google-authenticator pamtester"
    # workaround for debian/armhf: curl fails to validate some SSL certificates,
    # whereas wget succeeds; this is needed for e.g. install-ttyrec.sh
    if [ "$(uname -m)" = armv7l ]; then
        wanted_list="$wanted_list wget"
    fi
    # Debian >= 13 and Ubuntu >= 24.10 need libpam-lastlog2 instead of libpam-lastlog (that was bundled with libpam-modules)
    if [ "$LINUX_DISTRO" = ubuntu ] && { [ "$DISTRO_VERSION" = "24.10" ] || [ "$DISTRO_VERSION_MAJOR" -ge 25 ]; }; then
        wanted_list="$wanted_list libpam-lastlog2"
    fi
    if [ "$LINUX_DISTRO" = debian ] && [ "$DISTRO_VERSION_MAJOR" -ge 13 ]; then
        wanted_list="$wanted_list libpam-lastlog2"
    fi
    # optional packages
    [ "$opt_dev" = 1 ] && wanted_list="$wanted_list libperl-critic-perl libtest-deep-perl perltidy shellcheck openssl wget"
    [ "$opt_syslogng" = 1 ] && wanted_list="$wanted_list syslog-ng syslog-ng-core"

    if [ "$opt_install" = 1 ]; then
            export DEBIAN_FRONTEND=noninteractive
            # shellcheck disable=SC2086
            apt-get update && apt-get install -y --no-install-recommends $wanted_list
            exit $?
    fi

    installed=$(dpkg -l | awk '/^ii/ {print $2}' | cut -d: -f1)
    install_cmd="apt-get install"
elif echo "$DISTRO_LIKE" | grep -q -w rhel; then
    wanted_list="perl perl-JSON perl-Net-Netmask perl-Net-IP perl-Text-Template \
            perl-Net-DNS perl-DBD-SQLite perl-TermReadKey procps-ng \
            sudo fping xz sqlite binutils acl gnupg2 rsync perl-DateTime \
            perl-JSON-XS inotify-tools lsof curl perl-Term-ReadLine-Gnu \
            perl-libwww-perl perl-Digest perl-Net-Server cryptsetup mosh \
            expect openssh-server bash perl-CGI perl-Test-Simple passwd \
            cracklib-dicts perl-Time-Piece perl-Time-HiRes diffutils \
            perl-Sys-Syslog pamtester qrencode-libs util-linux-user \
            perl-LWP-Protocol-https perl-Test-Deep findutils tar iputils"
    [ "$opt_syslogng" = 1 ] && wanted_list="$wanted_list syslog-ng"


    if [ "$opt_install" = 1 ]; then
            # in December 2020, they added "-Linux" to their repo name, so trying both combinations
            # also try with "Rocky-" for RockyLinux
            for repo in PowerTools Extras
            do
                for prefix in CentOS CentOS-Linux Rocky
                do
                    test -f /etc/yum.repos.d/$prefix-$repo.repo || continue
                    sed -i -e 's/enabled=.*/enabled=1/g' /etc/yum.repos.d/$prefix-$repo.repo
                done
            done
            dnf makecache
            dnf install -y epel-release
            if [ -x /usr/bin/crb ]; then
                action_detail "Enabling CRB..."
                /usr/bin/crb enable
            fi
            if [ "$DISTRO_VERSION_MAJOR" -ge 9 ]; then
                extraopts='--allowerasing'
            else
                extraopts=''
            fi
            # shellcheck disable=SC2086
            dnf install -y $extraopts $wanted_list

            # under at least RockyLinux 10, google-authenticator seems to be missing, but we can
            # install it manually from epel of Fedora. First, try to install it the regular way
            if ! dnf install -y $extraopts google-authenticator; then
                # okay, try it manually
                action_detail "Trying to install google-authenticator manually..."
                rpmname=$(curl -sL "https://dl.fedoraproject.org/pub/epel/$DISTRO_VERSION_MAJOR/Everything/x86_64/Packages/g/" | \
                    grep -Eo 'google-authenticator-[a-z0-9._-]+\.x86_64\.rpm' | head -n1)
                if [ -n "$rpmname" ]; then
                    dltmpdir=$(mktemp -d)
                    pushd "$dltmpdir" >/dev/null
                    if curl -O "https://dl.fedoraproject.org/pub/epel/$DISTRO_VERSION_MAJOR/Everything/x86_64/Packages/g/$rpmname"; then
                        rpm -Uvh "$rpmname"
                        rm -f "$rpmname"
                    fi
                    popd >/dev/null
                    rmdir "$dltmpdir"
                fi
            fi

            exit 0
    fi

    installed=$(rpm -qa --queryformat '%{NAME}\n')
    install_cmd="dnf install"
elif echo "$DISTRO_LIKE" | grep -q -w suse; then
    wanted_list="perl-common-sense perl-JSON perl-Net-Netmask perl-Net-IP \
            perl-Net-DNS perl-DBD-SQLite perl-Term-ReadKey perl-DateTime \
            fortune sudo fping perl perl-base gzip procps \
            xz sqlite3 binutils acl gpg2 rsync perl-Text-Template \
            perl-JSON-XS inotify-tools lsof curl perl-TermReadLine-Gnu \
            perl-libwww-perl perl-Digest perl-IO-Socket-SSL \
            perl-Net-Server cryptsetup mosh expect openssh \
            coreutils bash perl-CGI iputils util-linux-systemd \
            perl-Time-HiRes perl-Unix-Syslog hostname perl-LWP-Protocol-https \
            google-authenticator-libpam tar perl-Test-Deep"
    [ "$opt_syslogng" = 1 ] && wanted_list="$wanted_list syslog-ng"

    if [ "$LINUX_DISTRO" = opensuse-leap ] && [ "$DISTRO_VERSION_MAJOR" -ge 16 ]; then
        # openSUSE Leap >= 16 dropped most standalone perl module packages from the
        # OSS repo; they're now provided by the devel:languages:perl OBS repo, which
        # we add below. Core perl modules are now provided by the 'perl' package itself.
        new_list=''
        for pkg in $wanted_list; do
            case "$pkg" in
                perl-Time-HiRes|perl-Digest) continue;;
                *)                           new_list="$new_list $pkg";;
            esac
        done
        wanted_list="$new_list"
        # pamtester is available for >= 16.0
        wanted_list="$wanted_list pamtester"

        if [ "$opt_install" = 1 ]; then
            perl_repo="https://download.opensuse.org/repositories/devel:/languages:/perl/$DISTRO_VERSION/"
            if ! zypper --non-interactive repos devel_languages_perl >/dev/null 2>&1; then
                zypper --non-interactive addrepo --refresh "$perl_repo" devel_languages_perl
            fi
            # pamtester is not in the openSUSE OSS repos, but the official
            # Linux-PAM project on OBS ships it for Leap >= 16.0
            pamtester_repo="https://download.opensuse.org/repositories/Linux-PAM/$DISTRO_VERSION/Linux-PAM.repo"
            if ! zypper --non-interactive repos Linux-PAM >/dev/null 2>&1; then
                zypper --non-interactive addrepo --refresh "$pamtester_repo"
            fi

            # refresh the repos and import the keys
            zypper --non-interactive --gpg-auto-import-keys refresh
        fi

    fi

    if [ "$opt_install" = 1 ]; then
        # shellcheck disable=SC2086
        zypper install -y $wanted_list
        exit $?
    fi

    installed=$(rpm -qa --queryformat '%{NAME}\n')
    install_cmd="zypper install"
elif [ "$OS_FAMILY" = FreeBSD ]; then
    wanted_list="base64 coreutils rsync bash sudo pamtester p5-JSON p5-JSON-XS gnupg \
            p5-common-sense p5-DateTime p5-Net-IP p5-DBD-SQLite p5-Net-Netmask lsof \
            p5-Term-ReadKey expect fping p5-Net-Server p5-CGI p5-LWP-Protocol-https \
            p5-Test-Deep p5-Term-ReadLine-Gnu p5-Text-Template"
    install_cmd="pkg add"
    installed=""
    for i in $wanted_list
    do
        if pkg info -e "$i"; then
                installed="$installed $i"
        fi
    done
    if [ "$opt_install" = 1 ]; then
        # shellcheck disable=SC2086
        pkg install -y $wanted_list
        exit $?
    fi
else
    echo "This script doesn't support this OS yet ($DISTRO_LIKE)" >&2
    exit 1
fi

missing=''
for i in $wanted_list ; do
    ok=0
    for j in $installed ; do
        [ "$i" = "$j" ] && ok=1 && break
    done
    [ $ok = 1 ] || missing="$missing $i"
done

if [ -n "$missing" ] ; then
    action_error "Some packages are missing, to install them, use:"
    action_detail "$install_cmd$missing"
else
    action_done "All needed packages are installed"
fi
