#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
set -e

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

opt_dev=0
opt_install=0
opt_syslogng=0
opt_ttyrec=0
opt_supervisor=0
while builtin getopts "distv" opt; do
    # shellcheck disable=SC2154
    case "$opt" in
        "d") opt_dev=1;;
        "i") opt_install=1;;
        "s") opt_syslogng=1;;
        "t") opt_ttyrec=1;;
        "v") opt_supervisor=1;;
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
                coreutils netcat bash libcgi-pm-perl iputils-ping tar"
    # workaround for debian/armhf: curl fails to validate some SSL certificates,
    # whereas wget succeeds; this is needed for e.g. install-ttyrec.sh
    if [ "$(uname -m)" = armv7l ]; then
        wanted_list="$wanted_list wget"
    fi
    [ "$opt_dev" = 1 ] && wanted_list="$wanted_list libperl-critic-perl perltidy shellcheck openssl"
    if { [ "$LINUX_DISTRO" = debian ] && [ "$DISTRO_VERSION_MAJOR" -lt 9 ]; } ||
       { [ "$LINUX_DISTRO" = ubuntu ] && [ "$DISTRO_VERSION_MAJOR" -le 16 ]; }; then
        wanted_list="$wanted_list openssh-blacklist openssh-blacklist-extra"
    fi
    if { [ "$LINUX_DISTRO" = debian ] && [ "$DISTRO_VERSION_MAJOR" -ge 8 ]; } ||
       { [ "$LINUX_DISTRO" = ubuntu ] && [ "$DISTRO_VERSION_MAJOR" -ge 14 ]; }; then
        wanted_list="$wanted_list liblinux-prctl-perl libpam-google-authenticator pamtester"
    fi
    [ "$opt_syslogng" = 1 ] && wanted_list="$wanted_list syslog-ng syslog-ng-core"
    [ "$opt_ttyrec" = 1 ] && wanted_list="$wanted_list ovh-ttyrec"
    [ "$opt_supervisor" = 1 ] && wanted_list="$wanted_list supervisor"

    if [ "$opt_install" = 1 ]; then
            export DEBIAN_FRONTEND=noninteractive
            # shellcheck disable=SC2086
            apt-get update && apt-get install -y $wanted_list
            exit $?
    fi

    installed=$(dpkg -l | awk '/^ii/ {print $2}' | cut -d: -f1)
    install_cmd="apt-get install"
elif echo "$DISTRO_LIKE" | grep -q -w rhel; then
    wanted_list="perl-JSON perl-Net-Netmask perl-Net-IP \
            perl-Net-DNS perl-DBD-SQLite perl-TermReadKey \
            sudo fping xz sqlite binutils acl gnupg2 rsync perl-DateTime \
            perl-JSON-XS inotify-tools lsof curl perl-Term-ReadLine-Gnu \
            perl-libwww-perl perl-Digest perl-Net-Server cryptsetup mosh \
            expect openssh-server nc bash perl-CGI perl(Test::More) passwd \
            cracklib-dicts perl-Time-Piece perl-Time-HiRes diffutils \
            perl-Sys-Syslog pamtester google-authenticator qrencode-libs \
            util-linux-user perl-LWP-Protocol-https findutils tar"
    if [ "$DISTRO_VERSION_MAJOR" = 7 ]; then
        wanted_list="$wanted_list fortune-mod coreutils"
    fi
    [ "$opt_syslogng" = 1 ] && wanted_list="$wanted_list syslog-ng"
    [ "$opt_ttyrec" = 1 ] && wanted_list="$wanted_list ovh-ttyrec"
    [ "$opt_supervisor" = 1 ] && wanted_list="$wanted_list supervisor"

    if [ "$opt_install" = 1 ]; then
            if [ "$DISTRO_VERSION_MAJOR" = 8 ]; then
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
            fi
            if command -v dnf >/dev/null; then
                dnf_or_yum=dnf
            else
                dnf_or_yum=yum
            fi
            $dnf_or_yum makecache
            $dnf_or_yum install -y epel-release
            # shellcheck disable=SC2086
            $dnf_or_yum install -y $wanted_list
            exit 0
    fi

    installed="FIXME"
    install_cmd="yum install"
elif echo "$DISTRO_LIKE" | grep -q -w suse; then
    wanted_list="perl-common-sense perl-JSON perl-Net-Netmask perl-Net-IP \
            perl-Net-DNS perl-DBD-SQLite perl-TermReadKey perl-DateTime \
            fortune sudo fping \
            xz sqlite binutils acl gpg2 rsync \
            perl-JSON-XS inotify-tools lsof curl perl-TermReadLine-Gnu \
            perl-libwww-perl perl-Digest perl-IO-Socket-SSL \
            perl-Net-Server cryptsetup mosh expect openssh \
            coreutils netcat-openbsd bash perl-CGI iputils \
            perl-Time-HiRes perl-Unix-Syslog hostname perl-LWP-Protocol-https"
        wanted_list="$wanted_list google-authenticator-libpam tar"
    [ "$opt_syslogng" = 1 ] && wanted_list="$wanted_list syslog-ng"
    [ "$opt_ttyrec" = 1 ] && wanted_list="$wanted_list ovh-ttyrec"
    [ "$opt_supervisor" = 1 ] && wanted_list="$wanted_list python-supervisor python-setuptools"

    if [ "$opt_install" = 1 ]; then
        if [ "$opt_supervisor" = 1 ]; then
            zypper addrepo https://download.opensuse.org/repositories/home:bmanojlovic/openSUSE_Leap_15.0/home:bmanojlovic.repo
            zypper refresh
        fi
        # shellcheck disable=SC2086
        zypper install -y $wanted_list
        exit $?
    fi

    installed="FIXME"
    install_cmd="zypper install"
elif [ "$OS_FAMILY" = FreeBSD ]; then
    wanted_list="base64 coreutils rsync bash sudo pamtester p5-JSON p5-JSON-XS gnupg \
            p5-common-sense p5-DateTime p5-Net-IP p5-DBD-SQLite p5-Net-Netmask lsof \
            p5-Term-ReadKey expect fping p5-Net-Server p5-CGI p5-LWP-Protocol-https"
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
