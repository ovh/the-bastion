# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash

# shellcheck source=lib/shell/colors.inc disable=SC2128
. "$(dirname "$BASH_SOURCE")"/colors.inc

# authorized_keys file, relative to the user's HOME directory.
# if you change this, also change it in lib/perl/OVH/Bastion.pm
# shellcheck disable=SC2034
AK_FILE=".ssh/authorized_keys2"

OS_FAMILY=$(uname -s)
LINUX_DISTRO=unknown
DISTRO_VERSION=''
DISTRO_LIKE=''
if [ -e /etc/os-release ]; then
    LINUX_DISTRO=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
    DISTRO_LIKE=$(grep '^ID_LIKE=' /etc/os-release | cut -d= -f2 | tr -d '"')
    DISTRO_VERSION=$(grep '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
fi
if [ -z "$LINUX_DISTRO" ] || [ -z "$DISTRO_VERSION" ]; then
    if command -v lsb_release >/dev/null 2>&1; then
        LINUX_DISTRO=$(lsb_release -si)
        DISTRO_VERSION=$(lsb_release -sr)
    elif [ -e /etc/debian_version ]; then
        LINUX_DISTRO=debian
        DISTRO_VERSION=$(cat /etc/debian_version)
    elif [ -e /etc/redhat-release ]; then
        LINUX_DISTRO=redhat
    fi
fi
if [ "$DISTRO_VERSION" = "buster/sid" ]; then
    DISTRO_VERSION=10
fi
LINUX_DISTRO=$(echo "$LINUX_DISTRO" | tr '[:upper:]' '[:lower:]' | tr -d ' ')
# shellcheck disable=SC2034
DISTRO_VERSION_MAJOR=$(echo "$DISTRO_VERSION" | grep -Eo '^[0-9]+' || true)
[ -z "$DISTRO_LIKE" ] && DISTRO_LIKE="$LINUX_DISTRO"

# shellcheck disable=SC2034
LOCKFILE=/var/run/bastion-upgrade.lock

# set ETC_DIR
ETC_DIR=/etc
[ "$OS_FAMILY" = FreeBSD ] && ETC_DIR=/usr/local/etc
[ "$OS_FAMILY" = NetBSD  ] && ETC_DIR=/usr/pkg/etc
# shellcheck disable=SC2034
BASTION_ETC_DIR=$ETC_DIR/bastion

# set UID0 and GID0 (os-dependent)
# shellcheck disable=SC2034
UID0=$(getent passwd 0 | awk -F: '{print $1}')
# shellcheck disable=SC2034
GID0=$(getent group  0 | awk -F: '{print $1}')
# shellcheck disable=SC2034
UID0HOME=$(getent passwd 0 | awk -F: '{print $6}')

# set sudoers_dir
SUDOERS_FILE=/etc
if [ -e /usr/local/etc/sudoers ] && ! [ -e /etc/sudoers ] ; then
    SUDOERS_FILE=/usr/local/etc
elif [ -e /usr/pkg/etc/sudoers ] && ! [ -e /etc/sudoers ] ; then
    SUDOERS_FILE=/usr/pkg/etc
fi
# shellcheck disable=SC2034
SUDOERS_DIR="$SUDOERS_FILE/sudoers.d"
SUDOERS_FILE="$SUDOERS_FILE/sudoers"

# set SSH_DIR
SSH_DIR=$ETC_DIR/ssh
if [ ! -e "$SSH_DIR" ]; then
    SSH_DIR=/etc/ssh
fi

# set PAM_DIR
PAM_DIR=$ETC_DIR/pam.d
if [ ! -e "$PAM_DIR" ]; then
    PAM_DIR=/etc/pam.d
fi

# set PAM_SSHD
# under FreeBSD, both /usr/local/etc/pam.d and /etc/pam.d can exist
PAM_SSHD="/etc/pam.d/sshd"
if [ -e "/usr/local/etc/pam.d/sshd" ]; then
    # shellcheck disable=SC2034
    PAM_SSHD="/usr/local/etc/pam.d/sshd"
fi

# set CRON_DIR
CRON_DIR=$ETC_DIR/cron.d
if [ ! -e "$CRON_DIR" ]; then
    CRON_DIR=/etc/cron.d
fi

action_doing()
{
    printf '\r*** %b\n' "$*"
}
action_detail()
{
    printf '\r`-> %b\n' "$*"
}
action_done()
{
    printf "%b" "\\r\`-> [${GREEN} OK ${NOC}]"
    if [ -n "$1" ]; then
        printf "%b" " ... $*"
    fi
    echo
}
action_warn()
{
    printf '%b %b\n' "\\r\`-> [${YELLOW}WARN${NOC}]" "$*"
}
action_error()
{
    printf '%b %b\n' "\\r\`-> [${RED}ERR.${NOC}]" "$*"
}
action_na()
{
    printf '%b %b\n' "\\r\`-> [${BLUE}N/A.${NOC}]" "$*"
}

sed_compat()
{
    local _sedcmd="$1" _file="$2"
    if sed --version 2>/dev/null | grep -q GNU || [ "$OS_FAMILY" = NetBSD ] ; then
        # GNU sed or NetBSD
        sed -i -re "$_sedcmd" "$_file"
    else
        # other BSD-style sed
        sed -i '' -re "$_sedcmd" "$_file"
    fi
}

md5sum_compat()
{
    if command -v gmd5sum >/dev/null; then
        gmd5sum "$@"; return $?
    else
        md5sum "$@"; return $?
    fi
}

useradd_compat()
{
    local _user="$1" _uid="" _home="" _shell="" _gid="" _extra=""
    shift
    if [ -n "$*" ]; then _uid="$1"; shift; fi
    if [ -n "$*" ]; then _home="$1"; shift; fi
    if [ -n "$*" ]; then _shell="$1"; shift; fi
    if [ -n "$*" ]; then _gid="$1"; shift; fi

    [ -n "$_uid"   ] && _extra="$_extra -u $_uid"
    if [ -n "$_home" ]; then
        _extra="$_extra -d $_home"
    fi
    if [ "$_home" != "/nonexistent" ]; then
        _extra="$_extra -m"
    fi
    if [ -n "$_gid" ]; then
        _extra="$_extra -g $_gid"
    elif command -v useradd >/dev/null ; then
        [ "$OS_FAMILY" != OpenBSD ] && [ "$OS_FAMILY" != NetBSD ] && _extra="$_extra -U"
    fi

    # special case for /bin/false, it might be /usr/bin/false on some BSDs
    if [ "$_shell" = /bin/false ] && ! [ -e /bin/false ] && [ -e /usr/bin/false ] ; then
        _shell="/usr/bin/false"
    fi
    [ -n "$_shell" ] && _extra="$_extra -s $_shell"

    if command -v useradd >/dev/null ; then
        if [ "$OS_FAMILY" = OpenBSD ] || [ "$OS_FAMILY" = NetBSD ]; then
            # shellcheck disable=SC2086
            useradd -r 400..499 -g =uid $_extra "$_user"
        else
            # shellcheck disable=SC2086
            useradd -r -p '*' $_extra "$_user"
        fi
    elif command -v pw >/dev/null ; then
        # shellcheck disable=SC2086
        pw useradd -n "$_user" $_extra
    else
        echo "useradd_compat: Don't know how to add user $_user!" >&2
        return 1
    fi
}

groupadd_compat()
{
    local _group="$1" _gid="$2"
    if command -v groupadd >/dev/null ; then
        if [ -n "$_gid" ] && [ "$_gid" != HIGH ]; then
            # works for Linux, NetBSD and OpenBSD
            groupadd -g "$_gid" "$_group"
        elif [ "$OS_FAMILY" = Linux ] ; then
            if [ "$_gid" = HIGH ]; then
                groupadd "$_group"
            else
                groupadd -r "$_group"
            fi
        elif [ "$OS_FAMILY" = NetBSD ]; then
            if [ "$_gid" = HIGH ]; then
                groupadd "$_group"
            else
                groupadd -r 300..399 "$_group"
            fi
        elif [ "$OS_FAMILY" = OpenBSD ]; then
            if [ -z "$_gid" ] ; then
                # try to pick a groupid ourselves...
                local _g=0
                for _g in {300..399} ; do
                    if ! groupinfo -e "$_g" ; then
                        groupadd -g "$_g" "$_group"
                        return 0
                    fi
                done
            fi
            # couldn't find any (or highid asked)... let the system decide
            groupadd "$_group"
        else
            groupadd "$_group"
        fi
    elif command -v pw >/dev/null ; then
        if [ -n "$_gid" ] && [ "$_gid" != HIGH ]; then
            pw groupadd -n "$_group" -g "$_gid"
            return 0
        elif [ -z "$_gid" ] ; then
            # try to pick a groupid ourselves...
            local _g=0
            for _g in {300..399} ; do
                if ! pw groupshow -g "$_g" &>/dev/null ; then
                    pw groupadd -g "$_g" -n "$_group"
                    return 0
                fi
            done
        fi
        # couldn't find any (or highid asked)... let the system decide
        pw groupadd -n "$_group"
    else
       echo "groupadd_compat: Don't know how to add group $_group!" >&2
        return 1
    fi
}

usermod_changeuid_compat()
{
    local _user="$1" _newuid="$2"
    if command -v usermod >/dev/null ; then
        usermod -u "$_newuid" "$_user"
    elif command -v pw >/dev/null ; then
        pw usermod -n "$_user" -u "$_newuid"
    else
        echo "usermod_changeuid_compat: Don't know how to change uid of user $_user to $_newuid!" >&2
        return 1
    fi
}

group_change_gid_compat()
{
    local _group="$1" _newgid="$2"
    if command -v groupmod >/dev/null ; then
        groupmod -g "$_newgid" "$_group"; return $?
    elif command -v pw >/dev/null ; then
        pw groupmod -n "$_group" -g "$_newgid"; return $?
    else
        echo "group_change_gid_compat: Don't know how to change gid of group $_group to $_newgid!" >&2
        return 1
    fi
}

group_rename_compat()
{
    local _oldname="$1" _newname="$2"
    if command -v groupmod >/dev/null ; then
        groupmod -n "$_newname" "$_oldname"; return $?
    elif command -v pw >/dev/null ; then
        pw groupmod -n "$_oldname" -l "$_newname"; return $?
    else
        echo "group_rename_compat: Don't know how to rename group $_oldname to $_newname!" >&2
        return 1
    fi
}

add_user_to_group_compat()
{
    local _user="$1" _group="$2"
    if command -v usermod >/dev/null ; then
        if [ "$OS_FAMILY" = OpenBSD ] || [ "$OS_FAMILY" = NetBSD ] ; then
            usermod -G "$_group" "$_user"
        else
            usermod -a -G "$_group" "$_user"
        fi
    elif command -v pw >/dev/null ; then
        pw groupmod -n "$_group" -m "$_user"
    else
        echo "add_user_to_group_compat: don't know how to add $_user to $_group!" >&2
        return 1
    fi
}

del_user_from_group_compat()
{
    local _user="$1" _group="$2"
    if command -v gpasswd >/dev/null ; then
        gpasswd -d "$_user" "$_group"
    elif command -v pw >/dev/null ; then
        pw groupmod -n "$_group" -d "$_user"
    else
        echo "del_user_from_group_compat: don't know how to del $_user from $_group!" >&2
        return 1
    fi
}

_logtag="$(basename "$0")[$$]"
__log()
{
    level="$1"
    shift
    [ -n "$LOG_FACILITY" ] && logger -t "$_logtag" -p "$LOG_FACILITY"."$level" "$*"
    [ -z "$LOG_QUIET"    ] && echo "$(date +'[%Y/%m/%d %H:%M:%S] ')$*"
}
_log()
{
    __log info "$*"
}
_warn()
{
    __log warn "WARN: $*"
}
_err()
{
    __log err "ERROR: $*" >&2
}
