#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
#
# this script can be called by pam during sshd login, when negotiating MFA.
# it'll show in how many days the user password will expire.
# it can be called this way:
#
#auth   optional   pam_exec.so   quiet debug stdout /opt/bastion/bin/shell/pam_exec_pwd_info.sh

[ -n "$PAM_USER" ] || exit 0
exp_date=$(chage -l "$PAM_USER" 2>/dev/null | grep 'Password expires' | cut -d: -f2-)
exp_date=$(date -d "$exp_date" +'%Y/%m/%d' 2>/dev/null)
[ -n "$exp_date" ] || exit 0
exp=$(date -d "$exp_date" +'%s')
now=$(date +'%s')
daysleft=$(( (exp - now) / 86400 ))
echo "Your password expires on $exp_date, in $daysleft days"
