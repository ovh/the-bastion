#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck disable=SC2086
# shellcheck disable=SC2016
# shellcheck disable=SC2046
set -e

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

remote_ip="$1"
remote_port="$2"
account0="$3"
user_ssh_key_path="$4"
root_ssh_key_path="$5"
osh_etc="$6"
remote_basedir="$7"
[ -n "$osh_etc" ] || osh_etc=/etc/bastion
[ -n "$remote_basedir" ] || remote_basedir="$basedir"

[ -z "$HAS_ED25519"      ] && HAS_ED25519=1
[ -z "$HAS_BLACKLIST"    ] && HAS_BLACKLIST=0
[ -z "$HAS_MFA"          ] && HAS_MFA=1
[ -z "$HAS_MFA_PASSWORD" ] && HAS_MFA_PASSWORD=0
[ -z "$HAS_PAMTESTER"    ] && HAS_PAMTESTER=1
[ -z "$nocc"             ] && nocc=0
[ -z "$nowait"           ] && nowait=0
[ -z "$TARGET"           ] && TARGET=''
[ -z "$TEST_SCRIPT"      ] && TEST_SCRIPT=''

# die if using an unset var
set -u

if [ -z "$root_ssh_key_path" ] ; then
    echo "Usage: $0 <IP> <Port> <remote_user_name> <user_ssh_key_path> <root_ssh_key_path>"
    exit 1
fi

# does ssh work there ?
server_output=$(echo test | nc -w 1 $remote_ip $remote_port)
if echo "$server_output" | grep -q ^SSH-2 ; then
    echo SSH to $remote_ip:$remote_port OK
else
    echo "Port $remote_port doesn't seem open on $remote_ip, or is not SSH! ($server_output)"
    exit 1
fi

# those vars are also used in all our modules
# shellcheck disable=SC2034
{
    account1="testu_Ser.1-"
    account2="tesT-user2_"
    account3=teStuser3
    account4=TeStUsEr4
    uid1=9001
    uid2=9002
    uid3=9003
    uid4=9004
    group1="test_Group1-"
    group2="tEst-group2_"
    group3=testgrOup3
    shellaccount="test-shell_"
    randomstr=randomstr_pUuGXu3tfhi5WII4_randomstr

    mytmpdir=$(mktemp -d -t bastiontest.XXXXXX)
    trap 'echo CLEANING UP ; rm -rf "$mytmpdir" ; exit 255' EXIT
    account0key1file="$mytmpdir/account0key1file"
    account1key1file="$mytmpdir/account1key1file"
    account1key2file="$mytmpdir/account1key2file"
    account2key1file="$mytmpdir/account2key1file"
    account3key1file="$mytmpdir/account3key1file"
    account4key1file="$mytmpdir/account4key1file"
    rootkeyfile="$mytmpdir/rootkeyfile"
    for f in $account1key1file $account1key2file $account2key1file $account3key1file $account4key1file
    do
        ssh-keygen -N '' -t ecdsa -f $f -q
    done
    cp $user_ssh_key_path $account0key1file
    ssh-keygen -y -f $user_ssh_key_path > $account0key1file.pub
    cp $root_ssh_key_path $rootkeyfile
    ssh-keygen -y -f $root_ssh_key_path > $rootkeyfile.pub
    chmod 400 $account0key1file

    jq="jq --raw-output --compact-output --sort-keys"
    js="--json-greppable"
    t="timeout --foreground 30"
    tf="timeout --foreground 15"
    a0="  $t ssh -F $mytmpdir/ssh_config -i $account0key1file $account0@$remote_ip -p $remote_port -- $js "
    a1="  $t ssh -F $mytmpdir/ssh_config -i $account1key1file $account1@$remote_ip -p $remote_port -- $js "
    a1k2="$t ssh -F $mytmpdir/ssh_config -i $account1key2file $account1@$remote_ip -p $remote_port -- $js "
    a2="  $t ssh -F $mytmpdir/ssh_config -i $account2key1file $account2@$remote_ip -p $remote_port -- $js "
    a3="  $t ssh -F $mytmpdir/ssh_config -i $account3key1file $account3@$remote_ip -p $remote_port -- $js "
    a4="  $t ssh -F $mytmpdir/ssh_config -i $account4key1file $account4@$remote_ip -p $remote_port -- $js "
    a4f="$tf ssh -F $mytmpdir/ssh_config -i $account4key1file $account4@$remote_ip -p $remote_port -- $js "
    r0="  $t ssh -F $mytmpdir/ssh_config -i $rootkeyfile           root@$remote_ip -p $remote_port -- "
};

grant()  { success prereq grantcmd  $a0 --osh accountGrantCommand  --account $account0 --command "$1"; }
revoke() { success prereq revokecmd $a0 --osh accountRevokeCommand --account $account0 --command "$1"; }

cat >"$mytmpdir/ssh_config" <<EOF
   StrictHostKeyChecking no
   SendEnv LC_*
   PubkeyAuthentication yes
   PasswordAuthentication no
   RequestTTY yes
EOF
if [ "$HAS_MFA" = 1 ] || [ "$HAS_MFA_PASSWORD" = 1 ]; then
        cat >>"$mytmpdir/ssh_config" <<EOF
           ChallengeResponseAuthentication yes
           KbdInteractiveAuthentication yes
           PreferredAuthentications publickey,keyboard-interactive
EOF
else
        cat >>"$mytmpdir/ssh_config" <<EOF
           ChallengeResponseAuthentication no
           KbdInteractiveAuthentication no
           PreferredAuthentications publickey
EOF
fi

outdir="$mytmpdir/out"
mkdir -p $outdir || exit 1
touch "$outdir/.basename"

# checking which screen syntax works on this OS
screen="screen -L"
if screen -h 2>&1 | grep -q -- -Logfile; then
    screen="screen -L -Logfile"
fi
# /checking

testno=0
testcount=0
basename=""
nbfailedret=0
nbfailedgrep=0
nbfailedcon=0
nbfailedlog=0
nbfailedgeneric=0
isbad=0

start_time=$(date +%s)
prefix()
{
    local elapsed=$(( $(date +%s) - start_time))
    local min=$(( elapsed / 60 ))
    local sec=$(( elapsed - min * 60 ))
    local totalerrors=$(( nbfailedret + nbfailedgrep + nbfailedcon + nbfailedgeneric ))
    if [ "$totalerrors" = 0 ]; then
        printf "%b%02dm%02d [noerror]" "$TARGET" "$min" "$sec"
    else
        printf "%b%02dm%02d %b[%d err]%b" "$TARGET" "$min" "$sec" "$RED" "$totalerrors" "$NOC"
    fi
}

run()
{
    # display verbose output about the previous test if it was bad
    # we do this here because this way we're sure that all checks have been done for it
    # at this stage (retvalshouldbe, json, ...)
    if [ "$isbad" = 1 ]; then
        if [ -f "$outdir/$basename.script" ]; then
            printf "%b%b%b\\n" "$WHITE_ON_BLUE" "[INFO] test script follows" "$NOC"
            cat "$outdir/$basename.script"
        fi
        printf "%b%b%b\\n" "$WHITE_ON_BLUE" "[INFO] output of the command follows" "$NOC"
        cat "$outdir/$basename.log"
        printf "%b%b%b\\n" "$WHITE_ON_BLUE" "[INFO] returned json follows" "$NOC"
        grep "^JSON_OUTPUT=" -- $outdir/$basename.log | cut -d= -f2- | $jq .
        if [ "$nocc" != 1 ]; then
            printf "%b%b%b\\n" "$WHITE_ON_BLUE" "[INFO] consistency check follows" "$NOC"
            cat "$outdir/$basename.cc"
        fi
        if test -t 0 && [ "$nowait" != 1 ]; then
            printf "%b%b%b\\n" "$WHITE_ON_BLUE" "[INFO] press enter to continue" "$NOC"
            read -r _
        fi
    fi
    isbad=0

    # now prepare for the current test
    testno=$(( testno + 1 ))
    [ "$COUNTONLY" = 1 ] && return
    name=$1
    shift
    case=$1
    shift
    basename=$(printf '%03d-%s-%s' $testno $name $case | sed -re "s=/=_=g")

    # if we're about to run a script, keep a copy there
    if [ -x "$1" ] && [ "$#" -eq 1 ]; then
        cp "$1" "$outdir/$basename.script"
    fi

    printf '%b %b*** [%03d/%03d] %b::%b %s(%b)\n' "$(prefix)" "$BOLD_CYAN" "$testno" "$testcount" "$name" "$case" "$NOC" "$*"

    # special case for scp: we need to wait a bit before terminating the test
    sleepafter=0
    [ "$name" = "scp" ] && sleepafter=2

    # put an invalid value in this file, should be overwritten. we also use it as a lock file.
    echo -1 > $outdir/$basename.retval
    # run the test
    flock "$outdir/$basename.retval" $screen "$outdir/$basename.log" -D -m -fn -ln bash -c "$* ; echo \$? > $outdir/$basename.retval ; sleep $sleepafter"
    flock "$outdir/$basename.retval" true

    # look for generally bad strings in the output
    _bad='at /usr/share/perl|compilation error|compilation aborted|BEGIN failed|gonna crash|/opt/bastion/|sudo:|ontinuing anyway|MAKETESTFAIL'
    _badexclude='/etc/shells'
    # shellcheck disable=SC2126
    if [ "$(grep -qE "$_bad" $outdir/$basename.log | grep -Ev "$_badexclude" | wc -l)" -gt 0 ]; then
        nbfailedgeneric=$(( nbfailedgeneric + 1 ))
        fail "BAD STRING" "(generic known-bad string found in output)"
    fi

    # now run consistency check on the target, unless configured otherwise
    if [ "$nocc" != 1 ]; then
        flock "$outdir/$basename.retval" $screen "$outdir/$basename.cc" -D -m -fn -ln $r0 '
                /opt/bastion/bin/admin/check-consistency.pl ; echo _RETVAL_CC=$?= ;
                grep -Fw -e warn -e die -e code-warning /var/log/bastion/bastion.log | grep -Fv "'"${code_warn_exclude:-__none__}"'" | sed "s/^/_SYSLOG=/" ;
                : > /var/log/bastion/bastion.log
            '
        flock "$outdir/$basename.retval" true
        ccret=$(     grep _RETVAL_CC= "$outdir/$basename.cc" | cut -d= -f2)
        syslogline=$(grep _SYSLOG=    "$outdir/$basename.cc" | cut -d= -f2-)
        if [ "$ccret" != 0 ]; then
            nbfailedcon=$(( nbfailedcon + 1 ))
            fail "CONSISTENCY CHECK"
        fi
        if [ -n "$syslogline" ]; then
            nbfailedlog=$(( nbfailedlog + 1 ))
            fail "WARN/DIE/CODE-WARN TRIGGERED"
        fi
        # reset this for the next test
        unset code_warn_exclude
    fi
}

script() {
    name=$1
    shift
    section=$1
    shift
    if [ "$COUNTONLY" = 1 ]; then
        run $name $section true
        return
    fi

    tmpscript=$(mktemp)
    echo "#! /usr/bin/env bash" > "$tmpscript"
    echo "$*" >> "$tmpscript"
    chmod 755 "$tmpscript"
    run $name $section "$tmpscript"
    rm -f "$tmpscript"
}

retvalshouldbe()
{
    [ "$COUNTONLY" = 1 ] && return
    shouldbe=$1
    got=$(< $outdir/$basename.retval)
    if [ "$got" = "$shouldbe" ] ; then
        ok "RETURN VALUE" "($shouldbe)"
    else
        nbfailedret=$(( nbfailedret + 1 ))
        fail "RETURN VALUE" "(got $got instead of $shouldbe)"
    fi
}

fail() {
    printf '%b %b[FAIL]%b %b\n' "$(prefix)" "$BLACK_ON_RED" "$NOC" "$*"
    isbad=1
}
ok() {
    printf '%b %b[ OK ]%b %b\n' "$(prefix)" "$BLACK_ON_GREEN" "$NOC" "$*"
}

success()
{
    run "$@"
    retvalshouldbe 0
}

plgfail()
{
    run "$@"
    retvalshouldbe 100
}

ignorecodewarn()
{
    code_warn_exclude="$*"
}

get_json()
{
    [ "$COUNTONLY" = 1 ] && return
    grep "^JSON_OUTPUT=" -- $outdir/$basename.log | tail -n1 | cut -d= -f2-
}

get_stdout()
{
    [ "$COUNTONLY" = 1 ] && return
    cat $outdir/$basename.log
}

json()
{
    [ "$COUNTONLY" = 1 ] && return
    local jq1="" jq2="" jq3=""
    local splitsort=0
    while [ $# -ge 2 ] ; do
        if [ "$1" = "--splitsort" ]; then
            splitsort=1
            shift
            continue
        elif [ "$1" = "--argjson" ] || [ "$1" = "--arg" ]; then
            jq1="$1"
            jq2="$2"
            jq3="$3"
            shift 3
            continue
        fi
        local filter="$1" expected="$2"
        shift 2
        json=$(get_json)
        set +e
        if [ -n "$jq3" ]; then
            got=$($jq "$jq1" "$jq2" "$jq3" "$filter" <<< "$json")
        else
            got=$($jq "$filter" <<< "$json")
        fi
        if [ "$splitsort" = 1 ]; then
            expected=$(echo "$expected" | tr " " "\\n" | sort)
            got=$($jq ".[]" <<< "$got" | sort)
        fi
        set -e
        if [ -z "$json" ] ; then
            nbfailedgrep=$(( nbfailedgrep + 1 ))
            fail "JSON VALUE" "(no json found in output, couldn't look for key <$filter>)"
        elif [ "$expected" = "$got" ] ; then
            ok "JSON VALUE" "($filter => $expected) [$jq1 $jq3 $jq3]"
        else
            nbfailedgrep=$(( nbfailedgrep + 1 ))
            fail "JSON VALUE" "(for key <$filter> wanted <$expected> but got <$got>, with optional params jq1='$jq1' jq2='$jq2' jq3='$jq3')"
        fi
    done
}

pattern()
{
    [ "$COUNTONLY" = 1 ] && return
    if grep -qE -- "$1" <<< "$2" ; then
        ok "PATTERN" "(got '$1' in '$2')"
    else
        nbfailedgrep=$(( nbfailedgrep + 1 ))
        fail "PATTERN" "(wanted '$1' in '$2')"
    fi
}

contain()
{
    [ "$COUNTONLY" = 1 ] && return
    local specialoption=''
    if [ "$1" != "REGEX" ] ; then
        specialoption='-F'
    else
        specialoption='-E'
        shift
    fi
    if grep -q $specialoption -- "$1" "$outdir/$basename.log"; then
        ok "MUST CONTAIN" "($1)"
    else
        nbfailedgrep=$(( nbfailedgrep + 1 ))
        fail "MUST CONTAIN" "($1)"
    fi
}

nocontain()
{
    [ "$COUNTONLY" = 1 ] && return
    grepit="$1"
    if grep -Eq "$grepit" "$outdir/$basename.log"; then
        nbfailedgrep=$(( nbfailedgrep + 1 ))
        fail "MUST NOT CONTAIN" "(should not have found string '$grepit' in output)"
    else
        ok "MUST NOT CONTAIN" "($grepit)"
    fi
}

configchg()
{
    success bastion configchange $r0 perl -pe "$*" -i $osh_etc/bastion.conf
}

runtests()
{
    # ensure syslog is clean
    ignorecodewarn 'Configuration error' # previous unit tests can provoke this
    success bastion syslog_cleanup $r0 "\": > /var/log/bastion/bastion.log\""

    # backup the original default configuration on target side
    now=$(date +%s)
    success bastion backupconfig $r0 "dd if=$osh_etc/bastion.conf of=$osh_etc/bastion.conf.bak.$now"

    grant accountRevokeCommand

    for module in "$(dirname $0)"/tests.d/???-*.sh
    do
        if [ -n "$TEST_SCRIPT" ] && [ "$TEST_SCRIPT" != "$(basename "$module")" ]; then
            echo "### SKIPPING MODULE $module"
            continue
        fi
        echo "### RUNNING MODULE $module"

        # as this is a loop, we do the check in a reversed way, see any included module for more info:
        # shellcheck disable=SC1090
        source "$module" || true
    done

    # put the backed up configuration back
    success bastion restoreconfig $r0 "dd if=$osh_etc/bastion.conf.bak.$now of=$osh_etc/bastion.conf"
}

COUNTONLY=0
echo === running unit tests ===
if ! $r0 perl "$remote_basedir/tests/unit/run.pl"; then
    printf "%b%b%b\\n" "$WHITE_ON_RED" "Unit tests failed :(" "$NOC"
    exit 1
fi

COUNTONLY=1
testno=0
echo === counting functional tests ===
runtests
testcount=$testno

echo === will run $testcount functional tests ===
COUNTONLY=0
testno=0
runtests
echo

if [ $((nbfailedret + nbfailedgrep + nbfailedcon + nbfailedgeneric)) -eq 0 ] ; then
    printf "%b%b%b\\n" "$BLACK_ON_GREEN" "All tests succeeded :)" "$NOC"
else
    (
    echo
    printf "%b" "$WHITE_ON_RED"
    echo "One or more tests failed :("
    echo "- $nbfailedret unexpected return values"
    echo "- $nbfailedgrep unexpected JSON/text values"
    echo "- $nbfailedcon failed consistency checks"
    echo "- $nbfailedlog warn/die triggered"
    echo "- $nbfailedgeneric generic bad strings found"
    printf "%b" "$NOC"
    ) | tee $outdir/summary
fi
echo

set +e
set +u
(( totalerrors = nbfailedret + nbfailedgrep + nbfailedcon + nbfailedgeneric ))
[ $totalerrors -ge 255 ] && totalerrors=254

rm -rf "$mytmpdir"
trap EXIT
exit $totalerrors
