#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck disable=SC2086
# shellcheck disable=SC2016
# shellcheck disable=SC2046
set -eu

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

opt_remote_etc_bastion=/etc/bastion
opt_remote_basedir=$basedir
opt_skip_consistency_check=0
opt_no_pause_on_fail=0
opt_log_prefix=
opt_module=
declare -A capabilities=( [ed25519]=1 [blacklist]=0 [mfa]=1 [mfa-password]=0 [pamtester]=1 [piv]=1 )

# set the helptext now to get the proper default values
help_text=$(cat <<EOF
Test Options:
    --skip-consistency-check   Speed up tests by skipping the consistency check between every test
    --no-pause-on-fail         Don't pause when a test fails
    --log-prefix=X             Prefix all logs by this name
    --module=X                 Only test this module (specify a filename found in \`functional/tests.d/\`)

Remote OS directory locations:
    --remote-etc-bastion=X     Override the default remote bastion configuration directory (default: $opt_remote_etc_bastion)
    --remote-basedir=X         Override the default remote basedir location (default: $opt_remote_basedir)

Specifying features support of the underlying OS of the tested bastion:
    --has-ed25519=[0|1]        Ed25519 keys are supported (default: ${capabilities[ed25519]})
    --has-blacklist=[0|1]      Detection of bad SSH keys generated during the Debian OpenSSL debacle of 2006 is supported (default: ${capabilities[blacklist]})
    --has-mfa=[0|1]            PAM is usable to check passwords and TOTP (default: ${capabilities[mfa]})
    --has-mfa-password=[0|1]   PAM is usable to check passwords (default: ${capabilities[mfa-password]})
    --has-pamtester=[0|1]      The \`pamtester\` binary is available, and PAM is usable (default: ${capabilities[pamtester]})
    --has-piv=[0|1]            The \`yubico-piv-tool\` binary is available (default: ${capabilities[piv]})

EOF
)


usage() {
    if [ "${1:-}" != "light" ]; then
        cat <<EOF

Usage: $0 [OPTIONS] <IP> <SSH_Port> <HTTP_Proxy_Port_or_Zero> <Remote_Admin_User_Name> <Admin_User_SSH_Key_Path> <Root_SSH_Key_Path>

EOF
    fi
    echo "$help_text"
}

while [ -n "${1:-}" ]
do
    optval="${1/*=/}"
    case "$1" in
        --remote-etc-bastion=*)
            opt_remote_etc_bastion="$optval"
            ;;
        --remote-basedir=*)
            opt_remote_basedir="$optval"
            ;;
        --skip-consistency-check)
            opt_skip_consistency_check=1
            ;;
        --no-pause-on-fail)
            opt_no_pause_on_fail=1
            ;;
        --log-prefix=*)
            opt_log_prefix="$optval"
            ;;
        --module=*)
            opt_module="$optval"
            if [ ! -e "$basedir/tests/functional/tests.d/$optval" ]; then
                echo "Unknown module specified '$opt_module', supported modules are:"
                cd "$basedir/tests/functional/tests.d"
                ls -- ???-*.sh
                exit 1
            fi
            ;;
        --has-*=*)
            optname=${1/--has-/}
            optname=${optname/=*/}
            capabilities[$optname]=$optval
            ;;
        --help)
            usage
            exit 0
            ;;
        --help-light)
            usage light
            exit 0
            ;;
        -*)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
        *) break
            ;;
    esac
    shift
done

if [ -n "${7:-}" ]; then
    echo "Error: too many parameters"
    usage
    exit 1
fi

if [ -z "${6:-}" ]; then
    echo "Error: missing parameters"
    usage
    exit 1
fi

remote_ip="$1"
remote_port="$2"
# the var below is used in sourced test files
# shellcheck disable=SC2034
remote_proxy_port="$3"
account0="$4"
user_ssh_key_path="$5"
root_ssh_key_path="$6"

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
    account1="te3456789012345678stu_Ser.1-"
    account2="te23456789012345678sT-user2_"
    account3="te23456789012345678St-user3."
    account4="Te0123456789012345678StUsEr4"
    uid1=9001
    uid2=9002
    uid3=9003
    uid4=9004
    group1="te.st_Group1-"
    group2="tEst-gr.oup2_"
    group3="testgrOup3"
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
    a4np="$t ssh -F $mytmpdir/ssh_config -o PubkeyAuthentication=no $account4@$remote_ip -p $remote_port -- $js "
    r0="  $t ssh -F $mytmpdir/ssh_config -i $rootkeyfile           root@$remote_ip -p $remote_port -- "
};

grant()  { success grantcmd  $a0 --osh accountGrantCommand  --account $account0 --command "$1"; }
revoke() { success revokecmd $a0 --osh accountRevokeCommand --account $account0 --command "$1"; }

cat >"$mytmpdir/ssh_config" <<EOF
   StrictHostKeyChecking no
   SendEnv LC_*
   PubkeyAuthentication yes
   PasswordAuthentication no
   RequestTTY yes
EOF
if [ "${capabilities[mfa]}" = 1 ] || [ "${capabilities[mfa-password]}" = 1 ]; then
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
totalerrors=0
isbad=0

start_time=$(date +%s)

update_totalerrors()
{
    (( totalerrors = nbfailedret + nbfailedgrep + nbfailedcon + nbfailedlog + nbfailedgeneric ))
}

prefix()
{
    local elapsed=$(( $(date +%s) - start_time))
    local min=$(( elapsed / 60 ))
    local sec=$(( elapsed - min * 60 ))
    local prefixfmt="%b"
    update_totalerrors

    [ -n "$opt_log_prefix" ] && prefixfmt="%16b "
    if [ "$totalerrors" = 0 ]; then
        printf "${prefixfmt}%02dm%02d %b[--]%b" "$opt_log_prefix" "$min" "$sec" "$DARKGRAY" "$NOC"
    else
        printf "${prefixfmt}%02dm%02d %b[%d err]%b" "$opt_log_prefix" "$min" "$sec" "$RED" "$totalerrors" "$NOC"
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
        grep "^JSON_OUTPUT=" -- $outdir/$basename.log | cut -d= -f2- | jq --sort-keys .
        if [ "$opt_skip_consistency_check" != 1 ]; then
            printf "%b%b%b\\n" "$WHITE_ON_BLUE" "[INFO] consistency check follows" "$NOC"
            cat "$outdir/$basename.cc"
        fi
        if test -t 0 && [ "$opt_no_pause_on_fail" != 1 ]; then
            printf "%b%b%b\\n" "$WHITE_ON_BLUE" "[INFO] press enter to continue" "$NOC"
            read -r _
        fi
    fi
    isbad=0

    # now prepare for the current test
    testno=$(( testno + 1 ))
    [ "$COUNTONLY" = 1 ] && return
    name="$modulename"
    if [ -z "$name" ]; then
        name="main"
    fi
    case="$1"
    shift
    basename=$(printf '%04d-%s-%s' $testno $name $case | sed -re "s=/=_=g")

    # if we're about to run a script, keep a copy there
    if [ -x "$1" ] && [ "$#" -eq 1 ]; then
        cp "$1" "$outdir/$basename.script"
    fi

    printf '%b %b*** [%04d/%04d] %b::%b %b(%b)%b\n' "$(prefix)" "$BOLD_CYAN" "$testno" "$testcount" "$name" "$case" "$NOC$DARKGRAY" "$*" "$NOC"

    # special case for scp: we need to wait a bit before terminating the test
    sleepafter=0
    [[ $case =~ ^scp_ ]] && sleepafter=2

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
    if [ "$opt_skip_consistency_check" != 1 ]; then
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
    section=$1
    shift
    if [ "$COUNTONLY" = 1 ]; then
        run $section true
        return
    fi

    tmpscript=$(mktemp)
    echo "#! /usr/bin/env bash" > "$tmpscript"
    echo "$*" >> "$tmpscript"
    chmod 755 "$tmpscript"
    run $section "$tmpscript"
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

json_document()
{
    [ "$COUNTONLY" = 1 ] && return
    local fulljson="$1"
    local tmpdiff; tmpdiff=$(mktemp)
    local diffret=0
    diff -u0 <(echo "$fulljson" | jq -S .) <(get_json | jq -S .) > "$tmpdiff"; diffret=$?
    if [ "$diffret" = 0 ]; then
        ok "JSON DOCUMENT" "(fully matched)"
    else
        fail "JSON DOCUMENT" "($(awk '{if(NR>3){print}}' "$tmpdiff" | grep -c '^[-+]') lines differ)"
        awk '{if(NR>3){print}}' "$tmpdiff"
    fi
    rm -f "$tmpdiff"
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
    success configchange $r0 perl -pe "$*" -i "$opt_remote_etc_bastion/bastion.conf"
}

onfigsetquoted()
{
    success configset $r0 perl -pe 's=^\\\\x22'"$1"'\\\\x22.+=\\\\x22'"$1"'\\\\x22:\\\\x22'"$2"'\\\\x22,=' -i "$opt_remote_etc_bastion/bastion.conf"
}

configset()
{
    success configset $r0 perl -pe 's=^\\\\x22'"$1"'\\\\x22.+=\\\\x22'"$1"'\\\\x22:'"$2"',=' -i "$opt_remote_etc_bastion/bastion.conf"
}


sshclientconfigchg()
{
    success sshclientconfigchange $r0 perl -pe "$*" -i /etc/ssh/ssh_config
}

runtests()
{
    # ensure syslog is clean
    ignorecodewarn 'Configuration error' # previous unit tests can provoke this
    success syslog_cleanup $r0 "\": > /var/log/bastion/bastion.log\""

    modulename=main
    # backup the original default configuration on target side
    now=$(date +%s)
    success backupconfig $r0 "dd if=$opt_remote_etc_bastion/bastion.conf of=$opt_remote_etc_bastion/bastion.conf.bak.$now"

    grant accountRevokeCommand

    for module in "$(dirname $0)"/tests.d/???-*.sh
    do
        module="$(readlink -f "$module")"
        modulename="$(basename "$module" .sh)"
        if [ -n "$opt_module" ] && [ "$opt_module" != "$(basename "$module")" ]; then
            echo "### SKIPPING MODULE $modulename"
            continue
        fi
        echo "### RUNNING MODULE $modulename"

        # as this is a loop, we do the check in a reversed way, see any included module for more info:
        # shellcheck disable=SC1090
        source "$module" || true

        # put the backed up configuration back after each module, just in case the module modified it
        modulename=main
        success configrestore $r0 "dd if=$opt_remote_etc_bastion/bastion.conf.bak.$now of=$opt_remote_etc_bastion/bastion.conf"
    done
}

COUNTONLY=0
echo '=== running unit tests ==='
# a while read loop doesn't work well here:
# shellcheck disable=SC2044
for f in $(find "$basedir/tests/unit/" -mindepth 1 -maxdepth 1 -type f -name "*.pl" -print)
do
    fbasename=$(basename "$f")
    echo "-> $fbasename"
    if ! $r0 perl "$opt_remote_basedir/tests/unit/$fbasename"; then
        printf "%b%b%b\\n" "$WHITE_ON_RED" "Unit tests failed :(" "$NOC"
        exit 1
    fi
done

COUNTONLY=1
testno=0
echo '=== counting functional tests ==='
runtests
testcount=$testno

echo "=== will run $testcount functional tests ==="
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
update_totalerrors
[ $totalerrors -ge 255 ] && totalerrors=254

rm -rf "$mytmpdir"
trap EXIT
exit $totalerrors
