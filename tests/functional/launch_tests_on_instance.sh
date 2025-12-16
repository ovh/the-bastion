#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck disable=SC2086,SC2016,SC2046,SC2317
set -eu

# ensure a sparse '*' somewhere doesn't end up in us expanding it silently
set -f

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

opt_remote_etc_bastion=/etc/bastion
opt_remote_basedir=$basedir
opt_consistency_check=0
opt_no_pause_on_fail=0
opt_slowness_factor=1
opt_log_prefix=
opt_module=
opt_post_run=
opt_functional_tests=1
opt_unit_tests=1
declare -A capabilities=( [ed25519]=1 [mfa]=1 [mfa-password]=0 [pamtester]=1 [piv]=1 [sk]=0 [ipv6]=1 )

# set the helptext now to get the proper default values
help_text=$(cat <<EOF
Functional Test Options:
    --consistency-check        Check system consistency between every test
    --no-pause-on-fail         Don't pause when a test fails
    --log-prefix=X             Prefix all logs by this name
    --module=X                 Only test this module (specify a filename found in \`functional/tests.d/\`), can be specified multiple times
    --slowness-factor=X        If your test environment is slow, set this to 2, 3 or more to use higher timeouts (default: 1)
    --post-run=X               Commands to run after we're done testing
    --skip-functional-tests    Skip functional tests

Unit Test Options:
    --skip-unit-tests          Skip unit tests

Remote OS directory locations:
    --remote-etc-bastion=X     Override the default remote bastion configuration directory (default: $opt_remote_etc_bastion)
    --remote-basedir=X         Override the default remote basedir location (default: $opt_remote_basedir)

Specifying features support of the underlying OS of the tested bastion:
    --has-ed25519=[0|1]        Ed25519 keys are supported (default: ${capabilities[ed25519]})
    --has-mfa=[0|1]            PAM is usable to check passwords and TOTP (default: ${capabilities[mfa]})
    --has-mfa-password=[0|1]   PAM is usable to check passwords (default: ${capabilities[mfa-password]})
    --has-pamtester=[0|1]      The \`pamtester\` binary is available, and PAM is usable (default: ${capabilities[pamtester]})
    --has-piv=[0|1]            The \`yubico-piv-tool\` binary is available (default: ${capabilities[piv]})
    --has-sk=[0|1]             The openssh-server supports Secure Keys (FIDO2) (default: ${capabilities[sk]})
    --has-ipv6=[0|1]           OS supports IPv6 and has a recent-enough version of Net::Netmask (default: ${capabilities[ipv6]})

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
            # deprecated and undocumented, as it is now the default
            opt_consistency_check=0
            ;;
        --consistency-check)
            opt_consistency_check=1
            ;;
        --no-pause-on-fail)
            opt_no_pause_on_fail=1
            ;;
        --slowness-factor=*)
            if [[ $optval =~ ^[1-9]$ ]]; then
                opt_slowness_factor=$optval
            fi
            ;;
        --log-prefix=*)
            opt_log_prefix="$optval"
            ;;
        --post-run=*)
            opt_post_run="$optval"
            ;;
        --module=*)
            if [ ! -e "$basedir/tests/functional/tests.d/$optval" ]; then
                echo "Unknown module specified '$optval', supported modules are:"
                cd "$basedir/tests/functional/tests.d"
                ls -- ???-*.sh
                exit 1
            fi
            opt_module="$opt_module $optval"
            ;;
        --skip-functional-tests)
            opt_functional_tests=0
            ;;
        --skip-unit-tests)
            opt_unit_tests=0
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

# when sourcing modules, if they exit or contain syntax error, check their stderr,
# as they won't give us back execution control
check_sourced_module_output()
{
    if [ -s "$source_stderr" ]; then
        echo
        echo "DEFINITION ERROR in module $module, aborting:"
        echo "-----"
        cat "$source_stderr"
        echo "-----"
        echo
        return 1
    fi
    return 0
}

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
    tmp_a=$(mktemp -t bastiontest.XXXXXX)
    tmp_b=$(mktemp -t bastiontest.XXXXXX)
    source_stderr=$(mktemp -t bastiontest.XXXXXX)
    trap '
        check_sourced_module_output;
        echo CLEANING UP;
        rm -rf "$mytmpdir";
        rm -f "$tmp_a" "$tmp_b" "$source_stderr";
        exit 255
    ' EXIT
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
    default_timeout=$((30 * opt_slowness_factor))
    t="timeout --foreground $default_timeout"
    tf="timeout --foreground $((default_timeout / 2))"
    a0="  $t ssh -F $mytmpdir/ssh_config -i $account0key1file $account0@$remote_ip -p $remote_port -- $js "
    a0f="$tf ssh -F $mytmpdir/ssh_config -i $account0key1file $account0@$remote_ip -p $remote_port -- $js "
    a1="  $t ssh -F $mytmpdir/ssh_config -i $account1key1file $account1@$remote_ip -p $remote_port -- $js "
    a1k2="$t ssh -F $mytmpdir/ssh_config -i $account1key2file $account1@$remote_ip -p $remote_port -- $js "
    a2="  $t ssh -F $mytmpdir/ssh_config -i $account2key1file $account2@$remote_ip -p $remote_port -- $js "
    a3="  $t ssh -F $mytmpdir/ssh_config -i $account3key1file $account3@$remote_ip -p $remote_port -- $js "
    a4="  $t ssh -F $mytmpdir/ssh_config -i $account4key1file $account4@$remote_ip -p $remote_port -- $js "
    a4f="$tf ssh -F $mytmpdir/ssh_config -i $account4key1file $account4@$remote_ip -p $remote_port -- $js "
    a4np="$t ssh -F $mytmpdir/ssh_config -o PubkeyAuthentication=no $account4@$remote_ip -p $remote_port -- $js "
    r0="  $t ssh -F $mytmpdir/ssh_config -i $rootkeyfile           root@$remote_ip -p $remote_port -- "

    # gpg has a terrible tendency to block on the pseudo-random number generator because it
    # reads from /dev/random instead of /dev/urandom for bad reasons. so, just hardcode some keys here

    admins_gpg_key_fp='77BD43B49D953216B23FB0D3EF588AFD95728724'
    admins_gpg_key_id='EF588AFD95728724'
    admins_gpg_key_password='password'
    admins_gpg_key_pub='
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEaManoRYJKwYBBAHaRw8BAQdAJrSyrZwplw4fLoCTA/+qtadGBfgAFrTGNEVG
6VLEA5G0KVRoZSBCYXN0aW9uIEZ1bmN0aW9uYWwgVGVzdHMgMSBETyBOT1QgVVNF
iJAEExYIADgWIQR3vUO0nZUyFrI/sNPvWIr9lXKHJAUCaManoQIbAwULCQgHAgYV
CgkICwIEFgIDAQIeAQIXgAAKCRDvWIr9lXKHJMPDAQDX9cynb7vYgqoDchZ96j18
mDj771Hj8UqMKvvmAOs89AEAhWPfBPFPLIuE3I1i4xcqqDxGhJjOEImguomvw+Mk
XQa4OARoxqfPEgorBgEEAZdVAQUBAQdAPknOek1HwmahNN5cIZytU5gui0jOzMzM
BHoIa2gJp2oDAQgHiHgEGBYIACAWIQR3vUO0nZUyFrI/sNPvWIr9lXKHJAUCaMan
zwIbDAAKCRDvWIr9lXKHJIVXAP9kvmTQSL6slzKEJg0ihG2osctYtA4qjqHLT7nJ
83nW/AEAyBRd/CP5DQzVeLgf0yY3rfKyPJXPkRT7Jv5VYJ0OTgw=
=Rl5j
-----END PGP PUBLIC KEY BLOCK-----
'
    # shellcheck disable=SC1078,SC1079
    admins_gpg_key_priv='
-----BEGIN PGP PRI''VATE KEY BLOCK-----

lIYEaManoRYJKwYBBAHaRw8BAQdAJrSyrZwplw4fLoCTA/+qtadGBfgAFrTGNEVG
6VLEA5H+BwMCDR1ixPbIDkD/pJPZ0bDoc5QNSvdYkBNMcfn8jU1nuP0ae830qr6Z
l17PSnJYswDB9FnsILgHY4m/53h/1XbzOioeY8B69gNOxvmDI5MDyLQpVGhlIEJh
c3Rpb24gRnVuY3Rpb25hbCBUZXN0cyAxIERPIE5PVCBVU0WIkAQTFggAOBYhBHe9
Q7SdlTIWsj+w0+9Yiv2VcockBQJoxqehAhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4B
AheAAAoJEO9Yiv2Vcockw8MBANf1zKdvu9iCqgNyFn3qPXyYOPvvUePxSowq++YA
6zz0AQCFY98E8U8si4TcjWLjFyqoPEaEmM4QiaC6ia/D4yRdBpyLBGjGp88SCisG
AQQBl1UBBQEBB0A+Sc56TUfCZqE03lwhnK1TmC6LSM7MzMwEeghraAmnagMBCAf+
BwMCpS1daNVeiWj/pW7Ul3dcOBcb4Six3puFfhKCqISbYxz8TCyryskobgV7rNQW
JtP/KiPIm3n9zSTeKe+Mz61MkP2terPwkmCcpIXGQxO6F4h4BBgWCAAgFiEEd71D
tJ2VMhayP7DT71iK/ZVyhyQFAmjGp88CGwwACgkQ71iK/ZVyhySFVwD/ZL5k0Ei+
rJcyhCYNIoRtqLHLWLQOKo6hy0+5yfN51vwBAMgUXfwj+Q0M1Xi4H9MmN63ysjyV
z5EU+yb+VWCdDk4M
=X0wo
-----END PGP PRI''VATE KEY BLOCK-----
'

    admins_gpg_key2_fp='DDD75B4E323605E2F2D84C57B07681E46080FA6C'
    admins_gpg_key2_id='B07681E46080FA6C'
    admins_gpg_key2_password='password'
    admins_gpg_key2_pub='
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEaMan1hYJKwYBBAHaRw8BAQdAe5q2pQcaPCvoCBvAplS4bDoAHZYrvBSNOeI1
YyWt7ca0KVRoZSBCYXN0aW9uIEZ1bmN0aW9uYWwgVGVzdHMgMiBETyBOT1QgVVNF
iJAEExYIADgWIQTd11tOMjYF4vLYTFewdoHkYID6bAUCaMan1gIbAwULCQgHAgYV
CgkICwIEFgIDAQIeAQIXgAAKCRCwdoHkYID6bC1/AQCttlvVVZYCuy6M0pdBQhnj
5hi+h7ZsOEbxLuBS1Q0xBwEAk/6SesVpnWQaZ34ZMGwu0b5UsqLDNssNFpEnEE+X
jg64OARoxqfgEgorBgEEAZdVAQUBAQdA1vSd5OghmsJLq+j1l47ZMRL2vY84pN/U
PWfGqRi3FEwDAQgHiHgEGBYIACAWIQTd11tOMjYF4vLYTFewdoHkYID6bAUCaMan
4AIbDAAKCRCwdoHkYID6bAlFAQC1fdDV2DpgpsS9eqi4RAMnJu92HMMi5vts9zsb
lg0/tgEArubNUjLLiOHz9mDnHvYeDfH78XxKOYolCpJ75kH9ygc=
=Xr7M
-----END PGP PUBLIC KEY BLOCK-----
'

    # CF27BEC1C8266FFE EC6CEA6719EF3700
    admins_gpg_key_double1_id='CF27BEC1C8266FFE'
    admins_gpg_key_double2_id='EC6CEA6719EF3700'
    admins_gpg_key_double_pub='
-----BEGIN PGP PUBLIC KEY BLOCK-----

mI0EZTjY4gEEALsLQRaWUyfXtD9gtAXmo9Uq1DV9ZInd9xkxvEbLx8PJxsAnD5dV
yK/LfJnY+imd2Wf8C0KJLcTiQX8wjSNc2cuDJB/V8A8Ps/ZijBNSUjrVBvihToUd
GSPTDUr1tR9bH4Cz4olsbsQdThhpGQpDEAGdey2Xf3iMbekuQ7dKX+WLABEBAAG0
JWJhc3Rpb24gdGVzdHMgNyA8YmFzdGlvbkBleGFtcGxlLm9yZz6I1AQTAQoAPhYh
BOlCsHVGNoszKG4QgM8nvsHIJm/+BQJlONjiAhsDBQkDwmcABQsJCAcCBhUKCQgL
AgQWAgMBAh4BAheAAAoJEM8nvsHIJm/++6ID/igoQyP5+wp5UcFL/El8rU0yqGEg
0ZHLtxm+kKXzBgm5CBj2ZYcu1MUSKHJf4EI/0Hgdb62Er9eDHVXYMkrx5qWPZO/K
uGgY5iQECjae1wQXX3EWADttWE15WbzADNCguEUeTcc/eHJ2yR1EYmENSTHRJmSD
U6prPW5pHz6GTKwpuI0EZTjaugEEAM8qqbN3AKkd4FCvzW4RXXdLbXkPcxwX7TT+
XzMmdDagXjB/+GLyY3tCNgyGogLGkP+VvVX3LD5qdKIjqpR1w5NPUfUzCEv6SsIa
Rg9BZrOlwJlagdGkSfY/11TAh8UUX1pq59nHri4jnrYWQyy8CmgCYlHoRV/n60fd
4ql/O4rBABEBAAGItgQYAQoAIBYhBOlCsHVGNoszKG4QgM8nvsHIJm/+BQJlONq6
AhsMAAoJEM8nvsHIJm/+W5MD/Av/zkeVjiP1+XwzqVPB1CCSjormF6t17wHRSpwM
ZFQ2/a4Jxj4W0jl+KcwFB0zGits2sIqACd8CRi8bJiPJXLzqH/JIp5S3CknQoBK+
0XRSi/TZyYD7dI8RpXGdNbf9bD4BnVa6oKAjRxi0ZlE693IZLFHnVeNgqkbCt1Y3
rkZgmI0EZTjY5gEEAKyaPsb3+0YE4gOX1aKIZKwk1F2gYWBrKnVjeev1oEyeQ9Sn
hufIkHC6sRhDgI2lfUKkLdcKt75IMZdpdFHvOvXaMkcyY7+OukZm01vIcLRXi0m6
4L3dFChlvaz5AawS/hoonXMviwkt19kfYbE6t+ILD4ukD3U1OTwe6yjVKhUtABEB
AAG0JWJhc3Rpb24gdGVzdHMgOCA8YmFzdGlvbkBleGFtcGxlLm9yZz6I1AQTAQoA
PhYhBAB98E297Qm/EV76+uxs6mcZ7zcABQJlONjmAhsDBQkDwmcABQsJCAcCBhUK
CQgLAgQWAgMBAh4BAheAAAoJEOxs6mcZ7zcAypUD/i8LVSrXxuDxr0bEGsNsVb5O
8cofaO6wW04AtCags7pQeLuLcVepeSRORtHaoRZsa3SHFSBykdiPB+ll8G4grYja
mYHHXTTUgjYuoiFMUJoFqJkDUACgxBXP9uzFY6mIDdrX63LF9muGWtNdUz0LybOb
ACYlqY9sKUCMB4vV44qpuI0EZTjavgEEAM+rofSi7kH9yyrL3jFGDZRsmrOrGVTu
phUJfdewV8N4xMxj+NPeC955x1L4zb9bi2Ev5kOsM/YGB09v8nUFSoIqWE93NbQL
pMUq7m7aOilIxjjW0O6+iS8bE8gIOzzMweUBvt4bylJtlX8x3hqf94BXhwv3V+4S
YVJC9XGOYv2dABEBAAGItgQYAQoAIBYhBAB98E297Qm/EV76+uxs6mcZ7zcABQJl
ONq+AhsMAAoJEOxs6mcZ7zcAATgD/3tFCp1GszTi935QMXCNZpZY09QdncgXKVy9
jcJ2pnpER/7t2Pm6Zqu0UZdWHuAIP+lPTgL8Bf0UAmF+h7jIOwr0n76NvPiHNW1X
Gx+RVkNPSEbTH0bWdsyV8LE+E0NowoUaVsjWMzq+QZY+wjrURSWC2iLC1yDb+EPd
kTfIwdES
=ZNGF
-----END PGP PUBLIC KEY BLOCK-----
'
};

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
        if [ "$opt_consistency_check" = 1 ]; then
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

    # if not set, set to zero, see sleepafter()
    : "${sleepafter:=0}"

    # put an invalid value in this file, should be overwritten. we also use it as a lock file.
    echo -1 > $outdir/$basename.retval
    # run the test
    flock "$outdir/$basename.retval" $screen "$outdir/$basename.log" -D -m -fn -ln bash -c "set -f; $* ; echo \$? > $outdir/$basename.retval ; sleep $sleepafter"
    flock "$outdir/$basename.retval" true
    unset sleepafter

    # look for generally bad strings in the output
    _bad='at /usr/share/perl|compilation error|compilation aborted|BEGIN failed|gonna crash|/opt/bastion/|sudo:|ontinuing anyway|MAKETESTFAIL'
    _badexclude='/etc/shells'
    # shellcheck disable=SC2126
    if [ "$(grep -qE "$_bad" $outdir/$basename.log | grep -Ev "$_badexclude" | wc -l)" -gt 0 ]; then
        nbfailedgeneric=$(( nbfailedgeneric + 1 ))
        fail "BAD STRING" "(generic known-bad string found in output)"
    fi

    # now run consistency check on the target, unless configured otherwise
    if [ "$opt_consistency_check" = 1 ]; then
        # sleep 1s if sshd has been reloaded
        [ "$case" = "sshd_reload" ] && sleep 1
        flock "$outdir/$basename.retval" $screen "$outdir/$basename.cc" -D -m -fn -ln $r0 '
                /opt/bastion/bin/admin/check-consistency.pl ; echo _RETVAL_CC=$?= ;
                grep -Fw -e warn -e die -e code-warning /var/log/bastion/bastion.log
                | grep -Fv
                  -e "'"${code_warn_exclude:-__none__}"'"
                  -e "System does not support IPv6"
                  -e "Defaulting to E[UG]ID"
                  -e "starting!"
                  -e "Binding to SSL port"
                | sed "s/^/_SYSLOG=/" ;
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

sleepafter()
{
    sleepafter=$(($1 * opt_slowness_factor))
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

configsetquoted()
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

dump_vars_and_funcs()
{
    set | grep -v -E '^('\
'testno|section|code_warn_exclude|COPROC_PID|LINES|COLUMNS|PIPESTATUS|_|'\
'BASH_LINENO|basename|case|json|name|tmpscript|grepit|got|isbad|'\
'nbfailedgrep|nbfailedcon|nbfailedgeneric|nbfailedlog|nbfailedret|shouldbe|modulename)='
}

runtests()
{
    modulename=main

    # ensure syslog is clean
    ignorecodewarn 'Configuration error' # previous unit tests can provoke this
    success syslog_cleanup $r0 "\": > /var/log/bastion/bastion.log\""

    # patch the remote bastionCommand to the proper value
    configchg 's=^\\\\x22bastionCommand\\\\x22.+=\\\\x22bastionCommand\\\\x22:\\\\x22ssh\\\\x20USER\\\\x40'"$remote_ip"'\\\\x20-p\\\\x20'"$remote_port"'\\\\x20-t\\\\x20--\\\\x22,='

    # account1 skips PAM MFA
    success account1_nopam $r0 "command -v pw \>/dev/null \&\& pw groupmod -n bastion-nopam -m $account0 \|\| usermod -a -G bastion-nopam $account0"

    # backup the original default configuration on target side
    now=$(date +%s)
    success backupconfig $r0 "dd if=$opt_remote_etc_bastion/bastion.conf of=$opt_remote_etc_bastion/bastion.conf.bak.$now"

    # shellcheck disable=SC2044
    for module in $(find "$(dirname $0)/tests.d/" -mindepth 1 -maxdepth 1 -type f -name '???-*.sh' | sort)
    do
        module="$(readlink -f "$module")"
        modulename="$(basename "$module" .sh)"
        if [ -n "$opt_module" ]; then
            skip=1
            for wantedmod in $opt_module
            do
                if [ "$wantedmod" = "$(basename "$module")" ]; then
                    skip=0
                fi
            done
            if [ "$skip" = 1 ]; then
                echo "### SKIPPING MODULE $modulename"
                continue
            fi
        fi
        echo "### RUNNING MODULE $modulename"

        dump_vars_and_funcs > "$tmp_a"
        module_ret=0
        if [ "$COUNTONLY" = 0 ]; then
            # as this is a loop, we do the shellcheck in a reversed way, see any included module for more info:
            # shellcheck disable=SC1090
            source "$module" || module_ret=$?
        else
            # take the opportunity to ensure there's nothing in stderr, or there might be
            # errors in the module we're sourcing by capturing 2>
            # shellcheck disable=SC1090
            source "$module" 2>"$source_stderr" || module_ret=$?
            check_sourced_module_output || exit 1
            :>"$source_stderr"
        fi
        modulename=main
        # dump vars after module run
        dump_vars_and_funcs > "$tmp_b"
        # ensure the module exited successfully
        success module_postrun_exit_status test "$module_ret" = 0
        # put the backed up configuration back after each module, just in case the module modified it
        success module_postrun_config_restore $r0 "dd if=$opt_remote_etc_bastion/bastion.conf.bak.$now of=$opt_remote_etc_bastion/bastion.conf"
        # verify that the env hasn't been modified
        success module_postrun_check_env diff -u "$tmp_a" "$tmp_b"
    done

    # if the check_env_after_module of the last module fails, we wouldn't get the verbose error,
    # craft a test that always work and will notice that the previous one failed, which'll display
    # the verbose error information
    modulename=main
    success "done" true
}

if [ "$opt_unit_tests" = 1 ]; then
    echo '=== running unit tests ==='
    $r0 perl "$opt_remote_basedir/tests/unit/run-tests.pl"; ret=$?
    if [ $ret != 0 ]; then
        printf "%b%b%b\\n" "$WHITE_ON_RED" "Unit tests failed (ret=$ret) :(" "$NOC"
        exit 1
    fi
fi

if [ "$opt_functional_tests" = 1 ]; then
    COUNTONLY=1
    testno=0
    echo '=== counting functional tests ==='
    runtests
    testcount=$testno

    echo "=== will run $testcount functional tests ==="
    COUNTONLY=0
    testno=0
    runtests
fi

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
if [ -n "$opt_post_run" ]; then
    bash -c "$opt_post_run"
fi
exit $totalerrors
