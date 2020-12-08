#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
set -e

basedir=$(readlink -f "$(dirname "$0")"/../../..)
# shellcheck source=lib/shell/colors.inc
. "$basedir"/lib/shell/colors.inc

namespace=the-bastion-test

target="$1"
test_script="$2"

get_supported_targets() {
    local target targets subtarget
    for dockerfile in "$(dirname "$0")"/../../../docker/Dockerfile.*; do
        if grep -q '^# TESTENV ' "$dockerfile"; then
            target=$(basename "$dockerfile")
            target=${target/Dockerfile./}
            # if the file has a TESTFROM entry, then it's actually multiple similar targets
            if grep -q '^# TESTFROM ' "$dockerfile"; then
                # shellcheck disable=SC2013
                for testfrom in $(grep '^# TESTFROM ' "$dockerfile" | cut -d' ' -f3-); do
                    subtarget="$target@$testfrom"
                    targets="$targets $subtarget"
                done
            fi
            targets="$targets $target"
        fi
    done
    # shellcheck disable=SC2086
    echo $targets
}

print_supported_targets() {
    local target
    for target in $(get_supported_targets | tr " " "\n" | sort); do
        echo "- $target"
    done
    echo
}

if [ -z "$target" ] || [ "$target" = "--list-targets" ]; then
    if [ -z "$target" ]; then
        echo "Usage: $0 <TARGET>" >&2
        echo "Supported targets are: " >&2
        print_supported_targets >&2
        exit 1
    else
        # shellcheck disable=SC2086
        print_supported_targets
        exit 0
    fi
fi

if echo "$target" | grep -q '@'; then
    subtarget=$(echo "$target" | cut -d@ -f2)
    target_dockerfile=$(echo "$target" | cut -d@ -f1)
else
    subtarget=''
    target_dockerfile="$target"
fi
target_dockerfile="$(dirname "$0")"/../../../docker/Dockerfile."$target_dockerfile"
if [ ! -f "$target_dockerfile" ] ; then
    echo "Couldn't find a Dockerfile for $target ($target_dockerfile)" >&2
    exit 1
fi

# build test env
echo "Building test environment"
testenv_dockerfile="$(dirname "$0")/../../../docker/Dockerfile.tester"
docker build -f "$testenv_dockerfile" -t "$namespace:tester" "$(dirname "$0")"/../../..

# if we have a subtarget, we need to override the FROM of the target_dockerfile
# don't do this in place however, create a tempfile for this
if [ -n "$subtarget" ]; then
    dockerfiletmp=$(mktemp)
    trap 'rm -f $dockerfiletmp' EXIT
    sed -re "s/^FROM .+/FROM $subtarget/" "$target_dockerfile" > "$dockerfiletmp"
    target_dockerfile="$dockerfiletmp"
fi

# build target
echo "Building target environment"
target=$(echo "$target" | sed -re 's/[^a-zA-Z0-9_-]/_/g')
docker build -f "$target_dockerfile" -t "$namespace:$target" --build-arg "TEST_QUICK=$TEST_QUICK" "$(dirname "$0")"/../../..

# get the target environment we want from the dockerfile
varstoadd=''
privileged=''
for var in $(grep '^# TESTENV' "$target_dockerfile" | tail -n1 | sed -re 's/^# TESTENV//')
do
    echo "$var" | grep -Eq '^[A-Z0-9_]+=[01]$' && varstoadd="$varstoadd -e $var "
    [ "$var" = "PRIVILEGED=1" ] && privileged='--privileged'
done

# cleanup the dockerfile temp if applicable
if [ -n "$subtarget" ]; then
    rm -f "$dockerfiletmp"
    trap - EXIT
fi

# create temp key
echo "Create user and root SSH keys"
privdir=$(mktemp -d)
trap 'rm -rf "$privdir"' EXIT
ssh-keygen -t ecdsa -N '' -q -f "$privdir"/userkey
USER_PRIVKEY_B64=$(base64 -w0 < "$privdir"/userkey)
USER_PUBKEY_B64=$(base64 -w0 < "$privdir"/userkey.pub)
ssh-keygen -t ecdsa -N '' -q -f "$privdir"/rootkey
ROOT_PRIVKEY_B64=$(base64 -w0 < "$privdir"/rootkey)
ROOT_PUBKEY_B64=$(base64 -w0 < "$privdir"/rootkey.pub)
rm -rf "$privdir"
trap - EXIT

echo "Configuring network"
docker rm -f "bastion_${target}_target" 2>/dev/null || true
docker rm -f "bastion_${target}_tester" 2>/dev/null || true
if docker inspect "bastion-$target" >/dev/null 2>&1; then
    docker network rm "bastion-$target" >/dev/null
fi
docker network create "bastion-$target" >/dev/null

# run target but force entrypoint to test one, and add some keys in env (will be shared with tester)
echo "Starting target instance"
docker run $privileged \
    --name="bastion_${target}_target" \
    --network "bastion-$target" \
    -d \
    --entrypoint=/opt/bastion/tests/functional/docker/target_role.sh \
    -e USER_PUBKEY_B64="$USER_PUBKEY_B64" \
    -e ROOT_PUBKEY_B64="$ROOT_PUBKEY_B64" \
    -e TARGET_USER="user.5000" \
    -e TEST_QUICK="${TEST_QUICK:-0}" \
    $namespace:"$target"
docker logs -f "bastion_${target}_target" | sed -u -e 's/^/target: /;s/$/\r/' &

show_target_logs() {
    if [ "$ret" -ne 0 ] && [ "$ret" -ne 255 ]; then
        echo
        echo '>>> TARGET LOGS FOLLOW <<<'
        docker logs "bastion_${target}_target" | sed -u -e 's/^/target: /;s/$/\r/'
    fi
}

cleanup() {
    set +e
    docker rm -f "bastion_${target}_target" "bastion_${target}_tester" >/dev/null 2>/dev/null || true
    docker network rm "bastion-$target" >/dev/null
}

cleanup_exit() {
    show_target_logs
    cleanup
}

cleanup_int() {
    printf "%b%b%b\\n" "$WHITE_ON_RED" '>>> CLEANING UP, DO NOT CTRL+C AGAIN! <<<' "$NOC"
    cleanup
}

trap "cleanup_int" INT HUP

# run test env on it
if [[ -t 1 ]] && [ -z "$DOCKER_TTY" ]; then
    DOCKER_TTY="true"
else
    DOCKER_TTY="false"
fi
echo "Starting test instance and run tests with --tty=$DOCKER_TTY"
set +e
# shellcheck disable=SC2086
docker run \
    --name="bastion_${target}_tester" \
    --network "bastion-$target" \
    -i \
    --tty=$DOCKER_TTY \
    -e TARGET_IP="bastion_${target}_target" \
    -e TARGET_PORT=22 \
    -e TARGET_USER="user.5000" \
    -e USER_PRIVKEY_B64="$USER_PRIVKEY_B64" \
    -e ROOT_PRIVKEY_B64="$ROOT_PRIVKEY_B64" \
    -e TARGET="$target " \
    -e TEST_SCRIPT="$test_script" \
    -e TEST_QUICK="${TEST_QUICK:-0}" \
    $varstoadd $namespace:tester
ret=$?
if [ $ret -ne 0 ]; then
    printf '%b%b%b\n' "$WHITE_ON_RED" "Test instance returned $ret" "$NOC"
fi
trap - INT HUP

show_target_logs

if [ $ret -ne 0 ]; then
    if [ $ret -eq 255 ]; then
        printf '%b%b%b\n' "$WHITE_ON_RED" "=====================================" "$NOC"
        printf '%b%b%b\n' "$WHITE_ON_RED" ">>> TARGET DIDN'T START CORRECTLY <<<" "$NOC"
        printf '%b%b%b\n' "$WHITE_ON_RED" "=====================================" "$NOC"
        docker logs "bastion_${target}_target"
    elif [ $ret -eq 254 ]; then
        printf '%b%b%b\n' "$WHITE_ON_RED" "============================" "$NOC"
        printf '%b%b%b\n' "$WHITE_ON_RED" ">>> PREREQUISITES FAILED <<<" "$NOC"
        printf '%b%b%b\n' "$WHITE_ON_RED" "============================" "$NOC"
        docker logs "bastion_${target}_tester"
    else
        printf '%b%b%b\n' "$WHITE_ON_RED" "==============================================" "$NOC"
        printf '%b%b%b\n' "$WHITE_ON_RED" ">>> AN OVERVIEW OF THE FAILED TESTS FOLLOW <<<" "$NOC"
        printf '%b%b%b\n' "$WHITE_ON_RED" "==============================================" "$NOC"
        docker logs "bastion_${target}_tester" | grep -B5 -F -- '[FAIL]' | grep -vF -- '[ OK ]'
        echo "=== last few lines of the tester logs follow:"
        docker logs "bastion_${target}_tester" | tail -7
    fi
fi

cleanup
exit $ret
