#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
set -e

basedir=$(readlink -f "$(dirname "$0")"/../../..)
# shellcheck source=lib/shell/colors.inc
. "$basedir"/lib/shell/colors.inc

namespace=the-bastion-test

target="$1"
shift || true

# all remaining options will be passed as-is on the target docker, through target_role.sh to launch-tests-on-instance.sh

get_supported_targets() {
    local target targets subtarget
    for dockerfile in "$(dirname "$0")"/../../../docker/Dockerfile.*; do
        if grep -q '^# TESTOPT ' "$dockerfile"; then
            target=$(basename "$dockerfile")
            target=${target/Dockerfile./}
            # if the file has a TESTFROM entry, then it's actually multiple similar targets
            if grep -q '^# TESTFROM ' "$dockerfile"; then
                # shellcheck disable=SC2013
                for testfrom in $(grep '^# TESTFROM ' "$dockerfile" | cut -d' ' -f3-); do
                    subtarget="$target@$testfrom"
                    targets="$targets $subtarget"
                done
            else
                targets="$targets $target"
            fi
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
        echo "Usage: $0 <TARGET> [additional options]"
        echo
        echo "Supported targets are: "
        print_supported_targets
        echo "These additional options are passed directly to the worker:"
        "$basedir"/tests/functional/launch_tests_on_instance.sh --help-light
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

# slim sshd-only image, used to spin up the "jumphost" and "remoteserver" boxes
# sitting behind the bastion (for the proxy-jump functional tests). The role
# script is bind-mounted at run time, so this image carries no bastion code.
echo "Building slim ssh host environment"
docker build -f "$(dirname "$0")/../../../docker/Dockerfile.sshslim" -t "$namespace:sshslim" "$(dirname "$0")"/../../..

# if we have a subtarget, we need to override the FROM of the target_dockerfile
# don't do this in place however, create a tempfile for this
if [ -n "$subtarget" ]; then
    dockerfiletmp=$(mktemp)
    trap 'rm -f $dockerfiletmp' EXIT
    sed -re "s=^FROM .+=FROM $subtarget=" "$target_dockerfile" > "$dockerfiletmp"
    target_dockerfile="$dockerfiletmp"
fi

# build target
echo "Building target environment"
target=$(echo "$target" | sed -re 's/[^a-zA-Z0-9_-]/_/g')
docker build -f "$target_dockerfile" -t "$namespace:$target" "$(dirname "$0")"/../../..

# get the target environment we want from the dockerfile
testopts="$(grep '^# TESTOPT' "$target_dockerfile" | tail -n1 | cut -c10-)"
privileged=''
if grep -q '^# PRIVILEGED' "$target_dockerfile"; then
    privileged='--privileged'
fi

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
docker rm -f "bastion_${target}_target2" 2>/dev/null || true
docker rm -f "bastion_${target}_tester" 2>/dev/null || true
docker rm -f "bastion_${target}_jumphost" 2>/dev/null || true
docker rm -f "bastion_${target}_remoteserver" 2>/dev/null || true
if docker inspect "bastion-$target" >/dev/null 2>&1; then
    docker network rm "bastion-$target" >/dev/null
fi

docker network create "bastion-$target" >/dev/null

# run target but force entrypoint to test one, and add some keys in env (will be shared with tester)
echo "Starting target instance"
docker run $privileged \
    --name="bastion_${target}_target" \
    --network "bastion-$target" \
    --init \
    -d \
    --entrypoint=/opt/bastion/tests/functional/docker/target_role.sh \
    -e USER_PUBKEY_B64="$USER_PUBKEY_B64" \
    -e ROOT_PUBKEY_B64="$ROOT_PUBKEY_B64" \
    -e TARGET_USER="user.5000" \
    -e WANT_HTTP_PROXY=1 \
    $namespace:"$target"
docker logs -f "bastion_${target}_target" | sed -u -e 's/^/target: /;s/$/\r/' &

# start a second bastion, used as the "remote" bastion for the inter-realm tests
echo "Starting second bastion instance"
docker run $privileged \
    --name="bastion_${target}_target2" \
    --network "bastion-$target" \
    --init \
    -d \
    --entrypoint=/opt/bastion/tests/functional/docker/target_role.sh \
    -e USER_PUBKEY_B64="$USER_PUBKEY_B64" \
    -e ROOT_PUBKEY_B64="$ROOT_PUBKEY_B64" \
    -e TARGET_USER="user.5000" \
    $namespace:"$target"
docker logs -f "bastion_${target}_target2" | sed -u -e 's/^/target2: /;s/$/\r/' &

# start two slim ssh boxes behind the bastion (used by the proxy-jump tests):
# - jumphost: the host the bastion proxies through (egress user 'jump_')
# - remoteserver: the final host reached through the bastion and the jumphost (egress user 'test-shell_')
# both get the root pubkey so the tester can root-SSH in and push the bastion egress keys at test time
sshhost_role="$basedir/tests/functional/docker/sshhost_role.sh"
echo "Starting jumphost instance"
docker run \
    --name="bastion_${target}_jumphost" \
    --network "bastion-$target" \
    --init \
    -d \
    -v "$sshhost_role:/sshhost_role.sh:ro" \
    --entrypoint bash \
    -e ROOT_PUBKEY_B64="$ROOT_PUBKEY_B64" \
    -e SSHHOST_ROLE="jumphost" \
    -e SSHHOST_USERS="jump_" \
    "$namespace:sshslim" /sshhost_role.sh
docker logs -f "bastion_${target}_jumphost" | sed -u -e 's/^/jumphost: /;s/$/\r/' &

echo "Starting remoteserver instance"
docker run \
    --name="bastion_${target}_remoteserver" \
    --network "bastion-$target" \
    --init \
    -d \
    -v "$sshhost_role:/sshhost_role.sh:ro" \
    --entrypoint bash \
    -e ROOT_PUBKEY_B64="$ROOT_PUBKEY_B64" \
    -e SSHHOST_ROLE="remoteserver" \
    -e SSHHOST_USERS="test-shell_" \
    "$namespace:sshslim" /sshhost_role.sh
docker logs -f "bastion_${target}_remoteserver" | sed -u -e 's/^/remoteserver: /;s/$/\r/' &

show_target_logs() {
    if [ "$ret" -ne 0 ] && [ "$ret" -ne 255 ]; then
        echo
        echo '>>> TARGET LOGS FOLLOW <<<'
        docker logs "bastion_${target}_target" | sed -u -e 's/^/target: /;s/$/\r/'
        echo '>>> SECOND BASTION LOGS FOLLOW <<<'
        docker logs "bastion_${target}_target2" 2>/dev/null | sed -u -e 's/^/target2: /;s/$/\r/'
    fi
}

cleanup() {
    set +e
    docker rm -f "bastion_${target}_target" "bastion_${target}_target2" "bastion_${target}_tester" \
        "bastion_${target}_jumphost" "bastion_${target}_remoteserver" >/dev/null 2>/dev/null || true
    docker network rm "bastion-$target" >/dev/null
}

# shellcheck disable=SC2317
cleanup_exit() {
    show_target_logs
    cleanup
}

# shellcheck disable=SC2317
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
echo "Starting test instance and run tests with --tty=$DOCKER_TTY (testopts: $testopts, extra params: $*)"
set +e
# shellcheck disable=SC2086
docker run \
    --name="bastion_${target}_tester" \
    --network "bastion-$target" \
    --init \
    -i \
    --tty=$DOCKER_TTY \
    -e TARGET_IP="bastion_${target}_target" \
    -e TARGET_PORT=22 \
    -e TARGET_PROXY_PORT=8443 \
    -e TARGET2_IP="bastion_${target}_target2" \
    -e JUMPHOST_IP="bastion_${target}_jumphost" \
    -e REMOTESERVER_IP="bastion_${target}_remoteserver" \
    -e TARGET_USER="user.5000" \
    -e USER_PRIVKEY_B64="$USER_PRIVKEY_B64" \
    -e ROOT_PRIVKEY_B64="$ROOT_PRIVKEY_B64" \
    -e EXTRA_OPTIONS="$testopts $*" \
    $namespace:tester
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
