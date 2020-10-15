#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
set -e
set -u

basedir=$(readlink -f "$(dirname "$0")"/../../..)
# shellcheck source=lib/shell/colors.inc
. "$basedir"/lib/shell/colors.inc


if [ "$TEST_QUICK" = 0 ]; then
    printf '%b>>> %b <<<%b\n' "$BOLD_CYAN" "SHELL CHECK" "$NOC"
    "$(dirname "$0")"/../../../bin/dev/shell-check.sh || exit 254

    printf '%b>>> %b <<<%b\n' "$BOLD_CYAN" "PERL CRITIC" "$NOC"
    "$(dirname "$0")"/../../../bin/dev/perl-critic.sh || exit 254

    printf '%b>>> %b <<<%b\n' "$BOLD_CYAN" "PERL TIDY" "$NOC"
    "$(dirname "$0")"/../../../bin/dev/perl-tidy.sh test || exit 254
fi

printf '%b>>> %b <<<%b\n' "$BOLD_CYAN" "SETTING UP KEYS" "$NOC"
base64 -d <<< "$USER_PRIVKEY_B64" > /root/user.privkey
chmod 400 /root/user.privkey
base64 -d <<< "$ROOT_PRIVKEY_B64" > /root/root.privkey
chmod 400 /root/root.privkey

printf '%b>>> %b <<<%b\n' "$BOLD_CYAN" "STARTING TESTS" "$NOC"

chmod 755 "$(dirname "$0")/../launch_tests_on_instance.sh"
[ ! -d "/root/.ssh" ] && mkdir /root/.ssh

delay=10
for i in $(seq 1 $delay); do
    echo "tester: waiting for target docker to be up ($i/$delay)..."
    fping -r 1 "$TARGET_IP" && break
done
if [ "$i" = "$delay" ]; then
    echo "tester: Error, target doesn't answer to pings after $delay tries :("
    exit 255
fi

delay=300
for i in $(seq 1 $delay); do
    echo "tester: waiting for target SSH to be up ($i/$delay)..."
    sleep 1
    if echo test | nc -w 1 "$TARGET_IP" "$TARGET_PORT" | grep -q ^SSH-2 ; then
        echo "tester: it's alive, starting tests!"
        [ "$TEST_QUICK" = 1 ] && export nocc=1
        "$(dirname "$0")"/../launch_tests_on_instance.sh "$TARGET_IP" "$TARGET_PORT" "$TARGET_USER" /root/user.privkey /root/root.privkey; ret=$?
        [ "$ret" -gt 253 ] && ret=253
        exit "$ret"
    elif ! fping -r 1 "$TARGET_IP" >/dev/null 2>&1; then
        echo "tester: Error, target stopped pinging before SSH was up, problem in target_role.sh entrypoint?"
        exit 255
    fi
done

echo "tester: Error, target is not alive or not listening for SSH :("
exit 255
