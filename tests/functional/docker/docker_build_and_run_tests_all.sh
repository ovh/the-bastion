#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:

basedir=$(readlink -f "$(dirname "$0")"/../../..)
# shellcheck source=lib/shell/colors.inc
. "$basedir"/lib/shell/colors.inc

cd "$(dirname "$0")" || exit 1

targets=$(./docker_build_and_run_tests.sh --list-targets)

printf '%b%b%b\n' "$WHITE_ON_BLUE" "============================================================" "$NOC"
printf '%b%b%b\n' "$WHITE_ON_BLUE" "Testing all targets in parallel, ensure you have enough RAM!" "$NOC"
printf '%b%b%b\n' "$WHITE_ON_BLUE" "============================================================" "$NOC"
echo "Targets:"
echo "$targets"
echo
echo "Starting in 5 seconds, you can still CTRL+C in the meantime."

sleep 5

echo "GO!"

tempdir=$(mktemp -d)
# shellcheck disable=SC2317
cleanup() {
    test -d "$tempdir" && rm -rf "$tempdir"
    docker ps | grep -Eo 'bastion_.*_(target|tester)$' | xargs -r docker kill
}
trap 'cleanup' EXIT

for t in $targets
do
    [ "$t" = "-" ] && continue
    (
        friendlyname=$(echo "$t" | sed -re 's/@[^:]+//')
        DOCKER_TTY=false ./docker_build_and_run_tests.sh "$t" "--log-prefix=$friendlyname $*"
        echo $? > "$tempdir/$friendlyname"
    ) &
done
wait

echo

nberrors=0

for t in $targets
do
    [ "$t" = "-" ] && continue
    friendlyname=$(echo "$t" | sed -re 's/@[^:]+//')
    err=$(cat "$tempdir/$friendlyname" 2>/dev/null)
    rm -f "$tempdir/$friendlyname"
    if [ -z "$err" ]; then
        printf "%b%16s: tests couldn't run properly%b\\n" "$BLACK_ON_RED" "$friendlyname" "$NOC"
        nberrors=$(( nberrors + 1 ))
    elif [ "$err" = 0 ]; then
        printf "%b%16s: no errors :)%b\\n" "$BLACK_ON_GREEN" "$friendlyname" "$NOC"
    elif [ "$err" = 143 ]; then
        printf "%b%16s: tests interrupted%b\\n" "$BLACK_ON_RED" "$friendlyname" "$NOC"
        nberrors=$(( nberrors + 1 ))
    elif [ "$err" -lt 254 ]; then
        printf "%b%16s: $err tests failed%b\\n" "$BLACK_ON_RED" "$friendlyname" "$NOC"
        nberrors=$(( nberrors + 1 ))
    else
        printf "%b%16s: $err errors%b\\n" "$BLACK_ON_RED" "$friendlyname" "$NOC"
        nberrors=$(( nberrors + 1 ))
    fi
done

exit "$nberrors"
