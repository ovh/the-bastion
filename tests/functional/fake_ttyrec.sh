#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck disable=SC2046
set -- $(getopt -o 'ZcCupVhvanf:z:d:t:T:k:s:e:l:F:' -l "zstd,level:,verbose,append,cheatcodes,no-cheatcodes,shell-cmd:,dir:,output:,uuid:,no-openpty,lock-timeout:,kill-timeout:,msg:,count-bytes,term:,version,help,zstd-try,max-flush-time:,name-format:" -- "$@")
while [ "$1" != "--" ]; do
    if [ "$1" = "-V" ]; then
        echo "fake-ttyrec v1.1.6.1"
        exit 0
    fi
    shift
done
shift
eval "$@"
