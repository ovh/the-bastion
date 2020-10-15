# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck shell=bash
# shellcheck disable=SC2034

RED=$(printf "%b" '\033[31m')
GREEN=$(printf "%b" '\033[32m')
YELLOW=$(printf "%b" '\033[33m')
BLUE=$(printf "%b" '\033[34m')

BOLD_CYAN=$(printf "%b" '\033[1;36m')

WHITE_ON_RED=$(printf "%b" '\033[41m')
WHITE_ON_BLUE=$(printf "%b" '\033[44m')
BLACK_ON_GREEN=$(printf "%b" '\033[30m\033[42m')
BLACK_ON_RED=$(printf "%b" '\033[1;30m\033[41m')

NOC=$(printf "%b" '\033[0m')
