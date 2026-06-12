#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
# shellcheck disable=SC2119
set -e

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

action="$1"
type="$2"
name="$3"

# Number of shards per entity type. MUST be identical fleet-wide (master+slaves),
# because the shard a given account/group lands in is derived from its name.
# Changing it requires a full `regen all` (handled below: rebuild + prune).
case "$SUDOERS_SHARD_COUNT" in
    '' | *[!0-9]*) echo "SUDOERS_SHARD_COUNT must be a positive integer" >&2; exit 1 ;;
    *) ;;
esac
[ "$SUDOERS_SHARD_COUNT" -ge 1 ] || { echo "SUDOERS_SHARD_COUNT must be >= 1" >&2; exit 1; }
# zero-pad shard number so sharded files sort nicely
_maxshard=$((SUDOERS_SHARD_COUNT - 1))
SHARD_WIDTH=${#_maxshard}

die_usage() {
    echo "Usage: $0 <create|delete> <account|group> [name]" >&2
    exit 1
}

# Template cache, loaded once per process (an invocation only ever handles one type: account or group)
_TPL_LOADED=""
_TPL_PATHS=()
_TPL_BODIES=()
load_templates() {
    # $1 = account|group
    [ "$_TPL_LOADED" = "$1" ] && return 0
    local _tmpldir _os _t _bn
    if [ "$1" = account ]; then
        _tmpldir="$basedir/etc/sudoers.account.template.d"
    else
        _tmpldir="$basedir/etc/sudoers.group.template.d"
    fi
    _os=$(echo "$OS_FAMILY" | tr '[:upper:]' '[:lower:]')
    _TPL_PATHS=()
    _TPL_BODIES=()
    for _t in $(find "$_tmpldir/" -type f -name "*.sudoers" | sort); do
        _bn="${_t##*/}"
        # xxx-name.$os.sudoers is OS-specific: keep only if $os matches ours
        if [ "$(echo "$_bn" | cut -d. -f3)" = "sudoers" ]; then
            if [ "$(echo "$_bn" | cut -d. -f2 | tr '[:upper:]' '[:lower:]')" != "$_os" ]; then
                continue
            fi
        fi
        _TPL_PATHS+=("$_t")
        _TPL_BODIES+=("$(<"$_t")")
    done
    _TPL_LOADED="$1"
}

# render one entity (group or account) sudoers block, delimited by #>>>'s and #<<<'s, to stdout, from the cached templates.
render_block() {
    # $1 = account|group   $2 = name   $3 = md5 hex of the name
    local _type="$1" _name="$2" _md5="$3" _norm _i _body
    load_templates "$_type"

    # %NORMACCOUNT% / %NORMGROUP%: globally-unique, sudoers-alias-safe identifier.
    _norm="${_name//[!A-Za-z0-9_]/_}_${_md5:0:6}"
    _norm="${_norm^^}"

    echo "#>>> $_type $_name"
    for _i in "${!_TPL_PATHS[@]}"; do
        echo "# ${_TPL_PATHS[$_i]}:"
        _body="${_TPL_BODIES[$_i]}"
        if [ "$_type" = account ]; then
            _body="${_body//%ACCOUNT%/$_name}"
            _body="${_body//%NORMACCOUNT%/$_norm}"
        else
            _body="${_body//%GROUP%/$_name}"
            _body="${_body//%NORMGROUP%/$_norm}"
        fi
        printf '%s\n' "${_body//%BASEPATH%/$basedir}"
    done
    echo "#<<< $_type $_name"
}

# output $srcfile with the given entity's block removed (markers included).
# no-op if the block isn't present, so create is idempotent and delete is safe.
# shellcheck disable=SC2317  # reached only via with_lock-invoked _apply_shard_edit
strip_block() {
    # $1 = type   $2 = name   $3 = srcfile
    awk -v b="#>>> $1 $2" -v e="#<<< $1 $2" '
        $0 == b { skip = 1; next }
        $0 == e { skip = 0; next }
        !skip   { print }
    ' "$3"
}

# syntax-validate a shard file. Tolerates aliases defined elsewhere in the global
# sudoers (e.g. SUPEROWNERS) thanks to -q, but still fails on real syntax errors.
validate_shard() {
    # $1 = file
    command -v visudo >/dev/null 2>&1 || return 0   # no visudo: skip (don't block)
    visudo -cqf "$1" >/dev/null 2>&1
}

# the locked critical section of a single-entity edit. Called via with_lock(),
# to ensure we're the only ones to tinker with sudoers.d/osh-* files.
# shellcheck disable=SC2317  # invoked indirectly through with_lock "$@"
_apply_shard_edit() {
    # $1 = create|delete   $2 = type   $3 = name   $4 = dst   $5 = md5
    local _todo="$1" _type="$2" _name="$3" _dst="$4" _md5="$5" _tmp="$4.tmp"

    if [ -f "$_dst" ]; then
        strip_block "$_type" "$_name" "$_dst" > "$_tmp"
    else
        echo "# bastion sharded sudoers - $_type shard (do not edit by hand)" > "$_tmp"
    fi
    if [ "$_todo" = create ]; then
        render_block "$_type" "$_name" "$_md5" >> "$_tmp"
    fi
    chmod 0440 "$_tmp"

    if ! validate_shard "$_tmp"; then
        action_error "generated $_dst failed visudo validation, not applying"
        rm -f "$_tmp"
        return 1
    fi
    # atomic publish (sudo ignores the .tmp, so that it never sees a partial file)
    mv -f "$_tmp" "$_dst"

    # if migrating via install, keep this shard out of the obsolete-files list
    if [ -n "${OLD_SUDOERS:-}" ]; then
        sed_compat "/${_dst##*/}$/d" "$OLD_SUDOERS"
    fi
    return 0
}

# add or remove a single account/group, editing only its shard in place.
manage_entity() {
    # $1 = create|delete   $2 = account|group   $3 = name
    local _todo="$1" _type="$2" _types="${2}s" _name="$3" _md5 _shard _dst

    # on create we expect the entity to exist, check for this below
    if [ "$_todo" = create ]; then
        if [ "$_type" = account ]; then
            if ! getent passwd "$_name" | grep -q ":$basedir/bin/shell/osh.pl$"; then
                action_error "$_name is not a bastion account"
                return 1
            fi
        else
            if ! test -f "/home/$_name/allowed.ip"; then
                action_error "$_name doesn't seem to be a valid bastion group"
                return 1
            fi
        fi
    fi
    # on delete the caller may be mid-removal, so don't try to validate with that
    # we have on the filesystem.
    # ---

    _md5=$(md5sum_compat - <<< "$_name")
    printf -v _shard "%0${SHARD_WIDTH}d" "$(( 16#${_md5:0:8} % SUDOERS_SHARD_COUNT ))"
    _dst="$SUDOERS_DIR/osh-$_types-shard-$_shard"

    if [ "$_todo" = create ]; then
        action_detail "... $_name -> ${_dst##*/}"
    else
        action_detail "... removing $_name from ${_dst##*/}"
    fi

    with_lock "osh-$_types-shard-$_shard" _apply_shard_edit "$_todo" "$_type" "$_name" "$_dst" "$_md5"
}

# rebuild every shard for a type from scratch (install / migration / count change).
# Builds all touched shards as .tmp, validates, atomically publishes, then prunes any
# stale shard file we didn't just write (emptied shards, orphans from a larger COUNT).
regen_all() {
    # $1 = account|group
    local _type="$1" _types="${1}s" _name _md5 _shard _dst _tmp _bn _f
    declare -A _started=()
    declare -A _final=()

    # cache the templates once before iterating (possibly) thousands of entities
    load_templates "$_type"

    while IFS= read -r _name; do
        [ -n "$_name" ] || continue
        _md5=$(md5sum_compat - <<< "$_name")
        printf -v _shard "%0${SHARD_WIDTH}d" "$(( 16#${_md5:0:8} % SUDOERS_SHARD_COUNT ))"
        _dst="$SUDOERS_DIR/osh-$_types-shard-$_shard"
        _tmp="$_dst.tmp"
        if [ -z "${_started[$_shard]:-}" ]; then
            echo "# bastion sharded sudoers - $_type shard $_shard (do not edit by hand)" > "$_tmp"
            _started[$_shard]=1
        fi
        render_block "$_type" "$_name" "$_md5" >> "$_tmp"
    done < <(list_entities "$_type")

    for _shard in "${!_started[@]}"; do
        _dst="$SUDOERS_DIR/osh-$_types-shard-$_shard"
        _tmp="$_dst.tmp"
        chmod 0440 "$_tmp"
        if ! validate_shard "$_tmp"; then
            action_error "shard ${_dst##*/} failed visudo validation, skipping"
            rm -f "$_tmp"
            continue
        fi
        mv -f "$_tmp" "$_dst"
        _final[${_dst##*/}]=1
        if [ -n "${OLD_SUDOERS:-}" ]; then
            sed_compat "/${_dst##*/}$/d" "$OLD_SUDOERS"
        fi
    done

    # prune shard files for this type that we did not (re)write this run
    for _f in "$SUDOERS_DIR"/osh-"$_types"-shard-*; do
        [ -e "$_f" ] || continue
        _bn="${_f##*/}"
        case "$_bn" in
            *.tmp) continue ;;
            *) ;;
        esac
        if [ -z "${_final[$_bn]:-}" ]; then
            action_detail "... pruning obsolete shard $_bn"
            rm -f "$_f"
        fi
    done
    return 0
}

# list existing bastion entities of a type, one name per line
list_entities() {
    # $1 = account|group
    if [ "$1" = account ]; then
        getent passwd | grep ":$basedir/bin/shell/osh.pl$" | cut -d: -f1 | sort
    else
        getent group | cut -d: -f1 | grep -- '-gatekeeper$' | sed -e 's/-gatekeeper$//' | sort
    fi
}

#### main ####

if [ "$type" != group ] && [ "$type" != account ]; then
    echo "Invalid type specified" >&2
    die_usage
fi

nbfailed=0

if [ -z "$name" ]; then
    if [ "$action" = create ]; then
        action_doing "Regenerating all $type sudoers shards from templates"
        regen_all "$type" || nbfailed=$((nbfailed + 1))
    elif [ "$action" = delete ]; then
        echo "Cowardly refusing to delete all $type sudoers, a man needs a name" >&2
        die_usage
    else
        die_usage
    fi
else
    if [ "$action" = create ]; then
        action_doing "Updating $type '$name' sudoers shard"
        manage_entity create "$type" "$name" || nbfailed=$((nbfailed + 1))
    elif [ "$action" = delete ]; then
        action_doing "Removing $type '$name' from its sudoers shard"
        manage_entity delete "$type" "$name" || nbfailed=$((nbfailed + 1))
    else
        die_usage
    fi
fi

if [ "$nbfailed" != 0 ]; then
    action_error "Failed generating $nbfailed sudoers"
else
    action_done
fi
exit "$nbfailed"
