#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
set -e

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

if [ -z "$2" ] || [ -n "$3" ]; then
    echo "Usage: $0 <NAME> <UID>"
    echo "Note: UID can be the special value 'AUTO'"
    exit 1
fi

# Pre-check: the system groups that account creation relies on are created by
# the 'bin/admin/install' script. If the bastion code was deployed but the
# install script never ran, we'll be missing groups.
missing_groups=
for group in bastion-users \
  mfa-password-reqd mfa-password-bypass mfa-password-configd \
  mfa-totp-reqd mfa-totp-bypass mfa-totp-configd bastion-nopam osh-pubkey-auth-optional
do
    if ! getent group "$group" >/dev/null 2>&1; then
        missing_groups="$missing_groups $group"
    fi
done
if [ -n "$missing_groups" ]; then
    _err "Required system group(s) missing:$missing_groups"
    exit_fail "The bastion doesn't seem to be fully installed. Please run '$basedir/bin/admin/install' first, then retry."
fi

if [ "$2" = AUTO ] || [ "$2" = auto ]; then
    USER=root HOME=/root "$basedir/bin/plugin/restricted/accountCreate" '' '' '' '' --uid-auto --account "$1"
else
    USER=root HOME=/root "$basedir/bin/plugin/restricted/accountCreate" '' '' '' '' --uid "$2" --account "$1"
fi

"$basedir"/bin/admin/grant-all-restricted-commands-to.sh "$1"

add_user_to_group_compat "$1" "osh-admin"

configline=$(BASEDIR="$basedir" ACCOUNT="$1" perl -e '
    use lib $ENV{BASEDIR}."/lib/perl";
    use JSON;
    use OVH::Bastion;
    my $C = OVH::Bastion::load_configuration();
    if (!$C->value || ref $C->value->{adminAccounts} ne "ARRAY") { die "Could not add $ENV{ACCOUNT} in \"adminAccounts\" of bastion.conf, please do it manually!"; }
    my $account = $ENV{ACCOUNT};
    my $adminAccounts = $C->value->{adminAccounts};
    # Check if account is already in adminAccounts array
    my $already_exists = 0;
    foreach my $existing_account (@$adminAccounts) {
        if ($existing_account eq $account) {
            $already_exists = 1;
            last;
        }
    }
    # Only add if not already present
    if (!$already_exists) {
        push @{ $C->value->{adminAccounts} }, $account;
    }
    print encode_json($C->value->{adminAccounts});
')

if [ -n "$configline" ]; then
    sed_compat 's/^"adminAccounts": .*/"adminAccounts": '"$configline"',/' "$BASTION_ETC_DIR/bastion.conf"
fi
