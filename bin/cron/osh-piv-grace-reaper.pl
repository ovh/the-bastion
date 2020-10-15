#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

use File::Basename;
use lib dirname(__FILE__) . '/../../lib/perl';
use OVH::Bastion;
use OVH::Result;
use OVH::SimpleLog;

my $fnret;

$fnret = OVH::Bastion::load_configuration_file(
    file     => OVH::Bastion::main_configuration_directory() . "/osh-piv-grace-reaper.conf",
    secure   => 1,
    keywords => [qw{ SyslogFacility }],
);

my $config;
if (not $fnret) {
    _err "Error while loading configuration, continuing anyway with default values...";
}
else {
    $config = $fnret->value;
    if (ref $config ne 'HASH') {
        _err "Invalid data returned while loading configuration, continuing anyway with default values...";
    }
}

# logging
if ($config && $config->{'SyslogFacility'}) {
    OVH::SimpleLog::setSyslog($config->{'SyslogFacility'});
}

_log "Looking for accounts with a PIV grace...";

# loop through all the accounts, and only work on those that have a grace period set
$fnret = OVH::Bastion::get_account_list();
if (!$fnret) {
    _err "Couldn't get account list: " . $fnret->msg;
    exit 1;
}

# this'll be used in syslog
$ENV{'UNIQID'} = OVH::Bastion::generate_uniq_id()->value;

foreach my $account (%{$fnret->value}) {

    # if account doesn't have PIV grace, don't bother
    $fnret = OVH::Bastion::account_config(account => $account, public => 1, key => OVH::Bastion::OPT_ACCOUNT_INGRESS_PIV_GRACE);
    next if !$fnret;

    # we have PIV grace set for this account
    my $expiry = $fnret->value;
    my $human = OVH::Bastion::duration2human(seconds => ($expiry - time()))->value;
    _log "Account $account has PIV grace expiry set to $expiry (" . $human->{'human'} . ")";

    # is PIV grace TTL expired?
    if (time() > $expiry) {

        # it is, but if current policy is not set to enforce, it's useless
        _log "... grace for $account is expired, is current policy set to enforced?";
        $fnret = OVH::Bastion::account_config(account => $account, public => 1, key => OVH::Bastion::OPT_ACCOUNT_INGRESS_PIV_POLICY);
        if (!$fnret || $fnret->value ne 'yes') {

            # PIV grace expired but current policy is already relaxed, so just remove the grace flag
            _log "... grace for $account is expired, but current policy is not set to enforced, removing grace...";
            $fnret = OVH::Bastion::account_config(account => $account, public => 1, key => OVH::Bastion::OPT_ACCOUNT_INGRESS_PIV_GRACE, delete => 1);
            if (!$fnret) {
                _err "... couldn't remove grace flag for $account";
                next;
            }

            # grace removed for this account, no change needed on keys because it wasn't set to enforced
            next;
        }

        # PIV grace expired, we need to remove the non-PIV keys from the account's authorized_keys2 file
        _log "... grace for $account is expired, enforcing PIV-keys only...";
        OVH::SimpleLog::closeSyslog();
        $fnret = OVH::Bastion::ssh_ingress_keys_piv_apply(action => "enable", account => $account);
        if (!$fnret) {
            _err "... failed to re-enforce PIV policy for $account ($fnret->msg)";
            next;
        }
        if ($config && $config->{'SyslogFacility'}) {
            OVH::SimpleLog::setSyslog($config->{'SyslogFacility'});
        }
        _log "... re-enforced PIV policy for $account";

        # ok, now remove grace flag
        $fnret = OVH::Bastion::account_config(account => $account, public => 1, key => OVH::Bastion::OPT_ACCOUNT_INGRESS_PIV_GRACE, delete => 1);
        if (!$fnret) {
            _err "... couldn't remove grace flag for $account";
        }
        else {
            _log "... grace flag removed for $account";
        }
    }
    else {
        _log "... grace for $account is not expired yet, skipping...";
    }
}

_log "Done";
