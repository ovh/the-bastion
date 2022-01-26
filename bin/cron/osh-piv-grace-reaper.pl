#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

use File::Basename;
use lib dirname(__FILE__) . '/../../lib/perl';
use OVH::Bastion;
use OVH::Result;
use OVH::SimpleLog;

# this'll be used in syslog
$ENV{'UNIQID'} = OVH::Bastion::generate_uniq_id()->value;

my $fnret;

# abort early if we're not a master instance
if (OVH::Bastion::config('readOnlySlaveMode')->value) {
    _log "We're not a master instance, don't do anything";
    exit 0;
}

$fnret = OVH::Bastion::load_configuration_file(
    file   => OVH::Bastion::main_configuration_directory() . "/osh-piv-grace-reaper.conf",
    secure => 1,
);

my $config;
if (!$fnret) {
    if (-e OVH::Bastion::main_configuration_directory() . "/osh-piv-grace-reaper.conf") {
        _warn "Error while loading configuration, continuing anyway with default values...";
    }
    else {
        _log "No configuration file found, using default config values...";
    }
}
else {
    $config = $fnret->value;
    if (ref $config ne 'HASH') {
        _warn "Invalid data returned while loading configuration, continuing anyway with default values...";
    }
}

# set default values
$config = {} if ref $config ne 'HASH';
$config->{'SyslogFacility'} //= 'local6';

# logging
if ($config->{'SyslogFacility'}) {
    OVH::SimpleLog::setSyslog($config->{'SyslogFacility'});
}

_log "Looking for accounts with a PIV grace...";

# loop through all the accounts, and only work on those that have a grace period set
$fnret = OVH::Bastion::get_account_list();
if (!$fnret) {
    _err "Couldn't get account list: " . $fnret->msg;
    exit 1;
}
foreach my $account (sort keys %{$fnret->value}) {

    # if account doesn't have PIV grace, we have nothing to do
    $fnret = OVH::Bastion::account_config(account => $account, public => 1, key => OVH::Bastion::OPT_ACCOUNT_INGRESS_PIV_GRACE);
    next if !$fnret;

    # we have PIV grace set for this account
    my $expiry = $fnret->value;
    my $human  = OVH::Bastion::duration2human(seconds => ($expiry - time()))->value;
    _log "Account $account has PIV grace expiry set to $expiry (" . $human->{'human'} . ")";

    # is PIV grace TTL expired?
    if (time() < $expiry) {
        _log "... grace for $account is not expired yet, skipping...";
        next;
    }

    # it is: remove it
    _log "... grace for $account is expired, removing it";
    $fnret = OVH::Bastion::account_config(account => $account, public => 1, key => OVH::Bastion::OPT_ACCOUNT_INGRESS_PIV_GRACE, delete => 1);
    if (!$fnret) {
        warn_syslog("Couldn't remove grace flag for $account: " . $fnret->msg);
        _err "... couldn't remove grace flag for $account";
        next;
    }

    $fnret = OVH::Bastion::syslogFormatted(
        severity => 'info',
        type     => 'account',
        fields   => [
            [action  => 'modify'],
            [account => $account],
            [item    => 'piv_grace'],
            [old     => 'true'],
            [new     => 'false'],
            [comment => "PIV grace up to " . $human->{'human'} . " has been removed"]
        ]
    );

    # PIV grace expired, if the effective piv policy for this account is enabled (depending on global and account specific policy),
    # we need to remove the non-PIV keys from the account's authorized_keys2 file, as we're now out from grace
    $fnret = OVH::Bastion::is_effective_piv_account_policy_enabled(account => $account);
    if ($fnret->is_err) {
        my $msg = "Couldn't get the effective PIV account policy of $account (" . $fnret->msg . ")";
        warn_syslog($msg);
        _err("... $msg");
    }
    elsif ($fnret->is_ok) {

        # effective policy is enabled, remove non-piv keys
        OVH::SimpleLog::closeSyslog();
        $fnret = OVH::Bastion::ssh_ingress_keys_piv_apply(action => "enable", account => $account);
        if ($config && $config->{'SyslogFacility'}) {
            OVH::SimpleLog::setSyslog($config->{'SyslogFacility'});
        }
        if (!$fnret) {
            my $msg = "failed to re-enforce PIV policy for $account (" . $fnret->msg . ")";
            warn_syslog($msg);
            _err("... $msg");
        }
        else {
            _log "... re-enforced PIV policy for $account";
        }
    }
    else {
        _log "... effective policy is disabled for this $account, not disabling non-PIV keys";
    }
}

_log "Done, got " . (OVH::SimpleLog::nb_errors()) . " error(s) and " . (OVH::SimpleLog::nb_warnings()) . " warning(s).";
