#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;
use Getopt::Long;

use File::Basename;
use lib dirname(__FILE__) . '/../../lib/perl';
use OVH::Bastion;
use OVH::Result;
use OVH::SimpleLog;

# this'll be used in syslog
$ENV{'UNIQID'} = OVH::Bastion::generate_uniq_id()->value;

my $fnret;

# abort early if we're not a master instance
if (!$ENV{'FORCE'}) {
    if (OVH::Bastion::config('readOnlySlaveMode')->value) {
        _log "We're not a master instance, don't do anything";
        exit 0;
    }
}

$fnret = OVH::Bastion::get_account_list();
if (!$fnret) {
    _err "Couldn't get the accounts list: $fnret";
    exit 1;
}

foreach my $account (sort keys %{$fnret->value || {}}) {
    _log "Working on account $account";
    $fnret = OVH::Bastion::ssh_ingress_keys_from_apply_account(account => $account, dryRun => $ENV{'DRYRUN'});
    if ($fnret->err eq 'OK_NO_CHANGE') {
        _log "... OK (no change across " . $fnret->value->{'nbkeys'} . " keys)";
    }
    elsif ($fnret) {
        _log "... $fnret ("
          . $fnret->value->{'nbchanged'}
          . " keys changed out of "
          . $fnret->value->{'nbkeys'}
          . " keys)";
    }
    else {
        _warn "... $fnret";
    }
}

_log "Done, got " . (OVH::SimpleLog::nb_errors()) . " error(s) and " . (OVH::SimpleLog::nb_warnings()) . " warning(s).";
