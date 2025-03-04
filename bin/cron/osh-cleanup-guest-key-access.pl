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
if (OVH::Bastion::config('readOnlySlaveMode')->value) {
    _log "We're not a master instance, don't do anything";
    exit 0;
}

$fnret = OVH::Bastion::load_configuration_file(
    file   => OVH::Bastion::main_configuration_directory() . "/osh-cleanup-guest-key-access.conf",
    secure => 1,
);

my $config;
if (!$fnret) {
    if (-e OVH::Bastion::main_configuration_directory() . "/osh-cleanup-guest-key-access.conf") {
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
$config->{'syslog_facility'} //= ($config->{'SyslogFacility'} // 'local6');
$config->{'enabled'}         //= ($config->{'Enabled'}        // 1);

# logging
if ($config->{'syslog_facility'}) {
    OVH::SimpleLog::setSyslog($config->{'syslog_facility'});
}

if (!$config->{'enabled'}) {
    _log "Script is disabled.";
    exit 0;
}

# command-line
sub print_usage {
    print <<"EOF";

$0 [options]

--dry-run   Don't actually do anything, just report what would be done
--verbose   More detailed logging

EOF
    return 1;
}

my ($dryRun, $verbose);
{
    my $optwarn = 'Unknown error';
    local $SIG{'__WARN__'} = sub { $optwarn = shift; };
    if (
        !GetOptions(
            "dry-run"  => \$dryRun,
            "verbose+" => \$verbose,
        )
      )
    {
        _err "Error while parsing command-line options: $optwarn";
        print_usage();
        exit 1;
    }
}

_log "Looking for group guests that no longer have any access to any server of the group...";

$fnret = OVH::Bastion::get_group_list(groupType => "key");
if (!$fnret) {
    _err "Couldn't get group list:" . $fnret->msg;
    exit 1;
}
my $groups = $fnret->value;

foreach my $shortGroup (sort keys %$groups) {
    foreach my $account (@{$groups->{$shortGroup}{'members'}}) {
        next if ($account eq 'allowkeeper');    # don't need to check this special user

        _log "<$shortGroup/$account> checking if group guest..." if $verbose;

        # rule out realm accounts, we would need to check every remote account's info
        next if ($account =~ /^realm_/);

        # the "members" of the system group key$shortGroup might be either members or guests,
        # so we first rule out members
        next if OVH::Bastion::is_group_member(account => $account, group => $shortGroup, cache => 1);

        # it seems to be a guest, double-check that
        next if !OVH::Bastion::is_group_guest(account => $account, group => $shortGroup, cache => 1);

        _log "<$shortGroup/$account> found a guest, checking remaining accesses..." if $verbose;

        # okay, any access remaining?
        $fnret = OVH::Bastion::get_acl_way(way => 'groupguest', group => $shortGroup, account => $account);
        if (!$fnret) {
            _warn "<$shortGroup/$account> Error getting guest accesses ($fnret), skipping";
            next;
        }
        elsif ($fnret->err eq 'OK') {
            _log "<$shortGroup/$account> The account still has "
              . (@{$fnret->value})
              . " accesses to the group, skipping"
              if $verbose;
            next;
        }
        elsif ($fnret->err eq 'OK_EMPTY' && !@{$fnret->value}) {

            # this is a guest, but no ACL remains (probably the last one had a TTL),
            # so we'll cleanup this guest
            if ($dryRun) {
                _log
                  "<$shortGroup/$account> The account is a guest of group but has no remaining access, would have cleaned up in non-dry-run mode";
                next;
            }
            _log "<$shortGroup/$account> The account is a guest of group but has no remaining access, cleaning up...";

            # get $group from $shortGroup
            $fnret = OVH::Bastion::is_valid_group_and_existing(group => $shortGroup, groupType => 'key', cache => 1);
            if (!$fnret) {
                _warn "<$shortGroup/$account> Group seems invalid ($fnret), skipping";
                next;
            }
            my $group = $fnret->value->{'group'};

            # remove account from group
            my @command = qw{ /usr/bin/env perl -T };
            push @command, $OVH::Bastion::BASEPATH . '/bin/helper/osh-groupSetRole';
            push @command, '--type',    'guest';
            push @command, '--group',   $group;
            push @command, '--account', $account;
            push @command, '--action',  'del';
            $fnret = OVH::Bastion::helper(cmd => \@command);

            if (!$fnret) {
                _err "<$shortGroup/$account> Failed to revoke key access: $fnret";
            }
            else {
                _log "<$shortGroup/$account> Key access revoked";
            }
        }
    }
}

_log "Done, got " . (OVH::SimpleLog::nb_errors()) . " error(s) and " . (OVH::SimpleLog::nb_warnings()) . " warning(s).";
