package OVH::Bastion::Plugin::handleSessions;
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

use File::Basename;
use lib dirname(__FILE__) . '/../../../../../lib/perl';
use OVH::Result;
use OVH::Bastion;
#use OVH::Bastion::Plugin qw{ :DEFAULT };

sub kill_sessions {
    my %params = @_;
    my $fnret;

    my $account = $params{'account'};
    if (!$account) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing 'account' parameter");
    }

    $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $account);
    $fnret or return $fnret;

    $account = $fnret->value->{'account'};    # untainted

    $fnret = OVH::Bastion::sys_list_processes(user => $account);
    $fnret or return $fnret;

    my @pids = @{$fnret->value || []};

    my $problems = 0;
    my $count    = @pids;

    if ($count) {
        osh_info("Found $count processes running for $account, terminating them...");
    }
    else {
        osh_info("Found no process running for $account");
    }

    foreach my $pid (@pids) {
        $fnret = OVH::Bastion::execute_simple(cmd => ['kill', $pid], must_succeed => 1);
        $problems++ if !$fnret;
    }

    if ($problems) {
        return R('ERR_CANNOT_TERMINATE_PROCESSES', msg => "Couldn't terminate $problems out of $count processes");
    }
    return R('OK', value => {count => $count, terminated => ($count - $problems)});
}

1;
