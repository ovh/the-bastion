# vim: set filetype=perl ts=4 sw=4 sts=4 et:
package OVH::Bastion;

use common::sense;

use Time::Piece;    # $t->strftime

# Allocate a free local port for port forwarding
# This function MUST be called while holding the portallocation lock
# to prevent race conditions between concurrent allocations
sub allocate_local_port {
    # Get the port range configuration
    my $fnret = _get_local_port_range();
    $fnret or return $fnret;
    my $port_range = $fnret->value;
    my $min_port   = $port_range->{'min'};
    my $max_port   = $port_range->{'max'};

    $fnret = _get_allocated_local_ports();
    $fnret or return $fnret;
    my %allocated_ports = %{$fnret->value->{'ports'}};

    for (my $port = $min_port; $port <= $max_port; $port++) {
        if (!exists $allocated_ports{$port}) {
            return R('OK', value => {localPort => $port});
        }
    }

    return R('ERR_NO_FREE_PORTS',
        msg => "No free local ports available in range $min_port-$max_port. "
          . "Please contact your bastion administrator ASAP!");
}

# Validate if a remote port is valid and port count is within allowed limits
sub is_valid_portforwarding {
    my %params     = @_;
    my $remotePort = $params{'remotePort'};
    my $way        = $params{'way'};          # personal, group

    my $fnret = OVH::Bastion::is_valid_port(port => $remotePort);
    $fnret or osh_exit $fnret;
    $remotePort = $fnret->value;

    # TODO: check limits based on user/group
    $fnret = _get_allocated_local_ports();
    $fnret or return $fnret;

    return R('OK', value => {remotePort => $remotePort});
}

# TODO: maybe cache this to make it faster?
sub _get_allocated_local_ports {
    my $fnret = OVH::Bastion::get_group_list();
    $fnret or return $fnret;
    my $groups = $fnret->value;

    $fnret = OVH::Bastion::get_account_list();
    $fnret or return $fnret;
    my $accounts = $fnret->value;

    # loop over all groups and accounts to gather allocated ports
    my %allocated_local_ports;
    foreach my $group (keys %$groups) {
        my $grantedGroup = OVH::Bastion::get_acl_way(way => "group", group => $group);
        next if not $grantedGroup;
        foreach my $entry (@{$grantedGroup->value || []}) {
            if (defined $entry->{'localPort'}) {
                $allocated_local_ports{$entry->{'localPort'}} = 1;
            }
        }
    }

    foreach my $account (keys %$accounts) {
        my $grantedPersonal = OVH::Bastion::get_acl_way(way => 'personal', account => $account);
        next if not $grantedPersonal;
        foreach my $entry (@{$grantedPersonal->value || []}) {
            if (defined $entry->{'localPort'}) {
                $allocated_local_ports{$entry->{'localPort'}} = 1;
            }
        }
    }

    osh_debug("Allocated local ports: " . join(", ", keys %allocated_local_ports));
    return R('OK', value => {ports => \%allocated_local_ports});
}

# Get the configured port range free for port allocations used to allocate local ports
sub _get_local_port_range {
    my $fnret = OVH::Bastion::load_configuration();
    $fnret or return $fnret;
    my $config = $fnret->value;

    my $min_port = $config->{'portForwardingLocalPortMin'};
    my $max_port = $config->{'portForwardingLocalPortMax'};

    return R('OK', value => {min => $min_port, max => $max_port});
}

1;
