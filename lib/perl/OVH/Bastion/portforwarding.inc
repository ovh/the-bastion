# vim: set filetype=perl ts=4 sw=4 sts=4 et:
package OVH::Bastion;

use common::sense;

use File::Basename;
use lib dirname(__FILE__) . '/../../../../lib/perl';
use OVH::Bastion::Plugin::otherProtocol;

use Time::Piece;    # $t->strftime

# Check if a port is in use by any process on the system
sub _is_port_in_use {
    my %params = @_;
    my $port   = $params{'port'};

    # try ss first
    my ($ss_test, $ss_exit_code) = OVH::Bastion::execute(cmd => ['ss', '-ln'], noisy_stderr => 0);
    if ($ss_exit_code == 0 && $ss_test && $ss_test =~ /:$port /) {
        return 1;
    }
    if ($ss_exit_code == 0) {
        return 0;
    }

    # fallback to netstat if ss failed for some reason
    my ($netstat_test, $netstat_exit_code) = OVH::Bastion::execute(cmd => ['netstat', '-ln'], noisy_stderr => 0);
    if ($netstat_exit_code == 0 && $netstat_test && $netstat_test =~ /:$port /) {
        return 1;
    }
    if ($netstat_exit_code == 0) {
        return 0;
    }

    # If both commands fail, assume port is free 
    warn_syslog("Warning: Both 'ss' and 'netstat' commands failed, assuming port $port is free");
    return 0;
}

# Allocate a free local port for port forwarding
# This function MUST be called while holding the portforwarding lock
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

    my @tried_ports;
    for my $port ($min_port .. $max_port) {
        if (!exists $allocated_ports{$port}) {
            # Check if the port is actually in use by another process
            if (_is_port_in_use(port => $port)) {
                push @tried_ports, $port;
                osh_warn("Port $port is in use by another process, trying next port...");
                next;
            }
            
            # Port is free and not in use
            if (@tried_ports) {
                osh_info("Successfully allocated port $port after finding "
                       . scalar(@tried_ports) . " port(s) in use: " 
                       . join(", ", @tried_ports));
            }
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

# generate an sshd portforwarding configuration for a given account
# this function MUST be called while holding the portforwarding lock to prevent any race conditions.
sub generate_account_sshd_forwarding_config {
    my %params  = @_;
    my $account = $params{'account'};

    my $fnret = OVH::Bastion::get_acls(account => $account, sudo => 1);
    $fnret or return $fnret;

    if (not @{$fnret->value}) {
        osh_ok R('OK_EMPTY', msg => "$account has no accesses, no port forwarding config to generate");
    }

    my @allowed_ports;
    my $acls = $fnret->value;
    foreach my $contextAcl (@$acls) {
        foreach my $entry (@{$contextAcl->{'acl'}}) {
            # skip if not a portforwarding entry
            if ($entry->{'user'} ne '!portforward') {
                next;
            }

            # should never happen
            if (!defined $entry->{'localPort'}) {
                osh_debug("user: "
                      . ($entry->{'user'} // '<undef>') . " ip: "
                      . ($entry->{'ip'}   // '<undef>')
                      . " port: "
                      . ($entry->{'port'} // '<undef>')
                      . " remotePort: "
                      . ($entry->{'remotePort'} // '<undef>')
                      . " localPort: "
                      . ($entry->{'localPort'} // '<undef>'));
                return R('ERR_INTERNAL_ERROR',
                    msg => "Found portforwarding entry without localPort for account $account");
            }

            push @allowed_ports, $entry->{'localPort'};
        }
    }

    osh_debug("Found " . scalar(@allowed_ports) . " allowed local ports for account $account");

    # Now write the sshd config file
    $fnret = _write_sshd_forwarding_config(account => $account, ports => \@allowed_ports);
    return $fnret;
}

# Write the sshd forwarding configuration file for an account
sub _write_sshd_forwarding_config {
    my %params  = @_;
    my $account = $params{'account'};
    my $ports   = $params{'ports'};     # Array ref of local port numbers

    # Validate and untaint the account name
    my $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $account);
    $fnret or return $fnret;
    $account = $fnret->value->{'account'};    # untainted

    my $config_dir  = "/etc/ssh/sshd_config.forward.d";
    my $config_file = "$config_dir/$account.conf";

    # Ensure the directory exists
    if (!-d $config_dir) {
        if (!mkdir($config_dir, 0755)) {
            return R('ERR_DIRECTORY_NOT_WRITABLE', msg => "Failed to create directory $config_dir: $!");
        }
    }

    # If no ports, remove the config file
    if (!$ports || !@$ports) {
        if (-e $config_file) {
            if (!unlink($config_file)) {
                return R('ERR_UNLINK_FAILED', msg => "Failed to remove config file $config_file: $!");
            }
            osh_debug("Removed empty config file $config_file");
        }
        return R('OK', msg => "No port forwarding entries, config file removed");
    }

    # Build the list of PermitOpen entries
    my @permit_opens;
    foreach my $localPort (@$ports) {
        push @permit_opens, "localhost:$localPort";
    }

    # Generate the config content
    my $config_content = "# This file is automatically generated by The Bastion\n";
    $config_content .= "# DO NOT EDIT MANUALLY\n";
    $config_content .= "# Generated at: " . localtime() . "\n\n";
    $config_content .= "Match User $account\n";
    $config_content .= "    AllowTcpForwarding local\n";
    $config_content .= "    GatewayPorts no\n";

    if (@permit_opens) {
        $config_content .= "    PermitOpen " . join(" ", @permit_opens) . "\n";
    }

    # Write the config file
    my $fh;
    if (!open($fh, '>', $config_file)) {
        return R('ERR_CANNOT_OPEN_FILE', msg => "Failed to open config file $config_file for writing: $!");
    }

    print $fh $config_content;
    close($fh);
    chmod 0644, $config_file;

    osh_debug("Wrote sshd forwarding config to $config_file with " . scalar(@permit_opens) . " PermitOpen entries");
    return R('OK', msg => "Successfully wrote sshd forwarding config for $account");
}

1;
