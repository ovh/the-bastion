# vim: set filetype=perl ts=4 sw=4 sts=4 et:
package OVH::Bastion;

use common::sense;

use File::Basename;
use lib dirname(__FILE__) . '/../../../../lib/perl';
use OVH::Bastion::Plugin::otherProtocol;

use Time::Piece;    # $t->strftime
use POSIX qw(strftime);

# Here lies the code that manages the portforwarding capabilities of The Bastion.
#
# Instead of just granting access to a target, you can now also grant access to a specific remote port on that target.
# For every remote port, we will allocate a unique local port from a configured port range.
# We then generate a sshd config for every user containing a list of PermitOpen entries for every available portforwarding rule.
# This ensures that we not only control the forwarding from the bastion to the target, but also who can access which local port on the bastion itself.
#
# In practise, a portforwarding will then look like this:
# $ ssh bastion -l myuser -L 8080:localhost:20000 -- 192.168.1.10 -L 20000:127.0.0.1:80
#
# This will forward port 80 from the target to local port 20000 on the bastion,
# and port 20000 on the bastion to local port 8080 on the user's machine.
#
# The approach isn't perfect, but I found no better way to manage this with all the quirks of sshd if it comes to port forwarding.
# Also, this feature could be abused to bypass The Bastion by forwarding the ssh port back to the users machine.
# If you are not willing to accept this risk, you should not enable portforwarding at all.
#
# The following limitations apply:
#    - there is a limited amount of available forwards, since the local port range is limited.
#      So this feature might not be what you need if you require a large amount of remote port accesses.
#    - port forwarding only works on a bastion master
#    - when performing a HA failover, an additional step to handle the sshd config is required
#    - If the debug option is enabled in the config, a user could potentially read ACLs of other users and groups.
#      This is caused by the fact that finding a new local ports requires reading all existing ACLs to find already allocated ports.

# Check if a port is in use by any process on the system
sub _is_port_in_use {
    my %params = @_;
    my $port   = $params{'port'};

    # try ss first
    my $fnret = OVH::Bastion::execute(cmd => ['ss', '-ln'], noisy_stderr => 0);
    if ($fnret && $fnret->value->{'sysret'} == 0 && $fnret->value->{'output'} =~ /:$port /) {
        return 1;
    }
    if ($fnret && $fnret->value->{'sysret'} == 0) {
        return 0;
    }

    # fallback to netstat if ss failed for some reason
    $fnret = OVH::Bastion::execute(cmd => ['netstat', '-ln'], noisy_stderr => 0);
    if ($fnret && $fnret->value->{'sysret'} == 0 && $fnret->value->{'output'} =~ /:$port /) {
        return 1;
    }
    if ($fnret && $fnret->value->{'sysret'} == 0) {
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
    my $fnret = _get_allocated_local_ports();
    $fnret or return $fnret;
    my %allocated_ports = keys %{$fnret->value};

    # Get the port range configuration
    $fnret = _get_local_port_range();
    $fnret or return $fnret;
    my $port_range = $fnret->value;
    my $min_port   = $port_range->{'min'};
    my $max_port   = $port_range->{'max'};

    $fnret = _get_unavailable_ports();
    $fnret or return $fnret;
    my %unavailable_ports = %{$fnret->value};

    my @available_ports;
    for my $port ($min_port .. $max_port) {
        if (!exists $allocated_ports{$port} && !exists $unavailable_ports{$port}) {
            push @available_ports, $port;
        }
    }

    if (!@available_ports) {
        return R('ERR_NO_FREE_PORTS',
            msg => "No free local ports available in range $min_port-$max_port. "
              . "Please contact your bastion administrator ASAP!");
    }

    # Shuffle available ports to randomly select one
    my @shuffled_ports = sort { rand() <=> rand() } @available_ports;

    my @tried_ports;
    for my $port (@shuffled_ports) {
        # Check if the port is actually in use by another process
        if (_is_port_in_use(port => $port)) {
            push @tried_ports, $port;
            osh_warn("Port $port is in use by another process, trying next port...");
            next;
        }

        # Port is free and not in use
        if (@tried_ports) {
            osh_info("Successfully allocated port $port after finding "
                  . scalar(@tried_ports)
                  . " port(s) in use: "
                  . join(", ", @tried_ports));
        }
        return R('OK', value => {localPort => $port});
    }

    return R('ERR_NO_FREE_PORTS',
        msg => "No free local ports available in range $min_port-$max_port. "
          . "Please contact your bastion administrator ASAP!");
}

# Validate if a remote port is valid and port count is within allowed limits
sub is_valid_portforwarding {
    my %params     = @_;
    my $action     = $params{'action'};       # add or del
    my $way        = $params{'way'};          # personal, group
    my $account    = $params{'account'};
    my $group      = $params{'group'};
    my $remotePort = $params{'remotePort'};

    my $fnret = OVH::Bastion::is_valid_port(port => $remotePort);
    $fnret or osh_exit $fnret;
    $remotePort = $fnret->value;

    if ($action eq 'del') {
        return R('OK', value => {remotePort => $remotePort});
    }

    $fnret = _get_allocated_local_ports();
    $fnret or return $fnret;
    my $allocatedPorts = $fnret->value;

    $fnret = OVH::Bastion::load_configuration();
    $fnret or return $fnret;
    my $config = $fnret->value;

    my $groupMaxForwards   = $config->{'portForwardingMaxPerGroup'};
    my $accountMaxForwards = $config->{'portForwardingMaxPerUser'};

    if ($way eq 'personal') {
        my $count = 0;
        foreach my $port_info (values %{$allocatedPorts}) {
            if ($port_info->{'way'} eq 'personal' && $port_info->{'account'} eq $account) {
                $count++;
            }
        }
        if ($count >= $accountMaxForwards) {
            return R('ERR_PORTFORWARDING_LIMIT_EXCEEDED',
                msg =>
                  "Account $account has reached the maximum number of allowed port forwardings ($accountMaxForwards)");
        }
        osh_debug("Account $account has $count/$accountMaxForwards port forwardings");
    }
    elsif ($way eq 'group') {
        my $count = 0;
        foreach my $port_info (values %{$allocatedPorts}) {
            if ($port_info->{'way'} eq 'group' && $port_info->{'group'} eq $group) {
                $count++;
            }
        }
        if ($count >= $groupMaxForwards) {
            return R('ERR_PORTFORWARDING_LIMIT_EXCEEDED',
                msg => "Group $group has reached the maximum number of allowed port forwardings ($groupMaxForwards)");
        }
        osh_debug("Group $group has $count/$groupMaxForwards port forwardings");
    }
    elsif ($way eq 'groupguest') {
        return R('OK', value => {remotePort => $remotePort});
    }
    else {
        return R('ERR_INVALID_PARAMETER', msg => "Invalid way parameter: $way");
    }

    return R('OK', value => {remotePort => $remotePort});
}

# Get all allocated local ports from all groups and accounts
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
                $allocated_local_ports{$entry->{'localPort'}} = {way => 'group', group => $group};
            }
        }
    }

    foreach my $account (keys %$accounts) {
        my $grantedPersonal = OVH::Bastion::get_acl_way(way => 'personal', account => $account);
        next if not $grantedPersonal;
        foreach my $entry (@{$grantedPersonal->value || []}) {
            if (defined $entry->{'localPort'}) {
                $allocated_local_ports{$entry->{'localPort'}} = {way => 'personal', account => $account};
            }
        }
    }

    osh_debug("Allocated local ports: " . join(", ", keys %allocated_local_ports));
    return R('OK', value => \%allocated_local_ports);
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
    my %params           = @_;
    my $account          = $params{'account'};
    my $deletedLocalPort = $params{'deletedLocalPort'};    # optional: local port that was just deleted

    my $fnret = OVH::Bastion::get_acls(account => $account, sudo => 1);
    $fnret or return $fnret;

    if (not @{$fnret->value}) {
        return R('OK_EMPTY', msg => "$account has no accesses, no port forwarding config to generate");
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
    $fnret = _write_sshd_forwarding_config(
        account          => $account,
        ports            => \@allowed_ports,
        deletedLocalPort => $deletedLocalPort
    );
    $fnret or return $fnret;

    # reload sshd to apply changes
    $fnret = _test_and_reload_sshd();
    $fnret or return $fnret;

    $fnret = cleanup_unavailable_ports();
    if ($fnret && $fnret->value->{'cleaned'} > 0) {
        osh_debug("Cleaned up " . $fnret->value->{'cleaned'} . " unavailable ports");
    }

    if (defined $deletedLocalPort) {
        $fnret = mark_port_unavailable(port => $deletedLocalPort);
        $fnret or return $fnret;
    }

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

            $fnret = _test_and_reload_sshd();
            $fnret or return $fnret;
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

# Test sshd configuration and reload the sshd daemon
sub _test_and_reload_sshd {
    osh_debug("Testing sshd configuration...");
    my $fnret = OVH::Bastion::execute(cmd => ['sshd', '-t'], noisy_stderr => 1);

    if (!$fnret || $fnret->value->{'sysret'} != 0) {
        osh_warn("sshd configuration test failed!");
        return R('ERR_SSHD_CONFIG_TEST_FAILED',
                msg => "sshd configuration test failed with exit code "
              . ($fnret ? $fnret->value->{'sysret'} : 'unknown')
              . ". Output: "
              . ($fnret ? $fnret->value->{'output'} : 'unknown') . "\n"
              . "Tell your administrator about this ASAP!");
    }

    osh_debug("sshd configuration test passed");

    $fnret = OVH::Bastion::load_configuration();
    $fnret or main_exit(OVH::Bastion::EXIT_CONFIGURATION_FAILURE, "configuration_failure", $fnret->msg);
    my $config     = $fnret->value;
    my $reload_cmd = $config->{'sshdReloadCommand'};

    # Split the command into executable and arguments
    my @cmd_parts = split(/\s+/, $reload_cmd);

    osh_debug("Reloading sshd with command: $reload_cmd");
    $fnret = OVH::Bastion::execute(cmd => \@cmd_parts, noisy_stderr => 1);

    if (!$fnret || $fnret->value->{'sysret'} != 0) {
        osh_warn("Failed to reload sshd!");
        return R('ERR_SSHD_RELOAD_FAILED',
                msg => "Failed to reload sshd with exit code "
              . ($fnret ? $fnret->value->{'sysret'} : 'unknown')
              . ". Output: "
              . ($fnret ? $fnret->value->{'output'} : 'unknown') . "\n"
              . "Tell your administrator about this ASAP!");
    }

    osh_debug("sshd reloaded successfully");
    return R('OK', msg => "sshd configuration tested and daemon reloaded successfully");
}

# With have this unfortunate situation, where a user could accidentally get access to an unallowed portforward.
# Lets say userA has access to the local port 20000 and has an open ssh session using the -N flag. Sshd will allow forwarding to this port.
# If that access gets removed and the session is still open, the access to the port 20000 remains, because an sshd reload doesnt affect existing sessions.
# If another portforwarding is added, and the random function has a bad day (or the local port pool is running out), the port 20000 could be reused.
# This would allow userA to use his existing session to access whatever userB is now forwarding from a different remote target to port 20000.
# To avoid this, we temporarily mark ports as unavailable when they are removed from an account/group.
# The port remains unavailable until there are no ssh sessions that started before the port was marked unavailable

sub _unavailable_ports_file_modify {
    my %params = @_;
    my $action = $params{'action'};    # 'read', 'write', 'delete'
    my $ports  = $params{'ports'};     # ports mapped to timestamp

    my $file = "/home/allowkeeper/.portforwarding_unavailable_ports";

    if ($action eq 'read') {
        my %unavailable;
        if (-e $file) {
            if (open(my $fh, '<', $file)) {
                while (my $line = <$fh>) {
                    chomp $line;
                    if ($line =~ /^(\d+):(\d+)$/) {
                        $unavailable{$1} = $2;
                    }
                }
                close($fh);
            }
        }
        return R('OK', value => \%unavailable);
    }
    elsif ($action eq 'write') {
        if (!$ports || ref($ports) ne 'HASH') {
            return R('ERR_MISSING_PARAMETER', msg => "ports parameter is required for write action");
        }

        my $temp_file = "$file.tmp.$$";
        if (!open(my $fh, '>', $temp_file)) {
            return R('ERR_CANNOT_OPEN_FILE', msg => "Failed to open temp file for unavailable ports: $!");
        }
        else {
            foreach my $p (sort { $a <=> $b } keys %$ports) {
                print $fh "$p:$ports->{$p}\n";
            }
            close($fh);
        }

        if (!rename($temp_file, $file)) {
            unlink($temp_file);
            return R('ERR_RENAME_FAILED', msg => "Failed to update unavailable ports file: $!");
        }

        chmod 0644, $file;
        return R('OK');
    }
    elsif ($action eq 'delete') {
        if (-e $file) {
            if (!unlink($file)) {
                return R('ERR_UNLINK_FAILED', msg => "Failed to remove unavailable ports file: $!");
            }
        }
        return R('OK');
    }
    else {
        return R('ERR_INVALID_PARAMETER', msg => "Invalid action: $action");
    }
}

# This function MUST be called while holding the portforwarding lock.
sub mark_port_unavailable {
    my %params = @_;
    my $port   = $params{'port'};

    if (!$port) {
        return R('ERR_MISSING_PARAMETER', msg => "Port parameter is required");
    }

    # use current time as timestamp when sshd was reloaded. This is safe, since we call this after doing the actual reload.
    my $timestamp = time();

    # Read current unavailable ports
    my $fnret = _unavailable_ports_file_modify(action => 'read');
    $fnret or return $fnret;
    my %unavailable = %{$fnret->value};

    # Add the new port with timestamp
    $unavailable{$port} = $timestamp;

    # Write back
    $fnret = _unavailable_ports_file_modify(action => 'write', ports => \%unavailable);
    $fnret or return $fnret;

    osh_debug("Marked port $port as unavailable at timestamp $timestamp");
    return R('OK', value => {port => $port, timestamp => $timestamp});
}

# Get list of temporarily unavailable ports
sub _get_unavailable_ports {
    return _unavailable_ports_file_modify(action => 'read');
}

# Check if there are any SSH sessions that started before a given timestamp
sub _has_sessions_before_timestamp {
    my %params    = @_;
    my $timestamp = $params{'timestamp'};

    # We'll use 'who -u' which shows the PID and login time from active sessions.
    # Unfortunately, the timestamp from 'who' is not very precise, so we will check 'ps' for the session start time
    my $fnret = OVH::Bastion::execute(cmd => ['who', '-u'], must_succeed => 1, noisy_stdout => 0, noisy_stderr => 0);
    if (!$fnret || $fnret->value->{'sysret'} != 0) {
        osh_warn("Failed to run 'who -u' command, assuming old sessions exist for safety");
        return R('OK', value => 1);
    }
    my $output = $fnret->value->{'stdout'};

    osh_debug("Output of 'who -u': " . scalar(@$output) . " lines");
    osh_debug("Checking for sessions started before timestamp $timestamp");

    foreach my $line (@$output) {
        # Skip empty lines
        next if !defined $line || $line !~ /\S/;

        osh_debug("Processing line from 'who -u': $line");
        # Parse 'who -u' output to get PID
        # Format: user pts/0 2024-11-18 10:30 old 12345 (192.168.1.1)
        my $pid;
        if ($line !~ /\s+(\d+)\s+\(/) {
            osh_debug("Skipping unparseable line from 'who -u': $line");
            next;
        }
        else {
            $pid = $1;
            osh_debug("Checking session with PID $pid");
        }

        $fnret = OVH::Bastion::execute_simple(
            cmd          => ['ps', '-o', 'lstart=', '-D', '%s', '-p', $pid],
            must_succeed => 1
        );
        $fnret or return $fnret;

        if ($fnret && $fnret->value->{'sysret'} == 0) {
            my $lstart = $fnret->value->{'output'};
            chomp $lstart;
            $lstart =~ s/^\s+|\s+$//g;    # Trim whitespace

            # Parse the timestamp (Unix epoch format from ps -D %s)
            my $session_time;
            if ($lstart =~ /^(\d+)$/) {
                $session_time = $1;
            }
            else {
                # If we can't parse it, we assume something went wrong and abort
                osh_debug("Could not parse session time for PID $pid: $lstart");
                return R('OK', value => 1);
            }

            if ($session_time < $timestamp) {
                osh_debug("Found session (PID $pid) started before timestamp $timestamp at $session_time");
                return R('OK', value => 1);
            }
        }
    }

    # No old sessions found
    return R('OK', value => 0);
}

# cleanup ports that are safe to use again
# This function MUST be called while holding the portforwarding lock
sub cleanup_unavailable_ports {
    my %params = @_;

    my $fnret = _get_unavailable_ports();
    $fnret or return $fnret;
    my %unavailable = %{$fnret->value};

    if (!%unavailable) {
        osh_debug("No unavailable ports to clean up");
        return R('OK', value => {cleaned => 0});
    }

    my @to_remove;
    my $oldest_timestamp = time();    # find the oldest timestamp

    foreach my $port (keys %unavailable) {
        my $timestamp = $unavailable{$port};
        if ($timestamp < $oldest_timestamp) {
            $oldest_timestamp = $timestamp;
        }
    }

    # Check if there are any sessions older than the oldest unavailable port timestamp
    $fnret = _has_sessions_before_timestamp(timestamp => $oldest_timestamp);
    $fnret or return $fnret;
    if (!$fnret->value) {
        # No old sessions, we can clear all unavailable ports
        @to_remove = keys %unavailable;
        osh_debug("No sessions before timestamp $oldest_timestamp, clearing all unavailable ports");
    }
    else {
        osh_debug("Still have sessions before timestamp $oldest_timestamp, keeping ports unavailable");
        return R('OK', value => {cleaned => 0});
    }

    if (@to_remove) {
        foreach my $port (@to_remove) {
            delete $unavailable{$port};
        }

        if (!%unavailable) {
            # All ports cleaned up, delete the file
            $fnret = _unavailable_ports_file_modify(action => 'delete');
            $fnret or return $fnret;
            osh_debug("Removed " . scalar(@to_remove) . " ports from unavailable list, file removed");
        }
        else {
            # Some ports remain, write back the updated list
            $fnret = _unavailable_ports_file_modify(action => 'write', ports => \%unavailable);
            $fnret or return $fnret;
            osh_debug("Removed " . scalar(@to_remove) . " ports from unavailable list");
        }

        return R('OK', value => {cleaned => scalar(@to_remove), ports => \@to_remove});
    }

    return R('OK', value => {cleaned => 0});
}

1;
