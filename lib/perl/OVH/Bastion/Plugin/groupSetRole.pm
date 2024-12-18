package OVH::Bastion::Plugin::groupSetRole;

# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

use File::Basename;
use lib dirname(__FILE__) . '/../../../../../lib/perl';
use OVH::Result;
use OVH::Bastion;

# Called by the helper osh-groupSetRole, and also by act() below.
sub preconditions {
    my %params = @_;
    # common params:
    my ($self, $account, $group, $action, $type, $sudo, $silentoverride) =
      @params{qw{ self   account   group   action   type   sudo   silentoverride }};
    # params only used for adding/removing guest accesses:
    my ($user, $port, $host, $ttl) = @params{qw{ user port host ttl }};
    my $fnret;

    if (!$self || !$account || !$group || !$type || !$action) {
        return R('ERR_MISSING_PARAMETER',
            msg => "Missing argument self[$self], account[$account], group[$group], type[$type] or action[$action]");
    }

    if (!grep { $action eq $_ } qw{ add del }) {
        return R('ERR_INVALID_PARAMETER', msg => "Action should be add or del");
    }

    # a regex is overkill here but we need it for untaint
    if ($type !~ /^(owner|gatekeeper|aclkeeper|member|guest)$/) {    ## no critic (ProhibitFixedStringMatches)
        return R('ERR_INVALID_PARAMETER', msg => "Type should be either owner, gatekeeper, aclkeeper, member or guest");
    }

    # untaint it:
    $type = $1;                                                      ## no critic (ProhibitCaptureWithoutTest)

    if ($type eq 'guest' && !$sudo) {
        # Guest access require a host, user and port might be undef to say 'any', and a ttl can be provided too.
        # In sudo mode, these are not used, because the osh-groupSetRole helper that calls us doesn't handle the guest
        # access add by itself, the act() func of this package, directly called by the group(Del|Add)GuestAccess plugin, does.

        if (not $host) {
            return R('ERR_MISSING_PARAMETER', msg => "Missing argument host for type guest");
        }
        if ($port) {
            $fnret = OVH::Bastion::is_valid_port(port => $port);
            $fnret or return $fnret;
        }
        if ($user) {
            $fnret = OVH::Bastion::is_valid_remote_user(user => $user, allowWildcards => 1);
            $fnret or return $fnret;
        }

        if ($action eq 'add') {
            # policy check for guest accesses: if group forces ttl, the account creation must comply
            $fnret = OVH::Bastion::group_config(group => $group, key => "guest_ttl_limit");

            # if this config key is not set, no policy enforce has been requested, otherwise, check it:
            if ($fnret) {
                my $max = $fnret->value();
                if (!$ttl) {
                    return R('ERR_INVALID_PARAMETER',
                            msg => "This group requires guest accesses to have a TTL set, to a duration of "
                          . OVH::Bastion::duration2human(seconds => $max)->value->{'duration'}
                          . " or less");
                }
                if ($ttl > $max) {
                    return R('ERR_INVALID_PARAMETER',
                        msg => "The TTL you specified is invalid, this group requires guest accesses to have a TTL of "
                          . OVH::Bastion::duration2human(seconds => $max)->value->{'duration'}
                          . " maximum");
                }
            }
        }
    }

    $fnret = OVH::Bastion::is_valid_group_and_existing(group => $group, groupType => "key");
    $fnret or return $fnret;

    # get returned untainted value
    $group = $fnret->value->{'group'};
    my $shortGroup = $fnret->value->{'shortGroup'};

    $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $account);
    $fnret or return $fnret;

    # get returned untainted value
    $account = $fnret->value->{'account'};
    my $realm         = $fnret->value->{'realm'};
    my $remoteaccount = $fnret->value->{'remoteaccount'};
    my $sysaccount    = $fnret->value->{'sysaccount'};

    if ($self eq 'root' && $< == 0) {
        osh_debug("called by root, allowing anyway");
    }
    else {
        my $neededright = 'unknown';
        if (grep { $type eq $_ } qw{ owner gatekeeper aclkeeper }) {
            $neededright = "owner";
            $fnret =
              OVH::Bastion::is_group_owner(account => $self, group => $shortGroup, superowner => 1, sudo => $sudo);
            if (!$fnret) {
                osh_debug("user $self not an owner of $shortGroup");
                return R('ERR_NOT_GROUP_OWNER',
                    msg => "Sorry, you're not an owner of group $shortGroup, which is needed to change its $type list");
            }

            # if account is from a realm, he can't be owner/gk/aclk
            if (defined $realm) {
                return R('ERR_REALM_USER', msg => "Sorry, $account is from another realm, this account can't be $type");
            }
        }
        elsif (grep { $type eq $_ } qw{ member guest }) {
            $neededright = "gatekeeper";
            $fnret =
              OVH::Bastion::is_group_gatekeeper(account => $self, group => $shortGroup, superowner => 1, sudo => $sudo);
            if (!$fnret) {
                osh_debug("user $self not a gk of $shortGroup");
                return R('ERR_NOT_GROUP_GATEKEEPER',
                    msg =>
                      "Sorry, you're not a gatekeeper of group $shortGroup, which is needed to change its $type list");
            }
        }
        else {
            return R('ERR_INTERNAL', msg => "Unknown type $type");
        }

        if ($fnret->value() and $fnret->value()->{'superowner'} and not $silentoverride) {
            osh_warn "SUPER OWNER OVERRIDE: You're not a $neededright of the group $shortGroup,";
            osh_warn "but allowing because you're a superowner. This has been logged.";

            OVH::Bastion::syslogFormatted(
                criticity => 'info',
                type      => 'security',
                fields    => [
                    ['type',    'superowner-override'],
                    ['account', $params{'self'}],
                    ['plugin',  $params{'scriptName'}],
                    ['params',  $params{'savedArgs'}],
                ]
            );
        }
    }

    return R(
        'OK',
        value => {
            group         => $group,
            shortGroup    => $shortGroup,
            account       => $account,
            type          => $type,
            realm         => $realm,
            remoteaccount => $remoteaccount,
            sysaccount    => $sysaccount
        }
    );
}

# We handle the proper helper calls (osh-groupSetRole, osh-groupAddSymlinkToAccount, osh-accountAddGroupServer) to modify the roles as asked.
# Called by all the plugins that modify account roles on groups, and also by the groupCreate helper.
# This sub also calls itself in the case of group member add,
# if the account had guest group accesses before, so as to remove them.
sub act {
    my %params = @_;
    my $fnret  = preconditions(%params);
    $fnret or return $fnret;

    # get returned untainted value
    my %values = %{$fnret->value()};
    my ($group, $shortGroup, $account, $type, $realm, $remoteaccount, $sysaccount) =
      @values{qw{ group shortGroup account type realm remoteaccount sysaccount }};
    my ($action, $self, $user, $host, $port, $ttl, $comment) = @params{qw{ action self user host port ttl comment }};

    my @command;

    osh_debug(
        "groupSetRole::act, $action $type $group/$account ($sysaccount/$realm/$remoteaccount) $user\@$host:$port ttl=$ttl"
    );

    # add/del system user to system group except if we're removing a guest access (will be done after if needed)
    if (!($type eq 'guest' and $action eq 'del')) {
        @command = qw{ sudo -n -u root -- /usr/bin/env perl -T };
        push @command, $OVH::Bastion::BASEPATH . '/bin/helper/osh-groupSetRole';
        push @command, '--type', $type;
        push @command, '--group', $group;
        push @command, '--account', $account, '--action', $action;
        $fnret = OVH::Bastion::helper(cmd => \@command);
        $fnret or return $fnret;
    }

    if ($type eq 'member') {

        if ($action eq 'add'
            && OVH::Bastion::is_group_guest(group => $shortGroup, account => $account, sudo => $params{'sudo'}))
        {

            # if the user is a guest, must remove all their guest accesses first
            $fnret = OVH::Bastion::get_acl_way(way => 'groupguest', group => $shortGroup, account => $account);
            if ($fnret && $fnret->value && @{$fnret->value}) {
                osh_warn("This account was previously a guest of this group, with the following accesses:");
                my @acl = @{$fnret->value};
                OVH::Bastion::print_acls(acls => [{type => 'group-guest', group => $shortGroup, acl => \@acl}]);

                osh_info("\nCleaning these guest accesses before granting membership...");

                # foreach guest access, delete
                foreach my $access (@acl) {
                    my $machine = OVH::Bastion::machine_display(
                        ip   => $access->{'ip'},
                        port => $access->{'port'},
                        user => $access->{'user'}
                    )->value;
                    $fnret = OVH::Bastion::Plugin::groupSetRole::act(
                        account => $account,
                        group   => $shortGroup,
                        action  => 'del',
                        type    => 'guest',
                        user    => $access->{'user'},
                        port    => $access->{'port'},
                        host    => $access->{'ip'},
                        self    => $self,
                    );
                    if (!$fnret) {
                        osh_warn("Failed removing guest access to $machine, proceeding anyway...");
                        warn_syslog(
                            "Failed removing guest access to $machine in group $shortGroup for $account, before granting this account full membership on behalf of $self: "
                              . $fnret->msg);
                    }
                }
            }
        }

        # then, for add and del, we need to handle the symlink
        @command = qw{ sudo -n -u allowkeeper -- /usr/bin/env perl -T };
        push @command, $OVH::Bastion::BASEPATH . '/bin/helper/osh-groupAddSymlinkToAccount';
        push @command, '--group', $group;    # must be first params, forced in sudoers.d
        push @command, '--account', $account;
        push @command, '--action',  $action;
        $fnret = OVH::Bastion::helper(cmd => \@command);
        $fnret or return $fnret;

        if ($fnret->err eq 'OK_NO_CHANGE') {

            # make the error msg user friendly
            $fnret->{'msg'} =
                "Account $account was already "
              . ($action eq 'del' ? 'not ' : '')
              . "a member of $shortGroup, nothing to do";
        }
    }
    elsif ($type eq 'guest') {

        # in that case, we need to handle the add/del of the guest access to $user@$host:$port
        # check if group has access to $user@$ip:$port
        my $machine = OVH::Bastion::machine_display(ip => $host, port => $port, user => $user)->value;
        osh_debug(
            "groupSetRole::act, checking if group $group has access to $machine to $action $type access to $account");

        if ($action eq 'add') {

            $fnret = OVH::Bastion::is_access_way_granted(
                way   => 'group',
                group => $shortGroup,
                user  => $user,
                port  => $port,
                ip    => $host,
            );
            if (not $fnret) {
                osh_debug("groupSetRole::act, it doesn't! $fnret");
                return R('ERR_GROUP_HAS_NO_ACCESS',
                    msg =>
                      "The group $shortGroup doesn't have access to $machine, so you can't add a guest group access "
                      . "to it (first add it to the group if applicable, with groupAddServer)");
            }

            # if no comment was specified for this guest access, reuse the one from the matching group ACL entry
            $comment ||= $fnret->value->{'comment'};
        }

        # If the account is already a member, can't add/del them as guest
        if (OVH::Bastion::is_group_member(group => $shortGroup, account => $account, sudo => $params{'sudo'})) {
            return R('ERR_MEMBER_CANNOT_BE_GUEST',
                msg => "Can't $action $account as a guest of group $shortGroup, they're already a member!");
        }

        # Add/Del user access to user@host:port with group key
        @command = qw{ sudo -n -u allowkeeper -- /usr/bin/env perl -T };
        push @command, $OVH::Bastion::BASEPATH . '/bin/helper/osh-accountAddGroupServer';
        push @command, '--group', $group;    # must be first params, forced in sudoers.d
        push @command, '--account', $account;
        push @command, '--action',  $action;
        push @command, '--ip',      $host;
        push @command, '--user',    $user if $user;
        push @command, '--port',    $port if $port;
        push @command, '--ttl',     $ttl if $ttl;
        push @command, '--comment', $comment if $comment;

        $fnret = OVH::Bastion::helper(cmd => \@command);
        $fnret or return $fnret;

        if ($fnret->err eq 'OK_NO_CHANGE') {
            if ($action eq 'add') {
                osh_info "Account $account already had access to $machine through $shortGroup";
            }
            else {
                osh_info "Account $account didn't have access to $machine through $shortGroup";
            }
        }
        else {
            if ($action eq 'add') {
                osh_info "Account $account has now access to the group key of $shortGroup, but does NOT";
                osh_info "automatically inherits access to any of the group's servers, only to $machine,";
                osh_info "and any other(s) $shortGroup group server(s) previously granted to $account.";
                osh_info "This access will expire in " . OVH::Bastion::duration2human(seconds => $ttl)->value->{'human'}
                  if $ttl;
            }
            else {
                osh_info "Access to $machine through group $shortGroup was removed from account $account";
            }
        }

        if ($action eq 'del') {

            # if the guest group access file of this account is now empty, we should remove the account from the group
            # but ONLY if the account doesn't have regular member access to the group too.
            my $accessesFound = 0;
            if (!$realm) {

                # in non-realm mode, just check the account itself
                $fnret = OVH::Bastion::get_acl_way(way => 'groupguest', group => $shortGroup, account => $account);
                $fnret or return $fnret;
                $accessesFound += @{$fnret->value};
            }
            else {
                # in realm-mode, we need to check that all the other remote accounts no longer have access either, before removing the key
                $fnret = OVH::Bastion::get_remote_accounts_from_realm(realm => $realm);
                $fnret or return $fnret;
                foreach my $pRemoteaccount (@{$fnret->value}) {
                    $fnret = OVH::Bastion::get_acl_way(
                        way     => 'groupguest',
                        group   => $shortGroup,
                        account => "$realm/$pRemoteaccount"
                    );
                    $accessesFound += @{$fnret->value};
                    last if $accessesFound > 0;
                }
            }

            if ($accessesFound == 0
                && !OVH::Bastion::is_group_member(group => $shortGroup, account => $account, sudo => $params{'sudo'}))
            {
                osh_debug
                  "No guest access remains to group $shortGroup for account $account, removing group key access";
                #
                # remove account from group
                #
                @command = qw{ sudo -n -u root -- /usr/bin/env perl -T };
                push @command, $OVH::Bastion::BASEPATH . '/bin/helper/osh-groupSetRole';
                push @command, '--type', 'guest';
                push @command, '--group', $group;
                push @command, '--account', $account;
                push @command, '--action', 'del';

                $fnret = OVH::Bastion::helper(cmd => \@command);
                $fnret or return $fnret;

                if (!$realm) {
                    osh_info
                      "No guest access to servers of group $shortGroup remained for account $account, removed group key access";
                }
                else {
                    osh_info
                      "No guest access to servers of group $shortGroup remained for realm $realm, removed group key access";
                }
            }
        }
        else {
            osh_info "\nYou can view ${account}'s guest accesses to $shortGroup with the following command:";
            my $bastionName = OVH::Bastion::config('bastionName')->value();
            osh_info "$bastionName --osh groupListGuestAccesses --account $account --group $shortGroup";
        }
    }

    # don't log on OK_NO_CHANGE, only on OK
    if ($fnret->err eq 'OK') {
        OVH::Bastion::syslogFormatted(
            severity => 'info',
            type     => 'membership',
            fields   => [
                ['action',  $action],
                ['type',    $type],
                ['group',   $shortGroup],
                ['account', $account],
                ['self',    $self],
                ['user',    $user],
                ['host',    $host],
                ['port',    $port],
                ['ttl',     $ttl],
                ['comment', $comment || ''],
            ]
        );
    }

    return $fnret;
}

1;
