package OVH::Bastion;

# vim: set filetype=perl ts=4 sw=4 sts=4 et:

use common::sense;

use Time::Piece;    # $t->strftime

# Check if user belongs to a specific group
sub is_user_in_group {
    my %params = @_;
    my $group  = $params{'group'};
    my $user   = $params{'user'} || OVH::Bastion::get_user_from_env()->value;

    # mandatory keys
    if (!$user or !$group) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing parameter 'user' or 'group'");
    }

    # get group info
    my ($groupname, $passwd, $gid, $members) = getgrnam($group);
    my @membersList = split / /, $members;

    if (grep { $user eq $_ } @membersList) {
        return R('OK', value => {account => $user});
    }
    return R('KO_NOT_IN_GROUP', msg => "Account $user doesn't belong to the group $group");
}

# does this group exist ?
sub is_group_existing {
    my %params = @_;
    my $group  = $params{'group'};

    if (!$group) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing parameter 'group'");
    }

    my ($groupname, $password, $gid, $members) = getgrnam($group);
    if ($groupname) {
        my (undef, $shortGroup) = $group =~ m{^(key)?(.+)};
        return R('OK', value => {group => $group, shortGroup => $shortGroup, gid => $gid, members => [split(/ /, $members)]});
    }
    return R('KO_GROUP_NOT_FOUND', msg => "Group '$group' doesn't exist");
}

# validate uid/gid
sub is_valid_uid {
    my %params = @_;
    my $uid    = $params{'uid'};
    my $type   = $params{'type'};

    # Basic input validation
    if ($uid !~ m/^\d+$/) {
        return R('ERR_INVALID_PARAMETER', msg => "Parameter 'uid' should be numeric");
    }

    if ($type ne 'user' and $type ne 'group') {
        return R('ERR_INVALID_PARAMETER', msg => "Parameter 'type' is invalid");
    }

    # Input validation against configuration
    my $fnret = OVH::Bastion::load_configuration();
    $fnret or return $fnret;

    my ($accountUidMin, $accountUidMax, $ttyrecGroupIdOffset) =
      @{$fnret->value}{qw{ accountUidMin accountUidMax ttyrecGroupIdOffset }};

    if (not $accountUidMin or not $accountUidMax or not $ttyrecGroupIdOffset) {
        return R('ERR_CANNOT_LOAD_CONFIGURATION');
    }

    my ($low, $high) = ($accountUidMin, $accountUidMax);

    if ($type eq 'group') {
        $high += $ttyrecGroupIdOffset;
    }

    if ($uid < $low or $uid > $high) {
        return R('KO_BAD_RANGE', msg => "Parameter 'uid' should be between $low and $high");
    }

    $uid =~ m/^(\d+)$/;    # Untaint

    return R('OK', value => $1);
}

sub get_next_available_uid {
    my %params = @_;

    my $higher = OVH::Bastion::config('accountUidMax')->value();
    my $lower  = OVH::Bastion::config('accountUidMin')->value();
    my $next   = $higher;
    while ($next >= $lower) {
        last if not scalar(getpwuid($next));
        $next--;
    }
    return R('OK', value => $next) if not scalar(getpwuid($next));
    return R('ERR_UID_COLLISION', msg => "No available UID in the allowed range");
}

sub is_bastion_account_valid_and_existing {
    my %params = @_;
    my $fnret  = OVH::Bastion::is_account_valid(%params);
    $fnret or return $fnret;
    my %values = %{$fnret->value()};
    my ($account, $realm, $sysaccount, $remoteaccount) = @values{qw{ account realm sysaccount remoteaccount}};
    $fnret = OVH::Bastion::is_account_existing(account => $sysaccount, checkBastionShell => 1);
    $fnret or return $fnret;
    $fnret->value->{'account'}       = $account;
    $fnret->value->{'sysaccount'}    = $sysaccount;
    $fnret->value->{'realm'}         = $realm;
    $fnret->value->{'remoteaccount'} = $remoteaccount;
    return $fnret;
}

# check if account name is valid, i.e. non-weird chars and non reserved parts
sub is_account_valid {
    my %params  = @_;
    my $account = $params{'account'};
    my $accountType =
      $params{'accountType'} || 'normal';    # normal (local account or $realm/$remoteself formatted account) | group (must start with key*) | realm (must start with realm_*)
    my $localOnly = $params{'localOnly'};    # for accountType == normal, disallow realm-formatted accounts ($realm/$remoteself)
    my $realmOnly = $params{'realmOnly'};    # for accountType == normal, allow only realm-formatted accounts ($realm/$remoteself)

    if (!$account) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing parameter 'account'");
    }

    my $whatis = ($accountType eq 'realm' ? "Realm" : "Account");

    if ($localOnly && $account =~ m{/}) {
        return R('KO_REALM_FORBIDDEN', msg => "$whatis name must not contain any '/'");
    }
    elsif ($realmOnly && $account !~ m{/}) {
        return R('KO_LOCAL_FORBIDDEN', msg => "$whatis name must contain a '/'");
    }
    elsif ($account =~ m/-tty$/i) {
        return R('KO_FORBIDDEN_SUFFIX', msg => "$whatis name contains an unauthorized suffix");
    }
    elsif ($account =~ m/^key/i && $accountType ne 'group') {
        return R('KO_FORBIDDEN_PREFIX', msg => "$whatis name contains an unauthorized key prefix");
    }
    elsif ($account !~ m/^key/i && $accountType eq 'group') {
        return R('KO_BAD_PREFIX', msg => "$whatis should start with the group prefix");
    }
    elsif ($account =~ m/^realm_/ && $accountType ne 'realm') {
        return R('KO_FORBIDDEN_PREFIX', msg => "$whatis name contains an unauthorized realm prefix");
    }
    elsif ($account !~ m/^realm_/ && $accountType eq 'realm') {
        return R('KO_BAD_PREFIX', msg => "$whatis should start with the realm prefix");
    }
    elsif (grep { $account eq $_ } qw{ root proxyhttp keykeeper passkeeper logkeeper realm realm_realm }) {
        return R('KO_FORBIDDEN_NAME', msg => "$whatis name is reserved");
    }
    elsif ($account =~ m{^([a-zA-Z0-9-]+)/([a-zA-Z0-9._-]+)$} && $accountType eq 'normal') {
        if (length("realm_$1") > 18) {
            return R('KO_TOO_LONG', msg => "$whatis name is too long, length(realm_$1) > 18");
        }
        elsif (length($1) < 2) {
            return R('KO_TOO_SMALL', msg => "$whatis name is too long, length($1) < 2");
        }
        elsif (length($2) > 18) {
            return R('KO_TOO_LONG', msg => "Remote account name is too long, length($2) > 18");
        }
        elsif (length($2) < 2) {
            return R('KO_TOO_SMALL', msg => "Remote account name is too short, length($2) < 2");
        }
        return R('OK', value => {sysaccount => "realm_$1", realm => $1, remoteaccount => $2, account => "$1/$2"});    # untainted
    }
    elsif ($account =~ m/^([a-zA-Z0-9._-]+)$/) {
        if (length($1) < 2) {
            return R('KO_TOO_SMALL', msg => "$whatis name is too small, length($1) < 2");
        }
        elsif (length($1) > 18) {
            return R('KO_TOO_LONG', msg => "$whatis name is too long, length($1) > 18");
        }
        return R('OK', value => {sysaccount => $1, realm => undef, remoteaccount => undef, account => $1});           # untainted
    }
    else {
        return R('KO_FORBIDDEN_CHARS', msg => "$whatis name contains forbidden characters $account");
    }
    return R('ERR_IMPOSSIBLE_CASE');
}

# check that this account is present on the bastion
# it also returns untainted data, including splitting by realm where applicable
sub is_account_existing {
    my %params            = @_;
    my $account           = $params{'account'};
    my $checkBastionShell = $params{'checkBastionShell'};    # check if this account is a bastion user

    if (!$account) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing parameter 'account'");
    }

    my ($name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir, $shell, $expire) = getpwnam($account);
    if (OVH::Bastion::is_mocking()) {
        ($name, $passwd, $uid, $gid, $gcos, $dir, $shell) = OVH::Bastion::mock_get_account_entry(account => $account);
    }
    if ($name) {
        my ($newname) = $name =~ m{([a-zA-Z0-9._-]+)};
        return R('ERR_SECURITY_VIOLATION', msg => "Forbidden characters in account name") if ($newname ne $name);
        $name = $newname;    # untaint

        if ($checkBastionShell && $shell ne $OVH::Bastion::BASEPATH . "/bin/shell/osh.pl") {
            return R('KO_NOT_FOUND', msg => "Account '$account' doesn't exist");    # msg is the same as below, voluntarily
        }

        my ($newdir) = $dir =~ m{([/a-zA-Z0-9._-]+)};                               # untaint
        return R('ERR_SECURITY_VIOLATION', msg => "Forbidden characters in account home directory") if ($newdir ne $dir);
        $dir = $newdir;                                                             # untaint
        return R('OK', value => {uid => $uid, gid => $gid, dir => $dir, account => $name});
    }
    return R('KO_NOT_FOUND', msg => "Account '$account' doesn't exist");
}

# all ACL modifications (on groups, on accounts, including group-guests) are handled here
sub access_modify {
    my %params = @_;

    my $action = $params{'action'};                                                 # add or del

    my $user = $params{'user'};                                                     # if undef, means a user-wildcard access
    my $ip   = $params{'ip'};                                                       # can be a single ip or prefix
    my $port = $params{'port'};                                                     # if undef, means a port-wildcard access

    my $ttl = $params{'ttl'};

    my $way     = $params{'way'};                                                   # group, groupguest, personal
    my $group   = $params{'group'};                                                 # only for way=group or way=groupguest
    my $account = $params{'account'};                                               # only for way=personal

    my $forceKey = $params{'forceKey'};
    my $comment  = $params{'comment'};

    my $fnret;

    foreach my $mandatoryParam (qw/action ip way/) {
        if (!$params{$mandatoryParam}) {
            return R('ERR_MISSING_PARAMETER', msg => "Missing parameter '$mandatoryParam'");
        }
    }

    # due to how plugins work, sometimes user and port are just '', make them undef in those cases
    undef $user if (defined $user && $user eq '');
    undef $port if (defined $port && $port eq '');

    # check way
    if ($way eq 'personal') {
        return R('ERR_INVALID_PARAMETER', msg => "Group parameter specified with way=personal")   if defined $group;
        return R('ERR_MISSING_PARAMETER', msg => "Account parameter mandatory with way=personal") if not defined $account;
    }
    elsif ($way eq 'group') {
        return R('ERR_MISSING_PARAMETER', msg => "Group parameter mandatory with way=group")   if not defined $group;
        return R('ERR_INVALID_PARAMETER', msg => "Account parameter specified with way=group") if defined $account;
    }
    elsif ($way eq 'groupguest') {
        if (not defined $account or not defined $group) {
            return R('ERR_MISSING_PARAMETER', msg => "Account or group parameter missing with way=groupguest");
        }
    }
    else {
        return R('ERR_INVALID_PARAMETER', msg => "Parameter 'way' must be either personal, group or groupguest");
    }

    if ($action ne 'add' and $action ne 'del') {
        return R('ERR_INVALID_PARAMETER', msg => "Action should be either 'del' or 'add'");
    }

    # check ip
    $fnret = OVH::Bastion::is_valid_ip(ip => $ip, allowPrefixes => 1);
    return $fnret unless $fnret;
    $ip = $fnret->value->{'ip'};

    # check port
    if (defined $port) {
        $fnret = OVH::Bastion::is_valid_port(port => $port);
        return $fnret unless $fnret;
        $port = $fnret->value;
    }

    # check remote user
    if (defined $user) {
        $fnret = OVH::Bastion::is_valid_remote_user(user => $user);
        return $fnret unless $fnret;
        $user = $fnret->value;
    }

    # check account
    my ($remoteaccount, $sysaccount);
    if (defined $account) {

        # accountType==normal : account must NOT be a realm_* account (but can be a realm/jdoe account)
        $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $account, accountType => 'normal');
        $fnret or return $fnret;
        $sysaccount    = $fnret->value->{'sysaccount'};
        $account       = $fnret->value->{'account'};
        $remoteaccount = $fnret->value->{'remoteaccount'};
    }

    # check group
    my $shortGroup;
    if (defined $group) {
        $fnret = OVH::Bastion::is_valid_group_and_existing(group => $group, groupType => 'key');
        $fnret or return $fnret;
        $group      = $fnret->value->{'group'};         # untainted
        $shortGroup = $fnret->value->{'shortGroup'};    # untainted
    }

    # check key fingerprint
    if ($forceKey) {
        $fnret = OVH::Bastion::is_valid_fingerprint(fingerprint => $forceKey);
        $fnret or return $fnret;
        $forceKey = $fnret->value->{'fingerprint'};
    }

    if ($ttl) {
        return R('ERR_INVALID_PARAMETER', msg => "The TTL must be numeric") if ($ttl !~ /^(\d+)$/);
        $ttl = $1;
    }

    # check if the caller has the right to make the change he's asking
    # ... 1. either $> is allowkeeper and $ENV{'SUDO_USER'} is the requesting account
    # ... 2. or $> is $grouptomodify  and $ENV{'SUDO_USER'} is the requesting account

    my ($running_as) = (getpwuid($>))[0] =~ /([0-9a-zA-Z_.-]+)/;
    my ($requester)  = $ENV{'SUDO_USER'} =~ /([0-9a-zA-Z_.-]+)/;

    # requester can never be a realm_* account, because it's shared and should not be able to add access to anything
    return R('ERR_SECURITY_VIOLATION', msg => "Requester can't be a realm user") if $requester =~ /^realm_/;

    my @one_should_succeed;
    my $expected_running_as = 'allowkeeper';

    if ($way eq 'personal') {
        if ($requester eq $account) {
            push @one_should_succeed, OVH::Bastion::is_user_in_group(user => $requester, group => 'osh-self' . ucfirst($action) . 'PersonalAccess', sudo => 1);
        }

        # this is not a else here: somebody who has the account* right doesn't need the self* right
        push @one_should_succeed, OVH::Bastion::is_user_in_group(user => $requester, group => 'osh-account' . ucfirst($action) . 'PersonalAccess', sudo => 1);
    }
    elsif ($way eq 'group') {
        $expected_running_as = "$group-aclkeeper";
        push @one_should_succeed, OVH::Bastion::is_group_aclkeeper(account => $requester, group => $shortGroup, superowner => 1, sudo => 1);
    }
    elsif ($way eq 'groupguest') {
        push @one_should_succeed, OVH::Bastion::is_group_gatekeeper(account => $requester, group => $shortGroup, superowner => 1, sudo => 1);
    }

    if (not defined $expected_running_as || $running_as ne $expected_running_as) {
        return R('ERR_SECURITY_VIOLATION', msg => "Current running user unexpected");
    }

    if (grep({ $_ } @one_should_succeed) == 0 && $requester ne 'root') {
        return R('ERR_SECURITY_VIOLATION', msg => "You're not allowed to do that");
    }

    # now, check if the access we're being asked to change is already in place or not
    osh_debug("for action $action of $user\@$ip:$port of way $way with account=$account and group=$group, checking if already granted");
    $fnret = OVH::Bastion::is_access_way_granted(
        user       => $user,
        ip         => $ip,
        port       => $port,
        way        => $way,
        group      => $shortGroup,
        account    => $account,
        exactMatch => 1,             # we're checking if the exact right we're asked to modify exists or not
    );
    osh_debug("... result is $fnret");

    #return $fnret if $fnret->is_err;

    if ($action eq 'add' and $fnret) {
        return R('OK_NO_CHANGE', msg => "The requested access to add was already granted");
    }
    elsif ($action eq 'del' and not $fnret) {
        return R('OK_NO_CHANGE', msg => "The requested access to delete was not found, no change made");
    }

    # TODO for groupguest case, also check that the group has the right

    # ok, now do the change, first define this sub

    my $_access_modify_file = sub {
        my %sub_params = @_;
        my $file       = $sub_params{'file'};

        # we don't check our params or the rights because our caller already did, guaranteed by the scoping of this sub

        # check if we can access the file
        if (!(-e $file)) {

            # it doesn't exist yet, create it
            OVH::Bastion::touch_file($file, 0644);
            if (!(-e $file)) {
                return R('ERR_CANNOT_CREATE_FILE', msg => "File '$file' is missing and couldn't be created");
            }
        }

        # can we write to it ?
        if (!(-w $file)) {
            return R('ERR_CANNOT_OPEN_FILE', msg => "File '$file' cannot be written to");
        }

        # build the line we're either adding or looking for (to delete it)
        my $entry = $ip;
        $entry = $user . "@" . $entry if defined $user;
        $entry = $entry . ":" . $port if defined $port;
        my $machine = $entry;

        my $t            = localtime(time);
        my $fmt          = "%Y-%m-%d %H:%M:%S";
        my $date         = $t->strftime($fmt);
        my $entryComment = "# $action by $requester on $date";

        # if we're adding it, add comment and potential FORCEKEY
        if ($action eq 'add') {

            $entry .= " $entryComment";

            if ($forceKey) {

                # hash is case-sensitive only for new SHA256 format
                $forceKey = lc($forceKey) if ($forceKey !~ /^sha256:/i);
                $entry .= " # FORCEKEY=" . $forceKey;
            }
            if ($ttl) {
                $entry .= " # EXPIRY=" . (time() + $ttl);
            }
            if ($comment) {
                $comment =~ s{[#<>\\"']}{_}g;
                $entry .= " # COMMENT=<" . $comment . ">";
            }
        }

        # to be extra sure, remove any \n in $entry, which is impossible because we vetted all the params,
        # but if somehow we failed, we'll be sure it doesn't permit to add multiple rights at once
        $entry =~ s/[\r\n]*//gm;

        # now, do the change
        my $returnmsg;
        if ($action eq 'add') {
            osh_debug("going to add entry '$entry'");
            if (open(my $fh_file, '>>', $file)) {
                print $fh_file $entry . "\n";
                close($fh_file);
            }
            else {
                return R('ERR_CANNOT_OPEN_FILE', msg => "Error opening $file: $!");
            }
            my $ttlmsg = $ttl ? (' (expires in ' . OVH::Bastion::duration2human(seconds => $ttl)->value->{'human'} . ')') : '';
            $returnmsg = "Access to $machine successfully added$ttlmsg";
        }
        elsif ($action eq 'del') {
            if (open(my $fh_file, '<', $file)) {
                my $newFile;
                my $found = 0;
                while (my $line = <$fh_file>) {
                    if ($line =~ m{^\Q$entry\E(\s|$)}) {
                        chomp $line;
                        $line = "# $line # $comment\n";
                        $found++;
                    }
                    $newFile .= $line;
                }
                close($fh_file);

                if ($found) {

                    # now rewrite
                    if (open(my $fh_file, '>', $file)) {
                        print $fh_file $newFile;
                        close($fh_file);
                        $returnmsg = "Access to $machine successfully removed";
                    }
                    else {
                        return R('ERR_CANNOT_OPEN_FILE', msg => "Unable to write open $file");
                    }
                }
                else {
                    return R('OK_NO_CHANGE', msg => "Entry $entry was not present in file $file");
                }
            }
        }
        OVH::Bastion::syslogFormatted(
            severity => 'info',
            type     => 'acl',
            fields   => [
                ['action',    $params{'action'}],
                ['type',      $params{'way'}],
                ['group',     $shortGroup],
                ['account',   $params{'account'}],
                ['user',      $params{'user'}],
                ['ip',        $params{'ip'}],
                ['port',      $params{'port'}],
                ['ttl',       $params{'ttl'}],
                ['force_key', $params{'forceKey'}],
                ['comment',   $params{'comment'}],
            ]
        );
        return R('OK', msg => $returnmsg) if $returnmsg;
        return R('ERR_INTERNAL');
    };    # end of sub definition

    # then call the sub we just defined
    delete $params{'file'};
    my $ret;
    my $prefix = $remoteaccount ? "allowed_$remoteaccount" : "allowed";
    if ($way eq 'personal') {
        $ret = $_access_modify_file->(%params, file => "/home/allowkeeper/$sysaccount/$prefix.private");
    }
    elsif ($way eq 'group') {
        $ret = $_access_modify_file->(%params, file => "/home/$group/allowed.ip");
    }
    elsif ($way eq 'groupguest') {
        $ret = $_access_modify_file->(%params, file => "/home/allowkeeper/$sysaccount/$prefix.partial.$shortGroup");
    }
    osh_debug("_access_modify_file() said $ret");
    return $ret if defined $ret;

    return R('ERR_INTERNAL');    # unreachable
}

# Check that a group is valid or not (syntax)
sub is_valid_group {
    my %params    = @_;
    my $group     = $params{'group'};
    my $groupType = $params{'groupType'};

    # osh: osh-accountListBastionKeys
    # tty: login8-tty
    # key: keymygroup
    # gatekeeper: keymygroup-gatekeeper
    # aclkeeper: keymygroup-aclkeeper
    # owner: keymygroup-owner

    if (!$group) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing parameter 'group'");
    }

    # autodetect if my caller prefixed the group name with 'key' or not, and adjust accordingly.
    # we'll return normalized group and shortGroup values to our caller
    if ($group !~ /^key/ && defined $groupType && grep { $groupType eq $_ } qw{ key gatekeeper aclkeeper owner }) {
        $group = "key$group";
    }

    if ($group =~ m/keeper$/i and not grep { $groupType eq $_ } qw{ gatekeeper aclkeeper }) {
        return R('KO_FORBIDDEN_SUFFIX', msg => 'Forbidden suffix in group name');
    }
    elsif ($group =~ m/owner$/i and $groupType ne 'owner') {
        return R('KO_FORBIDDEN_SUFFIX', msg => 'Forbidden suffix in group name');
    }
    elsif ($group =~ m/-tty$/i and $groupType ne 'tty') {
        return R('KO_FORBIDDEN_SUFFIX', msg => 'Forbidden suffix in group name');
    }
    elsif ($group =~ m/^key/i and not grep { $groupType eq $_ } qw{ key gatekeeper owner }) {
        return R('KO_FORBIDDEN_PREFIX', msg => 'Forbidden prefix in group name');
    }
    elsif ($group =~ /^(key)?(private|root|user|self|legacy|osh)(-(gatekeeper|aclkeeper|owner))?$/) {
        return R('KO_FORBIDDEN_NAME', msg => 'Forbidden group name');
    }
    elsif ($group =~ m/^([a-zA-Z0-9_-]+)$/) {
        $group = $1;    # untainted
        if ($groupType eq 'key' and $group !~ m/^key/) {
            return R('KO_MISSING_PREFIX', msg => "The group $group should have a prefix (group type $groupType)");
        }
        elsif ($groupType eq 'gatekeeper' and $group !~ m/^key.+-gatekeeper$/) {
            return R('KO_MISSING_PREFIX', msg => "The group $group should have a prefix (group type $groupType)");
        }
        elsif ($groupType eq 'owner' and $group !~ m/^key.+-owner$/) {
            return R('KO_MISSING_PREFIX', msg => "The group $group should have a prefix (group type $groupType)");
        }
        elsif ($groupType and $groupType eq 'tty' and $group !~ m/-tty$/) {
            return R('KO_MISSING_SUFFIX', msg => "The group $group should have a suffix (group type $groupType)");
        }
        my $shortGroup = $group;
        $shortGroup =~ s/^key|^osh-|-(gatekeeper|aclkeeper|owner|tty)$//g;

        if (length($group) > 32) {

            # 32 max for the whole group (system limit)
            return R('KO_NAME_TOO_LONG', msg => 'Group name is too long (system limit)');
        }

        if ($groupType ne 'osh' and length($shortGroup) > 18) {

            # 18 max for the short group (except for osh groups)
            return R('KO_NAME_TOO_LONG', msg => 'Group name is too long (code limit)');
        }

        return R('OK', value => {group => $group, shortGroup => $shortGroup});
    }
    return R('KO_FORBIDDEN_NAME', msg => 'Group name contains invalid characters');
}

sub is_valid_group_and_existing {
    my %params = @_;

    my $fnret = OVH::Bastion::is_valid_group(%params);
    $fnret or return $fnret;
    $params{'group'} = $fnret->value->{'group'};
    return OVH::Bastion::is_group_existing(%params);
}

# Add a user to a group
sub add_user_to_group {
    my %params      = @_;
    my $group       = $params{'group'};
    my $user        = $params{'user'};
    my $accountType = $params{'accountType'};
    my $groupType   = $params{'groupType'};
    my $fnret;

    osh_debug('validating user');
    $fnret = OVH::Bastion::is_account_valid(account => $user, accountType => $accountType);
    $fnret or return $fnret;
    osh_debug('user is ok');
    $user = $fnret->value->{'account'} || $fnret->value->{'realm'};

    osh_debug('validating group name');
    if ($groupType) {
        $fnret = OVH::Bastion::is_valid_group(group => $group, groupType => $groupType);
    }
    else {
        $fnret = OVH::Bastion::is_valid_group(group => $group);
    }
    $fnret or return $fnret;
    osh_debug('group name is ok');
    $group = $fnret->value->{'group'};

    $fnret = OVH::Bastion::sys_addmembertogroup(group => $group, user => $user);
    $fnret or return R('ERR_USERMOD_FAILED', msg => "Error while adding $user to group $group (" . $fnret->msg . ")");
    return R('OK');
}

my %_cache_get_group_list;

sub get_group_list {
    my %params    = @_;
    my $groupType = $params{'groupType'};
    my $cache     = $params{'cache'};       # if true, allow cache use

    if ($cache and $_cache_get_group_list{$groupType}) {
        return $_cache_get_group_list{$groupType};
    }

    my $antiloop = 9000;
    my %groups;
    setgrent();
    while (my @nextgroup = getgrent()) {
        $antiloop-- < 0 and last;
        my ($name, $passwd, $gid, $members) = @nextgroup;
        if (    $groupType eq 'key'
            and $name =~ /^key/
            and $name !~ /-(owner|gatekeeper|aclkeeper)$/
            and not grep { $name eq $_ } qw{ keykeeper keyreader })
        {
            $name =~ s/^key//;
            my @members = split(/ /, $members);
            $groups{$name} = {gid => $gid, members => split(/ /, $members)};
        }
    }
    $_cache_get_group_list{$groupType} = R('OK', value => \%groups);
    return $_cache_get_group_list{$groupType};
}

my $_cache_get_account_list = undef;

sub get_account_list {
    my %params   = @_;
    my $accounts = $params{'accounts'} || [];
    my $cache    = $params{'cache'};            # if true, allow cache use

    if ($cache and $_cache_get_account_list) {
        return $_cache_get_account_list;
    }

    my %users;

    if (@$accounts) {
        foreach (@$accounts) {
            my ($name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir, $shell, $expire) = getpwnam($_);
            next unless OVH::Bastion::is_bastion_account_valid_and_existing(account => $name);
            $users{$name} = {name => $name, uid => $uid, gid => $gid, home => $dir, shell => $shell};
        }
    }
    else {
        setpwent();
        while (my ($name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir, $shell, $expire) = getpwent()) {
            next unless OVH::Bastion::is_bastion_account_valid_and_existing(account => $name);
            $users{$name} = {name => $name, uid => $uid, gid => $gid, home => $dir, shell => $shell};
        }
    }
    $_cache_get_account_list = R('OK', value => \%users);
    return $_cache_get_account_list;
}

sub get_realm_list {
    my %params = @_;
    my $realms = $params{'realms'} || [];

    my %users;

    setpwent();

    if (@$realms) {
        foreach (@$realms) {
            my ($name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir, $shell, $expire) = getpwnam("realm_" . $_);
            next unless OVH::Bastion::is_bastion_account_valid_and_existing(account => $name, accountType => "realm");
            $name =~ s{^realm_}{};
            $users{$name} = {name => $name};
        }
    }
    else {
        setpwent();
        while (my ($name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir, $shell, $expire) = getpwent()) {
            next unless OVH::Bastion::is_bastion_account_valid_and_existing(account => $name, accountType => "realm");
            $name =~ s{^realm_}{};
            $users{$name} = {name => $name};
        }
    }

    return R('OK', value => \%users);
}

# check if account is a bastion admin (gives access to adminXyz commands)
# hint: an admin is also always a superowner
sub is_admin {
    my %params  = @_;
    my $sudo    = $params{'sudo'};      # we're run under sudo
    my $account = $params{'account'};

    if (not $account) {
        $account = $sudo ? $ENV{'SUDO_USER'} : OVH::Bastion::get_user_from_env()->value;
    }

    if (not $account) {
        return R('ERR_INTERNAL_ERROR');
    }
    if (not $sudo and exists $ENV{'SUDO_USER'}) {

        # only legit case is if we have osh.pl under sudo because of an admin (adminSudo / ssh-as), check this
        if (not OVH::Bastion::is_admin(account => $ENV{'SUDO_USER'}, sudo => 1)) {
            OVH::Bastion::syslogFormatted(
                criticity => 'info',
                type      => 'security',
                fields    => [['type', 'unexpected-sudo'], ['account', $params{'account'}], ['plugin', 'is_admin'], ['params', join(" ", @_)],]
            );
            return R('ERR_SECURITY_VIOLATION', msg => "Wasn't expected to be called under sudo, but was, with user " . $ENV{'SUDO_USER'});
        }
    }

    my $adminList = OVH::Bastion::config('adminAccounts')->value();
    if (grep { $account eq $_ } @$adminList) {
        return OVH::Bastion::is_user_in_group(group => "osh-admin", user => $account);
    }
    return R('KO_ACCESS_DENIED');
}

# check if account is a superowner
# hint: an admin is also always a superowner
sub is_super_owner {
    my %params  = @_;
    my $sudo    = $params{'sudo'};      # we're run under sudo
    my $account = $params{'account'};

    if (not $account) {
        $account = $sudo ? $ENV{'SUDO_USER'} : OVH::Bastion::get_user_from_env()->value;
    }

    if (not $account) {
        return R('ERR_INTERNAL_ERROR');
    }
    if (not $sudo and exists $ENV{'SUDO_USER'}) {

        # only legit case is if we have osh.pl under sudo because of an admin (adminSudo / ssh-as), check this
        if (not OVH::Bastion::is_admin(account => $ENV{'SUDO_USER'}, sudo => 1)) {
            OVH::Bastion::syslogFormatted(
                criticity => 'info',
                type      => 'security',
                fields    => [['type', 'unexpected-sudo'], ['account', $params{'account'}], ['plugin', 'is_super_owner'], ['params', join(" ", @_)],]
            );
            return R('ERR_SECURITY_VIOLATION', msg => "Wasn't expected to be called under sudo, but was, with user " . $ENV{'SUDO_USER'});
        }
    }

    my $superownerList = OVH::Bastion::config('superOwnerAccounts')->value();
    if (grep { $account eq $_ } @$superownerList) {
        return OVH::Bastion::is_user_in_group(group => "osh-superowner", user => $account);
    }

    # if admin, then we're good too
    return OVH::Bastion::is_admin(account => $account, sudo => $sudo);
}

# check if account is an auditor
sub is_auditor {
    my %params  = @_;
    my $sudo    = $params{'sudo'};      # we're run under sudo
    my $account = $params{'account'};

    if (not $account) {
        $account = $sudo ? $ENV{'SUDO_USER'} : OVH::Bastion::get_user_from_env()->value;
    }

    if (not $account) {
        return R('ERR_INTERNAL_ERROR');
    }
    if (not $sudo and exists $ENV{'SUDO_USER'}) {

        # only legit case is if we have osh.pl under sudo because of an admin (adminSudo / ssh-as), check this
        if (not OVH::Bastion::is_admin(account => $ENV{'SUDO_USER'}, sudo => 1)) {
            OVH::Bastion::syslogFormatted(
                criticity => 'info',
                type      => 'security',
                fields    => [['type', 'unexpected-sudo'], ['account', $params{'account'}], ['plugin', 'is_auditor'], ['params', join(" ", @_)],]
            );
            return R('ERR_SECURITY_VIOLATION', msg => "Wasn't expected to be called under sudo, but was, with user " . $ENV{'SUDO_USER'});
        }
    }

    return OVH::Bastion::is_user_in_group(group => "osh-auditor", user => $account);
}

# used by funcs below
sub _has_group_role {
    my %params     = @_;
    my $account    = $params{'account'};
    my $shortGroup = $params{'group'};
    my $role       = $params{'role'};          # regular or gatekeeper or owner
    my $superowner = $params{'superowner'};    # allow superowner (will always return yes if so)
    my $sudo       = $params{'sudo'};          # are we run under sudo ?

    if (not $account) {
        $account = $sudo ? $ENV{'SUDO_USER'} : OVH::Bastion::get_user_from_env()->value;
    }
    if (not $account) {
        return R('ERR_MISSING_PARAMETER', msg => 'Expected parameter account');
    }
    if (not $sudo and exists $ENV{'SUDO_USER'}) {

        # only legit case is if we have osh.pl under sudo because of an admin (adminSudo / ssh-as), check this
        if (not OVH::Bastion::is_admin(account => $ENV{'SUDO_USER'}, sudo => 1)) {
            OVH::Bastion::syslogFormatted(
                criticity => 'info',
                type      => 'security',
                fields    => [['type', 'unexpected-sudo'], ['account', $params{'account'}], ['plugin', '_has_group_role'], ['params', join(" ", @_)],]
            );
            return R('ERR_SECURITY_VIOLATION', msg => "Wasn't expected to be called under sudo, but was, with user " . $ENV{'SUDO_USER'});
        }
    }

    my $group = "key$shortGroup";

    # "regular" means "member or guest", i.e. user is in group key$GROUPNAME
    if ($role ne 'regular') {
        $group .= "-$role";
    }

    # for the realm case, we need to test sysaccount and not just account
    my $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $account);
    $fnret or return $fnret;

    my $sysaccount = $fnret->value->{'sysaccount'};

    my $fnret = OVH::Bastion::is_user_in_group(user => $sysaccount, group => $group);
    osh_debug("is <$sysaccount> in <$group> ? => " . ($fnret ? 'yes' : 'no'));
    if ($fnret) {
        $fnret->{'value'} = {account => $account, sysaccount => $sysaccount};
        return $fnret;
    }

    # if superowner allowed, try it
    if ($superowner) {
        if (OVH::Bastion::is_super_owner(account => $sysaccount, sudo => $sudo)) {
            osh_debug("is <$sysaccount> in <$group> ? => no but superowner so YES!");
            return R('OK', value => {account => $account, sysaccount => $sysaccount, superowner => 1});
        }
    }

    # not admin or no superowner allowed... return is_user_in_group status but fixup the value if true
    $fnret->{'value'} = {account => $account, sysaccount => $sysaccount} if $fnret;
    return $fnret;
}

sub is_group_aclkeeper {
    my %params = @_;
    $params{'role'} = 'aclkeeper';
    return _has_group_role(%params);
}

sub is_group_gatekeeper {
    my %params = @_;
    $params{'role'} = 'gatekeeper';
    return _has_group_role(%params);
}

sub is_group_owner {
    my %params = @_;
    $params{'role'} = 'owner';
    return _has_group_role(%params);
}

sub _is_group_member_or_guest {
    my %params     = @_;
    my $shortGroup = $params{'group'};
    my $want       = $params{'want'};    # guest or member

    my $fnret = _has_group_role(%params, role => "regular");
    $fnret or return $fnret;

    my $account = $fnret->value()->{'account'};
    $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $account);
    $fnret or return $fnret;

    $account = $fnret->value->{'account'};
    my $remoteaccount = $fnret->value->{'remoteaccount'};
    my $sysaccount    = $fnret->value->{'sysaccount'};

    my $group = "key$shortGroup";
    $fnret = OVH::Bastion::is_valid_group_and_existing(group => $group, groupType => "key");
    $fnret or return $fnret;
    $group      = $fnret->value()->{'group'};
    $shortGroup = $fnret->value()->{'shortGroup'};    # untainted

    my $weare = 'guest';

    # to be a member (old name: "full member"); one also need to have the symlink
    my $prefix = $remoteaccount ? "allowed_$remoteaccount" : "allowed";
    if (-l "/home/allowkeeper/$sysaccount/$prefix.ip.$shortGroup") {

        # -l => test that file exists and is a symlink
        # -r => test that the symlink dest still exists => REMOVED, because we (the caller) might not have the right to read the file if we're not member or guest ourselves
        $weare = 'member';
    }

    return R('OK') if ($weare eq $want);
    return R('KO');
}

# test if account is strictly a guest (i.e. if a member, then answer is no)
sub is_group_guest {
    my %params = @_;
    $params{'want'} = 'guest';
    return _is_group_member_or_guest(%params);
}

# test if account is strictly a member (i.e. if a guest, then answer is no)
sub is_group_member {
    my %params = @_;
    $params{'want'} = 'member';
    return _is_group_member_or_guest(%params);
}

sub get_remote_accounts_from_realm {
    my %params = @_;
    my $realm  = $params{'realm'};

    $realm = "realm_$realm" if $realm !~ /^realm_/;
    my $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $realm, accountType => "realm");
    $fnret or return $fnret;

    my $sysaccount     = $fnret->value->{'sysaccount'};
    my $allowkeeperdir = "/home/allowkeeper/$sysaccount/";

    my %accounts;
    if (opendir(my $dh, "/home/allowkeeper/$sysaccount")) {
        while (my $filename = readdir($dh)) {
            next if $filename !~ /allowed_([a-zA-Z0-9_-]+)\./;
            $accounts{$1} = 1;
        }
        closedir($dh);
    }
    return R('OK', value => [sort keys %accounts]);
}

sub is_valid_ttl {
    my %params = @_;
    my $ttl    = $params{'ttl'};
    my $seconds;

    if ($ttl =~ /^\d+$/) {
        return R('OK', value => {seconds => $ttl + 0});
    }
    elsif ($ttl =~ m{^(\d+[smhdwy]*)+$}i) {
        while ($ttl =~ m{(\d+)([smhdwy])?}gi) {
            if    ($2 eq 'y') { $seconds += $1 * 86400 * 365 }
            elsif ($2 eq 'w') { $seconds += $1 * 86400 * 7 }
            elsif ($2 eq 'd') { $seconds += $1 * 86400 }
            elsif ($2 eq 'h') { $seconds += $1 * 3600 }
            elsif ($2 eq 'm') { $seconds += $1 * 60 }
            else              { $seconds += $1 }
        }
        return R('OK', value => {seconds => $seconds + 0});
    }

    return R('KO_INVALID_PARAMETER', msg => "Invalid TTL ($ttl), expected an amount of seconds, or a duration string such as '2d8h15m'");
}

1;
