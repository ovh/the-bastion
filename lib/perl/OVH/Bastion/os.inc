# vim: set filetype=perl ts=4 sw=4 sts=4 et:
package OVH::Bastion;

use common::sense;

sub sysinfo {
    state $cached_response;
    if (not defined $cached_response) {
        my %data;
        if (open(my $fh, '<', '/etc/os-release')) {
            while (my $line = <$fh>) {
                chomp $line;
                # man 5 os-release
                foreach my $key (qw{ NAME VERSION ID VERSION_ID ID_LIKE PRETTY_NAME }) {
                    $data{lc($key)} = $1 if $line =~ m{^${key}="?([^"]+)};
                }
            }
            $cached_response = R('OK', value => \%data);
            close($fh);
        }
        else {
            $cached_response = R('ERR_MISSING_FILE', msg => "The /etc/os-release file couldn't be opened");
        }
    }
    return $cached_response;
}

sub is_linux { return R($^O eq 'linux' ? 'OK' : 'KO'); }

sub _is_distro {
    return R('KO') if !is_linux();

    my $distro  = shift;
    my $sysinfo = sysinfo();
    return $sysinfo if !$sysinfo;

    if ($sysinfo->value->{'id'} && $sysinfo->value->{'id'} eq $distro) {
        return R('OK');
    }
    if ($sysinfo->value->{'id_like'} && $sysinfo->value->{'id_like'} =~ /\Q$distro\E/) {
        return R('OK');
    }
    return R('KO');
}
sub is_debian        { return _is_distro('debian'); }
sub is_debian_trixie { return R(_is_distro('debian') && sysinfo()->value->{'version_id'} eq "13" ? 'OK' : 'KO'); }
sub is_redhat        { return _is_distro('rhel'); }

sub is_bsd     { return R($^O =~ /bsd$/    ? 'OK' : 'KO'); }
sub is_freebsd { return R($^O eq 'freebsd' ? 'OK' : 'KO'); }
sub is_openbsd { return R($^O eq 'openbsd' ? 'OK' : 'KO'); }
sub is_netbsd  { return R($^O eq 'netbsd'  ? 'OK' : 'KO'); }

sub has_acls { return R((is_linux || is_freebsd) ? 'OK' : 'KO'); }

# Helper to launch an external command that needs to modify /etc/passwd or /etc/group, such as useradd,
# userdel, groupadd, groupdel, usermod, groupmod, etc. and watch for it failing because of too much
# parallelism (as they try to lock those files). Depending on the versions, it either exits with an exit
# code of 10 (and in more rare occasions, 1), with an error message saying that it couldn't lock /etc/passwd
# or /etc/group and you should retry later. Detect that and retry silently a few times.
#
# We always return an OVH::Bastion::execute() result
sub _sys_autoretry {
    my %params = @_;

    my $fnret;
    foreach my $try (1 .. 10) {
        $fnret = OVH::Bastion::execute(%params);
        if (
            ($fnret->value && $fnret->value->{'sysret'} == 10)
            || (
                ($fnret->value && $fnret->value->{'sysret'} != 0)
                && (   ($fnret->value->{'stdout'} && grep { /retry|lock/i } @{$fnret->value->{'stdout'}})
                    || ($fnret->value->{'stderr'} && grep { /retry|lock/i } @{$fnret->value->{'stderr'}}))
            )
          )
        {
            # too much concurrency, sleep a bit and retry
            warn_syslog('Too much concurrency on try '
                  . $try
                  . " running command '"
                  . join(" ", @{$params{'cmd'} || []}) . "', "
                  . $fnret->msg
                  . ", stdout: '"
                  . (($fnret->value && $fnret->value->{'stdout'}) ? $fnret->value->{'stdout'}->[0] : '(null)') . "'"
                  . ", stderr: '"
                  . (($fnret->value && $fnret->value->{'stderr'}) ? $fnret->value->{'stderr'}->[0] : '(null)')
                  . "'");
            osh_info("This is taking longer than usually, please be patient...");
            sleep(rand(5) + (5 * $try));
        }
        else {
            # any other error or success, return
            return $fnret;
        }
    }

    # failed too many times, log the detailed error in our system log, warn the user and return what we have
    warn_syslog('Too much concurrency running command "'
          . join(" ", $params{'cmd'})
          . '", returned '
          . $fnret->msg
          . ', gave up');
    warn "Couldn't apply modifications (concurrency problem?)";
    return $fnret;
}

sub sys_useradd {
    my %params = @_;
    my $user   = delete $params{'user'};

    if (not $user) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing mandatory parameter 'user'");
    }

    my @cmd;
    if (exists $params{'uid'}) {
        push @cmd, ('-u', delete $params{'uid'});
    }
    if (exists $params{'gid'}) {
        push @cmd, ('-g', delete $params{'gid'});
    }
    if (exists $params{'home'}) {
        push @cmd, ('-d', delete $params{'home'});
    }
    if (exists $params{'comment'}) {
        push @cmd, ('-c', delete $params{'comment'});
    }
    if (exists $params{'shell'}) {
        my $shell = delete $params{'shell'};
        if (not defined $shell) {

            # we want a shell that exists and prevents login
          LOOP: foreach my $dir (qw{ /usr/sbin /usr/bin /sbin /bin }) {
                foreach my $exe (qw{ nologin false }) {
                    if (-x "$dir/$exe") {
                        $shell = "$dir/$exe";
                        last LOOP;
                    }
                }
            }
        }
        push @cmd, ('-s', $shell);
    }

    if (is_freebsd()) {
        @cmd = ('pw', 'useradd', '-n', $user, '-m', @cmd);
    }
    elsif (is_bsd()) {    # at least obsd and fbsd
                          # to avoid this useradd msg:
                          # useradd: Password `*' is invalid: setting it to `*************'
        @cmd = ('useradd', '-p', '*************', '-m', @cmd, $user);
    }
    else {
        @cmd = ('useradd', '-p', '*', '-m', @cmd, $user);
    }

    $params{'cmd'}          = \@cmd;
    $params{'must_succeed'} = 1;
    return _sys_autoretry(%params);
}

sub sys_groupadd {
    my %params = @_;
    my $group  = delete $params{'group'};

    if (not $group) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing mandatory parameter 'group'");
    }

    my @cmd;
    if ($params{'gid'}) {
        push @cmd, ('-g', delete $params{'gid'});
    }

    if (is_freebsd()) {
        @cmd = ('pw', 'groupadd', '-n', $group, @cmd);
    }
    else {
        @cmd = ('groupadd', @cmd, $group);
    }

    $params{'cmd'}          = \@cmd;
    $params{'must_succeed'} = 1;
    return _sys_autoretry(%params);
}

sub sys_userdel {
    my %params = @_;
    my $user   = delete $params{'user'};

    if (not $user) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing mandatory parameter 'user'");
    }

    my @cmd;
    if (is_freebsd()) {
        @cmd = ('pw', 'userdel', '-n', $user,);
    }
    elsif (is_netbsd() || is_openbsd()) {

        # main user group is never auto-removed, so we'll do it but only
        # if the name of the user is the same than the name of its primary group
        my ($fnret, $maingroup);
        $fnret = OVH::Bastion::execute(cmd => ['id', '-g', '-n', $user], %params);
        if ($fnret->err eq 'OK' and $fnret->value and $fnret->value->{'stdout'}) {
            $maingroup = $fnret->value->{'stdout'}->[0];
        }

        if (defined $maingroup && $user eq $maingroup) {

            # okay, maingroup == user, so delete the user first, then the corresponding group
            $fnret = OVH::Bastion::execute(cmd => ['userdel', $user], %params);
            if ($fnret->err eq 'OK') {
                @cmd = ('groupdel', $user);
            }
        }
        else {
            # hmm, either the main group is not the same as the user, or we can't tell,
            # so just delete the user anyway
            @cmd = ('userdel', $user);
        }
    }
    else {
        @cmd = ('userdel', $user);
    }

    $params{'cmd'}          = \@cmd;
    $params{'must_succeed'} = 1;
    return _sys_autoretry(%params);
}

sub sys_groupdel {
    my %params = @_;
    my $group  = delete $params{'group'};

    if (not $group) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing mandatory parameter 'group'");
    }

    my @cmd;
    if (is_freebsd()) {
        @cmd = ('pw', 'groupdel', '-n', $group,);
    }
    else {
        @cmd = ('groupdel', $group);
    }

    $params{'cmd'}          = \@cmd;
    $params{'must_succeed'} = 1;
    return _sys_autoretry(%params);
}

sub sys_addmembertogroup {
    my %params = @_;
    my $user   = delete $params{'user'};
    my $group  = delete $params{'group'};

    if (not $group or not $user) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing mandatory parameter 'group' or 'user'");
    }

    if (is_openbsd() || is_netbsd()) {
        my $fnret  = OVH::Bastion::execute(cmd => ["groups", $user], must_succeed => 1);
        my @stdout = @{$fnret->value->{'stdout'} || []};
        my @cur    = split(/ /, $stdout[0]);
        return R('ERR_SYSTEM_LIMIT_REACHED') if @cur >= 16;
    }

    my @cmd;
    if (is_freebsd()) {
        @cmd = ('pw', 'groupmod', '-n', $group, '-m', $user);
    }
    elsif (is_bsd()) {    # openbsd and netbsd: ok
        @cmd = ('usermod', '-G', $group, $user);
    }
    else {
        @cmd = ('usermod', '-a', '-G', $group, $user);
    }

    $params{'cmd'}          = \@cmd;
    $params{'must_succeed'} = 1;
    return _sys_autoretry(%params);
}

sub sys_delmemberfromgroup {
    my %params = @_;
    my $user   = delete $params{'user'};
    my $group  = delete $params{'group'};

    if (not $group or not $user) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing mandatory parameter 'group' or 'user'");
    }

    my @cmd;
    delete $params{'cmd'};    # security
    if (is_freebsd()) {
        @cmd = ('pw', 'groupmod', '-n', $group, '-d', $user);
    }
    # remove the Trixie if when this is fixed https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1109329
    elsif (is_debian() && !is_debian_trixie()) {
        @cmd = ('deluser', $user, $group);
    }
    elsif (is_openbsd() || is_linux()) {

        # geez. those guys are complicated.
        # first get the list of all groups user is a member of
        my $fnret = OVH::Bastion::execute(cmd => ['id', '-G', '-n', $user], %params);
        if ($fnret->err eq 'OK' and $fnret->value and $fnret->value->{'stdout'}) {
            my %groups = map { $_ => 1 } split(/ /, $fnret->value->{'stdout'}->[0]);

            # remove the group we want to remove from the list
            delete $groups{$group};

            # we must also remove the primary group from the list
            # because -S (openbsd) / -G (linux) is only for secondary groups
            $fnret = OVH::Bastion::execute(cmd => ['id', '-g', '-n', $user], %params);
            if ($fnret->err eq 'OK' and $fnret->value and $fnret->value->{'stdout'}) {
                my $primary = $fnret->value->{'stdout'}->[0];
                delete $groups{$primary};

                # now prepare the 3rd and last command
                @cmd = ('usermod', is_openbsd() ? '-S' : '-G', join(',', keys %groups), $user);
            }
            else {
                return R('ERR_INTERNAL', msg => "Couldn't remove user from group (unknown primary group)");
            }
        }
        else {
            return R('ERR_INTERNAL', msg => "Couldn't remove user from group (couldn't get group list)");
        }
    }
    elsif (is_netbsd()) {

        # NetBSD has no way of removing a user from a group without
        # manually patching /etc/group... eew :(
        my $contents;
        if (open(my $fh, '<', '/etc/group')) {
            local $_ = undef;
            while (<$fh>) {
                if (/^\Q$group\E:/) {
                    s/([:,])\Q$user\E(?:,|$)/$1/;
                    s/,$//;
                }
                $contents .= $_;
            }
            close($fh);
            if (open(my $fh, '>', '/etc/group')) {
                print $fh $contents;
                close($fh);
            }
            else {
                return R('ERR_INTERNAL', msg => "Couldn't open group file for writing ($!)");
            }
        }
        else {
            return R('ERR_INTERNAL', msg => "Couldn't open group file for reading ($!)");
        }
        return R('OK');    # we're done, we've no other command to execute
    }

    $params{'cmd'}          = \@cmd;
    $params{'must_succeed'} = 1;
    return _sys_autoretry(%params);
}

sub sys_changepassword {
    my %params   = @_;
    my $user     = delete $params{'user'};
    my $password = delete $params{'password'};

    if (!$user || !$password) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing mandatory parameter 'user' or 'password'");
    }

    my @cmd;
    my $stdin_str;

    if (is_linux()) {
        @cmd       = ('chpasswd');
        $stdin_str = "$user:$password";
    }
    elsif (is_freebsd()) {
        @cmd       = ('pw', 'usermod', $user, '-h', '0');
        $stdin_str = $password;
    }
    elsif (is_openbsd() || is_netbsd()) {
        my $fnret;
        if (is_openbsd()) {
            $fnret = OVH::Bastion::execute(cmd => ["encrypt"], stdin_str => $password, must_succeed => 1);
        }
        else {
            # netbsd
            $fnret = OVH::Bastion::execute(cmd => ["pwhash", $password], must_succeed => 1);
        }
        $fnret or return $fnret;
        my ($encrypted) = $fnret->value->{'stdout'}->[0] =~ m{^([\$a-zA-Z0-9./]+)};
        @cmd = ('usermod', '-p', $encrypted, $user);
    }
    else {
        return R('ERR_NOT_IMPLEMENTED');
    }

    $params{'stdin_str'}    = $stdin_str if defined $stdin_str;
    $params{'cmd'}          = \@cmd;
    $params{'must_succeed'} = 1;
    my $fnret = _sys_autoretry(%params);
    delete $ENV{'EDITOR'};
    return $fnret;
}

sub sys_neutralizepassword {
    my %params = @_;
    my $user   = delete $params{'user'};

    if (!$user) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing mandatory parameter 'user'");
    }

    my @cmd;
    my $stdin_str;

    if (is_linux()) {
        @cmd       = qw{ chpasswd -e };
        $stdin_str = "$user:*";
    }
    elsif (is_freebsd()) {
        @cmd = ('chpass', '-p', '*', $user);
    }
    elsif (is_openbsd() || is_netbsd()) {
        @cmd = ('usermod', '-p', '*' x 13, $user);
    }
    else {
        return R('ERR_NOT_IMPLEMENTED');
    }

    $params{'stdin_str'}    = $stdin_str if defined $stdin_str;
    $params{'cmd'}          = \@cmd;
    $params{'must_succeed'} = 1;
    my $fnret = _sys_autoretry(%params);
    delete $ENV{'EDITOR'};
    return $fnret;
}

sub sys_setpasswordpolicy {
    my %params       = @_;
    my $user         = delete $params{'user'};
    my $expireDays   = delete $params{'expireDays'};
    my $inactiveDays = delete $params{'inactiveDays'};
    my $minDays      = delete $params{'minDays'};
    my $maxDays      = delete $params{'maxDays'};
    my $warnDays     = delete $params{'warnDays'};

    if (!$user) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing mandatory parameter 'user' or 'password'");
    }

    my @cmd;

    if (is_linux()) {
        @cmd = ('chage');
        if (defined $expireDays) {
            require POSIX;
            push @cmd, '--expiredate', POSIX::strftime("%Y-%m-%d", localtime(time() + 86400 * $expireDays));
        }
        push @cmd, '--inactive', $inactiveDays if defined $inactiveDays;
        push @cmd, '--mindays',  $minDays      if defined $minDays;
        push @cmd, '--maxdays',  $maxDays      if defined $maxDays;
        push @cmd, '--warndays', $warnDays     if defined $warnDays;
        push @cmd, $user;
        if (@cmd == 1) {
            return R('ERR_MISSING_PARAMETER', msg => "No password policy to set");
        }
    }
    else {
        return R('OK_IGNORED');
    }

    $params{'cmd'}          = \@cmd;
    $params{'must_succeed'} = 1;
    return _sys_autoretry(%params);
}

sub sys_getpasswordinfo {
    my %params = @_;
    my $user   = delete $params{'user'};
    my $fnret;

    my %ret;
    if (is_linux()) {
        $fnret = OVH::Bastion::execute(cmd => ['getent', 'shadow', $user]);
        $fnret or return $fnret;
        return R('KO_NOT_FOUND') if ($fnret->value->{'sysret'} != 0);
        if ($fnret->value->{'stdout'}->[0] =~
            m{^([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*)$})
        {
            %ret = (
                user                => $1,
                password            => $2,
                epoch_changed_days  => $3,
                min_days            => $4,
                max_days            => $5,
                warn_days           => $6,
                inactive_days       => $7,
                epoch_disabled_days => $8
            );
        }
        else {
            return R('ERR_CANNOT_PARSE_SHADOW');
        }

    }
    elsif (is_bsd()) {

        # bsd has nothing to get "shadow" info without reading it ourselves...
        if (open(my $masterfd, '<', '/etc/master.passwd')) {
            my @lines = <$masterfd>;
            close($masterfd);
            my @userlines = grep { /^\Q$user\E:/ } @lines;
            return R('KO_NOT_FOUND') if (@userlines != 1);
            if ($userlines[0] =~ m{^([^:]*):([^:]*)}) {
                %ret = (user => $1, password => $2);
            }
            else {
                return R('ERR_CANNOT_PARSE_SHADOW');
            }
        }
        else {
            return R('ERR_CANNOT_READ_FILE', msg => "Couldn't open /etc/master.passwd: $!");
        }
    }

    if ($ret{'password'} =~ /^[*!]/) {
        $ret{'password'} = 'locked';
    }
    elsif (length($ret{'password'}) == 0) {
        $ret{'password'} = 'empty';
    }
    else {
        $ret{'password'} = 'set';
    }
    require POSIX;
    $ret{'date_changed_timestamp'} = 86400 * delete($ret{'epoch_changed_days'}) + 0;
    $ret{'date_changed'} =
      $ret{'date_changed_timestamp'} ? POSIX::strftime("%Y-%m-%d", localtime($ret{'date_changed_timestamp'})) : undef;
    $ret{'min_days'} += 0;
    $ret{'max_days'} += 0;
    $ret{'max_days'} = -1 if $ret{'max_days'} >= 9999;
    $ret{'warn_days'} += 0;
    $ret{'inactive_days'} = -1 if $ret{'inactive_days'} eq '';
    $ret{'inactive_days'} += 0;
    $ret{'date_disabled_timestamp'} = 86400 * delete($ret{'epoch_disabled_days'}) + 0;
    $ret{'date_disabled'} =
      $ret{'date_disabled_timestamp'} ? POSIX::strftime("%Y-%m-%d", localtime($ret{'date_disabled_timestamp'})) : undef;
    return R('OK', value => \%ret);
}

sub sys_getsudoersfolder {
    my $sudoers_dir = "/etc/sudoers.d";
    if (-d "/usr/local/etc/sudoers.d" && !-d "/etc/sudoers.d") {
        $sudoers_dir = "/usr/local/etc/sudoers.d";    # FreeBSD
    }
    if (-d "/usr/pkg/etc/sudoers.d" && !-d "/etc/sudoers.d") {
        $sudoers_dir = "/usr/pkg/etc/sudoers.d";      # NetBSD
    }
    return $sudoers_dir;
}

sub sys_setfacl {
    my %params  = @_;
    my $default = $params{'default'};
    my $clear   = $params{'clear'};
    my $delete  = $params{'delete'};
    my $target  = $params{'target'};
    my $perms   = $params{'perms'};

    return R('OK_IGNORED') if (!is_linux && !is_freebsd);
    my @cmd;
    my $fnret;

    # setfacl +X doesn't exist under FreeBSD
    $perms =~ s/X/x/g if is_freebsd();

    if ($default && !$delete && !$clear && is_freebsd()) {

        # FreeBSD refuses to set a default ACL concerning a user/group that is different
        # from the owner if there's not already a default ACL set for the owner/group/other
        # so silently set one to the same perms that the current UNIX perms of the target when this is the case
        $fnret = OVH::Bastion::execute(cmd => ['getfacl', '-d', '-q', $target], must_succeed => 1, noisy_stderr => 1);
        $fnret or return R('ERR_GETFACL_FAILED_FREEBSD_1', msg => "Couldn't get the current default ACL");
        if (@{$fnret->value->{'stdout'}} == 0) {

            # no default acl set, we must set one, to do this, get the current (non-ACL) perms
            $fnret = OVH::Bastion::execute(cmd => ['getfacl', '-q', $target], must_succeed => 1, noisy_stderr => 1);
            $fnret or return R('ERR_GETFACL_FAILED_FREEBSD_2', msg => "Couldn't get the current ACL");
            my @perms;
            foreach (@{$fnret->value->{'stdout'}}) {
                chomp;
                /^((?:user|group|other)::...)$/ or next;
                push @perms, $1;    # untaint
            }
            if (@perms != 3) {
                return R('ERR_GETFACL_PARSE_FAILED_FREEBSD',
                    msg => "Couldn't parse getfacl output to set prerequisite default ACL");
            }

            # apply the default ACL
            @cmd   = ('setfacl', '-d', '-m', join(',', @perms), $target);
            $fnret = OVH::Bastion::execute(cmd => \@cmd, must_succeed => 1, noisy_stderr => 1);
            $fnret or return R('ERR_SETFACL_FAILED_FREEBSD', msg => "Couldn't set the prerequisite default ACL");
        }
    }

    @cmd = ('setfacl');
    if    ($default) { push @cmd, '-d' }
    if    ($clear)   { push @cmd, '-b' }
    if    ($delete)  { push @cmd, '-x' }
    elsif ($perms)   { push @cmd, '-m' }
    push @cmd, $perms if $perms;
    push @cmd, $target;

    $fnret = OVH::Bastion::execute(cmd => \@cmd, must_succeed => 1, noisy_stderr => 1);
    $fnret or return R('ERR_SETFACL_FAILED', msg => "Couldn't set the requested ACL");
    return R('OK');
}

sub is_in_path {
    my %params = @_;
    my $binary = $params{'binary'};

    foreach my $path (split /:/, $ENV{'PATH'}) {
        return R('OK', value => "$path/$binary") if -f -x "$path/$binary";
    }
    return R('KO', msg => "$binary was not found in PATH");
}

# as setpwent/endpwent can have side effects to any getpwent used between
# them, possibly in other parts of the program, encapsulate everything here
# to avoid side effects
my %_pw_cache;
my $_pw_all_cached = 0;

sub sys_getpw_all {
    my %params = @_;
    my $cache  = $params{'cache'} || $ENV{'PW_GR_CACHE'};

    if (!$cache || !$_pw_all_cached) {
        # end/set: for some reason, if we don't end() before set(), there seem
        # to be a cache somewhere, and we get entries that have been
        # deleted (milli)seconds before. This behaviour is undocumented, as set()
        # is supposed to reset the pointer, and a no mention of a cache is done
        # anywhere. Luckily, Prepending the set() with an end() seems to
        # reliably fix the issue on all tested OSes.
        %_pw_cache = ();
        endpwent();
        setpwent();
        while (my @line = getpwent()) {
            $_pw_cache{$line[0]} = {
                name    => $line[0],
                passwd  => $line[1],
                uid     => $line[2],
                gid     => $line[3],
                quota   => $line[4],
                comment => $line[5],
                gcos    => $line[6],
                dir     => $line[7],
                shell   => $line[8],
                expire  => $line[9],
            };
        }
        endpwent();
        $_pw_all_cached = 1;
    }

    return R('OK', value => \%_pw_cache);
}

sub sys_getpw_all_cached {
    return R($_pw_all_cached ? 'OK' : 'KO');
}

# get a system account entry from name (getent passwd / getpwnam)
sub sys_getpw_name {
    my %params = @_;
    my $cache  = $params{'cache'} || $ENV{'PW_GR_CACHE'};
    my $name   = $params{'name'};

    if (!$name) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing 'name' parameter");
    }

    if ($cache) {
        # if cache is allowed and our $name entry exists in cache, return it
        if (exists $_pw_cache{$name}) {
            if (defined $_pw_cache{$name}) {
                return R('OK', value => $_pw_cache{$name});
            }
            else {
                # we cached its non-existence
                return R('KO_NOT_FOUND', msg => "Account '$name' doesn't exist");
            }
        }
        # if cache is allowed, cache has been filled but our name entry is not
        # there, it means the account doesn't exist
        elsif ($_pw_all_cached) {
            return R('KO_NOT_FOUND', msg => "Account '$name' doesn't exist");
        }
        # if cache is allowed, cache has not been filled and our entry doesn't
        # exist in cache, either we never cached anything, or we partly
        # cached some accounts due to previous calls to sys_getpw_name()
        # without a single call to sys_getpw_all(), in which case we need
        # to fetch the data from the system using getpwnam()
    }

    # if cache is not allowed, fetch data from system with getpwnam() and
    # cache it. As we're just caching data for this account, don't set
    # $_pw_all_cached so that other funcs know that the cache is partial
    my @fields = getpwnam($name);
    if (@fields) {
        $_pw_cache{$fields[0]} = {
            name    => $fields[0],
            passwd  => $fields[1],
            uid     => $fields[2],
            gid     => $fields[3],
            quota   => $fields[4],
            comment => $fields[5],
            gcos    => $fields[6],
            dir     => $fields[7],
            shell   => $fields[8],
            expire  => $fields[9],
        };
        return R('OK', value => $_pw_cache{$fields[0]});
    }
    else {
        # cache the non-existence of this account
        $_pw_cache{$name} = undef;
        return R('KO_NOT_FOUND', msg => "Account '$name' doesn't exist");
    }

    # unreachable
    return R('ERR_INTERNAL');
}

# as setgrent/endgrent can have side effects to any getgrent used between
# them, possibly in other parts of the program, encapsulate everything here
# to avoid side effects
my %_gr_cache;
my $_gr_all_cached = 0;

sub sys_getgr_all {
    my %params = @_;
    my $cache  = $params{'cache'} || $ENV{'PW_GR_CACHE'};

    if (!$cache || !$_gr_all_cached) {
        # end/set: for some reason, if we don't end() before set(), there seem
        # to be a cache somewhere, and we get entries that have been
        # deleted (milli)seconds before. This behaviour is undocumented, as set()
        # is supposed to reset the pointer, and a no mention of a cache is done
        # anywhere. Luckily, pPrepending the set() with an end() seems to
        # reliably fix the issue on all tested OSes.
        %_gr_cache = ();
        endgrent();
        setgrent();
        while (my @line = getgrent()) {
            $_gr_cache{$line[0]} = {
                name    => $line[0],
                passwd  => $line[1],
                gid     => $line[2],
                members => [split(/ /, $line[3])],
            };
        }
        endgrent();
        $_gr_all_cached = 1;
    }

    return R('OK', value => \%_gr_cache);
}

sub sys_getgr_all_cached {
    return R($_gr_all_cached ? 'OK' : 'KO');
}

# get a system group entry from name (getent group / getgrnam)
sub sys_getgr_name {
    my %params = @_;
    my $name   = $params{'name'};
    my $cache  = $params{'cache'} || $ENV{'PW_GR_CACHE'};

    if (!$name) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing 'name' parameter");
    }

    if ($cache) {
        # if cache is allowed and our $name entry exists in cache, return it
        if (exists $_gr_cache{$name}) {
            if (defined $_gr_cache{$name}) {
                return R('OK', value => $_gr_cache{$name});
            }
            else {
                # we cached its non-existence
                return R('KO_NOT_FOUND', msg => "Group '$name' doesn't exist");
            }
        }
        # if cache is allowed, cache has been filled but our name entry is not
        # there, it means the group doesn't exist
        elsif ($_gr_all_cached) {
            return R('KO_NOT_FOUND', msg => "Group '$name' doesn't exist");
        }
        # if cache is allowed, cache has not been filled and our entry doesn't
        # exist in cache, either we never cached anything, or we partly
        # cached some groups due to previous calls to sys_getgr_name()
        # without a single call to sys_getgr_all(), in which case we need
        # to fetch the data from the system using getgrnam()
    }

    # if cache is not allowed, fetch data from system with getgrnam() and
    # cache it. As we're just caching data for this group, don't set
    # $_gr_all_cached so that other funcs know that the cache is partial
    my @fields = getgrnam($name);
    if (@fields) {
        $_gr_cache{$fields[0]} = {
            name    => $fields[0],
            passwd  => $fields[1],
            gid     => $fields[2],
            members => [split(/ /, $fields[3])],
        };
        return R('OK', value => $_gr_cache{$fields[0]});
    }
    else {
        # cache the non-existence of this group
        $_gr_cache{$name} = undef;
        return R('KO_NOT_FOUND', msg => "Group '$name' doesn't exist");
    }

    # unreachable
    return R('ERR_INTERNAL');
}

sub sys_list_processes {
    my %params = @_;
    my $user   = $params{'user'};

    if (!$user) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing 'user' parameter");
    }

    # works for Linux and FreeBSD
    my $fnret = OVH::Bastion::execute_simple(cmd => ['ps', '-U', $user, '-o', 'pid']);

    # ps can return 1 if no process found, so don't test $fnret, just read the output if any
    my @pids;
    if ($fnret->value) {
        osh_debug("ps output: " . $fnret->value->{'output'}) if $fnret->value->{'output'};
        foreach my $line (split(/\n/, $fnret->value->{'output'} // '')) {
            chomp $line;
            push @pids, $1 if ($line =~ /^\s*([0-9]+)\s*$/);
        }
    }

    return R('OK', value => \@pids);
}

1;
