package OVH::Bastion::Plugin::generatePassword;

# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

use File::Basename;
use lib dirname(__FILE__) . '/../../../../../lib/perl';
use OVH::Result;
use OVH::Bastion;

sub preconditions {
    my %params  = @_;
    my $self    = $params{'self'};
    my $sudo    = $params{'sudo'};
    my $group   = $params{'group'};
    my $account = $params{'account'};
    my $size    = $params{'size'};
    my $context = $params{'context'};

    my $fnret;
    my ($shortGroup, $passhome, $base);

    if (!$size || !$context) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing argument 'size' or 'context'");
    }

    if ($context eq 'group') {
        if (not $group) {
            return R('ERR_MISSING_PARAMETER', msg => "Missing argument 'group'");
        }
        $fnret = OVH::Bastion::is_valid_group_and_existing(group => $group, groupType => 'key');
        $fnret or return $fnret;
        $group      = $fnret->value->{'group'};
        $shortGroup = $fnret->value->{'shortGroup'};
        $passhome   = "/home/$group/pass";
        $base       = "$passhome/$shortGroup";
    }
    elsif ($context eq 'account') {
        if (not $account) {
            return R('ERR_MISSING_PARAMETER', msg => "Missing argument 'account'");
        }
        $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $account);
        $fnret or return $fnret;
        $account  = $fnret->value->{'account'};
        $passhome = "/home/$account/pass";
        $base     = "$passhome/$account";
    }
    else {
        return R('ERR_INVALID_PARAMETER', msg => "Expected a context 'group' or 'account'");
    }

    $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $self);
    $fnret or return $fnret;
    $self = $fnret->value->{'account'};

    return R('ERR_INVALID_PARAMETER', msg => "The argument 'size' must be an integer") if $size !~ /^\d+$/;
    return R('ERR_INVALID_PARAMETER', msg => "Specified size must be >= 8")            if $size < 8;
    return R('ERR_INVALID_PARAMETER', msg => "Specified size must be <= 127")          if $size > 128;

    if ($context eq 'account' && $self ne $account) {
        $fnret = OVH::Bastion::is_user_in_group(user => $self, group => "osh-accountGeneratePassword");
        $fnret or return R('ERR_SECURITY_VIOLATION', msg => "You're not allowed to run this, dear $self");
    }
    elsif ($context eq 'group') {
        $fnret = OVH::Bastion::is_group_owner(account => $self, group => $shortGroup, superowner => 1, sudo => $sudo);
        $fnret or return R('ERR_NOT_ALLOWED', msg => "You're not a group owner of $shortGroup, dear $self");
    }

    # return untainted values
    return R(
        'OK',
        value => {
            self       => $self,
            account    => $account,
            shortGroup => $shortGroup,
            group      => $group,
            size       => $size,
            context    => $context,
            passhome   => $passhome,
            base       => $base
        }
    );
}

sub act {
    my %params = @_;
    my $fnret  = preconditions(%params);
    $fnret or return $fnret;

    my %values = %{$fnret->value()};
    my ($self, $account, $shortGroup, $group, $size, $passhome, $base, $context, $passhome, $base) =
      @values{qw{ self account shortGroup group size passhome base context passhome base }};

    my $pass;
    my $antiloop = 1000;

    my $hashes;
  RETRY: while ($antiloop-- > 0) {

        # generate a password
        $pass = '';
        # We only add 3 specials chars which are recognized as special chars in TL1,
        # as some network devices are very picky and only allow these 3.
        my @allowedChars = ('a' .. 'z', 'A' .. 'Z', '0' .. '9', '+', '%', '#');
        foreach (1 .. $size) {
            $pass .= $allowedChars[int(rand(@allowedChars))];
        }

        # get the corresponding hashes
        $fnret = OVH::Bastion::get_hashes_from_password(password => $pass);
        $fnret or return $fnret;

        # verify that the hashes match this regex (some constructors need it)
        my $check_re = qr'^\$\d\$[a-zA-Z0-9]+\$[a-zA-Z0-9.\/]+$';
        foreach my $hash (keys %{$fnret->value}) {
            next RETRY if ($fnret->value->{$hash} && $fnret->value->{$hash} !~ $check_re);
        }

        $hashes = $fnret->value;
        last;
    }

    if (ref $hashes ne 'HASH') {
        return R('ERR_INTERNAL', msg => "Couldn't generate a valid password");
    }

    # push password in a file
    if (!-d $passhome) {
        if (!mkdir $passhome) {
            return R('ERR_INTERNAL', msg => "Couldn't create passwords directory in group home '$passhome' ($!)");
        }
        if ($context eq 'account') {
            if (my (undef, undef, $uid, $gid) = getpwnam($account)) {
                chown $uid, $gid, $passhome;
            }
        }
    }
    if (!-d $passhome) {
        return R('ERR_INTERNAL', msg => "Couldn't create passwords directory in group home");
    }
    chmod 0750, $passhome;
    if (-e $base) {

        # rotate old passwords
        unlink "$base.99";
        foreach my $i (1 .. 98) {
            my $n    = 99 - $i;
            my $next = $n + 1;
            if (-e "$base.$n") {
                osh_debug "renaming $base.$n to $base.$next";
                if (!rename "$base.$n", "$base.$next") {
                    return R('ERR_INTERNAL', msg => "Couldn't rename '$base.$n' to '$base.$next' ($!)");
                }
                if (-e "$base.$n.metadata" && !rename "$base.$n.metadata", "$base.$next.metadata") {
                    return R('ERR_INTERNAL',
                        msg => "Couldn't rename '$base.$n.metadata' to '$base.$next.metadata' ($!)");
                }
            }
        }
        osh_debug "renaming $base to $base.1";
        if (!rename "$base", "$base.1") {
            return R('ERR_INTERNAL', msg => "Couldn't rename '$base' to '$base.1' ($!)");
        }
        if (-e "$base.metadata" && !rename "$base.metadata", "$base.1.metadata") {
            return R('ERR_INTERNAL', msg => "Couldn't rename '$base.metadata' to '$base.1.metadata' ($!)");
        }
    }
    if (open(my $fdout, '>', $base)) {
        print $fdout "$pass\n";
        close($fdout);
        if ($context eq 'account') {
            if (my (undef, undef, $uid, $gid) = getpwnam($account)) {
                chown $uid, $gid, $base;
            }
        }
        chmod 0440, $base;
    }
    else {
        return R('ERR_INTERNAL', msg => "Couldn't create password file in $base ($!)");
    }

    if (open(my $fdout, '>', "$base.metadata")) {
        print $fdout "CREATED_BY=$self\nBASTION_VERSION=" . $OVH::Bastion::VERSION . "\nCREATION_TIME=" . localtime() . "\nCREATION_TIMESTAMP=" . time() . "\n";
        close($fdout);
        if ($context eq 'account') {
            if (my (undef, undef, $uid, $gid) = getpwnam($account)) {
                chown $uid, $gid, "$base.metadata";
            }
        }
        chmod 0440, "$base.metadata";
    }
    else {
        osh_warn "Couldn't create metadata file, proceeding anyway";
    }

    return R('OK', value => {context => $context, group => $shortGroup, account => $account, hashes => $hashes});
}

1;
