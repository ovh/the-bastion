# vim: set filetype=perl ts=4 sw=4 sts=4 et:
package OVH::Bastion;

use common::sense;
use Digest::SHA qw{ hmac_sha256 };

# PBKDF2 like - HMAC-SHA256 - return 256 bits key
sub _get_key_from_password {
    my %params   = @_;
    my $password = $params{'password'};

    if (not $password) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing parameter 'password'");
    }

    my $salt       = 'JPYWrLpoXcXFA46m9DUI5z02SqUd2baG';
    my $iterations = 10_000;

    my $hash   = hmac_sha256($salt . pack('N', 0), $password);
    my $result = $hash;

    for my $iter (2 .. $iterations) {
        $hash = hmac_sha256($hash, $password);
        $result ^= $hash;
    }

    return R('OK', value => $result);
}

# generate a fixed salt given (a password AND a nonce AND a salt len)
sub _get_salt {
    my %params   = @_;
    my $password = $params{'password'};
    my $nonce    = $params{'nonce'} || $password;
    my $len      = $params{'len'}   || 4;

    if ($len > 16) {
        return R('ERR_INVALID_PARAMETER', msg => "Expected a len <= 16");
    }

    # get a derived key from what we've been given
    my $fnret = _get_key_from_password(password => $password . $nonce . $len . $nonce . $password);
    $fnret or return $fnret;

    # then generate the salt from the key
    my @u16 = unpack('S*', $fnret->value);
    my $s;
    foreach my $i (1 .. $len) {
        my $r = $u16[$i - 1] % (10 + 26 + 26);
        if    ($r < 10) { $s .= $r }
        elsif ($r < 36) { $s .= chr($r - 10 + ord('a')) }
        else            { $s .= chr($r - 36 + ord('A')) }
    }
    return R('OK', value => $s);
}

sub get_hashes_from_password {
    my %params   = @_;
    my $password = $params{'password'};

    if (not $password) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing parameter 'password'");
    }

    my %ret;
    $ret{'md5crypt'} =
      crypt($password, '$1$' . _get_salt(password => $password, nonce => '$1', len => 4)->value . '$');
    $ret{'sha256crypt'} =
      crypt($password, '$5$' . _get_salt(password => $password, nonce => '$5', len => 8)->value . '$');
    $ret{'sha512crypt'} =
      crypt($password, '$6$' . _get_salt(password => $password, nonce => '$6', len => 8)->value . '$');

    # some OSes have a broken crypt() that doesn't generate invalid hashes, undef those
    $ret{'sha256crypt'} = undef if $ret{'sha256crypt'} !~ m{^\$5\$};
    $ret{'sha512crypt'} = undef if $ret{'sha512crypt'} !~ m{^\$6\$};

    # get fixed (and untainted) salts for type8 and type9
    my ($type8salt) = _get_salt(password => $password, nonce => '$8', len => 14)->value =~ m{^([a-zA-Z0-9./]+)$};
    my ($type9salt) = _get_salt(password => $password, nonce => '$9', len => 14)->value =~ m{^([a-zA-Z0-9./]+)$};

    # if we have the-bastion-mkhash-helper, use it
    my $fnret = OVH::Bastion::execute(
        cmd          => ['the-bastion-mkhash-helper', '--salt-type8', $type8salt, '--salt-type9', $type9salt],
        stdin_str    => $password,
        must_succeed => 1
    );
    if ($fnret && $fnret->value && $fnret->value->{'stdout'}) {
        require JSON;
        my $hashes = eval { JSON::decode_json(join("\n", @{$fnret->value->{'stdout'}})); };
        if ($@) {
            warn_syslog("Couldn't parse the-bastion-mkhash-helper output: $@");
        }
        elsif ($hashes) {
            $ret{'type8'} = $hashes->{'Type8'} if $hashes->{'Type8'};
            $ret{'type9'} = $hashes->{'Type9'} if $hashes->{'Type9'};
        }
    }

    return R('OK', value => \%ret);
}

sub get_password_file {
    my %params  = @_;
    my $context = $params{'context'};
    my $group   = $params{'group'};
    my $account = $params{'account'};

    my $fnret;

    if ($context eq 'group') {
        $fnret = OVH::Bastion::is_valid_group_and_existing(group => $group, groupType => "key");
        $fnret or return $fnret;

        $group = $fnret->value->{'group'};
        my $shortGroup = $fnret->value->{'shortGroup'};
        return R('OK', value => "/home/$group/pass/$shortGroup");
    }
    elsif ($context eq 'account') {
        $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $account);
        $fnret or return $fnret;

        $account = $fnret->value->{'account'};
        return R('OK', value => "/home/$account/pass/$account");
    }
    else {
        return R('ERR_INVALID_PARAMETER', msg => "Expected a context of 'group' or 'account'");
    }
}

sub get_hashes_list {
    my %params  = @_;
    my $context = $params{'context'};
    my $group   = $params{'group'};
    my $account = $params{'account'};

    my $fnret;

    $fnret = OVH::Bastion::get_password_file(context => $context, group => $group, account => $account);
    $fnret or return $fnret;

    my $passfile = $fnret->value;

    my @ret;
    foreach my $inc ('', 1 .. 99) {
        my $currentname = $passfile;
        $currentname .= ".$inc" if (length($inc) > 0);
        if (open(my $fdin, '<', $currentname)) {
            my %current;
            my $pass = <$fdin>;
            close($fdin);
            chomp $pass;

            $fnret = OVH::Bastion::get_hashes_from_password(password => $pass);
            undef $pass;
            $fnret or return $fnret;

            my $desc = (length($inc) == 0 ? "Current password" : "Fallback password $inc");

            my %metadata;
            if (open(my $metadatafd, '<', "$currentname.metadata")) {
                local $_ = undef;
                while (<$metadatafd>) {
                    chomp;
                    m{^([A-Z0-9_-]+)=(.+)$} or next;
                    my ($key, $val) = (lc($1), $2);
                    $metadata{$key} = $val;

                    # int-ize if it's an int, for json:
                    $metadata{$key} += 0 if ($val =~ /^\d+$/);
                }
                close($metadatafd);
            }
            if (%metadata) {
                $current{'metadata'} = \%metadata;
                $desc .= " created at $metadata{'creation_time'} by $metadata{'created_by'}";
            }

            $current{'description'} = $desc;
            $current{'hashes'}      = $fnret->value;

            push @ret, \%current;
        }
        else {
            last;
        }
    }

    return R('OK', value => \@ret);
}

sub is_valid_hash {
    my %params = @_;
    my $hash   = $params{'hash'};

    if (not $hash) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing parameter 'hash'");
    }
    elsif ($hash =~ /^(\$1\$[a-zA-Z0-9]+\$[a-zA-Z0-9\.\/]+)$/) {
        return R('OK', value => {type => 'md5crypt', hash => $1});
    }
    elsif ($hash =~ /^(\$5\$[a-zA-Z0-9]+\$[a-zA-Z0-9\.\/]+)$/) {
        return R('OK', value => {type => 'sha256crypt', hash => $1});
    }
    elsif ($hash =~ /^(\$6\$[a-zA-Z0-9]+\$[a-zA-Z0-9\.\/]+)$/) {
        return R('OK', value => {type => 'sha512crypt', hash => $1});
    }
    return R('ERR_INVALID_PARAMETER',
        msg =>
          'Specified hash is invalid, examples of hashes: $1$Pl44$BEyG04AjjH0TRhLuhAs4A1 $5$8BzocSDA$Hu/FdA/KrFe9HFWvXL4F5csJFxV1HlrLt4c3AOac5N5'
    );
}

1;
