# vim: set filetype=perl ts=4 sw=4 sts=4 et:
package OVH::Bastion;

use common::sense;

use File::Temp;
use Fcntl qw{ :mode :DEFAULT };

sub has_piv_helper {
    my $fnret;
    $fnret = OVH::Bastion::execute(must_succeed => 1, cmd => ['yubico-piv-checker', '--version']);
    if (!$fnret) {
        return R('KO_HELPER_MISSING');
    }
    my $version;
    if ($fnret->value && $fnret->value->{'stdout'} && $fnret->value->{'stdout'}[0]) {

        # Version "0.9.9" (cb010890db0a7888b0f405008cb2dbbff0dbfc46-go1.15.3) build at 2020-11-06T13:42:13Z
        ($version) = $fnret->value->{'stdout'}[0] =~ m{Version "([^"]+)};
    }
    return R('OK', value => {version => $version});
}

sub verify_piv {
    my %params                 = @_;
    my $key                    = $params{'key'};
    my $keyCertificate         = $params{'keyCertificate'};
    my $attestationCertificate = $params{'attestationCertificate'};

    my $fnret;
    $fnret = OVH::Bastion::execute(
        must_succeed => 1,
        cmd          => ['yubico-piv-checker', $key, $attestationCertificate, $keyCertificate]
    );
    if (!$fnret || $fnret->value->{'sysret'} != 0) {
        return R('KO_INVALID_PIV', "This SSH key failed PIV verification");
    }
    my $keyPivInfo;
    eval {
        require JSON;
        $keyPivInfo = JSON::decode_json($fnret->value->{'stdout'}->[0]);
    };
    return R('OK', value => $keyPivInfo); # keyPivInfo can be undef if JSON decode failed, but the key is still a valid one
}

sub get_authorized_keys_from_file {
    my %params             = @_;
    my $file               = $params{'file'};
    my $includeInvalid     = $params{'includeInvalid'};        # also include keys that fail the sanity check
    my $includePivDisabled = $params{'includePivDisabled'};    # also include keys that are commented with # NOTPIV
    my $fnret;
    my @result;

    return R('ERR_MISSING_PARAMETER', msg => "Missing argument 'file'") if not $file;

    if (open(my $fh, '<', $file)) {
        my $i     = 0;
        my $state = 0;
        my $pivAttestationCertificate;
        my $pivKeyCertificate;
        my $info;
        while (my $line = <$fh>) {
            $i++;
            chomp $line;
            next if $line =~ /^\s*$/;    # ignore empty lines
            if ($line =~ /^# INFO: (.+)/) {
                $info = $1;
                osh_debug("[$i] got key info: $info");
                next;
            }
            elsif ($line eq '# PIV ATTESTATION CERTIFICATE:') {
                $state = 1;
                osh_debug("[$i] got a piv attestation certificate");
                next;
            }
            elsif ($line eq '# PIV KEY CERTIFICATE:') {
                $state = 2;
                osh_debug("[$i] got a piv key certificate");
                next;
            }
            elsif ($line =~ /^# (.+)/ && $state == 1) {

                # state 1: we're currently reading an attestation cert
                $pivAttestationCertificate .= $1 . "\n";
                next;
            }
            elsif ($line =~ /^# (.+)/ && $state == 2) {

                # state 2: we're currently reading a key cert
                $pivKeyCertificate .= $1 . "\n";
                next;
            }
            $state = 0;
            my $pivDisabled = 0;
            if ($includePivDisabled && $line =~ /^# NOTPIV (.+)/) {
                osh_debug("[$i] got a notpiv disabled key");
                $line        = $1;
                $pivDisabled = 1;
            }
            next if $line =~ /^\s*#/;    # ignore comments
            $fnret = OVH::Bastion::get_ssh_pub_key_info(pubKey => $line, way => 'ingress');
            if (grep { $fnret->err eq $_ } qw{ KO_NOT_A_KEY KO_PRIVATE_KEY ERR_INTERNAL }) {
                osh_debug("[$i] get_ssh_pub_key_info says: $fnret->err");
                next unless $includeInvalid;
                $fnret->{'value'} = {} if not ref $fnret->{'value'} eq 'HASH';
            }
            next if ($fnret->err eq 'KO_NOT_A_KEY' && !$fnret->value->{'line'});    # skip empty lines
            my $key = $fnret->value;

            $key->{'err'}                       = $fnret->err;
            $key->{'index'}                     = $i;
            $key->{'pivAttestationCertificate'} = $pivAttestationCertificate if $pivAttestationCertificate;
            $key->{'pivKeyCertificate'}         = $pivKeyCertificate if $pivKeyCertificate;
            $key->{'info'}                      = $info if $info;
            if ($pivAttestationCertificate && $pivKeyCertificate) {
                $fnret = OVH::Bastion::verify_piv(
                    key                    => $key->{'line'},
                    attestationCertificate => $pivAttestationCertificate,
                    keyCertificate         => $pivKeyCertificate
                );
                $key->{'isPiv'}   = ($fnret ? 1 : 0);
                $key->{'pivInfo'} = $fnret->value if $fnret;
                osh_debug("[$i] verify_piv says: " . $key->{'isPiv'});
            }
            if ($includePivDisabled && $pivDisabled) {
                $key->{'pivDisabled'} = 1;
            }
            push @result, $key;
            undef $info;
            undef $pivAttestationCertificate;
            undef $pivKeyCertificate;
        }
        close($fh);
    }
    else {
        return R('ERR_CANNOT_OPEN_FILE', msg => "Couldn't open $file ($!)");
    }
    return R('OK', value => \@result);
}

sub add_key_to_authorized_keys_file {
    my %params = @_;
    my $file   = $params{'file'};
    my $key    = $params{'key'};
    my $fnret;

    return R('ERR_MISSING_PARAMETER', msg => "Missing argument 'file'") if not $file;
    return R('KO_NO_SUCH_FILE', msg => "Specified file ($file) doesn't exist") if not -f $file;
    if (!$key) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing key param");
    }
    if (!$key->{'line'}) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing 'line' key");
    }
    $fnret = _format_key_data_to_text(key => $key);
    if ($fnret) {
        my $fh;
        if (!open($fh, '>>', $file)) {
            warn_syslog("Error while trying to open file $file for write ($!)");
            return R('ERR_CANNOT_OPEN_FILE', msg => "Couldn't open authorized_keys to append key");
        }
        else {
            print $fh $fnret->value;
            close($fh);
        }
    }
    else {
        warn_syslog("Failed to format key for authorized_keys write to '$file', aborting (" . $fnret->msg . ")");
        return R('ERR_INVALID_PARAMETER', msg => "Specified 'key' is not valid");
    }
    return R('OK');
}

sub _format_key_data_to_text {
    my %params = @_;
    my $key    = $params{'key'};

    # we're only called by other subs in this file, but let's do a quick
    # param check nevertheless
    if (!$key) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing key param");
    }
    if (!$key->{'line'}) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing 'line' key");
    }

    my $plaintext;
    if ($key->{'info'}) {
        $plaintext .= "# INFO: " . $key->{'info'} . "\n";
    }
    if ($key->{'pivAttestationCertificate'}) {
        my $toWrite = "PIV ATTESTATION CERTIFICATE:\n";
        $toWrite .= $key->{'pivAttestationCertificate'};
        $toWrite =~ s/^/# /mg;
        chomp $toWrite;
        $plaintext .= $toWrite . "\n";
    }
    if ($key->{'pivKeyCertificate'}) {
        my $toWrite = "PIV KEY CERTIFICATE:\n";
        $toWrite .= $key->{'pivKeyCertificate'};
        $toWrite =~ s/^/# /mg;
        chomp $toWrite;
        $plaintext .= $toWrite . "\n";
    }
    if ($key->{'pivDisabled'}) {
        $plaintext .= "# NOTPIV ";
    }
    $plaintext .= $key->{'line'} . "\n\n";
    return R('OK', value => $plaintext);
}

sub put_authorized_keys_to_file {
    my %params  = @_;
    my $file    = $params{'file'};
    my $data    = $params{'data'};
    my $account = $params{'account'};    # we need it to apply the proper rights
    my $fnret;

    return R('ERR_MISSING_PARAMETER', msg => "Missing argument 'file'") if not $file;
    return R('ERR_MISSING_PARAMETER', msg => "Missing argument 'data'") if not $data;
    if (ref $data ne 'ARRAY') {
        return R('ERR_INVALID_PARAMETER', msg => "Argument 'data' should be an array");
    }

    my $newFile = $file . ".new";
    my $fh;
    if (!sysopen($fh, $newFile, O_RDWR | O_CREAT | O_EXCL)) {    # sysopen: avoid symlink attacks
        warn_syslog("Error while trying to open file $newFile for write ($!)");
        return R('ERR_CANNOT_OPEN_FILE', msg => "Couldn't open authorized_keys to append key");
    }
    else {
        foreach my $key (@$data) {
            $fnret = _format_key_data_to_text(key => $key);
            if ($fnret) {
                print $fh $fnret->value;
            }
            else {
                warn_syslog(
                        "Failed to format key for authorized_keys write to '$file' for '$account', ignoring this one ("
                      . $fnret->msg
                      . ")");
            }
        }
        close($fh);
    }

    if ($account) {
        my (undef, undef, $uid, $gid) = getpwnam($account);
        chown $uid, $gid, $newFile;
    }
    chmod 0644, $newFile;

    my $backupName = $file . '.backup-' . time() . '-' . $$;
    if (!rename $file, $backupName) {
        warn_syslog("Couldn't rename old authorized keys file '$file' to '$backupName' ($!)");
        return R('ERR_RENAME_FAILED', msg => "Couldn't rename old authorized keys file, aborting");
    }
    if (!rename $newFile, $file) {
        warn_syslog("Couldn't replace authorized keys file '$file' with new version '$newFile' ($!)");
        return R('ERR_RENAME_FAILED',
            msg => "Couldn't replace authorized keys file, account left in a locked-out state!");
    }
    return R('OK');
}

sub get_ssh_pub_key_info {
    my %params = @_;
    my $pubKey = $params{'pubKey'};
    my $file   = $params{'file'};
    my $noexec = $params{'noexec'};
    my $way    = $params{'way'};
    my $fnret;

    if (not $way) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing argument way in get_ssh_pub_key_info");
    }
    if ($way ne 'ingress' && $way ne 'egress') {
        return R('ERR_INVALID_PARAMETER', msg => "Expected ingress or egress for argument way in get_ssh_pub_key_info");
    }
    $way = ucfirst($way);

    $pubKey =~ s/[\r\n]//g;

    my $mtime;
    if ($file) {
        if (open(my $fh, '<', $file)) {
            $pubKey = <$fh>;
            close($fh);
        }
        else {
            return R('ERR_CANNOT_OPEN_FILE', msg => "Couldn't open specified file ($!)");
        }
        $mtime = (stat($file))[9];
    }

    # some little sanity check
    if ($pubKey =~ /PRIVATE KEY/) {

        # n00b check
        return R('KO_PRIVATE_KEY');
    }

    my ($prefix, $typecode, $base64, $comment);
    if ($pubKey =~
        m{^\s*((\S+)\s+)?(ssh-dss|ssh-rsa|ecdsa-sha\d+-nistp\d+|ssh-ed\d+|sk-ssh-ed25519\@openssh\.com|sk-ecdsa-sha2-nistp256\@openssh\.com)\s+([a-zA-Z0-9/=+]+)(\s+(.{1,128})?)?$}
        && length($pubKey) <= 3000)
    {
        ($prefix, $typecode, $base64, $comment) = ($2, $3, $4, $6);
    }
    else {
        return R('KO_NOT_A_KEY');
    }
    my $line = "$typecode $base64";
    $prefix = '' if not defined $prefix;
    $line .= " " . $comment if $comment;
    $line = $prefix . " " . $line if $prefix;
    my @fromList;
    if ($prefix =~ /^from=["']([^ "']+)/) {
        @fromList = split /,/, $1;
    }

    # generate a uniq id f($line)
    require Digest::MD5;
    my $id = 'id' . substr(Digest::MD5::md5_hex($line), 0, 8);

    my %return = (
        prefix   => $prefix,
        typecode => $typecode,
        base64   => $base64,
        comment  => $comment,
        line     => $line,
        id       => $id,
        mtime    => $mtime,
        fromList => \@fromList,
    );

    # put that in a tempfile for ssh-keygen inspection
    if (not $noexec) {
        my $fh       = File::Temp->new(UNLINK => 1);
        my $filename = $fh->filename;
        print {$fh} $typecode . " " . $base64;
        close($fh);
        $fnret = OVH::Bastion::execute(cmd => ['ssh-keygen', '-l', '-f', $filename]);
        if ($fnret->is_err || !$fnret->value || ($fnret->value->{'sysret'} != 0 && $fnret->value->{'sysret'} != 1)) {

            # sysret == 1 means ssh-keygen didn't recognize this key, handled below.
            return R('ERR_SSH_KEYGEN_FAILED',
                msg => "Couldn't read the fingerprint of $filename (" . $fnret->msg . ")");
        }
        my $sshkeygen;
        if ($fnret->err eq 'OK') {
            $sshkeygen = $fnret->value->{'stdout'}->[0];
            chomp $sshkeygen;
        }

=cut
2048 01:c0:37:5e:b4:bf:00:b6:ef:d3:65:a7:5c:60:b1:81  john@doe (RSA)
521 af:84:cd:70:34:64:ca:51:b2:17:1a:85:3b:53:2e:52  john@doe (ECDSA)
1024 c0:4d:f7:bf:55:1f:95:59:be:7e:50:47:e4:81:c3:6a  john@doe (DSA)
256 SHA256:Yggd7VRRbbivxkdVwrdt0HpqKNylMK91nNIU+RxndTI john@doe (ED25519)
=cut

        if (defined $sshkeygen and $sshkeygen =~ /^(\d+)\s+(\S+)\s+(.+)\s+\(([A-Z0-9-]+)\)$/) {
            my ($size, $fingerprint, $comment2, $family) = ($1, $2, $3, $4);
            $return{'size'}        = $size + 0;
            $return{'fingerprint'} = $fingerprint;
            $return{'family'}      = $family;

            # check allowed algos and key size
            my $allowedSshAlgorithms = OVH::Bastion::config("allowed${way}SshAlgorithms");
            my $minimumRsaKeySize    = OVH::Bastion::config("minimum${way}RsaKeySize");
            if ($allowedSshAlgorithms && !grep { lc($return{'family'}) eq $_ } @{$allowedSshAlgorithms->value}) {
                return R('KO_FORBIDDEN_ALGORITHM', value => \%return);
            }
            if ($minimumRsaKeySize && lc($return{'family'}) eq 'rsa' && $minimumRsaKeySize->value > $return{'size'}) {
                return R('KO_KEY_SIZE_TOO_SMALL', value => \%return);
            }
            return R('OK', value => \%return);
        }
        else {
            return R('KO_NOT_A_KEY', value => \%return);
        }
    }
    else {
        # noexec is set, caller doesn't want us to call ssh-keygen
        return R('OK', value => \%return);
    }
    return R('ERR_INTERNAL', value => \%return);
}

sub is_valid_public_key {
    my %params = @_;
    my $pubKey = $params{'pubKey'};
    my $noexec = $params{'noexec'};    # don't run ssh-keygen in get_ssh_pub_key_info
    my $way    = $params{'way'};

    my $fnret = R('KO_NOT_A_KEY', msg => "This is not a key", silent => 1);

    if (defined $pubKey) {
        $pubKey =~ tr/\r\n//d;
        $fnret = OVH::Bastion::get_ssh_pub_key_info(pubKey => $pubKey, noexec => $noexec, way => $way);
    }

    if ($fnret->err eq 'KO_PRIVATE_KEY') {

        # n00b check
        $fnret->{'msg'} = <<'EOS';
HOLY SH*T, did you just paste your PRIVATE KEY?!! You have no idea what you are doing, do you? No matter what, don't do that ever again.
Hint: in 'private key', the most important word is 'private', which means, well, you know, NOT PUBLIC.
EOS
    }
    elsif ($fnret->err eq 'KO_NOT_A_KEY') {
        $fnret->{'msg'} = <<'EOS';
This doesn't look like an SSH public key, accepted formats are RSA (>= 2048 bits)
and if supported by the OS, ECDSA and Ed25519.
EOS
    }
    elsif ($fnret->err eq 'KO_VULNERABLE_KEY') {
        $fnret->{'msg'} = <<'EOS';
This key is COMPROMISED due to tue Debian OpenSSL 2008 debacle (aka CVE-2008-0166).
***********************************************
DO NOT USE THIS KEY ANYWHERE, IT IS VULNERABLE!
***********************************************
EOS
    }
    elsif ($fnret->err eq 'KO_KEY_SIZE_TOO_SMALL') {
        $fnret->{'msg'} = "This is too small. And sorry, but, yes, size DOES matter. Please re-generate a bigger key.";
    }
    elsif ($fnret->value && $fnret->value->{'family'} eq 'DSA') {
        $fnret->{'msg'} = "Wait, DSA key ? Seriously ? Hello, 90's are over ! Please re-generate a bigger key.";
    }
    elsif ($fnret->err eq 'KO_FORBIDDEN_ALGORITHM') {
        $fnret->{'msg'} = "This key generation algorithm has been disabled on this bastion, please use another one.";
    }
    elsif (not $fnret) {
        $fnret->{'msg'} = "Unknown error (" . $fnret->msg . "), please report to your sysadmin.";
    }
    else {
        if (not grep { $fnret->value->{'family'} eq $_ } qw{ RSA ECDSA ED25519 ECDSA-SK ED25519-SK }) {
            $fnret->{'err'} = 'ERR_UNKNOWN_TYPE';
            $fnret->{'msg'} =
              "Unknown family type (" . $fnret->value->{'family'} . "), please report to your sysadmin.";
        }
        elsif (not $fnret->value->{'base64'}) {
            $fnret->{'err'} = 'ERR_NOT_DECODED';
            $fnret->{'msg'} = "Unknown error parsing your key, please report to your sysadmin.";
        }
        else {
            # ok :)
        }
    }

    return $fnret;
}

sub get_from_for_user_key {
    my %params             = @_;
    my $userProvidedIpList = $params{'userProvidedIpList'} || [];    # arrayref
    my $forcedList         = $params{'forcedList'} || [];            # arrayref
    my $key                = $params{'key'};

    my $ingressKeysFrom              = OVH::Bastion::config('ingressKeysFrom');
    my $ingressKeysFromAllowOverride = OVH::Bastion::config('ingressKeysFromAllowOverride');

    if (not $ingressKeysFrom or not $ingressKeysFromAllowOverride) {
        return R('ERR_CANNOT_LOAD_CONFIGURATION');
    }

    my @ipList = @{$ingressKeysFrom->value};

    if ($ingressKeysFromAllowOverride->value and scalar @$userProvidedIpList) {
        @ipList = @$userProvidedIpList;
    }

    # if not empty, override everything by this list
    if (@$forcedList) {
        @ipList = @$forcedList;
    }

    my @ipListVerified = grep { OVH::Bastion::is_valid_ip(ip => $_, allowNetblocks => 1) } @ipList;

    my $from = '';
    if (@ipListVerified) {
        $from = sprintf('from="%s"', join(',', @ipListVerified));
    }

    # if we have a $key, modify it accordingly
    if ($key) {
        $key->{'prefix'} = $from;
        $key->{'line'}   = ($from ? $from . " " : "") . $key->{'typecode'} . " " . $key->{'base64'};
        $key->{'line'} .= " " . $key->{'comment'} if $key->{'comment'};
        $key->{'fromList'} = \@ipListVerified;
    }

    return R('OK', value => {from => $from, ipList => \@ipListVerified, key => $key});
}

sub generate_ssh_key {
    my %params         = @_;
    my $uid            = $params{'uid'};               # optional, uid to chmod key to, only if i'm root
    my $gid            = $params{'gid'};               # optional, gid to chmod key to, only if i'm root
    my $folder         = $params{'folder'};            # required, folder to put key into
    my $prefix         = $params{'prefix'};            # required, prefix of the key name
    my $name           = $params{'name'};              # optional, in key comment
    my $algo           = $params{'algo'};              # required, -t ssh-keygen param
    my $size           = $params{'size'};              # required, -b ssh-keygen param
    my $passphrase     = $params{'passphrase'};        # optional, passphrase to encrypt key with
    my $group_readable = $params{'group_readable'};    # optional, need g+r on privkey
    my $fnret;

    if (my @missingParameters = grep { not defined $params{$_} } qw{ folder prefix algo size }) {
        local $" = ', ';
        return R('ERR_MISSING_PARAMETER', msg => "Missing params @missingParameters on generate_ssh_key() call");
    }

    if (!-d $folder) {
        return R('ERR_DIRECTORY_NOT_FOUND', msg => "Specified directory not found ($folder)");
    }

    if (!-w $folder) {
        return R('ERR_DIRECTORY_NOT_WRITABLE', msg => "Specified directory can't be written to ($folder)");
    }

    if ($prefix !~ /^[A-Za-z0-9_.-]{1,64}$/) {
        return R('ERR_INVALID_PARAMETER', msg => "Specified prefix is invalid ($prefix)");
    }

    if ((defined $uid or defined $gid) and $< != 0) {
        return R('ERR_INVALID_PARAMETER', msg => "Can't specify uid or gid when not root");
    }

    $fnret = OVH::Bastion::is_allowed_algo_and_size(algo => $algo, size => $size, way => 'egress');
    $fnret or return $fnret;

    # Forge key
    $passphrase = '' if not $passphrase;
    $size       = '' if $algo eq 'ed25519';
    $name ||= $prefix;
    my $sshKeyName = $folder . '/id_' . $algo . $size . '_' . $prefix . '.' . time();

    if (-e $sshKeyName) {
        return R('ERR_KEY_ALREADY_EXISTS', msg => "Can't forge key, generated name already exists");
    }

    my $bastionName = OVH::Bastion::config('bastionName');
    if (!$bastionName) {
        return R('ERR_CANNOT_LOAD_CONFIGURATION');
    }
    $bastionName = $bastionName->value;

    my @command = ('ssh-keygen');
    push @command, '-t', $algo;
    push @command, '-b', $size if $size;
    push @command, '-N', $passphrase;
    push @command, '-f', $sshKeyName;
    push @command, '-C', "$name\@$bastionName:" . time();

    $fnret = OVH::Bastion::execute(cmd => \@command, noisy_stderr => 1);
    $fnret->err eq 'OK'
      or return R('ERR_SSH_KEYGEN_FAILED', msg => "Error while generating group key (" . $fnret->msg . ")");

    my %files = (
        $sshKeyName          => ($group_readable ? oct(440) : oct(400)),
        $sshKeyName . '.pub' => oct(444),
    );
    while (my ($file, $chmod) = each(%files)) {
        if (not -e $file) {
            return R('ERR_SSH_KEYGEN_FAILED', msg => "Couldn't find generated key ($file)");
        }
        chown $uid, -1, $file if defined $uid;
        chown -1, $gid, $file if defined $gid;
        chmod $chmod, $file;
    }
    return R('OK', value => {file => $sshKeyName});
}

# return the list of bastion's ips
sub get_bastion_ips {
    my %params = @_;
    my $fnret;

    my $egressKeysFrom = OVH::Bastion::config('egressKeysFrom');
    if (!$egressKeysFrom) {
        return R('ERR_CANNOT_LOAD_CONFIGURATION');
    }
    $egressKeysFrom = $egressKeysFrom->value;

    my @ips;
    if (not $egressKeysFrom or @$egressKeysFrom == 0) {
        $fnret = OVH::Bastion::execute(cmd => ['hostname', '--all-ip-addresses']);
        $fnret
          or return R('ERR_HOSTNAME_FAILED', msg => "Couldn't determine bastion IP addresses, please fix the config");
        @ips = split(/\s+/, join(' ', @{$fnret->value->{'stdout'} || []}));
    }
    else {
        @ips = @$egressKeysFrom;
    }

    my @checkedIps = grep { OVH::Bastion::is_valid_ip(ip => $_, allowNetblocks => 1) } @ips;

    return R('OK', value => \@checkedIps);
}

sub get_supported_ssh_algorithms_list {
    my %params = @_;
    my $way    = $params{'way'};    # ingress or egress
    state @cached_runtime_list;

    if (not $way) {
        return R('ERR_MISSING_PARAMETER', msg => 'Missing required argument way in get_supported_ssh_algorithms_list');
    }
    if ($way ne 'ingress' && $way ne 'egress') {
        return R('ERR_INVALID_PARAMETER',
            msg => 'Expected way argument of ingress or egress in get_supported_ssh_algorithms_list');
    }
    $way = ucfirst($way);

    # first, filter by config
    my $fnret = OVH::Bastion::config("allowed${way}SshAlgorithms");
    $fnret or return $fnret;
    my @allowedList = @{$fnret->value};

    # other vary, detect this by running openssh client -V
    my @supportedList;
    if (@cached_runtime_list) {
        @supportedList = @cached_runtime_list;
    }
    else {
        push @supportedList, 'rsa';    # rsa is always supported
        $fnret = OVH::Bastion::execute(cmd => [qw{ ssh -V }]);
        if ($fnret) {
            foreach (@{$fnret->value->{'stdout'} || []}, @{$fnret->value->{'stderr'} || []}) {
                if (/OpenSSH_(\d+\.\d+)/) {
                    my $version = $1;
                    push @supportedList, 'ecdsa'      if ($version gt "5.7");
                    push @supportedList, 'ed25519'    if ($version gt "6.5");
                    push @supportedList, 'ecdsa-sk'   if ($version gt "8.2");
                    push @supportedList, 'ed25519-sk' if ($version gt "8.2");
                    @cached_runtime_list = @supportedList;
                    last;
                }
            }
        }
    }

    # then, take the union of both
    my @list;
    foreach my $algo (@supportedList) {
        push @list, $algo if grep { $_ eq $algo } @allowedList;
    }
    return R('OK', value => \@list);
}

sub is_allowed_algo_and_size {
    my %params = @_;
    my $algo   = lc($params{'algo'});
    my $size   = $params{'size'};
    my $way    = $params{'way'};
    my $fnret;

    if (not $algo) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing parameter 'algo'");
    }

    $fnret = OVH::Bastion::get_supported_ssh_algorithms_list(way => $way);
    $fnret or return $fnret;
    my @supportedList = @{$fnret->value};

    if (not grep { $algo eq $_ } @supportedList) {
        return R('KO_NOT_SUPPORTED',
            msg => "The algorithm '$algo' is not supported (or disabled) for $way on this bastion");
    }

    if ($algo eq 'rsa') {
        $algo  = 'rsa';                                             # untaint
        $way   = ucfirst($way);
        $fnret = OVH::Bastion::config("minimum${way}RsaKeySize");
        $fnret or return $fnret;
        if ($size < $fnret->value) {
            return R('KO_KEY_SIZE_TOO_SMALL',
                    msg => "For the selected algorithm, minimum configured key size for $way by policy is "
                  . $fnret->value
                  . " bits");
        }
    }
    elsif ($algo eq 'ecdsa') {
        $algo = 'ecdsa';                                            # untaint
        if (not grep { $size eq $_ } qw{ 256 384 521 }) {
            return R('KO_KEY_SIZE_INVALID', msg => "For the selected algorithm, valid key sizes are 256, 384, 521");
        }
    }
    elsif ($algo eq 'ed25519') {
        $algo = 'ed25519';                                          # untaint
        if ($size && $size ne '256') {
            return R('KO_KEY_SIZE_INVALID', msg => "For the selected algorithm, key size must be 256");
        }
        $size = 256;
    }
    ($size) = $size =~ /^(\d+)$/;                                   # untaint
    return R('OK', value => {algo => $algo, size => $size});
}

sub is_valid_fingerprint {
    my %params      = @_;
    my $fingerprint = $params{'fingerprint'};

    if (not $fingerprint) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing parameter 'fingerprint'");
    }
    elsif ($fingerprint =~ /^(([0-9a-f]{2}:){15}[0-9a-f]{2}$)/i) {
        return R('OK', value => {type => 'md5', fingerprint => lc($1)});
    }
    elsif ($fingerprint =~ /^(SHA256:[\-\/a-z0-9+=]{43})$/i) {
        return R('OK', value => {type => 'sha256', fingerprint => $1});
    }
    return R('ERR_INVALID_PARAMETER',
        msg =>
          "Specified fingerprint is invalid, expected a key fingerprint of the form 12:34:56:78:9a:bc:de:f0:12:34:56:78:9a:bc:de:f0 or SHA256:base64fingerprint"
    );
}

sub print_public_key {
    my %params    = @_;
    my $key       = $params{'key'};
    my $id        = $params{'id'};
    my $err       = $params{'err'} || 'OK';
    my $nokeyline = $params{'nokeyline'};

    require Term::ANSIColor;

    # if id is passed directly, this is a key from an authkeys file, the id is the line number
    # otherwise, we should have an id within the key, it depends on $key->line, usually this is a key from a .pub file (no line number)
    if (!$id && $key->{'id'}) {
        $id = $key->{'id'};
    }

    my $line = $key->{'line'};
    if ($key->{'base64'}) {
        $line = sprintf("%s%s %s %s",
            $key->{'prefix'} ? $key->{'prefix'} . ' ' : '',
            $key->{'typecode'}, $key->{'base64'}, $key->{'comment'});
    }

    if ($key->{'info'}) {
        my $info = $key->{'info'};

        # parse data from 'info' and print it nicely
        my ($name) = $info =~ m{NAME="([^"]+)};
        osh_info(Term::ANSIColor::colored("name: " . $name, 'cyan'));

        my ($by)      = $info =~ m{ADDED_BY=(\S+)};
        my ($when)    = $info =~ m{DATETIME=(\S+)};
        my ($version) = $info =~ m{VERSION=(\S+)};
        my ($session) = $info =~ m{UNIQID=(\S+)};
        osh_info(
            Term::ANSIColor::colored(
                sprintf(
                    "info: added by %s at %s in session %s running v%s",
                    $by      || '(?)',
                    $when    || '(?)',
                    $session || '(?)',
                    $version || '(?)'
                ),
                'cyan'
            )
        );
    }

    if ($key->{'isPiv'}) {
        osh_info(
            Term::ANSIColor::colored(
                "PIV: "
                  . "TouchPolicy="
                  . $key->{'pivInfo'}{'Yubikey'}{'TouchPolicy'}
                  . " PinPolicy="
                  . $key->{'pivInfo'}{'Yubikey'}{'PinPolicy'}
                  . " SerialNo="
                  . $key->{'pivInfo'}{'Yubikey'}{'SerialNumber'}
                  . " Firmware="
                  . $key->{'pivInfo'}{'Yubikey'}{'FirmwareVersion'},
                'magenta'
            )
        );
    }

    osh_info(
        sprintf(
            "%s%s (%s-%d) [%s]%s",
            Term::ANSIColor::colored('fingerprint: ', 'green'),
            $key->{'fingerprint'} || 'INVALID_FINGERPRINT',
            $key->{'family'}      || 'INVALID_FAMILY',
            $key->{'size'},
            defined $id ? "ID = $id" : POSIX::strftime("%Y/%m/%d", localtime($key->{'mtime'})),
            $err eq 'OK' ? '' : ' ***<<' . $err . '>>***',
        )
    );

    if (!$nokeyline) {
        osh_info(Term::ANSIColor::colored('keyline', 'red') . ' follows, please copy the *whole* line:');
        print($line. "\n");
    }
    osh_info(' ');
    return;
}

sub account_ssh_config_get {
    my %params  = @_;
    my $account = $params{'account'};

    my $fnret;

    $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $account);
    $fnret or return $fnret;

    $account = $fnret->value->{'account'};
    my $dir = $fnret->value->{'dir'};

    # read file content. If it doesn't exist, not a problem
    my $sshconfig_data;
    if (open(my $sshconfig_fd, '<', "$dir/.ssh/config")) {
        local $/ = undef;
        $sshconfig_data = <$sshconfig_fd>;
        close($sshconfig_fd);

        # ensure we don't have any Host or Match directive.
        # If we do, bail out: the file has been modified manually by someone
        if ($sshconfig_data =~ /^\s*(Host|Match)\s/mi) {
            return R('ERR_FILE_LOCALLY_MODIFIED',
                msg =>
                  "The ssh configuration of this account has been modified manually. As we can't guarantee modifying it won't cause adverse effects, modification aborted."
            );
        }

        # remove empty lines & comments
        my @lines = grep { /./ && !/^\s*#/ } split(/\n/, $sshconfig_data);

        # lowercase all keys
        my %keys = map { m/^(\S+)\s+(.+)$/ ? (lc($1) => $2) : () } @lines;

        return R('OK_EMPTY') if !%keys;
        return R('OK', value => \%keys);
    }

    return R($! =~ /permission|denied/i ? 'ERR_ACCESS_DENIED' : 'OK_EMPTY');
}

sub account_ssh_config_set {
    my %params  = @_;
    my $account = $params{'account'};
    my $key     = $params{'key'};
    my $value   = $params{'value'};     # if undef, remove $key

    my $fnret;

    if (not defined $key) {
        return R('ERR_MISSING_PARAMETER', value => "Expected 'key' parameter");
    }
    $key = lc($key);

    $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $account);
    $fnret or return $fnret;

    $account = $fnret->value->{'account'};
    my $dir = $fnret->value->{'dir'};

    # read file content
    $fnret = OVH::Bastion::account_ssh_config_get(account => $account);
    $fnret or return $fnret;
    my %keys = %{$fnret->value()};

    # remove key if it already exists
    delete $keys{$key};

    # add new key+value
    $keys{$key} = $value if defined $value;

    # write modified file. to avoid symlink attacks, remove it then reopen it with sysopen()
    unlink("$dir/.ssh/config");
    if (sysopen(my $sshconfig_fd, "$dir/.ssh/config", O_RDWR | O_CREAT | O_EXCL)) {
        foreach my $keyWrite (sort keys %keys) {
            print $sshconfig_fd $keyWrite . " " . $keys{$keyWrite} . "\n";
        }
        close($sshconfig_fd);
    }
    else {
        return R('ERR_CANNOT_OPEN_FILE', msg => "Couldn't open ssh config file for write: $!");
    }

    # ensure file is readable by everyone (and mainly the account itself)
    if (!chmod 0644, "$dir/.ssh/config") {
        return R('ERR_CANNOT_CHMOD', msg => "Couldn't ensure the ssh config file perms are correct");
    }

    return R('OK');
}

# action=enable: will comment all non-PIV keys from the account's authorized_keys2,
# by calling get_authorized_keys_from_file() with the includePivDisabled param at 1,
# so we also get the commented PIV keys if we already have some, then we comment all
# non-PIV keys, and put them back with put_authorized_keys_to_file()
#
# action=disable: will uncomment all non-PIV keys from the account's authorized_keys2,
# by calling get_authorized_keys_from_file() with the includePivDisabled param at 1,
# so we also get the commented PIV keys, then we uncomment them all and put them back
# with put_authorized_keys_to_file()
sub ssh_ingress_keys_piv_apply {
    my %params  = @_;
    my $account = $params{'account'};
    my $action  = $params{'action'};

    my $fnret;

    if (not $action) {
        return R('ERR_MISSING_PARAMETER', msg => "Argument 'action' is required");
    }
    $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $account);
    $fnret or return $fnret;

    $account = $fnret->value->{'account'};
    my $dir = $fnret->value->{'dir'};

    $fnret = OVH::Bastion::get_authorized_keys_from_file(
        account            => $account,
        file               => $dir . '/' . OVH::Bastion::AK_FILE(),
        includePivDisabled => 1
    );
    $fnret or return $fnret;

    my $keys = $fnret->value();

    my $message;
    if ($action eq 'disable') {

        # re-enable any non-PIV key
        $_->{'pivDisabled'} = 0 for @$keys;
        $message = (scalar @$keys) . " ingress keys are now enabled";
    }
    elsif ($action eq 'enable') {

        # disable all non-PIV and non-verified PIV keys
        my $nbPiv = 0;
        foreach my $key (@$keys) {

            $key->{'pivDisabled'} = 0;
            if ($key->{'pivAttestationCertificate'} && $key->{'pivKeyCertificate'}) {

                # remove any commented PIV marker for the verify_piv()
                my $keyline = $key->{'line'};
                $keyline =~ s/^# NOTPIV //;
                $fnret = OVH::Bastion::verify_piv(
                    key                    => $keyline,
                    attestationCertificate => $key->{'pivAttestationCertificate'},
                    keyCertificate         => $key->{'pivKeyCertificate'}
                );
                if (!$fnret) {

                    # PIV verify failed, disable this key
                    $key->{'pivDisabled'} = 1;
                }
                else {
                    $nbPiv++;
                }
            }
            else {
                # no certificates => not PIV, disable this key
                $key->{'pivDisabled'} = 1;
            }
        }
        $message = "$nbPiv PIV keys are now enabled out of " . (scalar @$keys) . " total keys";
    }
    else {
        return R('ERR_INVALID_PARAMETER', msg => "Argument 'action' must be either 'enable' or 'disable'");
    }

    $fnret = OVH::Bastion::put_authorized_keys_to_file(
        account => $account,
        file    => $dir . '/' . OVH::Bastion::AK_FILE(),
        data    => $keys
    );
    $fnret or return $fnret;

    OVH::Bastion::syslogFormatted(
        severity => 'info',
        type     => 'account',
        fields   => [
            [action  => 'modify'],
            [account => $account],
            [item    => 'piv_ingress_keys_apply'],
            [new     => $action],
            [comment => $message]
        ]
    );

    return R('OK');
}

# return the effective PIV ingress keys policy for this account,
# can be either enabled or disabled, depending on 3 config params,
# ingressRequirePIV (global setting), the account's own potential
# ingress PIV policy and the potential account grace period, both
# set by accountPIV
sub is_effective_piv_account_policy_enabled {
    my %params  = @_;
    my $account = $params{'account'};
    my $fnret;

    $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $account);
    $fnret or return $fnret;

    my $accountPolicy;
    $fnret = OVH::Bastion::account_config(
        account => $account,
        public  => 1,
        key     => OVH::Bastion::OPT_ACCOUNT_INGRESS_PIV_POLICY()
    );
    if (!$fnret) {

        # if file is not found, it means the account PIV policy is the default one.
        # this is the same as having its config set explicitly to 'default'
        $accountPolicy = 'default';
    }
    else {
        $accountPolicy = $fnret->value;

        # previously, 'enforce' was stored as 'yes'
        $accountPolicy = 'enforce' if $accountPolicy eq 'yes';
    }

    # if account policy is set to never, then the global policy doesn't matter
    return R('KO_DISABLED') if $accountPolicy eq 'never';

    # if account is currently in a non-expired grace period, then the global policy doesn't matter either
    $fnret = OVH::Bastion::account_config(
        account => $account,
        public  => 1,
        key     => OVH::Bastion::OPT_ACCOUNT_INGRESS_PIV_GRACE()
    );
    my $expiry = $fnret->value || 0;
    my $human  = OVH::Bastion::duration2human(seconds => ($expiry - time()))->value;
    return R('KO_DISABLED', msg => "$account is still in grace period for " . $human->{'human'}) if (time() < $expiry);

    # if account is set to enforce, and it's not in grace (handled above), then it's enabled
    return R('OK_ENABLED', msg => "$account policy is set to enforce") if $accountPolicy eq 'enforce';

    # otherwise the global policy applies
    return OVH::Bastion::config('ingressRequirePIV')->value()
      ? R('OK_ENABLED',  msg => "inherits the globally enabled policy")
      : R('KO_DISABLED', msg => "inherits the globally disabled policy");
}

# Deduces from the bastion config what algorithms are accepted.
sub print_accepted_key_algorithms {
    my %params   = @_;
    my $way      = $params{'way'};
    my $fido     = ($params{'fido'} // 1);
    my $generate = ($params{'generate'} // 1);
    my $fnret;

    my @algoList;
    $fnret = OVH::Bastion::get_supported_ssh_algorithms_list(way => $way);
    if (!$fnret && $ENV{'PLUGIN_DOCGEN'}) {
        @algoList = qw{ rsa ecdsa ed25519 };
        push @algoList, qw{ ecdsa-sk ed25519-sk } if ($way eq 'ingress');
    }
    elsif (!$fnret) {
        return $fnret;
    }
    else {
        @algoList = @{$fnret->value};
    }

    my ($X, $o) = qw{ # . };
    if (OVH::Bastion::can_use_utf8() && OVH::Bastion::config('fanciness')->value eq 'full') {
        $X = "\N{U+2713}";
        $o = " ";
    }

    require POSIX;
    my $bastionName = OVH::Bastion::config('bastionName')->value;
    my $appName     = "ssh:" . POSIX::strftime("%Y-%m-%d.", localtime()) . substr($bastionName, 0, 24);

    my $hasFido = 0;

    my $prefix = "";
    osh_info("A quick overview of the different algorithms:");
    if ($ENV{'PLUGIN_DOCGEN'}) {
        $prefix = "   ";
        osh_info("\n.. code-block:: none\n");
    }

    if ($fido && grep { 'ed25519-sk' eq $_ } @algoList) {
        osh_info("${prefix}FIDO2 Ed25519: robustness[$X$X$X] speed[$X$X$X]"
              . ($generate ? ", generate: `ssh-keygen -t ed25519-sk -O resident -O application=$appName" : ""));
        $hasFido = 1;
    }
    if (grep { 'ed25519' eq $_ } @algoList) {
        osh_info("${prefix}Ed25519      : robustness[$X$X$X] speed[$X$X$X]"
              . ($generate ? ", generate: `ssh-keygen -t ed25519'" : ""));
    }
    if ($fido && grep { 'ecdsa-sk' eq $_ } @algoList) {
        osh_info("${prefix}FIDO2 ECDSA  : robustness[$X$X$o] speed[$X$X$X]"
              . ($generate ? ", generate: `ssh-keygen -t ecdsa-sk -b 521 -O resident -O application=$appName" : ""));
        $hasFido = 1;
    }
    if (grep { 'ecdsa' eq $_ } @algoList) {
        osh_info("${prefix}ECDSA        : robustness[$X$X$o] speed[$X$X$X]"
              . ($generate ? ", generate: `ssh-keygen -t ecdsa -b 521'" : ""));
    }
    if (grep { 'rsa' eq $_ } @algoList) {
        osh_info("${prefix}RSA          : robustness[$X$o$o] speed[$X$o$o]"
              . ($generate ? ", generate: `ssh-keygen -t rsa -b 4096'" : ""));
    }

    if ($hasFido) {
        osh_info("\nNote that FIDO2 algorithms require a FIDO2-compatible hardware Security Key.");
    }
    osh_info("\nThis table is meant as a quick cheat-sheet, you're warmly advised to do");
    osh_info("your own research, as other constraints may apply to your environment.");
    return;
}

1;
