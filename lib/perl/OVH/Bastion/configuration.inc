# vim: set filetype=perl ts=4 sw=4 sts=4 et:
package OVH::Bastion;

use common::sense;

use JSON;
use Fcntl qw{ :mode :DEFAULT };

sub load_configuration_file {
    my %params = @_;
    my $file   = $params{'file'};

    # if $secure is set, won't load the file if it's not writable by root only
    # it won't allow symlinks either
    my $secure = $params{'secure'};

    if ($secure) {
        my @stat = lstat($file);
        if (@stat) {
            if ($stat[4] != 0 or $stat[5] != 0) {
                return R('ERR_SECURITY_VIOLATION', msg => "Configuration file ($file) is not owned by root, report to your sysadmin.");
            }
            if (!S_ISREG($stat[2])) {
                return R('ERR_SECURITY_VIOLATION', msg => "Configuration file ($file) is not a regular file, report to your sysadmin.");
            }
            if (S_IMODE($stat[2]) & S_IWOTH) {
                return R('ERR_SECURITY_VIOLATION', msg => "Configuration file ($file) is world-writable, report to your sysadmin.");
            }
        }

        # no @stat ? file doesn't exist, we'll error just below
    }

    return OVH::Bastion::json_load(file => $file);
}

sub main_configuration_directory {
    if (!-d "/etc/bastion" && -d "/usr/local/etc/bastion") {

        # if this dir exists and /etc/bastion doesn't, use /usr/local
        return "/usr/local/etc/bastion";
    }
    elsif (!-d "/etc/bastion" && -d "/usr/pkg/etc/bastion") {

        # if this dir exists and /etc/bastion doesn't, use /usr/local
        return "/usr/pkg/etc/bastion";
    }

    # use /etc in all other cases
    return "/etc/bastion";
}

my $_cache_config = undef;

sub load_configuration {
    my %params    = @_;
    my $mock_data = $params{'mock_data'};

    if (defined $mock_data && !OVH::Bastion::is_mocking()) {

        # if we're overriding configuration with mock_data without being in mocking mode, we have a problem
        die("Attempted to load_configuration() with mock_data without being in mocking mode");
    }

    if (ref $_cache_config eq 'HASH') {
        return R('OK', value => $_cache_config);
    }

    my $C;
    if (!$mock_data) {
        my $file = OVH::Bastion::main_configuration_directory() . "/bastion.conf";

        # check that file exists and is readable
        if (not -r $file) {
            return R('ERR_CANNOT_LOAD_CONFIGURATION', msg => "Configuration file $file does not exist or is not readable");
        }

        $C = OVH::Bastion::load_configuration_file(file => $file, secure => 1);
        $C or return $C;
        $C = $C->value;
    }
    else {
        $C = $mock_data;
    }

    # define deprecated <=> new key names association
    my %new2old = qw(
      accountCreateDefaultPersonalAccesses accountCreateDefaultPrivateAccesses
      adminAccounts adminLogins
      allowedIngressSshAlgorithms allowedSshAlgorithms
      allowedEgressSshAlgorithms allowedSshAlgorithms
      bastionCommand cacheCommand
      bastionName cacheName
      ingressKeysFrom ipWhiteList
      ingressKeysFromAllowOverride ipWhiteListAllowOverride
      minimumIngressRsaKeySize minimumRsaKeySize
      minimumEgressRsaKeySize minimumRsaKeySize
      egressKeysFrom personalKeyFrom
    );

    # if we're missing some new key names, look for old keys and take their value
    while (my ($new, $old) = each %new2old) {
        $C->{$new} //= $C->{$old};
    }

    # now validate, lint and normalize the conf

    $C->{'bastionName'} ||= 'fix-my-config-please-missing-bastion-name';

    $C->{'bastionCommand'} ||= "ssh ACCOUNT\@HOSTNAME -t -- ";

    $C->{'defaultLogin'} = "" if (not defined $C->{'defaultLogin'});
    $C->{'defaultLogin'} =~ s/[^a-zA-Z0-9_-]//g;

    $C->{'accountUidMin'} = 2000 if (not defined $C->{'accountUidMin'} or $C->{'accountUidMin'} !~ /^\d+$/);
    $C->{'accountUidMin'} > 100       or $C->{'accountUidMin'} = 100;
    $C->{'accountUidMin'} < 999999999 or $C->{'accountUidMin'} = 999999999;    # usually 2^31-2 but well...

    $C->{'accountUidMax'} = 99999 if (not defined $C->{'accountUidMax'} or $C->{'accountUidMax'} !~ /^\d+$/);
    $C->{'accountUidMax'} > 100       or $C->{'accountUidMax'} = 100;
    $C->{'accountUidMax'} < 999999999 or $C->{'accountUidMax'} = 999999999;    # usually 2^31-2 but well...

    $C->{'accountUidMax'} = $C->{'accountUidMin'} + 1000 if ($C->{'accountUidMin'} + 1000 > $C->{'accountUidMax'});

    $C->{'ttyrecGroupIdOffset'} = 100000 if (not defined $C->{'ttyrecGroupIdOffset'} or $C->{'ttyrecGroupIdOffset'} !~ /^\d+$/);
    $C->{'ttyrecGroupIdOffset'} < 999999999 or $C->{'ttyrecGroupIdOffset'} = 999999999;
    if ($C->{'ttyrecGroupIdOffset'} < $C->{'accountUidMax'} - $C->{'accountUidMin'}) {

        # avoid overlap
        $C->{'ttyrecGroupIdOffset'} = ($C->{'accountUidMax'} - $C->{'accountUidMin'}) + 1;
    }

    foreach my $key (qw{ allowedIngressSshAlgorithms allowedIngressSshAlgorithms }) {
        $C->{$key} = ['rsa', 'ecdsa', 'ed25519'] if (not defined $C->{$key} or ref $C->{$key} ne 'ARRAY');
    }

    foreach my $key (qw{ Ingress Egress }) {
        my $minkey = "minimum${key}RsaKeySize";
        my $maxkey = "maximum${key}RsaKeySize";
        $C->{$minkey} = 2048 if (not defined $C->{$minkey} or $C->{$minkey} !~ /^\d+$/);
        $C->{$minkey} >= 1024  or $C->{$minkey} = 1024;
        $C->{$minkey} <= 16384 or $C->{$minkey} = 16384;
        $C->{$maxkey} = 8192 if (not defined $C->{$maxkey} or $C->{$maxkey} !~ /^\d+$/);
        $C->{$maxkey} >= 1024  or $C->{$maxkey} = 1024;
        $C->{$maxkey} <= 32768 or $C->{$maxkey} = 32768;
        $C->{$minkey} = $C->{$maxkey} if ($C->{$minkey} > $C->{$maxkey});    # ensure min <= max
    }

    $C->{'defaultAccountEgressKeyAlgorithm'} ||= 'rsa';
    if (!grep { $C->{'defaultAccountEgressKeyAlgorithm'} eq $_ } qw{ rsa ecdsa ed25519 }) {
        $C->{'defaultAccountEgressKeyAlgorithm'} = 'rsa';
    }

    $C->{'defaultAccountEgressKeySize'} = 0 if $C->{'defaultAccountEgressKeySize'} !~ /^\d+$/;
    if ($C->{'defaultAccountEgressKeyAlgorithm'} eq 'rsa') {
        $C->{'defaultAccountEgressKeySize'} ||= 4096;
        $C->{'defaultAccountEgressKeySize'} = 1024  if $C->{'defaultAccountEgressKeySize'} < 1024;
        $C->{'defaultAccountEgressKeySize'} = 32768 if $C->{'defaultAccountEgressKeySize'} > 32768;
    }
    elsif ($C->{'defaultAccountEgressKeyAlgorithm'} eq 'ecdsa') {
        $C->{'defaultAccountEgressKeySize'} ||= 521;
        if (!grep { $C->{'defaultAccountEgressKeySize'} eq $_ } qw{ 256 384 521 }) {
            $C->{'defaultAccountEgressKeySize'} = 521;
        }
    }
    elsif ($C->{'defaultAccountEgressKeyAlgorithm'} eq 'ed25519') {
        $C->{'defaultAccountEgressKeySize'} = 256;
    }

    $C->{'sshClientDebugLevel'} = 0 if (not defined $C->{'sshClientDebugLevel'} or $C->{'sshClientDebugLevel'} !~ /^\d+$/);
    $C->{'sshClientDebugLevel'} > 3 and $C->{'sshClientDebugLevel'} = 3;

    $C->{'accountMaxInactiveDays'} = 0
      if (not defined $C->{'accountMaxInactiveDays'} or $C->{'accountMaxInactiveDays'} !~ /^\d+$/);

    $C->{'interactiveModeTimeout'} = 15
      if (not defined $C->{'interactiveModeTimeout'} or $C->{'interactiveModeTimeout'} !~ /^\d+$/);
    $C->{'syslogFacility'}    = 'local7'  if (not defined $C->{'syslogFacility'}    or $C->{'syslogFacility'} !~ /^\S+$/);
    $C->{'syslogDescription'} = 'bastion' if (not defined $C->{'syslogDescription'} or $C->{'syslogDescription'} !~ /^\S+$/);

    $C->{'moshTimeoutNetwork'} = 86400 if (not defined $C->{'moshTimeoutNetwork'} or $C->{'moshTimeoutNetwork'} !~ /^\d+$/);
    $C->{'moshTimeoutSignal'}  = 30    if (not defined $C->{'moshTimeoutSignal'}  or $C->{'moshTimeoutSignal'} !~ /^\d+$/);
    $C->{'moshCommandLine'}    = ""    if (not defined $C->{'moshCommandLine'});

    $C->{'ttyrecFilenameFormat'} = '%Y-%m-%d.%H-%M-%S.#usec#.&uniqid.ttyrec' if (not $C->{'ttyrecFilenameFormat'});

    $C->{'idleLockTimeout'}       = 0 if (not defined $C->{'idleLockTimeout'}       or $C->{'idleLockTimeout'} !~ /^\d+$/);
    $C->{'idleKillTimeout'}       = 0 if (not defined $C->{'idleKillTimeout'}       or $C->{'idleKillTimeout'} !~ /^\d+$/);
    $C->{'warnBeforeLockSeconds'} = 0 if (not defined $C->{'warnBeforeLockSeconds'} or $C->{'warnBeforeLockSeconds'} !~ /^\d+$/);
    $C->{'warnBeforeKillSeconds'} = 0 if (not defined $C->{'warnBeforeKillSeconds'} or $C->{'warnBeforeKillSeconds'} !~ /^\d+$/);

    if (!grep { $C->{'accountMFAPolicy'} eq $_ } qw{ disabled enabled password-required totp-required any-required }) {
        $C->{'accountMFAPolicy'} = 'enabled';
    }
    $C->{'MFAPasswordInactiveDays'} = -1 if (!defined $C->{'MFAPasswordInactiveDays'} || $C->{'MFAPasswordInactiveDays'} !~ /^-\d+$/);
    $C->{'MFAPasswordMinDays'}      = 0  if (!defined $C->{'MFAPasswordMinDays'}      || $C->{'MFAPasswordMinDays'} !~ /^-?\d+$/);
    $C->{'MFAPasswordMaxDays'}      = 90 if (!defined $C->{'MFAPasswordMaxDays'}      || $C->{'MFAPasswordMaxDays'} !~ /^-?\d+$/);
    $C->{'MFAPasswordWarnDays'}     = 15 if (!defined $C->{'MFAPasswordWarnDays'}     || $C->{'MFAPasswordWarnDays'} !~ /^-?\d+$/);

    # if kill timeout is lower than lock timeout, just unset lock timeout
    $C->{'idleLockTimeout'} = 0 if ($C->{'idleKillTimeout'} <= $C->{'idleLockTimeout'});

    # booleans that can only be 0 or 1 and default to 1
    foreach my $key (
        qw{
        enableSyslog enableGlobalAccessLog enableAccountAccessLog enableGlobalSqlLog enableAccountSqlLog displayLastLogin
        interactiveModeByDefault
        }
      )
    {
        $C->{$key} = 1 if (not defined $C->{$key} or $C->{$key} !~ /^\d+$/);
        $C->{$key} > 1 and $C->{$key} = 1;
    }

    # booleans that can only be 0 or 1 and default to 0
    foreach my $key (
        qw{ interactiveModeAllowed readOnlySlaveMode sshClientHasOptionE ingressKeysFromAllowOverride
        moshAllowed debug keyboardInteractiveAllowed passwordAllowed telnetAllowed remoteCommandEscapeByDefault
        accountExternalValidationDenyOnFailure }
      )
    {
        $C->{$key} = 0 if (not defined $C->{$key} or $C->{$key} !~ /^\d+$/);
        $C->{$key} > 1 and $C->{$key} = 1;
    }

    # arrays that default to empty
    foreach my $key (
        qw{ accountCreateSupplementaryGroups accountCreateDefaultPrivateAccesses alwaysActiveAccounts
        superOwnerAccounts ingressKeysFrom egressKeysFrom adminAccounts allowedNetworks forbiddenNetworks
        ttyrecAdditionalParameters MFAPostCommand }
      )
    {
        $C->{$key} = [] if ref $C->{$key} ne 'ARRAY';
    }

    # lint the contents of some arrays
    foreach my $key (qw{ ingressKeysFrom egressKeysFrom }) {
        s=[^0-9.:/]==g for @{$C->{$key}};
    }
    $C->{'adminAccounts'} = [
        grep { OVH::Bastion::is_bastion_account_valid_and_existing(account => $_) }
        map { s/[^a-zA-Z0-9_-]//g; $_ } @{$C->{'adminAccounts'}}
    ];

    $C->{'documentationURL'} ||= "https://ovh.github.io/the-bastion/";

    # we've checked everything. now forcibly untaint all of it.
    foreach my $key (keys %$C) {
        ref $C->{$key} eq '' or next;
        ($C->{$key}) = $C->{$key} =~ m{(.+)};
        $C->{$key} += 0 if $C->{$key} =~ /^\d+$/;
    }

    $_cache_config = $C;
    return R('OK', value => $C);
}

sub config {
    my $key = shift;

    my $fnret = OVH::Bastion::load_configuration();
    $fnret or return $fnret;
    if (exists $fnret->value->{$key}) {
        return R('OK', value => $fnret->value->{$key});
    }
    return R('ERR_UNKNOWN_CONFIG_PARAMETER');
}

sub account_config {
    my %params  = @_;
    my $account = $params{'account'} || OVH::Bastion::get_user_from_env()->value;
    my $key     = $params{'key'};
    my $value   = $params{'value'};                                                 # only for setter
    my $delete  = $params{'delete'};                                                # if true, delete the config param entirely
    my $public  = $params{'public'};                                                # if true, check in /home/allowkeeper/$account instead of /home/$account
    my $fnret;

    if (my @missingParameters = grep { not defined $params{$_} } qw{ account key }) {
        local $" = ', ';
        return R('ERR_MISSING_PARAMETER', msg => "Missing @missingParameters on account_config() call");
    }

    if ($key !~ /^[a-zA-Z0-9_-]+$/) {
        return R('ERR_INVALID_PARAMETER', msg => "Invalid configuration key asked ($key)");
    }

    $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $account, accountType => ($account =~ /^realm_/ ? 'realm' : 'normal'));
    $fnret or return $fnret;

    $account = $fnret->value->{'account'};
    my $sysaccount    = $fnret->value->{'sysaccount'};
    my $remoteaccount = $fnret->value->{'remoteaccount'};

    my $rootdir;
    if ($public) {
        $rootdir = "/home/allowkeeper/$sysaccount";
    }
    else {
        $rootdir = (getpwnam($sysaccount))[7];
    }

    if (!-d $rootdir) {
        return R('ERR_DIRECTORY_NOT_FOUND', msg => "Home directory of $account ($rootdir) doesn't exist");
    }
    my $prefix = $remoteaccount ? "config_$remoteaccount" : "config";
    my $filename = "$rootdir/$prefix.$key";

    if ($delete) {
        return R('OK') if (unlink($filename));
        return R('ERR_UNLINK_FAILED', msg => "Couldn't delete account $account config $key with public=$public ($!)");
    }
    elsif (defined $value) {

        # setter mode
        unlink($filename);    # remove any previous value
        my $fh;
        if (!sysopen($fh, $filename, O_RDWR | O_CREAT | O_EXCL))    # sysopen: avoid symlink attacks
        {
            return R('ERR_CANNOT_OPEN_FILE', msg => "Error while trying to open file $filename for write ($!)");
        }
        print $fh $value;
        close($fh);
        chmod 0644, $filename;
        if ($public) {

            # need to chown to allowkeeper:allowkeeper
            my (undef, undef, $allowkeeperuid, $allowkeepergid) = getpwnam("allowkeeper");
            chown $allowkeeperuid, $allowkeepergid, $filename;
        }
        return R('OK');
    }
    else {
        # getter mode
        my $fh;
        if (!open($fh, '<', $filename)) {
            return R('ERR_CANNOT_OPEN_FILE', msg => "Error while trying to open file $filename for read ($!)");
        }
        my $value = do { local $/; <$fh> };
        close($fh);
        return R('OK', value => $value);
    }

    return R('ERR_INTERNAL');    # we shouldn't be here
}

my %_plugin_config_cache;

sub plugin_config {
    my %params = @_;
    my $plugin = $params{'plugin'};
    my $key    = $params{'key'};
    my $fnret;

    if (my @missingParameters = grep { not defined $params{$_} } qw{ plugin }) {
        local $" = ', ';
        return R('ERR_MISSING_PARAMETER', msg => "Missing @missingParameters on plugin_config() call");
    }

    if (not exists $_plugin_config_cache{$plugin}) {

        # sanitize $plugin
        if ($plugin !~ /^[a-zA-Z0-9_-]{1,128}$/) {
            return R('ERR_INVALID_PARAMETER', msg => "Invalid parameter for plugin");
        }

        # if not in cache, load it
        my %config;

        # 1of2) load from builtin config (plugin.json)
        my $pluginPath = $OVH::Bastion::BASEPATH . '/bin/plugin';
        undef $fnret;
        foreach my $pluginDir (qw{ open restricted group-gatekeeper group-aclkeeper group-owner admin }) {
            if (-e "$pluginPath/$pluginDir/$plugin") {
                $fnret = OVH::Bastion::load_configuration_file(file => "$pluginPath/$pluginDir/$plugin.json");
                if ($fnret->err eq 'KO_CANNOT_OPEN_FILE') {

                    # chmod error, don't fail silently
                    warn_syslog("Can't read configuration file '$pluginPath/$pluginDir/$plugin.json'");
                    return R('ERR_CONFIGURATION_ERROR', msg => "Configuration file has improper rights, ask your sysadmin!");
                }
                last;
            }
        }
        if ($fnret && ref $fnret->value eq 'HASH') {
            %config = %{$fnret->value};
        }

        # 2of2) load from /etc config (will NOT override plugin.json keys)
        $fnret = OVH::Bastion::load_configuration_file(file => "/etc/bastion/plugin.$plugin.conf", secure => 1);
        if ($fnret->err eq 'KO_CANNOT_OPEN_FILE') {

            # chmod error, don't fail silently
            warn_syslog("Can't read configuration file '/etc/bastion/plugin.$plugin.conf'");
            return R('ERR_CONFIGURATION_ERROR', msg => "Configuration file has improper rights, ask your sysadmin!");
        }
        if ($fnret && ref $fnret->value eq 'HASH') {

            # avoid overriding keys
            foreach my $key (keys %{$fnret->value}) {
                $config{$key} = $fnret->value->{$key} if not exists $config{$key};
            }
        }

        $_plugin_config_cache{$plugin} = \%config;
    }

    # if no $key is specified, return all config
    return R('OK', value => $_plugin_config_cache{$plugin}) if not defined $key;

    # or just the requested key's value otherwise (might be undef!)
    return R('OK', value => $_plugin_config_cache{$plugin}{$key});
}

sub group_config {
    my %params = @_;
    my $group  = $params{'group'};
    my $key    = $params{'key'};
    my $value  = $params{'value'};     # only for setter
    my $secret = $params{'secret'};    # only for setter, if true, only group members can read this config key
    my $delete = $params{'delete'};    # only for setter, if true, delete the config param entirely
    my $fnret;

    if (my @missingParameters = grep { not defined $params{$_} } qw{ group key }) {
        local $" = ', ';
        return R('ERR_MISSING_PARAMETER', msg => "Missing @missingParameters on group_config() call");
    }

    if ($key !~ /^[a-zA-Z0-9_-]+$/) {
        return R('ERR_INVALID_PARAMETER', msg => "Invalid configuration key asked ($key)");
    }

    $fnret = OVH::Bastion::is_valid_group_and_existing(group => $group, groupType => 'key');
    $fnret or return $fnret;

    $group = $fnret->value->{'group'};
    my $shortGroup = $fnret->value->{'shortGroup'};

    my $filename = "/home/$group/config.$key";

    if ($delete) {
        return R('OK') if (unlink($filename));
        return R('ERR_UNLINK_FAILED', msg => "Couldn't delete group $shortGroup config $key ($!)");
    }
    elsif (defined $value) {

        # setter mode
        unlink($filename);    # remove any previous value
        my $fh;
        if (!sysopen($fh, $filename, O_RDWR | O_CREAT | O_EXCL))    # sysopen: avoid symlink attacks
        {
            return R('ERR_CANNOT_OPEN_FILE', msg => "Error while trying to open file $filename for write ($!)");
        }
        print $fh $value;
        close($fh);
        chmod($secret ? 0640 : 0644), $filename;

        # need to chown to group:group
        my (undef, undef, $groupuid, $groupgid) = getpwnam($group);
        chown $groupuid, $groupgid, $filename;
        return R('OK');
    }
    else {
        # getter mode
        my $fh;
        if (!open($fh, '<', $filename)) {
            return R('ERR_CANNOT_OPEN_FILE', msg => "Error while trying to open file $filename for read ($!)");
        }
        {
            local $/ = undef;
            $value = <$fh>;
        }
        close($fh);
        return R('OK', value => $value);
    }

    return R('ERR_INTERNAL');    # we shouldn't be here
}

sub json_load {
    my %params = @_;

    # Check params
    my $file = $params{'file'};
    my $keywords = $params{'keywords'} || [];

    if (!$file) {
        return R('KO_MISSING_PARAMETER', msg => "Missing 'file' parameter");
    }

    # Load file content
    my $rawConf;
    if (open(my $fh, '<', $file)) {
        foreach (<$fh>) {
            chomp;
            s/^((?:(?:[^"]*"){2}|[^"]*)*[^"]*)\/\/.*$/$1/;    # Remove comment that start with //
            /^\s*#/ and next;                                 # Comment start with ^#
            $rawConf .= $_ . "\n";
        }
        close $fh;
    }
    else {
        # either the file doesn't exist, or we don't have the right to read it.
        if (-e $file) {
            return R('KO_CANNOT_OPEN_FILE', msg => "Couldn't open specified file ($!)");
        }
        else {
            return R('KO_NO_SUCH_FILE', msg => "File '$file' doesn't exist");
        }
    }

    #   Clean file content

    # Remove block comment
    $rawConf =~ s/\/\*\*.+?\*\///sgm;

    # Add {} if needed
    if ($rawConf !~ /^\{.*\}[\n]?$/sm) {
        $rawConf = "{\n" . $rawConf . "}\n";
    }

    #
    # Parse file content
    #
    my $configuration;
    eval { $configuration = decode_json($rawConf); };
    if ($@) {
        return R('KO_INVALID_JSON', msg => "Error while trying to decode JSON configuration from file: $@");
    }

    # Check that each given keywords are defined
    my @missing = map { defined($configuration->{$_}) ? () : $_ } keys %$configuration;
    if (@missing) {
        return R(
            'KO_MISSING_CONFIGURATION',
            value => $configuration,
            msg   => "Configuration is lacking mandatory keywords: " . join(', ', @missing)
        );
    }
    return R('OK', value => $configuration);
}

1;
