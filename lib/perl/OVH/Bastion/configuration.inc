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

    # if $rootonly is set, the $secure restriction apply, and
    # in addition we won't load the file if it's o+r
    my $rootonly = $params{'rootonly'};

    if ($secure || $rootonly) {
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
            if ($rootonly && S_IMODE($stat[2]) & S_IROTH) {
                return R('ERR_SECURITY_VIOLATION', msg => "Configuration file ($file) is world-readable, report to your sysadmin.");
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
    my $noisy     = $params{'noisy'};       # print warnings/errors on stdout in addition to syslog
    my $test      = $params{'test'};        # noisy + also print missing configuration options

    # do NOT use warn_syslog in this func, or any other function that needs to read configuration,
    # or we might end up in an infinite loop: store errors we wanna log at the end
    my @errors;

    $noisy = 1 if $test;

    if (defined $mock_data) {
        if (!OVH::Bastion::is_mocking()) {

            # if we're overriding configuration with mock_data without being in mocking mode, we have a problem
            die("Attempted to load_configuration() with mock_data without being in mocking mode");
        }

        # mock data always overrides cache
        undef $_cache_config;
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

    # define deprecated vs new key names association
    # new old
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

    ####################################################
    # now validate, lint, normalize and untaint the conf

    my %unknownkeys = map { $_ => 1 } keys %$C;

    # 1/6) Options that are strings, and must match given regex. Always include capturing parens in regex for untainting.
    foreach my $o (
        {name => 'bastionName',           default => 'fix-my-config-please-missing-bastion-name',                        validre => qr/^([a-zA-Z0-9_.-]+)$/},
        {name => 'bastionCommand',        default => "ssh ACCOUNT\@HOSTNAME -t -- ",                                     validre => qr/^(.+)$/},
        {name => 'defaultLogin',          default => "",                                                                 validre => qr/^([a-zA-Z0-9_.-]*)$/, emptyok => 1},
        {name => 'moshCommandLine',       default => "",                                                                 validre => qr/^(.*)$/, emptyok => 1},
        {name => 'documentationURL',      default => "https://ovh.github.io/the-bastion/",                               validre => qr'^([a-zA-Z0-9:/@&=",;_.# -]+)$'},
        {name => 'syslogFacility',        default => 'local7',                                                           validre => qr/^([a-zA-Z0-9_]+)$/},
        {name => 'syslogDescription',     default => 'bastion',                                                          validre => qr/^([a-zA-Z0-9_.-]+)$/},
        {name => 'ttyrecFilenameFormat',  default => '%Y-%m-%d.%H-%M-%S.#usec#.&uniqid.&account.&user.&ip.&port.ttyrec', validre => qr/^([a-zA-Z0-9%&#_.-]+)$/},
        {name => 'accountExpiredMessage', default => '',                                                                 validre => qr/^(.*)$/, emptyok => 1},
        {name => 'fanciness',                        default => 'full', validre => qr/^((none|boomer)|(basic|millenial)|(full|genz))$/},
        {name => 'accountExternalValidationProgram', default => '',     validre => qr'^([a-zA-Z0-9/$_.-]*)$', emptyok => 1},
      )
    {
        if (!$C->{$o->{'name'}} && !$o->{'emptyok'}) {
            $C->{$o->{'name'}} = $o->{'default'};
            push @errors, "Configuration error: missing option '" . $o->{'name'} . "', defaulting to '" . $o->{'default'} . "'" if $test;
        }
        if ($C->{$o->{'name'}} =~ $o->{'validre'}) {

            # untaint
            $C->{$o->{'name'}} = $1;
        }
        else {
            push @errors,
              "Configuration error: value of option '" . $o->{'name'} . "' ('" . $C->{$o->{'name'}} . "') didn't match allowed regex, defaulting to '" . $o->{'default'} . "'";
            $C->{$o->{'name'}} = $o->{'default'};
        }
        delete $unknownkeys{$o->{'name'}};
    }

    # 2/6) Options that must be numbers, between min and max.
    foreach my $o (
        {name => 'accountUidMin',                         min => 100,  max => 999_999_999, default => 2000},
        {name => 'accountUidMax',                         min => 100,  max => 999_999_999, default => 99999},
        {name => 'ttyrecGroupIdOffset',                   min => 1,    max => 999_999_999, default => 100_000},
        {name => 'minimumIngressRsaKeySize',              min => 1024, max => 16384,       default => 2048},
        {name => 'minimumEgressRsaKeySize',               min => 1024, max => 16384,       default => 2048},
        {name => 'maximumIngressRsaKeySize',              min => 1024, max => 32768,       default => 8192},
        {name => 'maximumEgressRsaKeySize',               min => 1024, max => 32768,       default => 8192},
        {name => 'moshTimeoutNetwork',                    min => 0,    max => 86400 * 365, default => 86400},
        {name => 'moshTimeoutSignal',                     min => 0,    max => 86400 * 365, default => 30},
        {name => 'idleLockTimeout',                       min => 0,    max => 86400 * 365, default => 0},
        {name => 'idleKillTimeout',                       min => 0,    max => 86400 * 365, default => 0},
        {name => 'warnBeforeLockSeconds',                 min => 0,    max => 86400 * 365, default => 0},
        {name => 'warnBeforeKillSeconds',                 min => 0,    max => 86400 * 365, default => 0},
        {name => 'MFAPasswordInactiveDays',               min => -1,   max => 365 * 5,     default => -1},
        {name => 'MFAPasswordMinDays',                    min => 0,    max => 365 * 5,     default => 0},
        {name => 'MFAPasswordMaxDays',                    min => 0,    max => 365 * 5,     default => 90},
        {name => 'MFAPasswordWarnDays',                   min => 0,    max => 365 * 5,     default => 15},
        {name => 'sshClientDebugLevel',                   min => 0,    max => 3,           default => 0},
        {name => 'accountMaxInactiveDays',                min => 0,    max => 365 * 5,     default => 0},
        {name => 'interactiveModeTimeout',                min => 0,    max => 86400 * 365, default => 15},
        {name => 'interactiveModeProactiveMFAexpiration', min => 0,    max => 86400,       default => 900},
      )
    {
        if (not defined $C->{$o->{'name'}}) {
            $C->{$o->{'name'}} = $o->{'default'};
            push @errors, "Configuration error: missing option '" . $o->{'name'} . "', defaulting to " . $o->{'default'} if $test;
        }
        if ($C->{$o->{'name'}} =~ /^(-?\d+)$/) {

            # untaint
            $C->{$o->{'name'}} = $1;
        }
        else {
            push @errors, "Configuration error: value of option '" . $o->{'name'} . "' ('" . $C->{$o->{'name'}} . "') is not a number, defaulting to " . $o->{'default'};
            $C->{$o->{'name'}} = $o->{'default'};
        }
        if ($C->{$o->{'name'}} > $o->{'max'}) {
            push @errors,
                "Configuration error: value of option '"
              . $o->{'name'} . "' ("
              . $C->{$o->{'name'}}
              . ") is higher than allowed value ("
              . $o->{'max'}
              . "), defaulting to "
              . $o->{'default'};
            $C->{$o->{'name'}} = $o->{'default'};
        }
        elsif ($C->{$o->{'name'}} < $o->{'min'}) {
            push @errors,
                "Configuration error: value of option '"
              . $o->{'name'} . "' ("
              . $C->{$o->{'name'}}
              . ") is lower than allowed value ("
              . $o->{'min'}
              . "), defaulting to "
              . $o->{'default'};
            $C->{$o->{'name'}} = $o->{'default'};
        }
        delete $unknownkeys{$o->{'name'}};
    }

    # 3/6) Booleans. Standard true/false values should be used in the JSON config file, but we normalize non-bool values here.
    # We cast the strings "no", "false", "disabled" to false. The JSON null value is the same as omitting the option entirely,
    # hence forcing the bastion to use the default value for this option.
    # For all other values, standard Perl applies: 0, "0", "" are false, everything else is true.
    # We warn where we have to cast, except for 0/1/"0"/"1" for backwards compatibility.
    foreach my $tuple (
        {
            default => 1,
            options => [
                qw{
                  enableSyslog enableGlobalAccessLog enableAccountAccessLog enableGlobalSqlLog enableAccountSqlLog displayLastLogin
                  interactiveModeByDefault interactiveModeProactiveMFAenabled
                  }
            ],
        },
        {
            default => 0,
            options => [
                qw{
                  interactiveModeAllowed readOnlySlaveMode sshClientHasOptionE ingressKeysFromAllowOverride
                  moshAllowed debug keyboardInteractiveAllowed passwordAllowed telnetAllowed remoteCommandEscapeByDefault
                  accountExternalValidationDenyOnFailure ingressRequirePIV
                  }
            ],
        }
      )
    {
        foreach my $o (@{$tuple->{'options'}}) {

            # if not defined (option missing or set to null), set to default value
            if (not defined $C->{$o}) {
                $C->{$o} = $tuple->{'default'};
                push @errors, "Configuration error: missing option '$o', defaulting to " . ($tuple->{'default'} ? 'true' : 'false') if $test;
            }

            # if a bool, it's ok, normalize to 0/1
            elsif (JSON::is_bool($C->{$o})) {
                $C->{$o} = $C->{$o} ? 1 : 0;
            }

            # if set to "no", "false" or "disabled", be nice and cast to false (because a string is true, otherwise)
            elsif (grep { lc($C->{$o}) eq lc } qw{ no false disabled }) {
                push @errors, "Configuration error: found value '" . $C->{$o} . "' for option '$o', but it's supposed to be a boolean, assuming false";
                $C->{$o} = 0;
            }

            # if 0 or 1, normalize silently (backwards compatible)
            elsif ($C->{$o} == 0 || $C->{$o} == 1) {
                $C->{$o} = $C->{$o} ? 1 : 0;
            }

            # otherwise, normalize any true/false value to 1/0, and log a warning
            else {
                push @errors, "Configuration error: found value '" . $C->{$o} . "' for option '$o', but it's supposed to be a boolean, assuming " . ($C->{$o} ? 'true' : 'false');
                $C->{$o} = $C->{$o} ? 1 : 0;
            }
            delete $unknownkeys{$o};
        }
    }

    # 4/6) Strings that must be one item of a specific enum.
    foreach my $o (
        {name => 'defaultAccountEgressKeyAlgorithm', default => 'rsa',     valid => [qw{ rsa ecdsa ed25519 }]},
        {name => 'accountMFAPolicy',                 default => 'enabled', valid => [qw{ disabled enabled password-required totp-required any-required }]},
      )
    {
        # if not defined, set to default value
        if (not defined $C->{$o->{'name'}}) {
            $C->{$o->{'name'}} = $o->{'default'};
            push @errors, "Configuration error: missing option '" . $o->{'name'} . "', defaulting to '" . (join(" ", @{$o->{'default'}})) . "'" if $test;
        }

        # must be one of the allowed values
        elsif (my @untainted = grep { $C->{$o->{'name'}} eq $_ } @{$o->{'valid'}}) {
            $C->{$o->{'name'}} = $untainted[0];
        }
        else {
            push @errors, "Configuration error: option '" . $o->{'name'} . "' should be one of [" . (join(",", @{$o->{'valid'}})) . "] instead of '" . $C->{$o->{'name'}} . "'";
            $C->{$o->{'name'}} = $o->{'default'};
        }
        delete $unknownkeys{$o->{'name'}};
    }

    # 5/6) Arrays whose values should match a specific regex.
    foreach my $o (
        ## no critic(RegularExpressions::ProhibitFixedStringMatches)
        {name => 'allowedIngressSshAlgorithms', default => [qw{ rsa ecdsa ed25519 }], validre => qr/^(rsa|ecdsa|ed25519)$/},
        ## no critic(RegularExpressions::ProhibitFixedStringMatches)
        {name => 'allowedEgressSshAlgorithms',           default => [qw{ rsa ecdsa ed25519 }], validre => qr/^(rsa|ecdsa|ed25519)$/},
        {name => 'accountCreateSupplementaryGroups',     default => [],                        validre => qr/^(.*)$/},
        {name => 'accountCreateDefaultPersonalAccesses', default => [],                        validre => qr/^(.*)$/},
        {name => 'alwaysActiveAccounts',                 default => [],                        validre => qr/^(.*)$/},
        {name => 'superOwnerAccounts',                   default => [],                        validre => qr/^(.*)$/},
        {name => 'ingressKeysFrom',                      default => [],                        validre => qr'^([0-9.:%/]+)$'},
        {name => 'egressKeysFrom',                       default => [],                        validre => qr'^([0-9.:%/]+)$'},
        {name => 'adminAccounts',                        default => [],                        validre => qr/^(.*)$/},
        {name => 'allowedNetworks',                      default => [],                        validre => qr'^([0-9.:%/]+)$'},
        {name => 'forbiddenNetworks',                    default => [],                        validre => qr'^([0-9.:%/]+)$'},
        {name => 'ttyrecAdditionalParameters',           default => [],                        validre => qr/^(.*)$/},
        {name => 'MFAPostCommand',                       default => [],                        validre => qr/^(.*)$/},
      )
    {
        # if not defined, set to default value
        if (not defined $C->{$o->{'name'}}) {
            $C->{$o->{'name'}} = $o->{'default'};
            push @errors, "Configuration error: missing option '" . $o->{'name'} . "', defaulting to [" . (join(",", @{$o->{'default'}})) . "]" if $test;
        }

        # must be an array
        elsif (ref $C->{$o->{'name'}} ne 'ARRAY') {
            $C->{$o->{'name'}} = $o->{'default'};
            push @errors, "Configuration error: options option '" . $o->{'name'} . "' should be an array, defaulting to [" . (join(" ", @{$o->{'default'}})) . "]";
        }

        # whose values validate the regex
        else {
            my @untainted;
            foreach my $v (@{$C->{$o->{'name'}}}) {
                if ($v =~ $o->{'validre'}) {
                    push @untainted, $1;
                }
                else {
                    push @errors,
                        "Configuration error: at least one of the values of the array defined by option '"
                      . $o->{'name'}
                      . "' is invalid, defaulting to ["
                      . (join(" ", @{$o->{'default'}})) . "]";
                    $C->{$o->{'name'}} = $o->{'default'};
                    last;
                }
            }
            $C->{$o->{'name'}} = \@untainted;
        }
        delete $unknownkeys{$o->{'name'}};
    }

    # 6/6) Special cases and/or additional checks for already vetted options

    # ... we must have enough room between min and max
    if ($C->{'accountUidMin'} + 1000 > $C->{'accountUidMax'}) {
        push @errors,
            "Configuration error: 'accountUidMax' ("
          . $C->{'accountUidMax'}
          . ") is too close from 'accountUidMin' ("
          . $C->{'accountUidMin'}
          . "), setting accountUidMax="
          . ($C->{'accountUidMin'} + 1000);
        $C->{'accountUidMax'} = $C->{'accountUidMin'} + 1000;
    }

    # ... ttyrec group offset must be high enough to avoid overlap with the accounts uids
    if ($C->{'ttyrecGroupIdOffset'} < $C->{'accountUidMax'} - $C->{'accountUidMin'}) {
        my $fixed = ($C->{'accountUidMax'} - $C->{'accountUidMin'}) + 1;
        push @errors, "Configuration error: the configured 'ttyrecGroupIdOffset' (" . $C->{'ttyrecGroupIdOffset'} . ") would overlap with account UIDs, setting it to $fixed";
        $C->{'ttyrecGroupIdOffset'} = $fixed;
    }

    # ... ensure min <= max
    foreach my $key (qw{ Ingress Egress }) {
        my $minkey = "minimum${key}RsaKeySize";
        my $maxkey = "maximum${key}RsaKeySize";
        if ($C->{$minkey} > $C->{$maxkey}) {
            push @errors, "Configuration error: '$minkey' (" . $C->{$minkey} . ") must be <= '$maxkey' (" . $C->{$maxkey} . "), setting $minkey=" . $C->{$maxkey};
            $C->{$minkey} = $C->{$maxkey};
        }
    }

    # ... defaultAccountEgressKeySize can only be checked after defaultAccountEgressKeyAlgorithm has been handled
    {
        if (not defined $C->{'defaultAccountEgressKeySize'}) {
            $C->{'defaultAccountEgressKeySize'} = 0;
        }
        if ($C->{'defaultAccountEgressKeySize'} =~ /^(\d+)$/) {
            $C->{'defaultAccountEgressKeySize'} = $1;
        }
        else {
            push @errors, "Configuration error: value of option 'defaultAccountEgressKeySize' ('" . $C->{'defaultAccountEgressKeySize'} . "') is not a number, defaulting to 0";
            $C->{'defaultAccountEgressKeySize'} = 0;
        }
        if ($C->{'defaultAccountEgressKeyAlgorithm'} eq 'rsa') {
            $C->{'defaultAccountEgressKeySize'} ||= 4096;
            if ($C->{'defaultAccountEgressKeySize'} < 1024) {
                push @errors,
                  "Configuration error: value of option 'defaultAccountEgressKeySize' ('" . $C->{'defaultAccountEgressKeySize'} . "') should be >= 1024, defaulting to 1024";
                $C->{'defaultAccountEgressKeySize'} = 1024;
            }
            elsif ($C->{'defaultAccountEgressKeySize'} > 32768) {
                push @errors,
                  "Configuration error: value of option 'defaultAccountEgressKeySize' ('" . $C->{'defaultAccountEgressKeySize'} . "') should be >= 1024, defaulting to 1024";
                $C->{'defaultAccountEgressKeySize'} = 32768;
            }
        }
        elsif ($C->{'defaultAccountEgressKeyAlgorithm'} eq 'ecdsa') {
            $C->{'defaultAccountEgressKeySize'} ||= 521;
            if (!grep { $C->{'defaultAccountEgressKeySize'} eq $_ } qw{ 256 384 521 }) {
                push @errors,
                    "Configuration error: value of option 'defaultAccountEgressKeySize' ('"
                  . $C->{'defaultAccountEgressKeySize'}
                  . "') should be one of [256,384,521], defaulting to 521";
                $C->{'defaultAccountEgressKeySize'} = 521;
            }
        }
        elsif ($C->{'defaultAccountEgressKeyAlgorithm'} eq 'ed25519') {

            # for ed25519, it's always 256 anyway
            if ($C->{'defaultAccountEgressKeySize'} != 256) {
                push @errors, "Configuration error: option 'defaultAccountEgressKeySize' has to be 256 when 'defaultAccountEgressKeyAlgorithm' is set to 'ed25519', forcing 256";
                $C->{'defaultAccountEgressKeySize'} = 256;
            }
        }
        delete $unknownkeys{'defaultAccountEgressKeySize'};
    }

    # ... if kill timeout is lower than lock timeout, just unset lock timeout
    if ($C->{'idleKillTimeout'} <= $C->{'idleLockTimeout'} && $C->{'idleLockTimeout'} != 0) {
        push @errors,
            "Configuration error: option 'idleKillTimeout' ("
          . $C->{'idleKillTimeout'}
          . ") is <= 'idleLockTimeout' ("
          . $C->{'idleLockTimeout'}
          . "), setting 'idleKillTimeout' to 0";
        $C->{'idleLockTimeout'} = 0;
    }

    # ... if warnBefore*Seconds are set whereas idle*Timeout are not, unset the warnBefore*Seconds params and log the misconfiguration
    foreach my $what (qw{ Kill Lock }) {
        if ($C->{"warnBefore${what}Seconds"} && !$C->{"idle${what}Timeout"}) {
            push @errors,
                "Configuration error: option 'warnBefore${what}Seconds' ("
              . $C->{"warnBefore${what}Seconds"}
              . ") is set whereas the corresponding 'idle${what}Timeout' option is not, setting 'warnBefore${what}Seconds' to 0";
            $C->{"warnBefore${what}Seconds"} = 0;
        }
    }

    # ... check that adminAccounts are actually valid accounts
    {
        foreach my $conf (qw{ adminAccounts superOwnerAccounts }) {
            my @validAccounts;
            foreach my $account (@{$C->{$conf}}) {
                my $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $account);
                if (!$fnret) {
                    push @errors, "Configuration error: specified $conf '$account' is not a valid account, ignoring";
                }
                else {
                    push @validAccounts, $fnret->value->{'account'};
                }
            }
            $C->{$conf} = \@validAccounts;
        }
    }

    # ... this one is complicated; it's an array of (arrays of 3 items: (two arrays and a string))
    if (not defined $C->{'ingressToEgressRules'}) {
        $C->{'ingressToEgressRules'} = [];
        push @errors, "Configuration error: missing option 'ingressToEgressRules', defaulting to []" if $test;
    }
    elsif (ref $C->{'ingressToEgressRules'} ne 'ARRAY') {
        $C->{'ingressToEgressRules'} = [];
        push @errors, "Configuration error: option 'ingressToEgressRules' is invalid, expected an array, defaulting to []";
    }
    else {
      SKIP: foreach my $rule (@{$C->{'ingressToEgressRules'}}) {
            if (ref $rule ne 'ARRAY') {
                $C->{'ingressToEgressRules'} = [];
                push @errors, "Configuration error: option 'ingressToEgressRules' has an invalid format (rules should be arrays), defaulting to []";
                last;
            }
            elsif (@$rule != 3 || ref $rule->[0] ne 'ARRAY' || ref $rule->[1] ne 'ARRAY' || ref $rule->[2]) {
                $C->{'ingressToEgressRules'} = [];
                push @errors, "Configuration error: option 'ingressToEgressRules' has an invalid format (rules should have 3 items: array, array, scalar), defaulting to []";
                last;
            }
            else {
                foreach my $i (0 .. 1) {
                    foreach my $j (0 .. $#{$rule->[$i]}) {
                        if ($rule->[$i][$j] =~ m{^([0-9.:%/]+)$}) {
                            $rule->[$i][$j] = $1;
                        }
                        else {
                            $C->{'ingressToEgressRules'} = [];
                            push @errors,
                              "Configuration error: option 'ingressToEgressRules' has an invalid format ('" . $rule->[$i][$j] . "' doesn't look like an IP), defaulting to []";
                            last SKIP;
                        }
                    }
                }
                if (!grep { $rule->[2] eq $_ } qw{ ALLOW-EXCLUSIVE ALLOW DENY }) {
                    $C->{'ingressToEgressRules'} = [];
                    push @errors,
                      "Configuration error: option 'ingressToEgressRules' has an invalid format ('" . $rule->[2] . "' should be ALLOW, DENY or ALLOW-EXCLUSIVE), defaulting to []";
                }
            }
        }
    }
    delete $unknownkeys{'ingressToEgressRules'};

    # ... normalize fanciness
    $C->{'fanciness'} = 'none'  if $C->{'fanciness'} eq 'boomer';
    $C->{'fanciness'} = 'basic' if $C->{'fanciness'} eq 'millenial';
    $C->{'fanciness'} = 'full'  if $C->{'fanciness'} eq 'genz';

    # OK we're done
    $_cache_config = $C;

    # now that we cached our result, we can call warn_syslog() without risking an infinite loop
    warn_syslog($_,                                                                          $noisy) for @errors;
    warn_syslog("Configuration error: got an unknown option '$_' in configuration, ignored", $noisy) for sort keys %unknownkeys;

    osh_info("Configuration loaded with " . scalar(@errors) . " warnings.") if $test;

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
    my $prefix   = $remoteaccount ? "config_$remoteaccount" : "config";
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
        my $getvalue = do { local $/ = undef; <$fh> };
        close($fh);
        return R('OK', value => $getvalue);
    }

    return R('ERR_INTERNAL');    # we shouldn't be here
}

my %_plugin_config_cache;

sub plugin_config {
    my %params    = @_;
    my $plugin    = $params{'plugin'};
    my $key       = $params{'key'};
    my $mock_data = $params{'mock_data'};
    my $fnret;

    if (my @missingParameters = grep { not defined $params{$_} } qw{ plugin }) {
        local $" = ', ';
        return R('ERR_MISSING_PARAMETER', msg => "Missing @missingParameters on plugin_config() call");
    }

    if (defined $mock_data) {

        if (!OVH::Bastion::is_mocking()) {

            # if we're overriding configuration with mock_data without being in mocking mode, we have a problem
            die("Attempted to load_configuration() with mock_data without being in mocking mode");
        }

        # mock data always overrides our cache
        delete $_plugin_config_cache{$plugin};
    }

    if (not exists $_plugin_config_cache{$plugin}) {

        # sanitize $plugin
        if ($plugin !~ /^[a-zA-Z0-9_-]{1,128}$/) {
            return R('ERR_INVALID_PARAMETER', msg => "Invalid parameter for plugin");
        }

        # if not in cache, load it
        my %config;

        if (!defined $mock_data) {

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
        }
        else {
            %config = %$mock_data;
        }

        # compat: we previously expected "yes" as a value for the 'disabled' option, instead of a boolean.
        # To keep compatibility we still consider "yes" as a true value (as any non-empty string is),
        # however we check that the user was not confused and didn't try to enable the plugin by using
        # a string such as "no" or "false" instead of a real false boolean:
        if (defined $config{'disabled'} && $config{'disabled'} =~ /no|false/) {
            warn_syslog("Configuration error for plugin $plugin on the 'disabled' key: expected a boolean, casted '" . $config{'disabled'} . "' into false");
            $config{'disabled'} = 0;
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
        if ($secret) {
            chmod 0640, $filename;
        }
        else {
            chmod 0644, $filename;
        }

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

    if (!$file) {
        return R('KO_MISSING_PARAMETER', msg => "Missing 'file' parameter");
    }

    # Load file content
    my $rawConf;
    if (open(my $fh, '<', $file)) {
        local $_ = undef;
        while (<$fh>) {
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

    return R('OK', value => $configuration);
}

1;
