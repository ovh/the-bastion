package OVH::Bastion::Plugin;

# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;
use Getopt::Long ();

use File::Basename;
use lib dirname(__FILE__) . '/../../../../lib/perl';
use OVH::Bastion;
use OVH::Result;

$| = 1;

use Exporter 'import';
## no critic (ProhibitPackageVars)
our ($user, $ip, $host, $port, $scriptName, $self, $sysself, $realm, $remoteself, $HOME, $savedArgs, $pluginConfig);
## no critic (ProhibitAutomaticExportation)
our @EXPORT = qw( $user $ip $host $port $scriptName $self $sysself $realm $remoteself $HOME $savedArgs $pluginConfig );
our @EXPORT_OK = qw( help );

my $_helptext;
sub help { osh_info $_helptext; return 1; }

# when init=1, validate the $user/$host/$ip/$port vars that are exported to the plugins, undef them when invalid.
# called in begin() below, which is called by most plugins.
#
# when init=0, explicitly called by the plugins themselves to change/validate the $user/$host/$ip/$port vars,
# from arguments they might have received themselves.
sub validate_tuple {
    my %params             = @_;
    my $userAllowWildcards = $params{'userAllowWildcards'};
    my $init               = $params{'init'};
    my $fnret;

    # user
    if (exists $params{'user'} || $init) {
        $user = $params{'user'} if !$init;
        if (defined $user && $user ne '') {
            $fnret = OVH::Bastion::is_valid_remote_user(user => $user, allowWildcards => $userAllowWildcards);
            $fnret or osh_exit $fnret;
            $user = $fnret->value;
        }
        else {
            undef $user;
        }
    }

    # port
    if (exists $params{'port'} || $init) {
        $port = $params{'port'} if !$init;
        if (defined $port && $port ne '') {
            $fnret = OVH::Bastion::is_valid_port(port => $port);
            $fnret or osh_exit $fnret;
            $port = $fnret->value;
        }
        else {
            undef $port;
        }
    }

    if ($init) {
        if (defined $ip && $ip ne '') {
            $fnret = OVH::Bastion::is_valid_ip(ip => $ip, allowSubnets => 1);
            $fnret or osh_exit $fnret;
            $ip = $fnret->value->{'ip'};
        }
        else {
            # special case due to osh.pl: when host=1.2.3.0/24 then ip=''
            # in that case, validate host and set ip to the same
            if ($host =~ m{/}) {
                $fnret = OVH::Bastion::is_valid_ip(ip => $host, allowSubnets => 1);
                $fnret or osh_exit $fnret;
                $ip = $host = $fnret->value->{'ip'};
            }
            else {
                undef $ip;
            }
        }
    }
    elsif (exists $params{'host'}) {
        $host = $params{'host'};
        if ($host) {
            if ($host !~ m{^[a-zA-Z0-9._/:-]+$}) {
                # can be an IP (v4 or v6), hostname, or prefix (with a /)
                osh_exit('KO_INVALID_REMOTE_HOST', msg => "Remote host name '$host' seems invalid");
            }
            $fnret = OVH::Bastion::get_ip(host => $host);
            if (!$fnret) {
                osh_exit('KO_INVALID_REMOTE_HOST', msg => "Remote host name '$host' couldn't be resolved");
            }
            else {
                $ip = $fnret->value->{'ip'};
            }
        }
        undef $host if $host eq '';
    }

    return R('OK');
}

sub begin {
    my %params = @_;

    my $options             = $params{'options'};
    my $header              = $params{'header'};
    my $argv                = $params{'argv'};
    my $loadConfig          = $params{'loadConfig'};
    my $exitOnSignal        = $params{'exitOnSignal'};
    my $helpfunc            = $params{'help'};
    my $userAllowWildcards  = $params{'userAllowWildcards'};
    my $allowUnknownOptions = $params{'allowUnknownOptions'};
    $_helptext = $params{'helptext'};

    my $fnret;
    my @pluginOptions;
    ($user, $ip, $host, $port, @pluginOptions) = @$argv;

    $helpfunc = \&help if (ref $helpfunc ne 'CODE');

    # our parent (osh.pl) is responsible for ensuring the closing log is written,
    # we don't have to handle it here, however if we get a signal, ensure that we propagate it to our
    # potential children, through the process group, so that no dangling process is left behind.
    # by default we want to continue what we were doing (hence the return), except if exitOnSignal is specified.
    for my $sig (qw{ INT TERM HUP PIPE }) {
        $SIG{$sig} = sub {
            my $signal = shift;
            # ignore any subsequent signal of the same type (including the one we're about to send to our own pgroup)
            $SIG{$signal} = 'IGNORE';
            # 0 == whole process group, which includes our children
            kill $signal, 0;
            if ($exitOnSignal) {
                # exit as asked
                exit(OVH::Bastion::EXIT_GOT_SIGNAL);
            }
            else {
                # just return and continue
                return;
            }
        }
    }

    # validate and untaint user/host/ip/port, exit if problem
    validate_tuple(init => 1, userAllowWildcards => $userAllowWildcards);

    #
    # Options from extraArgs
    #

    $savedArgs = join('^', @pluginOptions);
    my ($result, @optwarns);
    if (ref $options eq 'HASH' and %$options) {
        eval {
            local $SIG{__WARN__} = sub { push @optwarns, shift };
            Getopt::Long::Configure("pass_through") if $allowUnknownOptions;
            $result = Getopt::Long::GetOptionsFromArray(\@pluginOptions, %$options);
            Getopt::Long::Configure("no_pass_through") if $allowUnknownOptions;
        };
        if ($@) { die $@ }
    }
    else {
        $result = 1;
    }

    #
    # get scriptName, set a safe PATH env, and some other ENV vars
    #

    ($scriptName) = $0 =~ m{([a-zA-Z0-9]+)(\.[a-zA-Z0-9]+)*$};
    $_helptext =~ s/SCRIPT_NAME/$scriptName/g if $_helptext;
    $ENV{'PATH'}        = '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:/usr/pkg/bin';
    $ENV{'PLUGIN_NAME'} = $scriptName;

    $HOME = OVH::Bastion::get_home_from_env()->value;
    $self = OVH::Bastion::get_user_from_env()->value;

    # if we're generating documentation (PLUGIN_DOCGEN is set), leave the BASTION_ACCOUNT placeholder
    if ($_helptext && !$ENV{'PLUGIN_DOCGEN'}) {
        $_helptext =~ s/BASTION_ACCOUNT/$self/g;
    }

    osh_header($header) if $header;

    if (!$result && !$allowUnknownOptions) {
        $helpfunc->();
        local $" = ", ";
        osh_exit 'ERR_BAD_OPTIONS', "Error parsing options: @optwarns";
    }

    if ($ENV{'PLUGIN_HELP'}) {
        $helpfunc->();
        osh_exit;
    }

    $fnret =
      OVH::Result::R('OK', value => {sysaccount => $self, account => $self, realm => undef, remoteaccount => undef});
    if ($< == 0) {
        ;    # called by root, don't verify if it's a bastion account (because it's not)
    }
    elsif ($self =~ /^realm_([a-zA-Z0-9_.-]+)/) {
        $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => "$1/" . $ENV{'LC_BASTION'});
        $fnret or osh_exit('ERR_INVALID_ACCOUNT', "The realm-scoped account is invalid (" . $fnret->msg . ")");
    }
    else {
        $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $self);
        $fnret or osh_exit('ERR_INVALID_ACCOUNT', "The account is invalid (" . $fnret->msg . ")");
    }
    $sysself    = $fnret->value->{'sysaccount'};
    $self       = $fnret->value->{'account'};
    $realm      = $fnret->value->{'realm'};
    $remoteself = $fnret->value->{'remoteaccount'};

    if (not(-d -r $HOME)) {
        osh_exit 'ERR_MISSING_HOME', "Error with your HOME directory ($HOME), please report to your sysadmin.";
    }
    if ($sysself ne $ENV{'USER'}) {
        osh_exit 'ERR_INVALID_USER',
          "Error with your USER (\"$sysself\" vs \"$ENV{'USER'}\"), please report to your sysadmin.";
    }

    if ($loadConfig) {
        # try to load config, and abort if we get an error
        $fnret = OVH::Bastion::plugin_config(plugin => $scriptName);
        if (!$fnret) {
            warn_syslog("Invalid configuration for plugin $scriptName: $fnret");
            osh_exit 'ERR_INVALID_CONFIGURATION', "Error in plugin configuration, aborting";
        }
        $pluginConfig = $fnret->value;
    }

    # only unparsed options are remaining there
    return \@pluginOptions;
}

1;
