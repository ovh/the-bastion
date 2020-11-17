#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use 5.010;
use common::sense;

use File::Basename;
use lib dirname(__FILE__) . '/../../lib/perl';
use OVH::Result;
use OVH::Bastion;

use Getopt::Long qw(GetOptionsFromString :config pass_through no_ignore_case);
use Sys::Hostname;
use POSIX qw(strftime);
use Term::ANSIColor;

$ENV{'LANG'} = 'C';
$| = 1;
my $fnret;

#
# Signals
#

$SIG{'INT'}  = \&exit_sig;
$SIG{'TERM'} = \&exit_sig;
$SIG{'SEGV'} = \&exit_sig;
$SIG{'HUP'}  = \&exit_sig;

#
# Do just what is needed before the first call to main_exit in the code flow
#

# tell Getopt::Long to not try to be smart, it messes up with plugins
Getopt::Long::Configure("no_auto_abbrev");

# safe umask
umask(0027);

# sanitize user for taint mode
my $self = OVH::Bastion::get_user_from_env()->value;
my $home = OVH::Bastion::get_home_from_env()->value;
my ($sysself, $realm, $remoteself);    # to handle realm cases, will be filled later, look for # REALM below

# both needs to be there because in case of SIG, we need them in the handler
my $log_db_name   = undef;
my $log_insert_id = undef;

# set a uniqid that will be used in syslog, both sqls, and ttyrec name, so we can search for the same event
my $log_uniq_id = OVH::Bastion::generate_uniq_id()->value;
$ENV{'UNIQID'} = $log_uniq_id;         # some modules need it, also used in warn/die handler

# fetch basic connection info
my ($ipfrom, $portfrom, $bastionip, $bastionport) = split(/\s/, $ENV{'SSH_CONNECTION'});
my $hostfrom    = OVH::Bastion::ip2host($ipfrom)->value    || $ipfrom;
my $bastionhost = OVH::Bastion::ip2host($bastionip)->value || $bastionip;

# sub used to exit from this shell, also handles logs for early exits
sub main_exit {
    my ($retcode, $comment, $msg) = @_;

    # if, this is an early exit, we didn't log anything yet in the sql, do it now
    OVH::Bastion::log_access_insert(
        account     => $self,
        cmdtype     => 'abort',
        allowed     => undef,
        ipfrom      => $ipfrom,
        hostfrom    => $hostfrom,
        portfrom    => $portfrom,
        bastionhost => $bastionhost,
        bastionip   => $bastionip,
        bastionport => $bastionport,
        ipto        => undef,
        hostto      => undef,
        portto      => undef,
        user        => undef,
        plugin      => undef,
        params      => join('^', @ARGV),
        comment     => $comment,
        uniqid      => $log_uniq_id
    ) if (not defined $log_db_name or not defined $log_insert_id);

    my $R = R($retcode eq OVH::Bastion::EXIT_OK ? 'OK' : 'KO_' . uc($comment), msg => $msg);

    OVH::Bastion::osh_crit($R->msg) if not $R;
    OVH::Bastion::json_output($R)   if $ENV{'PLUGIN_JSON'};

    exit $retcode;
}

# Safeness check

if (not defined $self) {

    # wow, that's weird, stop here
    $self = '<none>';
    main_exit(OVH::Bastion::EXIT_EXEC_FAILED, "security_violation", "USER is not defined");
}

#
# Now, load config
#

$fnret = OVH::Bastion::load_configuration();
$fnret or main_exit(OVH::Bastion::EXIT_CONFIGURATION_FAILURE, "configuration_failure", $fnret->msg);
my $config = $fnret->value;

my $bastionName = $config->{'bastionName'};
my $osh_debug   = $config->{'debug'};

# REALM case: somebody from another realm (named xyz) connects with the realm_xyz account here,
# and the real remote account name (which doesn't have an account here because it's from another realm)
# is passed through LC_BASTION
if ($self =~ /^realm_([a-zA-Z0-9_.-]+)/) {
    $self = sprintf("%s/%s", $1, $ENV{'LC_BASTION'});
    $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $self, realmOnly => 1);
    $fnret or main_exit(OVH::Bastion::EXIT_ACCOUNT_INVALID, "account_invalid", "The realm-scoped account '$self' is invalid (" . $fnret->msg . ")");
}
else {
    # non-realm case
    $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $self);
    $fnret or main_exit(OVH::Bastion::EXIT_ACCOUNT_INVALID, "account_invalid", "The account is invalid (" . $fnret->msg . ")");
}
{
    my %values = %{$fnret->value};
    ($sysself, $self, $realm, $remoteself) = @values{qw{ sysaccount account realm remoteaccount }};
}

#
# First Check : is USER valid ?
#
my $activenessDenyOnFailure = OVH::Bastion::config("accountExternalValidationDenyOnFailure")->value;
my $msg_to_print_delayed;    # if set, will be osh_warn()'ed if we're connecting through ssh (i.e. not scp, it breaks it)
$fnret = OVH::Bastion::is_account_active(account => $self);
if ($fnret) {
    ;                        # OK
}
elsif ($fnret->is_ko || ($activenessDenyOnFailure && $fnret->is_err)) {
    main_exit OVH::Bastion::EXIT_ACCOUNT_INACTIVE, "account_inactive", "Your account is inactive, $self, sorry";
}
else {
    $msg_to_print_delayed = $fnret->msg;
}

#
# Now : are we in maintenance mode ?
#
if (-e '/home/allowkeeper/maintenance') {
    osh_crit "This bastion is currently in maintenance mode, new connections are not allowed.";
    my $maintenance_message = '(unknown)';
    if (open(my $fh, '<', '/home/allowkeeper/maintenance')) {
        local $/ = undef;
        $maintenance_message = <$fh>;
        close($fh);
    }
    osh_warn "The maintenance reason is as follows: $maintenance_message";
    if (OVH::Bastion::is_admin()) {
        osh_warn "You are a bastion admin, allowing anyway, but it's really because it's you.";
    }
    else {
        main_exit(OVH::Bastion::EXIT_MAINTENANCE_MODE, "maintenance_mode", $maintenance_message);
    }
}

#
# Does the user have a TTL, and if yes, has it expired?
#

$fnret = OVH::Bastion::account_config(account => $self, key => "account_ttl");
if ($fnret) {
    if ($fnret->value !~ /^\d+$/) {
        main_exit(OVH::Bastion::EXIT_TTL_EXPIRED, "ttl_expired", "Your TTL has an invalid value, access denied. Check with an administrator.");
    }
    my $ttl = $fnret->value;

    $fnret = OVH::Bastion::account_config(account => $self, key => "creation_timestamp");
    if ($fnret->value !~ /^\d+$/) {
        main_exit(OVH::Bastion::EXIT_TTL_EXPIRED,
            "ttl_expired", "Your account creation date has an invalid value, and you have a TTL set, access denied. Check with an administrator.");
    }
    my $created = $fnret->value;

    if ($created + $ttl < time()) {
        main_exit(OVH::Bastion::EXIT_TTL_EXPIRED, "ttl_expired", "Sorry $self, your account has expired.");
    }
}

#
# Second check : has account logged-in recently enough to be allowed ?
#
$fnret = OVH::Bastion::is_account_nonexpired(sysaccount => $sysself, remoteaccount => $remoteself);
if ($fnret->is_err) {

    # internal error, warn and pass
    osh_warn($fnret);
}
elsif ($fnret->is_ko) {

    # expired
    main_exit OVH::Bastion::EXIT_ACCOUNT_EXPIRED, 'account_expired', $fnret->msg;
}
my $lastlog_filepath = $fnret->value->{'filepath'};

my $lastlogmsg = sprintf("Welcome to $bastionName, $self, this is your first connection");
if ($fnret && $fnret->value && $fnret->value->{'seconds'}) {
    my $lastloginfo = $fnret->value->{'info'} ? " from " . $fnret->value->{'info'} : "";
    $fnret = OVH::Bastion::duration2human(seconds => $fnret->value->{'seconds'}, tense => "past");
    $lastlogmsg = sprintf("Welcome to $bastionName, $self, your last login was %s ago (%s)%s", $fnret->value->{'duration'}, $fnret->value->{'date'}, $lastloginfo);
}

# ok not expired, so we update lastlog
if ($lastlog_filepath && open(my $lastlogfh, '>', $lastlog_filepath)) {
    print $lastlogfh sprintf("%s(%s)", $ipfrom, $hostfrom);
    close($lastlogfh);
}
else {
    osh_warn "Couldn't update your lastlog ($lastlog_filepath: $!), contact a bastion admin";
}

#
# Fetch command options
#
my @saved_argv = @ARGV;

# these options are the ones on shell definition of user calling osh.pl,
# the user-passed commands are stringified after "-c" (as in sh -c)
# it's possible to define the shell as osh.pl --debug, to force debug
my $realOptions;
my $opt_debug;
my $result = GetOptions(
    "c=s"   => \$realOptions,    # user command under -c '...'
    "debug" => \$opt_debug,
);

if (not $result or not $realOptions) {
    help();
    main_exit OVH::Bastion::EXIT_UNKNOWN_COMMAND, "unknown_command", "Bad or empty command";
}

$osh_debug = 1 if $opt_debug;    # osh_debug was already 1 if specified in config file

# per-user debug ?
$fnret = OVH::Bastion::account_config(account => $self, key => "debug");
if ($fnret and $fnret->value() =~ /yes/) {
    $osh_debug = 1;
}

$ENV{'OSH_DEBUG'} = 1 if $osh_debug;

osh_debug("self=$self home=$home realm=$realm remoteself=$remoteself sysself=$sysself");
osh_debug("user-passed options : $realOptions");

#
#   Command params
#

my $port = 22;    # can be override by special port
my @toExecute;

# special case: mosh, in that case we have something like this in $realOptions
# mosh-server 'new' '-s' '-c' '256' '-l' 'LANG=en_US.UTF-8' '-l' 'LANGUAGE=en_US' '--' '--osh' 'info'
if ($realOptions =~ /^mosh-server (.+?) '--' (.*)/) {
    osh_debug("MOSH DETECTED (with params)");

    # remove mosh stuff and save it for later
    my $mosh = $1;
    $realOptions                      = $2;
    $ENV{'MOSH_SERVER_NETWORK_TMOUT'} = OVH::Bastion::config('moshTimeoutNetwork')->value();
    $ENV{'MOSH_SERVER_SIGNAL_TMOUT'}  = OVH::Bastion::config('moshTimeoutSignal')->value();

    # get @toExecute params from the stuff we got from mosh-client (stored in $mosh) ?
    # or maybe not... I don't trust users, and we need to override some things anyway (such as ports)
    @toExecute = qw{ mosh-server new -s -l LANG=en_US.UTF-8 -l LANGUAGE=en_US };

    # add what has been specified in the config
    my @moshCommandLine = split(/\s+/, OVH::Bastion::config('moshCommandLine')->value());
    push @toExecute, @moshCommandLine if @moshCommandLine;

    # okay, just extract the -c 256 / -c 8 from the command because it depends on the user terminal spec
    my $colors = 8;    # by default
    if ($mosh =~ m/'-c' '(\d+)'/) {
        $colors = $1;
    }
    push @toExecute, ('-c', $colors, '--');

    # mosh has the bad habit of surrounding every param with simple quotes ('), and escaping ' by '\'',
    # because it thinks we are a POSIX shell, but we're not. So get around that
    osh_debug("mosh params: $2");

    # now unescape mosh params... yay regexes!
    $realOptions =~ s/(?<!\\)'//g;
    $realOptions =~ s/\\'/'/g;
    osh_debug("after mosh parsing, remaining realOptions: <$realOptions>");
    if (not $config->{'moshAllowed'}) {
        main_exit OVH::Bastion::EXIT_MOSH_DISABLED, "mosh_disabled", "Mosh support has been disabled on this bastion";
    }
}
elsif ($realOptions =~ /^mosh-server /) {
    osh_debug("MOSH DETECTED (without any param)");

    # we won't really use mosh, as we'll exit later with the bastion help anyway
    $realOptions = '';
}

# If there is a '--' in command line, protect all the end of the command line
# in order to let it in one block after command line parsing

my $beforeOptions;
my $afterOptions;

if ($realOptions =~ /^(.*?) -- (.*)$/) {
    $beforeOptions = $1;
    $afterOptions  = $2;
    osh_debug("before <$beforeOptions> after <$afterOptions>");
    if (($config->{'remoteCommandEscapeByDefault'} and not $beforeOptions =~ /(^| )--never-escape( |$)/)
        or $beforeOptions =~ /(^| )--always-escape( |$)/)
    {
        # ugly / legacy mode: escape ' with \'
        $afterOptions =~ s/'/\\'/g;
        osh_debug("afterOptions after legacy voodoo is <$afterOptions>");
    }
    else {
        osh_debug("afterOptions without legacy voodoo is <$afterOptions>");
    }
}
else {
    # we have no -- delimiter, either there was no remote command (that's fine),
    # or it's indistinguishable from the bastion options, in that case GetOptionsFromString
    # will leave what it doesn't recognize, will also fuck up "" and '', but users are warned
    # to always use -- anyway, and we'll use that as a remote command
    $beforeOptions = $realOptions;
    $afterOptions  = undef;          # will contain the GetOptionsFromString leftovers
}

my $remainingOptions;
($result, $remainingOptions) = GetOptionsFromString(
    $beforeOptions,
    "port|p=i"        => \my $optPort,
    "verbose+"        => \my $verbose,
    "tty|t"           => \my $tty,
    "no-tty|T"        => \my $notty,
    "user|u=s"        => \my $user,
    "osh=s"           => \my $osh_command,
    "telnet|e"        => \my $telnet,
    "password=s"      => \my $passwordFile,
    "P"               => \my $selfPassword,
    "host|h=s"        => \my $host,
    "help"            => \my $help,
    "long-help"       => \my $longHelp,
    "quiet|q"         => \my $quiet,
    "timeout=i"       => \my $timeout,
    "bind=s"          => \my $bind,
    "debug"           => \my $debug,
    "json"            => \my $json,
    "json-greppable"  => \my $json_greppable,
    "json-pretty"     => \my $json_pretty,
    "always-escape"   => \my $_dummy1,              # not used as corresponding option has already been ninja-used above
    "never-escape"    => \my $_dummy2,              # not used as corresponding option has already been ninja-used above
    "interactive|i"   => \my $interactive,
    "netconf"         => \my $netconf,
    "wait"            => \my $wait,
    "ssh-as=s"        => \my $sshAs,
    "use-key=s"       => \my $useKey,
    "kbd-interactive" => \my $userKbdInteractive,
);

if (!$quiet && $realm && !$ENV{'OSH_NO_INTERACTIVE'}) {
    my $welcome =
      "You are now connected to " . colored($bastionName, "yellow") . ". Welcome, " . colored($remoteself, "yellow") . ", citizen of the " . colored($realm, "yellow") . " realm!";
    print colored("-" x (length($welcome) - 3 * 9) . "\n", "bold yellow");
    print $welcome. "\n";
    print colored("-" x (length($welcome) - 3 * 9) . "\n", "bold yellow");
    print "\n";
}
osh_debug("remainingOptions <" . join('/', @$remainingOptions) . ">");

if (defined $afterOptions and @$remainingOptions > 1) {

    # user specified -- but there are more than 1 unrecognized param (the 1 should be the user@host)
    # so we warn that we didn't understood
    osh_warn "WARN : I couldn't parse some of your options before the '--' delimiter, things are probably about to go very wrong\n";
}
if (not defined $afterOptions and @$remainingOptions > 1 and not $osh_command) {
    osh_warn "WARN : You did not use the '--' delimiter to pass your remote command, maybe something crazy will happen !\n";
}

if ($afterOptions) {
    push @$remainingOptions, split(/ /, $afterOptions);
    osh_debug("remainingOptionsAfterAdd <" . join('/', @$remainingOptions) . ">");
}

if ($json_pretty) {
    $ENV{'PLUGIN_JSON'} = 'PRETTY';
}
elsif ($json_greppable) {
    $ENV{'PLUGIN_JSON'} = 'GREP';
}
elsif ($json) {
    $ENV{'PLUGIN_JSON'} = 'DEFAULT';
}

if ($quiet || $json || $json_pretty || $json_greppable) {

    # remove colors
    $ENV{'ANSI_COLORS_DISABLED'} = 1;    # cf Term::ANSIColor;
}

if (!$result) {
    help();
    main_exit OVH::Bastion::EXIT_GETOPTS_FAILED, 'getopts_failed', "Error parsing command line options";
}

if ($help and not $osh_command) {
    help();
    main_exit OVH::Bastion::EXIT_OK, 'help', '';
}

if ($longHelp) {
    long_help();
    main_exit OVH::Bastion::EXIT_OK, 'long_help', '';
}

if ($bind) {
    $fnret = OVH::Bastion::get_bastion_ips();
    if ($fnret) {
        if (not grep { $bind eq $_ } @{$fnret->value}) {
            main_exit OVH::Bastion::EXIT_CONFLICTING_OPTIONS, "invalid_bind", "Invalid binding IP specified ($bind)";
        }
    }
}

if ($interactive and not $ENV{'OSH_NO_INTERACTIVE'}) {
    if (not $config->{'interactiveModeAllowed'}) {
        main_exit OVH::Bastion::EXIT_INTERACTIVE_DISABLED, "interactive_disabled", "Interactive mode has been disabled on this bastion";
    }
    if ($osh_command) {
        main_exit OVH::Bastion::EXIT_CONFLICTING_OPTIONS, "conflicting_options", "Incompatible options specified: --interactive and --osh";
    }
    if (@toExecute) {

        # hmm, we are under mosh, mosh needs something to exec, so let's
        # re-exec ourselves in interactive mode
        exec(@toExecute, $0, '-c', $realOptions);
    }

    my $logret = OVH::Bastion::log_access_insert(
        account     => $self,
        cmdtype     => 'interactive',
        allowed     => 1,
        ipfrom      => $ipfrom,
        hostfrom    => $hostfrom,
        portfrom    => $portfrom,
        bastionhost => $bastionhost,
        bastionip   => $bastionip,
        bastionport => $bastionport,
        ipto        => undef,
        hostto      => undef,
        portto      => undef,
        user        => undef,
        plugin      => undef,
        params      => undef,
        comment     => undef,
        uniqid      => $log_uniq_id
    );
    if ($logret) {

        # needed for the log_access_update func after we're done with the command
        $log_insert_id = $logret->value->{'insert_id'};
        $log_db_name   = $logret->value->{'db_name'};
    }
    else {
        osh_warn($logret->msg);
    }

    OVH::Bastion::interactive(realOptions => $realOptions, timeoutHandler => \&exit_sig, self => $self);

    # this functions may never return, especially in case of idle timeout exit

    if (defined $log_insert_id and defined $log_db_name) {
        $logret = OVH::Bastion::log_access_update(
            insert_id     => $log_insert_id,
            db_name       => $log_db_name,
            uniq_id       => $log_uniq_id,
            returnvalue   => undef,
            plugin_stdout => undef,
            plugin_stderr => undef
        );
        $logret or osh_warn($logret->msg);
    }
    main_exit OVH::Bastion::EXIT_OK, 'interactive', '';
}

# If it's an osh command
# we'll pass the remaining options to the plugin
my $remainingOptionsCounter = scalar(@$remainingOptions);
my $command;
if ($osh_command) {
    ($help)      and $ENV{'PLUGIN_HELP'}  = 1;
    ($quiet)     and $ENV{'PLUGIN_QUIET'} = 1;
    ($osh_debug) and $ENV{'PLUGIN_DEBUG'} = 1;
    ($debug)     and $ENV{'PLUGIN_DEBUG'} = 1;
    osh_debug('Going got pass the following supplement args to plugin: ' . join('^', @$remainingOptions));
}
else {
    # it's ssh or telnet =>  it may remain at least 'host' or 'user@host'
    osh_debug("Remaining options " . join('/', @$remainingOptions));
    if ($remainingOptionsCounter == 0) {
        if (!$host) {
            help();
            main_exit OVH::Bastion::EXIT_NO_HOST, 'no_host', "No osh command specified and no host to connect to";
        }
        else {
            ;    # we have an host with option -h
        }
    }
    else {
        $host = shift(@{$remainingOptions});
        if ($host eq '-osh' || $host eq '--osh') {

            # special case when using -osh without argument
            $osh_command = 'help';
            $host        = '';
        }
        else {
            $remainingOptionsCounter--;
            osh_debug("host = $host");
            if ($host =~ /^([\S\d\w\.\-_]+)\@([\S\d\w\.\-_]+)$/) {
                $user = $1;
                $host = $2;
            }
            osh_debug("user $user host $host");
        }
    }

    if ($remainingOptionsCounter > 0) {
        $command .= join(' ', @$remainingOptions);
        osh_debug("Going to add extra command $command");
    }
}

# Get real ip from host
$fnret = R('ERR_INTERNAL', silent => 1);
my $ip = undef;

# if: avoid loading Net::IP and BigInt if there's no host specified
if ($host) {
    $fnret = OVH::Bastion::get_ip(host => $host);
}
if (!$fnret) {

    # exit error when not osh ...
    if (!$osh_command) {
        main_exit OVH::Bastion::EXIT_HOST_NOT_FOUND, 'host_not_found', "Unable to resolve host '$host' ($fnret)";
    }
    elsif ($host && $host !~ m{^[0-9.:]+/\d+$})    # in some osh plugins, ip/mask is accepted, don't yell.
    {
        osh_warn("I was unable to resolve host '$host'. Something shitty might happen.");
    }
}
else {
    $ip = $fnret->value->{'ip'};
}

osh_debug("will work on IP $ip");

# Check if we got a telnet or ssh password user
my $userPasswordClue;
my $userPasswordContext;
if (defined $user and $user =~ /^(telnet|ssh)-passw(or)?d-([^-]+)(-([^-]+))?$/) {
    my $method = $1;

    # update user
    $user = $3;

    if ($4) {
        $userPasswordClue = $5;
    }
    else {
        $userPasswordClue = $user;
    }

    if ($method eq 'telnet') {

        # as if user specified -e aka --telnet
        $telnet = 1;
    }

    $userPasswordContext = 'group';
}
elsif ($passwordFile) {
    $userPasswordClue    = $passwordFile;
    $userPasswordContext = 'group';
}
elsif ($selfPassword) {
    $userPasswordClue    = $self;
    $userPasswordContext = 'self';
}

osh_debug("Will use password file $userPasswordClue with user $user under context $userPasswordContext") if $userPasswordClue;

if ($optPort) {
    $port = $optPort;
}
elsif ($telnet) {
    $port = 23;
}
else {
    $port = 22;
}

if ($telnet && !$config->{'telnetAllowed'}) {
    main_exit OVH::Bastion::EXIT_ACCESS_DENIED, 'telnet_denied', "Sorry, the telnet protocol has been disabled by policy";
}

if ($userKbdInteractive && !$config->{'keyboardInteractiveAllowed'}) {
    main_exit OVH::Bastion::EXIT_CONFLICTING_OPTIONS, 'kbd_interactive_denied', "Sorry, the keyboard-interactive egress authentication scheme has been disabled by policy";
}
$ENV{'OSH_KBD_INTERACTIVE'} = 1 if $userKbdInteractive;    # useful for plugins that need to call ssh by themselves (for example to test a connection, i.e. groupAddServer)

# MFA enforcing for ingress connection, either on global bastion config, or on specific account config
my $mfaPolicy               = OVH::Bastion::config('accountMFAPolicy')->value;
my $isMfaPasswordConfigured = OVH::Bastion::is_user_in_group(account => $sysself, group => OVH::Bastion::MFA_PASSWORD_CONFIGURED_GROUP);
my $isMfaTOTPConfigured     = OVH::Bastion::is_user_in_group(account => $sysself, group => OVH::Bastion::MFA_TOTP_CONFIGURED_GROUP);
my $isMfaPasswordRequired   = OVH::Bastion::is_user_in_group(account => $sysself, group => OVH::Bastion::MFA_PASSWORD_REQUIRED_GROUP);
my $hasMfaPasswordBypass    = OVH::Bastion::is_user_in_group(account => $sysself, group => OVH::Bastion::MFA_PASSWORD_BYPASS_GROUP);
my $isMfaTOTPRequired       = OVH::Bastion::is_user_in_group(account => $sysself, group => OVH::Bastion::MFA_TOTP_REQUIRED_GROUP);
my $hasMfaTOTPBypass        = OVH::Bastion::is_user_in_group(account => $sysself, group => OVH::Bastion::MFA_TOTP_BYPASS_GROUP);
if ($mfaPolicy ne 'disabled' && !grep { $osh_command eq $_ } qw{ selfMFASetupPassword selfMFASetupTOTP help info }) {

    if (($mfaPolicy eq 'password-required' && !$hasMfaPasswordBypass) || $isMfaPasswordRequired) {
        main_exit(OVH::Bastion::EXIT_MFA_PASSWORD_SETUP_REQUIRED,
            'mfa_password_setup_required',
            "Sorry, but you need to setup the Multi-Factor Authentication before using this bastion, please use the `--osh selfMFASetupPassword' option to do so")
          if !$isMfaPasswordConfigured;
    }

    if (($mfaPolicy eq 'totp-required' && !$hasMfaTOTPBypass) || $isMfaTOTPRequired) {
        main_exit(OVH::Bastion::EXIT_MFA_TOTP_SETUP_REQUIRED,
            'mfa_totp_setup_required',
            "Sorry, but you need to setup the Multi-Factor Authentication before using this bastion, please use the `--osh selfMFASetupTOTP' option to do so")
          if !$isMfaTOTPConfigured;
    }

    if ($mfaPolicy eq 'any-required' && (!$isMfaPasswordConfigured && !$hasMfaPasswordBypass) && (!$isMfaTOTPConfigured && !$hasMfaTOTPBypass)) {
        main_exit(OVH::Bastion::EXIT_MFA_ANY_SETUP_REQUIRED, 'mfa_any_setup_required',
"Sorry, but you need to setup the Multi-Factor Authentication before using this bastion, please use either the `--osh selfMFASetupPassword' or the `--osh selfMFASetupTOTP' option, at your discretion, to do so"
        );
    }
}

# /MFA enforcing

osh_debug("self     : "
      . (defined $self ? $self : '<undef>') . "\n"
      . "user       : "
      . (defined $user ? $user : '<undef>') . "\n"
      . "host       : "
      . (defined $host ? $host : '<undef>') . "\n"
      . "port       : "
      . (defined $port ? $port : '<undef>') . "\n"
      . "verbose    : "
      . (defined $verbose ? $verbose : '<undef>') . "\n"
      . "tty        : "
      . (defined $tty ? $tty : '<undef>') . "\n"
      . "osh        : "
      . (defined $osh_command ? $osh_command : '<undef>') . "\n"
      . "command    : "
      . (defined $command ? $command : '<undef>')
      . "\n");

my $hostto = OVH::Bastion::ip2host($host)->value || $host;

# Special case: adminSudo for ssh connection as another user
if ($sshAs) {
    $fnret = OVH::Bastion::is_admin(account => $self);
    my $logret = OVH::Bastion::log_access_insert(
        account     => $self,
        cmdtype     => 'sshas',
        allowed     => $fnret ? 1 : 0,
        ipfrom      => $ipfrom,
        hostfrom    => $hostfrom,
        portfrom    => $portfrom,
        bastionhost => $bastionhost,
        bastionip   => $bastionip,
        bastionport => $bastionport,
        ipto        => $ip,
        hostto      => $hostto,
        portto      => $optPort,
        user        => $user,
        plugin      => undef,
        params      => join(' ', @$remainingOptions),
        comment     => undef,
        uniqid      => $log_uniq_id
    );
    if (!$fnret) {
        main_exit OVH::Bastion::EXIT_RESTRICTED_COMMAND, "sshas_denied", "Sorry, this feature is reserved to bastion administrators. Your attempt has been logged.";
    }
    if ($osh_command) {
        main_exit OVH::Bastion::EXIT_CONFLICTING_OPTIONS, "conflicting_options",
          "Can't use --ssh-as and --osh together. If you want to run a plugin as another user, use --osh adminSudo";
    }
    $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $sshAs);
    $fnret or main_exit OVH::Bastion::EXIT_ACCESS_DENIED, 'invalid_account', "Sorry, the specified account is invalid";

    my @cmd = qw( sudo -n -u );
    push @cmd, $sshAs;
    push @cmd, qw( -- /usr/bin/env perl );
    push @cmd, $OVH::Bastion::BASEPATH . '/bin/shell/osh.pl';
    push @cmd, '-c';

    my @forwardOptions;
    push @forwardOptions, "--user", $user if $user;
    push @forwardOptions, "--host", $host if $host;
    push @forwardOptions, "--port", $port if $port;
    push @forwardOptions, @$remainingOptions if ($remainingOptions and @$remainingOptions);

    if (not @forwardOptions) {
        main_exit OVH::Bastion::EXIT_NO_HOST, 'no_host', "No osh command specified and no host to connect to";
    }

    push @cmd, join(" ", @forwardOptions);

    OVH::Bastion::syslogFormatted(
        criticity => 'info',
        type      => 'security',
        fields    => [['type', 'admin-ssh-as'], ['account' => $self], ['sudo-as', $sshAs], ['plugin', 'ssh'], ['params', join(" ", @forwardOptions)]]
    );

    osh_warn("ADMIN SUDO: $self, you'll now impersonate $sshAs, this has been logged.");

    exec(@cmd) or main_exit(OVH::Bastion::EXIT_EXEC_FAILED, "ssh_as_failed", "Couldn't start a session under the account $sshAs ($!)");
}

#
#   First case. We have an OSH command
#
if ($osh_command) {

    # For backward compatibility, accept old names of plugins
    my %legacy2new = qw(
      accountAddFullGroupAccess     groupAddMember
      accountDelFullGroupAccess     groupDelMember
      accountAddPartialGroupAccess  groupAddGuestAccess
      accountDelPartialGroupAccess  groupDelGuestAccess
      accountListPartialGroupAccess groupListGuestAccesses
      selfListKeys                  selfListIngressKeys
      selfAddKey                    selfAddIngressKey
      selfDelKey                    selfDelIngressKey
      selfListBastionKeys           selfListEgressKeys
      selfGenerateBastionKey        selfGenerateEgressKey
      selfAddPrivateAccess          selfAddPersonalAccess
      selfDelPrivateAccess          selfDelPersonalAccess
      accountAddPrivateAccess       accountAddPersonalAccess
      accountDelPrivateAccess       accountDelPersonalAccess
      accountListBastionKeys        accountListEgressKeys
      accountListKeys               accountListIngressKeys
      accountResetKeys              accountResetIngressKeys
      helloWorld                    info
      groupGenerateEgressPassword   groupGeneratePassword
      groupListEgressPasswords      groupListPasswords
      selfListEgressPasswords       selfListPasswords
    );
    $osh_command = $legacy2new{$osh_command} if $legacy2new{$osh_command};

    # Then test for rights
    $fnret = OVH::Bastion::can_account_execute_plugin(account => $self, plugin => $osh_command);

    my $logret = OVH::Bastion::log_access_insert(
        account     => $self,
        cmdtype     => 'osh',
        allowed     => ($fnret ? 1 : 0),
        ipfrom      => $ipfrom,
        hostfrom    => $hostfrom,
        portfrom    => $portfrom,
        bastionhost => $bastionhost,
        bastionip   => $bastionip,
        bastionport => $bastionport,
        ipto        => $ip,
        hostto      => $hostto,
        portto      => $optPort,
        user        => $user,
        plugin      => $osh_command,
        params      => join(' ', @$remainingOptions),
        comment     => 'plugin-' . ($fnret->value ? $fnret->value->{'type'} : 'UNDEF'),
        uniqid      => $log_uniq_id
    );
    if ($logret) {

        # needed for the log_access_update func after we're done with the command
        $log_insert_id = $logret->value->{'insert_id'};
        $log_db_name   = $logret->value->{'db_name'};
    }
    else {
        warn_syslog("Failed to insert access log: " . $logret->msg);
        if ($ip eq '127.0.0.1') {
            osh_warn("Would deny access on out of space condition but you're root\@127.0.0.1, I hope you're here to fix me!");
        }
        else {
            main_exit OVH::Bastion::EXIT_OUT_OF_SPACE, 'out_of_space', "Bastion is out of space, admin intervention is needed! (" . $logret->msg . ")";
        }
    }

    if ($fnret) {
        my @cmd = ($fnret->value->{'fullpath'}, $user, $ip, $host, $optPort, @$remainingOptions);

        # is plugin explicitly disabled?
        my $isDisabled = OVH::Bastion::plugin_config(plugin => $osh_command, key => "disabled");

        # plugin is enabled by default if not explicitly disabled
        if ($isDisabled and $isDisabled->value() =~ /yes/) {
            main_exit OVH::Bastion::EXIT_RESTRICTED_COMMAND, "plugin_disabled", "Sorry, this plugin has been disabled by policy.";
        }
        if ($isDisabled->is_err && $isDisabled->err ne 'KO_NO_SUCH_FILE') {
            warn_syslog("Failed to tell whether the '$osh_command' plugin is enabled or not (" . $isDisabled->msg . ")");
            main_exit OVH::Bastion::EXIT_RESTRICTED_COMMAND, "plugin_disabled",
              "Sorry, a configuration error prevents us to check whether this plugin is enabled, warn your sysadmin!";
        }

        # check if we need JIT MFA to call this plugin, this can be configured per-plugin
        # TODO: autodetect if the MFA check is done outside of the code by sshd+PAM, to avoid re-asking for it here
        my $MFArequiredForPlugin = OVH::Bastion::plugin_config(plugin => $osh_command, key => "mfa_required")->value;
        $MFArequiredForPlugin ||= 'none';    # no config means none
                                             # some plugins need an explicit MFA check before being called (mainly plugins manipulating authentication factors)
                                             # if the user wants to reset one of its MFA tokens, force require MFA
        if ((grep { $osh_command eq $_ } qw{ selfMFAResetPassword selfMFAResetTOTP }) && ($MFArequiredForPlugin eq 'none')) {

            # enforce MFA in those cases, even if it's not configured
            $MFArequiredForPlugin = 'any';
        }

        # if the user wants to setup TOTP, if it happens to be already set (or any other factor), require it too
        # note: this is not needed for selfMFASetupPassword, because `passwd` does the job of asking the previous password
        elsif ($osh_command eq 'selfMFASetupTOTP' && ($isMfaTOTPConfigured || $isMfaPasswordConfigured) && ($MFArequiredForPlugin eq 'none')) {
            $MFArequiredForPlugin = 'any';
        }

        if (!grep { $MFArequiredForPlugin eq $_ } qw{ password totp any none }) {
            main_exit(OVH::Bastion::EXIT_MFA_FAILED, 'mfa_plugin_configuration_failed', "MFA configuration is incorrect for this plugin, report to your sysadmin!");
        }
        my $skipMFA = 0;
        if ($MFArequiredForPlugin eq 'password' && !$isMfaPasswordConfigured) {
            if ($hasMfaPasswordBypass) {
                $skipMFA = 1;
            }
            else {
                main_exit(OVH::Bastion::EXIT_MFA_PASSWORD_SETUP_REQUIRED,
                    'mfa_password_setup_required',
                    "Sorry, but you need to setup the Multi-Factor Authentication before using this command,\n" . "please use the `--osh selfMFASetupPassword' option to do so");
            }
        }
        elsif ($MFArequiredForPlugin eq 'totp' && !$isMfaTOTPConfigured) {
            if ($hasMfaTOTPBypass) {
                $skipMFA = 1;
            }
            else {
                main_exit(OVH::Bastion::EXIT_MFA_TOTP_SETUP_REQUIRED,
                    'mfa_totp_setup_required',
                    "Sorry, but you need to setup the Multi-Factor Authentication before using this command,\n" . "please use the `--osh selfMFASetupTOTP' option to do so");
            }
        }
        elsif ($MFArequiredForPlugin eq 'any' && !$isMfaTOTPConfigured && !$isMfaPasswordConfigured) {
            if ($hasMfaPasswordBypass && $hasMfaTOTPBypass) {
                $skipMFA = 1;
            }
            else {
                main_exit(OVH::Bastion::EXIT_MFA_ANY_SETUP_REQUIRED, 'mfa_any_setup_required',
                        "Sorry, but you need to setup the Multi-Factor Authentication before using this command,\n"
                      . "please use either the `--osh selfMFASetupPassword' or the `--osh selfMFASetupTOTP' option, at your discretion, to do so");
            }
        }

        # and start the MFA phase if needed
        if ($MFArequiredForPlugin ne 'none' && !$skipMFA) {
            print "As this is required to run this plugin, entering MFA phase.\n";

            # use system() instead of OVH::Bastion::execute() because we need it to grab the term
            my $pamtries = 3;
            while (1) {
                y $pamsysret;
                if (OVH::Bastion::is_freebsd()) {
                    $pamsysret = system('sudo', '-n', '-u', 'root', '--', '/usr/bin/env', 'pamtester', 'sshd', $sysself, 'authenticate');
                }
                else {
                    $pamsysret = system('pamtester', 'sshd', $sysself, 'authenticate');
                }
                if ($pamsysret < 0) {
                    main_exit(OVH::Bastion::EXIT_MFA_FAILED, 'mfa_failed', "MFA is required for this plugin, but this bastion is missing the `pamtester' tool, aborting");
                }
                elsif ($pamsysret != 0) {
                    if (--$pamtries <= 0) {
                        main_exit(OVH::Bastion::EXIT_MFA_FAILED, 'mfa_failed', "Sorry, but Multi-Factor Authentication failed, aborting");
                    }
                    next;
                }

                # success, if we are configured to launch a external command on pamtester success, do it.
                # see the bastion.conf.dist file for usage example.
                my $MFAPostCommand = OVH::Bastion::config('MFAPostCommand')->value;
                if (ref $MFAPostCommand eq 'ARRAY' && @$MFAPostCommand) {
                    s/%ACCOUNT%/$self/g for @$MFAPostCommand;
                    $fnret = OVH::Bastion::execute(cmd => $MFAPostCommand, must_succeed => 1);
                    if (!$fnret) {
                        warn_syslog("MFAPostCommand returned a non-zero value: " . $fnret->msg);
                    }
                }
                last;
            }
        }

        OVH::Bastion::set_terminal_mode_for_plugin(plugin => $osh_command, action => 'set');

        # get the execution mode required by the plugin
        my $is_binary;
        my $system;
        $fnret = OVH::Bastion::plugin_config(plugin => $osh_command, key => "execution_mode_on_$^O");
        if (!$fnret || !$fnret->value) {
            $fnret = OVH::Bastion::plugin_config(plugin => $osh_command, key => "execution_mode");
        }
        if ($fnret && $fnret->value) {
            $system    = 1 if $fnret->value eq 'system';
            $is_binary = 1 if $fnret->value eq 'binary';
        }
        $ENV{'OSH_IP_FROM'} = $ipfrom;    # used in some plugins for is_access_granted()
        $fnret = OVH::Bastion::execute(
            cmd           => \@cmd,
            noisy_stdout  => 1,
            noisy_stderr  => 1,
            expects_stdin => 1,
            system        => $system,
            is_binary     => $is_binary,
        );
        OVH::Bastion::set_terminal_mode_for_plugin(plugin => $osh_command, action => 'restore');

        if (defined $log_insert_id and defined $log_db_name) {
            $logret = OVH::Bastion::log_access_update(
                insert_id     => $log_insert_id,
                db_name       => $log_db_name,
                uniq_id       => $log_uniq_id,
                returnvalue   => $fnret->value ? $fnret->value->{'sysret'} : undef,
                plugin_stdout => $fnret->value ? $fnret->value->{'stdout'} : undef,
                plugin_stderr => $fnret->value ? $fnret->value->{'stderr'} : undef
            );
            $logret or osh_warn($logret->msg);
        }
        exit($fnret->value ? $fnret->value->{'status'} : OVH::Bastion::EXIT_EXEC_FAILED);
    }
    else {
        if ($fnret->err eq 'KO_UNKNOWN_PLUGIN') {
            help();
            main_exit OVH::Bastion::EXIT_UNKNOWN_COMMAND, "unknown_command", $fnret->msg;
        }
        main_exit OVH::Bastion::EXIT_RESTRICTED_COMMAND, "restricted_command", $fnret->msg;
    }
}

#
#   Else, it's a ttyrec ssh or telnet connection
#

if (!$quiet) {
    if ($config->{'displayLastLogin'}) {
        osh_info($lastlogmsg);
        print "\n";
    }

    osh_warn($msg_to_print_delayed) if defined $msg_to_print_delayed;    # set if we had an error to print previously
}

# if no user yet, fix it to remote user
# do that here, cause sometimes we do not want to pass user to osh
$user = $user || $config->{'defaultLogin'} || $remoteself || $sysself;

# log request
osh_debug("final request : " . "$user\@$ip -p $port -- $command'\n");

my $displayLine = "$hostfrom:$portfrom => $self\@$bastionhost:$bastionport => $user\@$hostto:$port";

if (!$quiet) {
    print "$displayLine ...\n";
}

# before doing stuff, check if we have the right to connect somewhere (some users are locked only to osh commands)
$fnret = OVH::Bastion::account_config(account => $self, key => "osh_only");
if ($fnret and $fnret->value() =~ /yes/) {
    $fnret = R('KO_ACCESS_DENIED', msg => "You don't have the right to connect anywhere");
}
else {
    $fnret = OVH::Bastion::is_access_granted(account => $self, user => $user, ipfrom => $ipfrom, ip => $ip, port => $port, wantKeys => 1);
}

# so in the end, can we access the requested user@host machine ?
my $JITMFARequired;
if (!$fnret) {

    #   User is not allowed, exit
    my $message = $fnret->msg;
    if ($user eq $self) {
        $message .= " (tried with remote user '$user')";    # "root is not the default login anymore"
    }

    my $logret = OVH::Bastion::log_access_insert(
        account     => $self,
        cmdtype     => $telnet ? 'telnet' : 'ssh',
        allowed     => 0,
        ipfrom      => $ipfrom,
        hostfrom    => $hostfrom,
        portfrom    => $portfrom,
        bastionhost => $bastionhost,
        bastionip   => $bastionip,
        bastionport => $bastionport,
        ipto        => $ip,
        hostto      => $hostto,
        portto      => $port,
        user        => $user,
        params      => $command,
        uniqid      => $log_uniq_id
    );
    if (!$logret) {
        osh_warn($logret);
    }

    main_exit OVH::Bastion::EXIT_ACCESS_DENIED, 'access_denied', $message;
}

# else, keep calm and carry on
# build ttyrec command that'll prefix the real command
my $ttyrec_fnret = OVH::Bastion::build_ttyrec_cmdline(
    ip            => $ip,
    port          => $port,
    user          => $user,
    account       => $self,
    uniqid        => $log_uniq_id,
    home          => $home,
    realm         => $realm,
    remoteaccount => $remoteself,
    debug         => $osh_debug,
    tty           => $tty,
    notty         => $notty
);
main_exit(OVH::Bastion::EXIT_TTYREC_CMDLINE_FAILED, "ttyrec_failed", $ttyrec_fnret->msg) if !$ttyrec_fnret;

my @ttyrec   = @{$ttyrec_fnret->value->{'cmd'}};
my $saveFile = $ttyrec_fnret->value->{'saveFile'};

print " allowed ... log on($saveFile)\n\n" if !$quiet;

# now build the real command
my @command;

# if we want telnet (not ssh)
if ($telnet) {

    # TELNET PASSWORD AUTOLOGIN
    if ($userPasswordClue) {
        my $fnretpass = OVH::Bastion::get_passfile(hint => $userPasswordClue, context => $userPasswordContext, self => ($remoteself || $sysself), tryLegacy => 1);
        if (!$fnretpass) {
            main_exit OVH::Bastion::EXIT_PASSFILE_NOT_FOUND, "passfile-not-found", $fnretpass->msg;
        }
        $passwordFile = $fnretpass->value;
        osh_debug("going to use telnet with this password file : $passwordFile");
        print " will use TELNET with password autologin\n\n" unless $quiet;
        push @command, $OVH::Bastion::BASEPATH . '/bin/shell/autologin', 'telnet', $user, $ip, $port, $passwordFile, ($timeout ? $timeout : 45);
    }

    # TELNET PASSWORD INTERACTIVE
    else {
        print " will use TELNET with interactive password login\n\n" unless $quiet;
        push @command, '/usr/bin/telnet', '-l', $user, $host, $port;
    }
}

# if we want ssh (not telnet)
else {
    my @preferredAuths;

    # SSH PASSWORD AUTOLOGIN
    if ($userPasswordClue) {

        push @preferredAuths, 'keyboard-interactive';
        push @preferredAuths, 'password';

        my $fnretpass = OVH::Bastion::get_passfile(hint => $userPasswordClue, context => $userPasswordContext, self => ($remoteself || $sysself), tryLegacy => 1);
        if (!$fnretpass) {
            main_exit OVH::Bastion::EXIT_PASSFILE_NOT_FOUND, "passfile-not-found", $fnretpass->msg;
        }
        $passwordFile = $fnretpass->value;
        osh_debug("going to use ssh with this password file : $passwordFile");
        print " will use SSH with password autologin\n\n" unless $quiet;
        push @command, $OVH::Bastion::BASEPATH . '/bin/shell/autologin', 'ssh', $user, $ip, $port, $passwordFile, ($timeout ? $timeout : 45);

    }

    # SSH EGRESS KEYS (and maybe password interactive as a fallback if passwordAllowed)
    else {

        # ssh by key
        push @preferredAuths, 'publickey';

        # also set kbdinteractive if allowed in bastion config (needed for e.g. TOTP)
        push @preferredAuths, 'keyboard-interactive' if ($config->{'keyboardInteractiveAllowed'} && $userKbdInteractive);

        # also set password if allowed in bastion config (to allow users to enter a remote password interactively)
        push @preferredAuths, 'password' if $config->{'passwordAllowed'};

        push @command, '/usr/bin/ssh', $ip, '-l', $user, '-p', $port;

        my @keysToTry;
        print " will try the following accesses you have: \n" unless $quiet;
        foreach my $access (@{$fnret->value || []}) {
            foreach my $key (@{$access->{'sortedKeys'} || []}) {
                my $keyinfo = $access->{'keys'}{$key};
                my $type    = $access->{'type'} . " of " . $access->{'group'};
                if ($access->{'type'} =~ /^group/) {
                    $type = colored($access->{'type'}, $access->{'type'} eq 'group-member' ? 'green' : 'yellow');
                    $type .= " of " . colored($access->{'group'}, 'blue bold');
                }
                elsif ($access->{'type'} =~ /^personal/) {
                    $type = colored($access->{'type'}, 'red') . ' access';
                }
                my $generated = strftime("[%Y/%m/%d]", localtime($keyinfo->{'mtime'}));

                if ((not $useKey) || ($useKey eq $keyinfo->{'fingerprint'})) {
                    my $forced = ' ';
                    if ($useKey) {
                        $forced = colored(' (KEY FORCED ON CMDLINE)', 'bold red');
                    }
                    elsif ($access->{'forceKey'}) {
                        $forced = colored(' (KEY FORCED IN ACL)', 'bold red');
                    }
                    if ($access->{'mfaRequired'} && $access->{'mfaRequired'} ne 'none') {
                        $forced .= colored(' (MFA REQUIRED: ' . uc($access->{'mfaRequired'}) . ')', 'bold red');
                        $JITMFARequired = $access->{'mfaRequired'};
                    }
                    printf("  - %s with %s-%s key %s %s%s\n", $type, $keyinfo->{'family'}, $keyinfo->{'size'}, $keyinfo->{'fingerprint'}, $generated, $forced) unless $quiet;
                    push @keysToTry, $keyinfo->{'fullpath'} if not(grep { $_ eq $keyinfo->{'fullpath'} } @keysToTry);
                }
            }
        }
        if ($useKey and not @keysToTry) {
            print "  >>> No key matched the fingerprint you gave me ($useKey), connection will fail!\n";
        }
        print "\n" unless $quiet;

        foreach (@keysToTry) {
            if (-r) {
                osh_debug("Got a group key $_");
                push @command, '-i', $_;
            }
            else {
                osh_warn("Weird, key file $_ is not accessible");
            }
        }
    }

    if ($verbose) {
        foreach (1 .. $verbose) {
            push @command, '-v';
        }
    }
    push @command, '-q' if $quiet;
    push @command, '-t' if $tty;
    push @command, '-T' if $notty;
    push @command, '-o', "ConnectTimeout=$timeout" if $timeout;

    if (not $quiet) {
        $fnret = OVH::Bastion::account_config(account => $self, key => OVH::Bastion::OPT_ACCOUNT_IDLE_IGNORE, public => 1);
        if ($fnret && $fnret->value =~ /yes/) {
            osh_debug("Account is immune to idle");
        }
        else {
            if ($config->{'idleLockTimeout'}) {
                print("  /!\\ Your session will be locked after " . $config->{'idleLockTimeout'} . " seconds of inactivity, use `--osh unlock' to unlock it\n");
            }
            if ($config->{'idleKillTimeout'}) {
                print("  /!\\ Your session will be killed after " . $config->{'idleKillTimeout'} . " seconds of inactivity.\n");
            }
            print "\n" if ($config->{'idleLockTimeout'} || $config->{'idleKillTimeout'});
        }
    }

    push @command, '-o', 'PreferredAuthentications=' . (join(',', @preferredAuths));

    if ($config->{'sshClientHasOptionE'}) {
        push @command, '-E', $saveFile . '.sshdebug';
    }

    if ($config->{'sshClientDebugLevel'}) {
        foreach (1 .. $config->{'sshClientDebugLevel'}) {
            push @command, '-v';
        }
    }

    if ($netconf) {

        # in netconf mode, we must ask our ssh to request remote netconf subsystem
        push @command, '-s', 'netconf';
    }
    elsif ($command) {

        # the '--' is to force ssh (started by ttyrec (started by us)) to stop processing its options and pass the rest to remote shell
        push @command, '--', $command;
    }
}

# add remoteUser as LC_BASTION to be passed via ssh
$ENV{'LC_BASTION'} = $self;

if (!@command) {
    main_exit OVH::Bastion::EXIT_UNKNOWN_COMMAND, "empty_command", "Found no command to execute!";
}
else {

    # the '--' is to force ttyrec (started by us) to stop processing its options and execute the rest as is
    push @ttyrec, '--', @command;
}

# add binding IP if specified
# works for ssh *and* telnet
if ($bind) {
    push @command, '-b', $bind;
}

osh_debug("about to exec: " . join(' ', @ttyrec));

# if --wait is specified, we wait for the host to be alive before connecting
if ($wait) {
    my $startedat = time();
    osh_info "Pinging $host, will connect as soon as it's alive...";
    while (1) {
        my @pingcmd = qw{ fping -- };
        push @pingcmd, $host;

        my $fnretexec = OVH::Bastion::execute(cmd => \@pingcmd, noisy_stdout => 1, noisy_stderr => 1);
        $fnretexec or exit(OVH::Bastion::EXIT_EXEC_FAILED);
        if ($fnretexec->value->{'sysret'} == 0) {
            osh_info "Alive after waiting for " . (time() - $startedat) . " seconds, connecting...";
            sleep 2 if (time() > $startedat + 1);    # so that ssh has the time to startup... hopefully
            last;
        }
        sleep 1;
    }
}

my $logret = OVH::Bastion::log_access_insert(
    account     => $self,
    cmdtype     => $telnet ? 'telnet' : 'ssh',
    allowed     => 1,
    ipfrom      => $ipfrom,
    hostfrom    => $hostfrom,
    portfrom    => $portfrom,
    bastionhost => $bastionhost,
    bastionip   => $bastionip,
    bastionport => $bastionport,
    ipto        => $ip,
    hostto      => $hostto,
    portto      => $port,
    user        => $user,
    params      => join(' ', @ttyrec),
    ttyrecfile  => $saveFile,
    uniqid      => $log_uniq_id
);
if (!$logret) {
    osh_warn($logret);
    if ($ip eq '127.0.0.1') {
        osh_warn("Would deny access on out of space condition but you're root\@127.0.0.1, I hope you're here to fix me!");
    }
    else {
        main_exit OVH::Bastion::EXIT_OUT_OF_SPACE, 'out_of_space', "Bastion is out of space, admin intervention is needed! (" . $logret->msg . ")";
    }
    $logret->{'value'} = {};
}

# if we have JIT MFA, do it now
if ($JITMFARequired) {
    my $skipMFA = 0;
    print "As this is required for this host, entering MFA phase.\n";
    if ($JITMFARequired eq 'totp' && !$isMfaTOTPConfigured) {
        if ($hasMfaTOTPBypass) {
            $skipMFA = 1;
        }
        else {
            main_exit(OVH::Bastion::EXIT_MFA_TOTP_SETUP_REQUIRED,
                'mfa_totp_setup_required',
                "Sorry, but you need to setup the Multi-Factor Authentication before connecting to this host,\nplease use the `--osh selfMFASetupTOTP' option to do so");
        }
    }
    elsif ($JITMFARequired eq 'password' && !$isMfaPasswordConfigured) {
        if ($hasMfaPasswordBypass) {
            $skipMFA = 1;
        }
        else {
            main_exit(OVH::Bastion::EXIT_MFA_PASSWORD_SETUP_REQUIRED,
                'mfa_password_setup_required',
                "Sorry, but you need to setup the Multi-Factor Authentication before connecting to this host,\nplease use the `--osh selfMFASetupPassword' option to do so");
        }
    }
    elsif ($JITMFARequired eq 'any' && !$isMfaTOTPConfigured && !$isMfaPasswordConfigured) {
        if ($hasMfaPasswordBypass || $hasMfaTOTPBypass) {

            # FIXME: should actually be $hasMFABypassAll (not yet implemented)
            $skipMFA = 1;
        }
        else {
            main_exit(OVH::Bastion::EXIT_MFA_ANY_SETUP_REQUIRED, 'mfa_any_setup_required',
"Sorry, but you need to setup the Multi-Factor Authentication before connecting to this host,\nplease use either the `--osh selfMFASetupPassword' or the `--osh selfMFASetupTOTP' option, at your discretion, to do so"
            );
        }
    }

    if ($skipMFA) {
        print "... skipping as your account is exempt from MFA\n";
    }
    else {
        # use system() instead of OVH::Bastion::execute() because we need it to grab the term
        my $pamtries = 3;
        while (1) {
            my $pamsysret;
            if (OVH::Bastion::is_freebsd()) {
                $pamsysret = system('sudo', '-n', '-u', 'root', '--', '/usr/bin/env', 'pamtester', 'sshd', $sysself, 'authenticate');
            }
            else {
                $pamsysret = system('pamtester', 'sshd', $sysself, 'authenticate');
            }
            if ($pamsysret < 0) {
                main_exit(OVH::Bastion::EXIT_MFA_FAILED, 'mfa_failed', "MFA is required for this host, but this bastion is missing the `pamtester' tool, aborting");
            }
            elsif ($pamsysret != 0) {
                if (--$pamtries <= 0) {
                    main_exit(OVH::Bastion::EXIT_MFA_FAILED, 'mfa_failed', "Sorry, but Multi-Factor Authentication failed, I can't connect you to this host");
                }
                next;
            }

            # success, if we are configured to launch a external command on pamtester success, do it.
            # see the bastion.conf.dist file for usage example.
            my $MFAPostCommand = OVH::Bastion::config('MFAPostCommand')->value;
            if (ref $MFAPostCommand eq 'ARRAY' && @$MFAPostCommand) {
                s/%ACCOUNT%/$self/g for @$MFAPostCommand;
                $fnret = OVH::Bastion::execute(cmd => $MFAPostCommand, must_succeed => 1);
                if (!$fnret) {
                    warn_syslog("MFAPostCommand returned a non-zero value: " . $fnret->msg);
                }
            }
            last;
        }
    }
}

# here is a nice hack to drastically improve the memory footprint of an
# heavily used bastion. we exec() another script that is way lighter, see
# comments in the connect.pl file for more information.

if (!$quiet) {
    print "Connecting...\n";
}

push @toExecute, $OVH::Bastion::BASEPATH . '/bin/shell/connect.pl';
exec(
    @toExecute,                    $ip,                         $config->{'sshClientHasOptionE'}, $userPasswordClue, $saveFile,
    $logret->value->{'insert_id'}, $logret->value->{'db_name'}, $logret->value->{'uniq_id'},      @ttyrec
) or exit(OVH::Bastion::EXIT_EXEC_FAILED);

exit OVH::Bastion::EXIT_OK;

#
# FUNCTIONS follow
#

#
#   On SIG, still try to log in db
#
sub exit_sig {
    my ($sig) = @_;
    if (defined $log_insert_id and defined $log_db_name) {
        OVH::Bastion::log_access_update(
            insert_id   => $log_insert_id,
            db_name     => $log_db_name,
            uniq_id     => $log_uniq_id,
            returnvalue => -9999,
            comment     => 'signal_' . $sig
        );
    }
    exit OVH::Bastion::EXIT_OK;
}

#
#   Display help message
#
sub help {

=cut just to debug memory fingerprint
    use Devel::Size qw[total_size];
    my %siz;
    foreach (keys %::main::main::)
    {
        push @{ $siz{ total_size( $::main::main::{ $_ } ) } }, $_;
    }
    foreach (sort { $a <=> $b } keys %siz)
    {
        printf "%9d: %s\n", $_, join(' ', @{$siz{$_}});
    }
    exit OVH::Bastion::EXIT_OK;
=cut

    print STDERR <<"EOF" ;
    
The Bastion v$OVH::Bastion::VERSION quick usage examples:

    Connect to a server:              $bastionName admin\@srv1.example.org
    Run a command on a server:        $bastionName admin\@srv1.example.org -- uname -a

    List the osh commands:            $bastionName --osh help
    Help on a specific osh command:   $bastionName --osh OSH_COMMAND --help
    Enter interactive mode for osh:   $bastionName -i

    Get more complete help:           $bastionName --long-help

EOF
    return;
}

sub long_help {
    print STDERR <<"EOF" ;

Usage (ssh):     $bastionName [OPTIONS] [user\@]host [-- REMOTE_COMMAND]
Usage (telnet):  $bastionName -e [OPTIONS] [user\@]host
Usage (osh cmd): $bastionName --osh [OSH_COMMAND] [OSH_OPTIONS]

[OPTIONS]
    --host,    -h HOST   Host to connect to
    --user,    -u USER   Remote host user to connect as
    --port,    -p PORT   Port to use
    --telnet,  -e        Use telnet instead of ssh
    --timeout     DELAY  Specify a timeout for ssh or telnet egress connection
    --bind        IP     Force binding of the egress ssh connection to a specified local IP
    --password    GROUP  Use a group egress password instead of ssh keys to login (via ssh or telnet)
    --self-password, -P  Use your own personal account egress password instead of ssh keys to login (via ssh or telnet)
    --osh                Use an osh command (see --osh help to get a list)
    --interactive, -i    Enter interactive mode (useful to use multiple osh commands)
    --quiet,       -q    Disable most messages and colors, useful for scripts
    --always-escape      Bypass config and force the bugged behavior of old bastions for REMOTE_COMMAND escaping. Don't use.
    --never-escape       Bypass config and force the new behavior of new bastions for REMOTE_COMMAND escaping. Don't use.
    --wait               Ping the host before connecting to it (useful to ssh just after a reboot!)
    --long-help          Print this

[REMOTE_COMMAND]
    You can pass a command to execute on the remote machine. For complex commands, don't forget
    that your shell will eat one level of quotes and backslashes. One working example:
    $bastionName srv1.example.org -- "perl -e 'use Data::Dumper; print Dumper(\\\@ARGV)' one 'two is 2' three"

[OPTIONS (ssh)] :
    --verbose,  -v       Enable verbose ssh
    --tty,      -t       Force tty allocation
    --no-tty,   -T       Prevent tty allocation
    --use-key      FP    Explicitly specify the fingerprint of the egress key you want to use
    --kbd-interactive    Enable the keyboard-interactive authentication scheme on egress connection
    --netconf            Request to use netconf subsystem

[OPTIONS (osh cmd)]
    --json              Return data in json format between JSON_START and JSON_END tags
    --json-pretty       Prettify returned json, useful for debug / human reading
    --json-greppable    Return data in json format squashed on one line starting with JSON_DATA=

[OSH_COMMAND]
    These are used to interact with the bastion configuration, accesses,
    keys, accounts and groups. To get a list,
    use: $bastionName --osh help

[OSH_OPTIONS]
    Those options are specific for each OSH_COMMAND, to get help on those,
    use: $bastionName --osh OSH_COMMAND --help

EOF
    if (OVH::Bastion::is_admin(account => $self)) {
        print STDERR <<"EOF" ;
[ADMIN_OPTIONS]
    --ssh-as ACCOUNT    Impersonate another account to ssh connect somewhere on his or her behalf. This is logged.

EOF
    }
    return;
}
