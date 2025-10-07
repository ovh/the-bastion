#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use 5.026;
use common::sense;

use File::Basename;
use lib dirname(__FILE__) . '/../../lib/perl';
use OVH::Result;
use OVH::Bastion;

use Getopt::Long qw(GetOptionsFromString :config pass_through no_ignore_case no_auto_abbrev);
use Sys::Hostname;
use POSIX qw(strftime);
use Term::ANSIColor;
use JSON;

$| = 1;
my $fnret;

#
# Signals
#

$SIG{$_} = \&exit_sig for qw{ INT TERM HUP PIPE };

#
# Do just what is needed before the first call to main_exit in the code flow
#

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

    # always print to STDERR as some plugins (such as scp) won't display STDOUT
    $ENV{'FORCE_STDERR'} = 1;
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
    if ($ENV{'LC_BASTION'}) {

        # don't overwrite $self just yet because it might end up being invalid, and when we'll call main_exit 2 lines down,
        # we won't log to the proper place if sql logs or access logs are enabled per account.
        my $potentialSelf = sprintf("%s/%s", $1, $ENV{'LC_BASTION'});
        $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $potentialSelf, realmOnly => 1);
        $fnret
          or main_exit(OVH::Bastion::EXIT_ACCOUNT_INVALID,
            "account_invalid", "The realm-scoped account '$self' is invalid (" . $fnret->msg . ")");

        # $potentialSelf is valid, we can use it
        $self = $potentialSelf;
    }
    else {
        main_exit(OVH::Bastion::EXIT_ACCOUNT_INVALID,
            "account_invalid", "Attempted to use a realm account but not from another bastion");
    }
}
else {
    # non-realm case
    $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $self);
    $fnret
      or
      main_exit(OVH::Bastion::EXIT_ACCOUNT_INVALID, "account_invalid", "The account is invalid (" . $fnret->msg . ")");
}
{
    my %values = %{$fnret->value};
    ($sysself, $self, $realm, $remoteself) = @values{qw{ sysaccount account realm remoteaccount }};
}

#
# First Check : is USER valid ?
#
my $activenessDenyOnFailure = OVH::Bastion::config("accountExternalValidationDenyOnFailure")->value;
my $msg_to_print_delayed;    # if set, will be osh_warn()'ed if we're connecting through ssh (i.e. not scp/sftp, it breaks it)
$fnret = OVH::Bastion::is_account_active(account => $self);
if ($fnret) {
    ;                        # OK
}
elsif ($fnret->is_ko || ($activenessDenyOnFailure && $fnret->is_err)) {
    main_exit OVH::Bastion::EXIT_ACCOUNT_INACTIVE, "account_inactive", "Sorry $self, your account is inactive.";
}
else {
    $msg_to_print_delayed = $fnret->msg;
}

#
# is this account frozen?
#

$fnret = OVH::Bastion::is_account_nonfrozen(account => $self);
if (!$fnret) {
    my $msg          = "Sorry $self, your account is frozen.";
    my $freezeReason = $fnret->value->{'reason'};
    if ($freezeReason) {
        $msg = "Sorry $self, your account is frozen ($freezeReason).";
    }
    main_exit OVH::Bastion::EXIT_ACCOUNT_FROZEN, "account_frozen", $msg;
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

$fnret = OVH::Bastion::is_account_ttl_nonexpired(account => $self, sysaccount => $sysself);
if (!$fnret) {
    main_exit(OVH::Bastion::EXIT_TTL_EXPIRED, "ttl_expired", "Sorry $self, access denied (" . $fnret->msg . ")");
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
    $fnret      = OVH::Bastion::duration2human(seconds => $fnret->value->{'seconds'}, tense => "past");
    $lastlogmsg = sprintf(
        "Welcome to $bastionName, $self, your last login was %s ago (%s)%s",
        $fnret->value->{'duration'},
        $fnret->value->{'date'}, $lastloginfo
    );
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

# Check if this is a ProxyJump connection that should be executed directly
if ($ENV{'OSH_PROXYJUMP_CONNECTION'}) {
    osh_debug("Detected ProxyJump connection, executing command directly");
    
    # Extract the command from the realOptions or ARGV
    my $proxy_command;
    if (@ARGV && $ARGV[0] eq '-c' && $ARGV[1]) {
        $proxy_command = $ARGV[1];
    } else {
        $proxy_command = join(' ', @ARGV);
    }
    
    osh_debug("ProxyJump command: $proxy_command");
    
    # Execute the proxy command directly without further validation
    if ($proxy_command) {
        # Parse the command to extract program and arguments
        my @cmd_parts = split(/\s+/, $proxy_command);
        if (!@cmd_parts) {
            main_exit(OVH::Bastion::EXIT_EXEC_FAILED, "exec_failed", "Failed to parse proxy command");
        }
        
        # Remove "exec" if it's the first argument (the ssh subprocess puts that there)
        if ($cmd_parts[0] eq 'exec') {
            shift @cmd_parts;
        }

        # this should never happen, but just in case...
        if ($cmd_parts[0] ne 'ssh') {
            main_exit(OVH::Bastion::EXIT_EXEC_FAILED, "exec_failed", "Proxy command must start with 'ssh'");
        }
        
        osh_debug("Executing proxy command parts: " . join(' ', @cmd_parts));
        exec(@cmd_parts) or main_exit(OVH::Bastion::EXIT_EXEC_FAILED, "exec_failed", "Failed to execute proxy command: $!");
    } else {
        main_exit(OVH::Bastion::EXIT_EXEC_FAILED, "exec_failed", "No proxy command provided");
    }
}

# these options are the ones on shell definition of user calling osh.pl,
# the user-passed commands are stringified after "-c" (as in sh -c)
# it's possible to define the shell as osh.pl --debug, to force debug
my $realOptions;
my $opt_debug;
my $result = GetOptions(
    "c=s"   => \$realOptions,    # user command under -c '...'
    "debug" => \$opt_debug,
);
if (not $result) {
    help();
    main_exit OVH::Bastion::EXIT_UNKNOWN_COMMAND, "unknown_command", "Bad command";
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
if (defined $realOptions && $realOptions =~ /^mosh-server (.+?) '--' (.*)/) {
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
elsif (defined $realOptions && $realOptions =~ /^mosh-server /) {
    osh_debug("MOSH DETECTED (without any param)");

    # we won't really use mosh, as we'll exit later with the bastion help anyway
    $realOptions = '';
}

# If there is a '--' in command line, protect all the end of the command line
# in order to let it in one block after command line parsing

my $beforeOptions;
my $afterOptions;

if (defined $realOptions && $realOptions =~ /^(.*?) -- (.*)$/) {
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
    $beforeOptions // "",
    "port|p=i"                  => \my $optPort,
    "verbose+"                  => \my $verbose,
    "tty|t"                     => \my $tty,
    "no-tty|T"                  => \my $notty,
    "user|u=s"                  => \my $user,
    "osh=s"                     => \my $osh_command,
    "telnet|e"                  => \my $telnet,
    "password=s"                => \my $passwordFile,
    "self-password|P"           => \my $selfPassword,
    "host|h=s"                  => \my $host,
    "help"                      => \my $help,
    "long-help"                 => \my $longHelp,
    "quiet|q"                   => \my $quiet,
    "timeout=i"                 => \my $timeout,
    "bind=s"                    => \my $bind,
    "debug"                     => \my $debug,
    "json"                      => \my $json,
    "json-greppable"            => \my $json_greppable,
    "json-pretty"               => \my $json_pretty,
    "always-escape"             => \my $_dummy1,                 # not used as corresponding option has already been ninja-used above
    "never-escape"              => \my $_dummy2,                 # not used as corresponding option has already been ninja-used above
    "interactive|i"             => \my $interactive,
    "netconf"                   => \my $netconf,
    "wait"                      => \my $wait,
    "forward-agent|x"           => \my $sshAddKeysToAgent,
    "ssh-as=s"                  => \my $sshAs,
    "use-key=s"                 => \my $useKey,
    "kbd-interactive"           => \my $userKbdInteractive,
    "proactive-mfa"             => \my $proactiveMfa,
    "fallback-password-delay=i" => \my $fallbackPasswordDelay,
    "generate-mfa-token"        => \my $generateMfaToken,
    "mfa-token=s"               => \my $mfaToken,
    "term-passthrough"          => \my $termPassthrough,
    "J=s"                       => \my $proxyJump,
);
if (not defined $realOptions) {
    help();
    if (OVH::Bastion::config('interactiveModeByDefault')->value) {

        # nothing specified by the user, let's drop them to the interactive mode
        osh_warn("No command specified, entering interactive mode by default");
        $interactive = 1;
    }
    else {
        main_exit OVH::Bastion::EXIT_UNKNOWN_COMMAND, "unknown_command", "Missing command";
    }
}

if (!$quiet && $realm && !$ENV{'OSH_IN_INTERACTIVE_SESSION'}) {
    my $welcome =
        "You are now connected to "
      . colored($bastionName, "yellow")
      . ". Welcome, "
      . colored($remoteself, "yellow")
      . ", citizen of the "
      . colored($realm, "yellow")
      . " realm!";
    osh_print(colored("-" x (length($welcome) - 3 * 9), "bold yellow"));
    osh_print($welcome);
    osh_print(colored("-" x (length($welcome) - 3 * 9), "bold yellow"));
    osh_print('');
}
osh_debug("remainingOptions <" . join('/', @$remainingOptions) . ">");

if (defined $afterOptions and @$remainingOptions > 1) {

    # user specified -- but there are more than 1 unrecognized param (the 1 should be the user@host)
    # so we warn that we didn't understood
    osh_warn
      "WARN : I couldn't parse some of your options before the '--' delimiter, things are probably about to go very wrong\n";
}
if (not defined $afterOptions and @$remainingOptions > 1 and not $osh_command) {
    osh_warn
      "WARN : You did not use the '--' delimiter to pass your remote command, maybe something crazy will happen !\n";
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

if ($generateMfaToken && $mfaToken) {
    main_exit OVH::Bastion::EXIT_CONFLICTING_OPTIONS, "conflicting_options",
      "Can't specify both --generate-mfa-token and --mfa-token";
}

if ($tty && $notty) {
    main_exit OVH::Bastion::EXIT_CONFLICTING_OPTIONS, "tty_notty", "Options -t and -T are mutually exclusive";
}

# if proactive MFA has been requested, do it here, before the code diverts to either
# handling interactive session, plugins/osh commands, or a connection request
if ($proactiveMfa) {
    osh_print "As proactive MFA has been requested, entering MFA phase for $self.";
    $fnret = OVH::Bastion::do_pamtester(self => $self, sysself => $sysself);
    $fnret or main_exit(OVH::Bastion::EXIT_MFA_FAILED, 'mfa_failed', $fnret->msg);

    # if we're still here, it succeeded
    $ENV{'OSH_PROACTIVE_MFA'} = 1;
}

if ($interactive and not $ENV{'OSH_IN_INTERACTIVE_SESSION'}) {
    if (not $config->{'interactiveModeAllowed'}) {
        main_exit OVH::Bastion::EXIT_INTERACTIVE_DISABLED, "interactive_disabled",
          "Interactive mode has been disabled on this bastion";
    }
    if ($osh_command) {
        main_exit OVH::Bastion::EXIT_CONFLICTING_OPTIONS, "conflicting_options",
          "Incompatible options specified: --interactive and --osh";
    }
    if (@toExecute) {

        # hmm, we are under mosh, mosh needs something to exec, so let's
        # re-exec ourselves in interactive mode
        # TODO: does this work with proxyjump?
        exec(@toExecute, $0, '-c', $realOptions);
    }

    # TODO: log proxy info
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
            account     => $self,
            insert_id   => $log_insert_id,
            db_name     => $log_db_name,
            uniq_id     => $log_uniq_id,
            returnvalue => undef,
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
        osh_debug("After shift, remainingOptions " . join('/', @$remainingOptions));
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

my $proxyIp = undef;
my $proxyPort = 22;
# Parse proxyjump args if specified
if ($proxyJump) {
    if ($proxyJump =~ /^(\[?[a-zA-Z0-9._-]+\]?)(?::(\d+))?$/) {
        $proxyIp = $1;
        $proxyPort = $2 if $2;
        osh_debug("parsed proxyjump: host=$proxyIp port=$proxyPort");
    }
    else {
        main_exit OVH::Bastion::EXIT_INVALID_PROXYJUMP, 'invalid_proxyjump',
          "Invalid proxyjump specification '$proxyJump', should be host[:port]";
    }

    $fnret = OVH::Bastion::get_ip(host => $proxyIp, allowSubnets => 0);
    if (!$fnret && (($osh_command && $host) || !$osh_command)) {
        if ($fnret->err eq 'ERR_DNS_DISABLED') {
            main_exit OVH::Bastion::EXIT_DNS_DISABLED, 'dns_disabled', $fnret->msg;
        }
        elsif ($fnret->err eq 'ERR_IP_VERSION_DISABLED') {
            main_exit OVH::Bastion::EXIT_IP_VERSION_DISABLED, 'ip_version_disabled', $fnret->msg;
        }
        else {
            main_exit OVH::Bastion::EXIT_HOST_NOT_FOUND, 'host_not_found', $fnret->msg;
        }
    }
    $proxyIp = $fnret->value->{'ip'};
    osh_debug("Proxyjump host $proxyIp resolved to IP " . $fnret->value->{'ip'});

    $ENV{'OSH_PROXYJUMP_HOST'} = $proxyIp;
    $ENV{'OSH_PROXYJUMP_PORT'} = $proxyPort;
    $ENV{'OSH_PROXYJUMP_CONNECTION'} = 1;
}

# for plugins (osh_command), do a first check with allowWildcards, it'll be re-done in Plugin::start with
# either allowWildcards set to 0 or 1 depending on the plugin configuration that we don't have at this stage yet
if ($user && !OVH::Bastion::is_valid_remote_user(user => $user, allowWildcards => ($osh_command ? 1 : 0))) {
    main_exit OVH::Bastion::EXIT_INVALID_REMOTE_USER, 'invalid_remote_user', "Remote user name '$user' seems invalid";
}

# Get real ip from host
$fnret = R('ERR_MISSING_HOST', msg => "No host specified", silent => 1);
my $ip = undef;

# if: avoid loading Net::IP and BigInt if there's no host specified
if ($host) {

    # can be an IP (v4 or v6), hostname, or subnet (with a /)
    if ($host !~ m{^\[?[a-zA-Z0-9._/:-]+\]?$}) {
        main_exit OVH::Bastion::EXIT_INVALID_REMOTE_HOST, 'invalid_remote_host',
          "Remote host name '$host' seems invalid";
    }

    # subnets are only allowed for plugins
    if (index($host, '/') != -1 && !$osh_command) {
        main_exit OVH::Bastion::EXIT_INVALID_REMOTE_HOST, 'invalid_remote_host',
          "Remote host '$host' looks like a subnet, can't connect to that";
    }

    # probably this "host" is in fact an option, but we didn't parse it because it's an unknown one,
    # so we call the long_help() for the user, before exiting
    if ($host =~ m{^--}) {
        long_help();
        main_exit OVH::Bastion::EXIT_GETOPTS_FAILED, 'getopts_failed', "Couldn't parse option '$host'";
    }

    # otherwise, resolve the host
    $fnret = OVH::Bastion::get_ip(host => $host, allowSubnets => ($osh_command ? 1 : 0));

    # if it's a subnet but get_ip() sends an error, it's an invalid subnet
    if (!$fnret && index($host, '/') != -1) {
        main_exit OVH::Bastion::EXIT_INVALID_REMOTE_HOST, 'invalid_remote_host',
          "Remote host '$host' looks like a subnet, but with an invalid prefix";
    }
}

# if couldn't resolve host and either:
# - it's a plugin and a host was specified, or
# - it's not a plugin
# then exit
if (!$fnret && (($osh_command && $host) || !$osh_command)) {
    if ($fnret->err eq 'ERR_DNS_DISABLED') {
        main_exit OVH::Bastion::EXIT_DNS_DISABLED, 'dns_disabled', $fnret->msg;
    }
    elsif ($fnret->err eq 'ERR_IP_VERSION_DISABLED') {
        main_exit OVH::Bastion::EXIT_IP_VERSION_DISABLED, 'ip_version_disabled', $fnret->msg;
    }
    else {
        main_exit OVH::Bastion::EXIT_HOST_NOT_FOUND, 'host_not_found', $fnret->msg;
    }
}

# if host was resolved, store its IP
if ($fnret) {
    $ip = $fnret->value->{'ip'};
    osh_debug("will work on IP $ip");
}

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

osh_debug("Will use password file $userPasswordClue with user $user under context $userPasswordContext")
  if $userPasswordClue;

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
    main_exit OVH::Bastion::EXIT_ACCESS_DENIED, 'telnet_denied',
      "Sorry $self, the telnet protocol has been disabled by policy";
}

if ($userKbdInteractive && !$config->{'keyboardInteractiveAllowed'}) {
    main_exit OVH::Bastion::EXIT_CONFLICTING_OPTIONS, 'kbd_interactive_denied',
      "Sorry $self, the keyboard-interactive egress authentication scheme has been disabled by policy";
}
$ENV{'OSH_KBD_INTERACTIVE'} = 1 if $userKbdInteractive;    # useful for plugins that need to call ssh by themselves (for example to test a connection, i.e. groupAddServer)

# MFA enforcing for ingress connection, either on global bastion config, or on specific account config
my $mfaPolicy = OVH::Bastion::config('accountMFAPolicy')->value;
my $isMfaPasswordConfigured =
  OVH::Bastion::is_user_in_group(account => $sysself, group => OVH::Bastion::MFA_PASSWORD_CONFIGURED_GROUP);
my $isMfaTOTPConfigured =
  OVH::Bastion::is_user_in_group(account => $sysself, group => OVH::Bastion::MFA_TOTP_CONFIGURED_GROUP);
my $isMfaPasswordRequired =
  OVH::Bastion::is_user_in_group(account => $sysself, group => OVH::Bastion::MFA_PASSWORD_REQUIRED_GROUP);
my $hasMfaPasswordBypass =
  OVH::Bastion::is_user_in_group(account => $sysself, group => OVH::Bastion::MFA_PASSWORD_BYPASS_GROUP);
my $isMfaTOTPRequired =
  OVH::Bastion::is_user_in_group(account => $sysself, group => OVH::Bastion::MFA_TOTP_REQUIRED_GROUP);
my $hasMfaTOTPBypass =
  OVH::Bastion::is_user_in_group(account => $sysself, group => OVH::Bastion::MFA_TOTP_BYPASS_GROUP);

# auth information from a potential ingress realm:
my %ingressRealm = (
    mfa => {
        validated => 0,
        password  => 0,
        totp      => 0,
    },
    hasPiv => 0,
);

my $pivEffectivePolicyEnabled = OVH::Bastion::is_effective_piv_account_policy_enabled(account => $self);

# if we're coming from a realm, we're receiving a connection from another bastion, keep all the traces:
# TODO: do we need to do something here regarding proxyjump?
my @previous_bastion_details;
if ($realm && $ENV{'LC_BASTION_DETAILS'}) {
    my $decoded_details;
    eval { $decoded_details = decode_json($ENV{'LC_BASTION_DETAILS'}); };
    if (!$@) {
        @previous_bastion_details = @$decoded_details;

        # if the remote bastion did validate MFA, trust it
        $ingressRealm{'mfa'}{'validated'} = $decoded_details->[0]{'mfa'}{'validated'}        ? 1 : 0;
        $ingressRealm{'mfa'}{'password'}  = $decoded_details->[0]{'mfa'}{'type'}{'password'} ? 1 : 0;
        $ingressRealm{'mfa'}{'totp'}      = $decoded_details->[0]{'mfa'}{'type'}{'totp'}     ? 1 : 0;

        # also get the PIV status
        if (ref $decoded_details->[0]{'piv'} eq 'HASH') {
            $ingressRealm{'hasPiv'} = $decoded_details->[0]{'piv'}{'enforced'} ? 1 : 0;

            # if remote PIV is not enforced AND we enforce PIV locally (either by global policy or account-scoped policy),
            # we must refuse the connection.
            if ($pivEffectivePolicyEnabled && !$ingressRealm{'hasPiv'}) {
                my $otherSideName = $decoded_details->[0]{'via'}{'name'} || $decoded_details->[0]{'via'}{'host'};
                main_exit(OVH::Bastion::EXIT_PIV_REQUIRED, 'piv_required',
                    "Sorry $self, but the $bastionName bastion policy requires that you use a PIV key to connect, please set a PIV key up on your local bastion ($otherSideName)."
                );
            }
        }
    }
}

if ($mfaPolicy ne 'disabled'
    && !OVH::Bastion::plugin_config(plugin => $osh_command, key => "mfa_setup_not_required")->value)
{

    if (($mfaPolicy eq 'password-required' && !$hasMfaPasswordBypass) || $isMfaPasswordRequired) {
        main_exit(OVH::Bastion::EXIT_MFA_PASSWORD_SETUP_REQUIRED, 'mfa_password_setup_required',
            "Sorry $self, but you need to setup the Multi-Factor Authentication before using this bastion, please use the `--osh selfMFASetupPassword' option to do so"
        ) if (!$isMfaPasswordConfigured && !$ingressRealm{'mfa'}{'password'});
    }

    if (($mfaPolicy eq 'totp-required' && !$hasMfaTOTPBypass) || $isMfaTOTPRequired) {
        main_exit(OVH::Bastion::EXIT_MFA_TOTP_SETUP_REQUIRED, 'mfa_totp_setup_required',
            "Sorry $self, but you need to setup the Multi-Factor Authentication before using this bastion, please use the `--osh selfMFASetupTOTP' option to do so"
        ) if !($isMfaTOTPConfigured && !$ingressRealm{'mfa'}{'totp'});
    }

    if (   $mfaPolicy eq 'any-required'
        && (!$isMfaPasswordConfigured && !$hasMfaPasswordBypass)
        && (!$isMfaTOTPConfigured     && !$hasMfaTOTPBypass)
        && !$ingressRealm{'mfa'}{'validated'})
    {
        main_exit(OVH::Bastion::EXIT_MFA_ANY_SETUP_REQUIRED, 'mfa_any_setup_required',
            "Sorry $self, but you need to setup the Multi-Factor Authentication before using this bastion, please use either the `--osh selfMFASetupPassword' or the `--osh selfMFASetupTOTP' option, at your discretion, to do so"
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
      . "proxyJump  : "
      . (defined $proxyJump ? $proxyJump : '<undef>') . "\n"
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
    # TODO: log proxyjump info
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
        main_exit OVH::Bastion::EXIT_RESTRICTED_COMMAND, "sshas_denied",
          "Sorry $self, this feature is reserved to bastion administrators. Your attempt has been logged.";
    }
    if ($osh_command) {
        main_exit OVH::Bastion::EXIT_CONFLICTING_OPTIONS, "conflicting_options",
          "Can't use --ssh-as and --osh together. If you want to run a plugin as another user, use --osh adminSudo";
    }
    $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $sshAs);
    $fnret
      or main_exit OVH::Bastion::EXIT_ACCESS_DENIED, 'invalid_account',
      "Sorry $self, the specified account ($sshAs) is invalid";

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
        fields    => [
            ['type', 'admin-ssh-as'],
            ['account' => $self],
            ['sudo-as', $sshAs],
            ['plugin',  'ssh'],
            ['params',  join(" ", @forwardOptions)]
        ]
    );

    osh_warn("ADMIN SUDO: $self, you'll now impersonate $sshAs, this has been logged.");

    exec(@cmd)
      or main_exit(OVH::Bastion::EXIT_EXEC_FAILED,
        "ssh_as_failed", "Couldn't start a session under the account $sshAs ($!)");
}

# This will be filled with details we might want to pass on to the remote machine as a json-encoded envvar
my %bastion_details = (
    piv => {
        enforced => $pivEffectivePolicyEnabled ? \1 : \0,
        reason   => $pivEffectivePolicyEnabled->msg,
    },
);

# For either an SSH connection or a plugin,
# we first compute the correct idle-kill-timeout and idle-lock-timeout value,
# as these can be overridden for group accesses, see the help of groupModify command
# for details on the algorithm's logic.
# it can also be overridden on a per-plugin basis
my %idleTimeout = (
    kill => OVH::Bastion::config("idleKillTimeout")->value,
    lock => OVH::Bastion::config("idleLockTimeout")->value,
);

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
            osh_warn(
                "Would deny access on out of space condition but you're root\@127.0.0.1, I hope you're here to fix me!"
            );
        }
        else {
            main_exit OVH::Bastion::EXIT_OUT_OF_SPACE, 'out_of_space',
              "Bastion is out of space, admin intervention is needed! (" . $logret->msg . ")";
        }
    }

    if ($fnret) {
        my @cmd = ($fnret->value->{'fullpath'}, $user, $ip, $host, $optPort, @$remainingOptions);

        # does the plugin want us to only print messages on STDERR?
        if (OVH::Bastion::plugin_config(plugin => $osh_command, key => "force_stderr")->value) {
            $ENV{'FORCE_STDERR'} = 1;
        }

        # is plugin explicitly disabled?
        my $isDisabled = OVH::Bastion::plugin_config(plugin => $osh_command, key => "disabled");

        # plugin is enabled by default if not explicitly disabled
        if ($isDisabled and $isDisabled->value()) {
            main_exit OVH::Bastion::EXIT_RESTRICTED_COMMAND, "plugin_disabled",
              "Sorry $self, this plugin has been disabled by policy.";
        }
        if ($isDisabled->is_err && $isDisabled->err ne 'KO_NO_SUCH_FILE') {
            warn_syslog(
                "Failed to tell whether the '$osh_command' plugin is enabled or not (" . $isDisabled->msg . ")");
            main_exit OVH::Bastion::EXIT_RESTRICTED_COMMAND, "plugin_disabled",
              "Sorry $self, a configuration error prevents us to check whether this plugin is enabled, warn your sysadmin!";
        }

        # check if we need JIT MFA to call this plugin, this can be configured per-plugin
        my $MFArequiredForPlugin = OVH::Bastion::plugin_config(plugin => $osh_command, key => "mfa_required")->value;
        $MFArequiredForPlugin ||= 'none';    # no config means none

        # These kind of plugins will require MFA if we have at least one already configured, none otherwise.
        # This is mainly used by selfMFASetupTOTP, to ensure that the current TOTP is asked before allowing the user
        # to setup a new one. Note that this is not used by selfMFASetupPassword, as `passwd` already asks for
        # the current password before allowing to change it
        if ($MFArequiredForPlugin eq 'any-if-configured') {
            $MFArequiredForPlugin = (($isMfaTOTPConfigured || $isMfaPasswordConfigured) ? 'any' : 'none');
        }

        if (!grep { $MFArequiredForPlugin eq $_ } qw{ password totp any none }) {
            main_exit(
                OVH::Bastion::EXIT_MFA_FAILED,
                'mfa_plugin_configuration_failed',
                "MFA configuration is incorrect for this plugin, report to your sysadmin!"
            );
        }

        # run MFA for this plugin if needed
        $fnret = do_jit_mfa(
            actionType => 'plugin',
            mfaType    => $MFArequiredForPlugin,
        );
        if (!$fnret) {
            # shouldn't happen because do_jit_mfa() exits by itself on error, but we never know...
            main_exit(OVH::Bastion::EXIT_MFA_FAILED, 'mfa_failed', "Couldn't complete MFA");
        }
        elsif ($fnret->value && ref $fnret->value eq 'HASH' && $fnret->value->{'mfaInfo'}) {
            $bastion_details{'mfa'} = $fnret->value->{'mfaInfo'};
        }

        # now, check whether this plugin wants us to trigger a JIT MFA check depending on the
        # specified user/host/ip, if this is configured in one of the matching bastion groups
        # we are a part of (plugins such as sftp or scp will require us to do this, as they can't
        # do it themselves, and as they're accessing a remote asset, JIT MFA should apply to them too)
        my $pluginJitMfa = OVH::Bastion::plugin_config(plugin => $osh_command, key => "jit_mfa")->value;
        if ($pluginJitMfa) {
            $fnret = do_plugin_jit_mfa();
            # do_plugin_jit_mfa exits if needed, but just in case...
            main_exit(OVH::Bastion::EXIT_MFA_FAILED, "jit_mfa_failed", $fnret->msg) if !$fnret;
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

        # check if we have a plugin override for idle lock/kill timeouts
        foreach my $timeoutType (qw{ idle kill }) {
            $fnret = OVH::Bastion::plugin_config(plugin => $osh_command, key => "idle_${timeoutType}_timeout");
            if ($fnret && defined $fnret->value) {
                $idleTimeout{${timeoutType}} = $fnret->value;
            }
        }

        # build ttyrec command that'll prefix the real command
        $fnret = OVH::Bastion::build_ttyrec_cmdline(
            ip             => $osh_command,
            port           => 0,
            user           => 0,
            account        => $self,
            uniqid         => $log_uniq_id,
            home           => $home,
            realm          => $realm,
            remoteaccount  => $remoteself,
            debug          => $osh_debug,
            tty            => $tty,
            notty          => $notty,
            stealth_stdout => OVH::Bastion::plugin_config(
                plugin => $osh_command,
                key    => "stealth_stdout"
            )->value ? 1 : 0,
            stealth_stderr => OVH::Bastion::plugin_config(
                plugin => $osh_command,
                key    => "stealth_stderr"
            )->value ? 1 : 0,
            idleLockTimeout => $idleTimeout{'lock'},
            idleKillTimeout => $idleTimeout{'kill'},
        );
        main_exit(OVH::Bastion::EXIT_TTYREC_CMDLINE_FAILED, "ttyrec_failed", $fnret->msg) if !$fnret;

        @cmd = (@{$fnret->value->{'cmd'}}, '--', @cmd);

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
                account     => $self,
                insert_id   => $log_insert_id,
                db_name     => $log_db_name,
                uniq_id     => $log_uniq_id,
                returnvalue => $fnret->value ? $fnret->value->{'sysret_raw'} : undef,
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
        osh_print('');
    }

    osh_warn($msg_to_print_delayed) if defined $msg_to_print_delayed;    # set if we had an error to print previously
}

# if no user yet, fix it to remote user
# do that here, cause sometimes we do not want to pass user to osh
$user = $user || $config->{'defaultLogin'} || $remoteself || $sysself;

# log request
osh_debug("final request : " . "$user\@$ip -p $port -- $command'\n");

my $displayLine = sprintf("%s => %s => %s",
    OVH::Bastion::machine_display(ip => $hostfrom,    port => $portfrom)->value,
    OVH::Bastion::machine_display(ip => $bastionhost, port => $bastionport, user => $self)->value,
    OVH::Bastion::machine_display(ip => $hostto,      port => $port,        user => $user)->value,
);

if (!$quiet) {
    osh_print("$displayLine ...");
}

# before doing stuff, check if we have the right to connect somewhere (some users are locked only to osh commands)
$fnret = OVH::Bastion::account_config(account => $self, key => OVH::Bastion::OPT_ACCOUNT_OSH_ONLY);
if ($fnret and $fnret->value() =~ /yes/) {
    $fnret = R('KO_ACCESS_DENIED', msg => "You don't have the right to connect anywhere");
}
else {
    $fnret = OVH::Bastion::is_access_granted(
        account => $self,
        user    => $user,
        ipfrom  => $ipfrom,
        ip      => $ip,
        port    => $port,
        proxyIp => $proxyIp ? $proxyIp : undef,
        proxyPort => $proxyPort ? $proxyPort : undef,
        details => 1
    );
}

# so in the end, can we access the requested user@host machine ?
my $JITMFARequired;
if (!$fnret) {

    #   User is not allowed, exit
    my $message = $fnret->msg;
    if ($user eq $self) {
        $message .= " (tried with remote user '$user')";    # "root is not the default login anymore"
    }

    # TODO: log proxyjump info
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
my @accessList = @{$fnret->value || []};

if ($osh_debug) {
    require Data::Dumper;
    osh_debug("access list array:");
    osh_debug(Data::Dumper::Dumper(\@accessList));
}

# build ttyrec command that'll prefix the real command
# TODO: support proxyjump properly here
my $ttyrec_fnret = OVH::Bastion::build_ttyrec_cmdline_part1of2(
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

osh_print(" allowed ... log on($saveFile)\n") if !$quiet;

# now build the real command
my @command;

# if we are doing a password login, find the password(s)

# for autologin, "-1" means "try the main password, then try the fallbacks", 0 means "try only the main password", and N means "try only the Nth fallback password"
my $forcePasswordId = -1;

if ($userPasswordClue) {

    # locate main password file
    $fnret = OVH::Bastion::get_passfile(
        hint      => $userPasswordClue,
        context   => $userPasswordContext,
        self      => ($remoteself || $sysself),
        tryLegacy => 1
    );
    if (!$fnret) {
        main_exit OVH::Bastion::EXIT_PASSFILE_NOT_FOUND, "passfile-not-found", $fnret->msg;
    }
    $passwordFile = $fnret->value;

    # check if a specific password is forced
    foreach my $access (@accessList) {

        # only keep the grant matching the password clue and context AND with a forced password
        if (
            $access->{'forcePassword'}
            && (
                ($userPasswordContext eq 'self' && $access->{'type'} eq 'personal')
                || (   $userPasswordContext eq 'group'
                    && $access->{'type'} =~ /^group-(member|guest)$/
                    && $access->{'group'} eq $userPasswordClue)
            )
          )
        {

            # FIXME: force-password and force-key don't work yet for guest accesses, see #256
            # fetch the hashes of the main password and all its fallbacks
            if ($userPasswordContext eq 'self') {
                $fnret = OVH::Bastion::get_hashes_list(context => 'account', account => $userPasswordClue);
            }
            else {
                $fnret = OVH::Bastion::get_hashes_list(context => 'group', group => $userPasswordClue);
            }

            if (!$fnret) {
                main_exit(OVH::Bastion::EXIT_GET_HASH_FAILED, "get_hashes_list", $fnret->msg);
            }

            # is our forced password's hash one of them ?
            for my $id (0 .. $#{$fnret->value}) {
                foreach my $hash (values(%{$fnret->value->[$id]->{'hashes'}})) {
                    if ($access->{'forcePassword'} eq $hash) {
                        $forcePasswordId = $id;
                        osh_print(" forcing password with hash: " . $access->{'forcePassword'} . "\n") unless $quiet;
                    }
                }
            }

            # if the password was not found, abort
            if ($forcePasswordId == -1) {
                main_exit(OVH::Bastion::EXIT_PASSFILE_NOT_FOUND,
                    "forced-password-not-found", "The forced password could not be found");
            }
        }
    }
}

# if we want telnet (not ssh)
if ($telnet) {

    # TELNET PASSWORD AUTOLOGIN
    if ($userPasswordClue) {
        osh_debug("going to use telnet with this password file : $passwordFile");
        osh_print(" will use TELNET with password autologin\n") unless $quiet;
        push @command, $OVH::Bastion::BASEPATH . '/bin/shell/autologin';
        # arguments are positional for the 'autologin' script, put one per line below for readability
        push @command, 'telnet';
        push @command, $user;
        push @command, $ip;
        push @command, $port;
        push @command, $passwordFile;
        push @command, $forcePasswordId;
        push @command, ($timeout ? $timeout : 45);
        push @command, ($fallbackPasswordDelay // 3);
        push @command, ($notty           ? "raw -echo"  : "");
        push @command, ($termPassthrough ? $ENV{'TERM'} : "");
    }

    # TELNET PASSWORD INTERACTIVE
    else {
        osh_print(" will use TELNET with interactive password login\n") unless $quiet;
        push @command, '/usr/bin/telnet', '-l', $user, $host, $port;
    }
}

# if we want ssh (not telnet)
else {
    my @preferredAuths;

    # Now gather all the timeouts overrides that may be defined for the matching groups
    my %idleTimeoutsOverride = (kill => [], lock => []);
    foreach my $access (@accessList) {
        next if ($access->{'type'} !~ /^group/);
        push @{$idleTimeoutsOverride{'kill'}}, $access->{'idleKillTimeout'}
          if (defined $access->{'idleKillTimeout'} && $access->{'size'} != 2**32);
        push @{$idleTimeoutsOverride{'lock'}}, $access->{'idleLockTimeout'}
          if (defined $access->{'idleLockTimeout'} && $access->{'size'} != 2**32);
    }

    # Now, decide what to apply for each timeout setting
    foreach my $timeout (qw{ kill lock }) {
        if (@{$idleTimeoutsOverride{$timeout}} == 0) {

            # zero override, we'll use the global setting,
            # $idleTimeout{$timeout} is already inited to the global setting
            osh_debug("idle_timeout: no override for $timeout, using global setting");
        }
        elsif (@{$idleTimeoutsOverride{$timeout}} == 1) {

            # exactly one match, use it
            $idleTimeout{$timeout} = $idleTimeoutsOverride{$timeout}[0];
            osh_debug("idle_timeout: exactly one override for $timeout, using it");
        }
        else {
            osh_debug("idle_timeout: more than one override for $timeout, using the most restrictive one");

            # more than one match, so we add the global setting to the pile
            push @{$idleTimeoutsOverride{$timeout}}, $idleTimeout{$timeout};

            # and choose the most restrictive one (lowest positive integer)
            $idleTimeout{$timeout} = (sort { $a <=> $b } grep { $_ > 0 } @{$idleTimeoutsOverride{$timeout}})[0];
        }
        osh_debug("idle_timeout: finally using " . $idleTimeout{$timeout} . " for $timeout");
    }

    # if $command matches this option, set stealth_stdout for ttyrec
    my $stealth_stdout = 0;
    if (my $ttyrecStealthStdoutPattern = OVH::Bastion::config("ttyrecStealthStdoutPattern")->value) {
        $stealth_stdout = $command =~ $ttyrecStealthStdoutPattern;
    }

    # adjust the ttyrec cmdline with these parameters
    $ttyrec_fnret = OVH::Bastion::build_ttyrec_cmdline_part2of2(
        input           => $ttyrec_fnret->value,
        idleLockTimeout => $idleTimeout{'lock'},
        idleKillTimeout => $idleTimeout{'kill'},
        stealth_stdout  => $stealth_stdout,
    );
    main_exit(OVH::Bastion::EXIT_TTYREC_CMDLINE_FAILED, "ttyrec_failed", $ttyrec_fnret->msg) if !$ttyrec_fnret;
    @ttyrec = @{$ttyrec_fnret->value->{'cmd'}};

    # SSH PASSWORD AUTOLOGIN
    # TODO: how tf does this work??? And how to proxyjump with this?
    if ($userPasswordClue) {

        push @preferredAuths, 'keyboard-interactive';
        push @preferredAuths, 'password';

        osh_debug("going to use ssh with this password file : $passwordFile");
        if ($termPassthrough) {
            osh_print(" will use SSH with password autologin with TERM=" . $ENV{'TERM'} . "\n") unless $quiet;
        }
        else {
            osh_print(" will use SSH with password autologin with empty TERM, "
                  . "use --term-passthrough if output is scrambled\n")
              unless $quiet;
        }

        push @command, $OVH::Bastion::BASEPATH . '/bin/shell/autologin';
        # arguments are positional for the 'autologin' script, put one per line below for readability
        push @command, 'ssh';
        push @command, $user;
        push @command, $ip;
        push @command, $port;
        push @command, $passwordFile;
        push @command, $forcePasswordId;
        push @command, ($timeout ? $timeout : 45);
        push @command, ($fallbackPasswordDelay // 3);
        push @command, ($notty           ? "raw -echo"  : "");
        push @command, ($termPassthrough ? $ENV{'TERM'} : "");
    }

    # SSH EGRESS KEYS (and maybe password interactive as a fallback if passwordAllowed)
    else {
        # ssh by key
        push @preferredAuths, 'publickey';

        # also set kbdinteractive if allowed in bastion config (needed for e.g. TOTP)
        push @preferredAuths, 'keyboard-interactive'
          if ($config->{'keyboardInteractiveAllowed'} && $userKbdInteractive);

        # also set password if allowed in bastion config (to allow users to enter a remote password interactively)
        push @preferredAuths, 'password' if $config->{'passwordAllowed'};

        # If sshAddKeystoAgent is set, run 'ssh-agent' first and let it spawn 'ssh'
        push @command, 'ssh-agent', '-t', '60' if ($config->{'sshAddKeysToAgentAllowed'} && $sshAddKeysToAgent);
        push @command, '/usr/bin/ssh', $ip, '-l', $user, '-p', $port;

        $fnret = get_details_from_access_array(
            accessList => \@accessList,
            quiet      => $quiet,
            useKey     => $useKey
        );
        if ($fnret) {
            # add the -i key1 -i key2 etc. returned by get_details_from_access_array()
            push @command, @{$fnret->value->{'sshKeysArgs'}};
            # update the JIT MFA flag
            $JITMFARequired = $fnret->value->{'mfaRequired'};
        }
        else {
            main_exit(OVH::Bastion::EXIT_ACCESS_DENIED, "access_denied", $fnret->msg);
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


    if ($proxyJump) {
        # Build ProxyCommand with same options as main SSH command
        my @proxyCommand = ('ssh');
        push @proxyCommand, '-o', 'PreferredAuthentications=' . (join(',', @preferredAuths));
        
        # Add the same SSH keys to the proxy command
        if ($fnret && $fnret->value->{'sshKeysArgs'}) {
            push @proxyCommand, @{$fnret->value->{'sshKeysArgs'}};
        }
        
        push @proxyCommand, '-p', $proxyPort if $proxyPort && $proxyPort != 22;
        push @proxyCommand, '-l', $user, '-W', '%h:%p', $proxyIp;

        if ($verbose) {
            foreach (1 .. $verbose) {
                push @proxyCommand, '-v';
            }
        }
        push @proxyCommand, '-o', "ConnectTimeout=$timeout" if $timeout;
        
        # Quote arguments that contain spaces and build the command string
        my $proxyCommandStr = join(' ', map { /\s/ ? "'$_'" : $_ } @proxyCommand);
        push @command, '-o', "ProxyCommand=$proxyCommandStr";
        
        osh_debug("ProxyCommand: $proxyCommandStr");
    }

    if (not $quiet) {
        $fnret =
          OVH::Bastion::account_config(account => $self, key => OVH::Bastion::OPT_ACCOUNT_IDLE_IGNORE, public => 1);
        if ($fnret && $fnret->value =~ /yes/) {
            osh_debug("Account is immune to idle");
        }
        else {
            if ($idleTimeout{'lock'}) {
                osh_print("  /!\\ Your session will be locked after "
                      . $idleTimeout{'lock'}
                      . " seconds of inactivity, use `--osh unlock' to unlock it");
            }
            if ($idleTimeout{'kill'}) {
                osh_print(
                    "  /!\\ Your session will be killed after " . $idleTimeout{'kill'} . " seconds of inactivity.");
            }
            osh_print('') if ($idleTimeout{'lock'} || $idleTimeout{'kill'});
        }
    }

    # -x flag is set and allowed, as such set the -A flag (enable agent forwarding) and '-o AddKeysToAgent=yes' to automatically add the egress sshkey to the agent, so that it can be used
    if ($config->{'sshAddKeysToAgentAllowed'} && $sshAddKeysToAgent) {
        push @command, '-A', '-o', 'AddKeysToAgent=yes';
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

# add current account name as LC_BASTION to be passed via ssh
$ENV{'LC_BASTION'} = $self;

$bastion_details{'mfa'}{'validated'}        //= \0;
$bastion_details{'mfa'}{'type'}{'password'} //= \0;
$bastion_details{'mfa'}{'type'}{'totp'}     //= \0;
$bastion_details{'piv'}{'enforced'}         //= \0;
$bastion_details{'from'} = {addr => $ipfrom,    host => $hostfrom,    port => $portfrom + 0};
$bastion_details{'via'}  = {addr => $bastionip, host => $bastionhost, port => $bastionport + 0, name => $bastionName};
$bastion_details{'to'}   = {addr => $ip,        host => $hostto,      port => $port + 0,        user => $user};
$bastion_details{'account'} = $self;
$bastion_details{'uniqid'}  = $log_uniq_id;
$bastion_details{'version'} = $OVH::Bastion::VERSION;

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
    require IO::Socket::INET;
    my $startedat = time();
    my $loops     = 0;
    osh_info "Waiting for port $port to be open on $host before attempting to connect...";
    while ($loops < 3600) {    # can be up to 2h (socket timeout + sleep 1)
        my $Sock = IO::Socket::INET->new(
            Proto    => 'tcp',
            Timeout  => 1,
            PeerAddr => $ip,
            PeerPort => $port,
        );
        if ($Sock) {
            osh_info "Alive after waiting for " . (time() - $startedat) . " seconds, connecting...";
            $Sock->close();
            last;
        }
        sleep 1;    # to avoid looping too fast if the failure is immediate and not a timeout (i.e. port closed)
        $loops++;
        if ($loops % 5 == 0) {
            osh_info("Still trying to connect to $host:$port after " . (time() - $startedat) . " seconds...");
        }
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
        osh_warn(
            "Would deny access on out of space condition but you're root\@127.0.0.1, I hope you're here to fix me!");
    }
    else {
        main_exit OVH::Bastion::EXIT_OUT_OF_SPACE, 'out_of_space',
          "Bastion is out of space, admin intervention is needed! (" . $logret->msg . ")";
    }
    $logret->{'value'} = {};
}

# if we have JIT MFA, do it now
if ($JITMFARequired) {
    $fnret = do_jit_mfa(
        actionType => 'host',
        mfaType    => $JITMFARequired,
    );
    if (!$fnret) {
        # shouldn't happen because do_jit_mfa() exits by itself, but we never know...
        main_exit(OVH::Bastion::EXIT_MFA_FAILED, 'mfa_failed', "Couldn't complete MFA");
    }
    elsif ($fnret->value && ref $fnret->value eq 'HASH' && $fnret->value->{'mfaInfo'}) {
        $bastion_details{'mfa'} = $fnret->value->{'mfaInfo'};
    }
}

# now that we're about to connect, convert the bastion_details to a json envvar:
my @details_json = (\%bastion_details);

# if we have data from a previous bastion (due to a realm connection), include it on top:
push @details_json, @previous_bastion_details if @previous_bastion_details;

# then convert to json:
$ENV{'LC_BASTION_DETAILS'} = encode_json(\@details_json);

# make sure $home/tmp exists, as it might be used for egress ssh connection multiplexing.
# just attempt to create it instead of check+create, as it's not faster to do otherwise.
mkdir "$home/tmp", 0700;

# here is a nice hack to drastically improve the memory footprint of a
# heavily used bastion. we exec() another script that is way lighter, see
# comments in the connect.pl file for more information.

if (!$quiet) {
    osh_print("Connecting...");
}

push @toExecute, $OVH::Bastion::BASEPATH . '/bin/shell/connect.pl';
exec(
    @toExecute,        $ip, $port, $config->{'sshClientHasOptionE'},
    $userPasswordClue, $saveFile,
    $logret->value->{'insert_id'},
    $logret->value->{'db_name'},
    $logret->value->{'uniq_id'},
    $self, @ttyrec
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
            account   => $self,
            insert_id => $log_insert_id,
            db_name   => $log_db_name,
            uniq_id   => $log_uniq_id,
            signal    => $sig,
        );
    }
    # ensure the signal is propagated to our progress group, then exit.
    # this func is also called as the timeoutHandler of interactive mode,
    # and in this case $sig == 'TIMEOUT', which is not a real signal
    if ($sig ne 'TIMEOUT') {
        $SIG{$sig} = 'IGNORE';
        kill $sig, 0;
    }
    exit OVH::Bastion::EXIT_OK;
}

sub get_details_from_access_array {
    my %params     = @_;
    my $quiet      = $params{'quiet'};
    my $accessList = $params{'accessList'};
    my $useKey     = $params{'useKey'};

    my @keysToTry;
    my $mfaRequired;

    osh_print(" will try the following accesses you have:") unless $quiet;
    foreach my $access (@$accessList) {
        # each access has a type and possibly several keys
        my $type = $access->{'type'} . " of " . $access->{'group'};
        if ($access->{'type'} =~ /^group/) {
            $type = colored($access->{'type'}, $access->{'type'} eq 'group-member' ? 'green' : 'yellow');
            $type .= " of " . colored($access->{'group'}, 'blue bold');
        }
        elsif ($access->{'type'} =~ /^personal/) {
            $type = colored($access->{'type'}, 'red') . ' access';
        }

        foreach my $key (@{$access->{'sortedKeys'} || []}) {
            my $keyinfo   = $access->{'keys'}{$key};
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
                    $mfaRequired = $access->{'mfaRequired'};
                }
                osh_printf(
                    "  - %s with %s-%s key %s %s%s",
                    $type,      $keyinfo->{'family'}, $keyinfo->{'size'}, $keyinfo->{'fingerprint'},
                    $generated, $forced
                ) unless $quiet;
                push @keysToTry, $keyinfo->{'fullpath'} if not(grep { $_ eq $keyinfo->{'fullpath'} } @keysToTry);
            }
        }
        if ($access->{'forceKey'} && @{$access->{'sortedKeys'} || []} == 0) {
            osh_printf("  - %s but found no key matching the forced fingerprint in corresponding ACL %s",
                $type, colored('(SKIPPED)', 'bold red'))
              unless $quiet;
        }
    }
    if ($useKey and not @keysToTry) {
        osh_print("  >>> No key matched the fingerprint you gave me ($useKey), connection will fail!");
    }
    osh_print('') unless $quiet;

    my @sshKeysArgs;
    foreach (@keysToTry) {
        if (-r) {
            osh_debug("Got a group key $_");
            push @sshKeysArgs, '-i', $_;
        }
        else {
            osh_warn("Weird, key file $_ is not accessible");
            warn_syslog("Would have added key file '$_' but it's not accessible by current user");
        }
    }

    return R('OK', value => {sshKeysArgs => \@sshKeysArgs, mfaRequired => $mfaRequired});
}

# can exit if prerequisites are not met (i.e. MFA required but not configured on account)
# return a true OVH::Result if MFA is not needed/can be skipped
# a false OVH::Result otherwise
sub may_skip_mfa {
    my %params     = @_;
    my $mfaType    = $params{'mfaType'};       # password|totp|any|none
    my $actionType = $params{'actionType'};    # host|plugin

    if (!$mfaType || !$actionType) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing mandatory parameters to may_skip_mfa");
    }

    if (!grep { $mfaType eq $_ } qw{ totp password any none }) {
        return R('ERR_INVALID_PARAMETER', msg => "Invalid parameter 'mfaType' for may_skip_mfa");
    }

    return R('OK_NO_MFA_REQUIRED') if $mfaType eq 'none';

    my $skipMFA  = 0;
    my $realmMFA = 0;
    my $localfnret;

    osh_print("As this is required for this $actionType, entering MFA phase for $self.");

    if ($mfaType eq 'totp' && !$isMfaTOTPConfigured) {
        if ($hasMfaTOTPBypass) {
            $skipMFA = 1;
        }
        elsif ($ingressRealm{'mfa'}{'totp'} && $ingressRealm{'mfa'}{'validated'}) {
            $realmMFA = 1;
        }
        else {
            main_exit(OVH::Bastion::EXIT_MFA_TOTP_SETUP_REQUIRED, 'mfa_totp_setup_required',
                    "Sorry $self, "
                  . "but you need to setup the Multi-Factor Authentication for this $actionType,\n"
                  . "please use the `--osh selfMFASetupTOTP' option to do so");
        }
    }
    elsif ($mfaType eq 'password' && !$isMfaPasswordConfigured) {
        if ($hasMfaPasswordBypass) {
            $skipMFA = 1;
        }
        elsif ($ingressRealm{'mfa'}{'password'} && $ingressRealm{'mfa'}{'validated'}) {
            $realmMFA = 1;
        }
        else {
            main_exit(OVH::Bastion::EXIT_MFA_PASSWORD_SETUP_REQUIRED, 'mfa_password_setup_required',
                    "Sorry $self, "
                  . "but you need to setup the Multi-Factor Authentication for this $actionType,\n"
                  . "please use the `--osh selfMFASetupPassword' option to do so");
        }
    }
    elsif ($mfaType eq 'any' && !$isMfaTOTPConfigured && !$isMfaPasswordConfigured) {
        if ($hasMfaPasswordBypass || $hasMfaTOTPBypass) {
            $skipMFA = 1;
        }
        elsif ($ingressRealm{'mfa'}{'validated'}) {
            $realmMFA = 1;
        }
        else {
            main_exit(OVH::Bastion::EXIT_MFA_ANY_SETUP_REQUIRED, 'mfa_any_setup_required',
                    "Sorry $self, "
                  . "but you need to setup the Multi-Factor Authentication for this $actionType,\n"
                  . "please use either the `--osh selfMFASetupPassword' or the `--osh selfMFASetupTOTP' option, "
                  . "at your discretion, to do so");
        }
    }

    if ($skipMFA) {
        osh_print("... skipping as your account is exempt from MFA.");
        return R('OK_ACCOUNT_HAS_MFA_BYPASS');
    }
    elsif ($realmMFA) {
        osh_print("... you already validated MFA on the bastion you're coming from.");
        return R('OK_ACCOUNT_HAS_VALIDATED_MFA_REALM');
    }
    elsif ($ENV{'OSH_PROACTIVE_MFA'}) {
        osh_print("... you already validated MFA proactively.");
        return R('OK_ACCOUNT_HAS_VALIDATED_MFA_PROACTIVELY');
    }

    # no skip, mfa is required
    return R('KO_MFA_REQUIRED');
}

sub do_jit_mfa {
    my %params     = @_;
    my $mfaType    = $params{'mfaType'};       # password|totp|any|none
    my $actionType = $params{'actionType'};    # host|plugin

    my $localfnret = may_skip_mfa(mfaType => $mfaType, actionType => $actionType);
    if ($localfnret->is_ok) {
        # skip, localfnret includes the detailed reason
        return $localfnret;
    }

    # otherwise, do mfa
    $localfnret = OVH::Bastion::do_pamtester(self => $self, sysself => $sysself);
    main_exit(OVH::Bastion::EXIT_MFA_FAILED, 'mfa_failed', $localfnret->msg) if !$localfnret;

    # craft this so that the remote server, which can be a bastion in case we're chaining,
    # can enforce its own policy. This should be serialized in LC_BASTION_DETAILS on egress side
    my %mfaInfo = (
        validated => \1,
        reason    => "mfa_required_for_$actionType",
        type      => {
            password => $isMfaPasswordConfigured ? \1 : \0,
            totp     => $isMfaTOTPConfigured     ? \1 : \0,
        }
    );

    return R('OK_VALIDATED', value => {mfaInfo => \%mfaInfo});
}

# check whether this plugin wants us to trigger a JIT MFA check depending on the
# specified user/host/ip, if this is configured in one of the matching bastion groups
# we are a part of (plugins such as sftp or scp will require us to do this, as they can't
# do it themselves, and as they're accessing a remote asset, JIT MFA should apply to them too)
#
# this func may exit
sub do_plugin_jit_mfa {
    my $localfnret;

    if (!$host) {
        # if no host is specified, and the plugin has jit_mfa_allow_no_host, then
        # allow the plugin to be called, for example to show its builtin help()
        $localfnret = OVH::Bastion::plugin_config(plugin => $osh_command, key => 'jit_mfa_allow_no_host');
        if ($localfnret && $localfnret->value) {
            if ($generateMfaToken) {
                # return a dummy token so that our caller is happy, then exit
                print("MFA_TOKEN=notrequired\n");
                main_exit(OVH::Bastion::EXIT_OK);
            }
            # tell our caller that the plugin can be executed without host
            return R('OK_JIT_MFA_NOT_REQUIRED');
        }
        # otherwise, we need a host
        main_exit(OVH::Bastion::EXIT_NO_HOST, 'no_host', "A host is required for this plugin but none was specified");
    }

    # if $ip is undef it's because $host didn't resolve, exit
    if (!$ip) {
        main_exit OVH::Bastion::EXIT_HOST_NOT_FOUND, 'host_not_found', "Unable to resolve host '$host'";
    }

    # if no user yet, fix it to remote user
    # we need it to be able to get the proper answer for is_access_granted, and we need to
    # call is_access_granted so that we know whether we need to trigger JIT MFA for this
    # plugin, based on the groups we find
    my $remoteuser = $user || $config->{'defaultLogin'} || $remoteself || $sysself;

    $localfnret = OVH::Bastion::is_access_granted(
        account => $self,
        user    => $user,
        ipfrom  => $ipfrom,
        ip      => $ip,
        port    => $port,
        details => 1
    );

    if (!$localfnret) {
        # not allowed, exit
        my $message = $localfnret->msg;
        if ($remoteuser eq $self) {
            $message .= " (tried with remote user '$remoteuser')";
        }
        main_exit(OVH::Bastion::EXIT_ACCESS_DENIED, 'access_denied', $message);
    }

    # else, get the access list
    my @accessListForPlugin = @{$localfnret->value || []};

    # and check whether we need JIT MFA
    my $mfaType;
    $localfnret = get_details_from_access_array(
        accessList => \@accessListForPlugin,
        quiet      => ($quiet || $mfaToken),
        useKey     => $useKey
    );
    if ($localfnret && $localfnret->value->{'mfaRequired'}) {
        $mfaType = $localfnret->value->{'mfaRequired'};
    }
    elsif (!$localfnret) {
        main_exit(OVH::Bastion::EXIT_ACCESS_DENIED, "access_denied", $localfnret->msg);
    }

    # not required? we're done
    if (!$mfaType || may_skip_mfa(mfaType => $mfaType, actionType => 'plugin')) {
        if ($generateMfaToken) {
            # return a dummy token so that our caller is happy, then exit
            print("MFA_TOKEN=notrequired\n");
            main_exit(OVH::Bastion::EXIT_OK);
        }
        # no mfa required and our caller didn't request a token generation, just carry on
        return R('OK_JIT_MFA_NOT_REQUIRED');
    }

    $localfnret = OVH::Bastion::load_configuration_file(
        file     => OVH::Bastion::main_configuration_directory() . '/mfa-token.conf',
        rootonly => 1
    );
    if (!$localfnret || !$localfnret->value) {
        main_exit(OVH::Bastion::EXIT_MFA_FAILED, 'mfa_failed_no_secret',
            "No MFA token HMAC secret has been configured, please report to your sysadmin");
    }
    my $tokenConfig = $localfnret->value;
    if (ref $tokenConfig ne 'HASH' || !$tokenConfig->{'secret'} || length($tokenConfig->{'secret'}) < 32) {
        main_exit(OVH::Bastion::EXIT_MFA_FAILED, 'mfa_failed_invalid_secret',
            "An invalid MFA token HMAC secret has been configured, please report to your sysadmin");
    }
    my $secret = $tokenConfig->{'secret'};

    # so, if JIT MFA is required, we need to have either --generate-mfa-token, or --mfa-token
    if ($mfaToken) {
        # recompute the theoretical token value we should have
        my ($then) = $mfaToken =~ m{^v1,(\d+),[a-f0-9]{64}$};
        if (!$then) {
            main_exit(OVH::Bastion::EXIT_MFA_FAILED, 'mfa_failed_invalid_format',
                "Provided MFA token has invalid format");
        }

        # is the token expired?
        if ($then + 15 < time()) {
            main_exit(OVH::Bastion::EXIT_MFA_FAILED, 'mfa_failed_expired_token', "Provided MFA token is expired");
        }

        # is the token in the future?
        if ($then > time()) {
            main_exit(OVH::Bastion::EXIT_MFA_FAILED, 'mfa_failed_future_token',
                "Provided MFA token has creation date in the future");
        }

        require Digest::SHA;
        my $payload          = join(',', $then, $self, $host, $port, $remoteuser);
        my $theoreticalToken = sprintf("v1,%s,%s", $then, Digest::SHA::hmac_sha256_hex($payload, $secret));

        # are both tokens identical?
        if ($mfaToken ne $theoreticalToken) {
            main_exit(OVH::Bastion::EXIT_MFA_FAILED, 'mfa_failed_invalid_token', "Provided MFA token is invalid");
        }

        osh_print("... MFA token is valid, proceeding");
        return R('OK_JIT_MFA_VALIDATED');
    }
    elsif ($generateMfaToken) {
        # do MFA
        $localfnret = do_jit_mfa(
            actionType => 'plugin',
            mfaType    => $mfaType,
        );
        if (!$localfnret) {
            # shouldn't happen because do_jit_mfa() exits by itself on error, but we never know...
            main_exit(OVH::Bastion::EXIT_MFA_FAILED, 'mfa_failed', "Couldn't complete MFA");
        }
        elsif ($localfnret->value && ref $localfnret->value eq 'HASH' && $localfnret->value->{'mfaInfo'}) {
            $bastion_details{'mfa'} = $localfnret->value->{'mfaInfo'};
        }
        # if we're still here, MFA has been validated, generate a token, save and return it
        require Digest::SHA;
        my $now             = time();
        my $payload         = join(',', $now, $self, $host, $port, $remoteuser);
        my $generated_token = sprintf("v1,%s,%s", $now, Digest::SHA::hmac_sha256_hex($payload, $secret));

        # return token to caller
        print("MFA_TOKEN=$generated_token\n");
        main_exit(OVH::Bastion::EXIT_OK, "mfa_token_generated", "MFA token has been generated");
    }

    # MFA required but none provided or requested: bail out
    main_exit(OVH::Bastion::EXIT_MFA_FAILED, "jit_mfa_required_no_token",
        "JIT MFA is required, but you didn't specify either --generate-mfa-token or --mfa-token");

    return;    # make perlcritic happy
}

#
#   Display help message
#
sub help {

=begin comment
    # pod just to debug memory fingerprint
    use Devel::Size qw[total_size]; # pragma optional module
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
=end comment
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
    --forward-agent, -x  Enables ssh agent forwarding on the egress connection
    --long-help          Print this

[REMOTE_COMMAND]
    You can pass a command to execute on the remote machine. For complex commands, don't forget
    that your shell will eat one level of quotes and backslashes. One working example:
    $bastionName srv1.example.org -- "perl -e 'use Data::Dumper; print Dumper(\\\@ARGV)' one 'two is 2' three"

[OPTIONS (ssh)]
    --verbose                    Enable verbose ssh
    --tty,      -t               Force tty allocation
    --no-tty,   -T               Prevent tty allocation
    --use-key      FINGERPRINT   Explicitly specify the fingerprint of the egress key you want to use
    --kbd-interactive            Enable the keyboard-interactive authentication scheme on egress connection
    --netconf                    Request to use netconf subsystem
    --fallback-password-delay S  Amount of seconds to wait between subsequent tries in the SSH password autologin fallback mechanism (default: 3)
    --term-passthrough           Don't override the TERM value in the SSH password autologin script (default: "")

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
