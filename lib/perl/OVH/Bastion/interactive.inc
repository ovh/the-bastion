# vim: set filetype=perl ts=4 sw=4 sts=4 et:
package OVH::Bastion;

use common::sense;
use Term::ReadLine;
use POSIX ();

# autocompletion rules
my @rules;

sub _get_prompt {
    my ($self, $bastionName, $slaveOrMaster) = @_;
    my $mfaOk = "";
    if ($ENV{'OSH_PROACTIVE_MFA'}) {
        $mfaOk = "[" . "\001\033[33m\002" . "MFA-OK" . "\001\033[1;35m\002]";
    }
    my $prompt = ""
      . "\001\033[0m\033[33m\002"
      . $self
      . "\001\033[1;35m\002" . "@"
      . "\001\033[32m\002"
      . $bastionName
      . "\001\033[1;35m\002" . "("
      . "\001\033[0m\033[36m\002"
      . $slaveOrMaster
      . "\001\033[1;35m\002" . ")"
      . $mfaOk
      . "\001\033[0m\033[32m\002" . ">"
      . "\001\033[0m\002" . " ";
    return $prompt;
}

sub interactive {
    my %params         = @_;
    my $realOptions    = $params{'realOptions'};
    my $timeoutHandler = $params{'timeoutHandler'};
    my $self           = $params{'self'};
    my $fnret;

    my $bastionName            = OVH::Bastion::config('bastionName')->value();
    my $interactiveModeTimeout = OVH::Bastion::config('interactiveModeTimeout')->value() || 0;
    my $slaveOrMaster          = (OVH::Bastion::config('readOnlySlaveMode')->value() ? 'slave' : 'master');
    my $interactiveModeProactiveMFAexpiration = OVH::Bastion::config("interactiveModeProactiveMFAexpiration")->value;
    my $proactiveMFAenabledTime               = 0;

    my $term = Term::ReadLine->new('Bastion Interactive');

    print <<"EOM";

Welcome to $bastionName interactive mode, type `help' for available commands.
You can use <tab> and <tab><tab> for autocompletion.
EOM
    print "You'll be disconnected after $interactiveModeTimeout seconds of inactivity.\n" if $interactiveModeTimeout;

    # dynamically get the list of plugins we can use

    print "Loading... ";
    $fnret = OVH::Bastion::get_plugin_list();
    $fnret or return ();
    my $pluginList = $fnret->value;

    my @cmdlist = qw{ exit ssh mfa enable nomfa end };
    foreach my $plugin (sort keys %$pluginList) {
        $fnret = OVH::Bastion::can_account_execute_plugin(plugin => $plugin, account => $self, cache => 1);
        next if !$fnret;

        push @cmdlist, $plugin;

        # also load autocompletion rules for this plugin
        $fnret = OVH::Bastion::load_configuration_file(
            secure => 1,
            file   => $pluginList->{$plugin}->{'dir'} . '/' . $plugin . '.json'
        );
        if ($fnret) {
            my $jsonData = $fnret->value;
            if (ref $jsonData eq 'HASH' && ref $jsonData->{'interactive'} eq 'ARRAY') {
                push @rules, @{$jsonData->{'interactive'}};
            }
        }
        elsif ($fnret->err ne 'KO_NO_SUCH_FILE') {
            warn_syslog("Interactive mode: error reading configuration for plugin '$plugin': " . $fnret->msg);
        }
    }
    print scalar(@cmdlist) . " commands and " . (@rules / 2) . " autocompletion rules loaded.\n\n";

    # setup readline

    if (!$ENV{'TERM'}) {

        # if TERM is undef, don't call $term->ornaments(1) or we'll generate a warn
        print "Your TERM envvar is not defined, some things might not work correctly!\n\n";
    }
    else {
        $term->ornaments(1);
    }
    my $attribs = $term->Attribs;

    $attribs->{'completion_function'} = sub {
        my ($word, $line, $start) = @_;

        # word: current word being typed
        # line: whole line so far
        # start: cursor pos

        # avoid disconnection because the user seems to be alive
        alarm($interactiveModeTimeout);

        if (!$line) {

            # autocompletion asked without anything written yet
            return @cmdlist;
        }

        # easter egg
        if ($line eq $word and $word =~ /^con/) {
            return ('configure');
        }
        if ($line =~ /^conf(igure)?(\s|$)/ and ('terminal' =~ /^\Q$word\E/)) {
            return ('terminal');
        }

        # /easter egg

        if ($line eq $word) {

            # first word of line, user wants completion
            my @validcmds;
            foreach my $cmd (@cmdlist) {
                push @validcmds, $cmd if ($cmd =~ /^\Q$word\E/);
            }
            return @validcmds;
        }

        my $accountList          = OVH::Bastion::get_account_list(cache => 1)->value;
        my $groupList            = OVH::Bastion::get_group_list(cache => 1, groupType => 'key')->value;
        my $realmList            = OVH::Bastion::get_realm_list(cache => 1)->value;
        my $pluginListRestricted = OVH::Bastion::get_plugin_list(restrictedOnly => 1)->value;
        my $i                    = 0;
        while ($i + 1 < $#rules) {
            my $re   = $rules[$i++];
            my $item = $rules[$i++];

            next unless ($line =~ m{^$re\s*$} or $line =~ m{^$re\s\Q$word\E\s*$});

            # but wait, even if it matches, user must have the right to use this plugin,
            # check that here

            my ($typedPlugin) = $line =~ m{^(\S+)};
            next unless grep { $typedPlugin eq $_ } @cmdlist;

            # if autocomplete specified, just return it
            if ($item->{'ac'}) {

                # but before, check there's no magic inside, i.e. replace ACCOUNT by @account_list and GROUP by @group_list
                my @autocomplete;
                foreach (@{$item->{'ac'}}) {
                    if ($_ eq '<ACCOUNT>' && $accountList) {
                        push @autocomplete, sort keys %$accountList;
                        next;
                    }
                    elsif ($_ eq '<GROUP>' && $groupList) {
                        push @autocomplete, sort keys %$groupList;
                        next;
                    }
                    elsif ($_ eq '<REALM>' && $realmList) {
                        push @autocomplete, sort keys %$realmList;
                        next;
                    }
                    elsif ($_ eq '<RESTRICTED_COMMAND>' && $pluginListRestricted) {
                        push @autocomplete, 'auditor', sort keys %$pluginListRestricted;
                        next;
                    }
                    elsif ($_ eq '<COMMAND>' && $pluginList) {
                        push @autocomplete, sort keys %$pluginList;
                        next;
                    }
                    push @autocomplete, $_;
                }
                return @autocomplete;
            }

            # else, we just print stuff ourselves
            if ($item->{'pr'}) {
                print "\n"
                  . join("\n", @{$item->{'pr'}}) . "\n"
                  . _get_prompt($self, $bastionName, $slaveOrMaster)
                  . $line;
                return ();
            }
        }

        # nothing matches, we have nothing to return
        return ();
    };

    # for obscure reasons, perl signal handling code doesn't work well with readline
    # unless we force them to "unsafe" mode before perl starts, which is ugly.
    # so for this one, use direct sigaction() call and bypass perl signal mechanics
    # cf http://stackoverflow.com/questions/13316232/perl-termreadlinegnu-signal-handling-difficulties
    POSIX::sigaction POSIX::SIGALRM, POSIX::SigAction->new(
        sub {
            print "\n\nIdle timeout, goodbye!\n\n";
            &$timeoutHandler('TIMEOUT') if ref $timeoutHandler eq 'CODE';
            exit 1;    # normally not reached
        }
    );
    # handle ^C to clear the current prompt
    POSIX::sigaction POSIX::SIGINT, POSIX::SigAction->new(
        sub {
            print "\n";              # ensure we are on a new line
            $term->on_new_line();    # print the prompt
            $term->replace_line("", 0);    # clear the previous text
            $term->redisplay();
        }
    );

    my $BASTION_USER = OVH::Bastion::get_user_from_env()->value;
    alarm($interactiveModeTimeout);
    while (defined(my $line = $term->readline(_get_prompt($self, $bastionName, $slaveOrMaster)))) {
        alarm(0);                          # disable timeout
        $line =~ s/^\s+|\s+$//g;

        # disable proactive MFA if it has expired. Even if the user just typed "enter" with no command.
        if (   $proactiveMFAenabledTime > 0
            && $interactiveModeProactiveMFAexpiration
            && (time() - $proactiveMFAenabledTime) >= $interactiveModeProactiveMFAexpiration)
        {
            print "MFA proactive mode has been disabled after "
              . OVH::Bastion::duration2human(seconds => $interactiveModeProactiveMFAexpiration)->value->{'duration'}
              . "\n";
            $proactiveMFAenabledTime = 0;
            delete $ENV{'OSH_PROACTIVE_MFA'};
        }

        next if (length($line) == 0);                                    # ignore empty lines
        last if ($line eq 'exit' or $line eq 'quit' or $line eq 'q');    # break out of loop if asked

        $term->addhistory($line);

        if ($line =~ /^conf(i(g(u(r(e)?)?)?)?)? t(e(r(m(i(n(a(l)?)?)?)?)?)?)?$/) {
            print "Nice try, but... no :)\n";
            next;
        }

        {
            local $ENV{'OSH_IN_INTERACTIVE_SESSION'} = 1;
            if (lc($line) eq 'mfa' || $line =~ m{^en(a(b(le?)?)?)?$}) {
                if (OVH::Bastion::config("interactiveModeProactiveMFAenabled")->value) {
                    print "As proactive MFA validation has been requested, entering MFA phase.\n";
                    $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $self);
                    if (!$fnret) {
                        warn_syslog("Couldn't get account details in interactive mode (" . $fnret->msg . ")");
                        main_exit(OVH::Bastion::EXIT_ACCOUNT_INVALID(),
                            "account_invalid", "Error while getting account details");
                    }
                    my $sysself = $fnret->value->{'sysaccount'};
                    $fnret = OVH::Bastion::do_pamtester(self => $self, sysself => $sysself);
                    if ($fnret) {
                        print "Proactive MFA enabled, any command requiring MFA from now on will not ask you again.\n";
                        if ($interactiveModeProactiveMFAexpiration > 0) {
                            print "This mode will expire in "
                              . OVH::Bastion::duration2human(seconds => $interactiveModeProactiveMFAexpiration)
                              ->value->{'human'} . "\n";
                        }
                        print "To exit this mode manually, type 'nomfa'.\n";
                        $proactiveMFAenabledTime = time();
                        $ENV{'OSH_PROACTIVE_MFA'} = 1;
                    }
                    else {
                        print "MFA validation failed, as a consequence proactive MFA mode is NOT active.\n";
                        $proactiveMFAenabledTime = 0;
                        delete $ENV{'OSH_PROACTIVE_MFA'};
                    }
                }
                else {
                    print "Sorry, proactive MFA validation has been disabled in interactive mode by policy.\n";
                }
            }
            elsif (lc($line) eq 'nomfa' || $line eq 'end') {
                if ($ENV{'OSH_PROACTIVE_MFA'}) {
                    print "Your proactive MFA validation has been forgotten.\n";
                }
                else {
                    print "Nothing to do, you didn't proactively validate MFA.\n";
                }
                $proactiveMFAenabledTime = 0;
                delete $ENV{'OSH_PROACTIVE_MFA'};
            }
            elsif ($line =~ /^ssh (.+)$/) {
                system($0, '-c', "$realOptions $1");
            }
            else {
                system($0, '-c', "$realOptions --osh $line");

                # in addition to the normal help, also advertise the interactive mode builtin commands:
                if ($line eq 'help') {

                    osh_info("Under interactive mode, additional builtin commands are supported:\n"
                          . "- ssh [options] <server>  Connect to remote server, note that all the standard options\n"
                          . "                             can be used (--port, etc.), refer to --long-help for a list.\n"
                          . "- mfa                     Request an immediate MFA validation to elevate the current session,\n"
                          . "                             to avoid getting a prompt for each JIT MFA-required command.\n"
                          . "- nomfa                   Go back non-MFA elevated session.\n"
                          . "- exit                    Quit the interactive mode, 'quit' and ^D can be used instead.\n"
                    );
                }
            }
        }

        my (%before, %after);
        $fnret = OVH::Bastion::execute(cmd => [qw{ id -G -n }]);
        if ($fnret->err eq 'OK' and $fnret->value and $fnret->value->{'stdout'}) {
            chomp $fnret->value->{'stdout'}->[0];
            %before = map { $_ => 1 } split(/ /, $fnret->value->{'stdout'}->[0]);
        }
        $fnret = OVH::Bastion::execute(cmd => ['id', '-G', '-n', $BASTION_USER]);
        if ($fnret->err eq 'OK' and $fnret->value and $fnret->value->{'stdout'}) {
            chomp $fnret->value->{'stdout'}->[0];
            %after = map { $_ => 1 } split(/ /, $fnret->value->{'stdout'}->[0]);
        }
        my @newgroups = grep { !exists $before{$_} && !/^mfa-/ } keys %after;
        if (@newgroups) {
            osh_warn("IMPORTANT: You have been added to new groups since the session started.");
            osh_warn("You'll need to logout/login again from this interactive session to have");
            osh_warn("your new rights applied, or you'll get sudo errors if you try to use them.");
        }
    }
    continue {
        alarm($interactiveModeTimeout);
    }
    alarm(0);    # disable timeout
    print "\n\nGoodbye!\n\n";
    return 0;
}

1;
