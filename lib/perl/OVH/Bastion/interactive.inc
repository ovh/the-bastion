# vim: set filetype=perl ts=4 sw=4 sts=4 et:
package OVH::Bastion;

use common::sense;
use Term::ReadLine;
use JSON;
use POSIX ();

# autocompletion rules
my @rules;

sub interactive {
    my %params         = @_;
    my $realOptions    = $params{'realOptions'};
    my $timeoutHandler = $params{'timeoutHandler'};
    my $self           = $params{'self'};
    my $fnret;

    my $bastionName            = OVH::Bastion::config('bastionName')->value();
    my $interactiveModeTimeout = OVH::Bastion::config('interactiveModeTimeout')->value() || 0;
    my $slaveOrMaster          = (OVH::Bastion::config('readOnlySlaveMode')->value() ? 'slave' : 'master');

    my $term = Term::ReadLine->new('Bastion Interactive');
    ## no critic(ValuesAndExpressions::ProhibitEscapedCharacters)
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
      . "\001\033[0m\033[32m\002" . ">"
      . "\001\033[0m\002" . " ";

    my $prompt_non_readline = $prompt;
    $prompt_non_readline =~ s=\001|\002==g;

    print <<"EOM";

Welcome to $bastionName interactive mode, type `help' for available commands.
You can use <tab> and <tab><tab> for autocompletion.
You'll be disconnected after $interactiveModeTimeout seconds of inactivity.
EOM

    # dynamically get the list of plugins we can use

    print "Loading... ";
    $fnret = OVH::Bastion::get_plugin_list();
    $fnret or return ();
    my $pluginList = $fnret->value;

    my @cmdlist = qw{ exit ssh };
    foreach my $plugin (sort keys %$pluginList) {
        $fnret = OVH::Bastion::can_account_execute_plugin(plugin => $plugin, account => $self);
        next if !$fnret;

        push @cmdlist, $plugin;

        # also load autocompletion rules for this plugin
        if (open(my $jsonFd, '<', $pluginList->{$plugin}->{'dir'} . '/' . $plugin . '.json')) {
            local $/ = undef;
            my $jsonPayload = <$jsonFd>;
            close($jsonFd);
            my $jsonData;
            eval { $jsonData = decode_json($jsonPayload); };
            if (ref $jsonData eq 'HASH' && ref $jsonData->{'interactive'} eq 'ARRAY') {
                push @rules, @{$jsonData->{'interactive'}};
            }
        }
    }
    print scalar(@cmdlist) . " commands and " . (@rules / 2) . " autocompletion rules loaded.\n\n";

    # setup readline

    $term->ornaments(1);
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

        foreach my $i (0 .. $#rules) {
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
                    if ($_ eq '<ACCOUNT>') {
                        $fnret = OVH::Bastion::get_account_list(cache => 1);
                        if ($fnret) {
                            push @autocomplete, sort keys %{$fnret->value()};
                            next;
                        }
                    }
                    elsif ($_ eq '<GROUP>') {
                        $fnret = OVH::Bastion::get_group_list(cache => 1, groupType => 'key');
                        if ($fnret) {
                            push @autocomplete, sort keys %{$fnret->value()};
                            next;
                        }
                    }
                    elsif ($_ eq '<REALM>') {
                        $fnret = OVH::Bastion::get_realm_list();
                        if ($fnret) {
                            push @autocomplete, sort keys %{$fnret->value()};
                            next;
                        }
                    }
                    elsif ($_ eq '<RESTRICTED_COMMAND>') {
                        $fnret = OVH::Bastion::get_plugin_list(restrictedOnly => 1);
                        if ($fnret) {
                            push @autocomplete, 'auditor', sort keys %{$fnret->value()};
                            next;
                        }
                    }
                    elsif ($_ eq '<COMMAND>') {
                        $fnret = OVH::Bastion::get_plugin_list();
                        if ($fnret) {
                            push @autocomplete, sort keys %{$fnret->value()};
                            next;
                        }
                    }
                    push @autocomplete, $_;
                }
                return @autocomplete;
            }

            # else, we just print stuff ourselves
            if ($item->{'pr'}) {
                print "\n" . join("\n", @{$item->{'pr'}}) . "\n$prompt_non_readline$line";
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

    my $BASTION_USER = OVH::Bastion::get_user_from_env()->value;
    alarm($interactiveModeTimeout);
    while (defined(my $line = $term->readline($prompt))) {
        alarm(0);      # disable timeout
        $line =~ s/^\s+|\s+$//g;
        next if (length($line) == 0);                                    # ignore empty lines
        last if ($line eq 'exit' or $line eq 'quit' or $line eq 'q');    # break out of loop if asked

        $term->addhistory($line);

        if ($line =~ /^conf(i(g(u(r(e)?)?)?)?)? t(e(r(m(i(n(a(l)?)?)?)?)?)?)?$/) {
            print "Nice try, but... no :)\n";
            next;
        }

        {
            local $ENV{'OSH_NO_INTERACTIVE'} = 1;
            if ($line =~ /^ssh (.+)$/) {
                system($0, '-c', "$realOptions $1");
            }
            else {
                system($0, '-c', "$realOptions --osh $line");
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
