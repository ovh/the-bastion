package OVH::Bastion::Plugin::groupModify;

# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

use File::Basename;
use lib dirname(__FILE__) . '/../../../../../lib/perl';
use OVH::Result;
use OVH::Bastion;

# This module holds the group configuration options that can be set either when the group
# is created (`groupCreate`), or afterwards (`groupModify`). It is used by both plugins
# and by both helpers, so that these options only need to be declared, validated and
# applied in a single place.
#
# The usual flow is:
#   - plugin-side: options() to declare the command-line options, then validate_options()
#     to check them and convert the durations to seconds, then helper_args() to forward
#     them to the helper.
#   - helper-side: options() again to parse them back, then apply() once the group exists.

# Getopt::Long specs for the group configuration options, to be merged into the caller's
# own options. The parsed values are stored in the hash pointed to by 'opt'.
# Plugin-side, durations are taken as human-readable strings (e.g. '2d8h15m') and are
# converted to seconds by validate_options() below, hence helper-side, where the values
# have already been converted, 'seconds' must be set so that we only accept integers.
sub options {
    my %params  = @_;
    my $opt     = $params{'opt'};
    my $seconds = $params{'seconds'};

    my $duration = $seconds ? '=i' : '=s';

    return (
        "mfa-required=s"             => \$opt->{'mfaRequired'},
        "idle-lock-timeout$duration" => \$opt->{'idleLockTimeout'},
        "idle-kill-timeout$duration" => \$opt->{'idleKillTimeout'},
        "guest-ttl-limit$duration"   => \$opt->{'ttl'},
    );
}

# The help text of the above options, to be included in the callers' own help text.
sub helptext {
    return <<'EOF';
  --mfa-required      password|totp|any|none   Enforce UNIX password requirement, or TOTP requirement, or any MFA requirement, when connecting to a server of the group
  --idle-lock-timeout DURATION|0|-1            Overrides the global setting (`idleLockTimeout`), to the specified duration. If set to 0, disables `idleLockTimeout` for
                                                 this group. If set to -1, remove this group override and use the global setting instead.
  --idle-kill-timeout DURATION|0|-1            Overrides the global setting (`idleKillTimeout`), to the specified duration. If set to 0, disables `idleKillTimeout` for
                                                 this group. If set to -1, remove this group override and use the global setting instead.
  --guest-ttl-limit   DURATION                 This group will enforce TTL setting, on guest access creation, to be set, and not to a higher value than DURATION,
                                                 set to zero to allow guest accesses creation without any TTL set (default)

Note that `--idle-lock-timeout` and `--idle-kill-timeout` will NOT be applied for catch-all groups (having 0.0.0.0/0 in their server list).

If a server is in exactly one group an account is a member of, then its values of `--idle-lock-timeout` and `--idle-kill-timeout`, if set,
will prevail over the global setting. The global setting can be seen with `--osh info`.

Otherwise, the most restrictive setting (i.e. the one with the lower strictly positive duration) between
all the considered groups and the global setting, will be used.
EOF
}

# Plugin-side check of the values parsed thanks to options(): validates them, and converts
# the durations to a number of seconds, in place. Returns the number of options that have
# actually been specified by the caller, so that plugins requiring at least one of them can
# complain when none was.
sub validate_options {
    my %params = @_;
    my $opt    = $params{'opt'};
    my $fnret;

    foreach my $key (qw{ ttl idleLockTimeout idleKillTimeout }) {
        next if !defined $opt->{$key};

        # -1 is a valid value for the idle timeouts (see below), and is handled helper-side
        next if $opt->{$key} eq '-1';

        $fnret = OVH::Bastion::is_valid_ttl(ttl => $opt->{$key});
        $fnret or return $fnret;
        $opt->{$key} = $fnret->value->{'seconds'};
    }

    # for the idle timeouts, -1 means "remove the group override and use the global setting",
    # this has no meaning for the guest TTL limit, where 0 already means "no limit"
    if (defined $opt->{'ttl'} && $opt->{'ttl'} == -1) {
        return R('ERR_INVALID_PARAMETER',
            msg => "Invalid TTL (-1), expected an amount of seconds, or a duration string such as '2d8h15m'");
    }

    if (defined $opt->{'mfaRequired'} && !grep { $opt->{'mfaRequired'} eq $_ } qw{ password totp any none }) {
        return R('ERR_INVALID_PARAMETER',
            msg => "Expected 'password', 'totp', 'any' or 'none' as parameter to --mfa-required");
    }

    my $specified = grep { defined $opt->{$_} } qw{ mfaRequired ttl idleLockTimeout idleKillTimeout };
    return R('OK', value => {specified => $specified});
}

# Plugin-side: the list of arguments to append to the helper command line, for the options
# that have been specified.
sub helper_args {
    my %params = @_;
    my $opt    = $params{'opt'};

    my @args;
    push @args, '--mfa-required',      $opt->{'mfaRequired'}     if defined $opt->{'mfaRequired'};
    push @args, '--guest-ttl-limit',   $opt->{'ttl'}             if defined $opt->{'ttl'};
    push @args, '--idle-lock-timeout', $opt->{'idleLockTimeout'} if defined $opt->{'idleLockTimeout'};
    push @args, '--idle-kill-timeout', $opt->{'idleKillTimeout'} if defined $opt->{'idleKillTimeout'};
    return @args;
}

# Helper-side: apply the specified options to the group, which must already exist. The caller
# is responsible for having validated the group name and the rights of $self on it beforehand.
# Any option that hasn't been specified is left untouched. Errors are not fatal: they're warned
# about, and reported per-option in the returned value.
sub apply {
    my %params = @_;
    my $group  = $params{'group'};    # the long (prefixed by 'key') and untainted group name
    my $opt    = $params{'opt'};
    my $fnret;

    if (!$group || ref $opt ne 'HASH') {
        return R('ERR_MISSING_PARAMETER', msg => "Missing 'group' or 'opt' parameter");
    }

    my %result;

    if (defined $opt->{'mfaRequired'}) {
        osh_info "Modifying mfa-required policy of group...";
        if (grep { $opt->{'mfaRequired'} eq $_ } qw{ password totp any none }) {
            $fnret = OVH::Bastion::group_config(group => $group, key => "mfa_required", value => $opt->{'mfaRequired'});
            if ($fnret) {
                osh_info "... done, policy is now: " . $opt->{'mfaRequired'};
            }
            else {
                osh_warn "... error while changing mfa-required policy ($fnret)";
            }
            $result{'mfa_required'} = $fnret;
        }
        else {
            osh_warn "... invalid option '" . $opt->{'mfaRequired'} . "'";
            $result{'mfa_required'} = R('ERR_INVALID_PARAMETER');
        }
    }

    my %idleTimeout = (
        lock => {
            name  => "idle lock timeout",
            key   => \%{OVH::Bastion::OPT_GROUP_IDLE_LOCK_TIMEOUT()},
            value => $opt->{'idleLockTimeout'},
        },
        kill => {
            name  => "idle kill timeout",
            key   => \%{OVH::Bastion::OPT_GROUP_IDLE_KILL_TIMEOUT()},
            value => $opt->{'idleKillTimeout'},
        },
    );

    foreach my $item (keys %idleTimeout) {
        next if !defined $idleTimeout{$item}{'value'};

        osh_info "Modifying " . $idleTimeout{$item}{'name'} . " policy of group...";
        if ($idleTimeout{$item}{'value'} >= 0) {
            $fnret = OVH::Bastion::group_config(
                group => $group,
                %{$idleTimeout{$item}{'key'}}, value => $idleTimeout{$item}{'value'}
            );
            if ($fnret) {
                if ($idleTimeout{$item}{'value'} == 0) {
                    osh_info "... done, this group's "
                      . $idleTimeout{$item}{'name'}
                      . " policy is now set to: disabled";
                }
                else {
                    osh_info "... done, this group is now configured to use a "
                      . $idleTimeout{$item}{'name'}
                      . " policy of "
                      . OVH::Bastion::duration2human(seconds => $idleTimeout{$item}{'value'})->value->{'human'};
                }
            }
            else {
                osh_warn "... error while setting the group-specific "
                  . $idleTimeout{$item}{'name'}
                  . " policy ($fnret)";
                warn_syslog "Error setting the group-specific "
                  . $idleTimeout{$item}{'name'}
                  . " policy of $group ($fnret)";
            }
        }
        else {
            $fnret = OVH::Bastion::group_config(group => $group, %{$idleTimeout{$item}{'key'}}, delete => 1);
            if ($fnret) {
                osh_info "... done, this group will now use the global " . $idleTimeout{$item}{'name'} . " policy";
            }
            else {
                osh_warn "... error while removing the group-specific "
                  . $idleTimeout{$item}{'name'}
                  . " policy ($fnret)";
                warn_syslog "Error removing the group-specific "
                  . $idleTimeout{$item}{'name'}
                  . " policy of $group ($fnret)";
            }
        }
        $result{$idleTimeout{$item}{'key'}{'key'}} = $fnret;
    }

    if (defined $opt->{'ttl'}) {
        osh_info "Modifying guest TTL limit policy of group...";
        if ($opt->{'ttl'} > 0) {
            $fnret = OVH::Bastion::group_config(group => $group, key => "guest_ttl_limit", value => $opt->{'ttl'});
            if ($fnret) {
                osh_info
                  "... done, guest accesses must now have a TTL set on creation, with maximum allowed duration of "
                  . OVH::Bastion::duration2human(seconds => $opt->{'ttl'})->value->{'human'};
            }
            else {
                osh_warn "... error while setting guest-ttl-limit ($fnret)";
            }
        }
        else {
            $fnret = OVH::Bastion::group_config(group => $group, key => "guest_ttl_limit", delete => 1);
            if ($fnret) {
                osh_info "... done, guest accesses no longer need to have a TTL set";
            }
            else {
                osh_warn "... error while removing guest-ttl-limit ($fnret)";
            }
        }
        $result{'guest_ttl_limit'} = $fnret;
    }

    # a failed option is not fatal by design: the group itself is fine, and the other options
    # may have been applied successfully. The partial failure must not be lost, however: in
    # that case, return OK_WITH_ERRORS instead of OK, so that all our callers report it
    # consistently to their own caller.
    if (my @failed = sort grep { !$result{$_} } keys %result) {
        return R(
            'OK_WITH_ERRORS',
            value => \%result,
            msg   => "The following group configuration options couldn't be applied: " . join(", ", @failed)
        );
    }
    return R('OK', value => \%result);
}

1;
