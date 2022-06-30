# vim: set filetype=perl ts=4 sw=4 sts=4 et:
package OVH::Bastion;

use common::sense;

use constant {MINIJAIL_PATH => "/bin/minijail0",};

sub jailify {
    my %params = @_;

    my $required     = delete $params{'required'};
    my $use_sudo     = delete $params{'use_sudo'};
    my $user         = delete $params{'user'};
    my $group        = delete $params{'group'};
    my $no_new_privs = delete $params{'no_new_privs'};
    my $set_env      = delete $params{'set_env'};
    my $pid_ns       = delete $params{'pid_ns'};
    my $mount_mode   = delete $params{'mount_mode'};
    my $mount_ns     = delete $params{'mount_ns'};
    my $pivot_root   = delete $params{'pivot_root'};
    my $bind_mounts  = delete $params{'bind_mounts'};
    my $mounts       = delete $params{'mounts'};
    my $seccomp      = delete $params{'seccomp'};
    my $uts          = delete $params{'uts'};
    my $ld_preload   = delete $params{'ld_preload'};
    my $dev          = delete $params{'dev'};
    my $cmd          = delete $params{'cmd'};

    if (%params) {

        # this is a coding error => warn(), this'll make any test passing through it automatically fail
        warn("Spurious parameter passed to jailify(): " . join(", ", keys %params));
        return R('ERR_INTERNAL', msg => "Spurious parameter passed to jailify()");
    }

    if (!$cmd || ref $cmd ne 'ARRAY') {
        return R('ERR_INVALID_PARAMETER', msg => "Specified cmd is either missing or not an arrayref");
    }

    if (!-e -x OVH::Bastion::MINIJAIL_PATH) {
        return R('ERR_INTERNAL', msg => "minijail not available, please warn your bastion administrator") if $required;

        # not installed and not required? just return the @cmd untouched
        return R('OK_NO_CHANGE', value => $cmd);
    }

    # we need to be root for several cases
    if (($user || $group || $mount_ns || $pivot_root || $bind_mounts || $mounts) && ($> != 0) && !$use_sudo) {

        # this is a coding error => warn(), this'll make any test passing through it automatically fail
        warn(
            'Jailify attempted with a feature needing root without being root ',
            "\$user: ",
            ($user // "_undef_"),
            "\$group: ",
            ($group // "_undef_"),
            "\$mount_ns: ",
            ($mount_ns // "_undef_"),
            "\$pivot_root: ",
            ($pivot_root // "_undef_"),
            "\$bind_mounts: ",
            ($bind_mounts // "_undef_"),
            "\$mounts: ",
            ($mounts // "_undef_"),
        );
        return R('ERR_INTERNAL', msg => "Bad use of jailify(), please warn your bastion administrator");
    }

    my @jailcmd;
    if ($use_sudo) {
        push @jailcmd, qw{ sudo -n -u root -- };
    }

    push @jailcmd, OVH::Bastion::MINIJAIL_PATH, "--logging=stderr";
    push @jailcmd, "-u", $user  if $user;
    push @jailcmd, "-g", $group if $group;
    push @jailcmd, "-n"            if $no_new_privs;
    push @jailcmd, "-v"            if $mount_ns;
    push @jailcmd, "-p"            if $pid_ns;
    push @jailcmd, "--uts"         if $uts;
    push @jailcmd, "-K$mount_mode" if $mount_mode;
    push @jailcmd, "-d"            if $dev;
    push @jailcmd, "--child-ld-preload", $ld_preload if $ld_preload;

    if ($pivot_root) {
        return R('ERR_INVALID_PARAMETER', msg => "Specified pivot_root ($pivot_root) is not a directory")
          if !-d $pivot_root;
        push @jailcmd, "-P", $pivot_root;
    }

    if ($seccomp) {
        return R('ERR_INVALID_PARAMETER', msg => "Specified seccomp filter is not a file") if !-f -r $seccomp;
        push @jailcmd, "-S", $seccomp;
    }

    if (defined $bind_mounts) {
        return R('ERR_INVALID_PARAMETER', msg => "Specified bind_mounts is not an arrayref")
          if (ref $bind_mounts ne 'ARRAY');
        push @jailcmd, "-b", $_ for (@$bind_mounts);
    }

    if (defined $mounts) {
        return R('ERR_INVALID_PARAMETER', msg => "Specified mounts is not an arrayref") if (ref $mounts ne 'ARRAY');
        push @jailcmd, "-k", $_ for (@$mounts);
    }

    if (defined $set_env) {
        return R('ERR_INVALID_PARAMETER', msg => "Specified set_env is not an arrayref") if (ref $set_env ne 'ARRAY');
        push @jailcmd, "--set-env", $_ for (@$set_env);
    }

    push @jailcmd, '--', @$cmd;

    return R('OK', value => \@jailcmd);
}

1;
