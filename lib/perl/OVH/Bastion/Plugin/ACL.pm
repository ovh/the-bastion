package OVH::Bastion::Plugin::ACL;
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

use File::Basename;
use lib dirname(__FILE__) . '/../../../../../lib/perl';
use OVH::Result;
use OVH::Bastion;

sub check {
    my %params = @_;
    my ($port, $portAny, $user, $userAny, $scpUp, $scpDown, $sftp) =
      @params{qw{ port portAny user userAny scpUp scpDown sftp }};

    if ($user and $userAny) {
        return R('ERR_INCOMPATIBLE_PARAMETERS',
            msg => "A user was specified with --user, along with --user-any, "
              . "both are contradictory, please check your command");
    }

    if ($scpUp and $scpDown) {
        return R('ERR_INCOMPATIBLE_PARAMETERS',
            msg => "You specified both --scpup and --scpdown, "
              . "if you want to grant both, please do it in two separate commands");
    }

    if ($sftp and ($scpUp or $scpDown)) {
        return R('ERR_INCOMPATIBLE_PARAMETERS',
            msg => "You specified both --scp* and --sftp, "
              . "if you want to grant both protocols, please do it in two separate commands");
    }

    if (($scpUp or $scpDown or $sftp) and ($user or $userAny)) {
        return R('ERR_INCOMPATIBLE_PARAMETERS',
                msg => "To grant SCP or SFTP access, first ensure SSH access "
              . "is granted to the machine (with the --user you need, or --user-any), then grant with --scpup and/or "
              . "--scpdown and/or --sftp, omitting --user/--user-any");
    }
    $user = '!scpupload'   if $scpUp;
    $user = '!scpdownload' if $scpDown;
    $user = '!sftp'        if $sftp;

    if (not $user and not $userAny) {
        return R('ERR_MISSING_PARAMETER',
            msg => "No user specified, if you want to add this server with any user, use --user-any");
    }

    if ($portAny and $port) {
        return R('ERR_INCOMPATIBLE_PARAMETERS',
            msg => "A port was specified with --port, "
              . "along with --port-any, both are contradictory, please check your command");
    }

    if (not $port and not $portAny) {
        return R('ERR_MISSING_PARAMETER',
            msg => "No port specified, if you want to add this server with any port, use --port-any");
    }

    return R('OK', value => {user => $user});
}

1;
