package OVH::Bastion::Plugin::ACL;
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

use File::Basename;
use lib dirname(__FILE__) . '/../../../../../lib/perl';
use OVH::Result;
use OVH::Bastion;

sub check {
    my %params = @_;
    my ($port, $portAny, $user, $userAny, $scpUp, $scpDown, $sftp, $protocol, $proxyIp, $proxyPort, $proxyUser) =
      @params{qw{ port portAny user userAny scpUp scpDown sftp protocol proxyIp proxyPort proxyUser }};

    if ($user and $userAny) {
        return R('ERR_INCOMPATIBLE_PARAMETERS',
            msg => "A user was specified with --user, along with --user-any, "
              . "both are contradictory, please check your command");
    }

    # legacy option mapping
    $user = '*' if $userAny;

    if ($protocol) {
        if ($scpUp or $scpDown or $sftp) {
            return R('ERR_INCOMPATIBLE_PARAMETERS', msg => "Can't use --protocol with --scpup, --scpdown or --sftp");
        }
        if (!grep { $protocol eq $_ } qw{ scpupload scpdownload sftp rsync }) {
            return R('ERR_INVALID_PARAMETER',
                msg =>
                  "The protocol '$protocol' is not supported, expected either scpupload, scpdownload, sftp or rsync");
        }
    }

    if ($scpUp and $scpDown) {
        return R('ERR_INCOMPATIBLE_PARAMETERS',
            msg => "You specified both --scpup and --scpdown, "
              . "if you want to grant both, please do it in two separate commands");
    }

    if ($sftp and ($scpUp or $scpDown)) {
        return R('ERR_INCOMPATIBLE_PARAMETERS',
            msg => "You can specify only one of --sftp --scpup --scpdown at a time, "
              . "if you want to grant several of those protocols, please do it in separate commands");
    }

    # legacy options mapping
    if (!$protocol) {
        $protocol = 'sftp'        if $sftp;
        $protocol = 'scpupload'   if $scpUp;
        $protocol = 'scpdownload' if $scpDown;
    }

    if ($protocol and $user) {
        return R('ERR_INCOMPATIBLE_PARAMETERS',
                msg => "To grant access using the $protocol protocol, first ensure SSH access "
              . "is granted to the machine (with the --user you need), then grant with --protocol, "
              . "omitting --user");
    }

    # special user when a protocol is specified
    $user = "!$protocol" if $protocol;

    if (not $user and not $userAny) {
        return R('ERR_MISSING_PARAMETER',
            msg =>
              "No user specified, if you want to add this server with any user, use --user * (you might need to escape it from your shell)"
        );
    }

    if ($portAny and $port) {
        return R('ERR_INCOMPATIBLE_PARAMETERS',
            msg => "A port was specified with --port, "
              . "along with --port-any, both are contradictory, please check your command");
    }

    # legacy option mapping
    $port = '*' if $portAny;

    if (not defined $port) {
        return R('ERR_MISSING_PARAMETER',
            msg =>
              "No port specified, if you want to add this server with any port, use --port * (you might need to escape it from your shell)"
        );
    }

    # check proxy-host and proxy-port parameters
    osh_debug("Checking proxy parameters: proxyIp='$proxyIp' proxyPort='$proxyPort' proxyUser='$proxyUser'");
    if ($proxyIp) {
        if (!$proxyPort) {
            return R('ERR_MISSING_PARAMETER', msg => "When --proxy-host is specified, --proxy-port becomes mandatory");
        }

        # validate proxy host format (same as regular host validation)
        if ($proxyIp !~ m{^[a-zA-Z0-9._:-]+$}) {
            return R('ERR_INVALID_PARAMETER', msg => "Proxy host name '$proxyIp' seems invalid");
        }

        if (!$proxyUser) {
            return R('ERR_MISSING_PARAMETER', msg => "When --proxy-host is specified, --proxy-user becomes mandatory");
        }
    }

    if ($proxyPort) {
        if (!$proxyIp) {
            return R('ERR_MISSING_PARAMETER', msg => "When --proxy-port is specified, --proxy-host becomes mandatory");
        }

        # validate proxy port
        my $fnret = OVH::Bastion::is_valid_port(port => $proxyPort);
        if (!$fnret) {
            return R('ERR_INVALID_PARAMETER', msg => "Proxy port '$proxyPort' is invalid: " . $fnret->msg);
        }
    }

    # now, remap port and user '*' back to undef
    undef $user      if $user eq '*';
    undef $port      if $port eq '*';
    undef $proxyUser if $proxyUser eq '*';

    return R(
        'OK',
        value => {
            user      => $user,
            port      => $port,
            protocol  => $protocol,
            proxyIp   => $proxyIp,
            proxyPort => $proxyPort,
            proxyUser => $proxyUser
        }
    );
}

1;
