package OVH::Bastion::Plugin::otherProtocol;

# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

use File::Basename;
use lib dirname(__FILE__) . '/../../../../../lib/perl';
use OVH::Result;
use OVH::Bastion;

# used by scp, sftp, rsync
# we need to verify that the account has access to the tuple (user@host:port),
# and also that, using the same access way (the same egress ssh keys), that they are granted
# for this host:port using another protocol than ssh (scp, sftp, rsync)
# this requirement will be lifted once we add the "protocol type" to the whole access tuple data model
# while we're at it, return whether we found that this access requires MFA
sub has_protocol_access {
    my %params   = @_;
    my $account  = $params{'account'};
    my $user     = $params{'user'};
    my $ipfrom   = $params{'ipfrom'} || $ENV{'OSH_IP_FROM'};
    my $ip       = $params{'ip'};
    my $port     = $params{'port'};
    my $protocol = $params{'protocol'};

    if (!$account || !$ipfrom || !$ip || !$protocol || !$user || !$port) {
        return R('ERR_MISSING_PARAMETERS', msg => "Missing mandatory parameters for has_protocol_access");
    }

    my $machine = "$user\@$ip:$port";

    my %keys;
    osh_debug("Checking access 1/2 of $account to $machine...");
    my $fnret = OVH::Bastion::is_access_granted(
        account => $account,
        user    => $user,
        ipfrom  => $ipfrom,
        ip      => $ip,
        port    => $port,
        details => 1
    );

    if (not $fnret) {
        return R('KO_ACCESS_DENIED', msg => "Sorry, but you don't have access to $machine");
    }

    # get the keys we would try
    foreach my $access (@{$fnret->value || []}) {
        foreach my $key (@{$access->{'sortedKeys'} || []}) {
            my $keyfile = $access->{'keys'}{$key}{'fullpath'};
            $keys{$keyfile}++ if -r $keyfile;
            osh_debug("Checking access 1/2 keyfile: $keyfile");
        }
    }

    osh_debug("Checking access 2/2 of !$protocol to $user of $machine...");
    $fnret = OVH::Bastion::is_access_granted(
        account        => $account,
        user           => "!$protocol",
        ipfrom         => $ipfrom,
        ip             => $ip,
        port           => $port,
        exactUserMatch => 1,
        details        => 1
    );
    if (not $fnret) {
        return R('KO_ACCESS_DENIED',
            msg => "Sorry, you have ssh access to $machine, but you need to be granted specifically for $protocol");
    }

    # get the keys we would try, along with an eventual mfaRequired flag
    my $mfaRequired;
    foreach my $access (@{$fnret->value || []}) {
        foreach my $key (@{$access->{'sortedKeys'} || []}) {
            my $keyfile = $access->{'keys'}{$key}{'fullpath'};
            $keys{$keyfile}++ if -r $keyfile;
            osh_debug("Checking access 2/2 keyfile: $keyfile");
        }
        if ($access->{'mfaRequired'} && $access->{'mfaRequired'} ne 'none') {
            $mfaRequired = $access->{'mfaRequired'};
        }
    }

    # only use the key if it has been seen in both allow_deny() calls, this is to avoid
    # a security bypass where a user would have group access to a server, but not to the
    # !$protocol special user, and they would add themselves this access through selfAddPrivateAccess.
    # in that case both allow_deny would return OK, but with different keys.
    # we'll only use the keys that matched BOTH calls.
    my @validKeys;
    foreach my $keyfile (keys %keys) {
        next unless $keys{$keyfile} == 2;
        push @validKeys, $keyfile;
    }

    if (!@validKeys) {
        return R('KO_ACCESS_DENIED',
            msg =>
              "Sorry, you have access through ssh and $protocol but by different and distinct means (distinct keys)."
              . " The intersection between your rights for ssh and for $protocol needs to be at least one.");
    }

    return R('OK', value => {keys => \@validKeys, machine => $machine, mfaRequired => $mfaRequired});
}

1;
