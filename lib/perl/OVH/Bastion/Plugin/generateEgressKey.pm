package OVH::Bastion::Plugin::generateEgressKey;

# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

use File::Basename;
use lib dirname(__FILE__) . '/../../../../../lib/perl';
use OVH::Result;
use OVH::Bastion;
use OVH::Bastion::Plugin qw{ :DEFAULT };

sub help {
    require Term::ANSIColor;
    my $fnret        = OVH::Bastion::get_supported_ssh_algorithms_list(way => 'egress');
    my @algoList     = @{$fnret->value};
    my $algos        = Term::ANSIColor::colored(uc join(' ', @algoList), 'green');
    my $helpAlgoSize = '--algo rsa --size 4096';
    if (grep { $_ eq 'ecdsa' } @algoList) {
        $helpAlgoSize = '--algo ecdsa --size 521';
    }
    if (grep { $_ eq 'ed25519' } @algoList) {
        $helpAlgoSize = '--algo ed25519';
    }
    osh_info <<"EOF";
Create a new public + private key pair. The private key will stay on this bastion.

Usage: --osh $scriptName $helpAlgoSize [--encrypted]

  --algo ALGO  Specifies the algo of the key, either rsa, ecdsa or ed25519.

  --size SIZE  Specifies the size of the key to be generated.
               For RSA, choose between 2048 and 8192 (4096 is good).
               For ECDSA, choose either 256, 384 or 521.
               For ED25519, size is always 256.

  --encrypted  if specified, a passphrase will be prompted for the new key

With the policy and SSH version on this bastion,
the following algorithms are supported: $algos

algo    size  strength   speed    compatibility
------- ----  ---------- -------- -----------------------
RSA     4096  good       slow     works everywhere
ECDSA    521  strong     fast     debian7+ (OpenSSH 5.7+)
ED25519  256  verystrong veryfast debian8+ (OpenSSH 6.5+)
EOF
    return 0;
}

sub ask_passphrase {
    require Term::ReadKey;
    print "Please enter a passphrase for the private key that'll stay on the bastion (not echoed): ";
    Term::ReadKey::ReadMode('noecho');
    chomp(my $pass1 = <STDIN>);
    if (length($pass1) < 5) {

        # ssh-keygen will refuse
        print "\n";
        return R('ERR_PASSPHRASE_TOO_SHORT', msg => "Passphrase needs to be at least 5 chars");
    }
    print "\nPlease enter it again: ";
    chomp(my $pass2 = <STDIN>);
    print "\n";
    Term::ReadKey::ReadMode('restore');
    if ($pass1 ne $pass2) {
        return R('ERR_PASSPHRASE_MISMATCH', msg => "Passphrases don't match, please try again");
    }
    return R('OK', value => $pass1);
}

sub preconditions {
    my %params = @_;
    my $fnret;

    my ($self, $group, $algo, $size, $account, $sudo, $context) = @params{qw{  self   group   algo   size   account   sudo   context}};

    if (!$algo || !$context) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing argument algo[$algo] or context[$context]");
    }

    if (!grep { $context eq $_ } qw{ group account }) {
        return R('ERR_INVALID_PARAMETER', msg => "Type should be group or account");
    }

    # check whether algo is supported by system
    $fnret = OVH::Bastion::is_allowed_algo_and_size(algo => $algo, size => $size, way => 'egress');
    $fnret or return $fnret;
    ($algo, $size) = @{$fnret->value}{qw{ algo size }};    # untaint

    # check preconditions if we're generating a key for a group
    if ($context eq 'group') {
        if (!$group || !$self) {
            return R('ERR_MISSING_PARAMETER', msg => "Missing 'group' or 'self' parameter");
        }
        $fnret = OVH::Bastion::is_valid_group_and_existing(group => $group, groupType => 'key');
        $fnret or return $fnret;
        my $keyhome    = $fnret->value->{'keyhome'};
        my $shortGroup = $fnret->value->{'shortGroup'};
        $group = $fnret->value->{'group'};

        $fnret = OVH::Bastion::is_group_owner(group => $shortGroup, account => $self, superowner => 1, sudo => $sudo);
        if (!$fnret) {
            return R('ERR_NOT_GROUP_OWNER', msg => "Sorry, you're not an owner of group $shortGroup, which is needed to manage its egress keys ($fnret)");
        }

        return R('OK', value => {group => $group, shortGroup => $shortGroup, keyhome => $keyhome, algo => $algo, size => $size, context => $context});
    }
    elsif ($context eq 'account') {
        if (!$account) {
            return R('ERR_MISSING_PARAMETER', msg => "Missing 'group' parameter");
        }
        $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $account);
        $fnret or return $fnret;

        return R('OK', value => {algo => $algo, size => $size, context => $context});
    }
    else {
        return R('ERR_INTERNAL');
    }
}

1;
