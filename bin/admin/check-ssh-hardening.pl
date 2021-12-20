#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;
use Term::ANSIColor;
use IPC::Open2;
use MIME::Base64;
use Getopt::Long;
use File::Temp qw{ tempfile };

my $hideok = 0;

sub ko    ## no critic (RequireArgUnpacking)
{
    print colored("[ERR!] " . $_[0] . "\n", "red");
    return 1;
}

sub ok    ## no critic (RequireArgUnpacking)
{
    $hideok and return 1;
    print colored("[ ok ] " . $_[0] . "\n", "green");
    return 1;
}

sub wrn    ## no critic (RequireArgUnpacking)
{
    print colored("[warn] " . $_[0] . "\n", "yellow");
    return 1;
}

sub inf    ## no critic (RequireArgUnpacking)
{
    print colored("[info] " . $_[0] . "\n", "blue");
    return 1;
}

my $generate_moduli;
GetOptions(
    'hide-ok' => \$hideok,
    'generate-moduli=i', \$generate_moduli
);

my (%h, %d);

# %h contains the sshd configuration for this host
# %d contains the default sshd configuration of this sshd version

my $fh_cmd;
open($fh_cmd, '-|', '/usr/sbin/sshd -T 2>/dev/null') or die($!);
while (<$fh_cmd>) {
    /^(\S+)\s+(.+)$/ and push @{$h{$1}}, $2;
}
if (not keys %h) {

    # newer openssh versions need some context to give their config
    open($fh_cmd, '-|', '/usr/sbin/sshd -T -C user=root -C host=localhost -C addr=localhost 2>/dev/null') or die($!);
    while (<$fh_cmd>) {
        /^(\S+)\s+(.+)$/ and push @{$h{$1}}, $2;
    }
}
close($fh_cmd);
open($fh_cmd, '-|', "/usr/sbin/sshd -T -f /dev/null 2>/dev/null") or die($!);
while (<$fh_cmd>) {
    /^(\S+)\s+(.+)$/ and push @{$d{$1}}, $2;
}
close($fh_cmd);

# hacky way to find out ciphers/kex/macs on old sshd versions
if (not $d{ciphers} or not $d{kexalgorithms} or not $d{macs}) {

    # hacky way
    if (!open($fh_cmd, '-|', "strings /usr/sbin/sshd")) {
        ko "Error trying to get the ciphers/kexs/macs list ($!)";
    }
    else {
        my ($ciphers, $kexalgorithms, $macs);
        while (<$fh_cmd>) {
            /arcfour128,/                       and $ciphers       = $_;
            /mac-sha1,/                         and $macs          = $_;
            /diffie-hellman.*,.*diffie-hellman/ and $kexalgorithms = $_;
        }
        close($fh_cmd);
        chomp($ciphers, $macs, $kexalgorithms);
        $d{ciphers}       or $d{ciphers}[0]       = $ciphers;
        $h{ciphers}       or $h{ciphers}[0]       = $ciphers;
        $d{macs}          or $d{macs}[0]          = $macs;
        $h{macs}          or $h{macs}[0]          = $macs;
        $d{kexalgorithms} or $d{kexalgorithms}[0] = $kexalgorithms;
        $h{kexalgorithms} or $h{kexalgorithms}[0] = $kexalgorithms;
    }
}

my @myciphers = split /,/, $h{ciphers}[0];
my %ciphers   = (
    "3des-cbc"                       => 1,
    "blowfish-cbc"                   => 1,
    "cast128-cbc"                    => 1,
    "arcfour"                        => 1,
    "arcfour128"                     => 1,
    "arcfour256"                     => 1,
    "aes128-cbc"                     => 2,
    "aes192-cbc"                     => 2,
    "aes256-cbc"                     => 2,
    "rijndael-cbc\@lysator.liu.se"   => 2,
    "aes128-ctr"                     => 3,
    "aes192-ctr"                     => 3,
    "aes256-ctr"                     => 3,
    "aes128-gcm\@openssh.com"        => 3,
    "aes256-gcm\@openssh.com"        => 3,
    "chacha20-poly1305\@openssh.com" => 3,
);
my %list;
foreach my $cipher (split /,/, $d{ciphers}[0]) {
    if ($ciphers{$cipher} == 1) {
        push @{$list{((grep { $cipher eq $_ } @myciphers) ? 'weakon' : 'weakoff')}}, $cipher;
    }
    elsif ($ciphers{$cipher} == 2) {
        push @{$list{((grep { $cipher eq $_ } @myciphers) ? 'mediumon' : 'mediumoff')}}, $cipher;
    }
    elsif ($ciphers{$cipher} == 3) {
        push @{$list{((grep { $cipher eq $_ } @myciphers) ? 'highon' : 'highoff')}}, $cipher;
    }
    else { push @{$list{'unknown'}}, $cipher }
}
$list{'weakon'}  and wrn "ciphers: found enabled weak ciphers " . join(',', @{$list{'weakon'}});
$list{'weakoff'} and ok "ciphers: found disabled weak ciphers " . join(',', @{$list{'weakoff'}});
$list{'mediumon'} and ok "ciphers: found enabled medium-grade ciphers " . join(',', @{$list{'mediumon'}});
$list{'mediumoff'} and ok "ciphers: found disabled medium-grade ciphers " . join(',', @{$list{'mediumoff'}});
$list{'highon'} and ok "ciphers: found enabled high-grade ciphers " . join(',', @{$list{'highon'}});
$list{'highoff'} and wrn "ciphers: found disabled high-grade ciphers " . join(',', @{$list{'highoff'}});

my @mymacs = split /,/, $h{macs}[0];
my %macs   = (
    "hmac-sha1"                       => 1,
    "hmac-sha1-96"                    => 1,
    "hmac-sha2-256"                   => 2,
    "hmac-sha2-512"                   => 2,
    "hmac-md5"                        => 1,
    "hmac-md5-96"                     => 1,
    "hmac-ripemd160"                  => 1,
    "hmac-ripemd160\@openssh.com"     => 1,
    "umac-64\@openssh.com"            => 2,
    "umac-128\@openssh.com"           => 2,
    "hmac-sha1-etm\@openssh.com"      => 1,
    "hmac-sha1-96-etm\@openssh.com"   => 1,
    "hmac-sha2-256-etm\@openssh.com"  => 3,
    "hmac-sha2-512-etm\@openssh.com"  => 3,
    "hmac-md5-etm\@openssh.com"       => 1,
    "hmac-md5-96-etm\@openssh.com"    => 1,
    "hmac-ripemd160-etm\@openssh.com" => 2,
    "umac-64-etm\@openssh.com"        => 2,
    "umac-128-etm\@openssh.com"       => 2,
    "hmac-sha2-256-96"                => 2,
    "hmac-sha2-512-96"                => 2
);
%list = ();

foreach my $mac (split /,/, $d{macs}[0]) {
    if (not exists $macs{$mac}) {
        wrn "Unknown mac $mac";
        next;
    }
    if ($macs{$mac} == 1) {
        push @{$list{((grep { $mac eq $_ } @mymacs) ? 'weakon' : 'weakoff')}}, $mac;
    }
    elsif ($macs{$mac} == 2) {
        push @{$list{((grep { $mac eq $_ } @mymacs) ? 'mediumon' : 'mediumoff')}}, $mac;
    }
    elsif ($macs{$mac} == 3) {
        push @{$list{((grep { $mac eq $_ } @mymacs) ? 'highon' : 'highoff')}}, $mac;
    }
    else { push @{$list{'unknown'}}, $mac }
}
$list{'weakon'}  and wrn "macs: found enabled weak MACs " . join(',', @{$list{'weakon'}});
$list{'weakoff'} and ok "macs: found disabled weak MACs " . join(',', @{$list{'weakoff'}});
$list{'mediumon'} and ok "macs: found enabled medium-grade MACs " . join(',', @{$list{'mediumon'}});
$list{'mediumoff'} and ok "macs: found disabled medium-grade MACs " . join(',', @{$list{'mediumoff'}});
$list{'highon'} and ok "macs: found enabled high-grade MACs " . join(',', @{$list{'highon'}});
$list{'highoff'} and wrn "macs: found disabled high-grade MACs " . join(',', @{$list{'highoff'}});

my @mykexs = split /,/, $h{kexalgorithms}[0];
my %kexs   = (
    "diffie-hellman-group1-sha1"           => 1,
    "diffie-hellman-group14-sha1"          => 1,
    "diffie-hellman-group-exchange-sha1"   => 1,
    "diffie-hellman-group-exchange-sha256" => 3,
    "ecdh-sha2-nistp256"                   => 2,
    "ecdh-sha2-nistp384"                   => 2,
    "ecdh-sha2-nistp521"                   => 2,
    "curve25519-sha256\@libssh.org"        => 3,
    "curve25519-sha256"                    => 3,
    "diffie-hellman-group16-sha512"        => 3,
    "diffie-hellman-group18-sha512"        => 3,
    "diffie-hellman-group14-sha256"        => 3,
);
%list = ();

foreach my $kex (split /,/, $d{kexalgorithms}[0]) {
    if (not exists $kexs{$kex}) {
        wrn "Unknown kex $kex";
        next;
    }
    if ($kexs{$kex} == 1) {
        push @{$list{((grep { $kex eq $_ } @mykexs) ? 'weakon' : 'weakoff')}}, $kex;
    }
    elsif ($kexs{$kex} == 2) {
        push @{$list{((grep { $kex eq $_ } @mykexs) ? 'mediumon' : 'mediumoff')}}, $kex;
    }
    elsif ($kexs{$kex} == 3) {
        push @{$list{((grep { $kex eq $_ } @mykexs) ? 'highon' : 'highoff')}}, $kex;
    }
    else { push @{$list{'unknown'}}, $kex }
}
$list{'weakon'}  and wrn "kexs: found enabled weak KEXs " . join(',', @{$list{'weakon'}});
$list{'weakoff'} and ok "kexs: found disabled weak KEXs " . join(',', @{$list{'weakoff'}});
$list{'mediumon'} and ok "kexs: found enabled medium-grade KEXs " . join(',', @{$list{'mediumon'}});
$list{'mediumoff'} and ok "kexs: found disabled medium-grade KEXs " . join(',', @{$list{'mediumoff'}});
$list{'highon'} and ok "kexs: found enabled high-grade KEXs " . join(',', @{$list{'highon'}});
$list{'highoff'} and wrn "kexs: found disabled high-grade KEXs " . join(',', @{$list{'highoff'}});

my $hasecdsa   = 0;
my $hased25519 = 0;
my $hasrsa     = 0;
foreach my $file (@{$h{hostkey}}) {
    if (not -e $file) {
        ko "hostkey: $file defined in config but not found on disk!";
        next;
    }
    if (!open($fh_cmd, '-|', "ssh-keygen -lf $file.pub")) {
        ko "hostkey: $file.pub can't be opened for verification!";
        next;
    }
    my $out = <$fh_cmd>;
    close($fh_cmd);
    chomp $out;
    if (not $out =~ m{^(\d+) .+ \((.+)\)$}) {
        ko "hostkey: $file can't be parsed ($out)";
        next;
    }
    my ($size, $algo) = ($1, $2);    ## no critic (ProhibitCaptureWithoutTest)
    if ($algo eq 'DSA') { ko "hostkey: DSA $size host key found, you should get rid of it" }
    elsif ($algo eq 'RSA') {
        $size >= 4096 and ok "hostkey: RSA $size host key found";
        $size < 4096  and ko "hostkey: RSA $size host key found, this is too small (< 4096)";
        $hasrsa = 1;
    }
    elsif ($algo eq 'ECDSA') {
        ok "hostkey: ECDSA $size host key found";
        $hasecdsa = 1;
    }
    elsif ($algo eq 'ED25519') {
        ok "hostkey: Ed25519 $size host key found";
        $hased25519 = 1;
    }
    else {
        ko "hostkey: Unknown host key found ($file: $out)";
    }
}

if (!$hasecdsa) {
    if (grep { /_ecdsa_/ } @{$d{'hostkey'}}) {
        ok "hostkey: You don't have any ECDSA key, maybe you don't like NIST curves, that's your right!";
    }
    else {
        ok "hostkey: You don't have any ECDSA key (but it's not supported by your SSH)";
    }
}

if (!$hased25519) {
    if (grep { /_ed25519_/ } @{$d{'hostkey'}}) {
        wrn "hostkey: You don't have any Ed25519 key, generate one!";
    }
    else {
        ok "hostkey: You don't have any Ed25519 key (but it's not supported by your SSH)";
    }
}

$hasrsa || wrn "hostkey: You don't have any RSA key, generate one!";

# loading known moduli
my $delimiterseen = 0;
my @xz;
my %knownmoduli;
my %foundmoduli;
open(my $fh_myself, '<', $0) or die $!;
while (<$fh_myself>) {
    chomp;
    $delimiterseen and push @xz, $_;
    $delimiterseen++ if ($_ eq '__MODULI__');
}
close($fh_myself);
my $decoded = decode_base64(join("\n", @xz));
my $pid     = open2(\*CHLD_OUT, \*CHLD_IN, 'unxz', '-c');    #TODO get rid of this call
print CHLD_IN $decoded;
close(CHLD_IN);
my $rawlist;
while (<CHLD_OUT>) {
    $rawlist .= $_;
}
waitpid($pid, 0);
my $child_exit_status = $? >> 8;
if ($child_exit_status != 0) {
    ko "moduli: Error getting list of well known moduli";
}
else {
    foreach (split /\n/, $rawlist) {
        chomp;
        $knownmoduli{$_} = 1;
    }
}

# now moduli stuff
if (!open(my $fh_moduli, '<', "/etc/ssh/moduli")) {
    ko "Couldn't open /etc/ssh/moduli to check it ($!)";
}
else {
    my %moduli;
    my $atleast8191 = 0;
    while (<$fh_moduli>) {
        chomp;
        /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/ or next;    ## no critic (ProhibitUnusedCapture)
        push @{$moduli{$5}}, $1;
        $foundmoduli{$1} = 1;
    }
    close($fh_moduli);
    foreach my $size (sort keys %moduli) {
        my $count   = scalar @{$moduli{$size}};
        my $nbknown = 0;
        foreach my $mod (@{$moduli{$size}}) {
            $nbknown++ if exists $knownmoduli{$mod};
        }
        if    ($size < 2047) { ko "moduli: found $count weak moduli of size $size ($nbknown well-known)" }
        elsif ($size < 4095) { wrn "moduli: found $count medium moduli of size $size ($nbknown well-known)" }
        else                 { ok "moduli: found $count strong moduli of size $size ($nbknown well-known)" }
        $size >= 8191 and $atleast8191++;
    }
    if (not $atleast8191) {
        wrn "moduli: found no moduli of size of at least 8191";
    }
    my $wellknown = 0;
    foreach my $mod (sort keys %foundmoduli) {
        exists $knownmoduli{$mod} and $wellknown++;
    }
    if ($wellknown == 0) {
        ok "moduli: None of your moduli is well-known (searched for " . (scalar keys %knownmoduli) . " well-known moduli), nice!";
    }
    else {
        my $nbmod = scalar keys %foundmoduli;
        wrn "moduli: Found $wellknown/$nbmod well-known moduli in your file ("
          . ($wellknown * 100.0 / $nbmod)
          . "%), looked for "
          . (scalar keys %knownmoduli)
          . " well-known moduli";
    }
}

sub check_config_value {
    my $key      = shift;
    my $default  = shift;
    my $expected = shift;

    my $current_value = $default;
    if (exists $h{lc($key)}) {
        $current_value = $h{lc($key)}[0];
    }
    else {
        if (open(my $fh_config, '<', '/etc/ssh/sshd_config')) {
            while (<$fh_config>) {
                chomp;
                /^\Q$key \E(.+)$/i or next;
                $current_value = $1;
                ok "config(debug): parsed from conf $key as '$current_value'";
                last;
            }
            close($fh_config);
        }
    }

    ref $expected ne 'ARRAY' and $expected = [$expected];
    if (grep { $current_value eq $_ } @$expected) {
        ok "config: $key is set to '$current_value'";
    }
    else {
        wrn "config: $key is set to '$current_value', expected one of: " . join(',', @$expected);
    }

    return 1;
}

check_config_value 'UsePAM',         'no', [qw{ yes 1 }];
check_config_value 'LoginGraceTime', 120,  [(1 .. 120)];
check_config_value 'MaxAuthTries',   6,    [(1 .. 15)];
check_config_value 'IgnoreRHosts', 'no',  'yes';
check_config_value 'StrictModes',  'yes', 'yes';
check_config_value 'PermitRootLogin', 'yes', [qw{ no without-password forbid-password }];
check_config_value 'PermitEmptyPasswords', 'no', 'no';
check_config_value 'PermitTunnel', 'yes', [qw{ 0 no }];
check_config_value 'AllowAgentForwarding', 'yes', 'no';
check_config_value 'AllowTcpForwarding',   'yes', 'no';

# check passwords
foreach (qx{passwd -Sa})    ## no critic (ProhibitBacktickOperators)
{
    /^(\S+)\s+(\S+)/ or next;
    my ($login, $status) = ($1, $2);
    if ($status eq "P") {
        wrn "passwd: account $login has a usable password! maybe run usermod -L $login";
    }
    elsif ($status eq "NP") {
        wrn "passwd: account $login has an empty password!!! set one or run usermod -L $login";
    }
    elsif ($status ne "L") {
        wrn "passwd: account $login has a weird passwd status ($status)";
    }
    elsif ($login eq 'root') {
        ok "password: account $login has a locked password";
    }
}

# get a list of valid shells
my %shells;
if (open(my $fh_shells, '<', '/etc/shells')) {
    while (<$fh_shells>) {
        chomp;
        /^#/ and next;
        $shells{$_} = 1;
    }
    close($fh_shells);
}

# then check for ssh keys on valid shells
if (open(my $fh_passwd, '<', '/etc/passwd')) {
    while (<$fh_passwd>) {
        chomp;
        my @tokens = split /:/;
        my $shell  = $tokens[6];
        next unless exists $shells{$shell};
        my $login = $tokens[0];

        # has a valid shell
        my $home = $tokens[5];
        foreach my $file ("$home/.ssh/authorized_keys", "$home/.ssh/authorized_keys2") {
            next unless -e $file;
            if (open(my $fh_auth, '<', $file)) {
                while (<$fh_auth>) {
                    chomp;
                    /^\s*#/ and next;
                    /^\s*$/ and next;
                    my $short = $_;
                    length($short) > 99 and $short = substr($short, 0, 45) . '...' . substr($short, length($short) - 45);
                    inf "sshkey: login $login has a shell ($shell) and a key: $short";
                }
                close($fh_auth);
            }
        }
    }
    close($fh_passwd);
}

# check umask
my $umaskFound = undef;
if (open(my $fh_login, '<', '/etc/login.defs')) {
    while (<$fh_login>) {
        /^UMASK\s+(.+)/ or next;
        if ($1 ne '027' or not defined $umaskFound) {
            $umaskFound = $1;
        }
    }
    close($fh_login);
    if (not $umaskFound) {
        wrn "umask: no value found, expected 027 in /etc/login.defs";
    }
    elsif ($umaskFound ne '027') {
        wrn "umask: bad value found ($umaskFound), need 027 in /etc/login.defs";
    }
    else {
        ok "umask: expected 027 value found";
    }
}

if (open(my $fh_pam, '<', '/etc/pam.d/common-session')) {
    my $umaskOk = 0;
    while (<$fh_pam>) {
        /^\s*session\s+optional\s+pam_umask\.so\s+umask=0?027/ or next;
        ok "umask: correct umask found in pam.d";
        $umaskOk = 1;
        last;
    }
    close($fh_pam);
    if (not $umaskOk) {
        wrn "umask: no pam.d umask configuration found or bad one";
    }
}

if (defined $generate_moduli and $generate_moduli > 0) {
    my ($fh, $file_unchecked) = tempfile("moduli.unchecked.$generate_moduli.XXXXXX", SUFFIX => '.txt', TMPDIR => 1);
    local $SIG{'INT'} = sub { unlink($file_unchecked); };
    print "Generating candidates of size $generate_moduli...\n";
    system("nice ssh-keygen -G $file_unchecked -b $generate_moduli");
    print "Validating generated candidates of size $generate_moduli...\n";
    system("nice ssh-keygen -T /tmp/moduli.checked.$generate_moduli.pid$$.txt -f $file_unchecked");
    unlink($file_unchecked);
}

__END__

__MODULI__
/Td6WFoAAATm1rRGAgAhARYAAAB0L+Wj4H38EaRdAAUJiSlag5YALZsrn4vX1kL+swvtsDNqbhi5jgRqer9uFoOL/l1RVa2n1UisIBkstmyQX2e0I3/ERtnaY09bixqcdtyodOdXMaBU4xn+59EBJhAKyNi8IYwFkLXs92s4o3
VGs0BSb5HhIv+9KorGOzj/SgZG35nSVlpby5g+GErLTzBQlY4tX9Rfn3Sdvd0U6e3rhHAJuEU9npV7+/rynSZ+8Raob0IgD1DOs39p0S+BLvNF0iwo4cYokP4TJ7/ZiVYApfpuZsDmPQh1IW2gG1aw76Jg7NiJb2GTP5DpZkm+
1PzfVeF+sgB4IIMFplEp87/YEVFVYoutQ4WL7QSsFxZKr6UWkEJ02UE87wc2V/MEmkbFDDQi0qfRdZep7FmdE7DAsqHjUuKQxICnSDfwNvm7ZKwbUvdQZTdOZaTsrK++jRdRUYtCyp67HQ7rkQslbvdC/4E2unplRBFAvFSj6I
Z503HfCO6x0K+akz39ptUmSfaVwM3mjIpQ82qGtL/atu87hB0mT0MwpIkrW8BRwZwV5H21wEfz2A3tSDsQ3/n5OlGtH91yso2IYxHLC0ggd2mCSnjB+u4pUDNRpHxMUqUgv9pyyYAm3OTXT3zDu38EKBXt01WBHUPiLLRgRRb5
1FdpCWMptRV2zrdXJ8e2nugOba5LHdOWHHbvUBkGo8P0a4D8OTw7C9Vag/Ezvp+zW2W5y6B0PLi43UspJT1zU+BxZDoohV0ySdX6AQBZnfmEem84IfUB0m8VFUxplhbMoUPYxWueUH5Eoe3bt4yLFSspdYBxXGLmlyi5v6rORa
5NBmoXoUtUxHgPn/+p6Y2DHzULDB/MBnaLNBM1OJ9h1aftUeYq6SD9+KuaMaocv9EbfESOPj3AuEPX9afUdlNXgeJY5nmAQ0+rneIeB0xjR/lD5+ReUZTuZQgn/NO2a5glz7XRCE/HET082/sOFuFmBDbBkgZz/jKSrhbKJfZp
WAi7Q+GdjHpmiQ1fRmnr0dcuOs1uJ0DqR+fuxjQLWbXerx1qvtJdGwF2cIOpUQfXZrI0I5ZSXosUZoh0roGb7EG1kse4Pu6PU1Q8dZBsCX77keX/aiGnoamyKpwyWaF6VTBZIlNtbHzXNHNd36u2qHtfM5Fg+Vr6z7Y3Kz50E8
H1ALKRjrHX4zHP+AS0KdguYLVTW1urIgFbrd/34e+3k4PY7Kr7A3DFjjCx/T3vAfiB63wGzo8QJ3aEDIfEX6A+XcMEvfxx/qdjJCZoT5/b6phCtIQCxJkxU/6ZcTs3yrRkKskZZO4JE7iB5dZwiPXznB0Zmoow96r7zKQSL4va
6ahcMXHyPMpD0MP/n4rnMm7qxLcrS/TFSMoS4uNalS3HLlmMv40brBlnpZcfbk+iuW8P2xervK8WlzI9Xi43Xy00iZDC/pwPC7pGiGqePawE6AhK46XXWbj/Tujz+wRDw3OqdvTd1sO0grnQd4Rx8dUbgQ9aQk8b2jjTyd2Hhk
/qUVuTjoCwvLq60ZFjPjN4Z5S/TGwbddkOnMOgqRwYUdiQyj2G9HJZjakO3/uW6Ud5VTMbOIH5VYnb4iQCaw/3IpknDrvkWdb3Lj8eibgUUNzYglLrmr6udvhAWw5CQbMhYDgqFVkElnQv04Qji+2NhSsuUMhDxzMkmfvqjNDs
TiSX33KZZC9wgd15yTw68hhcApuxZrdkuwjmaINGgs92T1hE/0NW5ZafpCyijtdWBY7O8fhURGQbxIUBVu718Z9EjXigX1kuPXVmqHspiyJo5T8/o02Q9eoQTeNZIcLHwZediHS0dt0lrZLouDKx2RcWihAoxX99F9xiJ35i6C
EmncZVrHnXDCnWDJPyVRUI4cmYlGcgITGHFOaK9gtoo/IxfmCTCXsreuz+mXjMqlOSMvMYeprFsKiVFdq105HdLMXb2kpyXIj5hWAefggV59EVCcbMJgY8Nh9sOlzRvKoGEfj+9ZdiyqOduxoIAoGUOC52K2v7eIhiG5Z19qiT
QmXmDbPPOVYJcuxUbeyQIBxrHCOukEVxkPuCyffAjEf2oYkyHpH21ngk+roKkOhQJWiGwwUDUxXZp5R7iVhsPk5u0uMIzTrGugRwrHEZGeIKIGwvJ5GbyYTraI0qNYPaK5llz/MpFHdlqAtXG2qfL4tbCr/trrOFgQAC9y117v
8pzVOygwl4wmQVBCMMyI99mGTtnbkwRwRhA4t4GwP+cKXMo4+smRVvAlxVWAV++wCCZTfSu/FQdviVDxAbNPUQoEvAl8KSGWszSDWxnrffwSRafMRA3W3GAJt8ExXpp3jJmYqCINCB3vzX4/LWL6ypsuHPd63mgPS0L2sIR/zE
ChMtv9kTCh/Q/9hk8egcpQX8UG2WaBm+BE7UeuY0nid0y9sUxlPlKJcl2iGbMMOPIyGABZ0OzWXk17ta1CeVCAjXByIkbeoIwwrT/6XzVo4bodrM5iLAMNOiMDBznQj2I/UcWfvRVHraXjPG/b+NQAslEUyZdoSB78U5yv2NMG
eXIdlQ3eeJNJAfHAG4G5wdjJ0qNzdMDyaYhXfWgvkj7A2lYtKDdPwZChm+Q2EblxPN7DR9jUNhw7JhXUNa5ASCTdw0cOzvV1FYyT832us3/FYktRSGUbT+5nbIB+IZA82trUj7Awui6bg1ew0JKPlHsFeDugY6GLQrhtgE3ZDX
XoPcDXEPjTlJ2eR94k2ala0coe61I+0OfQ/Xl9ocicDpSXE97GUqqA/QfyCbDNv/hRd+75Nk+FW1Gkpi2iuy2/vR6BL0daxmAi428JQscKBsEGSjvPn11kmLp0UnHiEPkaTRm4GrrV+07tfOaZnIlKxs0MUFnI4dhJdB2xX0hi
b9FAFMzsP9BiBp6ZwEbjsstX0W3VCeGS3OeVaWlP7DULGE7agS9d9HkKZuw5mS2fmvO0c9HNpGrVoqDp5xfcggLVW744NDMPAkuRWIx1t6Exz1rzpDfZV0MN9PZf5gCg/TzOZcTtagwaITWCM9/J1hrnNueH5WbStDo4DwGpqD
LuWQoQzRdk5mfmzFUHbidczooLsjqiYRK9fwwztT+A0la/yYvMobR4vLoENgyNSCVF1Ei4bPXwL+VawqN6WYK5rK090gyhsDsVgzgNYbkV4urRb2+cDeoHN7o3nvUcj99Cozqv8zjD/30M+x34t/l6jpfrvy/7IJczOOCK82Qu
XvA97fxvLgBmtL1q7KPrb5LackAyRfItPtxZ1aM/vHWtHqsSI+l0BwdsqBeJe6cGWib6jWCEj2CWPC3D+X3fkte1qhHHSvHGFprNq15hRUp5MSYkNpI4OYrRj5hBbYSnTrYizbrIIssfrnF6ynEhGzr12pJCxAbK0PVfvaUkN1
NmMZfgdsk5Zf/nVhsT3UT3mWewNHqAWqG5yQizXhSNOGMAzzVjP/Xy1Uz1t9Al4BPc+LS80/6Q9KGokMx9DS02jqNWuwTJUVqJaoNcbvL8UREzGB8Ndt88QlBvKZdqqn1s9aUSA6e0SQnwwR05KeniCz7HJf2sPo06WrHMt2p9
tm/CAobg3vCP3ZimViSe68KxUM6LqXir/pCAcCklCoJEqhLKzLH/lrEE7IdWlbhgXVf4dENehFNzLwe05yxKX+jWvkEWG0z9C9zsgOTUjxixtoOnpszpgnayyTI3tcSOsPWZJHU88Nx5GM1VHxtFF93EvBJza90hZath/DhhRw
h6hZ8OWtmtIlWVGi/6oerhBF3yJxKB6VCaWyqHyTbiA722ADq+h3/ul99A57Rk1vzN0/neDJb0YWrzk1WofrFY+J44NtO7cArHLd2UKdbbLR1jMYax0wvu5gkdlJh2FCg5oJne0ZRQm+y8ScWyqk4dJbmw152MScHpqVFdrt7d
qWjusb94MRfyqV5ppqb3A5KJ4cdXPs+k30aAxzyMVmZbSGHL3TbwcduxI/aY3UNOxTXE5+Co1m78XdzmDTTg+gi1Udmv9VNl2+r4rn8pbghw6wcZlWyMSeZYKflfqu8jF5kRM0mq3tgF02bmmb8FzsXEC5okJi/iJkuQFzK/y9
y4mGUa1AowA4p2wBtq4xH/Dv0r+yirirSAFSJGppGC5CVxlG4vg+3+M1lutSNunBLfjXPplFdpdzad6lbDuQbBVXK80km8m29OXYt27FF76o3kOjkdb7adbbKZzK3eY8CSGuBZjN6X0DMBM5KcJQOo4XtNeQhZzd3px4V0RqmB
+NyMaC9EcAdFEJZ6K8QJ0S7HSXOfVRMS41TSXkz/L1cPTuRgbb/y/F+ona91ag3u6dNH2Mpw0FQMYg6hrtR8pd2lv0zaWbWNUffl/krQvdzENGKsW6zRsO7z0OM9ZikfQEnEo0RNj0Jn8r4oqWaf1e+BgvIxmSG08JtDZjo0f4
SM7gB/0oTGYzCysqxmdJ6vnv5kbVtm+KszveBB77PNDcj1MGeVG38LM1Hl/h4HkGt+1zDy87lc8jRbA6gcvYqKHv9ls651aV9d6qg23+K4rGgH0mCeEhCySLC06n+/hSwzmU8tOhpp8nSy3lBa6CeHnDYRyKSxPMtVdZD/rS1o
YCVr2BAZU5s2GY0AZgiAhprEpQqkfPmSiMXthV8DXmOb4P10T62GJfqgjsDbjg5LoYS4sl4OvsJ3LC8bCAo2nsqTGrb4CE+zbmn9L3MAnNYKHAnnhK/CZILBaCDalt1pSWiogkEOrtWjNZ/mX/OCDWAF1/kkMDS0trrzlNDQwn
LTLwmkkWBpqzzIiE5UJcMQA35+/gjbvQBjG3t3K5Q48ee44pAYcaVFCm6sCvzjZl5GXpQZv9XCNqXf+PjuEIsnCUodA8tmvV9nY3LyTmLDM2XZ8SmEQ/NbwLbpfM1l25mFLLTbfIXWO7WVEb7gtuHGmqPijGpgZh/Ubhc91+Lp
EgbEGRyJJKsUoPf/cie49oYurfwWwBB3qppPwaCtyRHLKIgJHJZXtf6M97ZpQW69DjbDgileth/6il6GbBxK/vrdQ52McwmLpnW1IhsymO0wq2OLt0tWxBVODaQPDtOKt/P49rKir8DL+3sM0XnjvTiI4XENwxi7qavLqaSNnB
4irzcrI+fEI4RSnZRAsGaPiRlLxism1JsDSzhgoatfXYKVYZvzXFHXpos+uXdTAW4Rb1ymu/TOKDwCKgUTm6i/4RQowPr5Xt4aOgAZS1TGqDCSguOYZDN/dQiVpFhDO8mA0esB5YITcE8ATXzMx40D8wMbJ28HVABotdWYHlY2
2/nmlQq4LeGoFXQHoZD4osxXyqOR46R+IbmjbndwmJl5XSZMJmUSboWdGKIs0D1E+cbtxYBHKLasupXOeEGmSxCF4iYGQjSmHT060e1otJDgv9/QA+imEOA9qiSLd1N3ZPQGeCt8WwV9Qqs90+1y9c3gtJRgaM6pEA7Se3sYzS
gTRKR6SDFN/uQo8MxATwGrC5chJLGH80TZj2v2F4I96Y2Xf20B5HKTNXCExmxw4xQEjZfqhrulblZuipuGD/lRCPAyNUEPMOLdD2veLeWIRLOD+N8i1gaC7jubmmLjkLYKbNKlpBhynwPfGzn2OL76zGXQRksFgdSNAhXmp5A6
o/rimulgO4pbCJ1Dkheu/fjpIUAZfryy+umwDoXwgkrES5++a5YLz4FBzVw9avP7T0ykrK5Bw/Ld1MoXM+rkp5JfHMFhTbicKndVKk5GeJ3WbPhjM1yaP+X/ac0nkQ1oWYXBjmoCbGgFw6O3Zhv5PL7+gtetsCWif4AQkLxQFo
5OoTvtDspWc7IBpQEEAp81St2VbgfSMzGVCWUi+LC/INMBk0z45hjiDqPZXRCJfwdFODahXjDCPkYuHfBaUOlvkwHzZ6pftxJ7tmBB7cYLWhu/3cC39o3eAd3G3xUGoeF8dODsS8yNrX4PS4Vk6kzuvTvgY/KgIAC5Y+IC2P1Q
/8RDaF4VCznj3IG4AiFZgsJv+4UbLzHiYCjqPfHyNxZY3p7E77JknAYXAJXAf/LHQQBsff4rbuYgCScaJ7wLC4zSnVam4rekpBOTH+QS5+LFgqOAAAOphsNU8vQF4AAcAj/fsBALf8WoCxxGf7AgAAAAAEWVo=

