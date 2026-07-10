#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
#
# Generate a hardened ssh_config or sshd_config from a Text::Template source
# file, adapting its directives to the target OpenSSH version.
#
# Usage:
#   openssh-config-generator.pl --mode sshd --template etc/ssh/sshd_config.tmpl
#   openssh-config-generator.pl --mode ssh  --template etc/ssh/ssh_config.tmpl -o /etc/ssh/ssh_config
#   openssh-config-generator.pl --template etc/ssh/sshd_config.tmpl --version 9.6   # target a version
#   openssh-config-generator.pl --mode sshd --template ... --check                  # validate the output
#
# With --check, the config is validated *before* being written: if validation
# fails, --output is left untouched (and we exit non-zero) so a broken config
# never clobbers the destination. Without --output the config still goes to
# stdout regardless, so the broken result remains visible.
#
# Version thresholds are taken from the OpenSSH release notes:
#   8.5  sntrup761x25519-sha512@openssh.com added (PQC hybrid KEX);
#        PubkeyAcceptedKeyTypes renamed to PubkeyAcceptedAlgorithms
#   8.7  ChallengeResponseAuthentication renamed to KbdInteractiveAuthentication
#   9.9  mlkem768x25519-sha256 added (PQC hybrid KEX), available by default
#  10.3  PerSourcePenalties also penalises unknown-user attempts (on by default)
#  10.4  mldsa44-ed25519 composite PQ signature (host key + pubkey auth); it is
#        experimental/optional, so it is gated on a capability probe (see %caps)
#
# When the target version is the local one (no --version), algorithm lists are
# additionally intersected with `ssh -Q` so we never emit an algorithm the local
# build doesn't actually support (e.g. compile-time disabled).

use strict;
use warnings;
use Getopt::Long qw(:config no_ignore_case bundling);
use Text::Template;
use File::Temp ();

my ($PROGNAME) = ($0 =~ s{.*/([^/]+)$}{$1}r);

sub usage {
    print {*STDERR} <<"EOF";
Usage: $PROGNAME --template FILE [options]
  --template FILE   Text::Template source to render (required)
  --mode MODE       'ssh' or 'sshd' (default: inferred from the template name)
  --version X.Y     target OpenSSH version (default: detected via 'ssh -V');
                    passing this disables binary probing (output is generic)
  --output FILE     write to FILE (default: stdout)
  --check           validate the generated config with the local ssh/sshd;
                    on failure --output is left untouched and we exit non-zero
  --ssh-bin PATH    path to the ssh binary  (default: autodetected)
  --sshd-bin PATH   path to the sshd binary (default: autodetected)
  --help            show this help
EOF
    return;
}

# Run a shell command and capture its output, honouring the caller's context
# (list of lines, or a single string). Redirections are part of $cmd.
sub run_capture {
    my ($cmd) = @_;
    my @out = `$cmd`;      ## no critic (ProhibitBacktickOperators)
    return wantarray ? @out : join('', @out);
}

# Extract a major.minor version pair from an arbitrary string.
sub parse_version {
    my ($string) = @_;
    return $string =~ /(\d+)\.(\d+)/ ? ($1, $2) : ();
}

# Locate a binary among well-known paths, falling back to PATH lookup.
sub find_binary {
    my ($name, @candidates) = @_;
    for my $path (@candidates) {
        return $path if -x $path;
    }
    chomp(my $which = run_capture("command -v $name 2>/dev/null"));
    return $which if $which;
    return;
}

# OpenSSH version as reported by `<binary> -V` (printed on stderr).
sub binary_version {
    my ($binary) = @_;
    return () if !$binary;
    my $out = run_capture("$binary -V 2>&1");
    return parse_version($out);
}

# Set of algorithms the local ssh build supports for a given `ssh -Q` type
# (e.g. 'kex', 'cipher', 'mac'). Returns an empty list if unavailable.
sub query_algorithms {
    my ($ssh, $type) = @_;
    return () if !$ssh;
    my @lines = run_capture("$ssh -Q $type 2>/dev/null");
    chomp @lines;
    return grep { length } @lines;
}

# Probe whether a single config keyword line is understood by the local binary.
# We feed a one-line config to the validator and look specifically for a
# "bad option" complaint naming that keyword: this stays correct even when the
# validator also fails for unrelated reasons (e.g. missing host keys).
sub keyword_supported {
    my ($mode, $binary, $keyword_line) = @_;
    return 0 if !$binary;
    my ($keyword) = split ' ', $keyword_line;
    my ($fh, $path) = File::Temp::tempfile(
        'ssh-probe-XXXXXX',
        TMPDIR => 1,
        SUFFIX => '.conf'
    );
    print {$fh} "$keyword_line\n";
    close $fh;
    my $cmd =
      $mode eq 'sshd'
      ? qq{$binary -t -f "$path" 2>&1}
      : qq{$binary -G -F "$path" bastion-keyword-probe.invalid 2>&1};
    my $out = run_capture($cmd);
    unlink $path;
    return $out =~ /(?:Bad configuration option|Unsupported option):?\s*\Q$keyword\E/i
      ? 0
      : 1;
}

# --- arguments ---------------------------------------------------------------

my %opt = (check => 0);
GetOptions(
    'mode=s'     => \$opt{mode},
    'template=s' => \$opt{template},
    'version=s'  => \$opt{version},
    'output|o=s' => \$opt{output},
    'check'      => \$opt{check},
    'ssh-bin=s'  => \$opt{ssh_bin},
    'sshd-bin=s' => \$opt{sshd_bin},
    'help'       => \$opt{help},
) or do { usage(); exit 1; };

if ($opt{help}) { usage(); exit 0; }

if (!defined $opt{template}) {
    print {*STDERR} "$PROGNAME: --template is required\n";
    usage();
    exit 1;
}
if (!-r $opt{template}) {
    die "$PROGNAME: cannot read template '$opt{template}'\n";
}

# Infer the mode from the template name when not given explicitly.
if (!defined $opt{mode}) {
    $opt{mode} = $opt{template} =~ /sshd/ ? 'sshd' : 'ssh';
}
if ($opt{mode} ne 'ssh' && $opt{mode} ne 'sshd') {
    die "$PROGNAME: --mode must be 'ssh' or 'sshd' (got '$opt{mode}')\n";
}

# --- locate binaries & determine the target version -------------------------

my $ssh = $opt{ssh_bin}
  || find_binary('ssh', qw(/usr/bin/ssh /usr/local/bin/ssh /bin/ssh));
my $sshd = $opt{sshd_bin}
  || find_binary('sshd', qw(/usr/sbin/sshd /sbin/sshd /usr/local/sbin/sshd));

my ($maj, $min);
if (defined $opt{version}) {
    ($maj, $min) = parse_version($opt{version})
      or die "$PROGNAME: could not parse a version from '$opt{version}'\n";
}
else {
    ($maj, $min) = binary_version($ssh);
    ($maj, $min) = binary_version($sshd) if !defined $maj;
    defined $maj
      or die "$PROGNAME: could not determine the OpenSSH version (pass --version)\n";
}
my $verstr = "$maj.$min";
my $ver    = $maj * 100 + $min;    # 9.6 -> 906; an integer that compares cleanly

# We only probe/query the local binaries when generating for the local version;
# with an explicit --version the target may differ from what is installed here.
my $probing = !defined $opt{version};

# --- capabilities exposed to the template -----------------------------------

# Algorithm-list filter: keep only what `ssh -Q TYPE` reports as supported,
# preserving our preference order. If -Q for this TYPE is unavailable or
# empty, or would empty the list, return the candidates unchanged.
my %algo_cache;
my $filter = sub {
    my ($type, @candidates) = @_;
    return @candidates if !$probing || !$ssh;
    $algo_cache{$type} ||= {map { $_ => 1 } query_algorithms($ssh, $type)};
    my $supported = $algo_cache{$type};
    return @candidates if !%{$supported};
    my @kept = grep { $supported->{$_} } @candidates;
    return @kept ? @kept : @candidates;
};

# Distro-patch-only keywords: gate on an actual probe of the local binary.
# Without probing (explicit --version) we omit them, which is the safe default
# since an unknown keyword breaks ssh/sshd entirely.
my %caps;
if ($probing) {
    if ($opt{mode} eq 'sshd') {
        $caps{DebianBanner}      = keyword_supported('sshd', $sshd, 'DebianBanner no');
        $caps{GSSAPIKeyExchange} = keyword_supported('sshd', $sshd, 'GSSAPIKeyExchange no');
    }
    else {
        $caps{GSSAPIKeyExchange} = keyword_supported('ssh', $ssh, 'GSSAPIKeyExchange no');
    }

    # The 10.4 composite post-quantum signature (mldsa44-ed25519) is
    # experimental and may not be compiled into a given build. The template
    # uses it as a host key and as an accepted pubkey algorithm; naming an
    # algorithm the build doesn't know makes sshd/ssh refuse to start, so -- as
    # with the distro-patch keywords above -- we only enable it when the local
    # binary actually advertises it, and leave it off in generic (--version)
    # mode where we cannot probe.
    my %known_sig = map { $_ => 1 } (query_algorithms($ssh, 'key'), query_algorithms($ssh, 'PubkeyAcceptedAlgorithms'));
    $caps{mldsa44_ed25519} = $known_sig{'mldsa44-ed25519'} ? 1 : 0;
}

# --- render ------------------------------------------------------------------

my $template = Text::Template->new(
    TYPE       => 'FILE',
    SOURCE     => $opt{template},
    DELIMITERS => ['{', '}'],
) or die "$PROGNAME: template construction failed: $Text::Template::ERROR\n";

my $broken = sub {
    my %args = @_;
    die "$PROGNAME: template error near '$args{text}': $args{error}";
};

my $config = $template->fill_in(
    HASH => {
        ver    => \$ver,
        verstr => \$verstr,
        filter => \$filter,
        caps   => \%caps,
    },
    BROKEN => $broken,
);
defined $config
  or die "$PROGNAME: template fill-in failed: $Text::Template::ERROR\n";

# --- optional validation -----------------------------------------------------

# Validate before writing: with --check, a failed validation must not clobber
# the destination file. We still emit to stdout (when no --output) so the broken
# result stays visible to the caller.
my $check_ok = $opt{check} ? check_config($config) : 1;

# --- output ------------------------------------------------------------------

if (defined $opt{output}) {
    if (!$check_ok) {
        warn "$PROGNAME: --check failed; leaving '$opt{output}' untouched.\n";
    }
    else {
        open my $ofh, '>', $opt{output}
          or die "$PROGNAME: cannot write '$opt{output}': $!\n";
        print {$ofh} $config;
        close $ofh or die "$PROGNAME: error closing '$opt{output}': $!\n";
    }
}
else {
    print $config;
}

exit 1 if !$check_ok;

# Validate the generated config with the local ssh/sshd, but only when the local
# binary is at least as recent as the target (an older binary would reject newer
# directives and report false errors). Returns true when the config is valid (or
# validation had to be skipped), false only on a genuine config-syntax error.
sub check_config {
    my ($cfg) = @_;
    my $binary = $opt{mode} eq 'sshd' ? $sshd : $ssh;
    if (!$binary) {
        warn "$PROGNAME: --check: no $opt{mode} binary found; skipping validation.\n";
        return 1;
    }
    my ($lmaj, $lmin) = binary_version($binary);
    my $lver = defined $lmaj ? $lmaj * 100 + $lmin : 0;
    if ($lver < $ver) {
        warn "$PROGNAME: --check: local $opt{mode} is older than the target $verstr; " . "skipping validation.\n";
        return 1;
    }
    my ($fh, $path) = File::Temp::tempfile(
        'ssh-check-XXXXXX',
        TMPDIR => 1,
        SUFFIX => '.conf'
    );
    print {$fh} $cfg;
    close $fh;
    my $cmd =
      $opt{mode} eq 'sshd'
      ? qq{$binary -t -f "$path" 2>&1}
      : qq{$binary -G -F "$path" bastion-config-check.invalid 2>&1};
    my $out = run_capture($cmd);
    my $rc  = $? >> 8;
    unlink $path;

    if ($rc == 0) {
        warn "$PROGNAME: --check: validation passed with local $opt{mode}.\n";
        return 1;
    }

    # A non-zero exit isn't necessarily a config problem: `sshd -t` also fails
    # when host keys are missing (common in build/test environments). Real
    # config-syntax errors reference the config file by path; keep only those.
    my @cfg_errors = grep { /\Q$path\E/ } split /\n/, $out;
    if (!@cfg_errors) {
        warn "$PROGNAME: --check: config syntax OK with local $opt{mode} "
          . "(ignored unrelated errors, e.g. missing host keys).\n";
        return 1;
    }
    warn "$PROGNAME: --check: validation FAILED (exit $rc):\n" . join("\n", @cfg_errors) . "\n";
    return 0;
}
