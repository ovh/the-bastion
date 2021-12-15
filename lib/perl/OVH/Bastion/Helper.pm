package OVH::Bastion::Helper;

# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

use File::Basename;
use lib dirname(__FILE__) . '/../../../../lib/perl';
use OVH::Bastion;
use OVH::Result;

# We handle our importer's '$self' var, this is by design.
use Exporter 'import';
our $self;    ## no critic (ProhibitPackageVars)
our @EXPORT = qw( $self HEXIT );    ## no critic (ProhibitAutomaticExportation)

# HEXIT aka "helper exit", used by helper scripts found in helpers/
# Can be used in several ways:
# With an R object: HEXIT(R('OK', value => {}, msg => "okey"))
# Or with 1 value, that will be taken as the R->err: HEXIT('OK')
# Or with 2 values, that will be taken as err, msg: HEXIT('ERR_UNKNOWN', 'Unexpected error')
# With more values, they'll be used as constructor for an R object
sub HEXIT {    ## no critic (ArgUnpacking)
    my $R;

    if (@_ == 1) {
        $R = ref $_[0] eq 'OVH::Result' ? $_[0] : R($_[0]);
    }
    elsif (@_ == 2) {
        my $err = shift || 'OK';
        my $msg = shift;
        $R = R($err, msg => $msg);
    }
    else {
        $R = R(@_);
    }
    OVH::Bastion::json_output($R, force_default => 1);
    exit 0;
}

# Used after Getopt::Long::GetOptions() in each helper, to ensure there are no unparsed/spurious args
sub check_spurious_args {
    if (@ARGV) {
        local $" = ", ";
        warn_syslog("Spurious arguments on command line: @ARGV");
        HEXIT('ERR_BAD_OPTIONS', msg => "Spurious arguments on command line: @ARGV");
    }
}

#
# This code has to be ran for all helpers before they attempt to do anything useful,
# and as we're only use'd by helpers, we include it here directly on top-level.
#

$| = 1;

# Don't let helpers be interrupted too easily
$SIG{'HUP'}  = 'IGNORE';    # continue even when attached terminal is closed (we're called with setsid on supported systems anyway)
$SIG{'PIPE'} = 'IGNORE';    # continue even if osh_info gets a SIGPIPE because there's no longer a terminal

# Ensure the PATH is not tainted, and has sane values
$ENV{'PATH'} = '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:/usr/pkg/bin';

# Build $self from SUDO_USER, as helpers are always run under sudo
($self) = $ENV{'SUDO_USER'} =~ m{^([a-zA-Z0-9._-]+)$};
if (not defined $self) {
    if ($< == 0) {
        $self = 'root';
    }
    else {
        HEXIT('ERR_SUDO_NEEDED', msg => 'This command must be run under sudo');
    }
}

1;
