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
our @EXPORT = qw( $self );    ## no critic (ProhibitAutomaticExportation)

$| = 1;

#
# This code has to be ran for all helpers so we include it here directly
#

$SIG{'HUP'}  = 'IGNORE';    # continue even when attached terminal is closed (we're called with setsid on supported systems anyway)
$SIG{'PIPE'} = 'IGNORE';    # continue even if osh_info gets a SIGPIPE because there's no longer a terminal
$ENV{'PATH'} = '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:/usr/pkg/bin';
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
