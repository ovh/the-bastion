package OVH::Bastion::Helper;

# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

use Fcntl       qw{ :flock :mode };
use Time::HiRes qw{ usleep };

use File::Basename;
use lib dirname(__FILE__) . '/../../../../lib/perl';
use OVH::Bastion;
use OVH::Result;

# We handle our importer's '$self' var, this is by design.
use Exporter 'import';
our $self;                          ## no critic (ProhibitPackageVars)
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

sub get_lock_fh {
    my %params   = @_;
    my $category = $params{'category'};

    return R('ERR_MISSING_PARAMETER', msg => "Missing category in get_lock_fh") if !$category;

    my $lockdirPerm = 0700;
    my $lockfileSharedAll = 0;
    my ($lockdir, $lockfile, $lockdircreate);
    if ($category eq 'passwd') {
        $lockdir       = "/tmp/bastion.lock.passwd";
        $lockfile      = "$lockdir/lock";
        $lockdircreate = 1;
    }
    elsif ($category eq 'groupacl') {
        $lockdir       = $params{'basepath'};
        $lockdircreate = 0;                     # must already exist
        if (!$lockdir || !-d $lockdir || !-w $lockdir) {
            return R('ERR_INVALID_PARAMETER',
                msg => "Missing or invalid basepath '" . ($lockdir // '<u>') . "' in get_lock_fh");
        }
        # we use the .db suffix because it's already excluded from the cluster sync:
        $lockfile = "$lockdir/lock.db";
    }
    elsif ($category eq 'portallocation') {
        # Global lock for local port allocations used by the port forwarding feature
        $lockdir       = "/tmp/bastion.lock.portallocation";
        $lockfile      = "$lockdir/lock";
        $lockdircreate = 1;
        $lockdirPerm   = 0755; # allowkeeper and group-aclkeeper must be able to read it
        $lockfileSharedAll = 1;
    }
    else {
        return R('ERR_INVALID_PARAMETER', msg => "Unknown category '$category' in get_lock_fh");
    }

    my $fh;

    if ($lockdircreate) {
        # to avoid symlink attacks, we first create a subdir only accessible by root
        unlink $lockdir;    # will silently fail if doesn't exist or is not a file
        mkdir $lockdir;     # will silently fail if we lost the race
        chown 0, 0, $lockdir;
        chmod $lockdirPerm, $lockdir;

        # now, check if we do have a directory, or if we lost the race
        if (!-d $lockdir) {
            warn_syslog("Couldn't create $lockdir: are we being raced against?");
            return R('ERR_CANNOT_LOCK', msg => "Couldn't create lock file, please retry");
        }
        # here, $lockdir is guaranteed to be a directory, check its perms
        my @perms = stat($lockdir);
        
        if ($lockfileSharedAll) {
            # For shared locks, only check the file mode, not ownership
            if (S_IMODE($perms[2]) != $lockdirPerm) {
                warn_syslog("The $lockdir directory has invalid perms: are we being raced against? mode="
                      . sprintf("%04o", S_IMODE($perms[2])));
                return R('ERR_CANNOT_LOCK', msg => "Couldn't create lock file, please retry");
            }
        }
        else {
            # For non-shared locks, check ownership and mode
            if ($perms[4] != $< || $perms[5] != $( || S_IMODE($perms[2]) != $lockdirPerm) {
                warn_syslog("The $lockdir directory has invalid perms: are we being raced against? mode="
                      . sprintf("%04o", S_IMODE($perms[2])));
                return R('ERR_CANNOT_LOCK', msg => "Couldn't create lock file, please retry");
            }
        }
    }

    # here, $lockdir is guaranteed to be owned only by us. but rogue files
    # might have appeared in it after the mkdir and before the chown/chmod,
    # so check for the lockfile existence. if it does exist, it must be a normal
    # file and not a symlink or any other file type. Note that we don't have
    # a TOCTTOU problem here because no rogue user can no longer create files
    # in $lockdir, as we checked just above.
    if (-l $lockfile || -e !-f $lockfile) {
        warn_syslog("The $lockfile file exists but is not a file, unlinking it and bailing out");
        unlink($lockfile);
        # don't give too much info to the caller
        return R('ERR_CANNOT_LOCK', msg => "Couldn't create lock file, please retry");
    }

    if (!open($fh, '>>', $lockfile)) {
        return R('ERR_CANNOT_LOCK', msg => "Couldn't create lock file, please retry");
    }

    if ($lockfileSharedAll) {
        chmod 0777, $lockfile;
    }

    return R('OK', value => $fh);
}

sub acquire_lock {
    my $fh = shift;
    return R('ERR_INVALID_PARAMETER', msg => "Invalid filehandle") if !$fh;

    # try to lock for at most 60 seconds
    my $limit = time() + 60;
    my $locked;
    my $first = 1;
    while (!($locked = flock($fh, LOCK_EX | LOCK_NB)) && time() < $limit) {
        usleep(rand(200_000) + 100_000);    # sleep for 100-300ms
        OVH::Bastion::osh_info("Acquiring lock, this may take a few seconds...") if $first;
        $first = 0;
    }
    return R('OK') if $locked;
    return R('KO_LOCK_FAILED', msg => "Couldn't acquire lock in a reasonable amount of time, please retry later");
}

1;
