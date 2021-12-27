package OVH::SimpleLog;

# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

# Simple package to log either to a file, to syslog, or to both
# Exports the _log, _warn and _err routines to do so

use base qw (Exporter);
our @EXPORT = qw(_log _warn _err);    ## no critic (ProhibitAutomaticExportation)

use Term::ANSIColor;
use Sys::Syslog qw{};

# Log file handler
my $LOG_FH;

# Syslog
my $FACILITY;

# Program name
my $PROGNAME;

BEGIN {
    # Extract program base name
    $PROGNAME = $0;
    if ($PROGNAME =~ /\/([^\/]+)$/) {
        $PROGNAME = $1;
    }
}

# Set a log file
sub setLogFile {
    my $filename = shift;
    if (not open($LOG_FH, '>>', $filename)) {
        _warn("Unable to open log file '$filename' ($!)");
        return 0;
    }
    return 1;
}

sub setSyslog {

    # if we previously opened syslog, close it
    closeSyslog();

    # then (re)open it with the wanted facility
    $FACILITY = shift;
    Sys::Syslog::openlog($PROGNAME . "[$$]", 'nofatal', $FACILITY);

    return 1;
}

sub closeSyslog {

    Sys::Syslog::closelog() if $FACILITY;
    undef $FACILITY;

    return 1;
}

sub _log  { _display('LOG',  @_); return 1; }    ## no critic (RequireArgUnpacking,ProhibitUnusedPrivateSubroutines)
sub _warn { _display('WARN', @_); return 1; }    ## no critic (RequireArgUnpacking,ProhibitUnusedPrivateSubroutines)
sub _err  { _display('ERR',  @_); return 1; }    ## no critic (RequireArgUnpacking,ProhibitUnusedPrivateSubroutines)

#   Display a message
sub _display {
    my $level   = shift;
    my $message = shift;

    #   Prepare message and possibly color
    my $color   = '';
    my $fullmsg = $message;
    my $OUT     = 'STDOUT';
    if ($level eq 'ERR') {
        $color   = 'red';
        $fullmsg = "ERROR: $message";
        $OUT     = 'STDERR';
    }
    elsif ($level eq 'WARN') {
        $color   = 'yellow';
        $fullmsg = "WARN: $message";
        $OUT     = 'STDERR';
    }

    # If it's not for a terminal, don't colorize log
    # perlcritic doesn't like -t, but IO::Interactive is not in core as per corelist
    $color = '' if not -t $OUT;    ## no critic (ProhibitInteractiveTest)

    my $coloredmsg = $fullmsg;
    $coloredmsg = colored($fullmsg, $color) if $color;
    if ($OUT eq 'STDERR') {
        print STDERR $coloredmsg . "\n";
    }
    else {
        print $coloredmsg. "\n";
    }

    # Print on a log file (if needed)
    if ($LOG_FH) {
        printf $LOG_FH "%s [%6s] %s: %s\n", scalar(localtime()), $level, $PROGNAME, $message;
    }

    # Push to syslog (only if a facility has been defined, which means openlog() has been called)
    if ($FACILITY) {

        $level = lc($level);
        $level = 'info' if (!grep { $level eq $_ } qw{ warn err });
        eval { Sys::Syslog::syslog($level, $fullmsg); };
        if ($@) {
            print STDERR "Couldn't syslog, report to administrator ($@)\n";
        }
    }

    return 1;
}

END {
    close($LOG_FH) if (defined $LOG_FH);
    Sys::Syslog::closelog() if (defined $FACILITY);
}

1;
