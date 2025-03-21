#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use strict;
use warnings;
use 5.026;

use File::Temp;
use File::Find;
use File::Path;
use File::Copy 'move';
use Getopt::Long;
use Fcntl qw{ :flock };
use IPC::Open3;

use File::Basename;
use lib dirname(__FILE__) . '/../../lib/perl';

use OVH::Bastion;
use OVH::SimpleLog;

my %config;
my ($dryRun, $configTest, $forceDelete, $forceEncrypt, $noDelete, $encryptOnly, $rsyncOnly, $verbose, $help);
$verbose = 0;
local $| = 1;

sub is_new_gpg {
    state $cached_response;
    return $cached_response if defined $cached_response;

    open(my $stdout, "-|", qw{ gpg --dump-options }) or die "is gnupg installed? ($!)";
    $cached_response = 0;
    while (<$stdout>) {
        $cached_response = 1 if /--pinentry-mode/;
    }
    close($stdout);

    return $cached_response;
}

sub gpg_sign {
    my %params = @_;
    my @cmd    = qw{ gpg --batch --trust-model always --sign --passphrase-fd 0 };
    push @cmd, qw{ --pinentry-mode loopback } if is_new_gpg();
    push @cmd, "-v"                           if $verbose >= 2;
    push @cmd, '--local-user', $params{'signkey'}, '--output', '-', $params{'infile'};

    my $outfile;
    if (!open($outfile, '>', $params{'outfile'})) {
        _err "Failed to open output file: $!";
        return 1;
    }

    my ($pid, $in, $out);
    eval { $pid = open3($in, $out, '>&STDERR', @cmd); };
    if ($@) {
        _err "Failed to run gpg_sign(): $!";
        return 1;
    }
    print {$in} $config{'signing_key_passphrase'};
    close($in);

    while (<$out>) {
        print {$outfile} $out;
    }

    waitpid($pid, 0);
    close($out);
    close($outfile);

    return 0;    # success
}

sub gpg_encrypt {
    my %params = @_;
    my @cmd    = qw{ gpg --batch --yes --trust-model always --encrypt };
    if ($params{'signkey'}) {
        push @cmd, qw{ --passphrase-fd 0 };
        push @cmd, qw{ --pinentry-mode loopback } if is_new_gpg();
        push @cmd, '--local-user', $params{'signkey'};
    }
    push @cmd, "-v" if $verbose >= 2;
    foreach my $recipient (@{$params{'recipients'}}) {
        push @cmd, "-r", $recipient;
    }

    push @cmd, '--output', $params{'outfile'};
    push @cmd, $params{'infile'};

    my ($pid, $infh);
    eval { $pid = open3($infh, '>&STDOUT', '>&STDERR', @cmd); };
    if ($@) {
        _err "Failed to run gpg_sign(): $!";
        return 1;
    }
    if ($params{'signkey'}) {
        print {$infh} $config{'signing_key_passphrase'};
    }
    close($infh);

    # ensure gpg is done
    waitpid($pid, 0);

    return 0;    # success
}

sub config_load_and_lint {
    my $fnret;

    # Useful when erroring before we had a chance to actually read the config,
    # and the configured syslog_facility value. This will be overridden below once we
    # know what the user configured.
    OVH::SimpleLog::setSyslog('local6');

    # we can have CONFIGDIR/osh-encrypt-rsync.conf
    # but also CONFIGDIR/osh-encrypt-rsync.conf.d/*
    # later files override the previous ones, item by item
    my @configfilelist;
    if (-f -r OVH::Bastion::main_configuration_directory() . "/osh-encrypt-rsync.conf") {
        push @configfilelist, OVH::Bastion::main_configuration_directory() . "/osh-encrypt-rsync.conf";
    }

    if (-d -x OVH::Bastion::main_configuration_directory() . "/osh-encrypt-rsync.conf.d") {
        if (opendir(my $dh, OVH::Bastion::main_configuration_directory() . "/osh-encrypt-rsync.conf.d")) {
            my @subfiles = map { OVH::Bastion::main_configuration_directory() . "/osh-encrypt-rsync.conf.d/" . $_ }
              grep { /\.conf$/ } readdir($dh);
            closedir($dh);
            push @configfilelist, sort @subfiles;
        }
    }

    # no config file, fail early
    if (not @configfilelist) {
        _err "Error, no config file found!";
        return 1;
    }

    # load config files in order
    foreach my $configfile (@configfilelist) {
        _log "Configuration: loading configfile $configfile...";
        $fnret = OVH::Bastion::load_configuration_file(
            file     => $configfile,
            rootonly => 1,
        );
        if (not $fnret) {
            _err "Error while loading configuration from $configfile, aborting (" . $fnret->msg . ")";
            return 1;
        }
        foreach my $key (keys %{$fnret->value}) {
            $config{$key} = $fnret->value->{$key};
        }

        # we'll be using our own config file as a handy flock() backend
        $config{'lockfile'} = $configfile if not defined $config{'lockfile'};
    }

    # set logging info as soon as we can, before vetting the rest of the config
    $config{'syslog_facility'} //= 'local6';
    if ($config{'syslog_facility'}) {
        OVH::SimpleLog::setSyslog($config{'syslog_facility'});
    }
    else {
        OVH::SimpleLog::closeSyslog();
    }
    OVH::SimpleLog::setLogFile($config{'logfile'}) if $config{'logfile'};

    # normalize / define defaults / quick checks
    if (not exists $config{'recipients'}) {
        _err "config error: recipients must be defined";
        return 1;
    }
    if (ref $config{'recipients'} ne 'ARRAY') {
        _err "config error: recipients must be an array of array of GPG key IDs! (layer 1)";
        return 1;
    }
    if (my @intruders = grep { ref $config{'recipients'}[$_] ne 'ARRAY' } 0 .. $#{$config{'recipients'}}) {
        local $" = ', ';
        _err "config error: recipients must be an array of array of GPG key IDs! (layer 2, indexes @intruders)";
        return 1;
    }

    $config{'encrypt_and_move_to_directory'} //= '/home/.encrypt';

    # new config option found
    if (defined $config{'encrypt_and_move_ttyrec_delay_days'}) {

        # check proper syntax
        if ($config{'encrypt_and_move_ttyrec_delay_days'} !~ /^(?:\d+|-1)$/) {
            _err "config error: encrypt_and_move_ttyrec_delay_days is not a positive integer nor -1!";
            return 1;
        }

        # syntax is good but we also have the deprecated name, warn and proceed
        if (defined $config{'encrypt_and_move_delay_days'}) {
            _warn "config: deprecated option 'encrypt_and_move_delay_days' exists, but has been ignored as "
              . "we also have the new option 'encrypt_and_move_ttyrec_delay_days' in the configuration";
        }
    }

    # new config option not found
    else {
        # do we have the legacy option name ?
        if (defined $config{'encrypt_and_move_delay_days'}) {

            # yes, check proper syntax
            if ($config{'encrypt_and_move_delay_days'} !~ /^(?:\d+|-1)$/) {
                _err "config error: encrypt_and_move_delay_days is not an integer >= -1!";
                return 1;
            }
            else {
                # syntax ok, save it to the new name
                $config{'encrypt_and_move_ttyrec_delay_days'} = delete $config{'encrypt_and_move_delay_days'};
            }
        }
    }

    foreach my $key (qw{ encrypt_and_move_user_logs_delay_days encrypt_and_move_user_sqlites_delay_days }) {
        $config{$key} //= 31;
        if ($config{$key} !~ /^(?:\d+|-1)$/) {
            _err "config error: $key is not an integer >= -1!";
            return 1;
        }
    }

    $config{'rsync_delay_before_remove_days'} //= 0;
    if ($config{'rsync_delay_before_remove_days'} !~ /^(?:\d+|-1)$/) {
        _err "config error: rsync_delay_before_remove_days is not an integer >= -1!";
        return 1;
    }

    $config{'rsync_destination'} //= '';
    $config{'rsync_rsh'}         //= '';
    $config{'verbose'}           //= 0;

    if ($config{'verbose'} !~ /^\d+$/) {
        _warn "config error: verbose is not an integer >= 0, defaulting to 0";
        $config{'verbose'} = 0;
    }

    # if $verbose is 0, then no cmdline override has been done, so we use the config value:
    $verbose ||= $config{'verbose'};

    # ensure the various config files defined all the keywords we need
    foreach my $keyword (qw{ signing_key signing_key_passphrase }) {
        next if defined $config{$keyword};
        _err "Missing mandatory configuration item '$keyword', aborting";
        return 1;
    }

    _log "Config successfully loaded.";

    if ($verbose) {
        require Data::Dumper;
        local $Data::Dumper::Sortkeys = 1;
        local $Data::Dumper::Terse    = 1;

        # hide passphrase
        my $passphrase = $config{'signing_key_passphrase'};
        $config{'signing_key_passphrase'} = '***REDACTED***';
        print Data::Dumper::Dumper({config => \%config});
        $config{'signing_key_passphrase'} = $passphrase;
    }

    return 0;
}

sub config_test {
    my $error;

    # check if my gpg conf is good
    my $infile = File::Temp->new(UNLINK => 1, TMPDIR => 1);
    print {$infile} time();
    close($infile);

    _log "Testing signature with key $config{'signing_key'}... ";
    my $outfile = File::Temp->new(UNLINK => 1, TMPDIR => 1);

    # first, check we can sign
    $error = gpg_sign(
        infile     => $infile,
        outfile    => $outfile,
        signkey    => $config{'signing_key'},
        passphrase => $config{'signing_key_passphrase'}
    );
    if ($error) {
        _err "Couldn't sign with the specified key $config{'signing_key'}, check your configuration";
        return 1;
    }
    if (!-s $outfile) {
        _err
          "Couldn't sign with the specified key $config{'signing_key'} (output file is empty), check your configuration";
        return 1;
    }

    my %recipients_uniq;
    foreach my $recipient_list (@{$config{'recipients'}}) {
        foreach my $recipient (@$recipient_list) {
            $recipients_uniq{$recipient}++;
        }
    }

    foreach my $recipient (keys %recipients_uniq) {
        _log "Testing encryption for recipient $recipient... ";

        # then, check we can encrypt to each of the recipients
        $outfile = File::Temp->new(UNLINK => 1, TMPDIR => 1);
        $error   = gpg_encrypt(
            infile     => $infile,
            outfile    => $outfile,
            recipients => [$recipient]
        );
        if ($error) {
            _err "Couldn't encrypt for the specified recipient <$recipient>, check your configuration";
            return 1;
        }
        if (not -s $outfile) {
            _err
              "Couldn't encrypt for the specified recipient <$recipient> (output file is empty), check your configuration";
            return 1;
        }
    }

    _log "Testing encryption for all recipients + signature... ";

    # then, encrypt to all the recipients, sign, and check the signature
    $outfile = File::Temp->new(UNLINK => 1, TMPDIR => 1);
    $error   = gpg_encrypt(
        infile     => $infile,
        outfile    => $outfile,
        recipients => [keys %recipients_uniq],
        signkey    => $config{'signing_key'},
        passphrase => $config{'signing_key_passphrase'}
    );
    if ($error) {
        _err "Couldn't encrypt and sign, check your configuration";
        return 1;
    }
    if (not -s $outfile) {
        _err "Couldn't encrypt and sign (output file is empty), check your configuration";
        return 1;
    }

    _log "Config test passed";
    return 0;
}

sub encrypt_multi {
    my %params                   = @_;
    my $source_file              = $params{'source_file'};
    my $destination_directory    = $params{'destination_directory'};
    my $remove_source_on_success = $params{'remove_source_on_success'} || 0;

    my $outfile = $source_file;
    $outfile =~ s!^/home/!$destination_directory/!;
    my $outdir = File::Basename::dirname($outfile);

    if (!-e $outdir) {
        _log "Creating $outdir";
        $dryRun or File::Path::mkpath(File::Basename::dirname($outfile), 0, oct(700));
    }

    my $layers = scalar(@{$config{'recipients'}});
    _log "Encrypting $source_file to $outfile" . ".gpg" x $layers;

    my $layer                    = 0;
    my $current_source_file      = $source_file;
    my $current_destination_file = $outfile . '.gpg';
    my $success                  = 1;
    foreach my $recipients_array (@{$config{'recipients'}}) {
        $layer++;
        _log " ... encrypting $current_source_file to $current_destination_file" if $verbose;
        my $error = encrypt_once(
            source_file      => $current_source_file,
            destination_file => $current_destination_file,
            recipients       => $recipients_array,
        );
        if ($layer > 1 and $layer <= $layers) {

            # transient file
            _log " ... deleting transient file $current_source_file" if $verbose;
            if (!$dryRun) {
                if (!unlink $current_source_file) {

                    # maybe it is +a? try to -a it blindly and retry
                    system('chattr', '-a', $current_source_file);
                    if (!unlink $current_source_file) {
                        _warn "Couldn't delete transient file '$current_source_file' ($!)";
                    }
                }
            }
        }
        if ($error) {
            $success = 0;
            last;
        }
        $current_source_file = $current_destination_file;
        $current_destination_file .= '.gpg';
    }
    if ($success and $remove_source_on_success) {
        _log " ... removing source file $source_file" if $verbose;
        if (!$dryRun) {
            if (!unlink $source_file) {

                # maybe it is +a? try to -a it blindly and retry
                system('chattr', '-a', $source_file);
                if (!unlink $source_file) {
                    _warn "Couldn't delete source file '$source_file' ($!)";
                }
            }
        }
    }
    return !$success;
}

sub encrypt_once {
    my %params           = @_;
    my $source_file      = $params{'source_file'};
    my $destination_file = $params{'destination_file'};
    my $recipients       = $params{'recipients'};
    my $error;

    if (not -f $source_file and not $dryRun) {
        _err "encrypt_once: source file $source_file is not a file!";
        return 1;
    }

    if (-f $destination_file) {
        _log "encrypt_once: destination file $destination_file already exists, renaming!";
        move($destination_file, "$destination_file.old." . time());
    }

    $error = gpg_encrypt(
        infile     => $source_file,
        outfile    => $destination_file,
        recipients => $recipients,
        signkey    => $config{'signing_key'},
        passphrase => $config{'signing_key_passphrase'},
    );
    if ($error) {
        _err "encrypt_once: failed encrypting $source_file to $destination_file";
        return 1;
    }
    if (!-s $destination_file) {
        _err "encrypt_once: failed encrypting $source_file to $destination_file (destination is empty)";
        return 1;
    }
    return 0;    # no error
}

# this sub is called for each file found
sub potentially_work_on_this_file {

    # file must be either:
    # - a ttyrec file or an osh_http_proxy_ttyrec-ish file
    # - a user sqlite file (possibly compressed)
    # - a user log file (possibly compressed)
    my ($filetype, $file_delay);
    if (m{^/home/[^/]+/ttyrec/[^/]+/[^/]+(?:\.ttyrec(?:\.zst)?)?$}) {
        $filetype   = 'ttyrec';
        $file_delay = $config{'encrypt_and_move_ttyrec_delay_days'};
    }
    elsif (m{^/home/[^/]+/ttyrec/[^/]+/\d+-\d+-\d+\.txt$}) {
        $filetype   = 'proxylog';
        $file_delay = $config{'encrypt_and_move_ttyrec_delay_days'};

        # never touch a file that's too recent because we might still write to it:
        $file_delay = 1 if $file_delay < 1;
    }
    elsif (m{^/home/[^/]+/[^/]+\.log(?:\.gz|\.xz)?$}) {
        $filetype   = 'userlog';
        $file_delay = $config{'encrypt_and_move_user_logs_delay_days'};

        # never touch a file that's too recent because we might still write to it:
        $file_delay = 31 if $file_delay < 31;
    }
    elsif (m{^/home/[^/]+/[^/]+\.sqlite(?:\.gz|\.xz)?$}) {
        $filetype   = 'usersqlite';
        $file_delay = $config{'encrypt_and_move_user_sqlites_delay_days'};

        # never touch a file that's too recent because we might still write to it:
        $file_delay = 31 if $file_delay < 31;
    }
    else {
        # ignore this file
        _log "Ignoring file $_" if ($verbose >= 2);
        return;
    }

    _log "Considering file $_" if ($verbose >= 2);

    # we might not have the right to touch some filetypes, as per config
    return if ($file_delay < 0);

    # $_ must exist and be a file
    -f or return;
    my $file = $_;

    # first, populate (once) the list of ttyrec files that are still opened by ttyrec
    state $openedFiles;
    if (ref $openedFiles ne 'HASH') {
        $openedFiles = {};
        if (open(my $fh_lsof, '-|', "lsof -a -n -c ttyrec -- /home/")) {
            while (<$fh_lsof>) {
                chomp;
                m{\s(/home/[^/]+/ttyrec/\S+)$} and $openedFiles->{$1} = 1;
            }
            close($fh_lsof);
            _log "Found " . (scalar keys %$openedFiles) . " opened ttyrec files we won't touch";
        }
        else {
            _warn "Error trying to get the list of opened ttyrec files, we might rotate opened files!";
        }
    }

    # still open? don't touch
    if (exists $openedFiles->{$file}) {
        _log "File $file is still opened by ttyrec, skipping";
        return;
    }

    # ignore files that are too recent (as per config)
    my $mtime = (stat($file))[9];
    if ($mtime > time() - 86400 * $file_delay) {
        _log "File $file is too recent ($filetype: $file_delay days), skipping" if $verbose;
        return;
    }

    # ok, this file is eligible, go
    my $error = encrypt_multi(
        source_file              => $file,
        destination_directory    => $config{'encrypt_and_move_to_directory'},
        remove_source_on_success => not $noDelete
    );
    if ($error) {
        _err "Got an error for $file, skipping!";
    }

    return;
}

sub directory_filter {    ## no critic (RequireArgUnpacking)

    # /home? check the subdirs and add them one by one if they are a bastion account's home
    if ($File::Find::dir eq '/home') {
        my @out = ();
        foreach (@_) {
            if (-e "/home/$_/lastlog" || -e "/home/$_/ttyrec") {
                push @out, $_;
            }
        }
        my @sorted = sort @out;
        if ($verbose >= 2) {
            _log "Filter: adding directory $_" for @sorted;
        }
        return @sorted;
    }

    # /home/*/ttyrec/*? check all subdirs/files up to infinite depth
    if ($File::Find::dir =~ m{^/home/[^/]+($|/ttyrec)}) {
        _log "Filter: adding all files of " . $File::Find::dir . ": " . join(", ", @_) if ($verbose >= 2);
        return @_;
    }

    _log "Filter: not adding anything from " . $File::Find::dir if ($verbose >= 2);
    return ();
}

sub print_usage {
    print <<"EOF";

    $0 [options]

    --dry-run        Don't actually compress/encrypt/rsync, just show what would be done
    --config-test    Test the validity of the config file and GPG setup
    --verbose        More logs, use twice to also get gpg raw output

    encryption phase:
    --encrypt-only   Encrypt and move the files, but skip the rsync phase
    --force-encrypt  Don't wait for the configured number of days before encrypting & moving files, do it immediately.
                     Note that filetypes that have their amount of days set to -1 from the config file will still be ignored,
                     and the minimum configurable amount of time still applies per filetype (i.e. to avoid moving a file still in use).

    rsync phase:
    --rsync-only     Skip the encryption phase, just rsync the already encrypted & moved files
    --force-delete   Don't wait for the configured number of days before deleting rsynced files,
                     do it as soon as they're transferred
    --no-delete      Don't delete local files after rsyncing, even if the configured amount of days has passed

EOF
    return;
}

sub main {
    _log "Starting...";

    {
        my $optwarn = 'Unknown error';
        local $SIG{'__WARN__'} = sub { $optwarn = shift; };
        if (
            !GetOptions(
                "dry-run"       => \$dryRun,
                "config-test"   => \$configTest,
                "no-delete"     => \$noDelete,
                "encrypt-only"  => \$encryptOnly,
                "rsync-only"    => \$rsyncOnly,
                "force-delete"  => \$forceDelete,
                "force-encrypt" => \$forceEncrypt,
                "verbose+"      => \$verbose,
                "help"          => \$help,
            )
          )
        {
            _err "Error while parsing command-line options: $optwarn";
            print_usage();
            return 1;
        }
    }

    if ($help) {
        print_usage();
        return 0;
    }

    if (config_load_and_lint() != 0) {
        _err "Configuration is invalid, aborting";
        return 1;
    }

    # ensure no other copy of myself is already running
    # except if we are in rsync-only mode (concurrency is then not a problem)
    my $lockfh;
    if (not $rsyncOnly) {
        if (!open($lockfh, '<', $config{'lockfile'})) {

            # flock() needs a file handler
            _log "Couldn't open config file, aborting";
            return 1;
        }
        if (!flock($lockfh, LOCK_EX | LOCK_NB)) {
            _log "Another instance is running, aborting this one!";
            return 1;
        }
    }

    if ($forceDelete) {
        $config{'rsync_delay_before_remove_days'} = 0;
    }
    if ($forceEncrypt) {
        foreach my $type (qw{ ttyrec user_logs user_sqlites }) {

            # keep config at -1 if it's set at -1 (i.e. filetype disabled)
            $config{"encrypt_and_move_${type}_delay_days"} = 0 if $config{"encrypt_and_move_${type}_delay_days"} > 0;
        }
    }

    if (config_test() != 0) {
        _err "Config test failed, aborting";
        return 1;
    }

    if ($configTest) {
        return 0;
    }

    if ($dryRun) {
        _log "Dry-run mode enabled, won't actually encrypt, move or delete files!";
    }

    if (not $rsyncOnly) {
        _log "Looking for files in /home/ ...";
        File::Find::find(
            {
                no_chdir   => 1,
                preprocess => \&directory_filter,
                wanted     => \&potentially_work_on_this_file
            },
            "/home/",
        );
    }

    if (not($encryptOnly || $config{'encrypt_only'}) and $config{'rsync_destination'}) {
        my @command;
        my $sysret;

        if (!-d $config{'encrypt_and_move_to_directory'} && $dryRun) {
            _log
              "DRYRUN: source directory doesn't exist, substituting with another one (namely the config directory which we know exists), just to try the rsync in dry-run mode";
            $config{'encrypt_and_move_to_directory'} = '/etc/cron.d/';
        }

        if (!-d $config{'encrypt_and_move_to_directory'}) {
            _log "Nothing to rsync as the rsync source dir doesn't exist";
        }
        else {
            _log "Now rsyncing files to remote host ...";
            @command = qw{ rsync --prune-empty-dirs --one-file-system -a };
            push @command, '-v' if $verbose;
            if ($config{'rsync_rsh'}) {
                push @command, '--rsh', $config{'rsync_rsh'};
            }
            if ($dryRun) {
                push @command, '--dry-run';
            }

            push @command, $config{'encrypt_and_move_to_directory'} . '/';
            push @command, $config{'rsync_destination'} . '/';
            _log "Launching the following command: @command";
            $sysret = system(@command);

            if ($sysret != 0) {
                _err "Error while rsyncing, stopping here";
                return 1;
            }

            # now run rsync again BUT only with files having mtime +rsync_delay_before_remove_days AND specifying --remove-source-files
            # this way only files old enough AND successfully transferred to the other side will be removed

            if (!$dryRun) {
                my $prevdir = $ENV{'PWD'};
                if (not chdir $config{'encrypt_and_move_to_directory'}) {
                    _err "Error while trying to chdir to " . $config{'encrypt_and_move_to_directory'} . ", aborting";
                    return 1;
                }

                _log "Building a list of rsynced files to potentially delete (older than "
                  . $config{'rsync_delay_before_remove_days'}
                  . " days)";
                my $cmdstr =
                    "find . -xdev -type f -name '*.gpg' -mtime +"
                  . ($config{'rsync_delay_before_remove_days'} - 1)
                  . " -print0 | rsync -"
                  . ($verbose ? 'v' : '') . "a ";
                if ($config{'rsync_rsh'}) {
                    $cmdstr .= "--rsh '" . $config{'rsync_rsh'} . "' ";
                }
                if ($dryRun) {
                    $cmdstr .= "--dry-run ";
                }
                $cmdstr .=
                    "--remove-source-files --files-from=- --from0 "
                  . $config{'encrypt_and_move_to_directory'} . '/' . " "
                  . $config{'rsync_destination'} . '/';
                _log "Launching the following command: $cmdstr";
                $sysret = system($cmdstr);
                if ($sysret != 0) {
                    _err "Error while rsyncing for deletion, stopping here";
                    return 1;
                }

                # remove empty directories
                _log "Removing now empty directories...";

                # errors would be printed for non empty dirs, we don't care
                system( "find "
                      . $config{'encrypt_and_move_to_directory'}
                      . " -type d ! -wholename "
                      . $config{'encrypt_and_move_to_directory'}
                      . " -delete 2>/dev/null");

                chdir $prevdir;
            }
        }
    }

    _log "Done, got "
      . (OVH::SimpleLog::nb_errors())
      . " error(s) and "
      . (OVH::SimpleLog::nb_warnings())
      . " warning(s).";
    return 0;
}

exit main();
