#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use strict;
use warnings;
use 5.010;

use File::Temp;
use File::Basename;
use File::Find;
use File::Path;
use File::Copy;
use Getopt::Long;
use Fcntl qw{ :flock };
use IPC::Open3;

use File::Basename;
use lib dirname(__FILE__) . '/../../lib/perl';

use OVH::Bastion;
use OVH::SimpleLog;

my %config;
my ($dryRun, $configTest, $forceRsync, $forceEncrypt, $noDelete, $encryptOnly, $rsyncOnly, $verbose, $help);
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
    push @cmd, "-v" if $config{'trace'};
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
    push @cmd, "-v" if $config{'trace'};
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

sub test_config {
    my $error;

    # normalize / define defaults / quick checks
    $config{'trace'} = $config{'trace'} ? 1 : 0;

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

    if ($config{'encrypt_and_move_delay_days'} !~ /^\d+$/) {
        _err "config error: encrypt_and_move_delay_days is not a positive integer!";
        return 1;
    }

    if ($config{'rsync_delay_before_remove_days'} !~ /^\d+$/) {
        _err "config error: rsync_delay_before_remove_days is not a positive integer!";
        return 1;
    }

    # ok, check if my gpg conf is good
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
        _err "Couldn't sign with the specified key $config{'signing_key'} (output file is empty), check your configuration";
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
            _err "Couldn't encrypt for the specified recipient <$recipient> (output file is empty), check your configuration";
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
            $dryRun or unlink $current_source_file;
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
        $dryRun or unlink $source_file;
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

my $openedFiles = undef;

sub potentially_work_on_this_file {

    # file must be a ttyrec file or an osh_http_proxy_ttyrec-ish file
    my $filetype;
    $filetype = 'ttyrec'   if m{^/home/[^/]+/ttyrec/[^/]+/[^/]+(\.ttyrec(\.zst)?)?$};
    $filetype = 'proxylog' if m{^/home/[^/]+/ttyrec/[^/]+/\d+-\d+-\d+\.txt$};
    $filetype or return;

    # must exist and be a file
    -f or return;
    my $file = $_;

    # first, check if we populated $openedFiles as a hashref
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

    # still open ? don't touch
    if (exists $openedFiles->{$file}) {
        _log "File $file is still opened by ttyrec, skipping";
        return;
    }

    # and must be older than encrypt_and_move_delay_days days
    my $mtime = (stat($file))[9];
    if ($mtime > time() - 86400 * $config{'encrypt_and_move_delay_days'}) {
        _log "File $file is too recent, skipping" if $verbose;
        return;
    }

    # for proxylog, never touch a file that's < 86400 sec old (because we might still write to it)
    if ($filetype eq 'proxylog' and $mtime > time() - 86400) {
        _log "File $file is too recent (proxylog), skipping" if $verbose;
        return;
    }

    my $error = encrypt_multi(source_file => $file, destination_directory => $config{'encrypt_and_move_to_directory'}, remove_source_on_success => not $noDelete);
    if ($error) {
        _err "Got an error for $file, skipping!";
    }

    return;
}

sub directory_filter {    ## no critic (RequireArgUnpacking)

    # /home ? check the subdirs
    if ($File::Find::dir eq '/home') {
        my @out = ();
        foreach (@_) {
            if (-d "/home/$_/ttyrec") {
                push @out, $_ if -d "/home/$_/ttyrec";
            }
        }
        return @out;
    }
    if ($File::Find::dir =~ m{^/home/[^/]+($|/ttyrec)}) {

        return @_;
    }

    return ();
}

sub print_usage {
    print <<"EOF";

    $0 [options]

    --dry-run        Don't actually compress/encrypt/rsync, just show what would be done
    --config-test    Test the validity of the config file
    --verbose        More logs

    rsync phase:
    --no-delete      During the encrypt phase, don't delete the source files after successful encryption
    --rsync-only     Skip the encrypt phase, just rsync the already encrypted & moved files
    --force-rsync    Don't wait for the configured number of days before rsyncing files, do it immediately

    encryption phase:
    --encrypt-only   Skip the rsync phase, just encrypt & move the files
    --force-encrypt  Don't wait for the configured number of days before encrypting & moving files, do it immediately

EOF
    return;
}

sub main {
    _log "Starting...";

    if (
        !GetOptions(
            "dry-run"       => \$dryRun,
            "config-test"   => \$configTest,
            "no-delete"     => \$noDelete,
            "encrypt-only"  => \$encryptOnly,
            "rsync-only"    => \$rsyncOnly,
            "force-rsync"   => \$forceRsync,
            "force-encrypt" => \$forceEncrypt,
            "verbose"       => \$verbose,
            "help"          => \$help,
        )
      )
    {
        _err "Error while parsing command-line options";
        print_usage();
        return 1;
    }

    if ($help) {
        print_usage();
        return 0;
    }

    # we can have CONFIGDIR/osh-encrypt-rsync.conf
    # but also CONFIGDIR/osh-encrypt-rsync.conf.d/*
    # later files override the previous ones, item by item

    my $fnret;
    my $lockfile;
    my @configfilelist;
    if (-f -r OVH::Bastion::main_configuration_directory() . "/osh-encrypt-rsync.conf") {
        push @configfilelist, OVH::Bastion::main_configuration_directory() . "/osh-encrypt-rsync.conf";
    }

    if (-d -x OVH::Bastion::main_configuration_directory() . "/osh-encrypt-rsync.conf.d") {
        if (opendir(my $dh, OVH::Bastion::main_configuration_directory() . "/osh-encrypt-rsync.conf.d")) {
            my @subfiles = map { OVH::Bastion::main_configuration_directory() . "/osh-encrypt-rsync.conf.d/" . $_ } grep { /\.conf$/ } readdir($dh);
            closedir($dh);
            push @configfilelist, sort @subfiles;
        }
    }

    if (not @configfilelist) {
        _err "Error, no config file found!";
        return 1;
    }

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
        $lockfile = $configfile if not defined $lockfile;
    }

    $verbose ||= $config{'verbose'};

    # ensure no other copy of myself is already running
    # except if we are in rsync-only mode (concurrency is then not a problem)
    my $lockfh;
    if (not $rsyncOnly) {
        if (!open($lockfh, '<', $lockfile)) {

            # flock() needs a file handler
            _log "Couldn't open config file, aborting";
            return 1;
        }
        if (!flock($lockfh, LOCK_EX | LOCK_NB)) {
            _log "Another instance is running, aborting this one!";
            return 1;
        }
    }

    # default values
    $config{'syslog_facility'} ||= 'local6';

    # ensure the various config files defined all the keywords we need
    foreach my $keyword (
        qw{
        signing_key signing_key_passphrase recipients encrypt_and_move_to_directory
        encrypt_and_move_delay_days rsync_delay_before_remove_days
        }
      )
    {
        next if defined $config{$keyword};
        _err "Missing mandatory configuration item '$keyword', aborting";
        return 1;
    }

    OVH::SimpleLog::setLogFile($config{'logfile'})        if $config{'logfile'};
    OVH::SimpleLog::setSyslog($config{'syslog_facility'}) if $config{'syslog_facility'};

    if ($forceRsync) {
        $config{'rsync_delay_days'} = 0;
    }
    if ($forceEncrypt) {
        $config{'encrypt_and_move_delay_days'} = 0;
    }

    if (test_config() != 0) {
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
            _log "DRYRUN: source directory doesn't exist, substituting with another one (namely the config directory which we know exists), just to try the rsync in dry-run mode";
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

                _log "Building a list of rsynced files to potentially delete (older than " . $config{'rsync_delay_before_remove_days'} . " days)";
                my $cmdstr = "find . -xdev -type f -name '*.gpg' -mtime +" . ($config{'rsync_delay_before_remove_days'} - 1) . " -print0 | rsync -" . ($verbose ? 'v' : '') . "a ";
                if ($config{'rsync_rsh'}) {
                    $cmdstr .= "--rsh '" . $config{'rsync_rsh'} . "' ";
                }
                if ($dryRun) {
                    $cmdstr .= "--dry-run ";
                }
                $cmdstr .= "--remove-source-files --files-from=- --from0 " . $config{'encrypt_and_move_to_directory'} . '/' . " " . $config{'rsync_destination'} . '/';
                _log "Launching the following command: $cmdstr";
                $sysret = system($cmdstr);
                if ($sysret != 0) {
                    _err "Error while rsyncing for deletion, stopping here";
                    return 1;
                }

                # remove empty directories
                _log "Removing now empty directories...";

                # errors would be printed for non empty dirs, we don't care
                system("find " . $config{'encrypt_and_move_to_directory'} . " -type d ! -wholename " . $config{'encrypt_and_move_to_directory'} . " -delete 2>/dev/null");

                chdir $prevdir;
            }
        }
    }

    _log "Done";
    return 0;
}

exit main();
