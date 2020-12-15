#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

# this line absolutely needs to be sync with the exec() of osh.pl
# that is launching us. we don't use GetOpts or such, as this is not
# user-modifiable anyway. We're mainly passing parameters we will need
# in this short script. some of them can sometimes be undef. this is normal.
my ($ip, $sshClientHasOptionE, $userPasswordClue, $saveFile, $insert_id, $db_name, $uniq_id, $self, @command) = @ARGV;

# on signal (HUP happens a lot), still try to log in db
sub exit_sig {
    my ($sig) = @_;

    if (defined $insert_id and defined $db_name) {

        # at that point, we might not have required the proper libs yet, do it
        require File::Basename;
        require ''    ## no critic (BarewordIncludes) ## I trust __FILE__, no worries
          . File::Basename::dirname(__FILE__) . '/../../lib/perl/OVH/Bastion.pm';

        # and log
        OVH::Bastion::log_access_update(
            account   => $self,
            insert_id => $insert_id,
            db_name   => $db_name,
            uniq_id   => $uniq_id,
            signal    => $sig,
        );
    }

    # signal my current process group
    kill $sig, 0;

    exit(117);    # EXIT_GOT_SIGNAL
}
$SIG{'INT'}  = \&exit_sig;
$SIG{'HUP'}  = \&exit_sig;
$SIG{'TERM'} = \&exit_sig;
$SIG{'SEGV'} = \&exit_sig;

# beautify for ps
local $0 = '' . __FILE__ . ' ' . join(' ', @command);

# set signal for when my parent dies (Linux only)
eval {
    require Linux::Prctl;

    # 1 is SIGHUP
    Linux::Prctl::set_pdeathsig(1);
};

# As we're going to system() something passed to us via @ARGV,
# we want to be sure we're being called by something we know.
# Yes. I'm fucking paranoid.
if (open(my $fh, '<', "/proc/" . getppid() . '/cmdline')) {
    my $cmdline = do { local $/ = undef; <$fh> };
    close($fh);
    my @pargv = split(/\x00/, $cmdline);

    # now check our parent infos.
    # regular case: ssh
    if (@pargv == 1 and $pargv[0] =~ /^sshd: /) {
        ;    # ok, our parent is sshd, legitimate use
    }

    # pingssh case
    elsif (@pargv == 4 and $pargv[0] =~ m{/perl$} and $pargv[1] =~ m{/osh\.pl} and $pargv[2] eq '-c') {
        ;    # ok pingssh case
    }

    # admin debug case: local su
    elsif (@pargv == 5 and $pargv[0] eq 'su' and $pargv[1] eq '-l' and $pargv[3] eq '-c') {
        print STDERR "\n\nHmm, hijack of " . $pargv[2] . " by root detected... debug I guess... okay, but it's really because it's you.\n\n";
    }

    # mosh
    elsif ($pargv[0] eq 'mosh-server') {
        ;    # we're being called by mosh-server, alrighty
    }

    # clush plugin
    elsif ($pargv[1] =~ m{^/opt/bastion/bin/plugin/(open|restricted)/clush$}) {
        ;    # we're being called by the clush plugin, ok
    }

    # interactive mode: our parent is osh.pl
    elsif ($pargv[0] eq 'perl' and $pargv[1] eq '/opt/bastion/bin/shell/osh.pl') {
        ;    # we're being called by the interactive mode of osh.pl, ok
    }

    # else: it sucks.
    else {
        #foreach (@pargv) { print "<".$_.">\n" };
        die("SECURITY VIOLATION, ABORTING.");
    }
}
else {
    ;        # grsec can deny us this. if that's the case, nevermind ... bypass this check
}

# in any case, force this
if (-e '/usr/local/bin/ttyrec') {
    $command[0] = '/usr/local/bin/ttyrec';
}
else {
    $command[0] = '/usr/bin/ttyrec';
}

# then finally launch the command !
my $sysret = system(@command);

# ... days or months may have passed once we arrive here, which is
# why we only used common::sense above (which is known to be light).
# using other packages would just waste memory for months as we would
# only really use them AFTER the command above has exited.

# so. now, we can require those files we need, rejoice, we have
# saved a lot of RAM in the meantime !

# special case for Time::HiRes, use a `use' instead of a `require'
# in an attempt to fix a strange 'Undefined subroutine &Time::HiRes::gettimeofday'
# that happens one every 10K connections or so
use Time::HiRes qw{ gettimeofday };
my ($timestamp, $timestampusec) = gettimeofday();

require File::Basename;
require ''    ## no critic (BarewordIncludes) ## I trust __FILE__, no worries
  . File::Basename::dirname(__FILE__) . '/../../lib/perl/OVH/Bastion.pm';

# ssh -E also silences normal errors on console, print them eventually
if ($sshClientHasOptionE) {
    if (open(my $sshdebug, '<', $saveFile . '.sshdebug')) {
        while (<$sshdebug>) {
            print
              unless /^debug|^key_load_public:|OpenSSL|^Authenticated to|^Transferred:|^Bytes per second:|^\s*$|client-session/;
        }
        close($sshdebug);
    }
}

# now guessify if the ssh worked or not
my @comments;
my $header;
if (open(my $fh_ttyrec, '<', $saveFile)) {
    read $fh_ttyrec, $header, 1000;    # 1K if there's the host key changed warning
    close($fh_ttyrec);
}
elsif (-r "$saveFile.zst") {
    my $fnret = OVH::Bastion::execute(cmd => ['zstd', '-d', '-c', "$saveFile.zst"], max_stdout_bytes => 1000, must_succeed => 1);
    $header = join("\n", @{$fnret->value->{'stdout'} || []}) if $fnret;
}

if ($header) {
    if ($header =~ /Permission denied \(publickey/) {
        push @comments, 'permission_denied';
        OVH::Bastion::osh_crit("BASTION SAYS: The remote server ($ip) refused all the keys we tried (see the list just above), there are FOUR things to verify:");
        OVH::Bastion::osh_warn(
"1) Check the remote account's authorized_keys on $ip, did you add the proper key there? (personal key or group key)\n2) Did you tell the bastion you added a key to the remote server, so it knows it has to use it? See the actually used keys just above. If you didn't, do it with selfAddPersonalAccess or groupAddServer.\n3) Check the from=\"\" part of the remote account's authorized_keys' keyline. Are all the bastion IPs present? Master and slave(s)? See groupInfo or selfListEgressKeys to get the proper keyline to copy/paste.\n4) Did you check the 3 above points carefully? Really? Because if you did, you wouldn't be reading this 4th bullet point, as your problem would already be fixed ;)"
        );
    }
    if ($header =~ /Permission denied \(keyboard-interactive/) {
        push @comments, 'permission_denied';
        my $keyboardInteractiveAllowed = OVH::Bastion::config('keyboardInteractiveAllowed')->value;
        OVH::Bastion::osh_crit("BASTION SAYS: The remote server ($ip) wanted to use keyboard-interactive authentication, but it's not enabled on this bastion!");
    }
    if ($header =~ /Too many authentication failures/) {
        push @comments, 'too_many_auth_fail';
        OVH::Bastion::osh_crit("BASTION SAYS: The remote server ($ip) disconnected us before we got a chance to try all the keys we wanted to (see the list just above).");
        OVH::Bastion::osh_warn(
            "This usually happens if there are too many keys to try, for example if you have numerous personal keys of if $ip is in many groups you have access to.");
        OVH::Bastion::osh_warn("Either reduce the number of keys to try, or modify $ip\'s sshd \"MaxAuthTries\" configuration option.");
    }
    push @comments, 'hostkey_changed' if $header =~ /IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY/;
    push @comments, 'hostkey_saved'   if $header =~ /Warning: Permanently added /;
    if ($header =~ /ssh: connect to host \S+ port \d+: Connection timed out/) {
        push @comments, 'connection_timeout';
    }
    elsif ($header =~ /ssh: connect to host \S+ port \d+: Connection refused/) {
        push @comments, 'connection_refused';
    }
    elsif ($header =~ /ssh: connect to host \S+ port \d+: /) {
        push @comments, 'connection_error';
    }
    elsif ($header =~ /disabled to avoid man-in-the-middle/) {
        push @comments, 'passauth_disabled';

        # be nice and explain to the user cf ticket BASTION-10
        if ($userPasswordClue) {
            OVH::Bastion::osh_crit("BASTION SAYS: Password auth is blocked because of the hostkey mismatch on $ip.");
            OVH::Bastion::osh_crit("If you are aware of this change, remove the hostkey cache with --osh selfForgetHostKey --host $ip --port PORT");
        }
    }
    if ($header =~ /remove with: ssh-keygen -f "\S+" -R (\S+)/) {

        # be nice and explain how to remove this warning
        OVH::Bastion::osh_crit("BASTION SAYS: If you know why the hostkey changed and you know this is normal, you can remove this warning by using the following command:");
        my $bastionName = OVH::Bastion::config('bastionName')->value;
        OVH::Bastion::osh_crit("$bastionName --osh selfForgetHostKey --host $1");
    }
}
else {
    push @comments, 'ttyrec_error';
}

# update our sql line if we successfully inserted it back in osh.pl
OVH::Bastion::log_access_update(
    account          => $self,
    insert_id        => $insert_id,
    db_name          => $db_name,
    uniq_id          => $uniq_id,
    returnvalue      => $sysret,
    comment          => @comments ? join(' ', @comments) : undef,
    timestampend     => $timestamp,
    timestampendusec => $timestampusec,
);

if ($sysret == -1) {
    OVH::Bastion::osh_crit("Couldn't start " . join('|', @command) . ($! ? " ($!)" : ", is it installed?"));
    exit($sysret);
}

exit($sysret >> 8);
