#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use strict;
use warnings;
use 5.010;

use Getopt::Long;

use File::Basename;
use lib dirname(__FILE__) . '/../../lib/perl';

my $getOptionsOk = GetOptions(
    "master-passwd=s" => \my $masterPasswdFile,
    "local-passwd=s"  => \my $localPasswdFile,
    "master-group=s"  => \my $masterGroupFile,
    "local-group=s"   => \my $localGroupFile,
    "output=s"        => \my $outputFile,
    "offset=i"        => \my $offset,             # undocumented on purpose
);

if (!$getOptionsOk) {
    die "Failed to parse options (see above), aborting.\n";
}

$localPasswdFile //= '/etc/passwd';
$localGroupFile  //= '/etc/group';
$offset          //= 50_000_000;

if ($offset < 10_000) {
    die "Offset is too low ($offset)\n";
}

if (!$masterGroupFile || !$masterPasswdFile || !$outputFile) {
    die "Usage: $0 --master-passwd PATH --master-group PATH --output FILE [--local-passwd PATH --local-group PATH]\n";
}

if (-e $outputFile && !-c _) {
    die "Output file '$outputFile' already exists!\n";
}

my (%local, %master);
read_pwgr_file($masterPasswdFile, \%master, 'pw');
read_pwgr_file($localPasswdFile,  \%local,  'pw');
read_pwgr_file($masterGroupFile,  \%master, 'gr');
read_pwgr_file($localGroupFile,   \%local,  'gr');

sub read_pwgr_file {
    my ($file, $hashref, $type) = @_;
    my $fh;
    if (!open($fh, '<', $file)) {
        die("Couldn't open file '$file': $!");
    }
    $hashref->{$type} = {};
    while (<$fh>) {
        chomp;
        my ($name, undef, $id) = split /:/;

        next if $id == 0;    # never mess with UID/GID 0

        $hashref->{$type}{name_by_id}{$id}   = $name;
        $hashref->{$type}{id_by_name}{$name} = $id;
    }
    close($fh);
    return;
}

my $orphans;
# first, report orphans
handle_list($local{'pw'}, $master{'pw'}, 'pw', 0);
handle_list($local{'gr'}, $master{'gr'}, 'gr', 0);
if ($orphans) {
    say "\nThere is at least one warning, see above.";
    say "If you want to handle them, you may still abort now.";
    say "Type 'YES' to proceed regardless.";
    my $ans = <STDIN>;
    chomp $ans;
    if ($ans ne 'YES') {
        say "Aborting on user request.";
        exit 0;
    }
    else {
        say "";
    }
}

# build the list of mountpoints on which we'll run chmod/chown
my @fslist;
if (open(my $fh, '<', '/proc/mounts')) {
    while (<$fh>) {
        # /dev/loop9 /snap/cups/872 squashfs ro,nodev,relatime,errors=continue 0 0
        my @fields = split / /;
        # ignore some filesystems
        next
          if (
            grep { $fields[2] eq $_ }
            qw{
            squashfs vfat cgroup cgroup2 devpts devtmpfs proc fuse.pathfs.pathInode
            cifs nfs nsfs rpc_pipefs pstore autofs debugfs configfs fusectl binfmt_misc
            mqueue securityfs sysfs efivarfs bpf hugetlbfs tracefs overlay overlay2 aufs
            }
          );
        # ignore some mountpoints we know we want to exclude anyway
        next if ($fields[1] =~ m{^/(dev|sys|proc|snap|boot)(/|\z)});
        # ignore readonly mountpoints
        next if ($fields[3] =~ m{(^|,)ro(,|$)});
        # ok add this mountpoint
        push @fslist, $fields[1];
    }
}
else {
    die "Couldn't open /proc/mounts: $!";
}

my @cmds;
my @grepcmds;
while (!handle_list($local{'pw'}, $master{'pw'}, 'pw', 1)) {
    ;
}
while (!handle_list($local{'gr'}, $master{'gr'}, 'gr', 1)) {
    ;
}
while (!handle_list($local{'pw'}, $master{'pw'}, 'pw', 2)) {
    ;
}
while (!handle_list($local{'gr'}, $master{'gr'}, 'gr', 2)) {
    ;
}

if (!@cmds) {
    say "There is nothing to change, all UIDs/GIDs are in sync :)";
    exit 0;
}
else {
    say "";
}

if (open(my $fh, '>', $outputFile)) {
    my $fslist_flat   = join(" ",  sort @fslist);
    my $grepcmds_flat = join("\n", @grepcmds);
    my $cmds_flat     = join("\n", @cmds);
    print $fh <<"EOF1", <<'EOF2', $cmds_flat, <<'EOF3';
#!/bin/bash
# You may change the list below if needed:
fslist="$fslist_flat"

# Don't change anything below this line (unless you know what you're doing!)
proclist=\$(true ; $grepcmds_flat)
EOF1

echo "We'll change the UIDs/GIDs of files, when needed, in the following mountpoints: $fslist"
echo "If you'd like to change this list, please edit this script and change the 'fslist' variable in the header."
echo "Otherwise, if this sounds reasonable (e.g. there is no remotely mounted filesystem that you don't want us to touch), say 'YES' below:"
read answer
if [ "$answer" != YES ]; then
    echo "Aborting on user request."
    exit 0
fi
proclist=$(echo $proclist | tr " " "\n" | sort -u)
if [ -n "$proclist" ]; then
    pscmd="ps fu"
    for pid in $proclist; do
    pscmd="$pscmd -p $pid"
    done
    echo
    echo "The following processes/daemons will need to be killed before swapping the UIDs/GIDs:"
    echo
    $pscmd
    echo
    echo "If you want to stop them manually, you may abort now (CTRL+C) and do so."
    echo "Press ENTER to continue."
    read __
fi
echo "Listing SUID/SGID files before potentially altering those..."
suidfiles=$(mktemp)
sgidfiles=$(mktemp)
trap "rm -f $suidfiles $sgidfiles" EXIT
find $fslist -xdev -ignore_readdir_race -perm /4000 -type f -print0 > "$suidfiles"
find $fslist -xdev -ignore_readdir_race -perm /2000 -type f -print0 > "$sgidfiles"
echo "Starting work"
echo
EOF2

echo
echo "Restoring SUID/SGID flags where needed..."
xargs -r0 chmod -v u+s -- < "$suidfiles"
xargs -r0 chmod -v g+s -- < "$sgidfiles"
echo
echo 'UID/GID swapping done, please reboot now.'
echo
EOF3

    close($fh);
    say "\nYou may now review the generated script ($outputFile) and launch it when you're ready.";
    say "Note that you'll have to reboot once the script has completed.";
}
else {
    die "Couldn't open '$outputFile' for write: $!";
}
exit 0;

sub handle_list {
    my ($local, $master, $type, $pass) = @_;
    my ($ch, $idtype, $typename);
    if ($type eq 'pw') {
        $ch       = 'chown';
        $idtype   = 'UID';
        $typename = 'account';
    }
    elsif ($type eq 'gr') {
        $ch       = 'chgrp';
        $idtype   = 'GID';
        $typename = 'group';
    }
    else {
        die "Unknown type '$type'";
    }

    my %unseen_ids   = map { $_ => 1 } keys %{$local->{'name_by_id'}};
    my %unseen_names = map { $_ => 1 } keys %{$local->{'id_by_name'}};
    my $fullsync     = 0;
    my $tocreate     = 0;

    # loop through the master ids, because master is always right
    foreach my $master_id (sort keys %{$master->{'name_by_id'}}) {
        delete $unseen_ids{$master_id};
        my $master_name = $master->{'name_by_id'}{$master_id};
        delete $unseen_names{$master_name};
        next if ($pass == 0);

        # does this master ID exists locally?
        if (exists $local->{'name_by_id'}{$master_id}) {
            # yes: but is this the same name?
            my $local_name = $local->{'name_by_id'}{$master_id};

            if ($local_name eq $master_name) {
                # yes: ok, both IDs and names match, we're done
                $fullsync++;
            }
            else {
                # no: name collision, we have two different names for the same ID
                printf("Name collision on $idtype: master $idtype %d exists on local "
                      . "but with a different name (master=%s local=%s)\n",
                    $master_id, $master_name, $local_name);
                if ($pass == 1) {
                    # in that case, on first pass, we push the local ID way higher to ensure it is out of the way
                    my $new_local_id = $master_id + $offset;
                    $local->{'name_by_id'}{$new_local_id} = delete $local->{'name_by_id'}{$master_id};
                    $local->{'id_by_name'}{$local_name}   = $new_local_id;
                    push @cmds, "echo '*** ${typename}s: step 1: offsetting $local_name to $new_local_id'";
                    push @cmds,
                      sprintf("find \$fslist -xdev -ignore_readdir_race -%s %d -ls -exec %s %d '{}' +",
                        lc($idtype), $master_id, $ch, $new_local_id);
                    push @cmds,     sprintf("pkill -%s %s && sleep 1", $type eq 'pw' ? 'U' : 'G', $local_name);
                    push @cmds,     sprintf("usermod  --uid %d %s",    $new_local_id, $local_name) if $type eq 'pw';
                    push @cmds,     sprintf("groupmod --gid %d %s",    $new_local_id, $local_name) if $type eq 'gr';
                    push @grepcmds, sprintf("pgrep -%s %s",            $type eq 'pw' ? 'U' : 'G', $local_name);
                    # and we ask our caller to call us again as we've changed the local ID for this account or group
                    say "-> okay, offsetting local UID $master_id to $new_local_id";
                    return 0;
                }
                else {
                    die "Should not happen";
                }
            }
        }

        else {
            # no: this master ID doesn't exists locally, but do we have a local name corresponding to the master one?
            my $local_id = $local->{'id_by_name'}{$master_name};

            if (defined $local_id) {
                # yes: differing name for same ID
                # don't report if $local_id is > $offset in pass 1, because it's a transient situation WE created,
                # and we know about it
                if ($pass == 2 || $local_id < $offset) {
                    printf("Differing name attached to same $idtype: master $idtype %s doesn't exist on local, "
                          . "but its corresponding name '%s' does, with local $idtype %d\n",
                        $master_id, $master_name, $local_id);
                }

                if ($pass == 2) {
                    # on second pass we know the master ID is now available locally, so do the change
                    $local->{'name_by_id'}{$master_id}   = delete $local->{'name_by_id'}{$local_id};
                    $local->{'id_by_name'}{$master_name} = $master_id;
                    push @cmds,
                      "echo '*** ${typename}s: step 2: setting back $master_name to $master_id instead of $local_id'";
                    push @cmds,
                      sprintf("find \$fslist -xdev -ignore_readdir_race -%s %d -ls -exec %s %d '{}' +",
                        lc($idtype), $local_id, $ch, $master_id);
                    push @cmds,     sprintf("pkill -%s %s && sleep 1", $type eq 'pw' ? 'U' : 'G', $master_name);
                    push @cmds,     sprintf("usermod  --uid %d %s",    $master_id, $master_name) if $type eq 'pw';
                    push @cmds,     sprintf("groupmod --gid %d %s",    $master_id, $master_name) if $type eq 'gr';
                    push @grepcmds, sprintf("pgrep -%s %s",            $type eq 'pw' ? 'U' : 'G', $master_name);
                    say "-> okay, setting local $idtype of $master_name to $master_id instead of $local_id";
                    # and we ask our caller to call us again as we've changed the local ID for this account or group
                    return 0;
                }
            }
            else {
                # no: ok, this new entry will be created locally
                $tocreate++;
            }
        }
    }

    if ($pass == 0) {
        # loop through the unseen IDs we have locally, and set their corresponding name as 'seen' (delete from unseen)
        foreach my $local_id (sort keys %unseen_ids) {
            next if $local_id >= $offset;
            my $local_name = $local->{'name_by_id'}{$local_id};
            delete $unseen_names{$local_name};
        }

        # loop through the unseen names we have locally, and report: they would be erased
        foreach my $local_name (sort keys %unseen_names) {
            my $local_id = $local->{'id_by_name'}{$local_name};
            next if $local_id >= $offset;
            printf("WARN: local orphan name: local name '%s' (with $idtype %d) is only present locally, "
                  . "if you want to keep it, create it on the master first or it'll be erased\n",
                $local_name, $local_id);
            $orphans++;
        }
    }

    return 1;
}
