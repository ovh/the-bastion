#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;
use Data::Dumper;
use Term::ANSIColor;
use Digest::MD5 ();
use File::Basename;

use lib dirname(__FILE__) . '/../../lib/perl';
use OVH::Bastion;

my $BASEDIR = dirname(__FILE__) . '/../..';

my $MIN_KEYGROUP_GID       = OVH::Bastion::config("groupGidMin")->value;
my $MAX_KEYGROUP_GID       = $MIN_KEYGROUP_GID + 99999;
my @KEY_GROUPS_IGNORE      = qw{ keeper reader };
my $HOME_SUBDIRS_IGNORE_RE = qr{^^};

my $bad;

# generate a uniq prefix based on caller's lineno and caller's caller's lineno, useful to grep or grep -v
sub _prefix { return uc(unpack('H*', pack('S', (caller(1))[2])) . unpack('H*', pack('S', (caller(2))[2]))) . ": "; }

sub info  { print $_[0] . "\n"; return 1; }
sub _wrn  { $bad++; print colored(_prefix() . $_[0], "blue") . "\n";     return 1; }    ## no critic (ProhibitUnusedPrivateSubroutine)
sub _err  { $bad++; print colored(_prefix() . $_[0], "red") . "\n";      return 1; }
sub _crit { $bad++; print colored(_prefix() . $_[0], "bold red") . "\n"; return 1; }

# Linux and BSD don't always have the same account names for UID/GID 0
my ($UID0)  = (qx{getent passwd 0})[0] =~ /^([^:]+)/;                                   ## no critic (ProhibitBacktickOperators)
my ($GID0)  = (qx{getent group 0})[0]  =~ /^([^:]+)/;                                   ## no critic (ProhibitBacktickOperators)
my $islinux = (($^O =~ /linux/i)         ? 1 : 0);
my $hasacls = (($^O =~ /linux|freebsd/i) ? 1 : 0);

# get all the key* groups
my %keygroupsbyname  = ();
my %aclkgroupsbyname = ();
my %gkgroupsbyname   = ();
my %owgroupsbyname   = ();
my %keygroupsbyid    = ();
my %aclkgroupsbyid   = ();
my %gkgroupsbyid     = ();
my %owgroupsbyid     = ();

my $sudoers_dir = '/etc/sudoers.d';
if (!-d $sudoers_dir && -d '/usr/pkg/etc/sudoers.d') {
    $sudoers_dir = '/usr/pkg/etc/sudoers.d';
}
elsif (!-d $sudoers_dir && !$islinux) {
    $sudoers_dir = '/usr/local/etc/sudoers.d';
}

_err "/nonexistent exists" if -e "/nonexistent";

open(my $fh_group, '<', '/etc/group') or die $!;
while (<$fh_group>) {
    /^key([^:]+):[^:]+:(\d+)/ or next;
    my $name = $1;
    my $id   = $2;

    if (   exists $keygroupsbyname{$name}
        or exists $gkgroupsbyname{$name}
        or exists $owgroupsbyname{$name}
        or exists $aclkgroupsbyname{$name})
    {
        _err "group $name already seen!";
    }
    if ($name =~ /-gatekeeper$/) {
        $gkgroupsbyname{$name} = {name => $name, id => $id};
    }
    elsif ($name =~ /-aclkeeper$/) {
        $aclkgroupsbyname{$name} = {name => $name, id => $id};
    }
    elsif ($name =~ /-owner$/) {
        $owgroupsbyname{$name} = {name => $name, id => $id};
    }
    else {
        $keygroupsbyname{$name} = {name => $name, id => $id};
    }

    if (   exists $keygroupsbyid{$id}
        or exists $gkgroupsbyid{$id}
        or exists $owgroupsbyid{$id}
        or exists $aclkgroupsbyname{$id})
    {
        _crit "group $name 's ID already seen!";
    }
    if ($name =~ /-gatekeeper$/) {
        $gkgroupsbyid{$id} = {name => $name, id => $id};
    }
    elsif ($name =~ /-aclkeeper$/) {
        $aclkgroupsbyid{$id} = {name => $name, id => $id};
    }
    elsif ($name =~ /-owner$/) {
        $owgroupsbyid{$id} = {name => $name, id => $id};
    }
    else {
        $keygroupsbyid{$id} = {name => $name, id => $id};
    }

    if (grep { $name eq $_ } @KEY_GROUPS_IGNORE) {
        delete $keygroupsbyname{$name};
        delete $keygroupsbyid{$id};
        next;
    }
    if ($id > $MAX_KEYGROUP_GID) { _err "group $name id $id is too high"; }
    if ($id < $MIN_KEYGROUP_GID) { _err "group $name id $id is too low"; }
}
close($fh_group);
info "found " . (scalar keys %keygroupsbyname) . " key groups";

# checking if allowkeeper is a member of all keygroups
my @allowkeeper_groups = split(/ /, qx/groups allowkeeper/);    ## no critic (ProhibitBacktickOperators)
chomp @allowkeeper_groups;

# some outputs of `groups` include "$username :" as a prefix, strip that
if ($allowkeeper_groups[0] eq 'allowkeeper' && $allowkeeper_groups[1] eq ':') {
    @allowkeeper_groups = splice @allowkeeper_groups, 2;
}
foreach my $group (keys %keygroupsbyname) {
    _err "allowkeeper user is not a member of group key$group" if (not grep { $_ eq "key$group" } @allowkeeper_groups);
}

# now check if each key group has a gk
# and vice versa
foreach my $group (keys %keygroupsbyname) {
    next if exists $gkgroupsbyname{$group . "-gatekeeper"};
    _err "key group $group is missing a gatekeeper group";
}
foreach my $groupori (keys %gkgroupsbyname) {
    my $group = $groupori;
    $group =~ s/-gatekeeper$//;
    next if exists $keygroupsbyname{$group};
    _err "gatekeeper group $group is missing a key group";
}

foreach my $group (keys %keygroupsbyname) {
    next if exists $owgroupsbyname{$group . "-owner"};
    _err "key group $group is missing an owner group";
}
foreach my $groupori (keys %owgroupsbyname) {
    my $group = $groupori;
    $group =~ s/-owner$//;
    next if exists $keygroupsbyname{$group};
    _err "owner group $group is missing a key group";
}

# now check if each key group has a /home/key* $HOME
# and vice versa
my @keyhomesfound;
opendir(my $dh, "/home/") or die $!;
while (my $file = readdir($dh)) {
    next unless -d "/home/$file";
    next if $file eq '.';
    next if $file eq '..';
    if ($file !~ /[a-zA-Z0-9_.-]+$/) {
        _err "bad chars in /home/$file";
        next;
    }
    push @keyhomesfound, $file if $file =~ /^key/;
}
foreach my $file (@keyhomesfound) {
    my $file2 = $file;
    $file2 =~ s/^key//;
    next if exists $keygroupsbyname{$file2};
    next if (grep { $file2 eq $_ } @KEY_GROUPS_IGNORE);
    _err "directory /home/key$file2 exists but no key group $file2";
}
foreach my $group (keys %keygroupsbyname) {
    next if -d "/home/key$group";
    _err "key group $group is missing /home/key$group";
}

my %ALL_FILES;
foreach (qx{find /home/key* /home/keykeeper /home/allowkeeper -print}) {    ## no critic (ProhibitBacktickOperators)
    chomp;
    /$HOME_SUBDIRS_IGNORE_RE/ and next;
    $ALL_FILES{$_} = 1;
}
while (my $homedir = glob '/home/*') {
    -d $homedir          or next;
    -d "$homedir/ttyrec" or next;
    next if $homedir eq '/home/proxyhttp';
    next if $homedir eq '/home/healthcheck';

    #$ALL_FILES{$_} = 1;
    #$ALL_FILES{$_.'/ttyrec'} = 1;
    #$ALL_FILES{$_.'/.ssh'} = 1;
    #$ALL_FILES{$_.'/osh.log'} = 1;
    my ($user) = $homedir =~ m{/([^/]+)$};
    my $usertty = "$user-tty";
    if (not getgrnam($usertty)) {
        $usertty = substr($user, 0, 5) . '-tty';
    }
    check_file_rights(
        "$homedir",
        [
            "# file: $homedir", "# owner: $user",     "# group: $user",        "user::rwx",
            "group::r-x",       "group:$usertty:--x", "group:osh-auditor:--x", "mask::r-x",
            "other::---",
        ],
        "drwxr-x--x",
        $user, $user
    );
    check_file_rights(
        "$homedir/ttyrec",
        [
            "# file: $homedir/ttyrec", "# owner: $user",     "# group: $user",             "user::rwx",
            "group::---",              "group:$usertty:r-x", "mask::r-x",                  "other::---",
            "default:user::rwx",       "default:group::---", "default:group:$usertty:r-x", "default:mask::r-x",
            "default:other::---",
        ],
        "drwxrwxr-x",
        $user, $user
    );
    check_file_rights(
        "$homedir/.ssh",
        [
            "# file: $homedir/.ssh", "# owner: $user",        "# group: $user", "user::rwx",
            "group::r-x",            "group:osh-auditor:--x", "mask::r-x",      "other::---",
        ],
        "drwxr-x---",
        $user, $user
    );
    if (-e "$homedir/osh.log")    # doesn't exist? nevermind
    {
        check_file_rights(
            "$homedir/osh.log",
            ["# file: $homedir/osh.log", "# owner: $user", "# group: $user", "user::rw-", "group::r--", "other::---",],
            "-rw-r-----",
            $user,
            $user
        );
    }

    # now check all keys in ~/.ssh
    opendir(my $dh, "$homedir/.ssh") or die "$homedir/.ssh: $!";
    while (my $keyfile = readdir($dh)) {
        next unless $keyfile =~ /^id_|private/;
        my $ret = check_file_rights(
            "$homedir/.ssh/$keyfile",
            [
                "# file: $homedir/.ssh/$keyfile",
                "# owner: $user",
                "# group: $user",
                "user::r--",
                $keyfile =~ /\.pub$/ ? "group::r--" : "group::---",
                $keyfile =~ /\.pub$/ ? "other::r--" : "other::---",
            ],
            $keyfile =~ /\.pub$/ ? "-r--r--r--" : "-r--------",
            $user, $user
        );
        if ($keyfile !~ /\.pub$/) {
            if (not $ret) {

                # wow ! private key readable ?
                _crit "due to above error, private key $homedir/.ssh/$keyfile might be readable !!";
            }
        }
        else {
            # check for spurious "from" in .pub
            open(my $pubfh, '<', "$homedir/.ssh/$keyfile") or die "$homedir/.ssh/$keyfile: $!";
            while (<$pubfh>) {
                /from=/ and _err "spurious from='...' in $homedir/.ssh/$keyfile";
            }
            close($pubfh);
        }
    }
    close($dh);
}

sub check_file_rights {
    my $file           = shift;
    my $expectedOutput = shift;
    my $expectedmodes  = shift;
    my $expectedowner  = shift;
    my $expectedgroup  = shift;

    #info "checking rights of $file";
    delete $ALL_FILES{$file};
    my $ok = 1;

    if (not -e $file) {
        _err "file $file doesn't exist!";
        $ok = 0;
        return $ok;
    }

    if (!$hasacls) {
        my ($modes, $owner, $group) = (qx{ls -ld $file})[0] =~ m{(\S+)\s+\d+\s+(\S+)\s+(\S+)};    ## no critic (ProhibitBacktickOperators)
        if ($modes ne $expectedmodes) { $ok = 0; _err "on $file got $modes wanted $expectedmodes"; }
        if ($owner ne $expectedowner) { $ok = 0; _err "on $file got $owner wanted $expectedowner"; }
        if ($group ne $expectedgroup) { $ok = 0; _err "on $file got $group wanted $expectedgroup"; }
        return $ok;
    }

    my $param = ($islinux ? '-p' : '');
    my @out   = qx{getfacl $param $file 2>/dev/null};    ## no critic (ProhibitBacktickOperators)
    chomp @out;
    my $lineno = -1;
    $expectedOutput = [sort @$expectedOutput];
    @out            = grep { /./ } sort @out;
    foreach my $outLine (@out) {
        next if not $outLine;
        $lineno++;
        $outLine eq $expectedOutput->[$lineno] and next;
        $ok = 0;
        _err "rights of $file, line$lineno, expected '" . $expectedOutput->[$lineno] . "' but got '" . $outLine . "'";
    }
    if (@out != @$expectedOutput) {
        _err "rights of $file, number of lines unexpected (got " . @out . " instead of " . @$expectedOutput . ")";
        $ok = 0;
    }
    return $ok;
}

# now check what is in /home/key* and the rights
foreach my $file (@keyhomesfound) {
    delete $ALL_FILES{"/home/$file/.bash_logout"};
    delete $ALL_FILES{"/home/$file/.bashrc"};
    delete $ALL_FILES{"/home/$file/.profile"};
    delete $ALL_FILES{"/home/$file/.ssh"};
    delete $ALL_FILES{"/home/$file/.ssh/known_hosts"};

    # check rights of /home/keytruc
    if (-e "/home/$file") {
        if ($file ne 'keykeeper' and $file ne 'keyreader') {
            check_file_rights(
                "/home/$file",
                [
                    "# file: /home/$file",       "# owner: $file",
                    "# group: $file",            "user::rwx",
                    "group::r-x",                "group:osh-whoHasAccessTo:--x",
                    "group:osh-auditor:--x",     "group:osh-superowner:--x",
                    "group:$file-aclkeeper:--x", "group:$file-gatekeeper:--x",
                    "group:$file-owner:--x",     "mask::r-x",
                    "other::---",
                ],
                "drwxr-x--x",
                $file, $file
            );
        }
        else {
            check_file_rights(
                "/home/$file",
                [
                    "# file: /home/$file",
                    "# owner: $file",
                    "# group: $file",
                    "user::rwx",
                    "group::r-x",
                    $file eq 'keykeeper' ? "other::r-x" : "other::---",    # special dir /home/keykeeper is 755
                ],
                $file eq 'keykeeper' ? "drwxr-xr-x" : "drwxr-x---",
                $file,
                $file
            );
        }
    }
    else {
        _err "/home/$file doesn't exist";
    }
    next if (grep { $file eq "key$_" } @KEY_GROUPS_IGNORE);

    # check rights of /home/keytruc/allowed.ip
    if (-e "/home/$file/allowed.ip") {

        #not -s "/home/$file/allowed.ip" and _wrn "group $file has no servers";
        check_file_rights(
            "/home/$file/allowed.ip",
            [
                "# file: /home/$file/allowed.ip", "# owner: $file",
                "# group: $file-aclkeeper",       "user::rw-",
                "group::rw-",                     "other::r--",
            ],
            "-rw-rw-r--",
            $file,
            "$file-aclkeeper"
        );
    }
    else {
        _err "/home/$file/allowed.ip doesn't exist";
    }

    # check rights of /home/keykeeper/keytruc/
    if (-e "/home/keykeeper/$file") {
        check_file_rights(
            "/home/keykeeper/$file",
            [
                "# file: /home/keykeeper/$file", "# owner: keykeeper",
                "# group: $file",                "user::rwx",
                "group::r-x",                    "other::r-x",
            ],
            "drwxr-xr-x",
            "keykeeper",
            $file
        );
    }
    else {
        _err "/home/keykeeper/$file doesn't exist";
    }

    # check rights of /home/keykeeper/keytruc/id_*
    opendir(my $dh, "/home/keykeeper/$file") or die "/home/keykeeper/$file: $!";
    while (my $keyfile = readdir($dh)) {
        next unless $keyfile =~ /^id_/;    # spurious files will be reported below
        my $ret = check_file_rights(
            "/home/keykeeper/$file/$keyfile",
            [
                "# file: /home/keykeeper/$file/$keyfile",
                "# owner: keykeeper",
                "# group: $file",
                "user::r--", "group::r--", $keyfile =~ /\.pub$/ ? "other::r--" : "other::---",
            ],
            $keyfile =~ /\.pub$/ ? "-r--r--r--" : "-r--r-----",
            "keykeeper",
            $file
        );
        if ($keyfile !~ /\.pub$/) {
            if (not $ret) {

                # wow ! private key readable ?
                _crit "due to above error, private key /home/keykeeper/$file/$keyfile might be readable !!";
            }
        }
        else {
            # check for spurious "from" in .pub
            open(my $pubfh, '<', "/home/keykeeper/$file/$keyfile") or die "/home/keykeeper/$file/$keyfile: $!";
            while (<$pubfh>) {
                /from=/ and _err "spurious from='...' in /home/keykeeper/$file/$keyfile";
            }
            close($pubfh);
        }
    }
    close($dh);
}

# check some special dirs
check_file_rights(
    "/home/allowkeeper",
    [
        "# file: /home/allowkeeper", "# owner: allowkeeper", "# group: allowkeeper", "user::rwx",
        "group::r-x", "other::r-x",
    ],
    "drwxr-xr-x",
    "allowkeeper",
    "allowkeeper"
);
check_file_rights("/home/keykeeper",
    ["# file: /home/keykeeper", "# owner: keykeeper", "# group: keykeeper", "user::rwx", "group::r-x", "other::r-x",],
    "drwxr-xr-x", "keykeeper", "keykeeper");
check_file_rights("/home/logkeeper",
    ["# file: /home/logkeeper", "# owner: $UID0", "# group: bastion-users", "user::rwx", "group::-wx", "other::---",],
    "drwx-wx---", $UID0, "bastion-users");
check_file_rights("/home/passkeeper",
    ["# file: /home/passkeeper", "# owner: $UID0", "# group: $GID0", "user::rwx", "group::r-x", "other::r-x",],
    "drwxr-xr-x", $UID0, $GID0);
check_file_rights("/home/oldkeeper",
    ["# file: /home/oldkeeper", "# owner: $UID0", "# group: $GID0", "user::rwx", "group::---", "other::---",],
    "drwx------", $UID0, $GID0)
  if -e "/home/oldkeeper";

# now get all bastion users
my %users;
my %usersbyid;
setpwent();
while (my ($name, $passwd, $uid, $gid, $quota, $comment, $gcos, $home, $shell, $expire) = getpwent()) {
    if ($shell =~ /osh.pl$|diverter.sh$/) {
        if (exists $users{$name}) {
            _err "duplicate user $name";
        }
        if (exists $usersbyid{$uid}) {
            _err "duplicate uid for user $name";
        }
        if ($home ne "/home/$name") {
            _err "bad home for $name: $home";
        }
        if (!-d $home) {
            _err "home of $name doesn't exist ($home)";
        }
        $users{$name}    = {name => $name, uid => $uid, gid => $gid, shell => $shell};
        $usersbyid{$uid} = {name => $name, uid => $uid, gid => $gid, shell => $shell};
    }

    # TODO check who has shell access
}
info "found " . (scalar keys %users) . " bastion users";

my %groups;
my %usergroups;
setgrent();
while (my ($name, $passwd, $gid, $members) = getgrent()) {
    $groups{$name} = {name => $name, gid => $gid, members => [split(/ /, $members)]};
    foreach my $member (split(/ /, $members)) {
        push @{$usergroups{$member}}, $name;
    }
}

info "found " . (scalar keys %groups) . " groups";

# check that user keyreader is a member of all bastion users primary groups
my %keyreaderuserseen;
foreach my $group (@{$usergroups{'keyreader'}}) {
    $keyreaderuserseen{$group} = 1;
}
foreach my $user (keys %users) {
    next if (exists $keyreaderuserseen{$user});
    _err "user $user primary group doesn't have keyreader as member";
    if ($ENV{'FIX_KEYREADER'}) {
        system("usermod -a -G $user keyreader");
        _err "... fixed!";
    }
}

# check if user has /home/allowkeeper/testuser4/allowed.private
foreach my $account (keys %users) {
    check_file_rights(
        "/home/allowkeeper/$account",
        [
            "# file: /home/allowkeeper/$account", "# owner: allowkeeper",
            "# group: allowkeeper",               "user::rwx",
            "group::r-x",                         "other::r-x",
        ],
        "drwxr-xr-x",
        "allowkeeper",
        "allowkeeper"
    );
    check_file_rights(
        "/home/allowkeeper/$account/allowed.ip",
        [
            "# file: /home/allowkeeper/$account/allowed.ip", "# owner: allowkeeper",
            "# group: allowkeeper",                          "user::rw-",
            "group::r--",                                    "other::r--",
        ],
        "-rw-r--r--",
        "allowkeeper",
        "allowkeeper"
    );
    check_file_rights(
        "/home/allowkeeper/$account/allowed.private",
        [
            "# file: /home/allowkeeper/$account/allowed.private", "# owner: allowkeeper",
            "# group: allowkeeper",                               "user::rw-",
            "group::r--",                                         "other::r--",
        ],
        "-rw-r--r--",
        "allowkeeper",
        "allowkeeper"
    );
    if (!-e "/home/allowkeeper/$account/allowed.private" && $ENV{'FIX_MISSING_PRIVATE_FILES'}) {
        if (open(my $fh_priv, '>', "/home/allowkeeper/$account/allowed.private")) {
            close($fh_priv);
        }
        chmod 0644, "/home/allowkeeper/$account/allowed.private";
        my (undef, undef, $allowkeeperuid, $allowkeepergid) = getpwnam("allowkeeper");
        chown $allowkeeperuid, $allowkeepergid, "/home/allowkeeper/$account/allowed.private";
        _err "... fixed!";
    }

    # check all allowed.ip.GROUP symlinks
    my $dh;
    if (-d "/home/allowkeeper/$account") {
        opendir($dh, "/home/allowkeeper/$account");
        while (my $file = readdir($dh)) {
            if ($file =~ /^config\.[a-zA-Z0-9_-]+$/) {
                delete $ALL_FILES{"/home/allowkeeper/$account/$file"};
                next;
            }
            elsif ($file !~ /^allowed\.(ip|partial)\.([a-zA-Z0-9_-]+)$/) {
                next;
            }

            if (not grep { $2 eq $_ } keys %keygroupsbyname) {
                _err "file /home/allowkeeper/$account/$file has no corresponding known group";
            }
            if ($1 eq 'ip') {
                if (not -l "/home/allowkeeper/$account/$file") {
                    _err "file /home/allowkeeper/$account/$file should have been a symlink";
                }
            }
            elsif ($1 eq 'partial') {
                if (not -f "/home/allowkeeper/$account/$file") {
                    _err "file /home/allowkeeper/$account/$file should have been a plain file";
                }
            }
            else {
                _err "hmm, bug in the script ? got a '$1'";
            }
            delete $ALL_FILES{"/home/allowkeeper/$account/$file"};
        }
        close($dh);
    }
}

delete $ALL_FILES{'/home/allowkeeper'};
delete $ALL_FILES{'/home/allowkeeper/.bash_logout'};
delete $ALL_FILES{'/home/allowkeeper/.bashrc'};
delete $ALL_FILES{'/home/allowkeeper/.profile'};
delete $ALL_FILES{'/home/allowkeeper/.ssh'};
delete $ALL_FILES{'/home/allowkeeper/activeLogin.json'};
delete $ALL_FILES{'/home/allowkeeper/expirationGrant.json'};

if (keys %ALL_FILES) {
    _err "got some potentially unknown files:";
    print Dumper(sort keys %ALL_FILES);
}

# Expand a set of raw sudoers template lines into a list of normalized, atomic
# rules (one command per rule). The templates may use line continuations ("\" at
# the end of a line) and group several commands sharing the same
# account/group/runas tuple into a single comma-separated rule, to reduce the
# number of rules sudo has to parse, e.g.:
#    SUPEROWNERS, %GROUP%-owner ALL=(root) NOPASSWD: \
#        /path/helperA --group %GROUP% *, \
#        /path/helperB --group %GROUP% *
# while the per-helper "# KEYSUDOERS" declarations are always written as a single
# command per rule. Expanding both sides to the same atomic, whitespace-normalized
# form lets us compare them regardless of how the template is laid out. Comment
# and blank lines expand to nothing.
sub _expand_sudoers_rules {
    my @rawlines = @_;

    # first, join continuation lines together and drop comment/blank lines
    my @logical;
    my $current;
    foreach my $line (@rawlines) {
        if (!defined $current) {
            next if $line =~ /^\s*(?:#|$)/;
            $current = $line;
        }
        else {
            $line =~ s/^\s+//;
            $current .= " $line";
        }
        if ($current =~ s/\s*\\\s*$//) {
            next;    # the rule continues on the next line
        }
        push @logical, $current;
        undef $current;
    }
    push @logical, $current if defined $current;

    # then split each rule's comma-separated command list into atomic rules,
    # keeping the "user host=(runas) TAG:" prefix (which ends at the first colon)
    my @atomic;
    foreach my $rule (@logical) {
        my ($prefix, $commands) = $rule =~ /^(.*?:)\s*(.+)$/ or next;
        foreach my $command (split /\s*,\s*/, $commands) {
            my $atom = "$prefix $command";
            $atom =~ s/\s+/ /g;
            $atom =~ s/^\s+|\s+$//g;
            push @atomic, $atom;
        }
    }
    return @atomic;
}

# load a sudoers template directory (account or group), returning its raw lines.
# OS-specific templates (named xxx-name.os.sudoers) are skipped.
sub _load_sudoers_template {
    my $subdir = shift;
    my @lines;
    foreach my $tplfile (sort glob "$BASEDIR/etc/$subdir/*.sudoers") {
        next if basename($tplfile) =~ /\..+\.sudoers$/;    # OS-specific template, skip
        my $fh;
        if (!open($fh, '<', $tplfile)) {
            _err "can't open sudoers file template $tplfile to check: $!";
            next;
        }
        my @l = <$fh>;
        close($fh);
        chomp @l;
        push @lines, @l;
    }
    return @lines;
}

# compute the normalized, sudoers-alias-safe identifier the generator substitutes
# for %NORMACCOUNT% / %NORMGROUP%: uppercased, with every non-alphanumeric (and
# non-underscore) char turned into '_', suffixed with the first 6 hex chars of the
# md5 of the (raw) entity name.
sub _norm_name {
    my $name = shift;
    (my $norm = $name) =~ tr/[A-Za-z0-9_]/_/c;
    return uc($norm . '_' . substr(Digest::MD5::md5_hex($name), 0, 6));
}

# parse the sharded sudoers files for the given type ('account' or 'group') and
# return a hash mapping each entity name to the arrayref of raw lines of its block.
# Each shard file holds several blocks delimited by the markers the generator emits:
#     #>>> <type> <name>
#     ...rules...
#     #<<< <type> <name>
sub _read_sharded_sudoers {
    my $type = shift;
    my %blocks;
    foreach my $sudoersfile (sort glob "$sudoers_dir/osh-${type}s-shard-*") {
        my $fh;
        if (!open($fh, '<', $sudoersfile)) {
            _err "can't open $sudoersfile to check: $!";
            next;
        }
        my $name;
        while (my $line = <$fh>) {
            chomp $line;
            if ($line =~ /^#>>> \Q$type\E (.+)$/) {
                $name = $1;
                $blocks{$name} ||= [];
            }
            elsif ($line =~ /^#<<< \Q$type\E /) {
                undef $name;
            }
            elsif (defined $name) {
                push @{$blocks{$name}}, $line;
            }
        }
        close($fh);
    }
    return %blocks;
}

# verify that every sharded block of the given type contains all the rules of its
# template, and return the set of entity names that were seen (so the caller can
# in turn check that no expected entity is missing a block). $token is the template
# placeholder base, i.e. 'GROUP' (for %GROUP%/%NORMGROUP%) or 'ACCOUNT'.
sub _check_sharded_sudoers {
    my ($type, $subdir, $token) = @_;
    my @template = _load_sudoers_template($subdir);
    my %blocks   = _read_sharded_sudoers($type);
    my %seen;
    foreach my $name (sort keys %blocks) {
        $seen{$name} = 1;
        my $norm     = _norm_name($name);
        my @expected = map {
            my $line = $_;
            $line =~ s/%NORM\Q$token\E%/$norm/g;
            $line =~ s/%\Q$token\E%/$name/g;
            $line =~ s=%BASEPATH%=/opt/bastion=g;
            $line;
        } @template;

        # the template may group commands sharing the same tuple into a single
        # rule (continuations + comma lists), so compare on expanded atomic rules
        my %present = map { $_ => 1 } _expand_sudoers_rules(@{$blocks{$name}});
        foreach my $wantedrule (_expand_sudoers_rules(@expected)) {
            if (!$present{$wantedrule}) {
                _err "missing line in $type block '$name' (in $sudoers_dir/osh-${type}s-shard-*): $wantedrule";
            }
        }
    }
    return %seen;
}

# for new code, check sudo stuff
sub _tocheck {
    my $file       = shift;
    my $filesuffix = shift;
    my $tocheckref = shift;
    my %tocheck    = %$tocheckref;

    if (exists $tocheck{'NEEDGROUP'}) {
        my $group = $tocheck{'NEEDGROUP'}[0];
        my $gid   = getgrnam($group);
        if (not defined $gid) {
            _err "missing group $group";
        }
        elsif ($gid > 1000) {
            _err "group $group has a too high gid ($gid)";
        }
    }
    my @stat = stat($file);
    if (exists $tocheck{'FILEMODE'}) {
        my $mode = sprintf '%04o', $stat[2] & oct(7777);
        if ($mode ne $tocheck{'FILEMODE'}[0]) {
            _err "bad file mode on $file, got $mode but expected " . $tocheck{'FILEMODE'}[0];
        }
    }
    if (exists $tocheck{'FILEOWN'}) {
        my $uid       = $stat[4];
        my $gid       = $stat[5];
        my $wantuser  = (split / /, $tocheck{'FILEOWN'}[0])[0];
        my $wantgroup = (split / /, $tocheck{'FILEOWN'}[0])[1];
        $wantuser  = $UID0 if ($wantuser eq 'root'  || $wantuser eq '0');
        $wantgroup = $GID0 if ($wantgroup eq 'root' || $wantgroup eq '0');
        my $wantuid = getpwnam($wantuser);
        my $wantgid = getgrnam($wantgroup);

        if ($uid ne $wantuid) {
            _err "bad owner on file $file (got $uid but wanted $wantuid aka $wantuser)";
        }
        if ($gid ne $wantgid) {
            _err "bad group on file $file (got $gid but wanted $wantgid aka $wantgroup)";
        }
    }
    if (exists $tocheck{'SUDOERS'}) {
        my $sudoersfile = "$sudoers_dir/osh-plugin-" . $filesuffix;
        if (not -f $sudoersfile) {
            _err "sudoers file $sudoersfile doesn't exists";
        }
        else {
            my $mode = sprintf '%04o', (stat($sudoersfile))[2] & oct(7777);
            if ($mode ne "0440") {
                _err "sudoers file $sudoersfile has a bad mode $mode";
            }
            if (!open(my $fh_sudoers, '<', $sudoersfile)) {
                _err "can't open sudoers file $sudoersfile to check: $!";
            }
            else {
                my @contents = <$fh_sudoers>;
                close($fh_sudoers);
                chomp @contents;
                foreach my $wantedline (@{$tocheck{'SUDOERS'}}) {
                    if (not grep { $_ eq $wantedline } @contents) {
                        _err "missing line in plugin $sudoersfile: $wantedline";
                    }
                }
            }
        }
    }
    if (exists $tocheck{'KEYSUDOERS'}) {
        my @contents;
        foreach my $sudoersfile (sort <$BASEDIR/etc/sudoers.group.template.d/*>) {
            if (!open(my $fh_sudoers, '<', $sudoersfile)) {
                _err "can't open sudoers file template $sudoersfile to check: $!";
            }
            else {
                my @lines = <$fh_sudoers>;
                close($fh_sudoers);
                chomp @lines;
                push @contents, @lines;
            }
        }
        if (@contents) {
            # expand the (possibly grouped/multi-line) template into atomic rules
            my %templaterules = map { $_ => 1 } _expand_sudoers_rules(@contents);
            foreach my $wantedline (@{$tocheck{'KEYSUDOERS'}}) {
                $wantedline =~ s'@KEYGROUP@'%GROUP%'g;

                # a KEYSUDOERS declaration may be a documentation comment rather
                # than an actual rule: those expand to nothing and are skipped
                foreach my $wantedrule (_expand_sudoers_rules($wantedline)) {
                    if (!$templaterules{$wantedrule}) {
                        _err "missing line in plugin sudoers.group.template: $wantedline";
                    }
                }
            }
        }
    }
    foreach my $key (qw{ FILEMODE FILEOWN SUDOERS NEEDGROUP KEYSUDOERS }) {
        delete $tocheck{$key};
    }
    if (keys %tocheck) {
        _err "hum sparse tocheck key: " . join(" ", sort keys %tocheck);
    }

    return 1;
}

while (my $file = glob "$BASEDIR/bin/helper/*") {
    my ($filesuffix) = $file =~ m{/osh-([a-zA-Z0-9_-]+$)};
    if (!$filesuffix) {
        _err "helper file has a strange name ($file)";
        next;
    }
    my $fh_helper;
    if (!open($fh_helper, '<', $file)) {
        _err "can't open helper file $file to check: $!";
        next;
    }
    my %tochecklocal;
    while (<$fh_helper>) {
        /^#/ or last;
        if (/^\s*#\s*$/) {
            _tocheck($file, $filesuffix, \%tochecklocal);
            %tochecklocal = ();
            next;
        }
        /^# ([A-Z0-9]+) (.+)$/ or next;
        my ($keyword, $line) = ($1, $2);
        push @{$tochecklocal{$keyword}}, $line;
    }
    close($fh_helper);

    if (%tochecklocal) {
        _tocheck($file, $filesuffix, \%tochecklocal);
    }
}

# check /etc/sudoers.d vs $BASEDIR/etc/sudoers.d
# FIXME won't see if we have too many / old files in /etc/sudoers.d
while (my $distfile = glob "$BASEDIR/etc/sudoers.d/*") {
    my $prodfile = $distfile;
    $prodfile =~ s=^\Q$BASEDIR\E/etc/sudoers.d=$sudoers_dir=;
    if (-e $prodfile) {
        my @md5sums;
        foreach my $file ($prodfile, $distfile) {
            if (open(my $fh, '<', $file)) {
                binmode($fh);
                push @md5sums, Digest::MD5->new->addfile($fh)->hexdigest;
                close($fh);
            }
            else {
                push @md5sums, "ERR($file)";
            }
        }
        if ($md5sums[0] ne $md5sums[1]) {
            _err "sudoers file $distfile and $prodfile differ";
        }
    }
    elsif ($prodfile !~ /optional/) {
        _err "sudoers file $prodfile not found";
    }
}

# check the per-entity sudoers blocks. Both accounts and groups are now sharded:
# instead of one file per entity, the generator writes a handful of
# "osh-accounts-shard-NN" / "osh-groups-shard-NN" files, each holding several
# entity blocks (see _check_sharded_sudoers / _read_sharded_sudoers above).
{
    # groups: the block name is the full unix key-group name (e.g. "keymygroup"),
    # which is exactly what %GROUP% expands to in the template
    my %seengroups = _check_sharded_sudoers('group', 'sudoers.group.template.d', 'GROUP');
    foreach my $group (keys %keygroupsbyname) {
        next if $seengroups{"key$group"};
        _err "missing sudoers block for key group 'key$group' in $sudoers_dir/osh-groups-shard-*";
    }

    # accounts: there's one block per bastion account, i.e. each account whose
    # login shell is the bastion's osh.pl (this mirrors how the generator decides
    # which accounts get a sudoers entry)
    my %seenaccounts = _check_sharded_sudoers('account', 'sudoers.account.template.d', 'ACCOUNT');
    foreach my $line (qx{getent passwd}) {    ## no critic (ProhibitBacktickOperators)
        chomp $line;
        my ($account, $shell) = (split /:/, $line)[0, 6];
        next if !defined $shell || $shell ne '/opt/bastion/bin/shell/osh.pl';
        next if $seenaccounts{$account};
        _err "missing sudoers block for account '$account' in $sudoers_dir/osh-accounts-shard-*";
    }
}

exit($bad > 255 ? 255 : $bad);
