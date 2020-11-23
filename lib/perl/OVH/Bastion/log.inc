# vim: set filetype=perl ts=4 sw=4 sts=4 et:
package OVH::Bastion;

use common::sense;

use DBD::SQLite;
use Time::HiRes;
use Sys::Syslog qw();

my $_syslog_inited = 0;    # lazy init

sub syslog {
    my ($criticity, $message) = @_;

    if (not OVH::Bastion::config('enableSyslog')->value()) {
        return 1;          # don't do anything
    }

    if (not $_syslog_inited) {
        $_syslog_inited = 1;
        Sys::Syslog::openlog(OVH::Bastion::config('syslogDescription')->value(), 'nofatal', OVH::Bastion::config('syslogFacility')->value());
    }

    # if message is tainted, forcefully untaint it
    # or we'll crash and we won't even log that
    # we crashed because it's tainted so we would
    # crash trying to log the crash
    ($message) = $message =~ /^(.*)$/;
    eval { Sys::Syslog::syslog($criticity, $message); };
    if ($@) {
        osh_warn("Couldn't syslog, report to administrator ($@)");
    }
    return 1;
}

sub syslog_close {
    if ($_syslog_inited) {
        Sys::Syslog::closelog();
        $_syslog_inited = 0;
    }
}

END {
    syslog_close();
}

sub syslogFormatted {
    my %params    = @_;
    my $criticity = $params{'criticity'} || 'info';
    my $type      = $params{'type'} || 'unknown';
    my $fields    = $params{'fields'};

    if (ref $fields ne 'ARRAY') {
        my $error = "bad call to syslogFormatted, invalid fields parameter";
        warn($error);    # this will in turn log into syslog with the trace() thanks to the SIG{'WARN'} handler
        return R('INTERNAL_ERROR', msg => $error);
    }

    unshift @$fields, ['gid', ((split(/ /, $)))[0])];
    unshift @$fields, ['uid',       $>];
    unshift @$fields, ['sudo_user', $ENV{'SUDO_USER'}];
    unshift @$fields, ['sysuser',   OVH::Bastion::get_user_from_env()->value];
    unshift @$fields, ['ppid',      getppid()];
    unshift @$fields, ['pid',       $$];
    unshift @$fields, ['version',   $OVH::Bastion::VERSION];
    unshift @$fields, ['uniqid', ($ENV{'UNIQID'} || '-')];

    my @msg = ($type);
    if (($type eq 'die' || $type eq 'warn') && $criticity eq 'info') {

        # in that case, "downgrade" the criticity of the message
        @msg = ("$type-$criticity");
    }

    foreach my $item (@$fields) {

        # each @$fields item is a 2-dimensional array for key => value
        if (ref $item ne 'ARRAY') {
            my $error = "bad call to syslogFormatted, invalid item in fields (ref " . (ref $item) . ")";
            warn($error);
            return R('INTERNAL_ERROR', msg => $error);
        }
        my ($key, $value) = @$item;

        # remove any \n in the value
        $value =~ s/\n/ /g;

        # replace any \ by an escaped \ aka \\
        $value =~ s{\\}{\\\\}g;

        # replace any " by \"
        $value =~ s{"}{\\"}g;
        push @msg, qq{$key="$value"};
    }

    my $flatmsg = join(" ", @msg);
    OVH::Bastion::syslog($criticity, $flatmsg);
    return R('OK', value => $flatmsg);
}

sub warn_syslog {
    my $msg = shift;
    return syslogFormatted(
        type   => 'code-warning',
        fields => [['msg' => $msg]]
    );
}

sub _sql_update_db {
    my %params  = @_;
    my $sqltype = $params{'sqltype'};
    my $dbh     = $params{'dbh'};
    my $sth;
    my $result;
    my $fnret;

    $dbh->do("PRAGMA synchronous=0");

    # get current user_version of db
    $sth = $dbh->prepare("PRAGMA user_version");
    return R('KO', msg => "getting user_version (prepare)") if not $sth;

    $result = $sth->execute();
    return R('KO', msg => "getting user_version (execute)") if not $result;

    my $user_version = $sth->fetchrow_array();

    if ($user_version <= 0) {

        # set journal_mode, this is a no-op if already in WAL
        if (!$dbh->do("PRAGMA journal_mode=WAL")) {
            return R('KO', msg => "setting journal mode");
        }

        # create table
        $result = $dbh->do(
            $sqltype eq 'local'
            ? "CREATE TABLE IF NOT EXISTS connections(
                id        INTEGER PRIMARY KEY,
                timestamp INTEGER,
                timestampusec INTEGER,
                account   TEXT,
                cmdtype   TEXT,
                allowed   INTEGER,
                hostfrom  TEXT,
                ipfrom    TEXT,
                portfrom  INTEGER,
                bastionip TEXT,
                bastionport INTEGER,
                hostto    TEXT,
                ipto      TEXT,
                portto    INTEGER,
                user      TEXT,
                plugin    TEXT,
                ttyrecfile TEXT,
                ttyrecsize INTEGER,
                params    TEXT,
                timestampend INTEGER,
                timestampendusec INTEGER,
                returnvalue  INTEGER,
                comment TEXT,
                uniqid  TEXT)"
            : "CREATE TABLE IF NOT EXISTS connections_summary(
                    id        INTEGER PRIMARY KEY,
                    timestamp INTEGER,
                    account   TEXT,
                    cmdtype   TEXT,
                    allowed   INTEGER,
                    ipfrom    TEXT,
                    ipto      TEXT,
                    portto    INTEGER,
                    user      TEXT,
                    plugin    TEXT,
                    uniqid    TEXT)"
        );
        return R('KO', msg => "creating table ($sqltype)") if not $result;

        # create indexes if needed
        my @columns = (
            $sqltype eq 'local'
            ? qw{ timestamp ipto uniqid }
            : qw{ timestamp ipto uniqid }
        );
        my $table = ($sqltype eq 'local' ? "connections" : "connections_summary");
        foreach my $column (@columns) {
            $dbh->do("CREATE INDEX IF NOT EXISTS idx_$column ON $table ($column)")
              or return R('KO', msg => "creating index idx_$column on $table");
        }

        $dbh->do("PRAGMA user_version=1")
          or return R('KO', msg => "setting user_version to 1");
        $user_version = 1;
    }

    # endof version==0

    if ($user_version == 1) {
        ;    # insert here future schema modifications
    }

    return R('OK', msg => "sql update done");
}

sub _sql_log_insert_file {

    # don't call me directly, use sql_log_insert() !
    my %params        = @_;
    my $file          = $params{'file'};
    my $account       = $params{'account'};
    my $cmdtype       = $params{'cmdtype'};
    my $allowed       = $params{'allowed'};
    my $hostfrom      = $params{'hostfrom'};
    my $ipfrom        = $params{'ipfrom'};
    my $portfrom      = $params{'portfrom'};
    my $bastionip     = $params{'bastionip'};
    my $bastionport   = $params{'bastionport'};
    my $hostto        = $params{'hostto'};
    my $ipto          = $params{'ipto'};
    my $portto        = $params{'portto'};
    my $user          = $params{'user'};
    my $plugin        = $params{'plugin'};
    my $params        = $params{'params'};
    my $comment       = $params{'comment'};
    my $ttyrecfile    = $params{'ttyrecfile'};
    my $timestamp     = $params{'timestamp'};
    my $timestampusec = $params{'timestampusec'};
    my $uniqid        = $params{'uniqid'};
    my $sqltype       = $params{'sqltype'};

    if ($sqltype ne 'local' and $sqltype ne 'global') {
        return R('ERR_INVALID_PARAMETER', msg => "Invalid parameter sqltype");
    }

    if ($sqltype eq 'global') {

        # create the file ourselves, and set it rw rw rw (for global log)
        # -journal -shm and -wal files are created with same perms by sqlite
        OVH::Bastion::touch_file($file, 0666);
    }

    # big db-related retry block:
    # open db, set journal_mode, create table if not exists, insert data
    # opendb usually always works
    # journal_mode can get you a weird transient error on high concurrency (such as "failed to open database")
    # same for create and insert (such as "attempted to write on readonly database")
    # ... so we'll retry up to 20 times if any error arises, starting from the beginning,
    # to ensure we're not locked with a readonly-$dbh for some obscure race-condition-related reason
    my ($dbh, $sth, $result, $doing);
    foreach my $retry (0 .. 19) {

        # if we're retrying, sleep a bit before, to ease concurrency
        select(undef, undef, undef, $retry / 50 + rand() / 10) if $retry;

        # on each retry, clean those vars (undef $dbh disconnects if connected)
        undef $dbh;
        undef $sth;
        undef $result;
        undef $doing;

        # connect to db
        $dbh = DBI->connect("dbi:SQLite:dbname=$file", "", "", {PrintError => 0, RaiseError => 0});
        if (!$dbh) {
            $doing = "opening database";
            next;    # retry
        }

        my $fnret = _sql_update_db(dbh => $dbh, sqltype => $sqltype);
        if (!$fnret) {
            $doing = $fnret->msg;
            next;    # retry
        }

        # preparing data insertion query
        my $prepare;
        my @execute;
        if ($sqltype eq 'local') {
            $prepare = "INSERT INTO connections
(uniqid,timestamp,timestampusec,account,cmdtype,allowed,hostfrom,ipfrom,portfrom,bastionip,bastionport,hostto,ipto,portto,user,plugin,params,comment,ttyrecfile)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
            @execute = (
                $uniqid,      $timestamp, $timestampusec, $account, $cmdtype, $allowed, $hostfrom, $ipfrom,  $portfrom, $bastionip,
                $bastionport, $hostto,    $ipto,          $portto,  $user,    $plugin,  $params,   $comment, $ttyrecfile
            );
        }
        elsif ($sqltype eq 'global') {
            $prepare = "INSERT INTO connections_summary (uniqid,timestamp,account,cmdtype,allowed,ipfrom,ipto,portto,user,plugin)
VALUES (?,?,?,?,?,?,?,?,?,?)";
            @execute = ($uniqid, $timestamp, $account, $cmdtype, $allowed, $ipfrom, $ipto, $portto, $user, $plugin);
        }

        # prepare insertion on db
        $sth = $dbh->prepare($prepare);
        if (!$sth) {
            $doing = "inserting data (prepare)";
            next;    # retry
        }

        # execute insertion
        $result = $sth->execute(@execute);
        if (!$result) {
            $doing = "inserting data (execute)";
            next;    # retry
        }

        # if we're here, it worked, stop retrying
        last;
    }

    # if this is set, we probably reached max retry in previous loop without succeeding
    if ($DBI::err) {

        warn_syslog("Failed after multiple retries [$sqltype] err $DBI::err while doing [$doing]: $DBI::errstr");
        return R('ERR_SQL_EXECUTE', msg => "SQL error [$sqltype] err $DBI::err while doing [$doing]: $DBI::errstr");
    }

    return R('OK', value => {id => $dbh->last_insert_id("", "", "", "")});
}

sub log_access_insert {
    my %params  = @_;
    my $account = $params{'account'};
    my $uniqid  = $params{'uniqid'} || $ENV{'UNIQID'};
    my $loghome = $params{'loghome'};                    # only used for proxyhttp
    my $custom  = $params{'custom'};                     # only used for proxyhttp, not pushed to sql
    my $fnret;

    if (not defined $account) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing parameter 'account'");
    }

    $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $account);
    $fnret or return $fnret;

    $account = $fnret->value->{'account'};
    my $sysaccount    = $fnret->value->{'sysaccount'};
    my $remoteaccount = $fnret->value->{'remoteaccount'};

    $loghome ||= $sysaccount;

    $params{'account'} = $account;
    $params{'loghome'} = $loghome;

    if (not defined $uniqid) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing parameter 'uniqid'");
    }

    if (not defined $params{'bastionhost'} and defined $params{'bastionip'}) {
        $params{'bastionhost'} = OVH::Bastion::ip2host($params{'bastionip'})->value;
    }
    if (not defined $params{'hostto'} and defined $params{'ipto'}) {
        $params{'hostto'} = OVH::Bastion::ip2host($params{'ipto'})->value;
    }
    if (not defined $params{'hostfrom'} and defined $params{'ipfrom'}) {
        $params{'hostfrom'} = OVH::Bastion::ip2host($params{'ipfrom'})->value;
    }

    my ($timestamp, $timestampusec) = Time::HiRes::gettimeofday();
    $params{'timestamp'}     = $timestamp;
    $params{'timestampusec'} = $timestampusec;

    my @localtime      = localtime(time());
    my $sqlfile_global = sprintf("/home/logkeeper/global-log-%04d.sqlite", $localtime[5] + 1900);
    my $sqlfile_account =
      sprintf("/home/%s/%s-log-%04d%02d.sqlite", $params{'loghome'}, $remoteaccount || $loghome, $localtime[5] + 1900, $localtime[4] + 1);

    # first, log in account sql file
    my ($insert_id, $db_name);
    if (OVH::Bastion::config('enableAccountSqlLog')->value()) {
        $params{'file'}    = $sqlfile_account;
        $params{'sqltype'} = 'local';
        $fnret             = _sql_log_insert_file(%params);
        if ($fnret) {
            ($insert_id, $db_name) = ($fnret->value->{'id'}, $params{'file'});
        }
    }

    # then, syslog, we'll also say if the sqlinsert failed
    my @fields = (
        ['account', $account],
        ['cmdtype', $params{'cmdtype'}],
        ['allowed', ($params{'allowed'} ? 'true' : 'false')],
        ['ip_from',      $params{'ipfrom'}],
        ['port_from',    $params{'portfrom'}],
        ['host_from',    $params{'hostfrom'}],
        ['ip_bastion',   $params{'bastionip'}],
        ['port_bastion', $params{'bastionport'}],
        ['host_bastion', $params{'bastionhost'}],
        ['user',         $params{'user'}],
        ['ip_to',        $params{'ipto'}],
        ['port_to',      $params{'portto'}],
        ['host_to',      $params{'hostto'}],
        ['plugin',       $params{'plugin'}],
        ['comment',      $params{'comment'}],
        ['sqlfile', ($fnret ? '' : 'ERR:') . $params{'file'}],
        ['params', $params{'params'}],
    );
    if (ref $custom eq 'ARRAY') {
        foreach my $item (@$custom) {
            push @fields, $item if (ref $item eq 'ARRAY' && @$item == 2);
        }
    }
    $fnret = OVH::Bastion::syslogFormatted(
        criticity => 'info',
        type      => 'open',
        fields    => \@fields,
    );
    my $msg = '(empty)';
    $msg = $fnret->value if $fnret;

    # then, log in oldschool files
    if (OVH::Bastion::config('enableAccountAccessLog')->value()) {
        if (open(my $log_acc, ">>", sprintf("/home/%s/%s-log-%04d%02d.log", $params{'loghome'}, $remoteaccount || $loghome, $localtime[5] + 1900, $localtime[4] + 1))) {
            print $log_acc localtime() . " $msg\n";
            close($log_acc);
        }
    }
    if (OVH::Bastion::config('enableGlobalAccessLog')->value()) {
        if (open(my $log_gen, ">>", "/home/osh.log")) {
            print $log_gen localtime() . " $msg\n";
            close($log_gen);
        }
    }

    # then global sql
    if (OVH::Bastion::config('enableGlobalSqlLog')->value()) {
        $params{'file'}    = $sqlfile_global;
        $params{'sqltype'} = 'global';
        $fnret             = _sql_log_insert_file(%params);
    }

    return R('OK', value => {insert_id => $insert_id, db_name => $db_name, uniq_id => $params{'uniqid'}});
}

sub _sql_log_update_file {
    my %params           = @_;
    my $file             = $params{'file'};
    my $id               = $params{'id'};
    my $returnvalue      = $params{'returnvalue'};
    my $comment          = $params{'comment'};
    my $timestampend     = $params{'timestampend'};
    my $timestampendusec = $params{'timestampendusec'};
    my $ttyrecsize       = $params{'ttyrecsize'};

    my $plugin_stdout = $params{'plugin_stdout'};
    my $plugin_stderr = $params{'plugin_stderr'};

    if (not $file or not defined $id) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing required parameter file or id");
    }
    if (!-w $file) {
        return R('ERR_FILE_NOT_FOUND', msg => "File $file should already exist");
    }

    my ($dbh, $sth, $result, $doing);

    # retry block
    foreach my $retry (0 .. 19) {

        # if we're retrying, sleep a bit before, to ease concurrency
        select(undef, undef, undef, $retry / 50 + rand() / 10) if $retry;

        # on each retry, clean those vars (undef $dbh disconnects if connected)
        undef $dbh;
        undef $sth;
        undef $result;
        undef $doing;

        # connect to db
        $dbh = DBI->connect("dbi:SQLite:dbname=$file", "", "", {PrintError => 0, RaiseError => 0});
        if (!$dbh) {
            $doing = "opening database";
            next;    # retry
        }

        my $prepare = "UPDATE connections SET timestampend=?, timestampendusec=?, returnvalue=?";
        my @execute = ($timestampend, $timestampendusec, $returnvalue);

        if (defined $comment) {
            $prepare .= ", comment=?";
            push @execute, $comment;
        }
        if (defined $ttyrecsize) {
            $prepare .= ", ttyrecsize=?";
            push @execute, $ttyrecsize;
        }
        $prepare .= " WHERE id=? AND timestampend IS NULL";
        push @execute, $id;

        # prepare insertion on db
        $sth = $dbh->prepare($prepare);
        if (!$sth) {
            $doing = "updating data (prepare)";
            next;    # retry
        }

        # execute insertion
        $result = $sth->execute(@execute);
        if (!$result) {
            $doing = "updating data (execute)";
            next;    # retry
        }

        # if we're here, it worked, stop retrying
        last;
    }

    # if this is set, we probably reached max retry in previous loop without succeeding
    if ($DBI::err) {
        warn("Failed after multiple retries [updating] err $DBI::err while doing [$doing]: $DBI::errstr");
        return R('ERR_SQL_EXECUTE', msg => "SQL error [updating] err $DBI::err while doing [$doing]: $DBI::errstr");
    }

    # if we have plugin stdout or stderr, log it too
    if (defined $plugin_stdout or defined $plugin_stderr) {

        # retry block
        foreach my $retry (0 .. 19) {

            # if we're retrying, sleep a bit before, to ease concurrency
            select(undef, undef, undef, $retry / 50 + rand() / 10) if $retry;

            # on each retry, clean those vars (undef $dbh disconnects if connected)
            undef $dbh;
            undef $sth;
            undef $result;
            undef $doing;

            # connect to db
            $dbh = DBI->connect("dbi:SQLite:dbname=$file", "", "", {PrintError => 0, RaiseError => 0});
            if (!$dbh) {
                $doing = "opening database";
                next;    # retry
            }

            $sth = $dbh->prepare(
                "CREATE TABLE IF NOT EXISTS plugincalls(
                    id        INTEGER PRIMARY KEY,
                    connection_id INTEGER UNIQUE,
                    stdout    TEXT,
                    stderr    TEXT)
                "
            );
            if (!$sth) {
                $doing = "creating plugins table (prepare)";
                next;    # retry
            }
            $result = $sth->execute();
            if (!$result) {
                $doing = "creating plugins table (execute)";
                next;    # retry
            }

            $sth = $dbh->prepare("INSERT INTO plugincalls (connection_id, stdout, stderr) VALUES (?,?,?)");
            if (!$sth) {
                $doing = "inserting plugincall data (prepare)";
                next;    # retry
            }
            $result = $sth->execute($id, join("\n", @{$plugin_stdout || []}), join("\n", @{$plugin_stderr || []}));
            if (!$result) {
                $doing = "inserting plugincall data (execute)";
                next;    # retry
            }

            # if we're here, it worked, stop retrying
            last;
        }

        # if this is set, we probably reached max retry in previous loop without succeeding
        if ($DBI::err) {

            warn("Failed after multiple retries [plugins] err $DBI::err while doing [$doing]: $DBI::errstr");
            return R('ERR_SQL_EXECUTE', msg => "SQL error [plugins] err $DBI::err while doing [$doing]: $DBI::errstr");
        }
    }

    return R('OK');
}

sub log_access_update {
    my %params    = @_;
    my $insert_id = $params{'insert_id'};
    my $db_name   = $params{'db_name'};
    my $uniq_id   = $params{'uniq_id'};

    if (not defined $params{'timestampend'} or not defined $params{'timestampendusec'}) {
        ($params{'timestampend'}, $params{'timestampendusec'}) = Time::HiRes::gettimeofday();
    }

    # in any case, send a syslog even if we miss insert_id or db_name
    OVH::Bastion::syslogFormatted(
        criticity => 'info',
        type      => 'close',
        fields    => [

            # TODO: in addition to the specific "on-close" fields, we should re-log here everything
            # that was logged in the log_access_insert call for easier SIEM analytics
            ['sysret',        $params{'returnvalue'}],
            ['ttyrec_size',   $params{'ttyrecsize'}],
            ['comment_close', $params{'comment'}],
        ]
    );

    if (not defined $insert_id or not defined $db_name) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing required 'insert_id' or 'db_name'");
    }

    $params{'file'} = $db_name;
    $params{'id'}   = $insert_id;

    if (OVH::Bastion::config('enableAccountSqlLog')->value()) {
        return _sql_log_update_file(%params);
    }
    return R('OK');
}

sub log_access_get {
    my %params  = @_;
    my $account = $params{'account'};
    my $fnret;

    if (not defined $account) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing parameter 'account'");
    }

    $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $account);
    $fnret or return $fnret;
    $account = $fnret->value->{'account'};
    $params{'account'} = $account;

    my ($timestamp, $timestampusec) = Time::HiRes::gettimeofday();
    $params{'timestamp'}     = $timestamp;
    $params{'timestampusec'} = $timestampusec;

    my @localtime = localtime(time());

    # first, check in account sql file
    if (OVH::Bastion::config('enableAccountSqlLog')->value()) {
        $params{'file'} = sprintf("/home/%s/%s-log-%04d%02d.sqlite", $params{'account'}, $params{'account'}, $localtime[5] + 1900, $localtime[4] + 1), $params{'sqltype'} = 'local';
        $fnret = _sql_log_fetch_from_file(%params);
        return $fnret;
    }

    # second, check in global sql file

=cut not now, too slow and table columns differ
    if (OVH::Bastion::config('enableGlobalSqlLog')->value()) {
        $params{'file'}    = sprintf("/home/logkeeper/global-log-%04d.sqlite", $localtime[5] + 1900),
        $params{'sqltype'} = 'global',
        $fnret             = _sql_log_fetch_from_file(%params);
        return $fnret;
    }
=cut

    return R('ERR_DISABLED', msg => "This feature is not available");
}

sub _sql_log_fetch_from_file {

    # don't call me directly, use log_access_get() !
    my %params      = @_;
    my $file        = $params{'file'};
    my $sqltype     = $params{'sqltype'};
    my $limit       = $params{'limit'};
    my $uniqid      = $params{'uniqid'};
    my $account     = $params{'account'};
    my $cmdtype     = $params{'cmdtype'};
    my $allowed     = $params{'allowed'};
    my $ipfrom      = $params{'ipfrom'};
    my $ipto        = $params{'ipto'};
    my $portto      = $params{'portto'};
    my $bastionip   = $params{'bastionip'};
    my $bastionport = $params{'bastionport'};
    my $user        = $params{'user'};
    my $plugin      = $params{'plugin'};
    my $before      = $params{'before'};
    my $after       = $params{'after'};

    foreach my $param (qw{ limit before after }) {
        if (defined $params{$param} and $params{$param} !~ /^\d+$/) {
            return R('ERR_INVALID_PARAMETER', msg => "Expected a numeric $param");
        }
    }

    my @conditions;
    my @execvalues;
    if ($account) {
        push @conditions, "account = ?";
        push @execvalues, $account;
    }
    if ($cmdtype) {
        push @conditions, "cmdtype = ?";
        push @execvalues, $cmdtype;
    }
    if (defined $allowed) {
        push @conditions, "allowed = ?";
        push @execvalues, $allowed ? 1 : 0;
    }
    if ($uniqid) {
        push @conditions, "uniqid = ?";
        push @execvalues, $uniqid;
    }
    if ($user) {
        push @conditions, "user = ?";
        push @execvalues, $user;
    }
    if ($plugin) {
        push @conditions, "plugin = ?";
        push @execvalues, $plugin;
    }
    if ($ipto) {
        push @conditions, "ipto = ?";
        push @execvalues, $ipto;
    }
    if ($portto) {
        push @conditions, "portto = ?";
        push @execvalues, $portto;
    }
    if ($ipfrom) {
        push @conditions, "ipfrom = ?";
        push @execvalues, $ipfrom;
    }
    if ($bastionip) {
        push @conditions, "bastionip = ?";
        push @execvalues, $bastionip;
    }
    if ($bastionport) {
        push @conditions, "bastionport = ?";
        push @execvalues, $bastionport;
    }
    if ($before) {
        push @conditions, "timestamp <= ?";
        push @execvalues, $before;
    }
    if ($after) {
        push @conditions, "timestamp >= ?";
        push @execvalues, $after;
    }

    my $tablename;
    if ($sqltype eq 'local') {
        $tablename = 'connections';
    }
    elsif ($sqltype eq 'global') {
        $tablename = 'connections_summary';
    }
    else {
        return R('ERR_INVALID_PARAMETER', msg => "Unknown sqltype");
    }

    my $prepare = "SELECT * FROM $tablename WHERE (" . join(') AND (', @conditions) . ") ORDER BY id DESC";

    if ($limit) {
        $prepare .= " LIMIT ?";
        push @execvalues, $limit;
    }

    my $openflags = {PrintError => 0, RaiseError => 0};
    if ($DBD::SQLite::VERSION ge '1.42') {
        eval { $openflags->{'sqlite_open_flags'} = DBD::SQLite::OPEN_READONLY(); };
    }

    # big db-related retry block (see comment on _sql_log_insert_file)
    my ($dbh, $result, $doing);
    foreach my $retry (0 .. 19) {

        # if we're retrying, sleep a bit before, to ease concurrency
        select(undef, undef, undef, $retry / 50 + rand() / 10) if $retry;

        # on each retry, clean those vars (undef $dbh disconnects if connected)
        undef $dbh;
        undef $result;
        undef $doing;

        # connect to db
        $dbh = DBI->connect("dbi:SQLite:dbname=$file", "", "", $openflags);
        if (!$dbh) {
            $doing = "opening database";
            next;    # retry
        }

        # fetch data
        $result = $dbh->selectall_hashref($prepare, 'id', {}, @execvalues);
        if (!$result) {
            $doing = "querying data";
            next;    # retry
        }

        # if we're here, it worked, stop retrying
        last;
    }

    # if this is set, we probably reached max retry in previous loop without succeeding
    if ($DBI::err) {

        warn("Failed after multiple retries [$sqltype] err $DBI::err while doing [$doing]: $DBI::errstr");
        return R('ERR_SQL_EXECUTE', msg => "SQL error [$sqltype] err $DBI::err while doing [$doing]: $DBI::errstr");
    }

    return R('OK', value => $result);
}

1;
