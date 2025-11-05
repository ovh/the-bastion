package OVH::Bastion::ProxyHTTP;

# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

use File::Basename;
use lib dirname(__FILE__) . '/../../../../lib/perl';
use OVH::Result;
use OVH::Bastion;

use CGI;
use JSON;
use Fcntl       qw(:flock);
use Time::HiRes ();
use MIME::Base64;
use Net::Server::PreForkSimple;
use Net::Server::PreFork;
use Sys::Hostname;
use Storable qw{ thaw };
use base     qw{Net::Server::HTTP};

###########################
# BE CAREFUL IN THIS CLASS: STDIN && STDOUT are bound to the server->client socket
# of the current request, in other words, everything that is printed to stdout goes
# to the network, this is NOT the case with stderr

# override Net::Server::HTTP::send_status, because it hardcodes content-type: text/html,
# and there's no way for the caller to prevent that :(
sub send_status {
    my ($self, $status, $msg, $body) = @_;
    $msg ||= ($status == 200) ? 'OK' : '-';
    my $request_info = $self->{'request_info'};

    my $content_type_already_sent = 0;
    my $want_gzip                 = 0;
    my $out                       = "HTTP/1.0 $status $msg\r\n";
    foreach my $row (@{$self->http_base_headers}) {
        $out .= "$row->[0]: $row->[1]\r\n";
        push @{$request_info->{'response_headers'}}, $row;
        $content_type_already_sent++ if (lc($row->[0]) eq 'content-type');
        $want_gzip++                 if (lc($row->[0]) eq 'content-encoding' && $row->[1] =~ /gzip/);
    }
    $self->{'server'}->{'client'}->print($out);
    $request_info->{'http_version'}    = '1.0';
    $request_info->{'response_status'} = $status;
    $request_info->{'response_header_size'} += length $out;

    if ($body) {

        # add Content-Type only if not already defined
        if (not $content_type_already_sent) {
            push @{$request_info->{'response_headers'}}, ['Content-type', 'text/plain'];
            $out = "Content-Type: text/plain\r\n\r\n";
        }
        else {
            $out = "\r\n";
        }
        $request_info->{'response_header_size'} += length $out;
        $self->{'server'}->{'client'}->print($out);
        $request_info->{'headers_sent'} = 1;
        my $encoded_body = $body;
        if ($want_gzip) {
            require IO::Compress::Gzip;
            IO::Compress::Gzip::gzip(\$body => \$encoded_body);
        }
        $self->{'server'}->{'client'}->print($encoded_body);
        $request_info->{'response_size'} += length $encoded_body;
    }

    return 1;
}

sub log_and_exit {
    my ($self, $code, $msg, $body, $params) = @_;
    $params->{'returnvalue'} ||= "$code $msg";

    my $account              = delete $self->{'_log'}{'account'};
    my $user                 = delete $self->{'_log'}{'user'};
    my $hostto               = delete $self->{'_log'}{'hostto'};
    my $portto               = delete $self->{'_log'}{'portto'};
    my $starttime            = delete $self->{'_log'}{'start_time'};
    my $allowed              = delete $self->{'_log'}{'allowed'} || 0;
    my $bastion2device_delay = delete $self->{'_log'}{'bastion2device_delay'};
    my $request_body_length  = delete $self->{'_log'}{'request_body_length'};

    # log in sql and/or logfile and/or syslog
    my $processing_delay = ($starttime ? int(Time::HiRes::tv_interval($starttime) * 1_000_000) : undef);
    $params->{'account'}     = $account;                                        # might be undef if we're called before the account is extracted from the payload
    $params->{'user'}        = $user;                                           # ditto
    $params->{'hostto'}      = $hostto;                                         # ditto
    $params->{'portto'}      = $portto;                                         # ditto
    $params->{'loghome'}     = 'proxyhttp';
    $params->{'cmdtype'}     = 'proxyhttp_daemon';
    $params->{'ipfrom'}      = $self->{'request_info'}{'peeraddr'};
    $params->{'portfrom'}    = $self->{'request_info'}{'peerport'};
    $params->{'bastionip'}   = $self->{'request_info'}{'sockaddr'};
    $params->{'bastionport'} = $self->{'request_info'}{'sockport'};
    $params->{'params'}      = $self->{'request_info'}{'request_path'};
    $params->{'plugin'}      = uc($self->{'request_info'}{'request_method'});
    $params->{'allowed'}     = $allowed;

    # custom data will only be logged to logfile and syslog, not sql (it's not in the generic schema)
    $params->{'custom'} = [
        ['user_agent'                 => $ENV{'HTTP_USER_AGENT'}],
        ['request_headers_length'     => $self->{'request_info'}{'request_header_size'}],
        ['request_body_length'        => $request_body_length + 0],
        ['response_body_length'       => length($body)],
        ['timing_bastion2device_usec' => $bastion2device_delay],
        ['timing_global_usec'         => $processing_delay],
        ['code'                       => $code],
        ['msg'                        => $msg],
    ];
    if ($processing_delay) {
        push @{$params->{'custom'}}, ['timing_overhead_usec' => ($processing_delay - $bastion2device_delay) + 0];
    }
    $self->{'_log'}{'logret'} = OVH::Bastion::log_access_insert(%$params);

    # log in "ttyrec"
    my $basedir = "/home/proxyhttp/ttyrec";
    -d $basedir || mkdir $basedir;

    my $srcip    = 'src_' . ($ENV{'REMOTE_ADDR'} || '0.0.0.0');
    my $finaldir = "$basedir/$srcip";
    -d $finaldir || mkdir $finaldir;

    my @now = Time::HiRes::gettimeofday();
    my @t   = localtime($now[0]);

    my @request_lines = ($self->{'request_info'}{'request'});
    foreach my $array (@{$self->{'request_info'}{'request_headers'} || []}) {
        push @request_lines, sprintf("%s: %s", @$array);
    }
    if (exists $self->{'_log'}{'post_content'}) {
        push @request_lines, '';
        push @request_lines, delete $self->{'_log'}{'post_content'};
    }

    my $bastion_answer_log = "HTTP/1.0 $code $msg\n";
    foreach my $row (@{$self->http_base_headers()}) {
        $bastion_answer_log .= $row->[0] . ": " . $row->[1] . "\n";
    }
    $bastion_answer_log .= "\n(BODY OMITTED, " . length($body) . " bytes)\n";
    my @headerlog = ($ENV{'UNIQID'}, $now[0], $now[1], POSIX::strftime("%Y/%m/%d.%H:%M:%S", @t));
    my $logfile   = sprintf("%s/%s.txt", $finaldir, POSIX::strftime("%F", @t));
    my $logline   = sprintf(
        ""
          . "--- CLIENT_REQUEST UNIQID=%s TIMESTAMP=%d.%06d DATE=%s ---\n%s\n"
          . "--- BASTION_ANSWER UNIQID=%s TIMESTAMP=%d.%06d DATE=%s ---\n%s\n"
          . "--- END UNIQID=%s TIMESTAMP=%d.%06d DATE=%s ---\n\n",
        @headerlog, join("\n", @request_lines),
        @headerlog, $bastion_answer_log, @headerlog,
    );
    $logline =~ s/^(Authorization:).+/$1 (removed)/mgi;

    if (open(my $log, '>>', $logfile)) {
        flock($log, LOCK_EX);
        print $log $logline;
        flock($log, LOCK_UN);
        close($log);
    }
    else {
        warn("Couldn't open $logfile for log write");
    }

    # if status is 401, tell client what scheme we expect for the auth
    if ($code == 401) {
        push @{$self->{'_supplementary_headers'}}, ['WWW-Authenticate', 'Basic realm="bastion"'];
    }

    # and send status (will also fill access_log)
    return $self->send_status($code, $msg, $body . "\n");
}

# called by Net::Server when initializing, we set its log_function here to handle error logs, such as timeouts.
# if func is undefined when Net::Server needs it, it'll log to STDERR, and we don't want that
sub configure_hook {    ## no critic (RequireFinalReturn)
    my $self = shift;
    $self->{'server'}{'log_function'} = sub {
        my ($level, $msg) = @_;
        warn_syslog("osh-http-proxy-daemon: level $level: $msg");
    }
}

# overrides parent func
sub run {
    my ($self, %params) = @_;
    $self->{'proxy_config'} = (delete $params{'proxy_config'}) || {};
    return $self->SUPER::run($self, %params);
}

# used twice in process_http_request(): get the worker cmd to execute, launch it
# and decapsulate the result with the proper error checks
## no critic (Subroutines::RequireArgUnpacking)
sub _exec_worker_and_get_result {
    my $self = shift;
    my @cmd  = @_;
    my $fnret;

    $fnret = OVH::Bastion::execute_simple(cmd => \@cmd);
    $fnret
      or return $self->log_and_exit(
        500,
        "Internal Error (couldn't exec worker)",
        "Couldn't exec worker (" . $fnret->msg . ")",
        {comment => "worker_exec_failed"}
      );

    if ($fnret->value->{'sysret'} != 0) {
        return $self->log_and_exit(
            500,
            "Internal Error (worker returned a non-zero exit value)",
            "Worker returned a non-zero exit value (" . $fnret->value->{'sysret'} . ")",
            {comment => "worker_non_zero_exit"}
        );
    }

    if (!$fnret->value->{'output'}) {
        return $self->log_and_exit(
            500,
            "Internal Error (worker returned no data)",
            "Worker returned no data",
            {comment => "worker_no_data"}
        );
    }

    my $json_decoded;
    eval { $json_decoded = decode_json($fnret->value->{'output'}); };
    if ($@) {
        return $self->log_and_exit(
            500,
            "Internal Error (worker returned invalid JSON)",
            "Worker returned "
              . (length($fnret->value->{'output'}))
              . " bytes of data but JSON decoding failed ($@). The first 500 bytes follow:\n"
              . substr($fnret->value->{'output'}, 0, 500),
            {comment => "worker_invalid_json"}
        );
    }

    $fnret = OVH::Bastion::helper_decapsulate($json_decoded);
    $fnret
      or return $self->log_and_exit(
        500,
        "Internal Error (worker returned an error)",
        "Worker returned an error ($fnret)",
        {comment => "worker_error"}
      );

    my $value_object = eval { thaw(decode_base64($fnret->value)); };
    if ($@) {
        return $self->log_and_exit(
            500,
            "Internal Error (can't decode worker data)",
            "Error while decoding worker data ($@)\n",
            {comment => "worker_decoding_error"}
        );
    }

    return R($fnret->err, msg => $fnret->msg, value => $value_object);
}

# overrides parent func
sub process_http_request {
    my ($self, $client) = @_;
    my $fnret;

    $ENV{'FORCE_STDERR'} = 1;
    $self->{'_log'}{'start_time'} = [Time::HiRes::gettimeofday()];

    $ENV{'UNIQID'} = OVH::Bastion::generate_uniq_id()->value;

    $self->{'server'}{'access_log_format'} = qq#%h - - %t "%r" %>s %b "-" "$ENV{'UNIQID'}" "%{User-Agent}i" %D -#;

    # consistency check
    if ($self->{'request_info'}{'peerport'} ne $ENV{'REMOTE_PORT'}) {
        return $self->log_and_exit(
            500,
            "Internal Server Error (consistency)",
            "Internal consistency error: remote_port doesn't match peerport, this shouldn't happen",
            {comment => 'consistency_error'}
        );
    }

    # default set by the daemon and adjusted by the config, just ensure it's not undef
    $self->{'proxy_config'}{'allowed_methods'} ||= [];
    # only some methods are allowed
    if (not grep { uc($self->{'request_info'}{'request_method'}) eq $_ } @{$self->{'proxy_config'}{'allowed_methods'}})
    {
        return $self->log_and_exit(
            400,
            "Bad Request (method forbidden)",
            "The " . uc($self->{'request_info'}{'request_method'}) . " method is forbidden by policy",
            {comment => 'method_forbidden'}
        );
    }

    # if we don't have the request_headers, we really have a big problem
    if (ref $self->{'request_info'} ne 'HASH' or ref $self->{'request_info'}{'request_headers'} ne 'ARRAY') {
        return $self->log_and_exit(
            500,
            "Internal Server Error (headers not found)",
            "The headers of the request can't be found",
            {comment => "headers_not_found"}
        );
    }

    # convert headers into a hash
    my $req_headers = _flatten_headers($self->{'request_info'}{'request_headers'});
    if (ref $req_headers ne 'HASH') {
        return $self->log_and_exit(
            500,
            "Internal Server Error (headers are not a hash)",
            "Request headers couldn't be parsed properly",
            {comment => "headers_cannot_be_parsed"}
        );
    }

    # check if it's not just a self-health test
    if ($ENV{'REQUEST_URI'} eq '/bastion-health-check') {

        # launch the worker in monitoring mode, to be sure we test all the sudo part
        my @cmd = (
            "sudo", "-n", "-u", "proxyhttp", "--", "/usr/bin/env", "perl", "-T",
            "/opt/bastion/bin/proxy/osh-http-proxy-worker"
        );
        push @cmd, "--monitoring", "--uniqid", $ENV{'UNIQID'};

        $fnret = $self->_exec_worker_and_get_result(@cmd);

        my $workerversion = $fnret->value->{'body'};

        if ($workerversion eq $OVH::Bastion::VERSION) {
            return $self->log_and_exit(200, "OK", "Bastion HTTPS proxy version " . $OVH::Bastion::VERSION . " is running nominally.", {comment => "monitoring"});
        }
        else {
            return $self->log_and_exit(
                202,
                "Semi-OK",
                "A discrepancy was found between the Bastion HTTPS proxy daemon version ("
                  . $OVH::Bastion::VERSION
                  . ") and worker version ($workerversion), please reload the daemon to avoid problems.",
                {comment => "monitoring"}
            );
        }
    }

    # this header is mandatory, and must be a Basic scheme auth
    if (not $req_headers->{'authorization'}) {
        return $self->log_and_exit(
            401,
            "Authorization required (no auth provided)",
            "No authentication provided, and authentication is mandatory",
            {comment => "no_auth_provided"}
        );
    }
    my $basic_auth_header_value;
    if (not $req_headers->{'authorization'} =~ m{^Basic (\S+)$}i) {
        return $self->log_and_exit(
            401,
            "Authorization required (basic auth scheme needed)",
            "Basic authorization scheme required",
            {comment => "bad_auth_scheme"}
        );
    }
    else {
        $basic_auth_header_value = $1;
    }
    if ($req_headers->{'authorization'} ne $ENV{'HTTP_AUTHORIZATION'}) {
        return $self->log_and_exit(
            500,
            "Internal Server Error (consistency)",
            "Internal consistency error: authorization header doesn't match envvar",
            {comment => 'consistency_error'}
        );
    }
    delete $ENV{'HTTP_AUTHORIZATION'};

    # decode the auth header
    my $decoded = decode_base64($basic_auth_header_value);
    undef $basic_auth_header_value;

    #print STDERR "I decoded $decoded\n";

    # the decoded header should be of the form LOGIN:PASSWORD
    if (not $decoded or $decoded !~ /^(.+):([^:]+)$/) {
        return $self->log_and_exit(
            401,
            "Authorization required (malformed basic auth)",
            "Malformed Basic authorization '$decoded'",
            {comment => "malformed_basic_auth"}
        );
    }

    # in our case, the LOGIN should in fact be of the form bastion_account@remote_login_expression@remote_host_to_connect_to,
    # where remote_login_expression can be one of "$user", "group=$shortGroup,user=$user" or "user=$user"
    my ($loginpart, $pass) = ($1, $2);    ## no critic (ProhibitCaptureWithoutTest)
    if (
        $loginpart !~ m{^
            ([^@]+)@ # account
            ([^@]+)@ # user_expression
            (\[?[0-9a-zA-Z._:-]+\]?) # remotemachine, can be a host, IPv4 or IPv6
            (?:%
                ([0-9]+) # port, optional
            )?
        $}x
      )
    {
        return $self->log_and_exit(
            400,
            "Bad Request (bad login format)",
            "Expected an Authorization line with credentials of the form 'BASTIONACCOUNT\@USEREXPR\@HOSTEXPR:PASSWORD' where\n"
              . "USEREXPR can be either 'DEVICEUSER' or 'group=BASTIONGROUP,user=DEVICEUSER' or 'user=DEVICEUSER'\n"
              . "HOSTEXPR can be either a 'HOST' or 'HOST%PORT', with HOST being a resolvable hostname or IP",
            {comment => "bad_login_format"}
        );
    }
    my ($account, $user_expression, $remotemachine, $remoteport) = ($1, $2, $3, $4);    ## no critic (ProhibitCaptureWithoutTest)
    undef $loginpart;                                                                   # no longer needed
    $remoteport               = 443 if not defined $remoteport;
    $self->{'_log'}{'hostto'} = $remotemachine;
    $self->{'_log'}{'portto'} = $remoteport;

    my $context;
    my $group;
    my $user;
    if ($user_expression =~ m{^group=(\S+),user=(\S+)$}) {
        $context = 'group';
        $group   = $1;
        $user    = $2;
    }
    elsif ($user_expression =~ m{^user=(\S+),group=(\S+)$}) {
        $context = 'group';
        $group   = $2;
        $user    = $1;
    }
    elsif ($user_expression =~ m{^user=(\S+)$}) {
        $context = 'self';
        $user    = $1;
    }
    else {
        $context = 'autodetect';
        $user    = $user_expression;
    }
    undef $user_expression;    # no longer needed

    if (not OVH::Bastion::is_account_valid(account => $account)) {
        return $self->log_and_exit(
            400,
            "Bad Request (bad account)",
            "Account name is invalid",
            {comment => "invalid_account"}
        );
    }
    my $escaped_account = $account;
    $escaped_account =~ s/%/%%/g;
    $self->{'server'}{'access_log_format'} =
      qq#%h $escaped_account %u %t "%r" %>s %b "$remotemachine" "$ENV{'UNIQID'}" "%{User-Agent}i" %D -#;
    if (not OVH::Bastion::is_valid_port(port => $remoteport)) {
        return $self->log_and_exit(
            400,
            "Bad Request (bad port number)",
            "Port number is out of range",
            {comment => "invalid_port_number"}
        );
    }

    $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $account);
    if (not $fnret) {

        # don't be too specific on the error message to avoid account name guessing
        return $self->log_and_exit(
            403,
            "Access Denied",
            "Incorrect username ($account) or password (#REDACTED#, length=" . length($pass) . ")",
            {comment => "invalid_credentials"}
        );
    }
    $account = $fnret->value->{'account'};                      # untaint
    $self->{'_log'}{'account'} = $account;

    if ($user !~ /^[a-zA-Z0-9._-]+/) {
        return $self->log_and_exit(
            400,
            "Bad Request (bad user name)",
            "User name '$user' has forbidden characters",
            {comment => "bad_user_name"}
        );
    }
    $self->{'_log'}{'user'} = $user;
    my $escaped_user = $user;
    $escaped_user =~ s/%/%%/g;
    $self->{'server'}{'access_log_format'} =
      qq#%h $escaped_account $escaped_user %t "%r" %>s %b "$remotemachine" "$ENV{'UNIQID'}" "%{User-Agent}i" %D -#;

    # config value by default
    my $timeout = $self->{'proxy_config'}{'timeout'};

    # if there's a timeout header, get it
    if ($req_headers->{'x-bastion-timeout'}) {
        if ($req_headers->{'x-bastion-timeout'} =~ /^\d+$/) {
            $timeout = $req_headers->{'x-bastion-timeout'};
        }
        else {
            return $self->log_and_exit(
                400,
                "Bad Request (invalid timeout value)",
                "Expected an integer timeout value expressed in seconds",
                {comment => "bad_timeout_value"}
            );
        }
    }

    # set default egress protocol if not specified in config
    $self->{'proxy_config'}{'allowed_egress_protocols'} ||= ['https'];

    # if there's an egress-protocol header, get it
    my $egress_protocol = $req_headers->{'x-bastion-egress-protocol'} || 'https';
    # protocol must be explicitly allowed per Bastion policy, by default only https is allowed
    if (!grep { $egress_protocol eq $_ } @{$self->{'proxy_config'}{'allowed_egress_protocols'} || []}) {
        return $self->log_and_exit(
            400,
            "Bad Request (forbidden egress protocol)",
            "The egress protocol '$egress_protocol' is not allowed by policy",
            {comment => "forbidden_egress_protocol"}
        );
    }

    # if there's an allow-downgrade header, get it
    my $allow_downgrade = 0;
    if ($req_headers->{'x-bastion-allow-downgrade'}) {
        if ($req_headers->{'x-bastion-allow-downgrade'} eq "1" || $req_headers->{'x-bastion-allow-downgrade'} eq "0") {
            $allow_downgrade = $req_headers->{'x-bastion-allow-downgrade'} + 0;
        }
        else {
            return $self->log_and_exit(
                400,
                "Bad Request (invalid allow-downgrade value)",
                "Expected value '0', '1' or no header",
                {comment => "bad_allow_downgrade_value"}
            );
        }
    }

    # if there's an enforce-secure header, get it
    my $enforce_secure = 0;
    if ($req_headers->{'x-bastion-enforce-secure'}) {
        if ($req_headers->{'x-bastion-enforce-secure'} eq "1" || $req_headers->{'x-bastion-enforce-secure'} eq "0") {
            $enforce_secure = $req_headers->{'x-bastion-enforce-secure'} + 0;
        }
        else {
            return $self->log_and_exit(
                400,
                "Bad Request (invalid enforce-secure value)",
                "Expected value '0', '1' or no header",
                {comment => "bad_enforce_secure_value"}
            );
        }
    }

    # here, we know the account is right, so we sudo to this account to proceed
    my @cmd = (
        "sudo", "-n", "-u", $account, "--", "/usr/bin/env", "perl", "-T",
        "/opt/bastion/bin/proxy/osh-http-proxy-worker"
    );
    push @cmd, "--account", $account, "--context", $context, "--user", $user, "--host", $remotemachine, "--uniqid",
      $ENV{'UNIQID'};
    push @cmd, "--method", $self->{'request_info'}{'request_method'}, "--path", $self->{'request_info'}{'request_path'};
    push @cmd, "--port",   $remoteport;
    push @cmd, "--group",   $group   if $group;
    push @cmd, "--timeout", $timeout if $timeout;
    push @cmd, "--allow-downgrade"      if $allow_downgrade;
    push @cmd, "--insecure"             if ($self->{'proxy_config'}{'insecure'} && !$enforce_secure);
    push @cmd, "--log-request-response" if ($self->{'proxy_config'}{'log_request_response'});
    push @cmd, "--log-request-response-max-size", $self->{'proxy_config'}{'log_request_response_max_size'}
      if ($self->{'proxy_config'}{'log_request_response'});
    push @cmd, "--egress-protocol", $egress_protocol;

    # X-Test-* is only used for functional tests, and has to be passed to the remote
    foreach my $pattern (qw{ accept content-type content-length content-encoding x-test-[a-z-]+ }) {
        foreach my $key (grep { /^$pattern$/i } keys %$req_headers) {
            push @cmd, "--header", $key . ':' . $req_headers->{$key};
        }
    }

    # we don't want the CGI module to parse/modify/interpret the content, so we
    # fake an application/xml content, this has the effect in the CGI module code
    # to not mess at all with the data, which is what we want. This way we can get the
    # raw unparsed/unmodified data through the special 'XForms:Model' param. Once done,
    # we simply restore the real content-type.
    # For PUT and PATCH, this is easier,
    # cf https://metacpan.org/dist/CGI/view/lib/CGI.pod#Handling-non-urlencoded-arguments
    my $content;
    my $real_content_type = $ENV{'CONTENT_TYPE'};
    $ENV{'CONTENT_TYPE'} = 'application/xml';
    my %verb2param = (POST => 'XForms:Model', PUT => 'PUTDATA', PATCH => 'PATCHDATA');
    if (my $param = $verb2param{$self->{'request_info'}{'request_method'}}) {
        $content = CGI->new->param($param);
    }
    $ENV{'CONTENT_TYPE'}    = $real_content_type;
    $ENV{'PROXY_POST_DATA'} = encode_base64($content);

    $ENV{'PROXY_ACCOUNT_PASSWORD'} = $pass;
    undef $pass;
    $self->{'_log'}{'request_body_length'} = length($content);

    $fnret = $self->_exec_worker_and_get_result(@cmd);

    delete $ENV{'PROXY_ACCOUNT_PASSWORD'};
    delete $ENV{'PROXY_POST_DATA'};

    if (ref $fnret->value->{'headers'} eq 'ARRAY') {
        push @{$self->{'_supplementary_headers'}}, @{$fnret->value->{'headers'}};
    }
    if ($req_headers->{'accept-encoding'} =~ /gzip/) {
        push @{$self->{'_supplementary_headers'}}, ['Content-Encoding', 'gzip'];
    }
    $self->{'request_info'}{'headers_sent'} = 1;    # needed to avoid duplicate headers by our parent package

    my $flattened_bastion2client_headers = _flatten_headers($self->{'_supplementary_headers'});
    my $bastion2devicedelay              = $flattened_bastion2client_headers->{'x-bastion-egress-timing'};
    $self->{'_log'}{'post_content'} = $content;
    $self->{'server'}{'access_log_format'} =
      qq#%h $escaped_account $escaped_user %t "%r" %>s %b "$remotemachine" "$ENV{'UNIQID'}" "%{User-Agent}i" %D #
      . ($bastion2devicedelay || '-');

    $self->{'_log'}{'bastion2device_delay'} = $bastion2devicedelay;
    $self->{'_log'}{'allowed'}              = $fnret->value->{'allowed'};
    $self->log_and_exit(
        $fnret->value->{'code'},
        $fnret->value->{'msg'},
        $fnret->value->{'body'},
        {comment => "worker_returned"}
    );

    return 1;
}

# overrides parent func
sub http_base_headers {
    my $self    = shift;
    my @headers = (
        [Date                 => gmtime() . " GMT"],
        [Connection           => 'close'],
        [Server               => "The Bastion " . $OVH::Bastion::VERSION],
        ['X-Bastion-Instance' => hostname()],
        ['X-Bastion-ReqID'    => $ENV{'UNIQID'}],
    );
    foreach my $keyval (@{$self->{'_supplementary_headers'}}) {
        my $keyname = $keyval->[0];
        $keyname = 'X-Bastion-Remote-' . $keyname if ($keyname =~ /^(client-ssl-)/i);
        push @headers, [$keyname, $keyval->[1]];
    }
    return \@headers;
}

# this sub turns [ [ HeaDerA, ValueA ], [ HEAderB, ValueB ] ]
# into { headera => ValueA, headerb => ValueB }
# and errors if there is a duplicate header somewhere
sub _flatten_headers {
    my $arrayref = shift;
    my %headers;

    if (ref $arrayref ne 'ARRAY') {
        return "Bad call";
    }

    foreach my $keyval (@$arrayref) {
        if (ref $keyval ne 'ARRAY' or @$keyval != 2) {
            return "Malformed headers";
        }
        my $key = lc($keyval->[0]);
        my $val = $keyval->[1];
        if (exists($headers{$key})) {
            return "Duplicate header $key";
        }
        $headers{$key} = $val;
    }
    return \%headers;
}

1;
