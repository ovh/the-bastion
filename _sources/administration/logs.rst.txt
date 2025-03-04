====
Logs
====

.. note::
   The Bastion comes with a lot of traceability features, you have to ensure that you've done your configuration
   correctly so that those logs are kept in a safe place when you need them. It is warmly advised to enable at least
   the syslog option, and push your logs to a remote syslog server.

.. contents::
   :depth: 5


Message types
=============

The Bastion has several configurable ways of logging events, but before detailing those,
let's see the different message types that can be logged.
The Bastion currently has 12 different message types, listed below:

- :ref:`log_open`
- :ref:`log_close`
- :ref:`log_warn`
- :ref:`log_warninfo`
- :ref:`log_codewarn`
- :ref:`log_acl`
- :ref:`log_membership`
- :ref:`log_security`
- :ref:`log_group`
- :ref:`log_account`

First, let's list the fields that are common to all the message types:

uniqid
   This is the unique connection ID, you can find all the logs relevant to the same connection
   by filtering on the ``uniqid``. This ID is also, by default, part of the filename given to the ``ttyrec`` files,
   for easier correlation. The same ID is also used in the sqlite logs, if you enabled those. In some rare cases,
   the value can be "-", for example if a satellite script has something to log,
   not linked to an actual connection or session.

version
   This indicates the version of The Bastion software that is writing the log

pid, ppid
   This is the system PID (resp. system parent PID) of the process writing the log,
   for easier correlation with system audit logs if you have them

sysuser
   This is the system user under which the process writing the log is currently running on,
   can be useful to detect abnormalities

sudo_user
   When the value is present, it contains the system user name that has launched the ``sudo`` command the code is
   currently running under (this will be the case if a so-called "bastion helper" is pushing a log, for example).
   However this field will often have an empty value, it means that the code that is writing the log
   is not running under ``sudo``

uid, gid
   This is the system user ID aka UID (resp. group ID aka GID) under which
   the process writing the log is currently running

account
   This is the name of the bastion account that launched the command that produced the log

The other fields depend on the message type, as detailed in the next sections.

.. _log_open:

open
****

This log is produced when a user established a session with the bastion.

Example::

   Dec 28 11:12:26 myhostname bastion: open uniqid="e9e4baf6873b" version="3.01.03" pid="18721" ppid="18720"
   sysuser="gthreepw" sudo_user="" uid="99998" gid="99998" account="gthreepw" cmdtype="ssh" allowed="true"
   ip_from="172.17.0.1" port_from="39696" host_from="172.17.0.1" ip_bastion="172.17.0.2" port_bastion="22"
   host_bastion="myhostname.example.org" user="foo" ip_to="172.17.0.123" port_to="22" host_to="srv123.example.org"
   plugin="" globalsql="ok" accountsql="ok" comment="" params="ttyrec -f
   /home/gthreepw/ttyrec/172.17.0.123/2020-12-28.11-12-26.074894.e9e4baf6873b.gthreepw.foo.172.17.0.123.22.ttyrec -F
   /home/gthreepw/ttyrec/172.17.0.123/%Y--%d.%H-%M-%S.#usec#.e9e4baf6873b.gthreepw.foo.172.17.0.123.22.ttyrec --
   /usr/bin/ssh 172.17.0.123 -l foo -p 22 -i /home/gthreepw/.ssh/id_rsa4096_private.1594384739 -i
   /home/keykeeper/keyagroup/id_ed25519_agroup.1607524914 -o PreferredAuthentications=publickey"

Fields:

cmdtype
   Indicates which category of command has been requested by the user:

   - ssh: the user is trying to establish an SSH egress connection to a remote server
   - telnet: the user is trying to establish a telnet egress connection to a remote server
   - abort: the action requested by the user has been aborted early, possibly because of permission issues
     or impossibility to understand the request, more information is available in the **bastion_comment** field
   - osh: the user is trying to execute a bastion plugin with the ``--osh`` command
   - interactive: the user just entered interactive mode. Note that all the commands launched through
     the interactive mode will still have their own log.
   - sshas: an administrator is currently establishing a connection on behalf of another user.
     This connection will also have its own log.
   - proxyhttp_daemon: the HTTPS proxy daemon received a request
   - proxyhttp_worker: the HTTPS proxy worker specifically spawned for the user by the daemon is handling the request

allowed
   Indicates whether the requested action was allowed or not by the bastion, after executing the authorization phase.
   Will be either "true" or "false".

ip_from, port_from, host_from
   These are the IP and source port as seen by the bastion, from which the ingress connection originates.
   If the bastion can resolve the reverse of the IP to a hostname, it'll be indicated in host_from,
   otherwise the IP will be repeated there.

ip_bastion, port_bastion, host_bastion
   These are the IP and port of the bastion to which the ingress connection terminates.
   If your bastion has several IPs and/or interfaces, this can be useful.
   If the bastion can resolve the reverse of the IP to a hostname, it'll be indicated in host_bastion,
   otherwise the IP will be repeated there.

ip_to, port_to, host_to
   These are the IP and destination port to which the bastion will connect on the egress side,
   on behalf of the requesting user. If the bastion can resolve the reverse of the IP to a hostname,
   it'll be indicated in host_to, otherwise the IP will be repeated there.

plugin
   When ``cmdtype`` is ``osh``, the name of the command (or *plugin*) will appear in this field.
   Otherwise it'll be blank.

accountsql
   This field will contain either:

   - ok: when :ref:`enableAccountSqlLog` is enabled, and we successfully inserted a new row for the log
   - no: when :ref:`enableAccountSqlLog` is disabled
   - error: when we couldn't insert a new row, **error** followed by a detailed error message,
     for example "error SQL error [global] err 8 while doing [inserting data (execute)]:
     attempt to write a readonly database".

globalsql
   This field can contain the same values than **accountsql** above,
   but for ``enableGlobalSqlLog`` instead of ``enableAccountSqlLog``

comment
   Some more information about the current event, depending on the ``cmdtype`` value.

params
   This is the fully expanded command line that will be launched under the currently running user rights,
   to establish the egress connection, if applicable.

.. _log_close:

close
*****

This log is produced when a user terminates a currently running session with The Bastion.
It is always matched (through the ``uniqid``) to another log with the ``open`` message type.

Example::

   Dec 28 11:12:26 myhostname bastion: open uniqid="e9e4baf6873b" version="3.01.03" pid="18721" ppid="18720"
   sysuser="gthreepw" sudo_user="" uid="99998" gid="99998" account="gthreepw" cmdtype="ssh" allowed="true"
   ip_from="172.17.0.1" port_from="39696" host_from="172.17.0.1" ip_bastion="172.17.0.2" port_bastion="22"
   host_bastion="myhostname.example.org" user="foo" ip_to="172.17.0.123" port_to="22"
   host_to="srv123.example.org" plugin="" globalsql="ok" accountsql="ok" comment="" params="ttyrec -f
   /home/gthreepw/ttyrec/172.17.0.123/2020-12-28.11-12-26.074894.e9e4baf6873b.gthreepw.foo.172.17.0.123.22.ttyrec -F
   /home/gthreepw/ttyrec/172.17.0.123/%Y--%d.%H-%M-%S.#usec#.e9e4baf6873b.gthreepw.foo.172.17.0.123.22.ttyrec --
   /usr/bin/ssh 172.17.0.123 -l foo -p 22 -i /home/gthreepw/.ssh/id_rsa4096_private.1594384739 -i
   /home/keykeeper/keyagroup/id_ed25519_agroup.1607524914 -o PreferredAuthentications=publickey" sysret="0"
   signal="" comment_close="hostkey_changed passauth_disabled" duration="43.692"

All the fields from the corresponding ``open`` log are repeated in this log line, in addition to the following fields:

sysret
   Return code of the launched system command (that established the egress connection)
   or the plugin (if an ``--osh`` command was passed).
   If we don't have a return code, for example because we were interrupted by a signal, the value will be empty.

signal
   Name of the UNIX signal that terminated the command, if any. For example "HUP" or "SEGV".
   If we got no signal, the value will be empty.

comment_close
   A space-separated list of messages giving some hints gathered at the end of a session.
   For example `hostkey_changed passauth_disabled` means that we detected that our egress ssh client
   emitted a warning telling us that the remote keys changed, and also that password authentication has been disabled.

duration
   Amount of seconds (with a millisecond precision) between the session open and the session close.

.. _log_warn:

warn, die
*********

These logs are produced when Perl emits a warning (using the ``warn()`` call),
or respectively when Perl halts abruptly due to a ``die()`` call.
This should not happen during nominal use. You might want to keep a look on those messages if they're produced.

Example::

  Dec 28 11:12:26 myhostname bastion: warn uniqid="a46e51b5dce4" version="3.01.02" pid="3308212" ppid="3308206"
  sysuser="lechuck" sudo_user="" uid="99994" gid="99994" msg="Cannot find termcap: TERM not set at
  /usr/share/perl/5.28/Term/ReadLine.pm line 379.  " program="/opt/bastion/bin/shell/osh.pl" cmdline="-c^-i ssh
  root@172.17.0.222 id" trace=" at /opt/bastion/bin/shell/../../lib/perl/OVH/Bastion.pm
  line 41.   OVH::Bastion::__ANON__(\"Cannot find termcap: TERM not set at /usr/share/perl/5.28/Ter\"...)
  called at /usr/share/perl/5.28/Term/ReadLine.pm line
  391     Term::ReadLine::TermCap::ornaments(Term::ReadLine::Stub=ARRAY(0x5575da36b690), 1) called at
  /opt/bastion/lib/perl/OVH/Bastion/interactive.inc line 77   OVH::Bastion::interactive(\"realOptions\", \"-i ssh
  root\\@172.17.0.222 id\"..., \"timeoutHandler\", CODE(0x5575da15aa78), \"self\", \"lechuck\")
  called at /opt/bastion/bin/shell/osh.pl line 485 "

Fields:

msg
   This is the message used as a parameter to the ``warn()`` or ``die()`` call

program
   Contains the name of the currently running program (first parameter of ``execve()``)

cmdline
   Contains the full command line passed to the currently running program (remaining parameters of ``execve()``).
   The command-line fields are separated by ``^``'s.

trace
   The call trace leading to this ``warn()`` or ``die()``

.. _log_warninfo:

warn-info, die-info
*******************

These logs are produced when some known portion of code (including libraries) called ``warn()`` or ``die()``
but in a known case that can happen during nominal use.
Don't use these logs to directly trigger an alert, but you can keep an eye on those, as e.g. an unusually
high number of occurences in a short time may be a weak signal that somebody or something is misbehaving.

The fields are the same than the ones specified above for **warn** and **die**.

.. _log_codeinfo:

code-info
*********

These logs are produced when some portion of the code encounters an minor issue that is worth logging,
to e.g. help debugging an issue or understanding what happened in a specific use-case,
for example if a user-session ended abruptly.
These logs are not the result of an error on the bastion configuration and don't mandate immediate admin attention.

Example::

   Dec 25 14:56:11 myhostname bastion: code-info uniqid="98d2f32b1a2d" version="3.07.00" pid="3708843"
   ppid="3708842" sysuser="lechuck" sudo_user="" uid="8423" gid="8423" msg="execute():
   error while syswriting(Broken pipe) on stderr, aborting this cycle"

Fields:

msg
   A human-readable text describing the error

.. _log_codewarn:

code-warning
************

These logs are produced when some portion of the code encounters an unexpected issue or abnormality
that is worth logging. They'll usually not be emitted due to a bad user interaction, but rather if the bastion
is misconfigured, or for anything that might need some attention or fixing from the admins.

Example::

   Dec 28 11:12:26 myhostname bastion: code-warning uniqid="ffee33abd1ba" version="3.01.03" pid="3709643"
   ppid="3709642" sysuser="lechuck" sudo_user="" uid="8423" gid="8423" msg="Configuration error
   for plugin selfGenerateEgressKey on the 'disabled' key: expected a boolean, casted 'no' into false"

Fields:

msg
   A human-readable text describing the error

.. _log_acl:

acl
***

This log is produced when an access control list is modified,
either personal accesses of an account, or a group servers list.

Example::

   Dec 28 11:12:26 myhostname bastion: acl uniqid="f25fe71c6635" version="3.01.02" pid="3116604"
   ppid="3116603" sysuser="keysomegroup" sudo_user="lechuck" uid="10006" gid="10057" action="add"
   type="group" group="somegroup" account="" user="root" ip="172.16.2.2" port="22" ttl="" force_key="" comment=""

Fields:

action
   Will be either *add* if an access is added, or *del* if an access is removed

type
   Will be either *group* if we're modifying a group server list, in which case the *group* field will be filled,
   or *account* if we're modifying personal accesses of an account, in which case the *account* field will be filled

group
   If **type** is *group*, indicates which group servers list has been modified

account
   If **type** is *account*, indicates which account personal accesses have been modified

user
   The remote user part of the access we're adding/removing

ip
   The IP or IP block of the access we're adding/removing

port
   The port of the access we're adding/removing

ttl
   If set, represents the TTL after which the access will automatically be removed

force_key
   If set, this contains the fingerprint of the key that'll be used for this access

comment
   Any comment set by the user adding/removing the access

.. _log_membership:

membership
**********

This log is produced when one of a group's role list is modified:
either an owner, member, guest, aclkeeper or gatekeeper.

Example::

   Dec 28 11:12:26 myhostname bastion: membership uniqid="a00993ec6767" version="3.01.02"
   pid="1072528" ppid="1072497" sysuser="lechuck" sudo_user="" uid="2070" gid="2070" action="add"
   type="member" group="monkeys" account="stan" self="lechuck" user="" host="" port="" ttl=""

Fields:

action
   Either *add* when an account is added to a group role list, or *del* when an account is removed

type
   Type of the role list we're modifying, either *member*, *aclkeeper*, *gatekeeper*, *guest* or *owner*

group
   Group whose one of the role list is being modified

account
   Account being added/removed to/from the group role list

self
   Account performing the change

user
   When **type** is *guest*, the remote user part of the access we're adding/removing

host
   When **type** is *guest*, the IP or IP block part of the access we're adding/removing

port
   When **type** is *guest*, the port of the access we're adding/removing

ttl
   When **type** is *guest* and **action** is *add*, if a TTL has been specified for the access, it appears here

.. _log_security:

security
********

This log is produced when an important security event has occurred, such as when an admin impersonates another user,
or when a super owner uses his implicit global ownership to modify a group. You might want to watch those closely.

Example::

   Dec 28 11:12:26 myhostname bastion: security uniqid="601a17b5e5ba" version="3.01.03" pid="20519"
   ppid="20518" sysuser="lechuck" sudo_user="" uid="2604" gid="2604" type="admin-ssh-as" account="lechuck"
   sudo-as="gthreepw" plugin="ssh" params="--user root --host supersecretserver.example.org --port 22"

Fields:

type
   Type of the security event that occurred. Can be:

   - admin-ssh-as: an admin impersonated another user to establish an egress connection
   - admin-sudo: an admin impersonated another user and launched an osh plugin on their behalf
   - superowner-override: a super owner used his implicit ownership on all groups to modify a group

account
   Account that emitted the security event

sudo-as
   When **type** is *admin-ssh-as* or *admin-sudo*, name of the account that was impersonated

plugin
   Name of the osh plugin that was launched

params
   Parameters passed to the plugin, or command line used to establish the egress connection

.. _log_group:

group
*****

This log is produced when a group is created or deleted.
Note that membership modifications are referenced with the **membership** type instead, see above.

Example::

   Dec 28 11:12:26 myhostname bastion: group uniqid="56f321fb3e58" version="3.01.03" pid="1325901"
   ppid="1325900" sysuser="root" sudo_user="lechuck" uid="0" gid="0" action="create" group="themonkeys"
   owner="stan" egress_ssh_key_algorithm="ed25519" egress_ssh_key_size="256" egress_ssh_key_encrypted="false"

Fields:

action
   Either *create* or *delete*, indicating whether the group has just been created or deleted

group
   The group name being created or deleted

owner
   When **action** is *create*, the name of the owner of the new group we're creating

egress_ssh_key_algorithm, egress_ssh_key_size
   When **action** is *create*, the algorithm (and size) used to generate the first pair of SSH keys,
   can be empty if ``--no-key`` was specified

egress_ssh_key_encrypted
   When **action** is *create*, if a key was generated,
   will be *true* if ``--encrypted`` has been used, *false* otherwise

.. _log_account:

account
*******

This log is produced when an account is created or deleted.

Example::

   Dec 21 14:30:26 myhostname bastion: account uniqid="ee4c91000b75" version="3.01.02" pid="537253" ppid="537252"
   sysuser="root" sudo_user="lechuck" uid="0" gid="0" action="create" account="stan" account_uid="8431"
   public_key="ssh-rsa AAAAB[...]" always_active="false" uid_auto="false" osh_only="false" immutable_key="false"
   comment="CREATED_BY=lechuck BASTION_VERSION=3.01.02 CREATION_TIME=Mon Dec 21 14:30:26 2020
   CREATION_TIMESTAMP=1608561026 COMMENT=requested_by_the_sword_master_of_melee_island_see_ticket_no_1337"

Fields:

action
   Either *create* or *delete*, indicating whether the account has just been created or deleted

account
   The account name being created or deleted

account_uid
   When **action** is *create*, the UID associated corresponding to the account we're creating

public_key
   When **action** is *create*, the public key we've generated for the new account

always_active, uid_auto, osh_only, immutable_key
   When **action** is *create*, *true* if the corresponding option was specified (``--always-active``,
   ``--uid-auto``, ``--osh-only`` or ``--immutable-key``), *false* otherwise

comment
   When **action** is *create*, the comment specified at creation if any, with some metadata that'll be stored in
   the account properties (*created_by*, *bastion_version*, *creation_time*, *creation_timestamp*)

tty_group
   When **action** is *delete*, the name of the tty group specific to this account that was deleted at the same time

.. _syslog:

Syslog
======

Files location
**************

If you use ``syslog-ng`` and installed the provided templates (which is the default if you used
the ``--new-install`` option to the install script), you'll have 4 files in your system log directory:

/var/log/bastion/bastion.log
   This is where all the bastion usage logs will be written. All the above message types can be found in this file.

/var/log/bastion/bastion-die.log
   This is where Perl crashes will be logged, with the message type ``die``.
   On a production bastion, this file should normally be empty.

/var/log/bastion/bastion-warn.log
   This is where Perl warnings will be logged, with the message type ``warning``.
   On a production bastion, this file should mostly be empty.

/var/log/bastion/bastion-scripts.log
   This is where all the satellite scripts (mostly found in the ``bin/cron/`` directory) will log their output.

Log format
**********

A syslog message will always match the following generic format::

   SYSLOG_TIME SYSLOG_HOST bastion: MSGTYPE field1="value1" field2="second value" ...

Where SYSLOG_TIME is the usual datetime field added by your local syslog daemon,
and SYSLOG_HOST the hostname of the local machine.
The MSGTYPE indicates the message type of the log line (the list of types is further below).
Then, a possibly long list of fields with quoted values, depending on the MSGTYPE.

An example follows::

   Dec 28 11:14:23 myhostname bastion: code-warning uniqid="e192fce7553a" version="3.01.03"
   pid="18803" ppid="18802" sysuser="gthreepw" sudo_user="" uid="99998" gid="99998"
   msg="Configuration error: specified adminAccounts 'joe' is not a valid account, ignoring"

In that case, the MSGTYPE is ``code-warning``, and we have a few field/value couples with some metadata of interest,
followed by a human-readable message, indicated by the ``msg`` field.

Only satellite scripts will miss the field/value construction, which will just be replaced by a plain text message.
These logs are stored in :file:`/var/log/bastion/bastion-scripts.log` by default.

Access logs
===========

If you don't or can't use :ref:`syslog`, the bastion can create and use access log files on its own,
without relying on a syslog daemon. Note that you can enable both syslog and these access logs, if you want.

These access logs will only contain :ref:`log_open` and :ref:`log_close` log types, which can be seen as "access logs".
All the other log types, such as :ref:`log_warn`, :ref:`log_membership`, etc. are only logged through syslog.

These logs are enabled through the :ref:`enableGlobalAccessLog` and :ref:`enableAccountAccessLog` options.

enableGlobalAccessLog
   When enabled, a single log file will be used, located in :file:`/home/logkeeper/global-log-YYYYMM.log`.
   There will be one file per month. Note that it can grow quite large if you have a busy bastion.

enableAccountAccessLog
   When enabled, one log file per account will be used, located in :file:`/home/USER/USER-log-YYYYMM.log`.
   There will be one file per month.

If both options are enabled, it means that every access log will be logged twice, to two different locations.
If you also enabled syslog, it's even three times!

SQLite logs
===========

If you want to store access logs into local sqlite databases, you can enable either :ref:`enableGlobalSqlLog`,
:ref:`enableAccountSqlLog`, or both.

enableGlobalSqlLog
   When enabled, a global sqlite database will be created in :file:`/home/logkeeper/global-log-YYYYMM.sqlite`.
   It'll contain one row per access (created at the same time the :ref:`log_open` log is emitted).
   The following columns exist: id, timestamp, account, cmdtype, allowed, ipfrom, ipto, portto, user, plugin, uniqid.
   Refer to the :ref:`log_open` log description to get the meaning of each column.

enableAccountSqlLog
   When enabled, an sqlite database per account will be created in :file:`/home/USER/USER-log-YYYYMM.sqlite`.
   It'll contain one row per access (created at the same time the :ref:`log_open` log is emitted),
   and the same row will be updated by the :ref:`log_close` event when it is emitted. The following columns exist:
   id, timestamp, timestampusec, account, cmdtype, allowed, hostfrom, ipfrom, bastionip, bastionport, hostto,
   ipto, portto, user, plugin, ttyrecfilee, params, timestampend, timestampendusec, returnvalue, comment, uniqid.
   Refer to the :ref:`log_open` log and :ref:`log_close` log descriptions to get the meaning of each column.
   Note that the :ref:`enableAccountSqlLog` option is required if you want the :doc:`/plugins/open/selfListSessions`
   and :doc:`/plugins/open/selfPlaySession` plugins to work, as they use this database.

Note that enabling these on a very busy bastion (several new connections per second) can create lock contention,
especially on the global log: ensure you have a fast storage. In any case, if a connection can't get the lock after
a few seconds, it'll proceed anyway, and skip writing the sql log. In that case, if you enabled syslog or
local access logs, the **globalsql** and/or the **accountsql** field will contain the error detail.

Terminal recordings (*ttyrec*)
==============================

Every egress connection is started under ``ttyrec``, which means that everything appearing on the console is recorded.
If a password is asked by some program, for example, and typing the password prints '*' or doesn't print
anything at all, this won't be recorded. This is by design. In other words, the keystrokes are not recorded,
except if they produce something on the screen.

The ttyrec files location is always :file:`/home/USER/ttyrec/REMOTEIP/file.ttyrec`, where the actual `file.ttyrec`
name can be configured by the :ref:`ttyrecFilenameFormat` option.
By default, it'll contain the date, time, account, remote ip, port and user used to start the egress connection,
as well as the uniqid, for easier correlation between all the logs produced by the same connection.
Note that for long connections, or connections producing a lot of output, ttyrec files will be transparently rotated,
without interrupting the connection.
This is to avoid ending up with ttyrec files of several gigabytes that would still be opened, written to,
hence impossible to compress, encrypt, and push to an escrow filer.
The uniqid will be the same for all the ttyrec files corresponding to the same connection.

To play ttyrec files, you can either use :doc:`/plugins/open/selfPlaySession` for yourself, or,
for admins having local access to the bastion machine, the ``ttyplay`` program can be used.
Another software, perhaps more powerful than ttyplay, can also be used:
`IPBT <https://www.chiark.greenend.org.uk/~sgtatham/ipbt/>`_ (`wiki <https://nethackwiki.com/wiki/IPBT>`_),
aka "It's PlayBack Time", by the PuTTY author.
It can do more advanced things such as look for words appearing on any frame recorded in the ttyrec file,
play files using a logarithmic speed, or display an OSD with the exact time output you're seeing has appeared.
As ttyrec is a well-known format that has been around for a while,
there are a bunch of other programs you can use to read or convert these files.
