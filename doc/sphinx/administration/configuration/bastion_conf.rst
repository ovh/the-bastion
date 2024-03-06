============
bastion.conf
============

 .. note::

   The Bastion has a lot of configuration options so that you can tailor it
   to your needs. However, if you're just beggining and would like to get
   started quickly, just configure the ``Main Options``.
   All the other options have sane defaults that can still be customized
   at a later time.

Option List
===========

Main Options options
--------------------

Those are the options you should customize when first setting up a bastion. All the other options have sane defaults and can be customized later if needed.

- `bastionName`_
- `bastionCommand`_
- `readOnlySlaveMode`_
- `adminAccounts`_
- `superOwnerAccounts`_

SSH Policies options
--------------------

All the options related to the SSH configuration and policies, both for ingress and egress connections.

- `allowedIngressSshAlgorithms`_
- `allowedEgressSshAlgorithms`_
- `minimumIngressRsaKeySize`_
- `maximumIngressRsaKeySize`_
- `minimumEgressRsaKeySize`_
- `maximumEgressRsaKeySize`_
- `defaultAccountEgressKeyAlgorithm`_
- `defaultAccountEgressKeySize`_
- `moshAllowed`_
- `moshTimeoutNetwork`_
- `moshTimeoutSignal`_
- `moshCommandLine`_

Global network policies options
-------------------------------

Those options can set a few global network policies to be applied bastion-wide.

- `dnsSupportLevel`_
- `allowedNetworks`_
- `forbiddenNetworks`_
- `ingressToEgressRules`_

Logging options
---------------

Options to customize how logs should be produced.

- `enableSyslog`_
- `syslogFacility`_
- `syslogDescription`_
- `enableGlobalAccessLog`_
- `enableAccountAccessLog`_
- `enableGlobalSqlLog`_
- `enableAccountSqlLog`_
- `ttyrecFilenameFormat`_
- `ttyrecAdditionalParameters`_
- `ttyrecStealthStdoutPattern`_

Other ingress policies options
------------------------------

Policies applying to the ingress connections

- `ingressKeysFrom`_
- `ingressKeysFromAllowOverride`_

Other egress policies options
-----------------------------

Policies applying to the egress connections

- `defaultLogin`_
- `egressKeysFrom`_
- `keyboardInteractiveAllowed`_
- `passwordAllowed`_
- `telnetAllowed`_

Session policies options
------------------------

Options to customize the established sessions behaviour

- `displayLastLogin`_
- `fanciness`_
- `interactiveModeAllowed`_
- `interactiveModeTimeout`_
- `interactiveModeByDefault`_
- `interactiveModeProactiveMFAenabled`_
- `interactiveModeProactiveMFAexpiration`_
- `idleLockTimeout`_
- `idleKillTimeout`_
- `warnBeforeLockSeconds`_
- `warnBeforeKillSeconds`_
- `accountExternalValidationProgram`_
- `accountExternalValidationDenyOnFailure`_
- `alwaysActiveAccounts`_

Account policies options
------------------------

Policies applying to the bastion accounts themselves

- `accountMaxInactiveDays`_
- `accountExpiredMessage`_
- `accountCreateSupplementaryGroups`_
- `accountCreateDefaultPersonalAccesses`_
- `ingressRequirePIV`_
- `accountMFAPolicy`_
- `MFAPasswordMinDays`_
- `MFAPasswordMaxDays`_
- `MFAPasswordWarnDays`_
- `MFAPasswordInactiveDays`_
- `MFAPostCommand`_
- `TOTPProvider`_

Other options options
---------------------

These options are either discouraged (in which case this is explained in the description) or rarely need to be modified.

- `accountUidMin`_
- `accountUidMax`_
- `ttyrecGroupIdOffset`_
- `documentationURL`_
- `debug`_
- `remoteCommandEscapeByDefault`_
- `sshClientDebugLevel`_
- `sshClientHasOptionE`_

Option Reference
================

Main Options
------------

.. _bastionName:

bastionName
***********

:Type: ``string``

:Default: ``"fix-my-config-please-missing-bastion-name"``

This will be the name advertised in the aliases admins will give to bastion users, and also in the banner of the plugins output. You can see it as a friendly name everybody will use to refer to this machine: something more friendly than just its full hostname.

.. _bastionCommand:

bastionCommand
**************

:Type: ``string``

:Default: ``"ssh USER@HOSTNAME -t --"``

The ``ssh`` command to launch to connect to this bastion as a user. This will be printed on ``accountCreate``, so that the new user knows how to connect. Magic tokens are:

- ACCOUNT or USER: replaced at runtime by the account name
- BASTIONNAME: replaced at runtime by the name defined in ``bastionName``
- HOSTNAME: replaced at runtime by the hostname of the system

So, for example if your specify ``ssh USER@HOSTNAME -t --``, it'll give ``johndoe@bastion1.example.org -t --`` as a bastion alias to *johndoe*

.. _readOnlySlaveMode:

readOnlySlaveMode
*****************

:Type: ``boolean``

:Default: ``false``

If set to ``false``, this bastion will work in standalone mode, or will be the master in a master/slave mode. If set to ``true``, this'll be the slave which means all plugins that modify groups, accounts, or access rights will be disabled, and the master bastion will push its modifications using inotify/rsync, please refer do the documentation to set this up.

.. _adminAccounts:

adminAccounts
*************

:Type: ``array of strings (account names)``

:Default: ``[]``

The list of accounts that are Admins of the bastion. Admins can't be deleted or otherwise modified by non-admins. They also gain access to special dangerous/sensitive ``--osh`` commands, such as being able to impersonate anybody else. Note that an Admin is also always considered as a Super Owner, which means they also override all checks of group administrative commands. Don't forget to add them to the ``osh-admin`` group too (system-wise), or they won't really be considered as Admins: this is an additional security measure against privilege escalation. Rule of thumb: it's probably a good idea to only add here people that have ``root`` access to the bastion machine itself.

.. _superOwnerAccounts:

superOwnerAccounts
******************

:Type: ``array of strings (account names)``

:Default: ``[]``

The list of accounts that are "Super Owners". They can run all group administrative commands, exactly as if they were implicitly owners of all the groups. Super Owners are only here as a last resort when the owners/gatekeepers/aclkeepers of a group are not available. Every command run by a Super Owner that would have failed if the account was not a Super Owner is logged explicitly as "Super Owner Override", you might want to add a rule for those in your SIEM. You can consider than the Super Owners have an implicit *sudo* for group management. Don't add here accounts that are bastion Admins, as they already inherit the Super Owner role. Don't forget to add them to the ``osh-superowner`` group too (system-wise), or they won't really be considered as "Super Owners": this is an additional security measure against privilege escalation.

SSH Policies
------------

.. _allowedIngressSshAlgorithms:

allowedIngressSshAlgorithms
***************************

:Type: ``array of strings (algorithm names)``

:Default: ``[ "rsa", "ecdsa", "ed25519" ]``

The algorithms authorized for ingress ssh public keys added to this bastion. Possible values: ``dsa``, ``rsa``, ``ecdsa``, ``ed25519``, note that some of those might not be supported by your current version of ``OpenSSH``: unsupported algorithms are automatically omitted at runtime.

.. _allowedEgressSshAlgorithms:

allowedEgressSshAlgorithms
**************************

:Type: ``array of strings (algorithm names)``

:Default: ``[ "rsa", "ecdsa", "ed25519" ]``

The algorithms authorized for egress ssh public keys generated on this bastion. Possible values: ``dsa``, ``rsa``, ``ecdsa``, ``ed25519``, note that some of those might not be supported by your current version of ``OpenSSH``, unsupported algorithms are automatically omitted at runtime.

.. _minimumIngressRsaKeySize:

minimumIngressRsaKeySize
************************

:Type: ``int > 0``

:Default: ``2048``

The minimum allowed size for ingress RSA keys (user->bastion). Sane values range from 2048 to 4096.

.. _maximumIngressRsaKeySize:

maximumIngressRsaKeySize
************************

:Type: ``int > 0``

:Default: ``8192``

The maximum allowed size for ingress RSA keys (user->bastion). Too big values (>8192) are extremely CPU intensive and don't really add that much security.

.. _minimumEgressRsaKeySize:

minimumEgressRsaKeySize
***********************

:Type: ``int > 0``

:Default: ``2048``

The minimum allowed size for egress RSA keys (bastion->server). Sane values range from 2048 to 4096.

.. _maximumEgressRsaKeySize:

maximumEgressRsaKeySize
***********************

:Type: ``int > 0``

:Default: ``8192``

The maximum allowed size for ingress RSA keys (bastion->server). Too big values (>8192) are extremely CPU intensive and don't really add that much security.

.. _defaultAccountEgressKeyAlgorithm:

defaultAccountEgressKeyAlgorithm
********************************

:Type: ``string``

:Default: ``"rsa"``

The default algorithm to use to create the egress key of a newly created account

.. _defaultAccountEgressKeySize:

defaultAccountEgressKeySize
***************************

:Type: ``int > 0``

:Default: ``4096``

The default size to use to create the egress key of a newly created account (also see ``defaultAccountEgressKeyAlgorithm``)

.. _moshAllowed:

moshAllowed
***********

:Type: ``boolean``

:Default: ``false``

If set to ``true``, mosh usage is allowed (mosh needs to be installed on serverside, obviously). Otherwise, this feature is disabled.

.. _moshTimeoutNetwork:

moshTimeoutNetwork
******************

:Type: ``int > 0``

:Default: ``86400``

Number of seconds of inactivity (network-wise) after a mosh-server will exit. By design even if the client is disconnected "for good", mosh-server would wait forever. If mosh is meant to handle shaky connections but not mobility, you can set this to a low value. It sets the ``MOSH_SERVER_NETWORK_TMOUT`` envvar for mosh, see ``man mosh-server`` for more information (mosh 1.2.6+).

.. _moshTimeoutSignal:

moshTimeoutSignal
*****************

:Type: ``int > 0``

:Default: ``30``

Number of seconds of inactivity (network-wise) a mosh-server will wait after receiving a ``SIGUSR1`` before exiting. It sets the ``MOSH_SERVER_SIGNAL_TMOUT`` envvar for mosh, see ``man mosh-server`` for more information (mosh 1.2.6+).

.. _moshCommandLine:

moshCommandLine
***************

:Type: ``string``

:Default: ``""``

:Example: ``"-s -p 40000:49999"``

Additional parameters that will be passed as-is to mosh-server. See ``man mosh-server``, you should at least add the ``-p`` option to specify a fixed number of ports (easier for firewall configuration).

Global network policies
-----------------------

.. _dnsSupportLevel:

dnsSupportLevel
***************

:Type: ``integer between 0 and 2``

:Default: ``2``

If set to 0, The Bastion will never attempt to do DNS or reverse-DNS resolutions, and return an error if you request connection to a hostname instead of an IP. Use this if you know there's no working DNS in your environment and only use IPs everywhere.
 If set to 1, The Bastion will not attempt to do DNS or reverse-DNS resolutions unless you force it to (i.e. by requesting connection to a hostname instead of an IP). You may use this if for example you have well-known hostnames in /etc/hosts, but don't have a working DNS (which would imply that reverse-DNS resolutions will always fail).
 If set to 2, The Bastion will make the assumption that you have a working DNS setup, and will do DNS and reverse-DNS resolutions normally.

.. _allowedNetworks:

allowedNetworks
***************

:Type: ``array of strings (IPs and/or prefixes)``

:Default: ``[]``

:Example: ``["10.42.0.0/16","192.168.111.0/24","203.0.113.42"]``

Restricts egress connection attempts to those listed networks only. This is enforced at all times and can NOT be overridden by users. If you are lucky enough to have you own IP blocks, it's probably a good idea to list them here. An empty array means no restriction is applied.

.. _forbiddenNetworks:

forbiddenNetworks
*****************

:Type: ``array of strings (IPs and/or prefixes)``

:Default: ``[]``

:Example: ``["10.42.42.0/24"]``

Prevents egress connection to the listed networks, this takes precedence over ``allowedNetworks``. This can be used to prevent connection to some hosts or subnets in a broadly allowed prefix. This is enforced at all times and can NOT be overridden by users.

.. _ingressToEgressRules:

ingressToEgressRules
********************

:Type: ``array of rules, a rule being a 3-uple of [array, array, string]``

:Default: ``[]``

Fine-grained rules (a la *netfilter*) to apply global restrictions to possible egress destinations given ingress IPs. This is similar to ``allowedNetworks`` and ``forbiddenNetworks``, but way more powerful (in fact, those two previous options can be expressed exclusively using ``ingressToEgressRules``). Those rules here are enforced at all times and can **NOT** be overridden by users or admins.
Each rule will be processed **IN ORDER**. The first rule to match will be applied and no other rule will be checked.
If no rule matches, the default is to apply no restriction.
A rule is a 3-uple of [``array of ingress networks``, ``array of egress networks``, ``policy to apply``].

- ``array of ingress networks``: if the IP of the ingress connection matches a network or IP in this list, the rule *may* apply: we proceed to check the egress network IP
- ``array of egress networks``: if the IP of the egress connection matches a network or IP in this list, the rule *does* apply and we'll enforce the policy defined in the third item of the rule
- ``policy to apply``: this is what to enforce when the ingress and egress network match

The "policy to apply" item can have 3 values:

- ``ALLOW``, no restriction will be applied (all rights-check of groups and personal accesses still apply)
- ``DENY``, access will be denied regardless of any group or personal accesses
- ``ALLOW-EXCLUSIVE``, access will be allowed **if and only if** the egress network match, given the ingress network. In other words, if the ingress IP matches one of the ingress networks specified in the rule, but the egress IP **DOES NOT** match any of the egress network specified, access will be denied. This is an easy way to ensure that a given list of ingress networks can only access a precise list of egress networks and nothing else.

For example, take the following configuration:

::

   [
      [["10.19.0.0/16","10.15.15.0/24"], ["10.20.0.0/16"],    "ALLOW-EXCLUSIVE"],
      [["192.168.42.0/24"],              ["192.168.42.0/24"], "ALLOW"],
      [["192.168.0.0/16"],               ["192.168.0.0/16"],  "DENY"]
   ]

- The ``10.19.0.0/16`` and ``10.15.15.0/24`` networks can only access the ``10.20.0.0/16`` network (rule ``#1``)
- The ``192.168.42.0/24`` network can access any machine from its own /24 network (rule ``#2``), but not any other machine from the wider ``192.168.0.0/16`` network (rule ``#3``). It can however access any other machine outside of this block (implicit allow catch-all rule, as there is no corresponding ``DENY`` rule, and rule ``#2`` is ``ALLOW`` and not ``ALLOW-EXCLUSIVE``)
- The ``192.168.0.0/16`` network (except ``192.168.42.0/16``) can access any machine except one from its own network (rule ``#3``)
- All the other networks can access any other network (including egress ``10.20.0.0/16`` or egress ``192.168.0.0/16``)

In any case, all the personal and group accesses still apply in addition to these global rules.

Logging
-------

.. _enableSyslog:

enableSyslog
************

:Type: ``boolean``

:Default: ``true``

If enabled, we'll send logs through syslog, don't forget to setup your syslog daemon!. You can also adjust ``syslogFacility`` and ``syslogDescription`` below, to match your syslog configuration. Note that the provided ``syslog-ng`` templates work with the default values left as-is.

.. _syslogFacility:

syslogFacility
**************

:Type: ``string``

:Default: ``"local7"``

Sets the facility that will be used for syslog.

.. _syslogDescription:

syslogDescription
*****************

:Type: ``string``

:Default: ``"bastion"``

Sets the description that will be used for syslog.

.. _enableGlobalAccessLog:

enableGlobalAccessLog
*********************

:Type: ``boolean``

:Default: ``true``

If enabled, all *open* and *close* logs will be written to ``/home/logkeeper/global-log-YYYYMM.log``. Those are also logged through syslog if *enableSyslog* is set.

.. _enableAccountAccessLog:

enableAccountAccessLog
**********************

:Type: ``boolean``

:Default: ``true``

If enabled, all *open* and *close* logs will be written to the corresponding user's home in ``/home/USER/USER-log-YYYYMM.log``. Those are also logged through syslog if *enableSyslog* is set.

.. _enableGlobalSqlLog:

enableGlobalSqlLog
******************

:Type: ``boolean``

:Default: ``true``

If enabled, all access logs (corresponding to the *open* and *close* events) will be written in a short SQL format, as one row per access, to ``/home/logkeeper/global-log-YYYYMM.sqlite``.

.. _enableAccountSqlLog:

enableAccountSqlLog
*******************

:Type: ``boolean``

:Default: ``true``

If enabled, all access logs (corresponding to the *open* and *close* events) will be written in a detailed SQL format, as one row per access, in the corresponding user's home to ``/home/USER/USER-log-YYYYMM.sqlite``. If you want to use ``selfListSessions`` and/or ``selfPlaySession``, this is required.

.. _ttyrecFilenameFormat:

ttyrecFilenameFormat
********************

:Type: ``string``

:Default: ``"%Y-%m-%d.%H-%M-%S.#usec#.&uniqid.&account.&user.&ip.&port.ttyrec"``

Sets the filename format of the output files of ttyrec for a given session. Magic tokens are: ``&bastionname``, ``&uniqid``, ``&account``, ``&ip``, ``&port``, ``&user`` (they'll be replaced by the corresponding values of the current session). Then, this string (automatically prepended with the correct folder) will be passed to ttyrec's ``-F`` parameter, which uses ``strftime()`` to expand it, so the usual character conversions will be done (``%Y`` for the year, ``%H`` for the hour, etc., see ``man strftime``). Note that in a addition to the usual ``strftime()`` conversion specifications, ttyrec also supports ``#usec#``, to be replaced by the current microsecond value of the time.

.. _ttyrecAdditionalParameters:

ttyrecAdditionalParameters
**************************

:Type: ``array of strings``

:Default: ``[]``

:Example: ``["-s", "This is a message with spaces", "--zstd"]``

Additional parameters you want to pass to ``ttyrec`` invocation. Useful, for example, to enable on-the-fly compression, disable cheatcodes, or set/unset any other ``ttyrec`` option. This is an ARRAY, not a string.

.. _ttyrecStealthStdoutPattern:

ttyrecStealthStdoutPattern
**************************

:Type: ``regex``

:Default: ``""``

:Example: ``"^rsync --server .+"``

When this is set to a non-falsy value, this is expected to be a string that will be converted to a regex which will be matched against a potential remote command specified when connecting through SSH to a remote server. If the regex matches, then we'll instruct ttyrec to NOT record stdout for this session.

Other ingress policies
----------------------

.. _ingressKeysFrom:

ingressKeysFrom
***************

:Type: ``array of strings (list of IPs and/or prefixes)``

:Default: ``[]``

This array of IPs (or prefixes, such as ``10.20.30.0/24``) will be used to build the ``from="..."`` in front of the ingress account public keys used to connect to the bastion (in ``accountCreate`` or ``selfAddIngressKey``). If the array is empty, then **NO** ``from="..."`` is added (this lowers the security).

.. _ingressKeysFromAllowOverride:

ingressKeysFromAllowOverride
****************************

:Type: ``boolean``

:Default: ``false``

If set to ``false``, any user-specified ``from="..."`` prefix on keys in commands such as ``selfAddIngressKey`` or ``accountCreate`` are silently ignored and replaced by the IPs in the ``ingressKeysFrom`` configuration option (if any).
If set to ``true``, any user-specified ``from="..."`` will override the value set in ``ingressKeysFrom`` (if any).
Note that when no user-specified ``from="..."`` appears, the value of ``ingressKeysFrom`` is still used, regardless of this option.

Other egress policies
---------------------

.. _defaultLogin:

defaultLogin
************

:Type: ``string``

:Default: ``""``

The default remote user to use for egress ssh connections where no user has been specified by our caller. If set to the empty string (``""``), will default to the account name of the caller. If your bastion is mainly used to connect as ``root`` on remote systems, you might want to set this to ``root`` for example, to spare a few keystrokes to your users. This is only used when no user is specified on the connection line. For example if your bastion alias is ``bssh``, and you say ``bssh srv1.example.net``, the value of the ``defaultLogin`` value will be used as the user to login as remotely.

.. _egressKeysFrom:

egressKeysFrom
**************

:Type: ``array of strings (IPs and/or prefixes)``

:Default: ``[]``

These IPs will be added to the ``from="..."`` of the personal account keys and the group keys. Typically you want to specify only the bastions IP here (including all the slaves). Note that if this option is NOT set at all or set to the empty array, it will default to autodetection at runtime (using ``hostname --all-ip-addresses`` under the hood). This is dependent from your system configuration and is therefore discouraged.

.. _keyboardInteractiveAllowed:

keyboardInteractiveAllowed
**************************

:Type: ``boolean``

:Default: ``true``

If set to ``true``, will allow keyboard-interactive authentication when publickey auth is requested for egress connections, this is needed e.g. for 2FA.

.. _passwordAllowed:

passwordAllowed
***************

:Type: ``boolean``

:Default: ``false``

If set to ``true``, will allow password authentication for egress ssh, so that user can type his remote password interactively.

.. _telnetAllowed:

telnetAllowed
*************

:Type: ``boolean``

:Default: ``false``

If set to ``true``, will allow telnet egress connections (``-e`` / ``--telnet``).

Session policies
----------------

.. _displayLastLogin:

displayLastLogin
****************

:Type: ``boolean``

:Default: ``true``

If ``true``, display their last login information on connection to your users.

.. _fanciness:

fanciness
*********

:Type: ``string``

:Default: ``full``

Customize to which extent the text output by the program will use decorations to enhance human-friendliness and highlight warnings or critical messages. Note that if a given session's terminal doesn't advertise UTF-8 support, UTF-8 will not be used, regardless of what is set here.

- "none": Text will only consist of us-ascii characters
- "basic": UTF-8 characters will be used to draw tables, instead of ---'s, among other things
- "full": Some emoticons may appear to highlight important messages

.. _interactiveModeAllowed:

interactiveModeAllowed
**********************

:Type: ``boolean``

:Default: ``true``

If set to ``true``, ``--interactive`` mode is allowed. Otherwise, this feature is disabled.

.. _interactiveModeTimeout:

interactiveModeTimeout
**********************

:Type: ``int >= 0 (seconds)``

:Default: ``60``

The number of idle seconds after which the user is disconnected from the bastion when in interactive mode. A value of 0 will disable this feature (user will never be disconnected for idle timeout).

.. _interactiveModeByDefault:

interactiveModeByDefault
************************

:Type: ``boolean``

:Default: ``true``

If ``true``, drops the user to interactive mode if nothing is specified on the command line. If ``false``, displays the help and exits with an error. Note that for ``true`` to have the expected effect, interactive mode must be enabled (see the ``interactiveModeAllowed`` option above).

.. _interactiveModeProactiveMFAenabled:

interactiveModeProactiveMFAenabled
**********************************

:Type: ``boolean``

:Default: ``true``

If enabled, the ``mfa`` command is allowed in interactive mode, to trigger a proactive MFA challenge, so that subsequent commands normally requiring MFA won't ask for it again.

.. _interactiveModeProactiveMFAexpiration:

interactiveModeProactiveMFAexpiration
*************************************

:Type: ``int >= 0 (seconds)``

:Default: ``900``

If the above ``interactiveModeProactiveMFAenabled`` option is ``true``, then this is the amount of seconds after which the proactive MFA mode is automatically disengaged.

.. _idleLockTimeout:

idleLockTimeout
***************

:Type: ``int >= 0 (seconds)``

:Default: ``0``

If set to a positive value >0, the number of seconds of input idle time after which the session is locked. If ``false``, disabled.

.. _idleKillTimeout:

idleKillTimeout
***************

:Type: ``int >= 0 (seconds)``

:Default: ``0``

If set to a positive value >0, the number of seconds of input idle time after which the session is killed. If ``false``, disabled. If ``idleLockTimeout`` is set, this value must be higher (obviously).

.. _warnBeforeLockSeconds:

warnBeforeLockSeconds
*********************

:Type: ``int >= 0 (seconds)``

:Default: ``0``

If set to a positive value >0, the number of seconds before ``idleLockTimeout`` where the user will receive a warning message telling them about the upcoming lock of his session. Don't enable this (by setting a non-zero value) if `idleLockTimeout` is disabled (set to zero).

.. _warnBeforeKillSeconds:

warnBeforeKillSeconds
*********************

:Type: ``int >= 0 (seconds)``

:Default: ``0``

If set to a positive value >0, the number of seconds before ``idleKillTimeout`` where the user will receive a warning message telling them about the upcoming kill of his session. Don't enable this (by setting a non-zero value) if `idleKillTimeout` is disabled (set to zero).

.. _accountExternalValidationProgram:

accountExternalValidationProgram
********************************

:Type: ``string (path to a binary)``

:Default: ``""``

:Example: ``"$BASEDIR/bin/other/check-active-account-simple.pl"``

Binary or script that will be called by the bastion, with the account name in parameter, to check whether this account should be allowed to connect to the bastion. If empty, this check is skipped. ``$BASEDIR`` is a magic token that is replaced by where the bastion code lives (usually, ``/opt/bastion``).

You can use this configuration parameter to counter-verify all accounts against an external system, for example an *LDAP*, an *Active Directory*, or any system having a list of identities, right when they're connecting to the bastion (on the ingress side). However, it is advised to avoid calling an external system in the flow of an incoming connection, as this violates the "the bastion must be working at all times, regardless of the status of the other components of the company's infrastructure" rule. Instead, you should have a cronjob to periodically fetch all the allowed accounts from said external system, and store this list somewhere on the bastion, then write a simple script that will be called by the bastion to verify whether the connecting account is present on this locally cached list.

An account present in this list is called an *active account*, in the bastion's jargon. An *inactive* account is an account existing on the bastion, but not in this list, and won't be able to connect. Note that for security reasons, inactive bastions administrators would be denied as any other account.

The result is interpreted from the program's exit code. If the program return 0, the account is deemed active. If the program returns 1, the account is deemed inactive. A return code of 2, 3 or 4 indicates a failure of the program in determining the activeness of the account. In this case, the decision to allow or deny the access is determined by the ``accountExternalValidationDenyOnFailure`` option below. Status code 3 additionally logs the ``stderr`` of the program *silently* to the syslog: this can be used to warn admins of a problem without leaking information to the user. Status code 4 does the same, but the ``stderr`` is also shown directly to the user. Any other return code deems the account inactive (same behavior that return code 1).

.. _accountExternalValidationDenyOnFailure:

accountExternalValidationDenyOnFailure
**************************************

:Type: ``boolean``

:Default: ``true``

If we can't validate an account using the program configured in ``accountExternalValidationProgram``, for example because the path doesn't exist, the file is not executable, or because the program returns the exit code 4 (see above for more information), this configuration option indicates whether we should deny or allow access.

Note that the bastion admins will always be allowed if the ``accountExternalValidationProgram`` doesn't work correctly, because they're expected to be able to fix it. They would be denied, as any other account, if ``accountExternalValidationProgram`` works correctly and denies them access, however. If you're still testing your account validation procedure, and don't want to break your users workflow while you're not 100% sure it works correctly, you can say ``false`` here, and return 4 instead of 1 in your ``accountExternalValidationProgram`` when you would want to deny access.

.. _alwaysActiveAccounts:

alwaysActiveAccounts
********************

:Type: ``array of strings (account names)``

:Default: ``[]``

List of accounts which should NOT be checked against the ``accountExternalValidationProgram`` mechanism above (for example bot accounts). This can also be set per-account at account creation time or later with the ``accountModify`` plugin's ``--always-active`` flag.

Account policies
----------------

.. _accountMaxInactiveDays:

accountMaxInactiveDays
**********************

:Type: ``int >= 0 (days)``

:Default: ``0``

If > 0, deny access to accounts that didn't log in since at least that many days. A value of 0 means that this functionality is disabled (we will never deny access for inactivity reasons).

.. _accountExpiredMessage:

accountExpiredMessage
*********************

:Type: ``string``

:Default: ``""``

If non-empty, customizes the message that will be printed to a user attempting to connect with an expired account (see ``accountMaxInactiveDays`` above). When empty, defaults to the standard message "Sorry, but your account has expired (#DAYS# days), access denied by policy.". The special token ``#DAYS#`` is replaced by the number of days since we've last seen this user.

.. _accountCreateSupplementaryGroups:

accountCreateSupplementaryGroups
********************************

:Type: ``array of strings (system group names)``

:Default: ``[]``

List of system groups to add a new account to when its created (see ``accountCreate``). Can be useful to grant some restricted commands by default to new accounts. For example ``osh-selfAddPersonalAccess``, ``osh-selfDelPersonalAccess``, etc. Note that the group here are **NOT** *bastion groups*, but system groups.

.. _accountCreateDefaultPersonalAccesses:

accountCreateDefaultPersonalAccesses
************************************

:Type: ``array of strings (list of IPs and/or prefixes)``

:Default: ``[]``

List of strings of the form USER@IP or USER@IP:PORT or IP or IP:PORT, with IP being IP or prefix (such as 1.2.3.0/24). This is the list of accesses to add to the personal access list of newly created accounts. The special value ACCOUNT is replaced by the name of the account being created. This can be useful to grant some accesses by default to new accounts (for example ACCOUNT@0.0.0.0/0)

.. _ingressRequirePIV:

ingressRequirePIV
*****************

:Type: ``boolean``

:Default: ``false``

When set to true, only PIV-enabled SSH keys will be able to be added with selfAddIngressKey, hence ensuring that an SSH key generated on a computer, and not within a PIV-compatible hardware token, can't be used to access The Bastion. If you only want to enable this on a per-account basis, leave this to false and set the flag on said accounts using accountPIV instead. When set to false, will not require PIV-enabled SSH keys to be added by selfAddIngressKey. If you have no idea what PIV keys are, leave this to false, this is what you want.

.. _accountMFAPolicy:

accountMFAPolicy
****************

:Type: ``string``

:Default: ``"enabled"``

Set a MFA policy for the bastion accounts, the supported values are:

- ``disabled``: the commands to setup TOTP and UNIX account password are disabled, nobody can setup MFA for themselves or others. Already configured MFA still applies, unless the sshd configuration is modified to no longer call PAM on the authentication phase
- ``password-required``: for all accounts, a UNIX account password is required in addition to the ingress SSH public key. On first connection with his SSH key, the user is forced to setup a password for his account, and can't disable it afterwards
- ``totp-required``: for all accounts, a TOTP is required in addition to the ingress SSH public key. On first connection with his SSH key, the user is forced to setup a TOTP for his account, and can't disable it afterwards
- ``any-required``: for all accounts, either a TOTP or an UNIX account password is required in addition to the ingress SSH public key. On first connection with his SSH key, the user is forced to setup either of those, as he sees fit, and can't disable it afterwards
- ``enabled``: for all accounts, TOTP and UNIX account password are available as opt-in features as the users see fit. Some accounts can be forced to setup either TOTP or password-based MFA if they're flagged accordingly (with the accountModify command)


.. _MFAPasswordMinDays:

MFAPasswordMinDays
******************

:Type: ``int >= 0 (days)``

:Default: ``0``

For the PAM UNIX password MFA, sets the min amount of days between two password changes (see ``chage -m``)

.. _MFAPasswordMaxDays:

MFAPasswordMaxDays
******************

:Type: ``int >= 0 (days)``

:Default: ``90``

For the PAM UNIX password MFA, sets the max amount of days after which the password must be changed (see ``chage -M``)

.. _MFAPasswordWarnDays:

MFAPasswordWarnDays
*******************

:Type: ``int >= 0 (days)``

:Default: ``15``

For the PAM UNIX password MFA, sets the number of days before expiration on which the user will be warned to change his password (see ``chage -W``)

.. _MFAPasswordInactiveDays:

MFAPasswordInactiveDays
***********************

:Type: ``int >= -1 (days)``

:Default: ``-1``

For the PAM UNIX password MFA, the account will be blocked after the password is expired (and not renewed) for this amount of days (see ``chage -E``). -1 disables this feature. Note that this is different from the ``accountMaxInactiveDays`` option above, that is handled by the bastion software itself instead of PAM

.. _MFAPostCommand:

MFAPostCommand
**************

:Type: ``array of strings (a valid system command)``

:Default: ``[]``

:Example: ``["sudo","-n","-u","root","--","/sbin/pam_tally2","-u","%ACCOUNT%","-r"] or ["/usr/sbin/faillock","--reset"]``

When using JIT MFA (i.e. not directly by calling PAM from SSHD's configuration, but using ``pamtester`` from within the code), execute this command on success.
This can be used for example if you're using ``pam_tally2`` or ``pam_faillock`` in your PAM MFA configuration, ``pamtester`` can't reset the counter to zero because this is usually done in the ``account_mgmt`` PAM phase. You can use a script to reset it here.
The magic token ``%ACCOUNT%`` will be replaced by the account name.
Note that usually, ``pam_tally2`` can only be used by root (hence might require the proper sudoers configuration), while ``faillock`` can directly be used by unprivileged users to reset their counter.

.. _TOTPProvider:

TOTPProvider
************

:Type: ``string``

:Default: ``'google-authenticator'``

Defines which is the provider of the TOTP MFA, that will be used for the ``(self|account)MFA(Setup|Reset)TOTP`` commands. Allowed values are:
- none: no TOTP providers are defined, the corresponding setup commands won't be available.
- google-authenticator: the pam_google_authenticator.so module will be used, along with its corresponding setup binary. This is the default, for backward compatibility reasons. This is also what is configured in the provided pam templates.
- duo: enable the use of the Duo PAM module (pam_duo.so), of course you need to set it up correctly in your `/etc/pam.d/sshd` file.

Other options
-------------

.. _accountUidMin:

accountUidMin
*************

:Type: ``int >= 100``

:Default: ``2000``

Minimum allowed UID for accounts on this bastion. Hardcoded > 100 even if configured for less.

.. _accountUidMax:

accountUidMax
*************

:Type: ``int > 0``

:Default: ``99999``

Maximum allowed UID for accounts on this bastion.

.. _ttyrecGroupIdOffset:

ttyrecGroupIdOffset
*******************

:Type: ``int > 0``

:Default: ``100000``

Offset to apply on user group uid to create its ``-tty`` group, should be > ``accountUidMax - accountUidMin`` to ensure there is no overlap.

.. _documentationURL:

documentationURL
****************

:Type: ``string``

:Default: ``"https://ovh.github.io/the-bastion/"``

The URL of the documentation where users will be pointed to, for example when displaying help. If you have some internal documentation about the bastion, you might want to advertise it here.

.. _debug:

debug
*****

:Type: ``boolean``

:Default: ``false``

Enables or disables debug *GLOBALLY*, printing a lot of information to anyone using the bastion. Don't enable this unless you're chasing a bug in the code and are familiar with it.

.. _remoteCommandEscapeByDefault:

remoteCommandEscapeByDefault
****************************

:Type: ``boolean``

:Default: ``false``

If set to ``false``, will not escape simple quotes in remote commands by default. Don't enable this, this is to keep compatibility with an ancient broken behavior. Will be removed in the future. Can be overridden at runtime with ``--never-escape`` and ``--always-escape``.

.. _sshClientDebugLevel:

sshClientDebugLevel
*******************

:Type: ``int (0-3)``

:Default: ``0``

Indicates the number of ``-v``'s that will be added to the ssh client command line when starting a session. Probably a bad idea unless you want to annoy your users.

.. _sshClientHasOptionE:

sshClientHasOptionE
*******************

:Type: ``boolean``

:Default: ``false``

Set to ``true`` if your ssh client supports the ``-E`` option and you want to use it to log debug info on opened sessions. **Discouraged** because it has some annoying side effects (some ssh errors then go silent from the user perspective).

