## v3.19.01 - 2025/03/04
- feat: httpproxy: optional support for plain http on egress
- fix: selfPlaySession: warn in syslog properly
- chore: github actions: replace ubuntu 20.04 by 24.04 (EOL)

## v3.19.00 - 2025/02/25
- feat: add agent forwarding support on egress side
- feat: add undocumented rename-account.sh and modify osh-orphaned-homedir.sh accordingly
- chg: upgrade tests from FreeBSD 13.2 to 14.2
- enh: ssh autologin: allow TERM env passthrough
- enh: use only TL1 special chars when generating passwords
- chore: github actions: add timeouts, always launch short tests

## v3.18.99-rc1 - 2025/01/03
- feat: IPv6 support
- chg: set ECDSA as default egress key algo for new installs
- chg: ``groupInfo``: remove deprecated JSON fields
- enh: 35% faster ``is_valid_ip()`` when fast=1
- enh: ``accountInfo``: add osh-only information for accounts
- enh: tests: add ``--skip-functional-tests`` and ``--skip-unit-tests``
- fix: ``accountInfo``: don't attempt (and fail) to display info non-auditors don't have access to
- fix: ``groupInfo``: don't attempt to (and fail) display the guest list when account doesn't have access to it
- fix: deny subnets for ``nc``, ``mtr``, ``ping``, ``alive`` plugins
- fix: is_in_any_net: support matching netblocks
- chore: faster tests by removing grant/revoke command dance
- chore: tests: no longer run consistency check by default
- chore: update README
- chore: use proper naming of 'subnet' instead of 'prefix' or 'slash'
- chore: use ``TAP::Harness`` for unit tests
- chore: factorize user@host:port display in ``machine_display()``

## v3.18.00 - 2024/12/10
- feat: add assetForgetHostKey
- fix: scp: downloads would sometimes stall (fix #486)
- chore: add release notes to doc/
- chore: add check of release-notes file in pre-commit

## v3.17.01 - 2024/10/23
- enh: interactive: handle CTRL+C nicely (fix #497)
- fix: osh.pl: remove a warning on interactive mode timeout
- fix: allow ssh-as in connect.pl
- chore: fix bad scpup/scpupload scp/scpdownload references in help and doc
- chore: change pod cuts to make recent versions of perltidy happy

## v3.17.00 - 2024/10/14
- fix: osh.pl: propagate signals to plugins before exiting
- fix: opensuse: add procps package (for pkill)

## v3.16.99-rc3 - 2024/09/25
- fix: regression introduced by 932e72e (rc1) for stealth stdout in ssh

## v3.16.99-rc2 - 2024/09/17
- feat: add rsync support through the ``--protocol rsync`` option in all plugins
- feat: add ``--egress-session-multiplexing`` option to ``accountModify``
- feat: add ``groupSetServers`` to entirely change a group ACL in one shot
- enh: add lock for group ACL change to avoid race conditions on busy bastions
- enh: ``selfPlaySession``: remove sqliteLog.ttyrecfile dependency
- chore: FreeBSD: ignore OS version mismatch with packages
- chore: ``selfMFASetupPassword``: clearer message

## v3.16.99-rc1 - 2024/07/04
- feat: support wildcards in --user for ACL management plugins (fix #461)
- feat: accountFreeze: terminate running sessions if any
- chg: support: add Ubuntu 24.04 LTS
- chg: support: bump OpenSUSE Leap from 15.5 to 15.6
- chg: support: remove CentOS 7 (EOL)
- chg: support: remove Ubuntu 16.04 LTS (EOL)
- enh: enable sntrup KEX by default for supported OpenSSH versions (Debian12, Ubuntu20+)
- enh: autologin: set term to ``raw noecho`` when --no-tty is used
- fix: stealth\_stdout/stderr was ignored for plugins (fix #482)
- fix: ignore transient errors during global destruction
- fix: install of ttyrec was failing under FreeBSD 13.2
- fix: selfGenerateProxyPassword: help message was incorrect

## v3.16.01 - 2024/04/17
- enh: info: removed uname dependency, added configuration
- chg: bastion-sync-helper.sh: use sh instead of bash
- fix: alive: don't mask signals
- chore: add README file into install/modules to ensure the folder exists even if empty
- chore: linters: limit to known directories

## v3.16.00 - 2024/04/10
- feat: support hardware-based Secure Keys (FIDO2) for ingress authentication
- enh: remove netcat dependency by using perl builtins
- enh: --wait now checks whether the TCP port is open instead of just pinging the host
- fix: logic error in etc/pam.d/sshd.rhel breaking MFA handling if enabled

## v3.15.00 - 2024/03/22
- feat: add ``dnsSupportLevel`` option for systems with broken DNS (fixes #397)
- enh: allow ``@`` as a valid remote user char (fixes #437)
- enh: ``interactive``: autocomplete: allow multi-spaces, remove unnecessary loops, fix display
- fix: ``connect.pl``: don't look for error messages when sysret==0
- fix: avoid a warning when an non-resolvable host is specified with ``scp`` or ``sftp``

## v3.14.16 - 2024/02/20
- feat: add ``ttyrecStealthStdoutPattern`` config
- enh: ``batch``: openhandle() is overkill and doesn't work on EOF
- enh: ``osh-lingering-sessions-reaper.sh``: handle dangling plugins
- enh: ``osh-orphaned-homedir.sh``: also cleanup ``/run/faillock``
- enh: plugins: better signal handling to avoid dangling children processes
- fix: ``accountInfo``: return always\_active=1 for globally-always-active accounts
- fix: don't exit with ``fping`` when host is unreachable
- fix: ``fixrights.sh``: add +x ``run-tool.sh``
- fix: ``osh-sync-watcher``: default to a valid ``rshcmd`` (fixes #433)
- fix: install: generation of the MFA secret under FreeBSD
- fix: install: silence ``tr`` message on secret generation

## v3.14.15 - 2023/11/08
- feat: support JIT MFA through plugins, including ``sftp`` and ``scp`` (fixes CVE-2023-45140)
- feat: add configuration option for plugins to override the global lock/kill timeout
- enh: ``setup-gpg.sh``: allow importing multiple public keys at once
- enh: ``connect.pl``: report empty ttyrec as ``ttyrec_empty`` instead of ``ttyrec_error``
- enh: orphaned homedirs: adjust behavior on master instances
- fix: check\_collisions: don't report orphan uids on slave, just use their name
- fix: ``scp``: adapt wrapper and tests to new ``scp`` versions requiring ``-O``
- meta: dev: add devenv docker, pre-commit info, and documentation on how to use them, along with how to write integration tests

## v3.14.00 - 2023/09/19
- feat: add type8 and type9 password hashes
- feat: add stealth\_stderr/stdout ttyrec support, enable it for scp & sftp

## v3.13.01 - 2023/08/22
- enh: setup-gpg.sh: create additional backup signing config with --generate
- fix: clush: restore default handlers for SIGHUP/PIPE
- doc: add JSON API and MFA documentations

## v3.13.00 - 2023/07/28
- enh: use ttyrec instead of sqlite to record plugin output
- fix: selfMFASetupPassword: restore default sighandlers to avoid being zombified
- chore: tests: ensure test modules don't pollute the caller's env
- chore: remove incorrect `-v` ssh option in help text
- chore: doc: fix a few typos

## v3.12.00 - 2023/06/27
- feat: add 2 configurable knobs to ``(self|account)AddPersonalAccess``
- feat: add dryrun in ``access_modify()`` and widest prefix precondition check
- feat: plugins: add loadConfig parameter & config validator support
- chg: drop support for Debian 9, add support for Debian 12
- fix: ``accountList``: crash in some cases
- fix: add missing autocompletions, readonly flags and help category for some plugins
- fix: update undocumented ``rename-group.sh`` script
- chore: doc: adding plugin configuration autogeneration
- chore: fix GitHub actions under FreeBSD
- chore: shell/functions: remove now unused global var

## v3.11.02 - 2023/04/18
- feat: add uid/gid collisions checking script & document it for HA cluster setup and backup restore (#378)
- fix: ``groupAddServer``: ``--force-key`` wasn't working properly (#259)
- fix: ``groupInfo``: reintroduce group name in human-readable output (mistakenly removed in v3.11.00)
- fix: tests: race condition after sshd reload that could sometimes make testcases fail
- chg: add Debian 12 to tests (not released yet, so not officially supported for now)
- chg: add RockyLinux 9 support
- chg: bump OpenSUSE Leap tests from 15.3 to 15.4
- chg: push sandbox and tester images from Debian 10 to Debian 11
- remove: get rid of decade-old Debian ``openssh-blacklist`` logic
- remove: get rid of deprecated ``UseRoaming`` option from ``ssh_config``
- chore: update DockerHub workflow to push sandbox image on release
- doc: update broken blog links

## v3.11.01 - 2023/03/27
- fix: ``groupInfo``: empty gatekeepers list and guest accesses list amount in human output (introduced in v3.11.00)

## v3.11.00 - 2023/03/23
- feat: add ``sftp`` support
- feat: add the possibility to auditors of listing all groups with ``groupInfo`` and all accounts with ``accountInfo``,
    using ``--all``, along with filtering additional data with ``--with-*`` and ``without-*`` new options
- enh: ``setup-encryption.sh``: don't require install to be called before us
- fix: race condition when two parallel account creations used the ``uid-auto`` option
- doc: add restore from backup howto
- doc: add PuTTY connection setup howto

## v3.10.00 - 2023/02/17
- feat: add ``accountFreeze``/``accountUnfreeze`` commands
- enh: ``accountList``: add ``--no-password-info`` and ``--no-output`` options
- enh: more precise matching of ``ssh`` client error messages
- enh: ``osh.pl``: add the account name on each error message
- fix: invalid suffixed account creation (#357)
- chore: ``generate-sudoers.sh``: sort alphabetically

## v3.09.02 - 2022/11/15
- fix: execute: rare race condition introduced in v3.09.01
- fix: basic mitigation for scp's CVE-2020-15778 (upstream doesn't consider it a bug)

## v3.09.01 - 2022/10/10
- fix: ``batch``: don't attempt to read if stdin is closed
- enh: make ``execute()`` way WAY faster

## v3.09.00 - 2022/09/21
- enh: tests: faster perl-check script
- fix: accountInfo wasn't showing TTL account expiration #329
- fix: remove spurious set +e/-e after commit bdea34c
- fix: accountUnlock: add missing check_spurious_args and no_auto_abbrev
- fix: doc: use code-blocks:: instead of code::
- doc: add a missing parameter in ping's help
- chore: selfListEgressKeys: fix typo

## v3.09.00-rc3 - 2022/07/12
- enh: install: better error detection
- fix: cleanup-guest-key-access: use cache for performance
- fix: performance issues introduced by effab4a

## v3.09.00-rc2 - 2022/07/05
- enh: MFA: specify account name in message
- enh: move some code from get_hashes_list() to a new get_password_file()
- enh: print_public_key: better formatter
- doc: osh-encrypt-rsync.conf: add verbose

## v3.09.00-rc1 - 2022/07/04
- feat: ``osh-encrypt-rsync.pl``: handle sqlite and user logs along with ttyrec files
- feat: add ``osh-cleanup-guest-key-access.pl`` script
- feat: add NRPE probes in ``contrib/``
- remove: ``compress-old-logs.sh`` script, as ``osh-encrypt-rsync.pl`` does the job now
- chg: CentOS 8 no longer supported (EOL)
- chg: Ubuntu 22.04 LTS now supported
- enh: standardize snake_case for all system scripts json config files
- enh: cron scripts: factorize common code and standardize logging & config
- enh: ``osh-lingering-sessions-reaper.pl``: make it configurable
- enh: ``osh-piv-grace-reaper.pl``: run only on master, standardize config reading
- enh: add more info in syslog warnings for ``accountDelete``
- fix: ``ping``: force a deadline, and restore default sighandlers
- fix: ``accountInfo``: missing creation date on non-json output
- fix: ``osh-remove-empty-folders.pl``: fix folders counting (logging only)
- fix: ``osh-encrypt-rsync.pl``: delete +a source files properly
- fix: ``osh-encrypt-rsync.pl``: ensure $verbose is always set & make it configurable
- fix: ``install``: ensure that the healthcheck user can always connect from 127.0.0.1
- fix: ``install``: avoid cases of sigpipe on `tr`
- fix: don't emit a membership log when nothing changed
- fix: ``{group,account}Delete``: move() would sometimes fail, replace by mv
- fix: workaround for undocumented caching in ``getpw``/``getgr`` funcs
- doc: better menu organization and more complete config files reference

## v3.08.01 - 2022/01/19
- feat: add osh-remove-empty-folders.sh script
- enh: better errror detection and logging in accountDelete & groupDelete

## v3.08.00 - 2022/01/04
- feat: move scripts to GnuPG 2.x, add tests & doc
- feat: add new OSes (Debian "Bullseye" 11, RockyLinux 8.x) and deprecate
    old ones (OpenSUSE Leap 15.2, older minor releases of CentOS 7.x and 8.x)
- feat: add the ``accountUnlock`` restricted plugin
- enh: detect silent password change failures
- enh: ``batch``: detect when asked to start a plugin requiring MFA
- enh: rewrite ``packages-check.sh``, ``perl-tidy.sh`` and ``shell-check.sh`` with
    more features and deprecated code removed
- feat: add the ``code-info`` syslog type in addition to ``code-warn``
- enh: tests: ``--module`` can now be specified multiple times
- fix: FreeBSD tests & portions of code, regression since v3.03.99-rc2
- chore: install: remove obsolete upgrading sections for pre-v3.x versions

## v3.07.00 - 2021/12/13
- feat: add support for Duo PAM auth as MFA (#249)
- feat: new access option: `--force-password <HASH>`, to only try one specific egress password (#256)
- fix: add helpers handling of SIGPIPE/SIGHUP
- fix: avoid double-close log messages on SIGHUP
- fix: `--self-password` was missing as a `-P` synonym (#257)
- fix: tests under OpenSUSE (fping raw sockets)
- chore: ensure proper Getopt::Long options are set everywhere
- chore: move HEXIT() to helper module, use HEXIT only in helpers
- chore: factorize helpers header

## v3.06.00 - 2021/10/15
- feat: accountModify: add --pubkey-auth-optional
- fix: accountPIV: fix bad autocompletion rule
- fix: groupdel: false positive in lock contention detection
- doc: bastion.conf: add superowner system group requirement

## v3.05.01 - 2021/09/22
- feat: add ``--proactive-mfa`` and ``mfa``/``nofa`` interactive commands
- feat: ``osh-backup-acl-keys``: add the possibility to sign encrypted backups (#209)
- doc: add help about the interactive builtin commands (#227)

## v3.05.00 - 2021/09/13
- feat: support ``pam_faillock`` for Debian 11 (#163)
- feat: add ``--fallback-password-delay`` (3) for ssh password autologin
- enh: add ``max_inactive_days`` to account configuration (#230)
- enh: accountInfo: add ``--list-groups``
- enh: max account length is now 28 chars up from 18
- enh: better error message when unknown option is used
- enh: better use of account creation metadata
- enh: config reading: add rootonly parameter
- fix: ``accountCreate``: ``--uid-auto``: rare case where a free UID couldn't be found
- doc: generate scripts doc reference for satellite scripts
- doc: add faq about session locking (#226)
- misc: a few other unimportant fixes

## v3.04.00 - 2021/07/02
No changes since rc2.

## v3.03.99-rc2 - 2021/06/30
- OS support: /!\ drop EOL OSes: Debian 8, Ubuntu 14.04, OpenSUSE 15.0/15.1, add OpenSUSE 15.3
- feat: add admin and super owner accounts list in `info` plugin (#206)
- enh: replace bool 'allowUTF8' (introduced in rc1) by 'fanciness' enum
- enh: tests: refactor the framework for more maintainability
- fix: `setup-first-admin-account.sh`: support to add several admins (#202)
- fix: use local `$\_` before `while(<>)` loops
- doc: added a lot of new content
- doc: `clush`: document `--user` and `--port`
- doc: several other fixes here and there

## v3.03.99-rc1 - 2021/06/03
- enh: `osh-orphaned-homedir.sh`: add more security checks to ensure we don't archive still-used home dirs
- enh: install.inc: try harder to hit GitHub API in CI
- fix: `fixrights.sh`: 'chmod --' not supported under FreeBSD
- fix: `packages-check.sh`: centos: ensure cache is up to date before trying to install packages
- fix: `groupDelServer`: missing autocompletion in interactive mode
- fix: `install-yubico-piv-checker`: ppc64le installation was broken
- fix: `scp`: abort early if host is not found to avoid a warn()
- fix: `osh-backup-acl-keys`: detect file removed transient error
- fix: add a case to the ignored perl panic race condition
- chore: `mkdir -p` doesn't fail if dir already exists
- chore: tests: support multiple unit-test files

## v3.03.01 - 2021/03/25
- enh: osh-orphaned-homedir.sh: add more security checks to ensure we don't archive still-used home dirs
- enh: install.inc: try harder to hit GitHub API in CI
- fix: fixrights.sh: 'chmod --' not supported under FreeBSD
- fix: packages-check.sh: centos: ensure cache is up to date before trying to install packages
- fix: groupDelServer: missing autocompletion in interactive mode
- fix: install-yubico-piv-checker: ppc64le installation was broken
- fix: scp: abort early if host is not found to avoid a warn()
- fix: osh-backup-acl-keys: detect file removed transient error
- fix: add a case to the ignored perl panic race condition
- chore: mkdir -p doesn't fail if dir already exists
- chore: tests: support multiple unit-test files

## v3.03.00 - 2021/02/22
- feat: transmit PIV enforcement status to remote realms, so that the remote policy can be enforced (#33)
- feat: add `groupGenerateEgressKey` and `groupDelEgressKey` (#135)
- feat: auto-add hostname as comment in `groupAddServer` and `selfAddPersonalAccesss` (side-note in #60)
- enh: `groupAddGuestAccess` now supports setting a comment (#17, #18)
- enh: `groupAddServer`: augment the returned JSON with the added server details
- enh: move unexpected-sudo messages from `security` to `code-warning` type
- enh: egress ssh key: compute an ID so that keys can be pointed to and deleted
- fix: `groupDelGuestAccess`: deleting a guest access returned an error on TTL-forced groups
- fix: groupSetRole(): pass sudo param to subfuncs to avoid a security warning
- fix: execute(): remove osh_warn on tainted params to avoid exposing arguments on coding error
- fix: `groupModify`: deny early if user is not an owner of the group
- enh: `groupInfo`: nicer message when no egress key exists
- enh: `install`: use in-place overwrite for sudoers files, the 3-seconds wait by default has been removed
    (and the `--no-wait` parameter now does nothing)
- fix: `interactive`: omit inactivity message warning when set to 0 seconds
- a few other internal fixes here and there

## v3.02.00 - 2021/02/01
- no functional change since rc4, this version ends the rc cycle and is considered stable

## v3.01.99-rc4 - 2021/01/25
- fix: admins no longer inherited superowner powers (since rc1)

## v3.01.99-rc3 - 2021/01/21
- feat: `rootListIngressKeys`: look for all well-known authkeys files
- feat: add `--(in|ex)clude` filters to `groupList` and `accountList`
- enh: groupList: use cache to speedup calls
- enh: config: detect `warnBefore`/`idleTimeout` misconfiguration (#125)
- fix: scripts: `(( ))` returns 1 if evaluated to zero, hence failing under `set -e`
- fix: config: be more permissive for `documentationURL` regex
- fix: TOCTTOU fixes in ttyrec rotation script and lingering sessions reaper
- fix: confusing error messages in `groupDelServer`
- chore: tests: also update totalerrors while tests are running

## v3.01.99-rc2 - 2021/01/12
- fix: re-introduce the ttyrecfile field (fixes #114)
- fix: logs: sql dbname was not properly passed through the update logs func (fixes #114)
- doc: upgrade: add a note about config normalization
- chore: fix: documentation build was missing a prereq

## v3.01.99-rc1 - 2021/01/12
- feat: add support for a PIV-enforced policy (see https://ovh.github.io/the-bastion/using/piv)
- feat: revamp logs (see the UPGRADING section of the documentation)
- feat: realms: use remote bastion MFA validation information for local policy enforcement
- feat: add `LC_BASTION_DETAILS` envvar so that remote hosts can gather more information about the connection
- feat: `accountModify`: add --osh-only policy (closes #97)
- enh: satellite scripts: better error handling
- enh: config: better parsing and normalization
- fix: groupList: remove 9K group limit
- fix: realmDelete: bad sudoers configuration
- fix: global-log: directly set proper perms on file creation
- fix: remove useless warning when there is no guest access
- fix: proper sqlite log location for invalid realm accounts
- fix: tests: syslog-logged errors were not counted towards the total
- chore: tests: remove OpenSUSE Leap 15.0 (due to https://bugzilla.opensuse.org/show_bug.cgi?id=1146027)
- chore: a few other fixes & enhancements around tests, documentation, perlcritic et al.

## v3.01.03 - 2020/12/15
- fix: sudogen: don't check for account/groups validity too much when deleting them (fixes #86)
- fix: guests: get rid of ghost guest accesses in corner cases (fixes internal ticket)
- fix: osh.pl: plugin_config 'disabled' key is a boolean
- chore: speedup tests by ~20%
- chore: osh-accountDelete: fix typo

## v3.01.02 - 2020/12/08
- fix: is_valid_remote_user: extend allowed size from 32 to 128
- feat: add support for CentOS 8.3
- doc: bastion.conf.dist: accountMFAPolicy wrong options values in comment
- chore: tests: now test the 3 more recent minor versions of CentOS 7 and CentOS 8

## v3.01.01 - 2020/12/04
- fix: interactive mode: mark non-printable chars as such to avoid readline quirks
- fix: osh-encrypt-rsync: remove 'logfile' as mandatory parameter
- fix: typo in MFAPasswordWarnDays parameter in bastion.conf.dist
- enh: interactive mode: better autocompletion for accountCreate and adminSudo
- enh: allow dot in group name as it is allowed in account, and adjust sudogen accordingly
- doc: add information about puppet-thebastion and yubico-piv-checker + some adjustments
- chore: tests: fail the tests when code is not tidy

## v3.01.00 - 2020/11/20
- feat: add FreeBSD 12.1 to automated tests, and multiple fixes to get back proper FreeBSD compatibility/experience
- feat: partial MFA support for FreeBSD
- feat: add interactiveModeByDefault option (#54)
- feat: install: add SELinux module for TOTP MFA (#26)
- enh: httpproxy: add informational headers to the egress side request
- fix: osh.pl: validate remote user and host format to fail early if invalid
- fix: osh-encrypt-rsync.pl: allow more broad chars to avoid letting weird-named files behind
- fix: osh-backup-acl-keys.sh: don't exclude .gpg, or we miss /root/.gnupg/secring.gpg
- fix: selfListSessions: bad sorting of the list
- misc: a few other fixes here and there

## v3.00.02 - 2020/11/16
- feat: add more archs to dockerhub sandbox
- fix: adminSudo: allow called plugins to read from stdin (#43)
- fix: add missing `echo` in the entrypoint of the sandbox
- chore: install-ttyrec.sh: adapt for multiarch

## v3.00.01 - 2020/11/06
- feat: add OpenSUSE 15.2 to the officially supported distros
- enh: install-ttyrec.sh: replaces build-and-install-ttyrec.sh, no longer builds in-place but prefers .deb
    and .rpm packages & falls back to precompiled static binaries otherwise
- enh: packages-check.sh: add qrencode-libs for RHEL/CentOS
- enh: provide a separated Dockerfile for the sandbox, squashing useless layers
- doc: a lot of fixes here and there
- chore: remove spurious config files
- chore: a few GitHub actions workflow fixes

## v3.00.00 - 2020/10/30
- First public release \o/
