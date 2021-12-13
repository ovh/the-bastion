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
- enh: `install`: use in-place overwrite for sudoers files, the 3-seconds wait by default has been removed (and the `--no-wait` parameter now does nothing)
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
- enh: install-ttyrec.sh: replaces build-and-install-ttyrec.sh, no longer builds in-place but prefers .deb and .rpm packages & falls back to precompiled static binaries otherwise
- enh: packages-check.sh: add qrencode-libs for RHEL/CentOS
- enh: provide a separated Dockerfile for the sandbox, squashing useless layers
- doc: a lot of fixes here and there
- chore: remove spurious config files
- chore: a few GitHub actions workflow fixes

## v3.00.00 - 2020/10/30
- First public release \o/
