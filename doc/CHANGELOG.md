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
