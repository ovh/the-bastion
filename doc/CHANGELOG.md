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
