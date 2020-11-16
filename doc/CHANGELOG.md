## v3.00.02 - 2020/11/16
- feat: add more archs to dockerhub sandbox
- fix: adminSudo: allow called plugins to read from stdin
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
