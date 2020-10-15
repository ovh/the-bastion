# Contributing to The Bastion

This project accepts contributions. In order to contribute, you should
pay attention to a few things:

1. your code must follow the The Bastion design choices, see DESIGN.md
2. your code must follow the coding style rules
3. your code must be added to the unit and/or integration tests where applicable
4. your code must be documented
5. your work must be signed (see below)
6. you may contribute through GitHub Pull Requests

# Coding and documentation Style for source code

- All languages
  - Code must be indented with 4-spaces, no tabs. Vim modelines are present
    in all source files, so if you use vim, you should be good to go
- Perl
  - Code must be tidy (see `bin/dev/perl-tidy.sh`)
  - Code must not raise any perlcritic warning (see `bin/dev/perl-critic.sh`)
  - One must refrain using any non-core Perl module (check `corelist`)
    - If not possible, the module should be packaged at least under Debian,
      all supported versions, and available at least in trusted third party
      repositories on other supported OSes. No `cpan install`.
- POSIX shell and Bash
  - Code must not raise any shellcheck warning (see `bin/dev/shell-check.sh`)

# Submitting Modifications

The contributions should be submitted through Github Pull Requests
and follow the DCO which is defined below.

# Licensing for new files

The Bastion is licensed under the Apache License 2.0. Anything
contributed to The Bastion must be released under this license.

When introducing a new file into the project, please make sure it has a
copyright header making clear under which license it's being released.

# Developer Certificate of Origin (DCO)

To improve tracking of contributions to this project we will use a
process modeled on the modified DCO 1.1 and use a "sign-off" procedure
on patches that are being emailed around or contributed in any other
way.

The sign-off is a simple line at the end of the explanation for the
patch, which certifies that you wrote it or otherwise have the right
to pass it on as an open-source patch.  The rules are pretty simple,
if you can certify the below:

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I have
    the right to submit it under the open source license indicated in
    the file; or

(b) The contribution is based upon previous work that, to the best of
    my knowledge, is covered under an appropriate open source License
    and I have the right under that license to submit that work with
    modifications, whether created in whole or in part by me, under
    the same open source license (unless I am permitted to submit
    under a different license), as indicated in the file; or

(c) The contribution was provided directly to me by some other person
    who certified (a), (b) or (c) and I have not modified it.

(d) The contribution is made free of any other party's intellectual
    property claims or rights.

(e) I understand and agree that this project and the contribution are
    public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.


then you just add a line saying

    Signed-off-by: Random J Developer <random@example.org>

using your real name (sorry, no pseudonyms or anonymous contributions.)
