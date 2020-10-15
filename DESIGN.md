# The Bastion design choices

This document aims to summarize a few design choices that have been made
on this project, that dictate how features are implemented.

## Use the well trusted and existing UNIX building blocks, don't recode them

The Bastion heavily relies on well known and trusted system blocks to work.
All the SSH part is completely handled by OpenSSH server and client programs.
The MFA mechanism also heavily relies on PAM.

## The OS as a safety net for buggy or exploitable code

A bastion functional user is always mapped to an actual operating system user.
Same goes for bastion groups: they're mapped to actual OS groups.
This is also true for group roles: gatekeeper, owner and aclkeeper roles are
mapped to system groups.

Private keys of an account are only readable by the corresponding operating
system user, and same goes for the group private keys. This way, even if the
code is tricked to allow access when it shouldn't have (flawed logic or bug),
then the OS will still deny reading the key file.

This concept has been explained in the ([https://www.ovh.com/blog/the-bastion-part-3-security-at-the-core/](Blog Post #3 - Security at the Core))

## Zero trust between portions of code running at different permission levels

Most of The Bastion code is running under the unprivileged system user
corresponding to the actual user of the bastion. When some code needs to
run with privileges, for example to be able to create an account, a first
portion of the code checks for the validity of the request first, under the
same privileges than the user, this is called `a plugin`.
To actually create the system user, `sudo` is used to run just a specific
portion of the code. Such portions of code are named `helpers`, and always
run under perl tainted mode.

Helpers communicate back their result using JSON, which is then read from
the plugin (the unprivileged portion of code), and parsed.

This concept has been explained in the ([https://www.ovh.com/blog/the-bastion-part-3-security-at-the-core/](Blog Post #3 - Security at the Core))
