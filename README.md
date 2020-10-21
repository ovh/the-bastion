The Bastion
===========

Bastions are a cluster of machines used as the unique entry point by operational teams (such as sysadmins, developers, database admins, ...) to securely connect to devices (servers, virtual machines, cloud instances, network equipment, ...), usually using `ssh`.

Bastions provides mechanisms for authentication, authorization, traceability and auditability for the whole infrastructure.

Learn more by reading the blog post series that announced the release:
- [Part 1 - Genesis](https://www.ovh.com/blog/the-ovhcloud-bastion-part-1/)
- [Part 2 - Delegation Dizziness](https://www.ovh.com/blog/the-ovhcloud-ssh-bastion-part-2-delegation-dizziness/)
- [Part 3 - Security at the Core](https://www.ovh.com/blog/the-bastion-part-3-security-at-the-core/)
- [Part 4 - Open Sourcing](https://www.ovh.com/blog/the-bastion-part-4-open-sourcing/)

## Installing, upgrading, using The Bastion

Please see the online documentation ([https://ovh.github.io/the-bastion](https://ovh.github.io/the-bastion)), or the corresponding text-based documentation which can be found in the `doc/` folder.

## TL;DR

### Testing it with Docker

Let's build the docker image and run it

    docker build -f docker/Dockerfile.debian10 -t bastion:debian10 .
    docker run -d -p 22 --name bastiontest bastion:debian10

Configure the first administrator account (get your public SSH key ready)

    docker exec -it bastiontest /opt/bastion/bin/admin/setup-first-admin-account.sh poweruser auto

We're now up and running with the default configuration! Let's setup a handy bastion alias, and test the `info` command:

    PORT=$(docker port bastiontest | cut -d: -f2)
    alias bastion="ssh poweruser@127.0.0.1 -tp $PORT -- "
    bastion --osh info

It should greet you as being a bastion admin, which means you have access to all commands. Let's enter interactive mode:

    bastion -i

This is useful to call several `--osh` plugins in a row. Now we can ask for help to see all plugins:

    $> help

If you have a remote machine you want to try to connect to through the bastion, fetch your egress key:

    $> selfListEgressKeys

Copy this public key to the remote machine's `authorized_keys` under the `.ssh/` folder of the account you want to connect to, then:

    $> selfAddPersonalAccess --host <remote_host> --user <remote_account_name> --port-any
    $> ssh <remote_account_name>@<remote_host>

Note that you can connect directly without using interactive mode, with:

    bastion <remote_account_name>@<remote_machine_host_or_ip>

That's it! Additional documentation is available under the `doc/` folder and online ([https://ovh.github.io/the-bastion](https://ovh.github.io/the-bastion)).
Be sure to check the help of the bastion (`bastion --help`) and the help of each osh plugin (`bastion --osh command --help`)
Also don't forget to customize your `bastion.conf` file, which can be found in `/etc/bastion/bastion.conf` (for Linux)

## Compatibility

Linux distros below are tested with each release, but as this is a security product, you are *warmly* advised to run it on the latest up-to-date stable version of your favorite OS:

- Debian 10 (Buster), 9 (Stretch), 8 (Jessie)
- RHEL/CentOS 8, 7
- Ubuntu LTS 20.04, 18.04, 16.04, 14.04*
- OpenSUSE Leap 15.1*, 15*

*: Note that these versions have no MFA support.
Any other so-called "modern" Linux version are not tested with each release, but should work with no or minor adjustments.

The code is also known to work correctly under:

- FreeBSD 10+ / HardenedBSD [no MFA support]

Other BSD variants partially work but are unsupported and discouraged as they have a severe limitation over the maximum number of supplementary groups (causing problems for group membership and restricted commands checks), no filesystem-level ACL support and missing MFA:

- OpenBSD 5.4+
- NetBSD 7+

## Reliability

When hell is breaking loose on all your infrastructures and/or your network, bastions still need to be the last component standing because you need them to access the rest of your infrastructure... to be able to actually fix the problem. Hence reliability is key.

* The KISS principle is used where possible for design and code: less complicated code means more auditability and less bugs
* Only a few well-known libraries are used, less third party code means a tinier attack surface
* The bastion is engineered to be self-sufficient: less dependencies such as databases, other daemons, or other machines, statistically means less downtime
* High availability can be setup so that multiple bastion instances form a cluster of several instances, with any instance usable at all times (active/active scheme)

# Code quality

* The code is ran under `perltidy`
* The code is also ran under `perlcritic`
* Functional tests are used before every release

## Security at the core

Even with the most conservative, precautionous and paranoid coding process, code has bugs, so it shouldn't be trusted blindly. Hence the bastion doesn't trust its own code. It leverages the operating system security primitives to get additional security, as seen below.

- Uses the well-known and trusted UNIX Discretionary Access Control:
    - Bastion users are mapped to actual system users
    - Bastion groups are mapped to actual system groups
    - All the code is constantly checking rights before allowing any action
    - UNIX DAC is used as a safety belt to prevent an action from succeeding even if the code is tricked into allowing it

- The bastion main script is declared as the bastion user's system shell:
    - No user has real (`bash`-like) shell access on the system
    - All code is ran under the unprivileged user's system account rights
    - Even if a user could escape to a real shell, he wouldn't be able to connect to machines he doesn't have access to, because he doesn't have filesystem-level read access to the SSH keys

- The code is modular
    - The main code mainly checks rights, logs actions, and enable `ssh` access to other machines
    - All side commands, called *plugins*, are in modules separated from the main code
    - The modules can either be *open* or *restricted*
        - Only accounts that have been specifically granted on a need-to-use basis can run a specific restricted plugin
        - This is checked by the code, and also enforced by UNIX DAC (the plugin is only readable and executable by the system group specific to the plugin)

- All the code needing extended system privileges is separated from the main code, in modules called *helpers*
    - Helpers are run exclusively under `sudo`
    - The `sudoers` configuration is attached to a system group specific to the command, which is granted to accounts on a need-to-use basis
    - The helpers are only readable and executable by the system group specific to the command
    - The helpers path and some of their immutable parameters are hardcoded in the `sudoers` configuration
    - Perl tainted mode (`-T`) is used for all code running under `sudo`, preventing any user-input to interfere with the logic, by halting execution immediately
    - Code running under `sudo` doesn't trust its caller and re-checks every input
    - Communication between unprivileged and privileged-code are done using JSON

## Auditability

- Bastion administrators must use the bastion's logic to connect to itself to administer it (or better, use another bastion to do so), this ensures auditability in all cases
* Every access and action (wether allowed or denied) is logged with:
    * `syslog`, which should also be sent to a remote syslog server to ensure even bastion administrators can't tamper their tracks, and/or
    * local `sqlite3` databases for easy searching
* This code is used in production in several PCI-DSS, ISO 27001, SOC1 and SOC2 certified environments

## Related

- [ovh-ttyrec](https://github.com/ovh/ovh-ttyrec) - A terminal (tty) recorder

## License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
