![The Bastion Logo](https://user-images.githubusercontent.com/218502/96882661-d3b21e80-147f-11eb-8d89-a69e37a5870b.png)

:lock: The Bastion
==================

## Overview

Bastions are a cluster of machines used as the unique entry point by operational teams (such as sysadmins, developers, database admins, ...) to securely connect to devices (servers, virtual machines, cloud instances, network equipment, ...), usually using `ssh`.

The Bastion provides mechanisms for authentication, authorization, traceability and auditability for your whole infrastructure.

Being between your users and your infrastructure, The Bastion adds a layer of abstraction in-between so that your infrastructure doesn't need to know your operational team members individually.

Each of your team member has an individual account on The Bastion, and may be a member of one or several bastion groups that may give them access to one or more infrastructures. The infrastructure devices only need to know and trust the bastion group(s) they may be a part of.

The Bastion fine-grained RBAC makes it possible to delegate some responsibilities to any account, group-scoped or bastion-wide, including to accounts that might be used by your automation to e.g. manage the lifecycle of the accounts (linked to your human resources management system, your LDAP or AD), ensure a group's ACL is up to date (linked to your CMDB), etc. Automated processes are easy to implement through the [JSON API over SSH](https://ovh.github.io/the-bastion/using/api.html).

## Knowledge resources

Want to know more while viewing some nice drawings? Here is a series of blog posts that dig more into the core functionalities and principles of The Bastion:
- [Part 1 - Genesis](https://blog.ovhcloud.com/the-ovhcloud-bastion-part-1/)
- [Part 2 - Delegation Dizziness](https://blog.ovhcloud.com/the-ovhcloud-ssh-bastion-part-2-delegation-dizziness/)
- [Part 3 - Security at the Core](https://blog.ovhcloud.com/the-bastion-part-3-security-at-the-core/)
- [Part 4 - A new era](https://blog.ovhcloud.com/the-bastion-part-4-a-new-era/)

Other resources that might be of interest:
- [Online documentation](https://ovh.github.io/the-bastion/)
- (Video in French, slides in English) [The Bastion at the Very Tech Trip 2023](https://verytechtrip.ovhcloud.com/fr-ca/sessions), case study of managing an infrastructure with and without a bastion
- (Video in French, slides in English) [The Bastion at the OSSIR, 2021](https://www.youtube.com/watch?v=UjiNMiB1LDU), quickly explaining the core principles, then detailing the realm functionality, and finally zooming on why the technical implementation choices that have been made enhance security (voluntarily adding a security vulnerability in the code to prove it!)
- (Podcast in French) [The Bastion at NoLimitSecu, 2021](https://www.nolimitsecu.fr/the-bastion), interview with questions & answers

## :recycle: Zero assumptions on your environment

Nothing fancy is needed either on the ingress or the egress side of The Bastion to make it work.

Only your good old `ssh` client is needed to connect through it, and on the other side, any standard `sshd` server will do the trick. This includes, for example, network devices on which you may not have the possibility to install any custom software.

Ancient devices that only support low-security cryptography algorithms or telnet can be hidden from the Internet by firewalling them and only allowing The Bastion, hereby avoiding a low-security trade-off by still allowing only high-security grade connections on the bastion ingress side.

## :curly_loop: Reliability

* Only a few well-known libraries are used, less third party code means a tinier attack surface
* The bastion is engineered to be self-sufficient: no dependencies such as databases, other daemons, other machines, or third-party cloud services, neither for the authentication or authorization phase, statistically means less downtime
* High availability can be setup so that multiple bastion instances form a cluster of several instances, with any instance usable at all times (active/active scheme)

## :godmode: Non-exhaustive features list

- [Personal](https://ovh.github.io/the-bastion/using/basics/access_management.html#personal-accesses) and [group](https://ovh.github.io/the-bastion/using/basics/access_management.html#group-accesses) access schemes with group roles delegation to ensure teams autonomy without security trade-offs
- SSH protocol break between the ingress and egress connections
- Interactive session recording (in standard ttyrec files)
- Non-interactive session recording (stdout and stderr through ttyrec)
- Extensive [logging](https://ovh.github.io/the-bastion/administration/logs.html) support through syslog for easy SIEM consumption
- Authentication features include support for [MFA/2FA](https://ovh.github.io/the-bastion/administration/mfa.html) (password, TOTP) in addition to publickey authentication
- Supports Yubico [PIV](https://ovh.github.io/the-bastion/using/piv.html) keys attestation checking and enforcement on the ingress connection side
- Supports [mosh](https://github.com/mobile-shell/mosh) on the ingress connection side
- Supports [scp, sftp and rsync](https://ovh.github.io/the-bastion/using/sftp_scp_rsync.html) passthrough, to upload and/or download files from/to remote servers
- Supports netconf SSH subsystem passthrough
- Supports realms, to create a trust between two bastions of possibly two different companies, splitting the authentication and authorization phases while still enforcing local policies
- Supports SSH password autologin on the egress side for legacy devices not supporting pubkey authentication, while still forcing proper pubkey authentication on the ingress side
- Supports telnet password autologin on the egress side for ancient devices not supporting SSH, while still forcing proper SSH pubkey authentication on the ingress side
- Supports [HTTPS proxying](https://ovh.github.io/the-bastion/using/http_proxy.html) with man-in-the-middle authentication and authorization handling, for ingress and egress password decoupling (mainly useful for network device APIs)

## :wrench: Installing, upgrading, using The Bastion

Please see the [online documentation](https://ovh.github.io/the-bastion/), or the corresponding text-based version found in the `doc/` folder.

## :movie_camera: Quick connection and replay example

[![asciicast](https://asciinema.org/a/369555.png)](https://asciinema.org/a/369555?autoplay=1)

## :zap: TL;DR: test it: disposable sandbox using Docker

This is a good way to test The Bastion within seconds, but [read the FAQ](https://ovh.github.io/the-bastion/faq.html#can-i-run-it-under-docker-in-production) if you're serious about using containerization in production.

The sandbox image is available for the following architectures: linux/386, linux/amd64, linux/arm/v6, linux/arm/v7, linux/arm64, linux/ppc64le, linux/s390x.

Let's run the docker image:

    docker run -d -p 22 --name bastiontest ovhcom/the-bastion:sandbox

Get your public SSH key at hand, then configure the first administrator account:

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

That's it! Of course, there is a lot more to it, documentation is available under the `doc/` folder and [online](https://ovh.github.io/the-bastion/).
Be sure to check the help of the bastion (`bastion --help`) and the help of each osh plugin (`bastion --osh command --help`).
Also don't forget to customize your `bastion.conf` file, which can be found in `/etc/bastion/bastion.conf` (for Linux).

## :twisted_rightwards_arrows: Supported OS for installation

Linux distros below are tested with each release, but as this is a security product, you are **warmly** advised to run it on the latest up-to-date stable version of your favorite OS:

- Debian 12 (Bookworm), 11 (Bullseye), 10 (Buster)
- RockyLinux 9.x, 8.x
- Ubuntu LTS 24.04, 22.04, 20.04, 18.04
- OpenSUSE Leap 15.5\*

\*: Note that these versions have no out-of-the-box MFA support, as they lack packaged versions of `pamtester`, `pam-google-authenticator`, or both. Of course, you may compile those yourself.
Any other so-called "modern" Linux version are not tested with each release, but should work with no or minor adjustments.

The following OS are also tested with each release:

- FreeBSD/HardenedBSD 13.2\*\*

\*\*: Note that these have partial MFA support, due to their reduced set of available `pam` plugins. Support for either an additional password or TOTP factor can be configured, but not both at the same time. The code is actually known to work on FreeBSD/HardenedBSD 10+, but it's only regularly tested under 13.2.

Other BSD variants, such as OpenBSD and NetBSD, are unsupported as they have a severe limitation over the maximum number of supplementary groups, causing problems for group membership and restricted commands checks, as well as no filesystem-level ACL support and missing PAM support (hence no MFA).

## :ok: Code quality

* The code is ran under `perltidy`
* The code is also ran under `perlcritic`
* Functional tests are used before every release

## :passport_control: Security at the core

Even with the most conservative, precautionous and paranoid coding process, code has bugs, so it shouldn't be trusted blindly. Hence the bastion doesn't trust its own code. It leverages the operating system security primitives to get additional security, as seen below.

- Uses the well-known and trusted UNIX Discretionary Access Control:
    - Bastion users are mapped to actual system users
    - Bastion groups are mapped to actual system groups
    - All the code is constantly checking rights before allowing any action
    - UNIX DAC is used as a safety belt to prevent an action from succeeding even if the code is tricked into allowing it

- The bastion main script is declared as the bastion user's system shell:
    - No user has real (`bash`-like) shell access on the system
    - All code is ran under the unprivileged user's system account rights
    - Even if a user could escape to a real shell, they wouldn't be able to connect to machines they don't have access to, because they don't have filesystem-level read access to the SSH keys

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

- A protocol break is operated between the ingress and the egress side, rendering most protocol-based vulnerabilities ineffective

## :mag: Auditability

- Bastion administrators must use the bastion's logic to connect to itself to administer it (or better, use another bastion to do so), this ensures auditability in all cases
* Every access and action (whether allowed or denied) is logged with:
    * `syslog`, which should also be sent to a remote syslog server to ensure even bastion administrators can't tamper their tracks, and/or
    * local `sqlite3` databases for easy searching
* Every session is recorded with `ttyrec`, helper scripts are provided to encrypt and push these records on a remote escrow filer
* This code is used in production in several PCI-DSS, ISO 27001, SOC1 and SOC2 certified environments

## :link: Related

### Dependencies

- [ovh-ttyrec](https://github.com/ovh/ovh-ttyrec) - an enhanced but compatible version of ttyrec, a terminal (tty) recorder

### Optional tools

- [yubico-piv-checker](https://github.com/ovh/yubico-piv-checker) - a self-contained go binary to check the validity of PIV keys and certificates. Optional, to enable The Bastion PIV-aware functionalities
- [puppet-thebastion](https://forge.puppet.com/modules/goldenkiwi/thebastion) ([GitHub](https://github.com/ovh/puppet-thebastion)) - a Puppet module to automate and maintain the configuration of The Bastion machines
- [the-bastion-ansible-wrapper](https://github.com/ovh/the-bastion-ansible-wrapper) - a wrapper to make it possible to run Ansible playbooks through The Bastion
- [debian-cis](https://github.com/ovh/debian-cis) - a script to apply and monitor the hardening of Debian hosts as per the [CIS](https://www.cisecurity.org/benchmark/debian_linux/) recommendations

### Community tools

A non-exhaustive list of related tools that are maintained by the community:

- [chef-cookbook](https://github.com/axl89/ovh_the_bastion) - a chef cookbook to install the-bastion and setup its default configuration

## :memo: License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
