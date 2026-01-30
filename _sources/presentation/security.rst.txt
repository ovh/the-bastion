========
Security
========

Security principles at the core
===============================

Even with the most conservative, precautionous and paranoid coding process, code has bugs,
so it shouldn't be trusted blindly. Hence the bastion doesn't trust its own code.
It leverages the operating system security primitives to get additional security, as seen below.

- Uses the well-known and trusted UNIX Discretionary Access Control:

    - Bastion users are mapped to actual system users
    - Bastion groups are mapped to actual system groups
    - All the code is constantly checking rights before allowing any action
    - UNIX DAC is used as a safety belt to prevent an action from succeeding even if the code
      is tricked into allowing it

- The bastion main script is declared as the bastion user's system shell:

    - No user has real (``bash``-like) shell access on the system
    - All code is ran under the unprivileged user's system account rights
    - Even if a user could escape to a real shell, they wouldn't be able to connect to machines they don't have
      access to, because they don't have filesystem-level read access to the SSH keys

- The code is modular

    - The main code mainly checks rights, logs actions, and enable ``ssh`` access to other machines
    - All side commands, called **plugins**, are in modules separated from the main code
    - The modules can either be **open** or **restricted**

        - Only accounts that have been specifically granted on a need-to-use basis can run a specific restricted plugin
        - This is checked by the code, and also enforced by UNIX DAC (the plugin is only readable and
          executable by the system group specific to the plugin)

- All the code needing extended system privileges is separated from the main code, in modules called **helpers**

    - Helpers are run exclusively under ``sudo``
    - The ``sudoers`` configuration is attached to a system group specific to the command,
      which is granted to accounts on a need-to-use basis
    - The helpers are only readable and executable by the system group specific to the command
    - The helpers path and some of their immutable parameters are hardcoded in the ``sudoers`` configuration
    - Perl tainted mode (``-T``) is used for all code running under ``sudo``, preventing any user-input to
      interfere with the logic, by halting execution immediately
    - Code running under ``sudo`` doesn't trust its caller and re-checks every input
    - Communication between unprivileged and privileged-code are done using JSON

Auditability
============

- Bastion administrators must use the bastion's logic to connect to itself to administer it (or better,
  use another bastion to do so), this ensures auditability in all cases

- Every access and action (whether allowed or denied) is logged with:

    - ``syslog``, which should also be sent to a remote syslog server to ensure even
      bastion administrators can't tamper their tracks, and/or
    - local ``sqlite3`` databases for easy searching

- This code is used in production in several PCI-DSS, ISO 27001, SOC1 and SOC2 certified environments
