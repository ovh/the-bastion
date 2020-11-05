Versioning logic
================

The bastion version is of the format: `X.YY.ZZ`, and loosely respects the `semver` rules.

- The `ZZ`part is considered a minor update, with no new features (or really tiny ones) and is mainly meant for bugfixes.
Update between a previous `ZZ` version is supposed to be frictionless.

- The `YY` part is considered a major update, potentially with new features (and new bugs!).
Be sure to read the UPGRADE.md documentation which might contain instructions for a smoother update.
If no specific instruction can be found, it means there's no specific action to be taken,
apart from following the usual update process.
If the change introduces an incompatibility between a `master` and its `slave`s,
it'll be detailed in the UPGRADE.md file.

- The `X` part is considered a massive ugrade, and requires special attention.
Be sure to read the UPGRADE.md documentation that will contain extensive information about the upgrade.
Note that it might be more complicated to rollback as massive upgrades might change the bastion on-disk file formats.
Most of the time, `master` and `slaves` won't be compatible across `X` versions.

- Occasionally, *release candidates* will be released, which will append `-rcW` suffixes to the above version format,
with `W` being a simple incrementing number.
To ensure the version ordering is always correct, the *release candidates* of a version
will always be named with the version number minus one `Z`.
For example, if `v5.17.14` is the current version, and the `v5.18.00` is the future to-be-released update,
and we want release candidates for this version, the first release candidate will be named `v5.17.99-rc1`.
The first release candidate of `v6.00.00` will, in the same way, be named `v5.99.99-rc1`.

- Each release is tagged with the version number, prepended by a `v`, such as `v1.23.45`
