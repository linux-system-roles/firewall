Changelog
=========

[1.2.2] - 2022-06-02
--------------------

### New Features

- none

### Bug fixes

- fix: state not required for masquerade and ICMP block inversion
- Fix deprecated syntax in Readme

### Other Changes

- tests\_ansible: replaced immediate options with runtime options

[1.2.1] - 2022-05-10
--------------------

### New Features

- none

### Bug Fixes

- none

### Other Changes

- remove customzone zone in cleanup
- bump tox-lsr version to 2.11.0; remove py37; add py310

[1.2.0] - 2022-05-02
--------------------

### New features

- Added ability to restore Firewalld defaults

### Bug Fixes

- none

### Other Changes

- none

[1.1.1] - 2022-04-13
--------------------

### New features

- support gather\_facts: false; support setup-snapshot.yml

### Bug Fixes

- none

### Other Changes

- none

[1.1.0] - 2022-02-22
--------------------

### New features

- ensure that changes to target take effect immediately
- Add ability to set the default zone

### Bug Fixes

- none

### Other Changes

- bump tox-lsr version to 2.10.1

[1.0.3] - 2022-01-20
--------------------

### New features

- Added implicit firewalld reload for when a custom zone is added or removed

### Bug Fixes

- none

### Other Changes

- Reformatted tests\_zone to use yaml format

[1.0.2] - 2022-01-10
--------------------

### New Features

- none

### Bug Fixes

- none

### Other Changes

- bump tox-lsr version to 2.8.3
- change recursive role symlink to individual role dir symlinks
- Added examples of options in Readme
- Added an issue template for the Firewalld System Role

[1.0.1] - 2021-11-11
--------------------

### New features

- Added support for RHEL 7
- Added runtime and permanent flags to documentation.

### Bug Fixes

- none

### Other Changes

- none

[1.0.0] - 2021-11-08
--------------------

### Initial Release
