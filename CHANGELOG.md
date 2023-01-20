Changelog
=========

[1.4.2] - 2023-01-20
--------------------

### New Features

- none

### Bug Fixes

- ansible-lint 6.x fixes
- cannot use distutils; use custom version

### Other Changes

- Add check for non-inclusive language (#114)
- Add CodeQL workflow for GitHub code scanning

[1.4.1] - 2022-12-12
--------------------

### New Features

- none

### Bug Fixes

- none

### Other Changes

- Added some example playbooks (#110)

[1.4.0] - 2022-07-26
--------------------

### New Features

- feature - add/remove interfaces by PCI ID

FEATURE OVERVIEW

* allows users to add by what a device is (vendor:device_type) instead of interface names

    * interface names that match the wildcard XXXX:XXXX (X = hex) will be converted to interface names.

    * Multiple matches will result in play being done on multiple devices

* Add Network Manager interaction when adding/removing interfaces from zones

* Add functions that convert PCI IDs into network interface names

Fixes #87

### Bug Fixes

- none

### Other Changes

- changelog_to_tag action - github action ansible test improvements

[1.3.0] - 2022-07-20
--------------------

### New Features

- Feature: add/update/delete services

    * Can add services by using the present state, with the specified details for the service (Permanent required)
    * Only required details are the service name using the service option, other options supported:
    * short, description, port, source port, protocol, module (helper_module), destination
    * remove services by using absent state and only the service name (no "detail" options) (Permanent required)
    * remove service elements by adding the elements and their values
    * service will not be removed if any of the removable elements are specified as well
    * update short and descriptions of services by using present state with the options while short or description are defined
    * Cannot remove short or descriptions
    * as with the rest of this feature, permanent is required to do this

Fixes: #80

- Feature: Ansible facts with firewalld configuration

    * called by calling the firewall system role with either no parameters
      or with only the `detailed` parameter
    * fetches and returns ansible fact `firewall_config`
    * detailed in README.md, under ansible_fact section

Fixes #82

### Bug Fixes

- bugfix: port forward dict form

    * fixed bug where port_forward argument only worked with string argument
    * additionally argument convert to list if necessary
    * minimal tests added for port forward
    * tests_port_forward.yml only has the fail case that the role fails

Fixes: #85

### Other Changes

- make all tests work with gather_facts: false (#84)

The tests_zone.yml test uses facts outside of the role and
needs to `gather_facts: true` when using ANSIBLE_GATHERING=explicit

- make min_ansible_version a string in meta/main.yml (#88)

The Ansible developers say that `min_ansible_version` in meta/main.yml
must be a `string` value like `"2.9"`, not a `float` value like `2.9`.

- fix destination rendering in github markdown renderer

Just make the problematic text a literal string so it won't get rendered incorrectly

- Add CHANGELOG.md (#90)

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
