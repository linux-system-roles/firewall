Changelog
=========

[1.8.0] - 2024-07-15
--------------------

### New Features

- feat: Handle reboot for transactional update systems (#226)

[1.7.8] - 2024-07-02
--------------------

### Bug Fixes

- fix: add support for EL10 (#224)

### Other Changes

- test: use cs9 container instead of cs8 (#222)
- ci: ansible-lint action now requires absolute directory (#223)

[1.7.7] - 2024-06-11
--------------------

### Other Changes

- ci: use tox-lsr 3.3.0 which uses ansible-test 2.17 (#217)
- ci: tox-lsr 3.4.0 - fix py27 tests; move other checks to py310 (#219)
- ci: Add supported_ansible_also to .ansible-lint (#220)

[1.7.6] - 2024-04-25
--------------------

### Other Changes

- ci: add ansible-test ignores for 2.16 (#215)

[1.7.5] - 2024-04-04
--------------------

### Other Changes

- ci: bump codecov/codecov-action from 3 to 4 (#208)
- ci: fix python unit test - copy pytest config to tests/unit (#210)
- ci: bump ansible/ansible-lint from 6 to 24 (#211)
- ci: bump mathieudutour/github-tag-action from 6.1 to 6.2 (#213)

[1.7.4] - 2024-01-23
--------------------

### Other Changes

- ci: Remove redundant reboot task (#206)

[1.7.3] - 2024-01-16
--------------------

### Other Changes

- ci: Use supported ansible-lint action; run ansible-lint against the collection (#200)
- ci: bump github/codeql-action from 2 to 3 (#201)
- ci: Use supported ansible-lint action; run ansible-lint against the collection (#203)
- ci: Add conditional reboot for transactional update support (#204)

[1.7.2] - 2023-12-08
--------------------

### Other Changes

- ci: bump actions/github-script from 6 to 7 (#197)
- refactor: get_ostree_data.sh use env shebang - remove from .sanity* (#198)

[1.7.1] - 2023-11-22
--------------------

### Other Changes

- refactor: improve support for ostree systems (#195)

[1.7.0] - 2023-10-26
--------------------

### New Features

- feat: support for ostree systems (#191)

### Other Changes

- build(deps): bump actions/checkout from 3 to 4 (#183)
- ci: ensure dependabot git commit message conforms to commitlint (#187)
- ci: use dump_packages.py callback to get packages used by role (#189)
- ci: tox-lsr version 3.1.1 (#192)

[1.6.4] - 2023-09-08
--------------------

### Other Changes

- docs: Make badges consistent, run markdownlint on all .md files (#179)

  - Consistently generate badges for GH workflows in README RHELPLAN-146921
  - Run markdownlint on all .md files
  - Add custom-woke-action if not used already
  - Rename woke action to Woke for a pretty badge
  
  Signed-off-by: Sergei Petrosian <spetrosi@redhat.com>

- ci: Remove badges from README.md prior to converting to HTML (#180)

  - Remove thematic break after badges
  - Remove badges from README.md prior to converting to HTML
  
  Signed-off-by: Sergei Petrosian <spetrosi@redhat.com>

[1.6.3] - 2023-08-17
--------------------

### Bug Fixes

- fix: files: overwrite firewalld.conf on previous replaced (#176)

[1.6.2] - 2023-08-15
--------------------

### Other Changes

- ci: Add markdownlint, test_converting_readme, and build_docs workflows (#173)
- test: this test requires facts, so explicitly gather (#174)

[1.6.1] - 2023-08-09
--------------------

### Other Changes

- tests: test_ping: fix compatability issues (#171)

[1.6.0] - 2023-08-08
--------------------

### New Features

- feat: define, modify, and remove ipsets (#166)

[1.5.0] - 2023-07-31
--------------------

### New Features

- feat: add new arg firewalld_conf, subarg allow_zone_drifting (#162)

### Bug Fixes

- fix: error when running with check mode and previous: replaced (#163)
- fix: firewall_lib: make try_set_zone_of_interface idempotent (#167)

### Other Changes

- test: tests_ansible zone cleanup; check for default zone (#165)

[1.4.7] - 2023-07-21
--------------------

### Bug Fixes

- fix: reload on resetting to defaults (#159)

[1.4.6] - 2023-07-19
--------------------

### Bug Fixes

- fix: make enabling/disabling non-existent services not fail in check mode (#153)
- fix: unmask firewalld on run, disable conflicting services (#154)
- fix: facts being gathered unnecessarily (#156)

### Other Changes

- ci: fix python 2.7 CI tests by manually installing python2.7 package (#152)
- ci: ansible-test ignores file for ansible-core 2.15 (#155)

[1.4.5] - 2023-06-21
--------------------

### Bug Fixes

- fix: Don't install python(3)-firewall it's a dependency of firewalld (#148)

  Enhancement: The role now does not run tasks to install python-firewall or python3-firewall based on installed python version.
  
  Reason:  python-firewall or python3-firewall is pulled automatically by dnf and yum when installing firewalld.
  The issue is that when I install python3 on EL 7, the role then fails with "No package matching 'python3-firewall' found available, installed or updated". It sees python3 present on the system and tries to install python3-firewall, which is not available on EL 7.
  
  Result: The role doesn't fail on EL 7 when python3 is installed on the managed node.

### Other Changes

- ci: Add commitlint GitHub action to ensure conventional commits (#139)

  For more information, see Conventional Commits format in Contribute
  https://linux-system-roles.github.io/contribute.html#conventional-commits-format
  
  Signed-off-by: Sergei Petrosian <spetrosi@redhat.com>

- docs: Add note about using previous: replaced and temporary service failures (#141)

  Add a note to the README about the use of `previous: replaced` and that it can
  cause temporary service outages to the node being managed.
  https://github.com/linux-system-roles/firewall/issues/138

- docs: Consistent contributing.md for all roles - allow role specific contributing.md section (#143)

  Provide a single, consistent contributing.md for all roles.  This mostly links to
  and summarizes https://linux-system-roles.github.io/contribute.html
  
  Allow for a role specific section which typically has information about
  role particulars, role debugging tips, etc.
  
  See https://github.com/linux-system-roles/.github/pull/19
  
  Signed-off-by: Rich Megginson <rmeggins@redhat.com>

- ci: update tox-lsr to version 3.0.0 (#144)

  The major version bump is because tox-lsr 3 drops support
  for tox version 2.  If you are using tox 2 you will need to
  upgrade to tox 3 or 4.
  
  tox-lsr 3.0.0 adds support for tox 4, commitlint, and ansible-lint-collection
  
  See https://github.com/linux-system-roles/tox-lsr/releases/tag/3.0.0
  for full release notes
  
  Signed-off-by: Rich Megginson <rmeggins@redhat.com>

- ci: fix pylintrc issues (#145)

  Remove `no-space-check` and `overgeneral-exception`

- ci: Add pull request template and run commitlint on PR title only (#147)

  We now ensure the conventional commits format only on PR titles and not on
  commits to let developers keep commit messages targeted for other developers
  i.e. describe actual changes to code that users should not care about.
  And PR titles, on the contrary, must be aimed at end users.
  
  For more info, see
  https://linux-system-roles.github.io/contribute.html#write-a-good-pr-title-and-description
  
  Signed-off-by: Sergei Petrosian <spetrosi@redhat.com>

- ci: Rename commitlint to PR title Lint, echo PR titles from env var (#149)

  Signed-off-by: Sergei Petrosian <spetrosi@redhat.com>

[1.4.4] - 2023-04-13
--------------------

### Other Changes

- fix ansible-lint issues in tests (#134)
- add docs for set_default_zone (#135)

[1.4.3] - 2023-04-06
--------------------

### Other Changes

- Add README-ansible.md to refer Ansible intro page on linux-system-roles.github.io (#132)

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
