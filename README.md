# firewall

[![ansible-lint.yml](https://github.com/linux-system-roles/firewall/actions/workflows/ansible-lint.yml/badge.svg)](https://github.com/linux-system-roles/firewall/actions/workflows/ansible-lint.yml) [![ansible-test.yml](https://github.com/linux-system-roles/firewall/actions/workflows/ansible-test.yml/badge.svg)](https://github.com/linux-system-roles/firewall/actions/workflows/ansible-test.yml) [![codeql.yml](https://github.com/linux-system-roles/firewall/actions/workflows/codeql.yml/badge.svg)](https://github.com/linux-system-roles/firewall/actions/workflows/codeql.yml) [![markdownlint.yml](https://github.com/linux-system-roles/firewall/actions/workflows/markdownlint.yml/badge.svg)](https://github.com/linux-system-roles/firewall/actions/workflows/markdownlint.yml) [![python-unit-test.yml](https://github.com/linux-system-roles/firewall/actions/workflows/python-unit-test.yml/badge.svg)](https://github.com/linux-system-roles/firewall/actions/workflows/python-unit-test.yml) [![shellcheck.yml](https://github.com/linux-system-roles/firewall/actions/workflows/shellcheck.yml/badge.svg)](https://github.com/linux-system-roles/firewall/actions/workflows/shellcheck.yml) [![woke.yml](https://github.com/linux-system-roles/firewall/actions/workflows/woke.yml/badge.svg)](https://github.com/linux-system-roles/firewall/actions/workflows/woke.yml)

This role configures the firewall on machines that are using firewalld.
If firewalld is not in use, the role will install (if not already installed),
unmask, and enable firewalld.

The role can also attempt to disable known conflicting services.

For the configuration the role uses the firewalld client interface
which is available in RHEL-7 and later.

## Supported Distributions

* RHEL-7+, CentOS-7+
* Fedora

## Requirements

See below

### Collection requirements

The role requires external collections only for management of `rpm-ostree`
nodes. Please run the following command to install them if you need to manage
`rpm-ostree` nodes:

```bash
ansible-galaxy collection install -vv -r meta/collection-requirements.yml
```

## Limitations

### Configuration over Network

The configuration of the firewall could limit access to the machine over the
network. Therefore it is needed to make sure that the SSH port is still
accessible for the ansible server.

### The Error Case

WARNING: If the configuration failed or if the firewall configuration limits
access to the machine in a bad way, it is most likely be needed to get
physical access to the machine to fix the issue.

## Gathering firewall ansible facts

To gather the firewall system role's ansible facts,
call the system role with no arguments e.g.

```yaml
vars:
  firewall:
```

Another option is to gather a more detailed version of the
ansible facts by using the detailed argument e.g.

```yaml
vars:
  firewall:
    detailed: true
```

**WARNING**: `firewall_config` uses considerably more memory (+ ~165KB) when `detailed=True`.
For reference, by default, `firewall_config` takes ~3KB when converted to a string.

### Available ansible facts

#### firewall_config

This ansible fact shows the permanent configuration of
of firewalld on the managed node in dictionary format.
The top level of the fact is made up of three keys:

* `default`
* `custom`
* `default_zone`

Each dictionaries custom and default have the keys:

* `zones`
* `services`
* `icmptypes`
* `helpers`
* `ipsets`
* `policies` (if supported by remote host's firewalld installation)

Each of the keys contains a list of elements present in
permanent configuration for each respective option.

`custom` will have a list of subdictionaries for each key,
providing a more detailed description.

`default` will have only the names of each setting,
unless the detailed option is supplied, in which case
it will be structured in the same manner as custom.

`default_zone` contains the configured default zone
for the managed node's firewalld installation. It
is a string value.

JSON representation of the structure of firewall_config fact:

```json
{
  "default": {...},
  "custom": {...},
  "default_zone": "public",
}
```

#### default

The default subdictionary of firewall_config contains the default
configuration for the managed node's firewalld configuration.
This subdictionary only changes with changes to the managed node's
firewalld installation.

default without detailed parameter set to true

```json
"default": {
  "zones": ["public",...],
  "services": ["amanda_client",...],
  "icmptypes": [...],
  "helpers": [...],
  "ipsets": [...],
  "policies": [...],
}
```

default when parameter set to true

```json
"default": {
  "zones": {
    "public": {
      ...
    },
    ...
  },
  "services": {
    "amanda_client":{
      ...
    },
    ...
  },
  "icmptypes": {
    ...
  },
  "helpers": {
    ...
  },
  "ipsets": {
    ...
  },
  "policies": {
    ...
  },
}
```

#### custom

The custom subdictionary contains any differences from the default
firewalld configuration. This includes a repeat for a default
element if that element has been modified in any way, and any new
elements introduced in addition to the defaults.

This subdictionary will be modified by any changes to the
firewalld installation done locally or remotely via the
firewall system role.

If the managed nodes firewalld settings are not different from the defaults,
the custom key and subdictionary will not be present in firewall_config.
Additionally, if any of firewalld's settings have not changed from the default,
there will not be a key-value pair for that setting in custom.

Below is the state of the custom subdictionary where at least one
permanent change was made to each setting:

```json
"custom": {
  "zones": {
    "custom_zone": {
      ...
    },
    ...
  },
  "services": {
    "custom_service": {
      ...
    },
    ...
  },
  "icmptypes": {
    "custom": {
      ...
    },
    ...
  },
  "helpers": {
    ...
  },
  "ipsets": {
    ...
  },
  "policies": {
    ...
  },
}
```

## Variables

### firewall_disable_conflicting_services

By default, the firewall role does not attempt to disable conflicting services due to the
overhead associated with enumerating the services when disabling services is potentially unecessary.
To enable this feature, set the variable `firewall_disable_conflicting_services` to `true`:

```yaml
- name: Enable firewalld, disable conflicting services
  include_role: linux-system-roles.firewall
  vars:
    firewall_disable_conflicting_services: true
```

List of known conflicting services:

* iptables
* nftables
* ufw

Please submit a GitHub issue at the linux-system-roles/firewall there are services missing or
add it locally to `vars/main.yml`.

<!-- markdownlint-disable-next-line no-duplicate-header -->
### firewall

The firewall role uses the variable `firewall` to specify the parameters. This variable is a `list` of `dict` values. Each `dict` value is comprised of one or more keys listed below. These are the variables that can be passed to the role:

#### firewalld_conf

`firewalld_conf` can be used to modify directives in firewalld's configuration file (`/etc/firewalld/conf` by default)
if support for their modification has been implemented.

**`permanent: true` must always be set to run this option without error**

```yaml
firewall:
  - firewalld_conf:
      allow_zone_drifting: false
    permanent: true
```

#### Supported Directives

##### allow_zone_drifting

Changes the AllowZoneDrifting directive.

This parameter will do nothing if AllowZoneDrifting has been deprecated
and no longer exists.

```yaml
firewall:
  firewalld_conf:
    allow_zone_drifting: true
  permanent: true
```

### set_default_zone

The default zone is the zone that is used for everything that is not explicitly
bound/assigned to another zone.

That means that if there is no zone assigned to a connection, interface or
source, only the default zone is used.  The zone should exist before setting
it as the default zone.

```yaml
firewall:
  - zone: mycustomzone  # ensure custom zone exists first
    state: present
  - set_default_zone: mycustomzone  # set custom as default
    state: enabled
```

### zone

Name of the zone that should be modified. If it is not set, the default zone
will be used. It will have an effect on these variables: `service`, `port`,
`source_port`, `forward_port`, `masquerade`, `rich_rule`, `source`, `interface`,
`icmp_block`, `icmp_block_inversion`, and `target`.

You can also use this to add/remove user-created zones.  Specify the `zone`
variable with no other variables, and use `state: present` to add the zone, or
`state: absent` to remove it.

```yaml
zone: public
```

### service

Name of a service or service list to add or remove inbound access to.

```yaml
service: ftp
service: [ftp,tftp]
```

If a specified service does not exist in firewalld, the module will fail in diff mode,
and when run in check mode will always report no changes and warn the user of the potential for failure.

#### User-defined services

You can use `service` with `state: present` to add a service, along
with any of the options `short`, `description`, `port`, `source_port`, `protocol`,
`helper_module`, or `destination` to initialize and add options to the service e.g.

```yaml
firewall:
  # Adds custom service named customservice,
  # defines the new services short to be "Custom Service",
  # sets its description to "Custom service for example purposes,
  # and adds the port 8080/tcp
  - service: customservice
    short: Custom Service
    description: Custom service for example purposes
    port: 8080/tcp
    state: present
    permanent: true
```

Existing services can be modified in the same way as you would create a service.
`short`, `description`, and `destination` can be reassigned this way, while `port`,
`source port`, `protocol`, and `helper_module` will add the specified options if they
did not exist previously without removing any previous elements. e.g.

```yaml
firewall:
  # changes ftp's description, and adds the port 9090/tcp if it was not previously present
  - service: ftp
    description: I am modifying the builtin service ftp's description as an example
    port: 9090/tcp
    state: present
    permanent: true
```

You can remove a `service` or specific `port`, `source_port`, `protocol`, `helper_module`
elements (or `destination` attributes) by using `service` with `state: absent` with any
of the removable attributes listed. e.g.

```yaml
firewall:
  # Removes the port 8080/tcp from customservice if it exists.
  # DOES NOT REMOVE CUSTOM SERVICE
  - service: customservice
    port: 8080/tcp
    state: absent
    permanent: true
  # Removes the service named customservice if it exists
  - service: customservice
    state: absent
    permanent: true
```

NOTE: `permanent: true` needs to be specified in order to define, modify, or remove
a service. This is so anyone using `service` with `state: present/absent` acknowledges
that this will affect permanent firewall configuration. Additionally,
defining services for runtime configuration is not supported by firewalld

For more information about custom services, see <https://firewalld.org/documentation/man-pages/firewalld.service.html>

### ipset

Name of the ipset being created, modified, or removed.
Use `source` to add and remove ipsets from a zone

When creating an ipset, you must also specify `ipset_type`,
and optionally `short`, `description`, `ipset_entries`

Defining an ipset with all optional fields:

```yaml
firewall:
  - ipset: customipset
    ipset_type: "hash:ip"
    short: Custom IPSet
    description: set of ip addresses specified in entries
    ipset_entries:
      - 1.1.1.1
      - 2.2.2.2
      - 3.3.3.3
      - 8.8.8.8
      - 127.0.0.1
    state: present
    permanent: true
```

Adding an entry to an existing ipset

```yaml
firewall:
  - ipset: customipset
    ipset_entries:
      - 127.0.0.2
    state: present
    permanent: true
```

Changing the short and description of an ipset

```yaml
firewall:
  - ipset: customipset
    short: Custom
    description: Set of IPv4 addresses
    state: present
    permanent: true
```

Removing entries from an ipset

```yaml
firewall:
  - ipset: customipset
    ipset_entries:
      - 127.0.0.1
      - 127.0.0.2
    state: absent
    permanent: true
```

Removing an ipset

```yaml
firewall:
  - ipset: customipset
    state: absent
    permanent: true
```

### port

Port or port range or a list of them to add or remove inbound access to. It
needs to be in the format ```<port>[-<port>]/<protocol>```.

```yaml
port: '443/tcp'
port: ['443/tcp','443/udp']
```

### ipset_type

Type of ipset being defined.
Used with `ipset`.

For a list of available ipset types, run `firewall-cmd --get-ipset-types`,
there is no method to get supported types from this role.

```yaml
ipset: customipset
ipset_type: hash:mac
```

See `ipset` for more usage information

### ipset_entries

List of addresses to add or remove from an ipset
Used with `ipset`

Entrys must be compatible with the ipset type of the `ipset`
being created or modified.

```yaml
ipset: customipset
ipset_entries:
  - 127.0.0.1
```

See `ipset` for more usage information

### source_port

Port or port range or a list of them to add or remove source port access to. It
needs to be in the format ```<port>[-<port>]/<protocol>```.

```yaml
source_port: '443/tcp'
source_port: ['443/tcp','443/udp']
```

### forward_port

Add or remove port forwarding for ports or port ranges for a zone. It takes two
different formats:

* string or a list of strings in the format like `firewall-cmd --add-forward-port` e.g. `<port>[-<port>]/<protocol>;[<to-port>];[<to-addr>]`
* dict or list of dicts in the format like `ansible.posix.firewalld`:

```yaml
forward_port:
  port: <port>
  proto: <protocol>
  [toport: <to-port>]
  [toaddr: <to-addr>]
```

examples

```yaml
forward_port: '447/tcp;;1.2.3.4'
forward_port: ['447/tcp;;1.2.3.4','448/tcp;;1.2.3.5']
forward_port:
  - 447/tcp;;1.2.3.4
  - 448/tcp;;1.2.3.5
forward_port:
  - port: 447
    proto: tcp
    toaddr: 1.2.3.4
  - port: 448
    proto: tcp
    toaddr: 1.2.3.5
```

`port_forward` is an alias for `forward_port`.  Its use is deprecated and will
be removed in an upcoming release.

### masquerade

Enable or disable masquerade on the given zone.

```yaml
masquerade: false
```

### rich_rule

String or list of rich rule strings. For the format see (Syntax for firewalld
rich language
rules)[https://firewalld.org/documentation/man-pages/firewalld.richlanguage.html]

```yaml
rich_rule: rule service name="ftp" audit limit value="1/m" accept
```

### source

List of source address address range strings, or ipsets.  A source address or address
range is either an IP address or a network IP address with a mask for IPv4 or
IPv6. For IPv4, the mask can be a network mask or a plain number. For IPv6 the
mask is a plain number.

```yaml
source: 192.0.2.0/24
```

Ipsets are used with this option by prefixing "ipset:" to the name of the ipset

```yaml
source: ipset:ipsetname
```

### interface

String or list of interface name strings.

```yaml
interface: eth2
```

This role handles interface arguments similar to
how firewalld's cli, `firewall-cmd` does, i.e.
manages the interface through NetworkManager if possible,
and handles the interface binding purely through firewalld
otherwise.

**WARNING**: Neither firewalld nor this role throw any
errors if the interface name specified is not
tied to any existing network interface. This can cause confusion
when attempting to add an interface via PCI device ID,
for which you should use the parameter `interface_pci_id`
instead of the `interface` parameter.

Allow interface named '8086:15d7' in dmz zone

firewall:

* zone: dmz
    interface: 8086:15d7
    state: enabled

The above will successfully add a nftables/iptables rule
for an interface named `8086:15d7`, but no traffic should/will
ever match to an interface with this name.

TLDR - When using this parameter, please stick only to using
logical interface names that you know exist on the device to
avoid confusing behavior.

### interface_pci_id

String or list of interface PCI device IDs.
Accepts PCI IDs if the wildcard `XXXX:YYYY` applies
where:

* XXXX: Hexadecimal, corresponds to Vendor ID
* YYYY: Hexadecimal, corresponds to Device ID

```yaml
# PCI id for Intel Corporation Ethernet Connection
interface_pci_id: 8086:15d7
```

Only accepts PCI devices IDs that correspond to a named network interface,
and converts all PCI device IDs to their respective logical interface names.

If a PCI id corresponds to more than one logical interface name,
all interfaces with the PCI id specified will have the play applied.

A list of PCI devices with their IDs can be retrieved using `lcpci -nn`.
For more information on PCI device IDs, see the linux man page at:
<https://man7.org/linux/man-pages/man5/pci.ids.5.html>

### icmp_block

String or list of ICMP type strings to block.  The ICMP type names needs to be
defined in firewalld configuration.

```yaml
icmp_block: echo-request
```

### icmp_block_inversion

ICMP block inversion bool setting.  It enables or disables inversion of ICMP
blocks for a zone in firewalld.

```yaml
icmp_block_inversion: true
```

### target

The firewalld zone target.  If the state is set to `absent`,this will reset the
target to default.  Valid values are "default", "ACCEPT", "DROP", "%%REJECT%%".

```yaml
target: ACCEPT
```

### short

Short description, only usable when defining or modifying a service or ipset.
See `service` or `ipset` for more usage information.

```yaml
short: Short Description
```

### description

Description for a service, only usable when adding a new service or
modifying an existing service.
See `service` or `ipset` for more information

```yaml
description: Your description goes here
```

### destination

list of destination addresses, option only implemented for user-defined services.
Takes 0-2 addresses, allowing for one IPv4 address and one IPv6 address or address range.

* IPv4 format: `x.x.x.x[/mask]`
* IPv6 format: `x:x:x:x:x:x:x:x[/mask]` (`x::x` works when abbreviating one or more subsequent IPv6 segments where x = 0)

```yaml
destination:
  - 1.1.1.0/24
  - AAAA::AAAA:AAAA
```

### helper_module

Name of a connection tracking helper supported by firewalld.

```yaml
# Both properly specify nf_conntrack_ftp
helper_module: ftp
helper_module: nf_conntrack_ftp
```

### timeout

The amount of time in seconds a setting is in effect. The timeout is usable if

* state is set to `enabled`
* firewalld is running and `runtime` is set
* setting is used with services, ports, source ports, forward ports, masquerade,
  rich rules or icmp blocks

```yaml
timeout: 60
state: enabled
service: https
```

### state

Enable or disable the entry.

```yaml
state: 'enabled' | 'disabled' | 'present' | 'absent'
```

NOTE: `present` and `absent` are only used for `zone`, `target`, and `service` operations,
and cannot be used for any other operation.

NOTE: `zone` - use `state: present` to add a zone, and `state: absent` to remove
a zone, when zone is the only variable e.g.

```yaml
firewall:
  - zone: my-new-zone
    state: present
```

NOTE: `target` - you can also use `state: present` to add a target - `state:
absent` will reset the target to the default.

NOTE: `service` - to see how to manage services, see the service section.

### runtime

Enable changes in runtime configuration. If `runtime` parameter is not provided, the default will be set to `True`.

```yaml
runtime: true
```

### permanent

Enable changes in permanent configuration. If `permanent` parameter is not provided, the default will be set to `True`.

```yaml
permanent: true
```

The permanent and runtime settings are independent, so you can set only the runtime, or only the permanent.  You cannot
set both permanent and runtime to `false`.

### previous

If you want to completely wipe out all existing firewall configuration, add
`previous: replaced` to the `firewall` list. This will cause all existing
configuration to be removed and replaced with your given configuration.  This is
useful if you have existing machines that may have existing firewall
configuration, and you want to make all of the firewall configuration the same
across all of the machines.

*WARNING*: When using this option, there's a small time window when firewall is
being reset and all new connections to the system are rejected.  Existing
connections will be unaffected. Applying changes with this option in production
might cause temporary service failures with new connections during the operation.

### firewall_transactional_update_reboot_ok

This variable is used to handle reboots required by transactional updates. If a transactional update requires a reboot, the role will proceed with the reboot if firewall_transactional_update_reboot_ok is set to true. If set to false, the role will notify the user that a reboot is required, allowing for custom handling of the reboot requirement. If this variable is not set, the role will fail to ensure the reboot requirement is not overlooked.

```yaml
firewall_transactional_update_reboot_ok: true
```

## Examples of Options

By default, any changes will be applied immediately, and to the permanent settings. If you want the changes to apply immediately but not permanently, use `permanent: false`. Conversely, use `runtime: false`.

Permit TCP traffic for port 80 in default zone, in addition to any existing
configuration:

```yaml
firewall:
  - port: 80/tcp
    state: enabled
```

Remove all existing firewall configuration, and permit TCP traffic for port 80
in default zone:

```yaml
firewall:
  - previous: replaced
  - port: 80/tcp
    state: enabled
```

Do not permit TCP traffic for port 80 in default zone:

```yaml
firewall:
  - port: 80/tcp
    state: disabled
```

Add masquerading to dmz zone:

```yaml
firewall:
  - masquerade: true
    zone: dmz
    state: enabled
```

Remove masquerading to dmz zone:

```yaml
firewall:
  - masquerade: false
    zone: dmz
    state: enabled
```

Allow interface eth2 in trusted zone:

```yaml
firewall:
  - interface: eth2
    zone: trusted
    state: enabled
```

Don't allow interface eth2 in trusted zone:

```yaml
firewall:
  - interface: eth2
    zone: trusted
    state: disabled
```

Permit traffic in default zone for https service:

```yaml
firewall:
  - service: https
    state: enabled
```

Do not permit traffic in default zone for https service:

```yaml
firewall:
  - service: https
    state: disabled
```

Allow interface with PCI device ID '8086:15d7' in dmz zone

```yaml
firewall:
  - zone: dmz
    interface_pci_id: 8086:15d7
    state: enabled
```

## Example Playbooks

Erase all existing configuration, and enable ssh service:

```yaml
---
- name: Erase existing config and enable ssh service
  hosts: myhost

  vars:
    firewall:
      - previous: replaced
      - service: ssh
        state: enabled
  roles:
    - linux-system-roles.firewall
```

With this playbook you can make sure that the tftp service is disabled in the firewall:

```yaml
---
- name: Make sure tftp service is disabled
  hosts: myhost

  vars:
    firewall:
      - service: tftp
        state: disabled
  roles:
    - linux-system-roles.firewall
```

It is also possible to combine several settings into blocks:

```yaml
---
- name: Configure firewall
  hosts: myhost

  vars:
    firewall:
      - {service: [tftp,ftp],
         port: ['443/tcp','443/udp'],
         state: enabled}
      - {forward_port: [eth2;447/tcp;;1.2.3.4,
                        eth2;448/tcp;;1.2.3.5],
          state: enabled}
      - {zone: internal, service: tftp, state: enabled}
      - {service: tftp, state: enabled}
      - {port: '443/tcp', state: enabled}
      - {forward_port: 'eth0;445/tcp;;1.2.3.4', state: enabled}
  roles:
    - linux-system-roles.firewall
```

The block with several services, ports, etc. will be applied at once. If there is something wrong in the block it will fail as a whole.

```yaml
---
- name: Configure external zone in firewall
  hosts: myhost

  vars:
    firewall:
      - {zone: external,
         service: [tftp,ftp],
         port: ['443/tcp','443/udp'],
         forward_port: ['447/tcp;;1.2.3.4',
                        '448/tcp;;1.2.3.5'],
         state: enabled}
  roles:
    - linux-system-roles.firewall

```

## rpm-ostree

See README-ostree.md

## Authors

Thomas Woerner

## License

GPLv2+
