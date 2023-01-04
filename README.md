firewall
========
![CI Testing](https://github.com/linux-system-roles/firewall/workflows/tox/badge.svg)

This role configures the firewall on machines that are using firewalld.

For the configuration the role uses the firewalld client interface
which is available in RHEL-7 and later.

Supported Distributions
-----------------------
* RHEL-7+, CentOS-7+
* Fedora

Limitations
-----------

### Configuration over Network

The configuration of the firewall could limit access to the machine over the
network. Therefore it is needed to make sure that the SSH port is still
accessible for the ansible server.

### The Error Case

WARNING: If the configuration failed or if the firewall configuration limits
access to the machine in a bad way, it is most likely be needed to get
physical access to the machine to fix the issue.

Ansible Facts
-------------

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

```
WARNING: `firewall_config` uses considerably more memory (+ ~165KB) when `detailed=True`.
For reference, by default, `firewall_config` takes ~3KB when converted to a string.
```

## Available ansible facts

### firewall_config

This ansible fact shows the permanent configuration of
of firewalld on the managed node in dictionary format.
The top level of the fact is made up of three keys:
- `default`
- `custom`
- `default_zone`

Each dictionaries custom and default have the keys:
- `zones`
- `services`
- `icmptypes`
- `helpers`
- `ipsets`
- `policies` (if supported by remote host's firewalld installation)

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

Variables
---------

The firewall role uses the variable `firewall` to specify the parameters.  This variable is a `list` of `dict` values.  Each `dict` value is comprised of one or more keys listed below. These are the variables that can be passed to the role:

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

Name of a service or service list to add or remove inbound access to. The
service needs to be defined in firewalld.

```yaml
service: ftp
service: [ftp,tftp]
```

###### User defined services

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

For more information about custom services, see https://firewalld.org/documentation/man-pages/firewalld.service.html

### port

Port or port range or a list of them to add or remove inbound access to. It
needs to be in the format ```<port>[-<port>]/<protocol>```.

```
port: '443/tcp'
port: ['443/tcp','443/udp']
```

### source_port

Port or port range or a list of them to add or remove source port access to. It
needs to be in the format ```<port>[-<port>]/<protocol>```.

```
source_port: '443/tcp'
source_port: ['443/tcp','443/udp']
```

### forward_port

Add or remove port forwarding for ports or port ranges for a zone. It takes two
different formats:
* string or a list of strings in the format like `firewall-cmd
  --add-forward-port` e.g. `<port>[-<port>]/<protocol>;[<to-port>];[<to-addr>]`
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

```
masquerade: false
```

### rich_rule

String or list of rich rule strings. For the format see (Syntax for firewalld
rich language
rules)[https://firewalld.org/documentation/man-pages/firewalld.richlanguage.html]

```
rich_rule: rule service name="ftp" audit limit value="1/m" accept
```

### source

List of source address or address range strings.  A source address or address
range is either an IP address or a network IP address with a mask for IPv4 or
IPv6. For IPv4, the mask can be a network mask or a plain number. For IPv6 the
mask is a plain number.

```
source: 192.0.2.0/24
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

```
WARNING: Neither firewalld nor this role throw any
errors if the interface name specified is not
tied to any existing network interface. This can cause confusion
when attempting to add an interface via PCI device ID,
for which you should use the parameter `interface_pci_id`
instead of the `interface` parameter.

Allow interface named '8086:15d7' in dmz zone

firewall:
  - zone: dmz
    interface: 8086:15d7
    state: enabled

The above will successfully add a nftables/iptables rule
for an interface named `8086:15d7`, but no traffic should/will
ever match to an interface with this name.

TLDR - When using this parameter, please stick only to using
logical interface names that you know exist on the device to 
avoid confusing behavior.
```

### interface_pci_id

String or list of interface PCI device IDs.
Accepts PCI IDs if the wildcard `XXXX:YYYY` applies
where:
- XXXX: Hexadecimal, corresponds to Vendor ID
- YYYY: Hexadecimal, corresponds to Device ID

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
https://man7.org/linux/man-pages/man5/pci.ids.5.html

### icmp_block

String or list of ICMP type strings to block.  The ICMP type names needs to be
defined in firewalld configuration.

```
icmp_block: echo-request
```

### icmp_block_inversion

ICMP block inversion bool setting.  It enables or disables inversion of ICMP
blocks for a zone in firewalld.

```
icmp_block_inversion: true
```

### target

The firewalld zone target.  If the state is set to `absent`,this will reset the
target to default.  Valid values are "default", "ACCEPT", "DROP", "%%REJECT%%".

```
target: ACCEPT
```
### short

Short description, only usable when adding or modifying a service.
See `service` for more usage information.

```yaml
short: WWW (HTTP)
```

### description

Description for a service, only usable when adding a new service or
modifying an existing service.
See `service` for more information

```yaml
description: Your description goes here
```

### destination

list of destination addresses, option only implemented for user defined services.
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

```
timeout: 60
state: enabled
service: https
```

### state

Enable or disable the entry.

```
state: 'enabled' | 'disabled' | 'present' | 'absent'
```
NOTE: `present` and `absent` are only used for `zone`, `target`, and `service` operations,
and cannot be used for any other operation.

NOTE: `zone` - use `state: present` to add a zone, and `state: absent` to remove
a zone, when zone is the only variable e.g.
```
firewall:
  - zone: my-new-zone
    state: present
```
NOTE: `target` - you can also use `state: present` to add a target - `state:
absent` will reset the target to the default.

NOTE: `service` - to see how to manage services, see the service section.

### runtime
Enable changes in runtime configuration. If `runtime` parameter is not provided, the default will be set to `True`.

```
runtime: true
```

### permanent

Enable changes in permanent configuration. If `permanent` parameter is not provided, the default will be set to `True`. 

```
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

Examples of Options
-------------------
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

Example Playbooks
-----------------

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
         state: enabled}
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

# Authors

Thomas Woerner

# License

GPLv2+
