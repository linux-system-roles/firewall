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

Variables
---------

These are the variables that can be passed to the role:

### zone

Name of the zone that should be modified. If it is not set, the default zone
will be used. It will have an effect on these variables: `service`, `port`,
`source_port`, `forward_port`, `masquerade`, `rich_rule`, `source`, `interface`,
`icmp_block`, `icmp_block_inversion`, and `target`.

You can also use this to add/remove user-created zones.  Specify the `zone`
variable with no other variables, and use `state: present` to add the zone, or
`state: absent` to remove it.

```
zone: 'public'
```

### service

Name of a service or service list to add or remove inbound access to. The
service needs to be defined in firewalld.

```
service: 'ftp'
service: [ 'ftp', 'tftp' ]
```

### port

Port or port range or a list of them to add or remove inbound access to. It
needs to be in the format ```<port>[-<port>]/<protocol>```.

```
port: '443/tcp'
port: [ '443/tcp', '443/udp' ]
```

### source_port

Port or port range or a list of them to add or remove source port access to. It
needs to be in the format ```<port>[-<port>]/<protocol>```.

```
source_port: '443/tcp'
source_port: [ '443/tcp', '443/udp' ]
```

### forward_port

Add or remove port forwarding for ports or port ranges for a zone. It takes two
different formats:
* string or a list of strings in the format like `firewall-cmd
  --add-forward-port` e.g. `<port>[-<port>]/<protocol>;[<to-port>];[<to-addr>]`
* dict or list of dicts in the format like `ansible.posix.firewalld`:

```
forward_port:
  port: <port>
  proto: <protocol>
  [toport: <to-port>]
  [toaddr: <to-addr>]
```
examples
```
forward_port: '447/tcp;;1.2.3.4'
forward_port: [ '447/tcp;;1.2.3.4', '448/tcp;;1.2.3.5' ]
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

```
interface: eth2
```

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
NOTE: `present` and `absent` are only used for `zone` and `target` operations,
and cannot be used for any other operation.

NOTE: `zone` - use `state: present` to add a zone, and `state: absent` to remove
a zone, when zone is the only variable e.g.
```
firewall:
  zone: my-new-zone
  state: present
```
NOTE: `target` - you can also use `state: present` to add a target - `state:
absent` will reset the target to the default.

Example Playbooks
-----------------

With this playbook it is possible to make sure the ssh service is enabled in the firewall:

```
---
- name: Make sure ssh service is enabled
  hosts: myhost

  vars:
    firewall:
      service: 'ssh'
      state: 'enabled'
  roles:
    - linux-system-roles.firewall
```

With this playbook you can make sure that the tftp service is disabled in the firewall:

```
---
- name: Make sure tftp service is disabled
  hosts: myhost

  vars:
    firewall:
      service: 'tftp'
      state: 'disabled'
  roles:
    - linux-system-roles.firewall
```

It is also possible to combine several settings into blocks:

```
---
- name: Configure firewall
  hosts: myhost

  vars:
    firewall:
      - { service: [ 'tftp', 'ftp' ],
          port: [ '443/tcp', '443/udp' ],
-         state: 'enabled' }
-     - { forward_port: [ 'eth2;447/tcp;;1.2.3.4',
                          'eth2;448/tcp;;1.2.3.5' ],
          state: 'enabled' }
      - { zone: "internal", service: 'tftp', state: 'enabled' }
      - { service: 'tftp', state: 'enabled' }
      - { port: '443/tcp', state: 'enabled' }
      - { forward_port: 'eth0;445/tcp;;1.2.3.4', state: 'enabled' }
          state: 'enabled' }
  roles:
    - linux-system-roles.firewall
```

The block with several services, ports, etc. will be applied at once. If there is something wrong in the block it will fail as a whole.

```---
- name: Configure external zone in firewall
  hosts: myhost

  vars:
    firewall:
      - { zone: 'external',
          service: [ 'tftp', 'ftp' ],
          port: [ '443/tcp', '443/udp' ],
          forward_port: [ '447/tcp;;1.2.3.4',
                          '448/tcp;;1.2.3.5' ],
          state: 'enabled' }
  roles:
    - linux-system-roles.firewall

```

# Authors

Thomas Woerner

# License

GPLv2+
