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

Name of the zone that should be modified. If it is not set, the default zone will be used. It will have an effect on these parameters: `service`, `port` and `forward_port`.

```
zone: 'public'
```

### service

Name of a service or service list to add or remove inbound access to. The service needs to be defined in firewalld.

```
service: 'ftp'
service: [ 'ftp', 'tftp' ]
```

### port

Port or port range or a list of them to add or remove inbound access to. It needs to be in the format ```<port>[-<port>]/<protocol>```.

```
port: '443/tcp'
port: [ '443/tcp', '443/udp' ]
```

### forward_port

Add or remove port forwarding for ports or port ranges for a zone. It needs to be in the format ```<port>[-<port>]/<protocol>;[<to-port>];[<to-addr>]```.

```
forward_port: '447/tcp;;1.2.3.4'
forward_port: [ '447/tcp;;1.2.3.4', '448/tcp;;1.2.3.5' ]
```

### state

Enable or disable the entry.

```
state: 'enabled' | 'disabled'
```

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
