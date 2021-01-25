firewall
========
![CI Testing](https://github.com/linux-system-roles/firewall/workflows/tox/badge.svg)

This role configures the firewall on machines that are using firewalld or
system-config-firewall/lokkit.

For the configuration the role tries to use the firewalld client interface
which is available in RHEL-7 and later. If this fails it tries to use the
system-config-firewall interface which is available in RHEL-7 as an
alternative.

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

### Using MAC addresses

As MAC addresses can not be used in netfilter to identify interfaces, this
role is doing a mapping from the MAC addresses to interfaces for netfilter.
The network needs to be configured before the firewall to be able to get the
mapping to interfaces.
After a MAC address change on the system, the firewall needs to be configured
again if the MAC address has been used in the configuration. This could be
done automatically if NetworkManager is controlling the affected interface.

### The Error Case

WARNING: If the configuration failed or if the firewall configuration limits
access to the machine in a bad way, it is most likely be needed to get
physical access to the machine to fix the issue.

### Rule sorting

If you want to add forwarding rules to an interface that also is masqueraded,
then the masquerading rules needs to be sorted before the forwarding rule.


Variables
---------

These are the variables that can be passed to the role:

### firewall_setup_default_solution

```
firewall_setup_default_solution: false
```

This turns off the installation and start of the default firewall solution for the specific Fedora or RHEL release. This is intended for users of system-config-firewall on RHEL-7+ or Fedora releases.

### zone

Name of the zone that should be modified. The zone parameter is only supported with firewalld. If it is not set for firewalld, the default zone will be used. It will have an effect on these parameters: `service`, `port` and `forward_port` without a given interface or MAC address.

```
zone: 'public'
```

### service

Name of a service or service list to add or remove inbound access to. The service needs to be defined in firewalld or system-config-firewall/lokkit configuration.

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

### trust

Interface to add or remove from the trusted interfaces.  The interface will be added to the trusted zone with firewalld.

```
trust: 'eth0'
trust: [ 'eth0', 'eth1' ]
```

### trust_by_connection

Current interface of a connection to add or remove from the trusted interfaces. This is a one time lookup. The firewall does not know about NetworkManager connections. The connection needs to exist and an interface needs to be assigned to the connection. The interface will be added to the trusted zone with firewalld.

```
trust_by_connection: 'MyTrustedConnection'
trust_by_connection: [ 'MyTrustedConnection1', 'MyTrustedConnection2' ]
```

### trust_by_mac

Interface to add or remove to the trusted interfaces by MAC address or MAC address list. Each MAC address will automatically be mapped to the interface that is using this MAC address. The interface will be added to the trusted zone with firewalld.

```
trust_by_mac: "00:11:22:33:44:55"
trust_by_mac: [ "00:11:22:33:44:55", "00:11:22:33:44:56" ]
```

### masq

Interface to add or remove to the interfaces that are masqueraded. The interface will be added to the `external` zone with firewalld.

```
masq: 'eth2'
masq: [ 'eth2', 'eth3' ]
```

### masq_by_connection

Current interface of a connection to add or remove from the interfaces that are masqueraded. This is a one time lookup. The firewall does not know about NetworkManager connections. The connection needs to exist and an interface needs to be assigned to the connection. The interface will be added to the `external` zone with firewalld.

```
masq_by_connection: 'MyExternalConnection'
masq_by_connection: [ 'MyExternalConnection2', 'MyExternalConnection3' ]
```

### masq_by_mac

Interface to add or remove to the interfaces that are masqueraded by MAC address or MAC address list. Each MAC address will automatically be mapped to the interface that is using this MAC address. The interface will be added to the `external` zone with firewalld.

```
masq_by_mac: "11:22:33:44:55:66"
masq_by_mac: [ "11:22:33:44:55:66", "11:22:33:44:55:67", ]
```

### forward_port

Add or remove port forwarding for ports or port ranges over an interface. It needs to be in the format ```[<interface>;]<port>[-<port>]/<protocol>;[<to-port>];[<to-addr>]```. If `interface` is not set, `zone` needs to be set for use with firewalld.

```
forward_port: 'eth0;447/tcp;;1.2.3.4'
forward_port: [ 'eth0;447/tcp;;1.2.3.4', 'eth0;448/tcp;;1.2.3.5' ]
forward_port: '447/tcp;;1.2.3.4'
```

### forward_port_by_connection

Add or remove port forwarding for ports or port ranges over an interface identified by a connection. It needs to be in the format ```<connection>;<port>[-<port>]/<protocol>;[<to-port>];[<to-addr>]```. Each connection will automatically be mapped to the interface that is used by the connection.

```
forward_port_by_connection: 'connection1;447/tcp;;1.2.3.4'
forward_port_by_connection: [ 'connection1;447/tcp;;1.2.3.4', 'connection2;448/tcp;;1.2.3.5' ]
```

### forward_port_by_mac

Add or remove port forwarding for ports or port ranges over an interface identified by a MAC address or MAC address list. It needs to be in the format ```<mac-addr>;<port>[-<port>]/<protocol>;[<to-port>];[<to-addr>]```. Each MAC address will automatically be mapped to the interface that is using this MAC address.

```
forward_port_by_mac: '00:11:22:33:44:55;447/tcp;;1.2.3.4'
forward_port_by_mac: [ '00:11:22:33:44:55;447/tcp;;1.2.3.4', '00:11:22:33:44:56;447/tcp;;1.2.3.4' ]
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
          trust: [ 'eth0', 'eth1' ],
          masq: [ 'eth2', 'eth3' ],
-         state: 'enabled' }
-     - { forward_port: [ 'eth2;447/tcp;;1.2.3.4',
                          'eth2;448/tcp;;1.2.3.5' ],
          state: 'enabled' }
      - { zone: "internal", service: 'tftp', state: 'enabled' }
      - { service: 'tftp', state: 'enabled' }
      - { port: '443/tcp', state: 'enabled' }
      - { trust: 'foo', state: 'enabled' }
      - { trust_by_mac: '00:11:22:33:44:55', state: 'enabled' }
      - { masq: 'foo2', state: 'enabled' }
      - { masq_by_mac: '00:11:22:33:44:55', state: 'enabled' }
      - { forward_port: 'eth0;445/tcp;;1.2.3.4', state: 'enabled' }
      - { forward_port_by_mac: '00:11:22:33:44:55;445/tcp;;1.2.3.4',
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

Example for trust, masq and forward_port by connection:

```---
- name: Configure external zone in firewall
  hosts: myhost

  vars:
    firewall:
      - { trust_by_connection: 'Connection1',
          masq_by_connection: 'Connection2',
          forward_port_by_connection: 'Connection3;447/tcp;;1.2.3.4',
          state: 'enabled' }
  roles:
    - linux-system-roles.firewall

```


# Authors

Thomas Woerner

# License

GPLv2+
