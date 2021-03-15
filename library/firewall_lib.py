#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2016,2017,2020,2021 Red Hat, Inc.
# Reusing some firewalld code
# Authors:
# Thomas Woerner <twoerner@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: firewall_lib
short_description: Module for firewall role
requirements:
  - python-firewall
  - system-config-firewall/lokkit.
description:
  - "WARNING: Do not use this module directly! It is only for role internal use."
  - >-
    Manage firewall with firewalld on Fedora and RHEL-7+.
author: "Thomas Woerner (@t-woerner)"
options:
  service:
    description:
      - >-
        Name of a service to add or remove inbound access to. The service needs to be
        defined in firewalld or system-config-firewall/lokkit configuration.
    required: false
    default: null
    type: list
    elements: str
  port:
    description:
      - >-
        Port or port range to add or remove inbound access to. It needs to be in the
        format port=<port>[-<port>]/<protocol>.
    required: false
    default: null
    type: list
    elements: str
  trust:
    description:
      - "Interface to add or remove to the trusted interfaces."
    required: false
    default: null
    type: list
    elements: str
  trust_by_connection:
    description:
      - "Interface identified by a connection name to add or remove to the trusted interfaces."
    required: false
    default: null
    type: list
    elements: str
  trust_by_mac:
    description:
      - "Interface to add or remove to the trusted interfaces by MAC address."
    required: false
    default: null
    type: list
    elements: str
  masq:
    description:
      - "Interface to add or remove to the interfaces that are masqueraded."
    required: false
    default: null
    type: list
    elements: str
  masq_by_connection:
    description:
      - "Interface identified by a connection name to add or remove to the interfaces that are masqueraded."
    required: false
    default: null
    type: list
    elements: str
  masq_by_mac:
    description:
      - >-
        Interface to add or remove to the interfaces that are masqueraded by MAC
        address.
    required: false
    default: null
    type: list
    elements: str
  forward_port:
    description:
      - >-
        Add or remove port forwarding for ports or port ranges over for interface or zone. Omit the interface part before ';' for use within a zone.
        It needs to be in the format
        [<interface>;]<port>[-<port>]/<protocol>;[<to-port>];[<to-addr>].
    required: false
    default: null
    type: list
    elements: str
  forward_port_by_connection:
    description:
      - >-
        Add or remove port forwarding for ports or port ranges over an interface
        identified by a connection name. It needs to be in the format
        <connection>;<port>[-<port>]/<protocol>;[<to-port>];[<to-addr>].
    required: false
    default: null
    type: list
    elements: str
  forward_port_by_mac:
    description:
      - >-
        Add or remove port forwarding for ports or port ranges over an interface
        identified by a MAC address. It needs to be in the format
        <mac-addr>;<port>[-<port>]/<protocol>;[<to-port>];[<to-addr>].
    required: false
    default: null
    type: list
    elements: str
  zone:
    description:
      - >-
        Name of the zone that the change will be done one for firewalld.
        If the zone name is not given, then the default zone will be used.
    required: false
    default: null
    type: str
  state:
    description:
      - "Enable or disable the entry."
    required: true
    type: str
    choices: [ "enabled", "disabled" ]
"""

import os
import os.path
import sys

try:
    from firewall.client import FirewallClient

    try:
        from firewall.core.fw_nm import (
            nm_is_imported,
            nm_get_connection_of_interface,
            nm_set_zone_of_connection,
        )
        from gi.repository import NM

        HAS_FIREWALLD_NM = True
    except ImportError:
        HAS_FIREWALLD_NM = False
    HAS_FIREWALLD = True
    HAS_SYSTEM_CONFIG_FIREWALL = False
except ImportError:
    HAS_FIREWALLD = False
    HAS_FIREWALLD_NM = False
    try:
        sys.path.append("/usr/share/system-config-firewall")
        import fw_lokkit
        from fw_functions import getPortRange

        HAS_SYSTEM_CONFIG_FIREWALL = True
    except ImportError:
        HAS_SYSTEM_CONFIG_FIREWALL = False


def try_set_zone_of_interface(_zone, interface):
    """Try to set zone of interface with NetworkManager"""
    if not HAS_FIREWALLD_NM:
        return False
    if nm_is_imported():
        try:
            connection = nm_get_connection_of_interface(interface)
        except Exception:
            pass
        else:
            if connection is not None:
                nm_set_zone_of_connection(_zone, connection)
                return True
    return False


class ifcfg(object):
    """ifcfg file reader class"""

    def __init__(self, filename):
        self._config = {}
        self._deleted = []
        self.filename = filename
        self.clear()

    def clear(self):
        self._config = {}
        self._deleted = []

    def cleanup(self):
        self._config.clear()

    def get(self, key):
        return self._config.get(key.strip())

    def set(self, key, value):
        _key = key.strip()
        self._config[_key] = value.strip()
        if _key in self._deleted:
            self._deleted.remove(_key)

    def read(self):
        self.clear()
        f = open(self.filename, "r")

        for line in f:
            if not line:
                break
            line = line.strip()
            if len(line) < 1 or line[0] in ["#", ";"]:
                continue
            # get key/value pair
            pair = [x.strip() for x in line.split("=", 1)]
            if len(pair) != 2:
                continue
            if len(pair[1]) >= 2 and pair[1].startswith('"') and pair[1].endswith('"'):
                pair[1] = pair[1][1:-1]
            if pair[1] == "":
                continue
            elif self._config.get(pair[0]) is not None:
                continue
            self._config[pair[0]] = pair[1]
        f.close()


def get_device_for_mac(mac_addr):
    """Get device for the MAC address from ifcfg file"""

    if HAS_FIREWALLD_NM and nm_is_imported:
        client = NM.Client.new(None)
        for nm_dev in client.get_devices():
            iface = nm_dev.get_iface()
            if iface == "lo":
                continue
            if nm_dev.get_hw_address().lower() == mac_addr.lower():
                return iface

    IFCFGDIR = "/etc/sysconfig/network-scripts"
    # Return quickly if config.IFCFGDIR does not exist
    if not os.path.exists(IFCFGDIR):
        return None

    for filename in sorted(os.listdir(IFCFGDIR)):
        if not filename.startswith("ifcfg-"):
            continue
        for ignored in [".bak", ".orig", ".rpmnew", ".rpmorig", ".rpmsave", "-range"]:
            if filename.endswith(ignored):
                continue
        if "." in filename:
            continue
        ifcfg_file = ifcfg("%s/%s" % (IFCFGDIR, filename))
        ifcfg_file.read()
        hwaddr = ifcfg_file.get("HWADDR")
        device = ifcfg_file.get("DEVICE")
        if hwaddr and device and hwaddr.lower() == mac_addr.lower():
            return device
    return None


def get_interface_for_connection(name):
    """Get interface for the connection name from NM"""

    if HAS_FIREWALLD_NM and nm_is_imported:
        client = NM.Client.new(None)
        for nm_con in client.get_connections():
            if nm_con.get_id() == name:
                return nm_con.get_interface_name()

    return None


def parse_forward_port(module, item, item_type=None):
    if item_type == "connection":
        type_string = "forward_port_by_connection"
    elif item_type == "mac":
        type_string = "forward_port_by_mac"
    else:
        type_string = "forward_port"

    args = item.split(";")
    if len(args) == 4:
        _interface, __port, _to_port, _to_addr = args
    elif len(args) == 3 and item_type is None:
        _interface = ""
        __port, _to_port, _to_addr = args
    else:
        module.fail_json(msg="improper %s format: %s" % (type_string, item))

    _port, _protocol = __port.split("/")
    if _protocol is None:
        module.fail_json(msg="improper %s format (missing protocol?)" % type_string)
    if _to_port == "":
        _to_port = None
    if _to_addr == "":
        _to_addr = None

    if item_type == "connection":
        _interface = get_interface_for_connection(_interface)
        if _interface is None:
            module.fail_json(msg="Connection '%s' not resolvable" % _interface)
    elif item_type == "mac":
        _interface = get_device_for_mac(_interface)
        if _interface is None:
            module.fail_json(msg="MAC address not found %s" % _interface)

    return (_interface, _port, _protocol, _to_port, _to_addr)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            service=dict(required=False, type="list", default=[]),
            port=dict(required=False, type="list", default=[]),
            trust=dict(required=False, type="list", default=[]),
            trust_by_connection=dict(required=False, type="list", default=[]),
            trust_by_mac=dict(required=False, type="list", default=[]),
            masq=dict(required=False, type="list", default=[]),
            masq_by_connection=dict(required=False, type="list", default=[]),
            masq_by_mac=dict(required=False, type="list", default=[]),
            forward_port=dict(required=False, type="list", default=[]),
            forward_port_by_connection=dict(required=False, type="list", default=[]),
            forward_port_by_mac=dict(required=False, type="list", default=[]),
            zone=dict(required=False, type="str", default=None),
            state=dict(choices=["enabled", "disabled"], required=True),
        ),
        required_one_of=(
            [
                "service",
                "port",
                "trust",
                "trust_by_connection",
                "trust_by_mac",
                "masq",
                "masq_by_connection",
                "masq_by_mac",
                "forward_port",
                "forward_port_by_connection",
                "forward_port_by_mac",
            ],
        ),
        supports_check_mode=True,
    )

    if not HAS_FIREWALLD and not HAS_SYSTEM_CONFIG_FIREWALL:
        module.fail_json(msg="No firewall backend could be imported.")

    service = module.params["service"]
    port = []
    for port_proto in module.params["port"]:
        _port, _protocol = port_proto.split("/")
        if _protocol is None:
            module.fail_json(msg="improper port format (missing protocol?)")
        port.append((_port, _protocol))
    trust = module.params["trust"]
    trust_by_mac = []
    for item in module.params["trust_by_mac"]:
        _interface = get_device_for_mac(item)
        if _interface is None:
            module.fail_json(msg="MAC address not found %s" % item)
        trust_by_mac.append(_interface)
    masq = module.params["masq"]
    masq_by_mac = []
    for item in module.params["masq_by_mac"]:
        _interface = get_device_for_mac(item)
        if _interface is None:
            module.fail_json(msg="MAC address not found %s" % item)
        masq_by_mac.append(_interface)
    forward_port = []
    for item in module.params["forward_port"]:
        forward_port.append(parse_forward_port(module, item))
    forward_port_by_mac = []
    for item in module.params["forward_port_by_mac"]:
        forward_port_by_mac.append(parse_forward_port(module, item, "mac"))

    zone = module.params["zone"]
    if HAS_SYSTEM_CONFIG_FIREWALL and zone is not None:
        module.fail_json(msg="Zone can not be used with system-config-firewall/lokkit.")
    trust_by_connection = []
    for item in module.params["trust_by_connection"]:
        _interface = get_interface_for_connection(item)
        if _interface is None:
            module.fail_json(msg="Connection '%s' not resolvable" % item)
        trust_by_connection.append(_interface)
    masq_by_connection = []
    for item in module.params["masq_by_connection"]:
        _interface = get_interface_for_connection(item)
        if _interface is None:
            module.fail_json(msg="Connection '%s' not resolvable" % item)
        masq_by_connection.append(_interface)
    forward_port_by_connection = []
    for item in module.params["forward_port_by_connection"]:
        forward_port_by_connection.append(
            parse_forward_port(module, item, "connection")
        )
    if not (HAS_FIREWALLD_NM or nm_is_imported()) and (
        len(trust_by_connection) > 0
        or len(masq_by_connection) > 0
        or len(forward_port_by_connection) > 0
    ):
        module.fail_json(
            msg="The use of connections requires firewalld and NetworkManager."
        )

    desired_state = module.params["state"]

    if HAS_FIREWALLD:
        fw = FirewallClient()

        def exception_handler(exception_message):
            module.fail_json(msg=exception_message)

        fw.setExceptionHandler(exception_handler)

        if not fw.connected:
            module.fail_json(msg="firewalld service must be running")

        trusted_zone = "trusted"
        external_zone = "external"
        default_zone = fw.getDefaultZone()
        if zone is not None:
            if zone not in fw.getZones():
                module.fail_json(msg="Runtime zone '%s' does not exist." % zone)
            if zone not in fw.config().getZoneNames():
                module.fail_json(msg="Permanent zone '%s' does not exist." % zone)
        else:
            zone = default_zone
        fw_zone = fw.config().getZoneByName(zone)
        fw_settings = fw_zone.getSettings()

        changed = False
        changed_zones = {}

        # service
        for item in service:
            if desired_state == "enabled":
                if not fw.queryService(zone, item):
                    fw.addService(zone, item)
                    changed = True
                if not fw_settings.queryService(item):
                    fw_settings.addService(item)
                    changed = True
                    changed_zones[zone] = fw_settings
            elif desired_state == "disabled":
                if fw.queryService(zone, item):
                    fw.removeService(zone, item)
                if fw_settings.queryService(item):
                    fw_settings.removeService(item)
                    changed = True
                    changed_zones[zone] = fw_settings

        # port
        for _port, _protocol in port:
            if desired_state == "enabled":
                if not fw.queryPort(zone, _port, _protocol):
                    fw.addPort(zone, _port, _protocol)
                    changed = True
                if not fw_settings.queryPort(_port, _protocol):
                    fw_settings.addPort(_port, _protocol)
                    changed = True
                    changed_zones[zone] = fw_settings
            elif desired_state == "disabled":
                if fw.queryPort(zone, _port, _protocol):
                    fw.removePort(zone, _port, _protocol)
                    changed = True
                if fw_settings.queryPort(_port, _protocol):
                    fw_settings.removePort(_port, _protocol)
                    changed = True
                    changed_zones[zone] = fw_settings

        # trust, trust_by_mac
        if len(trust) > 0 or len(trust_by_connection) > 0 or len(trust_by_mac) > 0:
            items = trust
            if len(trust_by_connection) > 0:
                items.extend(trust_by_connection)
            if len(trust_by_mac) > 0:
                items.extend(trust_by_mac)

            if zone != trusted_zone:
                _zone = trusted_zone
                _fw_zone = fw.config().getZoneByName(_zone)
                if _zone in changed_zones:
                    _fw_settings = changed_zones[_zone]
                else:
                    _fw_settings = _fw_zone.getSettings()
            else:
                _zone = zone
                _fw_zone = fw_zone
                _fw_settings = fw_settings

            for item in items:
                if desired_state == "enabled":
                    if try_set_zone_of_interface(_zone, item):
                        changed = True
                    else:
                        if not fw.queryInterface(_zone, item):
                            fw.changeZoneOfInterface(_zone, item)
                            changed = True
                        if not _fw_settings.queryInterface(item):
                            _fw_settings.addInterface(item)
                            changed = True
                            changed_zones[_zone] = _fw_settings
                elif desired_state == "disabled":
                    if try_set_zone_of_interface("", item):
                        if module.check_mode:
                            module.exit_json(changed=True)
                    else:
                        if fw.queryInterface(_zone, item):
                            fw.removeInterface(_zone, item)
                            changed = True
                        if _fw_settings.queryInterface(item):
                            _fw_settings.removeInterface(item)
                            changed = True
                            changed_zones[_zone] = _fw_settings

        # masq, masq_by_mac
        if len(masq) > 0 or len(masq_by_connection) > 0 or len(masq_by_mac) > 0:
            items = masq
            if len(masq_by_connection) > 0:
                items.extend(masq_by_connection)
            if len(masq_by_mac) > 0:
                items.extend(masq_by_mac)

            if zone != external_zone:
                _zone = external_zone
                _fw_zone = fw.config().getZoneByName(_zone)
                if _zone in changed_zones:
                    _fw_settings = changed_zones[_zone]
                else:
                    _fw_settings = _fw_zone.getSettings()
            else:
                _zone = zone
                _fw_zone = fw_zone
                _fw_settings = fw_settings

            for item in items:
                if desired_state == "enabled":
                    if try_set_zone_of_interface(_zone, item):
                        changed = True
                    else:
                        if not fw.queryInterface(_zone, item):
                            fw.changeZoneOfInterface(_zone, item)
                            changed = True
                        if not _fw_settings.queryInterface(item):
                            _fw_settings.addInterface(item)
                            changed = True
                            changed_zones[_zone] = _fw_settings
                elif desired_state == "disabled":
                    if try_set_zone_of_interface("", item):
                        if module.check_mode:
                            module.exit_json(changed=True)
                    else:
                        if fw.queryInterface(_zone, item):
                            fw.removeInterface(_zone, item)
                            changed = True
                        if _fw_settings.queryInterface(item):
                            _fw_settings.removeInterface(item)
                            changed = True
                            changed_zones[_zone] = _fw_settings

        # forward_port, forward_port_by_mac
        if (
            len(forward_port) > 0
            or len(forward_port_by_connection) > 0
            or len(forward_port_by_mac) > 0
        ):
            items = forward_port
            if len(forward_port_by_connection) > 0:
                items.extend(forward_port_by_connection)
            if len(forward_port_by_mac) > 0:
                items.extend(forward_port_by_mac)

            for _interface, _port, _protocol, _to_port, _to_addr in items:
                if _interface != "":
                    _zone = fw.getZoneOfInterface(_interface)
                else:
                    _zone = zone
                if _zone != "" and _zone != zone:
                    _fw_zone = fw.config().getZoneByName(_zone)
                    if _zone in changed_zones:
                        _fw_settings = changed_zones[_zone]
                    else:
                        _fw_settings = _fw_zone.getSettings()
                else:
                    _fw_zone = fw_zone
                    _fw_settings = fw_settings

                if desired_state == "enabled":
                    if not fw.queryForwardPort(
                        _zone, _port, _protocol, _to_port, _to_addr
                    ):
                        fw.addForwardPort(_zone, _port, _protocol, _to_port, _to_addr)
                        changed = True
                    if not _fw_settings.queryForwardPort(
                        _port, _protocol, _to_port, _to_addr
                    ):
                        _fw_settings.addForwardPort(
                            _port, _protocol, _to_port, _to_addr
                        )
                        changed = True
                        changed_zones[_zone] = _fw_settings
                elif desired_state == "disabled":
                    if fw.queryForwardPort(_zone, _port, _protocol, _to_port, _to_addr):
                        fw.removeForwardPort(
                            _zone, _port, _protocol, _to_port, _to_addr
                        )
                        changed = True
                    if _fw_settings.queryForwardPort(
                        _port, _protocol, _to_port, _to_addr
                    ):
                        _fw_settings.removeForwardPort(
                            _port, _protocol, _to_port, _to_addr
                        )
                        changed = True
                        changed_zones[_zone] = _fw_settings

        # apply changes
        if changed:
            for _zone in changed_zones:
                _fw_zone = fw.config().getZoneByName(_zone)
                _fw_zone.update(changed_zones[_zone])
            module.exit_json(changed=True)

    elif HAS_SYSTEM_CONFIG_FIREWALL:
        (config, old_config, _dummy) = fw_lokkit.loadConfig(args=[], dbus_parser=True)

        changed = False

        # service
        for item in service:
            if config.services is None:
                config.services = []

            if desired_state == "enabled":
                if item not in config.services:
                    config.services.append(item)
                    changed = True
            elif desired_state == "disabled":
                if item in config.services:
                    config.services.remove(item)
                    changed = True

        # port
        for _port, _protocol in port:
            if config.ports is None:
                config.ports = []

            _range = getPortRange(_port)
            if _range < 0:
                module.fail_json(msg="invalid port definition %s" % _port)
            elif _range is None:
                module.fail_json(msg="port _range is not unique.")
            elif len(_range) == 2 and _range[0] >= _range[1]:
                module.fail_json(msg="invalid port range %s" % _port)
            port_proto = (_range, _protocol)
            if desired_state == "enabled":
                if port_proto not in config.ports:
                    config.ports.append(port_proto)
                    changed = True
            elif desired_state == "disabled":
                if port_proto in config.ports:
                    config.ports.remove(port_proto)
                    changed = True

        # trust, trust_by_mac
        if len(trust) > 0 or len(trust_by_mac) > 0:
            if config.trust is None:
                config.trust = []

            items = trust
            if len(trust_by_mac) > 0:
                items.extend(trust_by_mac)

            for item in items:
                if desired_state == "enabled":
                    if item not in config.trust:
                        config.trust.append(item)
                        changed = True
                elif desired_state == "disabled":
                    if item in config.trust:
                        config.trust.remove(item)
                        changed = True

        # masq, masq_by_mac
        if len(masq) > 0 or len(masq_by_mac) > 0:
            if config.masq is None:
                config.masq = []

            items = masq
            if len(masq_by_mac) > 0:
                items.extend(masq_by_mac)

            for item in items:
                if desired_state == "enabled":
                    if item not in config.masq:
                        config.masq.append(item)
                        changed = True
                elif desired_state == "disabled":
                    if item in config.masq:
                        config.masq.remove(item)
                        changed = True

        # forward_port, forward_port_by_mac
        if len(forward_port) > 0 or len(forward_port_by_mac) > 0:
            if config.forward_port is None:
                config.forward_port = []

            items = forward_port
            if len(forward_port_by_mac) > 0:
                items.extend(forward_port_by_mac)

            for _interface, _port, _protocol, _to_port, _to_addr in items:
                _range = getPortRange(_port)
                if _range < 0:
                    module.fail_json(msg="invalid port definition")
                elif _range is None:
                    module.fail_json(msg="port _range is not unique.")
                elif len(_range) == 2 and _range[0] >= _range[1]:
                    module.fail_json(msg="invalid port range")
                fwd_port = {"if": _interface, "port": _range, "proto": _protocol}
                if _to_port is not None:
                    _range = getPortRange(_to_port)
                    if _range < 0:
                        module.fail_json(msg="invalid port definition %s" % _to_port)
                    elif _range is None:
                        module.fail_json(msg="port _range is not unique.")
                    elif len(_range) == 2 and _range[0] >= _range[1]:
                        module.fail_json(msg="invalid port range")
                    fwd_port["toport"] = _range
                if _to_addr is not None:
                    fwd_port["toaddr"] = _to_addr

                if desired_state == "enabled":
                    if fwd_port not in config.forward_port:
                        config.forward_port.append(fwd_port)
                        changed = True
                elif desired_state == "disabled":
                    if fwd_port in config.forward_port:
                        config.forward_port.remove(fwd_port)
                        changed = True

        # apply changes
        if changed:
            fw_lokkit.updateFirewall(config, old_config)
            if module.check_mode:
                module.exit_json(changed=True)

    else:
        module.fail_json(msg="No firewalld and system-config-firewall")

    module.exit_json(changed=False)


#################################################
# import module snippets
from ansible.module_utils.basic import AnsibleModule

if __name__ == "__main__":
    main()
