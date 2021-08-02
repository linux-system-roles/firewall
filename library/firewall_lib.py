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
        defined in firewalld configuration.
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
  forward_port:
    description:
      - >-
        Add or remove port forwarding for ports or port ranges for the zone.
        It needs to be in the format
        <port>[-<port>]/<protocol>;[<to-port>];[<to-addr>].
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
    HAS_FIREWALLD = True
except ImportError:
    HAS_FIREWALLD = False


def parse_forward_port(module, item):
    type_string = "forward_port"

    args = item.split(";")
    if len(args) == 3:
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

    return (_port, _protocol, _to_port, _to_addr)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            service=dict(required=False, type="list", default=[]),
            port=dict(required=False, type="list", default=[]),
            forward_port=dict(required=False, type="list", default=[]),
            zone=dict(required=False, type="str", default=None),
            state=dict(choices=["enabled", "disabled"], required=True),
        ),
        required_one_of=(
            [
                "service",
                "port",
                "forward_port",
            ],
        ),
        supports_check_mode=True,
    )

    if not HAS_FIREWALLD:
        module.fail_json(msg="No firewall backend could be imported.")

    service = module.params["service"]
    port = []
    for port_proto in module.params["port"]:
        _port, _protocol = port_proto.split("/")
        if _protocol is None:
            module.fail_json(msg="improper port format (missing protocol?)")
        port.append((_port, _protocol))
    forward_port = []
    for item in module.params["forward_port"]:
        forward_port.append(parse_forward_port(module, item))

    zone = module.params["zone"]
    desired_state = module.params["state"]

    if HAS_FIREWALLD:
        fw = FirewallClient()

        def exception_handler(exception_message):
            module.fail_json(msg=exception_message)

        fw.setExceptionHandler(exception_handler)

        if not fw.connected:
            module.fail_json(msg="firewalld service must be running")

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

        # forward_port
        if len(forward_port) > 0:
            for _port, _protocol, _to_port, _to_addr in forward_port:
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

    else:
        module.fail_json(msg="No firewalld")

    module.exit_json(changed=False)


#################################################
# import module snippets
from ansible.module_utils.basic import AnsibleModule

if __name__ == "__main__":
    main()
