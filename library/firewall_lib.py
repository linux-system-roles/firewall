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
  - python3-firewall or python-firewall
description:
  Manage firewall with firewalld on Fedora and RHEL-7+.
author: "Thomas Woerner (@t-woerner)"
options:
  service:
    description:
      List of service name strings.
      The service names needs to be defined in firewalld configuration.
      services in firewalld configuration can be defined by setting
      this option to a single service name and state to present.
    required: false
    type: list
    elements: str
  port:
    description:
      List of ports or port range strings.
      The format of a port needs to be port=<port>[-<port>]/<protocol>.
    required: false
    type: list
    elements: str
  source_port:
    description:
      List of source port or port range strings.
      The format of a source port needs to be port=<port>[-<port>]/<protocol>.
    required: false
    type: list
    elements: str
  forward_port:
    description:
      List of forward port strings or dicts,
      or a single string or dict.
      The format of a forward port string needs to be
      <port>[-<port>]/<protocol>;[<to-port>];[<to-addr>].
    aliases: ["port_forward"]
    required: false
    type: raw
  masquerade:
    description:
      The masquerade bool setting.
    type: bool
  rich_rule:
    description:
      List of rich rule strings.
      For the format see L(Syntax for firewalld rich language rules,
      https://firewalld.org/documentation/man-pages/firewalld.richlanguage.html).
    required: false
    type: list
    elements: str
  source:
    description:
      List of source address or address range strings.
      A source address or address range is either an IP address or a network
      IP address with a mask for IPv4 or IPv6. For IPv4, the mask can be a
      network mask or a plain number. For IPv6 the mask is a plain number.
    required: false
    type: list
    elements: str
  interface:
    description:
      List of interface name strings.
    required: false
    type: list
    elements: str
  icmp_block:
    description:
      List of ICMP type strings to block.
      The ICMP type names needs to be defined in firewalld configuration.
    required: false
    type: list
    elements: str
  icmp_block_inversion:
    description:
      ICMP block inversion bool setting.
      It enables or disables inversion of ICMP blocks for a zone in firewalld.
    required: false
    type: bool
  timeout:
    description:
      The amount of time in seconds a setting is in effect.
      The timeout is usable for services, ports, source ports, forward ports,
      masquerade, rich rules or icmp blocks for runtime only.
    required: false
    type: int
    default: 0
  target:
    description:
      The firewalld Zone target.
      If the state is set to C(absent), this will reset the target to default.
    required: false
    choices: ["default", "ACCEPT", "DROP", "%%REJECT%%"]
    type: str
  zone:
    description:
      The zone name string.
      If the zone name is not given, then the default zone will be used.
    required: false
    type: str
  set_default_zone:
    description: Sets the default zone.
    required: false
    type: str
  permanent:
    description:
      The permanent bool flag.
      Ensures settings permanently across system reboots and firewalld
      service restarts.
      If the permanent flag is not enabled, runtime is assumed.
    required: false
    type: bool
  runtime:
    description:
      The runtime bool flag.
      Ensures settings in the runtime environment that is not persistent
      across system reboots and firewalld service restarts.
    aliases: ["immediate"]
    required: false
    type: bool
  state:
    description:
      Ensure presence or absence of entries.  Use C(present) and C(absent) only
      for zone-only operations, service-only operations, or target operations.
    required: false
    type: str
    choices: ["enabled", "disabled", "present", "absent"]
  description:
    description:
      Creates or updates the description of a new or existing service.
      State needs to be present for the use of this option
      Currently only supported for permanent service operations
    required: false
    type: str
  short:
    description:
      Creates or updates a short description, generally just a full name of a
      new or existing service.
      Currently supported for service-only operations while state is present
    required: false
    type: str
  protocol:
    description:
      list of protocols supported by managed system.
      Supported for service configuration only
    required: false
    type: list
    elements: str
  helper_module:
    description:
      List of netfiler kernel helper module names
    required: false
    type: list
    elements: str
  destination:
    description:
      List of IPv4/IPv6 addresses with optional mask
      format - address[/mask]
      Currently only supported for service configuration
      Only one IPv4 and one IPv6 address allowed in list.
    required: false
    type: list
    elements: str
  __report_changed:
    description:
      If false, do not report changed true even if changed.
    required: false
    type: bool
    default: true
"""

from distutils.version import LooseVersion
from ansible.module_utils.basic import AnsibleModule

try:
    import firewall.config

    FW_VERSION = firewall.config.VERSION

    from firewall.client import (
        FirewallClient,
        Rich_Rule,
        FirewallClientZoneSettings,
        FirewallClientServiceSettings,
    )

    HAS_FIREWALLD = True
except ImportError:
    HAS_FIREWALLD = False


def create_service(module, fw, service):
    if not module.check_mode:
        fw.config().addService(service, FirewallClientServiceSettings())
        fw_service = fw.config().getServiceByName(service)
        fw_service_settings = fw_service.getSettings()
    else:
        fw_service = None
        fw_service_settings = FirewallClientServiceSettings()
    return fw_service, fw_service_settings


def handle_interface_permanent(
    zone, item, fw_zone, fw_settings, fw, fw_offline, module
):
    if fw_offline:
        iface_zone_objs = []
        for zone in fw.config.get_zones():
            old_zone_obj = fw.config.get_zone(zone)
            if item in old_zone_obj.interfaces:
                old_zone_settings = FirewallClientZoneSettings(
                    fw.config.get_zone_config(old_zone_obj)
                )
                old_zone_settings.removeInterface(item)
                fw.config.set_zone_config(old_zone_obj, old_zone_settings.settings)
                iface_zone_objs.append(old_zone_obj)

        old_zone_obj = iface_zone_objs[0]
        if old_zone_obj.name != zone:
            old_zone_settings = FirewallClientZoneSettings(
                fw.config.get_zone_config(old_zone_obj)
            )
            old_zone_settings.removeInterface(item)
            fw.config.set_zone_config(old_zone_obj, old_zone_settings.settings)
            fw_settings.addInterface(item)
            fw.config.set_zone_config(fw_zone, fw_settings.settings)
    else:
        old_zone_name = fw.config().getZoneOfInterface(item)
        if old_zone_name != zone:
            if old_zone_name:
                old_zone_obj = fw.config().getZoneByName(old_zone_name)
                old_zone_settings = old_zone_obj.getSettings()
                old_zone_settings.removeInterface(item)
                old_zone_obj.update(old_zone_settings)
            fw_settings.addInterface(item)


def parse_port(module, item):
    _port, _protocol = item.split("/")
    if _protocol is None:
        module.fail_json(msg="improper port format (missing protocol?)")
    return (_port, _protocol)


ipv4_charset = "0123456789./"
ipv6_charset = "0123456789abcdef:/"


def parse_destination_address(module, item):
    # Preventing long iterations for no reason
    if len(item) > 43:
        module.fail_json(msg="destination argument too long to be valid")

    ipv4 = True
    ipv6 = True

    for character in item:
        if character not in ipv4_charset:
            ipv4 = False
        if character not in ipv6_charset:
            ipv6 = False

    if (ipv4 and ipv6) or (not ipv4 and not ipv6):
        module.fail_json(msg="Invalid IPv4 or IPv6 address - " + item)

    # ipv4 specific error checking
    if ipv4:
        address = item.split(".")
        if len(address) != 4:
            module.fail_json(msg="IPv4 address does not have 4 octets - " + item)

        for octet in range(4):
            if "/" in address[octet] and octet != 3:
                module.fail_json(
                    msg="IPv4 address can only have a / "
                    "at the end of the address to specify "
                    "a subnet mask"
                )
            octet_value = address[octet]
            if octet == 3 and "/" in octet_value:
                octet_value, mask = octet_value.split("/")

                if int(mask) > 32:
                    module.fail_json(
                        msg="invalid IPv4 subnet mask - "
                        + mask
                        + " (must be between 0 and 32 inclusive)"
                    )

                if int(octet_value) > 255:
                    module.fail_json(
                        msg="invalid IPv4 octet "
                        + str(octet_value)
                        + " in address "
                        + item
                    )
        return "ipv4"
    if ipv6:
        address = item.split(":")
        num_segments = len(address)
        if num_segments > 10:
            module.fail_json(
                msg="Invalid IPv6 address " + item + " - too many segments"
            )
        for segment_number in range(num_segments):
            segment = address[segment_number]
            if segment != "":
                if segment_number != num_segments - 1 and "/" in segment:
                    module.fail_json(
                        msg="Invalid IPv6 address - subnet mask"
                        " found before last segment"
                    )
                if segment_number == num_segments - 1 and "/" in segment:
                    segment, mask = segment.split("/")
                    if int(mask) > 128:
                        module.fail_json(
                            msg="Invalid IPv6 address "
                            + item
                            + " - subnet mask "
                            + mask
                            + " invalid"
                        )
                if int(segment, 16) > 65535:
                    module.fail_json(
                        msg="Invalid IPv6 address " + item + " -"
                        " invalid segment " + segment
                    )

        return "ipv6"


def parse_helper_module(module, item):
    item = item.split("_")
    _module = [word for word in item if word != "nf" or word != "conntrack"]
    return "_".join(_module)


def get_forward_port(module):
    forward_port = module.params["forward_port"]
    if isinstance(forward_port, list):
        return forward_port
    else:
        return [forward_port]


def parse_forward_port(module, item):
    type_string = "forward_port"

    if isinstance(item, dict):
        if "port" not in item:
            module.fail_json(
                msg="%s is missing field 'port' in %s" % (type_string, item)
            )
        else:
            _port = str(item["port"])
        if "proto" not in item:
            module.fail_json(
                msg="%s is missing field 'proto' in %s" % (type_string, item)
            )
        else:
            _protocol = item["proto"]
        if "toport" in item:
            _to_port = str(item["toport"])
        else:
            _to_port = None
        _to_addr = item.get("toaddr")
    elif isinstance(item, str):
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
    else:
        module.fail_json(
            msg="improper %s type (must be str or dict): %s" % (type_string, item)
        )

    return (_port, _protocol, _to_port, _to_addr)


def set_the_default_zone(fw, set_default_zone):
    fw.setDefaultZone(set_default_zone)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            service=dict(required=False, type="list", elements="str", default=[]),
            port=dict(required=False, type="list", elements="str", default=[]),
            source_port=dict(required=False, type="list", elements="str", default=[]),
            forward_port=dict(
                required=False,
                type="raw",
                default=[],
                aliases=["port_forward"],
                deprecated_aliases=[
                    {
                        "name": "port_forward",
                        "date": "2021-09-23",
                        "collection_name": "ansible.posix",
                    },
                ],
            ),
            masquerade=dict(required=False, type="bool", default=None),
            rich_rule=dict(required=False, type="list", elements="str", default=[]),
            source=dict(required=False, type="list", elements="str", default=[]),
            interface=dict(required=False, type="list", elements="str", default=[]),
            icmp_block=dict(required=False, type="list", elements="str", default=[]),
            icmp_block_inversion=dict(required=False, type="bool", default=None),
            timeout=dict(required=False, type="int", default=0),
            target=dict(
                required=False,
                type="str",
                choices=["default", "ACCEPT", "DROP", "%%REJECT%%"],
                default=None,
            ),
            zone=dict(required=False, type="str", default=None),
            set_default_zone=dict(required=False, type="str", default=None),
            permanent=dict(required=False, type="bool", default=None),
            runtime=dict(
                required=False,
                type="bool",
                default=None,
                aliases=["immediate"],
                deprecated_aliases=[
                    {
                        "name": "immediate",
                        "date": "2021-09-23",
                        "collection_name": "ansible.posix",
                    },
                ],
            ),
            state=dict(
                choices=["enabled", "disabled", "present", "absent"],
                required=False,
                default=None,
            ),
            description=dict(required=False, type="str", default=None),
            short=dict(required=False, type="str", default=None),
            protocol=dict(required=False, type="list", elements="str", default=[]),
            helper_module=dict(required=False, type="list", elements="str", default=[]),
            destination=dict(required=False, type="list", elements="str", default=[]),
            __report_changed=dict(required=False, type="bool", default=True),
        ),
        supports_check_mode=True,
        required_if=(
            ("state", "present", ("zone", "target", "service"), True),
            ("state", "absent", ("zone", "target", "service"), True),
        ),
    )

    if not HAS_FIREWALLD:
        module.fail_json(msg="No firewall backend could be imported.")

    service = module.params["service"]
    short = module.params["short"]
    description = module.params["description"]
    protocol = module.params["protocol"]
    helper_module = []
    for _module in module.params["helper_module"]:
        helper_module.append(parse_helper_module(module, _module))
    port = []
    for port_proto in module.params["port"]:
        port.append(parse_port(module, port_proto))
    source_port = []
    for port_proto in module.params["source_port"]:
        source_port.append(parse_port(module, port_proto))
    forward_port = []
    for item in get_forward_port(module):
        forward_port.append(parse_forward_port(module, item))
    masquerade = module.params["masquerade"]
    rich_rule = []
    for item in module.params["rich_rule"]:
        try:
            rule = str(Rich_Rule(rule_str=item))
            rich_rule.append(rule)
        except Exception as e:
            module.fail_json(msg="Rich Rule '%s' is not valid: %s" % (item, str(e)))
    source = module.params["source"]
    destination_ipv4 = None
    destination_ipv6 = None
    for address in module.params["destination"]:
        ip_type = parse_destination_address(module, address)
        if ip_type == "ipv4" and not destination_ipv4:
            destination_ipv4 = address
        elif destination_ipv4 and ip_type == "ipv4":
            module.fail_json(msg="cannot have more than one destination ipv4")
        if ip_type == "ipv6" and not destination_ipv6:
            destination_ipv6 = address
        elif destination_ipv6 and ip_type == "ipv6":
            module.fail_json(msg="cannot have more than one destination ipv6")
    interface = module.params["interface"]
    icmp_block = module.params["icmp_block"]
    icmp_block_inversion = module.params["icmp_block_inversion"]
    timeout = module.params["timeout"]
    target = module.params["target"]
    zone = module.params["zone"]
    set_default_zone = module.params["set_default_zone"]
    permanent = module.params["permanent"]
    runtime = module.params["runtime"]
    state = module.params["state"]

    # All options that require state to be set
    state_required = any(
        (
            interface,
            source,
            service,
            source_port,
            port,
            forward_port,
            icmp_block,
            rich_rule,
        )
    )
    if permanent is None:
        runtime = True
    elif not any((permanent, runtime)):
        module.fail_json(msg="One of permanent, runtime needs to be enabled")

    if (
        masquerade is None
        and icmp_block_inversion is None
        and target is None
        and zone is None
        and not any(
            (
                service,
                port,
                source_port,
                forward_port,
                rich_rule,
                source,
                interface,
                icmp_block,
                set_default_zone,
            )
        )
    ):
        module.fail_json(
            msg="One of service, port, source_port, forward_port, "
            "masquerade, rich_rule, source, interface, icmp_block, "
            "icmp_block_inversion, target, zone or set_default_zone needs to be set"
        )

    # Checking for any permanent configuration operations
    zone_operation = False
    service_operation = False
    if state == "present" or state == "absent":
        if (
            masquerade is not None
            and icmp_block_inversion is not None
            and any(
                (
                    forward_port,
                    rich_rule,
                    source,
                    interface,
                    icmp_block,
                )
            )
        ):
            module.fail_json(
                msg="states present and absent only usable for zone, service, or target operations "
                "(when no parameters but zone or target and state(absent/present) are set, "
                "or when state and service are set with optional parameters short, description "
                " port, source_port, protocol, destination, or helper_module)"
            )

        # Zone and service are incompatible when state is set to present or absent
        if zone and service:
            module.fail_json(msg="both zone and service while state present/absent")

        # While short and description are options for new zones, they are unimplemented
        if target is None and zone is not None:
            if any(
                (
                    service,
                    description,
                    short,
                    port,
                    source_port,
                    helper_module,
                    protocol,
                    destination_ipv4,
                    destination_ipv6,
                )
            ):
                module.fail_json(
                    msg="short, description, port, source_port, helper_module, "
                    "protocol, or destination cannot be set while zone is specified "
                    "and state is set to present or absent"
                )
            else:
                zone_operation = True

        elif service:
            if target is not None:
                module.fail_json(
                    msg="both service and target cannot be set "
                    "while state is either present or absent"
                )
            elif not permanent:
                module.fail_json(
                    msg="permanent must be enabled for service configuration. "
                    "Additionally, service runtime configuration is not possible"
                )
            else:
                service_operation = True

    if service_operation:
        if state == "absent" and any(
            (
                description,
                short,
            )
        ):
            module.fail_json(
                msg="description or short is only usable with present state"
            )
        if len(service) != 1:
            module.fail_json(
                msg="can only add, modify, or remove one service at a time"
            )
        else:
            service = service[0]

    # Parameter checks
    if state == "disabled":
        if timeout > 0:
            module.fail_json(msg="timeout can not be used with state: disabled")
        if masquerade:
            module.fail_json(msg="masquerade can not be used with state: disabled")

        if icmp_block_inversion:
            module.fail_json(
                msg="icmp_block_inversion can not be used with state: disabled"
            )

        # if target is not None:
        #     module.fail_json(
        #         msg="target can not be used with state: disabled"
        #     )

    if timeout > 0:
        _timeout_ok = any(
            (
                masquerade,
                service,
                port,
                source_port,
                forward_port,
                rich_rule,
                icmp_block,
            )
        )

        if icmp_block_inversion is not None and not _timeout_ok:
            module.fail_json(
                msg="timeout can not be used with icmp_block_inversion only"
            )

        if len(source) > 0 and not _timeout_ok:
            module.fail_json(msg="timeout can not be used with source only")

        if len(interface) > 0 and not _timeout_ok:
            module.fail_json(msg="timeout can not be used with interface only")

        if target is not None and not _timeout_ok:
            module.fail_json(msg="timeout can not be used with target only")

    if len(source) > 0 and permanent is None:
        module.fail_json(msg="source cannot be set without permanent")

    if state is None and state_required:
        module.fail_json(msg="Options invalid without state option set")

    if not HAS_FIREWALLD:
        module.fail_json(msg="No firewalld")

    fw = FirewallClient()

    fw_offline = False
    if not fw.connected:
        # Firewalld is not currently running, permanent-only operations
        fw_offline = True
        runtime = False
        permanent = True

        # Pre-run version checking
        if LooseVersion(FW_VERSION) < LooseVersion("0.3.9"):
            module.fail_json(
                msg="Unsupported firewalld version %s" " requires >= 0.3.9" % FW_VERSION
            )

        try:
            from firewall.core.fw_test import Firewall_test

            fw = Firewall_test()

        except ImportError:
            # In firewalld version 0.7.0 this behavior changed
            from firewall.core.fw import Firewall

            fw = Firewall(offline=True)

        fw.start()
    else:
        # Pre-run version checking
        if LooseVersion(FW_VERSION) < LooseVersion("0.2.11"):
            module.fail_json(
                msg="Unsupported firewalld version %s, requires >= 0.2.11" % FW_VERSION
            )

        # Set exception handler
        def exception_handler(exception_message):
            module.fail_json(msg=exception_message)

        fw.setExceptionHandler(exception_handler)

    # Get default zone, the permanent zone and settings
    fw_zone = None
    fw_settings = None
    if fw_offline:
        # if zone is None, we will use default zone which always exists
        zone_exists = zone is None or zone in fw.zone.get_zones()
        if not zone_exists and not zone_operation:
            module.fail_json(msg="Permanent zone '%s' does not exist." % zone)
        elif zone_exists:
            zone = zone or fw.get_default_zone()
            fw_zone = fw.config.get_zone(zone)
            fw_settings = FirewallClientZoneSettings(
                list(fw.config.get_zone_config(fw_zone))
            )
    else:
        zone_exists = False
        if runtime:
            zone_exists = zone_exists or zone is None or zone in fw.getZones()
            err_str = "Runtime"
        if permanent:
            zone_exists = (
                zone_exists or zone is None or zone in fw.config().getZoneNames()
            )
            err_str = "Permanent"

        if not zone_exists and not zone_operation:
            module.fail_json(msg="%s zone '%s' does not exist." % (err_str, zone))
        elif zone_exists:
            zone = zone or fw.getDefaultZone()
            fw_zone = fw.config().getZoneByName(zone)
            fw_settings = fw_zone.getSettings()

    # Firewall modification starts here

    changed = False
    need_reload = False

    # zone
    if zone_operation:
        if state == "present" and not zone_exists:
            if not module.check_mode:
                fw.config().addZone(zone, FirewallClientZoneSettings())
                need_reload = True
            changed = True
        elif state == "absent" and zone_exists:
            if not module.check_mode:
                fw_zone.remove()
                need_reload = True
            changed = True
            fw_zone = None
            fw_settings = None

    # set default zone
    if set_default_zone:
        if fw.getDefaultZone() != set_default_zone:
            set_the_default_zone(fw, set_default_zone)
            changed = True

    # service
    if service_operation and permanent:
        service_exists = service in fw.config().getServiceNames()
        if service_exists:
            fw_service = fw.config().getServiceByName(service)
            fw_service_settings = fw_service.getSettings()
        elif state == "present":
            fw_service, fw_service_settings = create_service(module, fw, service)
            changed = True
            service_exists = True

        if state == "present":
            if (
                description is not None
                and description != fw_service_settings.getDescription()
            ):
                if not module.check_mode:
                    fw_service_settings.setDescription(description)
                changed = True
            if short is not None and short != fw_service_settings.getShort():
                if not module.check_mode:
                    fw_service_settings.setShort(short)
                changed = True
            for _port, _protocol in port:
                if not fw_service_settings.queryPort(_port, _protocol):
                    if not module.check_mode:
                        fw_service_settings.addPort(_port, _protocol)
                    changed = True
            for _protocol in protocol:
                if not fw_service_settings.queryProtocol(_protocol):
                    if not module.check_mode:
                        fw_service_settings.addProtocol(_protocol)
                    changed = True
            for _port, _protocol in source_port:
                if not fw_service_settings.querySourcePort(_port, _protocol):
                    if not module.check_mode:
                        fw_service_settings.addSourcePort(_port, _protocol)
                    changed = True
            for _module in helper_module:
                if fw_service_settings.queryModule(_module):
                    if not module.check_mode:
                        fw_service_settings.addModule(_module)
                    changed = True
            if destination_ipv4:
                if not fw_service_settings.queryDestination("ipv4", destination_ipv4):
                    if not module.check_mode:
                        fw_service_settings.setDestination("ipv4", destination_ipv4)
                    changed = True
            if destination_ipv6:
                if not fw_service_settings.queryDestination("ipv6", destination_ipv6):
                    if not module.check_mode:
                        fw_service_settings.setDestination("ipv6", destination_ipv6)
                    changed = True
        if state == "absent" and service_exists:
            if port:
                for _port, _protocol in port:
                    if fw_service_settings.queryPort(_port, _protocol):
                        if not module.check_mode:
                            fw_service_settings.removePort(_port, _protocol)
                        changed = True
            if source_port:
                for _port, _protocol in source_port:
                    if fw_service_settings.querySourcePort(_port, _protocol):
                        if not module.check_mode:
                            fw_service_settings.removeSourcePort(_port, _protocol)
                        changed = True
            if protocol:
                for _protocol in protocol:
                    if fw_service_settings.queryProtocol(_protocol):
                        if not module.check_mode:
                            fw_service_settings.removeProtocol(_protocol)
                        changed = True
            if helper_module:
                for _module in helper_module:
                    if fw_service_settings.queryModule(_module):
                        if not module.check_mode:
                            fw_service_settings.removeModule(_module)
                        changed = True
            if destination_ipv4:
                if fw_service_settings.queryDestination("ipv4", destination_ipv4):
                    if not module.check_mode:
                        fw_service_settings.removeDestination("ipv4", destination_ipv4)
                    changed = True
            if destination_ipv6:
                if fw_service_settings.queryDestination("ipv6", destination_ipv6):
                    if not module.check_mode:
                        fw_service_settings.removeDestination("ipv6", destination_ipv6)
                    changed = True
            if not any(
                (
                    port,
                    source_port,
                    protocol,
                    helper_module,
                    destination_ipv4,
                    destination_ipv6,
                )
            ):
                if not module.check_mode:
                    fw_service.remove()
                    service_exists = False
                changed = True
        # If service operation occurs, this should be the only instruction executed by the script
        if changed and not module.check_mode:
            if service_exists:
                fw_service.update(fw_service_settings)
            need_reload = True
    else:
        for item in service:
            if state == "enabled":
                if runtime and not fw.queryService(zone, item):
                    if not module.check_mode:
                        fw.addService(zone, item, timeout)
                    changed = True
                if permanent and not fw_settings.queryService(item):
                    if not module.check_mode:
                        fw_settings.addService(item)
                    changed = True
            elif state == "disabled":
                if runtime and fw.queryService(zone, item):
                    if not module.check_mode:
                        fw.removeService(zone, item)
                if permanent and fw_settings.queryService(item):
                    if not module.check_mode:
                        fw_settings.removeService(item)
                    changed = True

    # port
    for _port, _protocol in port:
        if state == "enabled":
            if runtime and not fw.queryPort(zone, _port, _protocol):
                if not module.check_mode:
                    fw.addPort(zone, _port, _protocol, timeout)
                changed = True
            if permanent and not fw_settings.queryPort(_port, _protocol):
                if not module.check_mode:
                    fw_settings.addPort(_port, _protocol)
                changed = True
        elif state == "disabled":
            if runtime and fw.queryPort(zone, _port, _protocol):
                if not module.check_mode:
                    fw.removePort(zone, _port, _protocol)
                changed = True
            if permanent and fw_settings.queryPort(_port, _protocol):
                if not module.check_mode:
                    fw_settings.removePort(_port, _protocol)
                changed = True

    # source_port
    for _port, _protocol in source_port:
        if state == "enabled":
            if runtime and not fw.querySourcePort(zone, _port, _protocol):
                if not module.check_mode:
                    fw.addSourcePort(zone, _port, _protocol, timeout)
                changed = True
            if permanent and not fw_settings.querySourcePort(_port, _protocol):
                if not module.check_mode:
                    fw_settings.addSourcePort(_port, _protocol)
                changed = True
        elif state == "disabled":
            if runtime and fw.querySourcePort(zone, _port, _protocol):
                if not module.check_mode:
                    fw.removeSourcePort(zone, _port, _protocol)
                changed = True
            if permanent and fw_settings.querySourcePort(_port, _protocol):
                if not module.check_mode:
                    fw_settings.removeSourcePort(_port, _protocol)
                changed = True

    # forward_port
    if len(forward_port) > 0:
        for _port, _protocol, _to_port, _to_addr in forward_port:
            if state == "enabled":
                if runtime and not fw.queryForwardPort(
                    zone, _port, _protocol, _to_port, _to_addr
                ):
                    if not module.check_mode:
                        fw.addForwardPort(
                            zone, _port, _protocol, _to_port, _to_addr, timeout
                        )
                    changed = True
                if permanent and not fw_settings.queryForwardPort(
                    _port, _protocol, _to_port, _to_addr
                ):
                    if not module.check_mode:
                        fw_settings.addForwardPort(_port, _protocol, _to_port, _to_addr)
                    changed = True
            elif state == "disabled":
                if runtime and fw.queryForwardPort(
                    zone, _port, _protocol, _to_port, _to_addr
                ):
                    if not module.check_mode:
                        fw.removeForwardPort(zone, _port, _protocol, _to_port, _to_addr)
                    changed = True
                if permanent and fw_settings.queryForwardPort(
                    _port, _protocol, _to_port, _to_addr
                ):
                    if not module.check_mode:
                        fw_settings.removeForwardPort(
                            _port, _protocol, _to_port, _to_addr
                        )
                    changed = True

    # masquerade
    if masquerade is not None:
        if masquerade:
            if runtime and not fw.queryMasquerade(zone):
                if not module.check_mode:
                    fw.addMasquerade(zone, timeout)
                changed = True
            if permanent and not fw_settings.queryMasquerade():
                if not module.check_mode:
                    fw_settings.addMasquerade()
                changed = True
        else:
            if runtime and fw.queryMasquerade(zone):
                if not module.check_mode:
                    fw.removeMasquerade(zone)
                changed = True
            if permanent and fw_settings.queryMasquerade():
                if not module.check_mode:
                    fw_settings.removeMasquerade()
                changed = True

    # rich_rule
    for item in rich_rule:
        if state == "enabled":
            if runtime and not fw.queryRichRule(zone, item):
                if not module.check_mode:
                    fw.addRichRule(zone, item, timeout)
                changed = True
            if permanent and not fw_settings.queryRichRule(item):
                if not module.check_mode:
                    fw_settings.addRichRule(item)
                changed = True
        elif state == "disabled":
            if runtime and fw.queryRichRule(zone, item):
                if not module.check_mode:
                    fw.removeRichRule(zone, item)
                changed = True
            if permanent and fw_settings.queryRichRule(item):
                if not module.check_mode:
                    fw_settings.removeRichRule(item)
                changed = True

    # source
    for item in source:
        if state == "enabled":
            if runtime and not fw.querySource(zone, item):
                if not module.check_mode:
                    fw.addSource(zone, item)
                changed = True
            if permanent and not fw_settings.querySource(item):
                if not module.check_mode:
                    fw_settings.addSource(item)
                changed = True
        elif state == "disabled":
            if runtime and fw.querySource(zone, item):
                if not module.check_mode:
                    fw.removeSource(zone, item)
                changed = True
            if permanent and fw_settings.querySource(item):
                if not module.check_mode:
                    fw_settings.removeSource(item)
                changed = True

    # interface
    for item in interface:
        if state == "enabled":
            if runtime and not fw.queryInterface(zone, item):
                if not module.check_mode:
                    fw.changeZoneOfInterface(zone, item)
                changed = True
            if permanent and not fw_settings.queryInterface(item):
                if not module.check_mode:
                    handle_interface_permanent(
                        zone, item, fw_zone, fw_settings, fw, fw_offline, module
                    )
                changed = True
        elif state == "disabled":
            if runtime and fw.queryInterface(zone, item):
                if not module.check_mode:
                    fw.removeInterface(zone, item)
                changed = True
            if permanent and fw_settings.queryInterface(item):
                if not module.check_mode:
                    fw_settings.removeInterface(item)
                changed = True

    # icmp_block
    for item in icmp_block:
        if state == "enabled":
            if runtime and not fw.queryIcmpBlock(zone, item):
                if not module.check_mode:
                    fw.addIcmpBlock(zone, item, timeout)
                changed = True
            if permanent and not fw_settings.queryIcmpBlock(item):
                if not module.check_mode:
                    fw_settings.addIcmpBlock(item)
                changed = True
        elif state == "disabled":
            if runtime and fw.queryIcmpBlock(zone, item):
                if not module.check_mode:
                    fw.removeIcmpBlock(zone, item)
                changed = True
            if permanent and fw_settings.queryIcmpBlock(item):
                if not module.check_mode:
                    fw_settings.removeIcmpBlock(item)
                changed = True

    # icmp_block_inversion
    if icmp_block_inversion is not None:
        if icmp_block_inversion:
            if runtime and not fw.queryIcmpBlockInversion(zone):
                if not module.check_mode:
                    fw.addIcmpBlockInversion(zone)
                changed = True
            if permanent and not fw_settings.queryIcmpBlockInversion():
                if not module.check_mode:
                    fw_settings.addIcmpBlockInversion()
                changed = True
        else:
            if runtime and fw.queryIcmpBlockInversion(zone):
                if not module.check_mode:
                    fw.removeIcmpBlockInversion(zone)
                changed = True
            if permanent and fw_settings.queryIcmpBlockInversion():
                if not module.check_mode:
                    fw_settings.removeIcmpBlockInversion()
                changed = True

    # target
    if target is not None:
        if state in ["enabled", "present"]:
            if permanent and fw_settings.getTarget() != target:
                if not module.check_mode:
                    fw_settings.setTarget(target)
                    need_reload = True
                changed = True
        elif state in ["absent", "disabled"]:
            target = "default"
            if permanent and fw_settings.getTarget() != target:
                if not module.check_mode:
                    fw_settings.setTarget(target)
                    need_reload = True
                changed = True

    # apply permanent changes
    if changed and (zone_operation or permanent):
        if fw_zone and fw_settings:
            if fw_offline:
                fw.config.set_zone_config(fw_zone, fw_settings.settings)
            else:
                fw_zone.update(fw_settings)
        if need_reload:
            fw.reload()

    if not module.params["__report_changed"]:
        changed = False
    module.exit_json(changed=changed, __firewall_changed=changed)


#################################################

if __name__ == "__main__":
    main()
