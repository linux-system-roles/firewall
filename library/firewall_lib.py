#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 - 2025 Red Hat, Inc.
# Reusing some firewalld code
# Authors:
# Thomas Woerner <twoerner@redhat.com>
# Martin Pitt <mpitt@redhat.com>
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
author: "Thomas Woerner (@t-woerner), Martin Pitt (@martinpitt)"
options:
  firewalld_conf:
    description:
      Modify firewalld.conf directives
    suboptions:
      allow_zone_drifting:
        description:
          Set AllowZoneDrifting directive if not deprecated
        required: false
        type: bool
    required: false
    type: dict
  service:
    description:
      List of service name strings.
      The service names needs to be defined in firewalld configuration.
      services in firewalld configuration can be defined by setting
      this option to a single service name and state to present.
    required: false
    type: list
    elements: str
    default: []
  port:
    description:
      List of ports or port range strings.
      The format of a port needs to be port=<port>[-<port>]/<protocol>.
    required: false
    type: list
    elements: str
    default: []
  source_port:
    description:
      List of source port or port range strings.
      The format of a source port needs to be port=<port>[-<port>]/<protocol>.
    required: false
    type: list
    elements: str
    default: []
  forward_port:
    description:
      List of forward port strings or dicts,
      or a single string or dict.
      The format of a forward port string needs to be
      <port>[-<port>]/<protocol>;[<to-port>];[<to-addr>].
    aliases: ["port_forward"]
    required: false
    type: raw
    default: []
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
    default: []
  source:
    description:
      List of source address, address range strings, or ipsets
      A source address or address range is either an IP address or a network
      IP address with a mask for IPv4 or IPv6. For IPv4, the mask can be a
      network mask or a plain number. For IPv6 the mask is a plain number.
      An ipset is used by prefixing "ipset{{ ":" }}" to the defined ipset's name.
    required: false
    type: list
    elements: str
    default: []
  interface:
    description:
      List of interface name strings.
    required: false
    type: list
    elements: str
    default: []
  interface_pci_id:
    description:
      List of interface PCI device ID strings.
      PCI device ID needs to correspond to a named network interface.
    required: false
    type: list
    elements: str
    default: []
  icmp_block:
    description:
      List of ICMP type strings to block.
      The ICMP type names needs to be defined in firewalld configuration.
    required: false
    type: list
    elements: str
    default: []
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
  ipset:
    description:
      Name of the ipset being configured.
      Can be used to define, modify, or remove ipsets.
      Must set state to C(present) or C(absent) to use this argument.
      Must set permanent to C(true) to use this argument.
    required: false
    type: str
  ipset_type:
    description:
      Type of ipset being defined
      Will only do something when ipset argument is defined.
      To get the list of supported ipset types, use
      firewall-cmd --get-ipset-types.
    required: false
    type: str
  ipset_entries:
    description:
      List of addresses to add/remove from ipset.
      Will only do something when set with ipset.
    required: false
    type: list
    elements: str
    default: []
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
      Creates or updates the description of a new or existing service or ipset.
      State needs to be present for the use of this argument.
      Supported for ipsets and services.
    required: false
    type: str
  short:
    description:
      Creates or updates a short description, generally just a full name of a
      new or existing service.
      Supported for custom services and ipsets while state is present
    required: false
    type: str
  protocol:
    description:
      list of protocols supported by managed system.
      Supported for service configuration only
    required: false
    type: list
    elements: str
    default: []
  helper_module:
    description:
      List of netfiler kernel helper module names
    required: false
    type: list
    elements: str
    default: []
  destination:
    description:
      List of IPv4/IPv6 addresses with optional mask
      format - address[/mask]
      Currently only supported for service configuration
      Only one IPv4 and one IPv6 address allowed in list.
    required: false
    type: list
    elements: str
    default: []
  includes:
    description:
      Services to include in this one.
    required: false
    type: list
    elements: str
    default: []
  __report_changed:
    description:
      If false, do not report changed true even if changed.
    required: false
    type: bool
    default: true
  online:
    description:
      When true, use the D-Bus API to query the status from the running system.
      Otherwise, use firewall-offline-cmd(1). Offline mode is
      incompatible with "runtime" mode.
    type: bool
    required: false
    default: true
"""

EXAMPLES = """
firewall:
  - port: ['443/tcp', '443/udp']
"""

from ansible.module_utils.basic import AnsibleModule
import re
import os

try:
    import firewall.config

    FW_VERSION = firewall.config.VERSION

    from firewall.client import (
        FirewallClient,
        Rich_Rule,
        FirewallClientZoneSettings,
        FirewallClientServiceSettings,
        FirewallClientIPSetSettings,
    )

    HAS_FIREWALLD = True
except ImportError:
    HAS_FIREWALLD = False

try:
    from firewall.core.fw_nm import (
        nm_is_imported,
        nm_get_connection_of_interface,
        nm_get_zone_of_connection,
        nm_set_zone_of_connection,
        nm_get_interfaces,
        nm_get_client,
    )

    NM_IMPORTED = nm_is_imported()
except ImportError:
    NM_IMPORTED = False


def try_get_connection_of_interface(interface):
    try:
        return nm_get_connection_of_interface(interface)
    except Exception:
        return None


def try_set_zone_of_interface(module, _zone, interface):
    if NM_IMPORTED:
        connection = try_get_connection_of_interface(interface)
        if connection is not None:
            if _zone == "":
                zone_string = "the default zone"
            else:
                zone_string = _zone
            if _zone == nm_get_zone_of_connection(connection):
                module.log(
                    msg="The interface is under control of NetworkManager and already bound to '%s'"
                    % zone_string
                )
                return (True, False)
            else:
                if not module.check_mode:
                    nm_set_zone_of_connection(_zone, connection)
                return (True, True)
    return (False, False)


# Above: adapted from firewall-cmd source code


class OnlineAPIBackend:
    """Implement operations with the FirewallClient() API.

    This requires firewalld to be running.
    """

    def __init__(
        self, module, permanent, runtime, zone_operation, zone, state, timeout
    ):
        self.module = module
        self.state = state
        self.permanent = permanent
        self.runtime = runtime
        self.zone = zone
        self.timeout = timeout

        self.fw = FirewallClient()

        # Set exception handler
        def exception_handler(exception_message):
            module.fail_json(msg=exception_message)

        self.fw.setExceptionHandler(exception_handler)

        self.changed = False
        self.need_reload = False

        # Get default zone, the permanent zone and settings
        zone_exists = False
        if runtime:
            zone_exists = zone_exists or zone is None or zone in self.fw.getZones()
            err_str = "Runtime"
        if permanent:
            zone_exists = (
                zone_exists or zone is None or zone in self.fw.config().getZoneNames()
            )
            err_str = "Permanent"

        if not zone_exists and not zone_operation:
            module.fail_json(msg="%s zone '%s' does not exist." % (err_str, zone))

        if zone_exists:
            self.zone = self.zone or self.fw.getDefaultZone()
            self.fw_zone = self.fw.config().getZoneByName(self.zone)
            self.fw_settings = self.fw_zone.getSettings()
        else:
            self.fw_zone = None
            self.fw_settings = None
            zone_exists = False

        self.zone_exists = zone_exists

    def finalize(self):
        if self.fw_zone and self.fw_settings:
            self.fw_zone.update(self.fw_settings)
        if self.need_reload:
            self.fw.reload()

    def set_firewalld_conf(self, firewalld_conf, allow_zone_drifting_deprecated):
        fw_config = self.fw.config()
        if not allow_zone_drifting_deprecated and firewalld_conf.get(
            "allow_zone_drifting"
        ) != fw_config.get_property("AllowZoneDrifting"):
            if not self.module.check_mode:
                fw_config.set_property(
                    "AllowZoneDrifting", firewalld_conf.get("allow_zone_drifting")
                )
            self.changed = True
            self.need_reload = True

    def set_zone(self):
        if self.state == "present" and not self.zone_exists:
            if not self.module.check_mode:
                self.fw.config().addZone(self.zone, FirewallClientZoneSettings())
                self.need_reload = True
                self.changed = True
        elif self.state == "absent" and self.zone_exists:
            if not self.module.check_mode:
                self.fw_zone.remove()
                self.need_reload = True
            self.changed = True
            self.fw_zone = None
            self.fw_settings = None

    def set_default_zone(self, zone):
        if self.fw.getDefaultZone() != zone:
            self.fw.setDefaultZone(zone)
            self.changed = True

    def _create_service(self, service):
        if not self.module.check_mode:
            self.fw.config().addService(service, FirewallClientServiceSettings())
            fw_service = self.fw.config().getServiceByName(service)
            fw_service_settings = fw_service.getSettings()
        else:
            fw_service = None
            fw_service_settings = FirewallClientServiceSettings()
        return fw_service, fw_service_settings

    def set_service(
        self,
        service_operation,
        service,
        description,
        short,
        port,
        protocol,
        source_port,
        helper_module,
        destination_ipv4,
        destination_ipv6,
        includes,
    ):
        if service_operation and self.permanent:
            service_exists = service in self.fw.config().getServiceNames()
            if service_exists:
                fw_service = self.fw.config().getServiceByName(service)
                fw_service_settings = fw_service.getSettings()
            elif self.state == "present":
                fw_service, fw_service_settings = self._create_service(service)
                self.changed = True
                service_exists = True

            if self.state == "present":
                if (
                    description is not None
                    and description != fw_service_settings.getDescription()
                ):
                    if not self.module.check_mode:
                        fw_service_settings.setDescription(description)
                    self.changed = True
                if short is not None and short != fw_service_settings.getShort():
                    if not self.module.check_mode:
                        fw_service_settings.setShort(short)
                    self.changed = True
                for _port, _protocol in port:
                    if not fw_service_settings.queryPort(_port, _protocol):
                        if not self.module.check_mode:
                            fw_service_settings.addPort(_port, _protocol)
                        self.changed = True
                for _protocol in protocol:
                    if not fw_service_settings.queryProtocol(_protocol):
                        if not self.module.check_mode:
                            fw_service_settings.addProtocol(_protocol)
                        self.changed = True
                for _port, _protocol in source_port:
                    if not fw_service_settings.querySourcePort(_port, _protocol):
                        if not self.module.check_mode:
                            fw_service_settings.addSourcePort(_port, _protocol)
                        self.changed = True
                for _module in helper_module:
                    if not fw_service_settings.queryHelper(_module):
                        if not self.module.check_mode:
                            fw_service_settings.addHelper(_module)
                        self.changed = True
                if destination_ipv4:
                    if not fw_service_settings.queryDestination(
                        "ipv4", destination_ipv4
                    ):
                        if not self.module.check_mode:
                            fw_service_settings.setDestination("ipv4", destination_ipv4)
                        self.changed = True
                if destination_ipv6:
                    if not fw_service_settings.queryDestination(
                        "ipv6", destination_ipv6
                    ):
                        if not self.module.check_mode:
                            fw_service_settings.setDestination("ipv6", destination_ipv6)
                        self.changed = True
                for _include in includes:
                    if not fw_service_settings.queryInclude(_include):
                        if not self.module.check_mode:
                            fw_service_settings.addInclude(_include)
                        self.changed = True
            if self.state == "absent" and service_exists:
                if port:
                    for _port, _protocol in port:
                        if fw_service_settings.queryPort(_port, _protocol):
                            if not self.module.check_mode:
                                fw_service_settings.removePort(_port, _protocol)
                            self.changed = True
                if source_port:
                    for _port, _protocol in source_port:
                        if fw_service_settings.querySourcePort(_port, _protocol):
                            if not self.module.check_mode:
                                fw_service_settings.removeSourcePort(_port, _protocol)
                            self.changed = True
                if protocol:
                    for _protocol in protocol:
                        if fw_service_settings.queryProtocol(_protocol):
                            if not self.module.check_mode:
                                fw_service_settings.removeProtocol(_protocol)
                            self.changed = True
                if helper_module:
                    for _module in helper_module:
                        if fw_service_settings.queryModule(_module):
                            if not self.module.check_mode:
                                fw_service_settings.removeModule(_module)
                            self.changed = True
                if destination_ipv4:
                    if fw_service_settings.queryDestination("ipv4", destination_ipv4):
                        if not self.module.check_mode:
                            fw_service_settings.removeDestination(
                                "ipv4", destination_ipv4
                            )
                        self.changed = True
                if destination_ipv6:
                    if fw_service_settings.queryDestination("ipv6", destination_ipv6):
                        if not self.module.check_mode:
                            fw_service_settings.removeDestination(
                                "ipv6", destination_ipv6
                            )
                        self.changed = True
                for _include in includes:
                    if fw_service_settings.queryInclude(_include):
                        if not self.module.check_mode:
                            fw_service_settings.removeInclude(_include)
                        self.changed = True
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
                    if not self.module.check_mode:
                        fw_service.remove()
                        service_exists = False
                    self.changed = True
            # If service operation occurs, this should be the only instruction executed by the script
            if self.changed and not self.module.check_mode:
                if service_exists:
                    fw_service.update(fw_service_settings)
                self.need_reload = True
        else:
            for item in service:
                service_exists = item in self.fw.config().getServiceNames()
                if self.state == "enabled" and service_exists:
                    if self.runtime and not self.fw.queryService(self.zone, item):
                        if not self.module.check_mode:
                            self.fw.addService(self.zone, item, self.timeout)
                        self.changed = True
                    if self.permanent and not self.fw_settings.queryService(item):
                        if not self.module.check_mode:
                            self.fw_settings.addService(item)
                        self.changed = True
                elif self.state == "disabled" and service_exists:
                    if self.runtime and self.fw.queryService(self.zone, item):
                        if not self.module.check_mode:
                            self.fw.removeService(self.zone, item)
                    if self.permanent and self.fw_settings.queryService(item):
                        if not self.module.check_mode:
                            self.fw_settings.removeService(item)
                        self.changed = True
                else:
                    if self.module.check_mode:
                        self.module.warn(
                            "Service does not exist - "
                            + item
                            + ". Ensure that you define the service in the playbook before running it in diff mode"
                        )
                    else:
                        self.module.fail_json(msg="INVALID SERVICE - " + item)

    def _create_ipset(self, ipset, ipset_type):
        if not ipset_type:
            self.module.fail_json(msg="ipset_type needed when creating a new ipset")

        fw_ipset = None
        fw_ipset_settings = FirewallClientIPSetSettings()
        fw_ipset_settings.setType(ipset_type)
        if not self.module.check_mode:
            self.fw.config().addIPSet(ipset, fw_ipset_settings)
            fw_ipset = self.fw.config().getIPSetByName(ipset)
            fw_ipset_settings = fw_ipset.getSettings()

        return fw_ipset, fw_ipset_settings

    def set_ipset(self, ipset, description, short, ipset_type, ipset_entries):
        ipset_exists = ipset in self.fw.config().getIPSetNames()
        fw_ipset = None
        fw_ipset_settings = None
        if ipset_exists:
            fw_ipset = self.fw.config().getIPSetByName(ipset)
            fw_ipset_settings = fw_ipset.getSettings()
            if ipset_type and ipset_type != fw_ipset_settings.getType():
                self.module.fail_json(
                    msg="Name conflict when creating ipset - "
                    "ipset %s of type %s already exists"
                    % (ipset, fw_ipset_settings.getType())
                )
        elif self.state == "present":
            fw_ipset, fw_ipset_settings = self._create_ipset(ipset, ipset_type)
            self.changed = True
            ipset_exists = True
        if self.state == "present":
            if (
                description is not None
                and description != fw_ipset_settings.getDescription()
            ):
                if not self.module.check_mode:
                    fw_ipset_settings.setDescription(description)
                self.changed = True
            if short is not None and short != fw_ipset_settings.getShort():
                if not self.module.check_mode:
                    fw_ipset_settings.setShort(short)
                self.changed = True
            for entry in ipset_entries:
                if not fw_ipset_settings.queryEntry(entry):
                    if not self.module.check_mode:
                        fw_ipset_settings.addEntry(entry)
                    self.changed = True
        elif ipset_exists:
            if ipset_entries:
                for entry in ipset_entries:
                    if fw_ipset_settings.queryEntry(entry):
                        if not self.module.check_mode:
                            fw_ipset_settings.removeEntry(entry)
                        self.changed = True
            else:
                ipset_source_name = "ipset:%s" % ipset
                bound_zone_permanent = self.fw.config().getZoneOfSource(
                    ipset_source_name
                )
                if bound_zone_permanent:
                    bound_zone_permanent = "permanent - %s" % bound_zone_permanent
                bound_zone_runtime = self.fw.getZoneOfSource(ipset_source_name)
                if bound_zone_runtime:
                    bound_zone_runtime = "runtime - %s" % bound_zone_runtime
                if bound_zone_permanent or bound_zone_runtime:
                    bound_zones = " | ".join(
                        [
                            i
                            for i in [bound_zone_permanent, bound_zone_runtime]
                            if i != ""
                        ]
                    )
                    if self.module.check_mode:
                        self.module.warn(
                            "Ensure %s is removed from all zones before attempting to remove it. Enabled zones: %s"
                            % (ipset_source_name, bound_zones)
                        )
                    else:
                        self.module.fail_json(
                            msg="Remove %s from all permanent and runtime zones before attempting to remove it"
                            % ipset_source_name
                        )
                elif ipset_exists:
                    if not self.module.check_mode:
                        fw_ipset.remove()
                        ipset_exists = False
                    self.changed = True

        if self.changed and not self.module.check_mode:
            if ipset_exists:
                fw_ipset.update(fw_ipset_settings)
            self.need_reload = True

    def set_port(self, port):
        for _port, _protocol in port:
            if self.state == "enabled":
                if self.runtime and not self.fw.queryPort(self.zone, _port, _protocol):
                    if not self.module.check_mode:
                        self.fw.addPort(self.zone, _port, _protocol, self.timeout)
                    self.changed = True
                if self.permanent and not self.fw_settings.queryPort(_port, _protocol):
                    if not self.module.check_mode:
                        self.fw_settings.addPort(_port, _protocol)
                    self.changed = True
            elif self.state == "disabled":
                if self.runtime and self.fw.queryPort(self.zone, _port, _protocol):
                    if not self.module.check_mode:
                        self.fw.removePort(self.zone, _port, _protocol)
                    self.changed = True
                if self.permanent and self.fw_settings.queryPort(_port, _protocol):
                    if not self.module.check_mode:
                        self.fw_settings.removePort(_port, _protocol)
                    self.changed = True

    def set_source_port(self, source_port):
        for _port, _protocol in source_port:
            if self.state == "enabled":
                if self.runtime and not self.fw.querySourcePort(
                    self.zone, _port, _protocol
                ):
                    if not self.module.check_mode:
                        self.fw.addSourcePort(self.zone, _port, _protocol, self.timeout)
                    self.changed = True
                if self.permanent and not self.fw_settings.querySourcePort(
                    _port, _protocol
                ):
                    if not self.module.check_mode:
                        self.fw_settings.addSourcePort(_port, _protocol)
                    self.changed = True
            elif self.state == "disabled":
                if self.runtime and self.fw.querySourcePort(
                    self.zone, _port, _protocol
                ):
                    if not self.module.check_mode:
                        self.fw.removeSourcePort(self.zone, _port, _protocol)
                    self.changed = True
                if self.permanent and self.fw_settings.querySourcePort(
                    _port, _protocol
                ):
                    if not self.module.check_mode:
                        self.fw_settings.removeSourcePort(_port, _protocol)
                    self.changed = True

    def set_forward_port(self, forward_port):
        for _port, _protocol, _to_port, _to_addr in forward_port:
            if self.state == "enabled":
                if self.runtime and not self.fw.queryForwardPort(
                    self.zone, _port, _protocol, _to_port, _to_addr
                ):
                    if not self.module.check_mode:
                        self.fw.addForwardPort(
                            self.zone,
                            _port,
                            _protocol,
                            _to_port,
                            _to_addr,
                            self.timeout,
                        )
                    self.changed = True
                if self.permanent and not self.fw_settings.queryForwardPort(
                    _port, _protocol, _to_port, _to_addr
                ):
                    if not self.module.check_mode:
                        self.fw_settings.addForwardPort(
                            _port, _protocol, _to_port, _to_addr
                        )
                    self.changed = True
            elif self.state == "disabled":
                if self.runtime and self.fw.queryForwardPort(
                    self.zone, _port, _protocol, _to_port, _to_addr
                ):
                    if not self.module.check_mode:
                        self.fw.removeForwardPort(
                            self.zone, _port, _protocol, _to_port, _to_addr
                        )
                    self.changed = True
                if self.permanent and self.fw_settings.queryForwardPort(
                    _port, _protocol, _to_port, _to_addr
                ):
                    if not self.module.check_mode:
                        self.fw_settings.removeForwardPort(
                            _port, _protocol, _to_port, _to_addr
                        )
                    self.changed = True

    def set_masquerade(self, masquerade):
        if masquerade:
            if self.runtime and not self.fw.queryMasquerade(self.zone):
                if not self.module.check_mode:
                    self.fw.addMasquerade(self.zone, self.timeout)
                self.changed = True
            if self.permanent and not self.fw_settings.queryMasquerade():
                if not self.module.check_mode:
                    self.fw_settings.addMasquerade()
                self.changed = True
        else:
            if self.runtime and self.fw.queryMasquerade(self.zone):
                if not self.module.check_mode:
                    self.fw.removeMasquerade(self.zone)
                self.changed = True
            if self.permanent and self.fw_settings.queryMasquerade():
                if not self.module.check_mode:
                    self.fw_settings.removeMasquerade()
                self.changed = True

    def set_rich_rule(self, rich_rule):
        for item in rich_rule:
            if self.state == "enabled":
                if self.runtime and not self.fw.queryRichRule(self.zone, item):
                    if not self.module.check_mode:
                        self.fw.addRichRule(self.zone, item, self.timeout)
                    self.changed = True
                if self.permanent and not self.fw_settings.queryRichRule(item):
                    if not self.module.check_mode:
                        self.fw_settings.addRichRule(item)
                    self.changed = True
            elif self.state == "disabled":
                if self.runtime and self.fw.queryRichRule(self.zone, item):
                    if not self.module.check_mode:
                        self.fw.removeRichRule(self.zone, item)
                    self.changed = True
                if self.permanent and self.fw_settings.queryRichRule(item):
                    if not self.module.check_mode:
                        self.fw_settings.removeRichRule(item)
                    self.changed = True

    def set_source(self, source):
        for item in source:
            # Error case handling for check mode
            if (
                self.module.check_mode
                and item.startswith("ipset:")
                and item.split(":")[1] not in self.fw.config().getIPSetNames()
            ):
                self.module.warn(
                    "%s does not exist - ensure it is defined in a previous task before running play outside check mode"
                    % item
                )
                self.changed = True
            elif self.state == "enabled":
                if self.runtime and not self.fw.querySource(self.zone, item):
                    if not self.module.check_mode:
                        self.fw.addSource(self.zone, item)
                    self.changed = True
                if self.permanent and not self.fw_settings.querySource(item):
                    if not self.module.check_mode:
                        self.fw_settings.addSource(item)
                    self.changed = True
            elif self.state == "disabled":
                if self.runtime and self.fw.querySource(self.zone, item):
                    if not self.module.check_mode:
                        self.fw.removeSource(self.zone, item)
                    self.changed = True
                if self.permanent and self.fw_settings.querySource(item):
                    if not self.module.check_mode:
                        self.fw_settings.removeSource(item)
                    self.changed = True

    def set_interface(self, interface):
        for item in interface:
            if self.state == "enabled":
                if self.runtime and not self.fw.queryInterface(self.zone, item):
                    if not self.module.check_mode:
                        self.fw.changeZoneOfInterface(self.zone, item)
                    self.changed = True
                if self.permanent:
                    nm_used, if_changed = try_set_zone_of_interface(
                        self.module, self.zone, item
                    )
                    if nm_used:
                        if if_changed:
                            self.changed = True
                    elif not self.fw_settings.queryInterface(item):
                        if not self.module.check_mode:
                            old_zone_name = self.fw.config().getZoneOfInterface(item)
                            if old_zone_name != self.zone:
                                if old_zone_name:
                                    old_zone_obj = self.fw.config().getZoneByName(
                                        old_zone_name
                                    )
                                    old_zone_settings = old_zone_obj.getSettings()
                                    old_zone_settings.removeInterface(item)
                                    old_zone_obj.update(old_zone_settings)
                                self.fw_settings.addInterface(item)
                        self.changed = True
            elif self.state == "disabled":
                if self.runtime and self.fw.queryInterface(self.zone, item):
                    if not self.module.check_mode:
                        self.fw.removeInterface(self.zone, item)
                    self.changed = True
                if self.permanent:
                    nm_used, if_changed = try_set_zone_of_interface(
                        self.module, "", item
                    )
                    if nm_used:
                        if if_changed:
                            self.changed = True
                    elif self.fw_settings.queryInterface(item):
                        if not self.module.check_mode:
                            self.fw_settings.removeInterface(item)
                        self.changed = True

    def set_icmp_block(self, icmp_block):
        for item in icmp_block:
            if self.state == "enabled":
                if self.runtime and not self.fw.queryIcmpBlock(self.zone, item):
                    if not self.module.check_mode:
                        self.fw.addIcmpBlock(self.zone, item, self.timeout)
                    self.changed = True
                if self.permanent and not self.fw_settings.queryIcmpBlock(item):
                    if not self.module.check_mode:
                        self.fw_settings.addIcmpBlock(item)
                    self.changed = True
            elif self.state == "disabled":
                if self.runtime and self.fw.queryIcmpBlock(self.zone, item):
                    if not self.module.check_mode:
                        self.fw.removeIcmpBlock(self.zone, item)
                    self.changed = True
                if self.permanent and self.fw_settings.queryIcmpBlock(item):
                    if not self.module.check_mode:
                        self.fw_settings.removeIcmpBlock(item)
                    self.changed = True

    def set_icmp_block_inversion(self, icmp_block_inversion):
        if icmp_block_inversion:
            if self.runtime and not self.fw.queryIcmpBlockInversion(self.zone):
                if not self.module.check_mode:
                    self.fw.addIcmpBlockInversion(self.zone)
                self.changed = True
            if self.permanent and not self.fw_settings.queryIcmpBlockInversion():
                if not self.module.check_mode:
                    self.fw_settings.addIcmpBlockInversion()
                self.changed = True
        else:
            if self.runtime and self.fw.queryIcmpBlockInversion(self.zone):
                if not self.module.check_mode:
                    self.fw.removeIcmpBlockInversion(self.zone)
                self.changed = True
            if self.permanent and self.fw_settings.queryIcmpBlockInversion():
                if not self.module.check_mode:
                    self.fw_settings.removeIcmpBlockInversion()
                self.changed = True

    def set_target(self, target):
        if self.state in ["enabled", "present"]:
            if self.permanent and self.fw_settings.getTarget() != target:
                if not self.module.check_mode:
                    self.fw_settings.setTarget(target)
                    self.need_reload = True
                self.changed = True
        elif self.state in ["absent", "disabled"]:
            target = "default"
            if self.permanent and self.fw_settings.getTarget() != target:
                if not self.module.check_mode:
                    self.fw_settings.setTarget(target)
                    self.need_reload = True
                self.changed = True


class OfflineCLIBackend:
    """Implement operations with firewall-offline-cmd.

    This works during container builds and similar environments.
    """

    def __init__(
        self, module, permanent, runtime, zone_operation, zone, state, timeout
    ):
        self.module = module
        self.state = state
        self.timeout = timeout

        self.changed = False

        if not permanent or runtime:
            module.fail_json(
                msg="runtime mode is not supported in offline environments"
            )

        # Get zone to operate on
        if zone is None:
            self.zone = self.cmd("--get-default-zone")
            self.zone_exists = True
        else:
            self.zone = zone
            zones = self.cmd("--get-zones").split()
            self.zone_exists = zone in zones

        if not self.zone_exists and not zone_operation:
            module.fail_json(msg="Zone '%s' does not exist." % zone)

    def _call_offline_cmd(self, args, check_rc=True):
        argv = ["firewall-offline-cmd"] + list(args)
        (rc, out, err) = self.module.run_command(argv, check_rc=check_rc)
        out = out.strip()
        self.module.debug("OfflineCLIBackend: %r -> exit %i, out: %s" % (argv, rc, out))
        return (rc, out)

    def cmd(self, *args):
        """Call firewall-offline-cmd with given arguments, expecting success."""

        return self._call_offline_cmd(args)[1]

    def change(self, *args):
        """Like cmd(), but skipped in check_mode.

        Also set self.changed.
        """
        if not self.module.check_mode:
            self.cmd(*args)
        self.changed = True

    def query(self, *args):
        """Call firewall-offline-cmd query command, convert exit code to bool."""

        rc = self._call_offline_cmd(args, check_rc=False)[0]
        return True if rc == 0 else False

    def finalize(self):
        # nothing to do here, all changes are written immediately in offline mode
        pass

    def check_state(self, allowed, option):
        """Check and interpret self.state

        allowed is a list of allowed values. E.g. most operations only accept
        enabled/disabled, while others only accept present/absent, some accept
        either. This keeps the behaviour bug-for-bug compatible with
        OnlineAPIBackend.

        Return True for enabled/present or False for disabled/absent.
        """
        if self.state not in allowed:
            self.module.fail_json(
                msg="state '%s' not accepted for option '%s'" % (self.state, option)
            )

        return self.state in ["enabled", "present"]

    def set_firewalld_conf(self, firewalld_conf, allow_zone_drifting_deprecated):
        if allow_zone_drifting_deprecated:
            # compatibility with OnlineAPIBackend: allow_zone_drifting gets
            # ignored when deprecated, without failing the role
            other_keys = set(firewalld_conf.keys()) - set(["allow_zone_drifting"])
            if len(other_keys) == 0:
                # parser in main() already wrote a warning
                return

        # there are currently no other supported options in firewalld_conf, so
        # this should not happen; if it ever does, implement it
        self.module.fail_json(
            msg="firewalld_conf is not currently supported in offline mode; please file a bug"
        )

    def set_zone(self):
        create = self.check_state(["present", "absent"], "zone")
        if create != self.zone_exists:
            self.change(
                "--%s-zone=%s" % ("new" if create else "delete", self.zone),
            )
        if not create and self.zone_exists:
            self.zone = None
            self.zone_exists = False

    def set_default_zone(self, zone):
        if self.cmd("--get-default-zone") != zone:
            self.change("--set-default-zone", zone)

    def set_service(
        self,
        service_operation,
        service,
        description,
        short,
        port,
        protocol,
        source_port,
        helper_module,
        destination_ipv4,
        destination_ipv6,
        includes,
    ):
        if service_operation:
            present = self.check_state(["present", "absent"], "service")
            known_services = self.cmd("--get-services").split()
            service_exists = service in known_services

            if present:
                if not service_exists:
                    self.change("--new-service", service)

                existing_description = self.cmd(
                    "--service", service, "--get-description"
                )
                if description is not None and description != existing_description:
                    self.change("--service", service, "--set-description", description)

                existing_short = self.cmd("--service", service, "--get-short")
                if short is not None and short != existing_short:
                    self.change("--service", service, "--set-short", short)

                for _port, _protocol in port:
                    spec = "%s/%s" % (_port, _protocol)
                    if not self.query("--service", service, "--query-port=" + spec):
                        self.change("--service", service, "--add-port=" + spec)

                for _protocol in protocol:
                    if not self.query(
                        "--service", service, "--query-protocol=" + _protocol
                    ):
                        self.change("--service", service, "--add-protocol=" + _protocol)

                for _port, _protocol in source_port:
                    spec = "%s/%s" % (_port, _protocol)
                    if not self.query(
                        "--service", service, "--query-source-port=" + spec
                    ):
                        self.change("--service", service, "--add-source-port=" + spec)

                for _module in helper_module:
                    if not self.query(
                        "--service", service, "--query-helper=" + _module
                    ):
                        self.change("--service", service, "--add-helper=" + _module)

                if destination_ipv4 and not self.query(
                    "--service",
                    service,
                    "--query-destination=ipv4:" + destination_ipv4,
                ):
                    self.change(
                        "--service",
                        service,
                        "--set-destination=ipv4:" + destination_ipv4,
                    )

                if destination_ipv6 and not self.query(
                    "--service",
                    service,
                    "--query-destination=ipv6:" + destination_ipv6,
                ):
                    self.change(
                        "--service",
                        service,
                        "--set-destination=ipv6:" + destination_ipv6,
                    )

                for _include in includes:
                    if not self.query(
                        "--service", service, "--query-include=" + _include
                    ):
                        self.change("--service", service, "--add-include=" + _include)

            if not present and service_exists:
                if port:
                    for _port, _protocol in port:
                        spec = "%s/%s" % (_port, _protocol)
                        if self.query("--service", service, "--query-port=" + spec):
                            self.change("--service", service, "--remove-port=" + spec)
                if source_port:
                    for _port, _protocol in source_port:
                        spec = "%s/%s" % (_port, _protocol)
                        if self.query(
                            "--service", service, "--query-source-port=" + spec
                        ):
                            self.change(
                                "--service", service, "--remove-source-port=" + spec
                            )
                if protocol:
                    for _protocol in protocol:
                        if self.query(
                            "--service", service, "--query-protocol=" + _protocol
                        ):
                            self.change(
                                "--service", service, "--remove-protocol=" + _protocol
                            )

                if helper_module:
                    for _module in helper_module:
                        if self.query(
                            "--service", service, "--query-helper=" + _module
                        ):
                            self.change(
                                "--service", service, "--remove-helper=" + _module
                            )

                if destination_ipv4 and self.query(
                    "--service",
                    service,
                    "--query-destination=ipv4:" + destination_ipv4,
                ):
                    # asymmetric, but correct: no IP value here, just the protocol version
                    self.change("--service", service, "--remove-destination=ipv4")

                if destination_ipv6 and self.query(
                    "--service",
                    service,
                    "--query-destination=ipv6:" + destination_ipv6,
                ):
                    self.change("--service", service, "--remove-destination=ipv6")

                for _include in includes:
                    if self.query("--service", service, "--query-include=" + _include):
                        self.change(
                            "--service", service, "--remove-include=" + _include
                        )

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
                    self.change("--delete-service", service)

        # not service_operation: add/remove service from zone
        else:
            known_services = self.cmd("--get-services").split()
            enable = self.check_state(["enabled", "disabled"], "service")
            for item in service:
                if item not in known_services:
                    if self.module.check_mode:
                        self.module.warn(
                            "Service does not exist - "
                            + item
                            + ". Ensure that you define the service in the playbook before running it in diff mode"
                        )
                        continue
                    else:
                        self.module.fail_json(msg="INVALID SERVICE - " + item)

                cur = self.query("--zone", self.zone, "--query-service=" + item)

                if cur != enable:
                    op = "--add-service=" if enable else "--remove-service-from-zone="
                    self.change("--zone", self.zone, op + item)

    def set_ipset(self, ipset, description, short, ipset_type, ipset_entries):
        present = self.check_state(["present", "absent"], "ipset")
        known_ipsets = self.cmd("--get-ipsets").split()
        ipset_exists = ipset in known_ipsets

        if ipset_exists and ipset_type:
            m = re.search(r"\stype: (.*)$", self.cmd("--info-ipset", ipset), re.M)
            if not m:
                self.module.fail_json(
                    "'firewall-offline-cmd --info-ipset %s' did not print 'type:'"
                    % ipset
                )
            existing_type = m.group(1)
            if ipset_type != existing_type:
                self.module.fail_json(
                    msg="Name conflict when creating ipset - "
                    "ipset %s of type %s already exists" % (ipset, existing_type)
                )

        if present:
            if not ipset_exists:
                if not ipset_type:
                    self.module.fail_json(
                        msg="ipset_type needed when creating a new ipset"
                    )
                self.change("--new-ipset", ipset, "--type=%s" % ipset_type)

            existing_description = self.cmd("--ipset", ipset, "--get-description")
            if description is not None and description != existing_description:
                self.change("--ipset", ipset, "--set-description", description)

            existing_short = self.cmd("--ipset", ipset, "--get-short")
            if short is not None and short != existing_short:
                self.change("--ipset", ipset, "--set-short", short)
            for entry in ipset_entries:
                if not self.query("--ipset", ipset, "--query-entry", entry):
                    self.change("--ipset", ipset, "--add-entry", entry)

        # remove
        elif ipset_exists:
            if ipset_entries:
                for entry in ipset_entries:
                    if self.query("--ipset", ipset, "--query-entry", entry):
                        self.change("--ipset", ipset, "--remove-entry", entry)
            else:
                rc, bound_zone = self._call_offline_cmd(
                    ["--get-zone-of-source=ipset:" + ipset], check_rc=False
                )
                if rc == 0:
                    if self.module.check_mode:
                        self.module.warn(
                            "Ensure ipset:%s is removed from zone %s before attempting to remove it"
                            % (ipset, bound_zone)
                        )
                    else:
                        self.module.fail_json(
                            msg="Remove ipset:%s from all zones before attempting to remove it"
                            % ipset
                        )

                self.change("--delete-ipset", ipset)

    def set_port(self, port):
        enable = self.check_state(["enabled", "disabled"], "port")
        for _port, _protocol in port:
            spec = "%s/%s" % (_port, _protocol)
            cur = self.query("--zone", self.zone, "--query-port=" + spec)

            if cur != enable:
                self.change(
                    "--zone",
                    self.zone,
                    "--%s-port=%s" % ("add" if enable else "remove", spec),
                )

    def set_source_port(self, source_port):
        enable = self.check_state(["enabled", "disabled"], "source_port")
        for _port, _protocol in source_port:
            spec = "%s/%s" % (_port, _protocol)
            cur = self.query("--zone", self.zone, "--query-source-port=" + spec)

            if cur != enable:
                self.change(
                    "--zone",
                    self.zone,
                    "--%s-source-port=%s" % ("add" if enable else "remove", spec),
                )

    def set_forward_port(self, forward_port):
        enable = self.check_state(["enabled", "disabled"], "forward_port")
        for _port, _protocol, _to_port, _to_addr in forward_port:
            spec = "port=%s:proto=%s" % (_port, _protocol)
            if _to_port is not None:
                spec += ":toport=%s" % _to_port
            if _to_addr is not None:
                spec += ":toaddr=%s" % _to_addr

            cur = self.query("--zone", self.zone, "--query-forward-port=" + spec)

            if cur != enable:
                self.change(
                    "--zone",
                    self.zone,
                    "--%s-forward-port=%s" % ("add" if enable else "remove", spec),
                )

    def set_masquerade(self, masquerade):
        cur = self.query("--zone", self.zone, "--query-masquerade")

        if cur != masquerade:
            self.change(
                "--zone",
                self.zone,
                "--%s-masquerade" % ("add" if masquerade else "remove"),
            )

    def set_rich_rule(self, rich_rule):
        enable = self.check_state(["enabled", "disabled"], "rich_rule")

        for item in rich_rule:
            # note: item is a Rich_Rule object, but its __str__() does the right thing
            cur = self.query("--zone", self.zone, "--query-rich-rule=" + item)

            if cur != enable:
                self.change(
                    "--zone",
                    self.zone,
                    "--%s-rich-rule=%s" % ("add" if enable else "remove", item),
                )

    def set_source(self, source):
        if self.module.check_mode:
            ipset_names = self.cmd("--get-ipsets").split()

        enable = self.check_state(["enabled", "disabled"], "source")

        for item in source:
            # Error case handling for check mode
            if (
                self.module.check_mode
                and item.startswith("ipset:")
                and item.split(":")[1] not in ipset_names
            ):
                self.module.warn(
                    "%s does not exist - ensure it is defined in a previous task before running play outside check mode"
                    % item
                )
                self.changed = True
            else:
                cur = self.query("--zone", self.zone, "--query-source=" + item)

                if cur != enable:
                    self.change(
                        "--zone",
                        self.zone,
                        "--%s-source=%s" % ("add" if enable else "remove", item),
                    )

    def set_interface(self, interface):
        # we can't do this via NM like in OnlineAPIBackend, always go via firewalld config
        enable = self.check_state(["enabled", "disabled"], "interface")

        for item in interface:
            cur = self.query("--zone", self.zone, "--query-interface=" + item)
            if cur != enable:
                self.change(
                    "--zone",
                    self.zone,
                    # note: --change-interface first removes it from the old zone
                    "--%s-interface=%s" % ("change" if enable else "remove", item),
                )

    def set_icmp_block(self, icmp_block):
        enable = self.check_state(["enabled", "disabled"], "icmp_block")

        for item in icmp_block:
            cur = self.query("--zone", self.zone, "--query-icmp-block=" + item)

            if cur != enable:
                self.change(
                    "--zone",
                    self.zone,
                    "--%s-icmp-block=%s" % ("add" if enable else "remove", item),
                )

    def set_icmp_block_inversion(self, icmp_block_inversion):
        cur = self.query("--zone", self.zone, "--query-icmp-block-inversion")

        if cur != icmp_block_inversion:
            self.change(
                "--zone",
                self.zone,
                "--%s-icmp-block-inversion"
                % ("add" if icmp_block_inversion else "remove"),
            )

    def set_target(self, target):
        enable = self.check_state(
            ["enabled", "present", "disabled", "absent"], "target"
        )
        cur_target = self.cmd("--zone", self.zone, "--get-target")
        new_target = target if enable else "default"

        if new_target != cur_target:
            self.change("--zone", self.zone, "--set-target", new_target)


PCI_REGEX = re.compile("[0-9a-fA-F]{4}:[0-9a-fA-F]{4}")


# NOTE: Because of PEP632, we cannot use distutils.
# In addition, because of the wide range of python
# versions we have to support, there isn't a good
# version parser across all of them, that is provided
# with Ansible.
def lsr_parse_version(v_str):
    v_ary = v_str.split(".")
    v = []
    for v_ary_str in v_ary:
        try:
            v.append(int(v_ary_str))
        except ValueError:
            v.append(0)
    return v


pci_ids = None


def get_interface_pci():
    pci_dict = {}
    for interface in nm_get_interfaces():
        # udi/device/[vendor, device]
        interface_ids = []
        device_udi = nm_get_client().get_device_by_iface(interface).get_udi()
        device_path = os.path.join(device_udi, "device")
        for field in ["vendor", "device"]:
            with open(os.path.join(device_path, field)) as _file:
                interface_ids.append(_file.readline().strip(" \n")[2:])
        interface_ids = ":".join(interface_ids)
        if interface_ids not in pci_dict:
            pci_dict[interface_ids] = [interface]
        else:
            pci_dict[interface_ids].append(interface)
    return pci_dict


def parse_pci_id(module, item):
    if not module.params["online"]:
        module.fail_json(msg="interface_pci_id is not supported in offline mode.")

    if PCI_REGEX.search(item):
        global pci_ids
        if not pci_ids:
            pci_ids = get_interface_pci()

        interface_name = pci_ids.get(item)
        if interface_name:
            return interface_name

        module.warn(msg="No network interfaces found with PCI device ID %s" % item)
    else:
        module.fail_json(
            msg="PCI id %s does not match format: XXXX:XXXX (X = hexadecimal number)"
            % item
        )
    return []


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


def check_allow_zone_drifting(firewalld_conf):
    if firewalld_conf["allow_zone_drifting"] is not None:
        if firewalld_conf["allow_zone_drifting"]:
            firewalld_conf["allow_zone_drifting"] = "yes"
        else:
            firewalld_conf["allow_zone_drifting"] = "no"


# Parse all suboptions of firewalld_conf into how they will be used by the role
# Return True if all suboptions were emptied as a result
def check_firewalld_conf(firewalld_conf):
    check_allow_zone_drifting(firewalld_conf)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            firewalld_conf=dict(
                required=False,
                type="dict",
                options=dict(
                    allow_zone_drifting=dict(required=False, type="bool", default=None),
                ),
                default=None,
            ),
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
            interface_pci_id=dict(
                required=False, type="list", elements="str", default=[]
            ),
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
            ipset=dict(required=False, type="str", default=None),
            ipset_type=dict(required=False, type="str", default=None),
            ipset_entries=dict(required=False, type="list", elements="str", default=[]),
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
            includes=dict(required=False, type="list", elements="str", default=[]),
            __report_changed=dict(required=False, type="bool", default=True),
            online=dict(required=False, type="bool", default=True),
        ),
        supports_check_mode=True,
        required_if=(
            ("state", "present", ("zone", "target", "service"), True),
            ("state", "absent", ("zone", "target", "service"), True),
        ),
    )

    if not HAS_FIREWALLD:
        module.fail_json(msg="No firewall backend could be imported.")

    # Argument parse
    firewalld_conf = module.params["firewalld_conf"]
    if firewalld_conf:
        check_firewalld_conf(firewalld_conf)
        allow_zone_drifting_deprecated = lsr_parse_version(
            FW_VERSION
        ) >= lsr_parse_version("1.0.0")
        if allow_zone_drifting_deprecated and firewalld_conf.get("allow_zone_drifting"):
            module.warn(
                "AllowZoneDrifting is deprecated in this version of firewalld and no longer supported"
            )
    else:
        # CodeQL will produce an error without this line
        allow_zone_drifting_deprecated = None
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
    for _interface in module.params["interface_pci_id"]:
        for interface_name in parse_pci_id(module, _interface):
            if interface_name not in interface:
                interface.append(interface_name)
    icmp_block = module.params["icmp_block"]
    icmp_block_inversion = module.params["icmp_block_inversion"]
    timeout = module.params["timeout"]
    target = module.params["target"]
    zone = module.params["zone"]
    set_default_zone = module.params["set_default_zone"]
    ipset = module.params["ipset"]
    ipset_type = module.params["ipset_type"]
    ipset_entries = module.params["ipset_entries"]
    permanent = module.params["permanent"]
    runtime = module.params["runtime"]
    state = module.params["state"]
    includes = module.params["includes"]
    online = module.params["online"]

    # All options that require state to be set
    state_required = any(
        (
            interface,
            source,
            service,
            ipset,
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
                firewalld_conf,
                ipset,
            )
        )
    ):
        module.fail_json(
            msg="One of service, port, source_port, forward_port, "
            "masquerade, rich_rule, source, interface, icmp_block, "
            "icmp_block_inversion, target, zone, set_default_zone, "
            "ipset or firewalld_conf needs to be set"
        )

    # Checking for any permanent configuration operations
    zone_operation = False
    service_operation = False
    ipset_operation = False
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

        # Zone, service, and ipset are incompatible with one another when state is set to present or absent
        num_conflicting_args = len([x for x in [zone, ipset, service] if x])
        if num_conflicting_args > 1:
            module.fail_json(
                msg="%s of {zone, service, ipset} while state present/absent, expected 1"
                % num_conflicting_args
            )
        del num_conflicting_args

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
                    ipset_entries,
                    ipset_type,
                )
            ):
                module.fail_json(
                    msg="short, description, port, source_port, helper_module, "
                    "protocol, destination, ipset_type or ipset_entries cannot be set "
                    "while zone is specified "
                    "and state is set to present or absent"
                )
            else:
                zone_operation = True

        elif state == "absent" and any(
            (
                short,
                description,
                ipset_type,
            )
        ):
            module.fail_json(
                msg="short, description and ipset_type can only be used when "
                "state is present"
            )
        elif service:
            if target is not None:
                module.fail_json(
                    msg="Both service and target cannot be set "
                    "while state is either present or absent"
                )
            elif not permanent:
                module.fail_json(
                    msg="permanent must be enabled for service configuration. "
                    "Additionally, service runtime configuration is not possible"
                )
            elif ipset_entries or ipset_type:
                module.fail_json(
                    msg="ipset parameters cannot be set when configuring services"
                )
            else:
                service_operation = True
        elif ipset:
            if target is not None:
                module.fail_json(msg="Only one of {ipset, target} can be set")
            elif not permanent:
                module.fail_json(
                    msg="permanent must be enabled for ipset configuration"
                )
            else:
                ipset_operation = True

    if service_operation:
        if len(service) != 1:
            module.fail_json(
                msg="can only add, modify, or remove one service at a time"
            )
        else:
            service = service[0]
    # firewalld.conf checks

    if firewalld_conf and not permanent:
        module.fail_json(msg="firewalld_conf can only be used with permanent")

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

    # Pre-run version checking
    if lsr_parse_version(FW_VERSION) < lsr_parse_version("0.2.11"):
        module.fail_json(
            msg="Unsupported firewalld version %s, requires >= 0.2.11" % FW_VERSION
        )

    backendClass = OnlineAPIBackend if online else OfflineCLIBackend
    backend = backendClass(
        module, permanent, runtime, zone_operation, zone, state, timeout
    )

    # Firewall modification starts here

    if firewalld_conf:
        backend.set_firewalld_conf(firewalld_conf, allow_zone_drifting_deprecated)
    if zone_operation:
        backend.set_zone()
    if set_default_zone:
        backend.set_default_zone(set_default_zone)
    if service:
        backend.set_service(
            service_operation,
            service,
            description,
            short,
            port,
            protocol,
            source_port,
            helper_module,
            destination_ipv4,
            destination_ipv6,
            includes,
        )
    if ipset_operation:
        backend.set_ipset(ipset, description, short, ipset_type, ipset_entries)
    if port and not service_operation:
        backend.set_port(port)
    if source_port and not service_operation:
        backend.set_source_port(source_port)
    if forward_port:
        backend.set_forward_port(forward_port)
    if masquerade is not None:
        backend.set_masquerade(masquerade)
    if rich_rule:
        backend.set_rich_rule(rich_rule)
    if source:
        backend.set_source(source)
    if interface:
        backend.set_interface(interface)
    if icmp_block:
        backend.set_icmp_block(icmp_block)
    if icmp_block_inversion is not None:
        backend.set_icmp_block_inversion(icmp_block_inversion)
    if target is not None:
        backend.set_target(target)

    backend.finalize()

    changed = backend.changed and module.params["__report_changed"]
    module.exit_json(changed=changed, __firewall_changed=changed)


#################################################

if __name__ == "__main__":
    main()
