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

from __future__ import absolute_import, division, print_function, unicode_literals

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
      Must be compatible with the ipset type of the `ipset`
      being created or modified.
      Will only do something when set with ipset.
    required: false
    type: list
    elements: str
    default: []
  ipset_options:
    description:
      Dict of key/value pairs of ipset options for the given ipset.
      Will only do something when set with ipset.
    required: false
    type: dict
    default: {}
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
  previous:
    description:
      The previous state of the firewall configuration.
      The value "replaced" means that the entire firewall configuration will be replaced with the new configuration.
    required: false
    type: str
    choices: ["replaced", "kept"]
    default: "kept"
  includes:
    description:
      Services to include in this one.
    required: false
    type: list
    elements: str
    default: []
  online:
    description:
      When true, use the D-Bus API to query the status from the running system.
      Otherwise, use firewall-offline-cmd(1). Offline mode is
      incompatible with "runtime" mode.
    type: bool
    required: false
    default: true
  __called_from_role:
    description:
      If true, the module is being called from the role.
    type: bool
    required: false
    default: false
  config_list:
    description:
      List of firewall configurations to apply.
      Each item in the list is a dictionary containing any of the module's
      parameters (except config_list itself).
      This allows applying multiple firewall configurations in a single
      module call. Cannot be used together with other module parameters.
    type: list
    elements: dict
    required: false
    default: []
    suboptions:
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
          Must be compatible with the ipset type of the `ipset`
          being created or modified.
          Will only do something when set with ipset.
        required: false
        type: list
        elements: str
        default: []
      ipset_options:
        description:
          Dict of key/value pairs of ipset options for the given ipset.
          Will only do something when set with ipset.
        required: false
        type: dict
        default: {}
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
          List of protocols supported by managed system.
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
      previous:
        description:
          The previous state of the firewall configuration.
          The value "replaced" means that the entire firewall configuration will be replaced with the new configuration.
        required: false
        type: str
        choices: ["replaced", "kept"]
        default: "kept"
      includes:
        description:
          Services to include in this one.
        required: false
        type: list
        elements: str
        default: []
"""

EXAMPLES = """
# Single configuration (current method)
- name: Configure firewall ports
  firewall_lib:
    - port: ['443/tcp', '443/udp']

# Multiple configurations using config_list (new method)
- name: Configure firewall ports again with config_list
  firewall_lib:
    config_list:
      - port: ['80/tcp']
        state: enabled
        permanent: true
      - service: ['ssh']
        state: enabled
        permanent: true
      - port: ['8080/tcp']
        zone: public
        state: enabled
        runtime: true

# Each dict in config_list can contain any parameters that the module supports
- name: Configure firewall with config_list again
  firewall_lib:
    config_list:
      - zone: public
        target: ACCEPT
        state: present
        permanent: true
      - service: ['http', 'https']
        zone: public
        state: enabled
        permanent: true
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.firewall_lsr.get_config import (
    config_to_dict,
    export_config_dict,
    recursive_show_diffs,
)
from ansible.module_utils.six import string_types
import re
import os
import copy

try:
    import ipaddress

    HAS_IPADDRESS = True
except ImportError:
    HAS_IPADDRESS = False

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
    from firewall.core.io.firewalld_conf import firewalld_conf
    from firewall.core.io.zone import Zone
    from firewall.core.io.service import Service
    from firewall.core.io.ipset import IPSet

    FIREWALLD_DIR = firewall.config.ETC_FIREWALLD

    HAS_FIREWALLD = True
except ImportError:
    FIREWALLD_DIR = "/etc/firewalld"
    HAS_FIREWALLD = False

try:
    if HAS_FIREWALLD:
        firewall.config.FIREWALLD_POLICIES

    HAS_POLICIES = True
except AttributeError:
    HAS_POLICIES = False

try:
    from firewall.functions import check_mac

    HAS_CHECK_MAC = True
except ImportError:
    HAS_CHECK_MAC = False

    def check_mac(mac):
        return False


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


# The argument to ip_interface must be a unicode string
# Must be "cast" in python2, python3 does not need this
def ip_interface(entry, module):
    try:
        entry_str = unicode(entry)
    except NameError:  # unicode is not defined in python3
        entry_str = entry
    try:
        return ipaddress.ip_interface(entry_str)
    except ValueError:
        module.fail_json(msg="Invalid IP address - " + entry)
        return None


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


# Check that all of the ipset entries are ipv4, ipv6, or mac addresses
# if not, fail the module
# if they are, return "ipv4", "ipv6", or "mac"
def get_ipset_entries_type(ipset_entries, module):
    addr_type = None
    is_mixed_addr_types = False
    for entry in ipset_entries:
        if check_mac(entry):
            if addr_type is None:
                addr_type = "mac"
            elif addr_type != "mac":
                is_mixed_addr_types = True
        else:
            if HAS_IPADDRESS:
                addr = ip_interface(entry, module)
                # ip_interface will fail the module if the address is invalid
                if addr is None:
                    continue
            else:
                module.fail_json(msg="No IP address library found")
                continue
            if addr.version == 4:
                if addr_type is None:
                    addr_type = "ipv4"
                elif addr_type != "ipv4":
                    is_mixed_addr_types = True
            elif addr.version == 6:
                if addr_type is None:
                    addr_type = "ipv6"
                elif addr_type != "ipv6":
                    is_mixed_addr_types = True
            else:
                module.fail_json(msg="Invalid IP address - " + entry)
    if is_mixed_addr_types:
        module.fail_json(
            msg="Address types cannot be mixed in ipset entries - " + str(ipset_entries)
        )
    return addr_type


# ipset options values must be strings
def normalize_ipset_options(ipset_options):
    for option, value in ipset_options.items():
        if value is not None and not isinstance(value, string_types):
            ipset_options[option] = str(value)


def check_and_normalize_ipset(module, ipset, ipset_entries, ipset_options):
    addr_type = get_ipset_entries_type(ipset_entries, module)
    if addr_type is None and ipset_entries:
        module.fail_json(
            msg="ipset %s: Invalid IP address - %s " % (ipset, str(ipset_entries))
        )
    copy_ipset_options = copy.deepcopy(ipset_options)
    normalize_ipset_options(copy_ipset_options)
    if addr_type == "ipv6" and "family" not in ipset_options:
        copy_ipset_options["family"] = "inet6"
    if addr_type == "ipv4" and copy_ipset_options.get("family") == "inet6":
        module.fail_json(
            msg="ipset %s: family=inet6 is not supported for IPv4 ipset_entries %s"
            % (ipset, ", ".join(ipset_entries))
        )
    if addr_type == "ipv6" and copy_ipset_options.get("family") == "inet":
        module.fail_json(
            msg="ipset %s: family=inet is not supported for IPv6 ipset_entries %s"
            % (ipset, ", ".join(ipset_entries))
        )
    return copy_ipset_options


# Above: adapted from firewall-cmd source code
class OnlineAPIBackend:
    """Implement operations with the FirewallClient() API.

    This requires firewalld to be running.
    """

    def __init__(self, module, permanent, runtime, zone, state, timeout):
        self.module = module
        self.state = state
        self.permanent = permanent
        self.runtime = runtime
        self.zone = zone
        self.timeout = timeout
        self.set_interface_changed = False

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
        if permanent:
            zone_exists = (
                zone_exists or zone is None or zone in self.fw.config().getZoneNames()
            )

        if zone_exists:
            self.zone = self.zone or self.fw.getDefaultZone()
            self.fw_zone = self.fw.config().getZoneByName(self.zone)
            self.fw_settings = self.fw_zone.getSettings()
        else:
            self.fw_zone = None
            self.fw_settings = None
            zone_exists = False

        self.zone_exists = zone_exists

    def check_zone_exists(self):
        return self.zone_exists

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
                    if hasattr(fw_service_settings, "queryHelper"):
                        if not fw_service_settings.queryHelper(_module):
                            if not self.module.check_mode:
                                fw_service_settings.addHelper(_module)
                            self.changed = True
                    elif not fw_service_settings.queryModule(_module):
                        if not self.module.check_mode:
                            fw_service_settings.addModule(_module)
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
                for _port, _protocol in port:
                    if fw_service_settings.queryPort(_port, _protocol):
                        if not self.module.check_mode:
                            fw_service_settings.removePort(_port, _protocol)
                        self.changed = True
                for _port, _protocol in source_port:
                    if fw_service_settings.querySourcePort(_port, _protocol):
                        if not self.module.check_mode:
                            fw_service_settings.removeSourcePort(_port, _protocol)
                        self.changed = True
                for _protocol in protocol:
                    if fw_service_settings.queryProtocol(_protocol):
                        if not self.module.check_mode:
                            fw_service_settings.removeProtocol(_protocol)
                        self.changed = True
                for _module in helper_module:
                    if hasattr(fw_service_settings, "queryHelper"):
                        if fw_service_settings.queryHelper(_module):
                            if not self.module.check_mode:
                                fw_service_settings.removeHelper(_module)
                            self.changed = True
                    elif fw_service_settings.queryModule(_module):
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

    def set_ipset(
        self, ipset, description, short, ipset_type, ipset_entries, ipset_options
    ):
        ipset_options = check_and_normalize_ipset(
            self.module, ipset, ipset_entries, ipset_options
        )
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
            for option, value in ipset_options.items():
                if value is None:
                    continue
                current_options = fw_ipset_settings.getOptions()
                if option in current_options:
                    if current_options[option] != value:
                        if not self.module.check_mode:
                            fw_ipset_settings.removeOption(option)
                            fw_ipset_settings.addOption(option, value)
                        self.changed = True
                else:
                    if not self.module.check_mode:
                        fw_ipset_settings.addOption(option, value)
                    self.changed = True
        elif ipset_exists:
            if ipset_entries or ipset_options:
                for entry in ipset_entries:
                    if fw_ipset_settings.queryEntry(entry):
                        if not self.module.check_mode:
                            fw_ipset_settings.removeEntry(entry)
                        self.changed = True
                for option, value in ipset_options.items():
                    current_options = fw_ipset_settings.getOptions()
                    if (value is None and option in current_options) or (
                        value is not None and current_options[option] == value
                    ):
                        if not self.module.check_mode:
                            fw_ipset_settings.removeOption(option)
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
                    self.set_interface_changed = True
                if self.permanent:
                    nm_used, if_changed = try_set_zone_of_interface(
                        self.module, self.zone, item
                    )
                    if nm_used:
                        if if_changed:
                            self.changed = True
                            self.set_interface_changed = True
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
                        self.set_interface_changed = True
            elif self.state == "disabled":
                if self.runtime and self.fw.queryInterface(self.zone, item):
                    if not self.module.check_mode:
                        self.fw.removeInterface(self.zone, item)
                    self.changed = True
                    self.set_interface_changed = True
                if self.permanent:
                    nm_used, if_changed = try_set_zone_of_interface(
                        self.module, "", item
                    )
                    if nm_used:
                        if if_changed:
                            self.changed = True
                            self.set_interface_changed = True
                    elif self.fw_settings.queryInterface(item):
                        if not self.module.check_mode:
                            self.fw_settings.removeInterface(item)
                        self.changed = True
                        self.set_interface_changed = True

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


class InMemoryBackend:
    """Implement operations using in-memory configuration.

    This backend reads the existing configuration into memory and applies
    changes to the in-memory representation. It can return both the original
    and modified configurations for comparison or deferred application.
    """

    def __init__(
        self,
        module,
        online,
        start_empty=False,
    ):
        self.module = module
        self.online = online
        self.state = None
        self.permanent = None
        self.runtime = None
        self.zone = None
        self.timeout = None
        self.changed = False
        self.set_interface_changed = False

        # Load the current configuration
        self.original_config = config_to_dict(module, detailed=True, online=online)
        self.firewalld_conf = copy.deepcopy(
            self.original_config.get("firewalld_conf", {})
        )

        self.working_config_runtime = {}
        if start_empty:
            # start with the built-in default settings
            self.default_zone = self.original_config.get(
                "fallback_default_zone", "public"
            )
            self.working_config_permanent = copy.deepcopy(
                self.original_config["default"]
            )
            if self.online:
                self.working_config_runtime = copy.deepcopy(
                    self.original_config["default"]
                )
                self._move_interfaces_to_default_zone(
                    self.original_config["custom_runtime_with_defaults"]
                )
        else:
            # start with the current permanent and runtime settings
            self.default_zone = self.original_config.get("default_zone", "public")
            self.working_config_permanent = copy.deepcopy(
                self.original_config["custom_permanent_with_defaults"]
            )
            if self.online:
                self.working_config_runtime = copy.deepcopy(
                    self.original_config["custom_runtime_with_defaults"]
                )
        self.original_default_zone = self.default_zone

    def check_zone_exists(self):
        self.zone_exists = False
        # Check in permanent config first
        if self.permanent and self.zone in self.working_config_permanent.get(
            "zones", {}
        ):
            self.zone_exists = True
        if (
            self.online
            and not self.zone_exists
            and self.runtime
            and self.zone in self.working_config_runtime.get("zones", {})
        ):
            self.zone_exists = True
        return self.zone_exists

    def _ensure_zone_in_working_config(self, create_if_not_exists):
        """Ensure the zone exists in working config with all necessary keys."""

        for flag, working_config in [
            (self.permanent, self.working_config_permanent),
            (self.online and self.runtime, self.working_config_runtime),
        ]:
            if flag:
                if self.zone not in working_config["zones"] and create_if_not_exists:
                    # Create new zone with empty settings
                    working_config["zones"][self.zone] = {}
                else:
                    raise ValueError("Zone '%s' does not exist" % self.zone)

    def _get_zone_config(self, config_type="permanent"):
        """Get the configuration for the current zone.

        Args:
            config_type: Either "permanent" or "runtime"
        """
        if config_type == "permanent":
            config = self.working_config_permanent
        elif self.online:
            config = self.working_config_runtime
        else:
            return None
        return config["zones"].get(self.zone, None)

    def finalize(self):
        """No-op for in-memory backend."""
        pass

    def get_configs(self):
        """Return both original and working configurations.

        Returns:
            tuple: (original_config, working_config_permanent, working_config_runtime, default_zone, firewalld_conf)

        """
        return (
            self.original_config,
            self.working_config_permanent,
            self.working_config_runtime,
            self.default_zone,
            self.firewalld_conf,
        )

    def set_firewalld_conf(self, firewalld_conf, allow_zone_drifting_deprecated):
        """Set firewalld.conf options."""
        # Store firewalld_conf settings in permanent config only
        # (firewalld.conf is a permanent configuration file)
        if (
            not allow_zone_drifting_deprecated
            and "allow_zone_drifting" in firewalld_conf
            and firewalld_conf.get("allow_zone_drifting")
            != self.firewalld_conf.get("allow_zone_drifting")
        ):
            self.firewalld_conf["allow_zone_drifting"] = firewalld_conf.get(
                "allow_zone_drifting"
            )
            self.changed = True

    def _new_zone(self):
        if HAS_FIREWALLD:
            return export_config_dict(Zone())
        else:
            return {}

    def set_zone(self):
        """Create or remove a zone."""
        # A zone must be present or absent in both permanent and runtime configurations
        if (
            self.state == "present"
            and self.zone not in self.working_config_permanent["zones"]
        ):
            self.working_config_permanent["zones"][self.zone] = self._new_zone()
            if self.online:
                self.working_config_runtime["zones"][self.zone] = self._new_zone()
            self.changed = True
        elif (
            self.state == "absent"
            and self.zone in self.working_config_permanent["zones"]
        ):
            del self.working_config_permanent["zones"][self.zone]
            if self.online:
                del self.working_config_runtime["zones"][self.zone]
            self.changed = True
            # removing a zone online requires a reload - if you remove the default zone, it
            # is set back to the original
            if self.default_zone == self.zone:
                self.default_zone = self.original_default_zone
                self.zone = self.default_zone

    def _move_interfaces_to_default_zone(self, working_config_runtime=None):
        if self.online:
            if not working_config_runtime:
                src = self.working_config_runtime
                dest = self.working_config_runtime
            else:
                src = working_config_runtime
                dest = self.working_config_runtime
            for zone_name, zone_config in src.get("zones", {}).items():
                if (
                    src is not dest or zone_name != self.default_zone
                ) and "interfaces" in zone_config:
                    for interface in zone_config["interfaces"]:
                        if interface not in dest["zones"][self.default_zone].get(
                            "interfaces", []
                        ):
                            dest["zones"][self.default_zone].setdefault(
                                "interfaces", []
                            ).append(interface)
                    if src is dest:
                        del zone_config["interfaces"]

    def set_default_zone(self, zone):
        """Set the default zone."""
        # Default zone applies to both permanent and runtime configurations
        if self.default_zone != zone:
            self.default_zone = zone
            self.changed = True
            # move all of the runtime interfaces to the new default zone
            self._move_interfaces_to_default_zone()

    def get_default_zone(self):
        """Get the default zone."""
        return self.default_zone

    def _new_service(self):
        if HAS_FIREWALLD:
            return export_config_dict(Service())
        else:
            return {}

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
        """Configure services."""
        if service_operation and self.permanent:
            working_configs = [self.working_config_permanent]
            if self.online:
                working_configs.append(self.working_config_runtime)
            for working_config in working_configs:
                if self.state == "present":
                    if "services" not in working_config:
                        working_config["services"] = {}

                    if service not in working_config["services"]:
                        working_config["services"][service] = self._new_service()
                        self.changed = True

                    svc = working_config["services"][service]

                    if (
                        description is not None
                        and svc.get("description") != description
                    ):
                        svc["description"] = description
                        self.changed = True

                    if short is not None and svc.get("short") != short:
                        svc["short"] = short
                        self.changed = True

                    for port_tuple in port:
                        if port_tuple not in svc.get("ports", []):
                            svc.setdefault("ports", []).append(port_tuple)
                            self.changed = True

                    for _protocol in protocol:
                        if _protocol not in svc.get("protocols", []):
                            svc.setdefault("protocols", []).append(_protocol)
                            self.changed = True

                    for port_tuple in source_port:
                        if port_tuple not in svc.get("source_ports", []):
                            svc.setdefault("source_ports", []).append(port_tuple)
                            self.changed = True

                    for _module in helper_module:
                        if _module not in svc.get("helpers", []):
                            svc.setdefault("helpers", []).append(_module)
                            self.changed = True

                    if destination_ipv4:
                        if svc.get("destination", {}).get("ipv4") != destination_ipv4:
                            svc.setdefault("destination", {})["ipv4"] = destination_ipv4
                            self.changed = True

                    if destination_ipv6:
                        if svc.get("destination", {}).get("ipv6") != destination_ipv6:
                            svc.setdefault("destination", {})["ipv6"] = destination_ipv6
                            self.changed = True

                    for _include in includes:
                        if _include not in svc.get("includes", []):
                            svc.setdefault("includes", []).append(_include)
                            self.changed = True

                elif self.state == "absent" and service in working_config.get(
                    "services", {}
                ):
                    if any(
                        (
                            port,
                            source_port,
                            protocol,
                            helper_module,
                            destination_ipv4,
                            destination_ipv6,
                            includes,
                        )
                    ):
                        # Remove specific items
                        svc = working_config["services"][service]
                        for port_tuple in port:
                            if port_tuple in svc.get("ports", []):
                                svc["ports"].remove(port_tuple)
                                self.changed = True
                        if "ports" in svc and not svc["ports"]:
                            del svc["ports"]

                        for _protocol in protocol:
                            if _protocol in svc.get("protocols", []):
                                svc["protocols"].remove(_protocol)
                                self.changed = True
                        if "protocols" in svc and not svc["protocols"]:
                            del svc["protocols"]

                        for port_tuple in source_port:
                            if port_tuple in svc.get("source_ports", []):
                                svc["source_ports"].remove(port_tuple)
                                self.changed = True
                        if "source_ports" in svc and not svc["source_ports"]:
                            del svc["source_ports"]

                        for _module in helper_module:
                            if _module in svc.get("helpers", []):
                                svc["helpers"].remove(_module)
                                self.changed = True
                        if "helpers" in svc and not svc["helpers"]:
                            del svc["helpers"]

                        if (
                            destination_ipv4
                            and svc.get("destination", {}).get("ipv4")
                            == destination_ipv4
                        ):
                            del svc["destination"]["ipv4"]
                            self.changed = True

                        if (
                            destination_ipv6
                            and svc.get("destination", {}).get("ipv6")
                            == destination_ipv6
                        ):
                            del svc["destination"]["ipv6"]
                            self.changed = True

                        if "destination" in svc and not svc["destination"]:
                            del svc["destination"]

                        for _include in includes:
                            if _include in svc.get("includes", []):
                                svc["includes"].remove(_include)
                                self.changed = True
                        if "includes" in svc and not svc["includes"]:
                            del svc["includes"]
                    else:
                        # Remove entire service
                        del working_config["services"][service]
                        self.changed = True
        else:
            # Zone service operation - applies to both permanent and runtime
            for config_type, zone_config in (
                (self.permanent, self._get_zone_config("permanent")),
                (self.online and self.runtime, self._get_zone_config("runtime")),
            ):
                if config_type and zone_config is not None:
                    for item in service:
                        service_exists = item in self.working_config_permanent.get(
                            "services", {}
                        ) or (
                            self.online
                            and item in self.working_config_runtime.get("services", {})
                        )
                        if service_exists and self.state == "enabled":
                            if item not in zone_config.get("services", []):
                                zone_config.setdefault("services", []).append(item)
                                self.changed = True
                        elif service_exists and self.state == "disabled":
                            if item in zone_config.get("services", []):
                                zone_config["services"].remove(item)
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

    def _new_ipset(self, ipset_type):
        new_ipset = {}
        if HAS_FIREWALLD:
            new_ipset = export_config_dict(IPSet())
        new_ipset["type"] = ipset_type
        return new_ipset

    def set_ipset(
        self, ipset, description, short, ipset_type, ipset_entries, ipset_options
    ):
        """Configure ipsets (permanent only)."""
        ipset_options = check_and_normalize_ipset(
            self.module, ipset, ipset_entries, ipset_options
        )
        existing_ipset = self.working_config_permanent.get("ipsets", {}).get(
            ipset,
            {},
        )

        if existing_ipset:
            if ipset_type and ipset_type != existing_ipset.get("type"):
                self.module.fail_json(
                    msg="Name conflict when creating ipset - "
                    "ipset %s of type %s already exists"
                    % (ipset, existing_ipset.get("type"))
                )

        # set ipset in permanent, and runtime if set
        for config_type, working_config in (
            (self.permanent, self.working_config_permanent),
            (self.online and self.runtime, self.working_config_runtime),
        ):
            if config_type and working_config is not None:
                if self.state == "present":
                    if not existing_ipset:
                        if "ipsets" not in working_config:
                            working_config["ipsets"] = {}
                        working_config["ipsets"][ipset] = self._new_ipset(ipset_type)
                        self.changed = True

                    ipset_cfg = working_config["ipsets"][ipset]

                    if (
                        description is not None
                        and ipset_cfg.get("description") != description
                    ):
                        ipset_cfg["description"] = description
                        self.changed = True

                    if short is not None and ipset_cfg.get("short") != short:
                        ipset_cfg["short"] = short
                        self.changed = True

                    for entry in ipset_entries:
                        if entry not in ipset_cfg.get("entries", []):
                            ipset_cfg.setdefault("entries", []).append(entry)
                            self.changed = True

                    for option, value in ipset_options.items():
                        if ipset_cfg.get("options", {}).get(option) != value:
                            ipset_cfg.setdefault("options", {})[option] = value
                            self.changed = True

                elif self.state == "absent" and existing_ipset:
                    if ipset_entries or ipset_options:
                        # Remove specific entries/options
                        ipset_cfg = working_config["ipsets"][ipset]
                        for entry in ipset_entries:
                            if entry in ipset_cfg.get("entries", []):
                                ipset_cfg["entries"].remove(entry)
                                self.changed = True
                    else:
                        # Remove entire ipset
                        del working_config["ipsets"][ipset]
                        # if no more ipsets, remove the top level
                        if not working_config["ipsets"]:
                            del working_config["ipsets"]
                        self.changed = True

    def _set_ports_or_source_ports(self, port, port_type):
        """Configure ports or source_ports in a zone."""
        for config_type, zone_config in (
            (self.permanent, self._get_zone_config("permanent")),
            (self.online and self.runtime, self._get_zone_config("runtime")),
        ):
            if config_type and zone_config is not None:
                for _port, _protocol in port:
                    # keep as tuple here
                    port_spec = (_port, _protocol)
                    if self.state == "enabled":
                        if port_spec not in zone_config.get(port_type, []):
                            zone_config.setdefault(port_type, []).append(port_spec)
                            self.changed = True
                    elif self.state == "disabled":
                        if port_spec in zone_config.get(port_type, []):
                            zone_config[port_type].remove(port_spec)
                            self.changed = True

    def set_port(self, port):
        """Configure ports in a zone."""
        self._set_ports_or_source_ports(port, "ports")

    def set_source_port(self, source_port):
        """Configure source ports in a zone."""
        self._set_ports_or_source_ports(source_port, "source_ports")

    def set_forward_port(self, forward_port):
        """Configure port forwarding in a zone."""
        for config_type, zone_config in (
            (self.permanent, self._get_zone_config("permanent")),
            (self.online and self.runtime, self._get_zone_config("runtime")),
        ):
            if config_type and zone_config is not None:
                for forward_port_item in forward_port:
                    if self.state == "enabled":
                        if forward_port_item not in zone_config.get(
                            "forward_ports", []
                        ):
                            zone_config.setdefault("forward_ports", []).append(
                                forward_port_item
                            )
                            self.changed = True
                    elif self.state == "disabled":
                        if forward_port_item in zone_config.get("forward_ports", []):
                            zone_config["forward_ports"].remove(forward_port_item)
                            self.changed = True

    def set_masquerade(self, masquerade):
        """Configure masquerading in a zone."""
        for config_type, zone_config in (
            (self.permanent, self._get_zone_config("permanent")),
            (self.online and self.runtime, self._get_zone_config("runtime")),
        ):
            if config_type and zone_config is not None:
                if zone_config.get("masquerade", False) != masquerade:
                    zone_config["masquerade"] = masquerade
                    self.changed = True

    def set_rich_rule(self, rich_rule):
        """Configure rich rules in a zone."""
        for config_type, zone_config in (
            (self.permanent, self._get_zone_config("permanent")),
            (self.online and self.runtime, self._get_zone_config("runtime")),
        ):
            if config_type and zone_config is not None:
                for item in rich_rule:
                    if self.state == "enabled":
                        if item not in zone_config.get("rich_rules", []):
                            zone_config.setdefault("rich_rules", []).append(item)
                            self.changed = True
                    elif self.state == "disabled":
                        if item in zone_config.get("rich_rules", []):
                            zone_config["rich_rules"].remove(item)
                            self.changed = True

    def set_source(self, source):
        """Configure sources in a zone."""
        for config_type, zone_config in (
            (self.permanent, self._get_zone_config("permanent")),
            (self.online and self.runtime, self._get_zone_config("runtime")),
        ):
            if config_type and zone_config is not None:
                for item in source:
                    if self.state == "enabled":
                        if item not in zone_config.get("sources", []):
                            zone_config.setdefault("sources", []).append(item)
                            self.changed = True
                    elif self.state == "disabled":
                        if item in zone_config.get("sources", []):
                            zone_config["sources"].remove(item)
                            self.changed = True

    def set_interface(self, interface):
        """Configure interfaces in a zone."""
        for config_type, zone_config in (
            (self.permanent, self._get_zone_config("permanent")),
            (self.online and self.runtime, self._get_zone_config("runtime")),
        ):
            if config_type and zone_config is not None:
                # we have no way to know if this will actually change the firewall configuration,
                # so set this flag here to let the real backend handle it even if there are
                # no other changes.
                self.set_interface_changed = True
                for item in interface:
                    if self.state == "enabled":
                        if item not in zone_config.get("interfaces", []):
                            zone_config.setdefault("interfaces", []).append(item)
                            self.changed = True
                    elif self.state == "disabled":
                        if item in zone_config.get("interfaces", []):
                            zone_config["interfaces"].remove(item)
                            self.changed = True

    def set_icmp_block(self, icmp_block):
        """Configure ICMP blocks in a zone."""
        for config_type, zone_config in (
            (self.permanent, self._get_zone_config("permanent")),
            (self.online and self.runtime, self._get_zone_config("runtime")),
        ):
            if config_type and zone_config is not None:
                for item in icmp_block:
                    if self.state == "enabled":
                        if item not in zone_config.get("icmp_blocks", []):
                            zone_config.setdefault("icmp_blocks", []).append(item)
                            self.changed = True
                    elif self.state == "disabled":
                        if item in zone_config.get("icmp_blocks", []):
                            zone_config["icmp_blocks"].remove(item)
                            self.changed = True

    def set_icmp_block_inversion(self, icmp_block_inversion):
        """Configure ICMP block inversion in a zone."""
        for config_type, zone_config in (
            (self.permanent, self._get_zone_config("permanent")),
            (self.online and self.runtime, self._get_zone_config("runtime")),
        ):
            if config_type and zone_config is not None:
                if (
                    zone_config.get("icmp_block_inversion", False)
                    != icmp_block_inversion
                ):
                    zone_config["icmp_block_inversion"] = icmp_block_inversion
                    self.changed = True

    def set_target(self, target):
        """Configure the target for a zone."""
        for config_type, zone_config in (
            (self.permanent, self._get_zone_config("permanent")),
            (self.online and self.runtime, self._get_zone_config("runtime")),
        ):
            if config_type and zone_config is not None:
                if self.state in ["enabled", "present"]:
                    if zone_config.get("target", "default") != target:
                        zone_config["target"] = target
                        self.changed = True
                elif self.state in ["absent", "disabled"]:
                    if zone_config.get("target", "default") != "default":
                        zone_config["target"] = "default"
                        self.changed = True


class OfflineCLIBackend:
    """Implement operations with firewall-offline-cmd.

    This works during container builds and similar environments.
    """

    def __init__(self, module, permanent, runtime, zone, state, timeout):
        self.module = module
        self.state = state
        self.timeout = timeout
        self.set_interface_changed = False

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

    def check_zone_exists(self):
        return self.zone_exists

    def _call_offline_cmd(self, args, check_rc=True):
        argv = ["firewall-offline-cmd"] + list(args)
        rc, out, err = self.module.run_command(argv, check_rc=check_rc)
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

    def set_ipset(
        self, ipset, description, short, ipset_type, ipset_entries, ipset_options
    ):
        addr_type = get_ipset_entries_type(ipset_entries, self.module)
        if addr_type is None and ipset_entries:
            self.module.fail_json(
                msg="ipset %s: Invalid IP address - %s" % (ipset, str(ipset_entries))
            )
        normalize_ipset_options(ipset_options)
        ipset_options_list = []
        if ipset_options:
            for kk, vv in ipset_options.items():
                ipset_options_list.append("--option")
                ipset_options_list.append(kk + "=" + str(vv))
        if addr_type == "ipv6" and "family=inet6" not in ipset_options_list:
            ipset_options_list.append("--option")
            ipset_options_list.append("family=inet6")
        if addr_type == "ipv4" and "family=inet6" in ipset_options_list:
            self.module.fail_json(
                msg="ipset %s: family=inet6 is not supported for IPv4 ipset_entries %s"
                % (ipset, ", ".join(ipset_entries))
            )
        if addr_type == "ipv6" and "family=inet" in ipset_options_list:
            self.module.fail_json(
                msg="ipset %s: family=inet is not supported for IPv6 ipset_entries %s"
                % (ipset, ", ".join(ipset_entries))
            )
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
                        msg="ipset %s: ipset_type needed when creating a new ipset"
                        % ipset
                    )
                self.change(
                    "--new-ipset", ipset, "--type=%s" % ipset_type, *ipset_options_list
                )

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
                self.set_interface_changed = True

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

    warning = ""
    if PCI_REGEX.search(item):
        if not NM_IMPORTED:
            module.fail_json(
                msg="interface_pci_id is only supported with NetworkManager.  If you want to use this feature, please install NetworkManager."
            )
        global pci_ids
        if not pci_ids:
            pci_ids = get_interface_pci()

        interface_names = pci_ids.get(item)
        if interface_names:
            return interface_names, warning

        warning = "No network interfaces found with PCI device ID %s" % item
        if callable(getattr(module, "warn", None)):
            module.warn(warning)
            warning = ""
    else:
        module.fail_json(
            msg="PCI id %s does not match format: XXXX:XXXX (X = hexadecimal number)"
            % item
        )
    return [], warning


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

    _port = None
    _protocol = None
    _to_port = None
    _to_addr = None
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
    elif isinstance(item, string_types):
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
    if isinstance(firewalld_conf["allow_zone_drifting"], bool):
        if firewalld_conf["allow_zone_drifting"]:
            firewalld_conf["allow_zone_drifting"] = "yes"
        else:
            firewalld_conf["allow_zone_drifting"] = "no"


# Parse all suboptions of firewalld_conf into how they will be used by the role
# Return True if all suboptions were emptied as a result
def check_firewalld_conf(firewalld_conf):
    check_allow_zone_drifting(firewalld_conf)


def get_base_argument_spec():
    """Return the base argument spec for firewall configuration parameters."""
    return dict(
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
        interface_pci_id=dict(required=False, type="list", elements="str", default=[]),
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
        ipset_options=dict(required=False, type="dict", default={}),
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
        previous=dict(required=False, choices=["replaced", "kept"], default="kept"),
    )


def get_full_argument_spec():
    full_spec = get_base_argument_spec()
    full_spec.update(
        dict(
            online=dict(required=False, type="bool", default=True),
            __called_from_role=dict(required=False, type="bool", default=False),
        )
    )
    return full_spec


def process_single_config(
    module,
    warnings,
    config_params=None,
    backend=None,
    online_param=None,
    __called_from_role_param=None,
):
    """
    Process a single configuration, either from module.params or from a config dict.

    Args:
        module: The Ansible module object
        config_params: Optional config dict to use instead of module.params
        backend: Optional backend object to use instead of creating a new one

    Returns a tuple of (backend, changed) or None if no action needed.
    """
    # Use config_params if provided, otherwise use module.params
    if config_params is None:
        params = module.params
    else:
        # Merge config_params with defaults from base argument spec
        params = {}
        base_spec = get_base_argument_spec()
        for key, spec in base_spec.items():
            params[key] = config_params.get(key, spec.get("default"))

    # Argument parse
    firewalld_conf = params["firewalld_conf"]
    if firewalld_conf:
        check_firewalld_conf(firewalld_conf)
        allow_zone_drifting_deprecated = lsr_parse_version(
            FW_VERSION
        ) >= lsr_parse_version("1.0.0")
        if allow_zone_drifting_deprecated and firewalld_conf.get("allow_zone_drifting"):
            if callable(getattr(module, "warn", None)):
                module.warn(
                    "AllowZoneDrifting is deprecated in this version of firewalld and no longer supported"
                )
            else:
                warnings.append(
                    "AllowZoneDrifting is deprecated in this version of firewalld and no longer supported"
                )
    else:
        # CodeQL will produce an error without this line
        allow_zone_drifting_deprecated = None
    service = params["service"]
    short = params["short"]
    description = params["description"]
    protocol = params["protocol"]
    helper_module = []
    for _module in params["helper_module"]:
        helper_module.append(parse_helper_module(module, _module))
    port = []
    for port_proto in params["port"]:
        port.append(parse_port(module, port_proto))
    source_port = []
    for port_proto in params["source_port"]:
        source_port.append(parse_port(module, port_proto))
    forward_port = []
    # Simulate get_forward_port for config_params
    if config_params is None:
        forward_port_items = get_forward_port(module)
    else:
        forward_port_raw = params["forward_port"]
        if isinstance(forward_port_raw, list):
            forward_port_items = forward_port_raw
        else:
            forward_port_items = [forward_port_raw] if forward_port_raw else []
    for item in forward_port_items:
        forward_port.append(parse_forward_port(module, item))
    masquerade = params["masquerade"]
    rich_rule = []
    for item in params["rich_rule"]:
        try:
            rule = str(Rich_Rule(rule_str=item))
            rich_rule.append(rule)
        except Exception as e:
            module.fail_json(msg="Rich Rule '%s' is not valid: %s" % (item, str(e)))
    source = params["source"]
    destination_ipv4 = None
    destination_ipv6 = None
    for address in params["destination"]:
        ip_type = parse_destination_address(module, address)
        if ip_type == "ipv4" and not destination_ipv4:
            destination_ipv4 = address
        elif destination_ipv4 and ip_type == "ipv4":
            module.fail_json(msg="cannot have more than one destination ipv4")
        if ip_type == "ipv6" and not destination_ipv6:
            destination_ipv6 = address
        elif destination_ipv6 and ip_type == "ipv6":
            module.fail_json(msg="cannot have more than one destination ipv6")
    interface = params["interface"]
    for _interface in params["interface_pci_id"]:
        interface_names, warning = parse_pci_id(module, _interface)
        for interface_name in interface_names:
            if interface_name not in interface:
                interface.append(interface_name)
        if warning:
            warnings.append(warning)
    icmp_block = params["icmp_block"]
    icmp_block_inversion = params["icmp_block_inversion"]
    timeout = params["timeout"]
    target = params["target"]
    zone = params["zone"]
    set_default_zone = params["set_default_zone"]
    ipset = params["ipset"]
    ipset_type = params["ipset_type"]
    ipset_entries = params["ipset_entries"]
    ipset_options = params["ipset_options"]
    permanent = params["permanent"]
    runtime = params["runtime"]
    state = params["state"]
    includes = params["includes"]
    if online_param is None:
        online = params["online"]
    else:
        online = online_param
    if __called_from_role_param is None:
        __called_from_role = params["__called_from_role"]
    else:
        __called_from_role = __called_from_role_param

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
    # NOTE: The old implementation of this role would always set permanent to True if it was not set,
    # and would set runtime to True if it was not set when called from the role.
    # so replicate that behavior here in order to maintain backwards compatibility in the module
    # in case someone is erroneously using the module directly
    if __called_from_role:
        if permanent is None:
            permanent = True
        if runtime is None:
            runtime = online
    else:
        if permanent is None:
            runtime = True
    if not any((permanent, runtime)):
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
        # Skip this config if no actionable parameters are set
        if config_params is not None:
            return None
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
                    ipset_options,
                )
            ):
                module.fail_json(
                    msg="short, description, port, source_port, helper_module, "
                    "protocol, destination, ipset_type, ipset_entries, or ipset_options cannot be set "
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
            elif ipset_entries or ipset_type or ipset_options:
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

    # Use provided backend or create a new one
    if backend is None:
        backendClass = OnlineAPIBackend if online else OfflineCLIBackend
        backend = backendClass(module, permanent, runtime, zone, state, timeout)
    else:
        # Update backend state for this config
        backend.state = state
        backend.permanent = permanent
        backend.runtime = runtime
        backend.zone = zone or backend.get_default_zone()
        backend.timeout = timeout

    # error out if the zone does not exist and this is not a zone operation
    if not zone_operation and not backend.check_zone_exists():
        module.fail_json(msg="Zone '%s' does not exist." % backend.zone)

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
        backend.set_ipset(
            ipset, description, short, ipset_type, ipset_entries, ipset_options
        )
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
    return backend.changed


def configs_are_equivalent(config1, config2):
    """
    Compare two firewall configurations for equivalence.
    Returns True if they represent the same firewall state.
    """

    # Create normalized copies
    def normalize_config(cfg):
        """Normalize a config dict for comparison."""
        normalized = copy.deepcopy(cfg)

        # Normalize custom section
        custom = normalized.get("custom", {})

        # Sort all list values for consistent comparison
        for zone_name, zone_cfg in custom.get("zones", {}).items():
            for key in [
                "services",
                "ports",
                "source_ports",
                "sources",
                "interfaces",
                "icmp_blocks",
                "rich_rules",
                "protocols",
            ]:
                if key in zone_cfg:
                    zone_cfg[key] = sorted(zone_cfg[key])

        return normalized

    norm1 = normalize_config(config1)
    norm2 = normalize_config(config2)

    # Compare custom sections (the parts users can modify)
    return norm1.get("custom") == norm2.get("custom")


def get_diffs(
    original_permanent,
    original_runtime,
    original_default_zone,
    original_firewalld_conf,
    current_permanent,
    current_runtime,
    current_default_zone,
    current_firewalld_conf,
    ignore_interface,
):
    diff = {}
    diff["permanent_diff"] = recursive_show_diffs(
        original_permanent, current_permanent, None, ignore_interface=ignore_interface
    )
    if original_runtime and current_runtime:
        diff["runtime_diff"] = recursive_show_diffs(
            original_runtime, current_runtime, None, ignore_interface=ignore_interface
        )
    else:
        diff["runtime_diff"] = {}
    if original_default_zone != current_default_zone:
        diff["before_default_zone"] = original_default_zone
        diff["after_default_zone"] = current_default_zone
    if (
        original_firewalld_conf
        and current_firewalld_conf
        and original_firewalld_conf.get("allow_zone_drifting")
        != current_firewalld_conf.get("allow_zone_drifting")
    ):
        diff["before_allow_zone_drifting"] = original_firewalld_conf.get(
            "allow_zone_drifting"
        )
        diff["after_allow_zone_drifting"] = current_firewalld_conf.get(
            "allow_zone_drifting"
        )
    return diff


def check_for_diffs(
    module,
    warnings,
    config_list,
    replaced,
    online_param=None,
    __called_from_role_param=None,
):
    """
    Process config_list with in-memory backend to check for differences.

    This creates a firewall config from scratch and compares it with the
    current config.

    The diff is a dict suitable to display in diff mode.

    custom_file_list is a list of xml files to be removed when
    replaced is true.

    Returns: (changed, diff, custom_file_list)
    """
    # Build the desired config using InMemoryBackend with empty starting config
    # We need to process all configs to build the complete desired state
    online = online_param
    backend = InMemoryBackend(module, online, start_empty=replaced)

    # Build desired config with InMemoryBackend
    for config in config_list:
        # Create a temporary module params dict for this config
        temp_params = copy.deepcopy(module.params)
        base_spec = get_base_argument_spec()
        for key, spec in base_spec.items():
            temp_params[key] = config.get(key, spec.get("default"))

        # Extract necessary parameters and set in backend for this config item
        backend.permanent = temp_params.get("permanent")
        backend.runtime = temp_params.get("runtime")
        backend.zone = temp_params.get("zone")
        backend.state = temp_params.get("state")
        backend.timeout = temp_params.get("timeout", 0)

        # Apply this configuration to the backend
        # Pass the backend to process_single_config
        process_single_config(
            module,
            warnings,
            config_params=config,
            backend=backend,
            online_param=online,
            __called_from_role_param=__called_from_role_param,
        )

    # Get the original and desired configs
    original_config, permanent_config, runtime_config, default_zone, firewalld_conf = (
        backend.get_configs()
    )

    custom_permanent_with_defaults = original_config.get(
        "custom_permanent_with_defaults", {}
    )
    diff = get_diffs(
        original_config["custom_permanent_with_defaults"],
        original_config.get("custom_runtime_with_defaults", {}),
        original_config["default_zone"],
        original_config["firewalld_conf"],
        permanent_config,
        runtime_config,
        default_zone,
        firewalld_conf,
        True,
    )
    changed = any(
        (
            diff["permanent_diff"],
            diff["runtime_diff"],
            diff.get("before_default_zone", False),
            diff.get("before_allow_zone_drifting", False),
        )
    )

    need_remove_custom_files = False
    # I have seen cases where there are files in /etc/firewalld for custom permanent config, but
    # the config is exactly the same as the default - this causes problems because it appears there
    # is custom permanent config, but it isn't different - not sure how this happens - I have seen
    # it in machine image builds, as if someone copied files from /usr/lib/firewalld
    # into /etc/firewalld but didn't change them - the problem is that this causes the tools to
    # report custom config where there isn't any actual customization or changes from the defaults
    if replaced and (changed or custom_permanent_with_defaults):
        default_diffs = {}
        if custom_permanent_with_defaults:
            # are the custom permanent settings the same as the defaults?
            default_diffs = recursive_show_diffs(
                custom_permanent_with_defaults, original_config.get("default", {}), None
            )
        need_remove_custom_files = changed or not default_diffs
    return (
        changed,
        diff,
        need_remove_custom_files,
        original_config,
        backend.set_interface_changed,
    )


def process_replaced_config(
    module,
    changed,
    need_remove_custom_files,
    online,
):
    # Remove existing firewalld configuration files
    if not module.check_mode and (changed or need_remove_custom_files):
        # Remove firewalld.conf
        firewalld_conf_path = os.path.join(FIREWALLD_DIR, "firewalld.conf")
        if changed and os.path.exists(firewalld_conf_path):
            try:
                os.remove(firewalld_conf_path)
                module.debug("Removed %s" % firewalld_conf_path)
                # ensure that firewalld.conf exists
                fc = firewalld_conf(None)
                try:
                    fc.read()
                except Exception:
                    pass  # the None causes an exception in read(), but this populates the fallback configuration
                fc.filename = firewalld_conf_path
                fc.write()
                module.debug("Wrote fallback configuration to %s" % firewalld_conf_path)
            except Exception as e:
                module.fail_json(
                    msg="Failed to remove %s: %s" % (firewalld_conf_path, str(e))
                )

        # remove custom files even if nothing else has changed in order to clean up cases
        # where there is a custom file which is exactly the same as a default file e.g.
        # someone copied public.xml from /usr/lib/firewalld/zones to /etc/firewalld/zones
        # and did not change it - it messes up the fact gathering because it is reported
        # as a customization but it really isn't - in this case we report changed: false
        # because the configuration didn't really change
        if changed or need_remove_custom_files:
            for root, dirs, files in os.walk(FIREWALLD_DIR):
                for filename in files:
                    if filename.endswith(".xml"):
                        xml_file = os.path.join(root, filename)
                        if os.path.exists(xml_file):
                            try:
                                os.remove(xml_file)
                                module.debug("Removed %s" % xml_file)
                            except Exception as e:
                                module.warn(
                                    "Failed to remove %s: %s" % (xml_file, str(e))
                                )

        if online:
            # Use FirewallClient to reload
            try:
                fw = FirewallClient()
                fw.reload()
                module.debug("Reloaded firewalld via FirewallClient")
            except Exception as e:
                module.fail_json(msg="Failed to reload firewalld: %s" % str(e))
        else:
            # Use firewall-offline-cmd (no reload needed in offline mode)
            module.debug("Offline mode - no reload needed")


def main():
    # Create the base argument spec
    argument_spec = get_full_argument_spec()

    # Add config_list parameter
    argument_spec["config_list"] = dict(
        required=False,
        type="list",
        elements="dict",
        options=get_base_argument_spec(),
        default=[],
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=(
            ("state", "present", ("zone", "target", "service"), True),
            ("state", "absent", ("zone", "target", "service"), True),
        ),
    )

    if not HAS_FIREWALLD:
        module.fail_json(msg="No firewall backend could be imported.")

    config_list = module.params["config_list"]
    online = module.params["online"]
    __called_from_role = module.params["__called_from_role"]
    diff = {}
    warnings = []
    # Check for mutual exclusivity between config_list and other parameters
    if config_list:
        # Check if any non-config_list parameters are set (except online)
        base_params = get_base_argument_spec()
        current_params_set = []
        for param_name, param_spec in base_params.items():
            if param_name in ["online", "__called_from_role"]:
                continue
            param_value = module.params[param_name]
            default_value = param_spec.get("default")
            if param_value != default_value:
                current_params_set.append(param_name)

        if current_params_set:
            module.fail_json(
                msg="config_list cannot be used together with other module parameters. "
                "Found these parameters set: %s" % ", ".join(current_params_set)
            )

        # Pre-scan config_list for previous="replaced"
        has_replaced = any(
            config.get("previous") == "replaced" for config in config_list
        )

        # Filter out all items with previous (keep items WITHOUT previous)
        filtered_config_list = [
            config for config in config_list if config.get("previous") != "replaced"
        ]

        # Validate all configs
        for i, config in enumerate(filtered_config_list):
            if not isinstance(config, dict):
                module.fail_json(
                    msg="config_list item %d must be a dictionary, got %s"
                    % (i, type(config).__name__)
                )

            # Validate config parameters against argument spec
            for key in config:
                if key not in base_params:
                    module.fail_json(
                        msg="config_list item %d contains invalid parameter '%s'. "
                        "Valid parameters: %s" % (i, key, ", ".join(base_params.keys()))
                    )

        (
            changed,
            diff,
            need_remove_custom_files,
            original_config,
            set_interface_changed,
        ) = check_for_diffs(
            module,
            warnings,
            filtered_config_list,
            has_replaced,
            online_param=online,
            __called_from_role_param=__called_from_role,
        )
        # NOTE: This means using previous: replaced with an interface change will not be
        # completely idempotent because we have to remove the files and reload firewalld in order to see
        # if the interface changes will actually change anything.
        if has_replaced and (
            changed or need_remove_custom_files or set_interface_changed
        ):
            # This handles removing the files that need to be removed and reloading firewalld if necessary
            process_replaced_config(
                module,
                changed,
                need_remove_custom_files or set_interface_changed,
                online,
            )

        if module.check_mode or (not changed and not set_interface_changed):
            # Exit early because either check_mode is True and we don't want to apply changes,
            # or no changes were made and no interfaces were changed, so we don't need to process
            # any changes.
            changed = changed if module.check_mode else False
            module.exit_json(
                changed=changed,
                __firewall_changed=changed,
                diff=diff,
                short_circuit=True,
            )

        # From here on, something has changed, and we need to process those changes
        # if set_interface_changed is True, we need to process the changes in order to see
        # if the interfaces have changed

        # Process each configuration in the list normally
        for config in filtered_config_list:
            # Process this configuration
            if process_single_config(
                module,
                warnings,
                config_params=config,
                online_param=online,
                __called_from_role_param=__called_from_role,
            ):
                # Something changed
                changed = True

        # get the current config after processing the changes, then compare it to the original config
        current_config = config_to_dict(module, detailed=True, online=online)
        diff = get_diffs(
            original_config["custom_permanent_with_defaults"],
            original_config.get("custom_runtime_with_defaults", {}),
            original_config["default_zone"],
            original_config["firewalld_conf"],
            current_config["custom_permanent_with_defaults"],
            current_config.get("custom_runtime_with_defaults", {}),
            current_config["default_zone"],
            current_config["firewalld_conf"],
            False,
        )
        if not changed:
            changed = any(
                (
                    diff["permanent_diff"],
                    diff["runtime_diff"],
                    diff.get("before_default_zone", False),
                    diff.get("before_allow_zone_drifting", False),
                )
            )
        module.exit_json(
            changed=changed,
            __firewall_changed=changed,
            diff=diff,
            short_circuit=False,
            warnings=warnings,
        )

    else:
        # Original single configuration mode
        changed = process_single_config(
            module,
            warnings,
            online_param=online,
            __called_from_role_param=__called_from_role,
        )
        module.exit_json(
            changed=changed,
            __firewall_changed=changed,
            short_circuit=False,
            warnings=warnings,
        )


#################################################

if __name__ == "__main__":
    main()
