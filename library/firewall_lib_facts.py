#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2016,2017,2020,2021 Red Hat, Inc.
# Reusing some firewalld code
# Authors:
# Brennan Paciorek <bpaciore@redhat.com>
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

DOCUMENTATION = """
module: firewall_lib_facts
short_description: module for firewall role
requirements:
  - python3-firewall or python-firewall
description:
  Get firewalld settings, including default settings
  and custom settings.
options:
  detailed:
    description:
      return more in-depth settings for default subdictionary of
      firewall_config. Matches the structure of the custom
      subdictionary if this is active.
    type: bool
    required: false
    default: false
author: Brennan Paciorek (@BrennanPaciorek)
"""

RETURN = """
changed:
  description:
    whether anything was changed, most likely false
  type: bool
  returned: always
  sample: False
firewall_config:
  description:
    firewall_config ansible fact,
    system role sets this output to the
    ansible fact named firewall_config
  type: dict
  returned: always
  sample: {
      "config": {
          "default": {},
          "custom": {},
      },
  }
"""

EXAMPLES = """
# Run with no parameters to gather facts
firewall_lib_facts:
"""


from ansible.module_utils.basic import AnsibleModule
import os

try:
    import firewall.config

    from firewall.client import FirewallClient

    HAS_FIREWALLD = True
except ImportError:
    HAS_FIREWALLD = False

try:
    if HAS_FIREWALLD:
        firewall.config.FIREWALLD_POLICIES

    HAS_POLICIES = True
except AttributeError:
    HAS_POLICIES = False


def config_to_dict(module):
    detailed = module.params.get("detailed", False)
    config = {}
    defaults = {}
    custom = {}
    setting_list = ["zones", "services", "icmptypes", "helpers", "ipsets"]

    if HAS_POLICIES:
        setting_list.append("policies")

    fw = FirewallClient()

    for setting in setting_list:
        default_setting_dir = os.path.join(firewall.config.USR_LIB_FIREWALLD, setting)
        custom_setting_dir = os.path.join(firewall.config.ETC_FIREWALLD, setting)

        settings = fetch_settings_from_dir(default_setting_dir, detailed, fw)
        if settings:
            defaults[setting] = settings
        settings = fetch_settings_from_dir(custom_setting_dir, True, fw)
        if settings:
            custom[setting] = settings

    if defaults:
        config["default"] = defaults
    if custom:
        config["custom"] = custom
    config["default_zone"] = fw.getDefaultZone()

    return config


def fetch_settings_from_dir(directory, detailed=False, fw=None):
    setting_options = [
        _file[:-4] for _file in os.listdir(directory) if _file.endswith(".xml")
    ]
    if not detailed:
        return setting_options
    else:
        setting_name = os.path.basename(directory)
        settings = {}
        for _item in setting_options:
            element_settings = {}
            if setting_name == "zones":
                element = fw.config().getZoneByName(_item).getSettings()
                try:
                    element_settings = element.getSettingsDict()
                except AttributeError:
                    element_settings["version"] = element.getVersion()
                    element_settings["short"] = element.getShort()
                    element_settings["description"] = element.getDescription()
                    element_settings["target"] = element.getTarget()
                    element_settings["services"] = element.getServices()
                    element_settings["ports"] = element.getPorts()
                    element_settings["icmp_blocks"] = element.getIcmpBlocks()
                    element_settings["masqerade"] = element.getMasquerade()
                    element_settings["forward_ports"] = element.getForwardPorts()
                    element_settings["interfaces"] = element.getInterfaces()
                    element_settings["sources"] = element.getSources()
                    element_settings["rules_str"] = element.getRichRules()
                    element_settings["protocols"] = element.getProtocols()
                    element_settings["source_ports"] = element.getSourcePorts()
                    element_settings["icmp_block_inversion"] = (
                        element.getIcmpBlockInversion()
                    )
            elif setting_name == "services":
                element = fw.config().getServiceByName(_item).getSettings()
                try:
                    element_settings = element.getSettingsDict()
                except AttributeError:
                    element_settings["version"] = element.getVersion()
                    element_settings["short"] = element.getShort()
                    element_settings["description"] = element.getDescription()
                    element_settings["protocols"] = element.getProtocols()
                    element_settings["source_ports"] = element.getSourcePorts()
                    element_settings["modules"] = element.getModules()
            elif setting_name == "icmptypes":
                element = fw.config().getIcmpTypeByName(_item).getSettings()
                element_settings["version"] = element.getVersion()
                element_settings["short"] = element.getShort()
                element_settings["description"] = element.getDescription()
                element_settings["destination"] = element.getDestinations()
            elif setting_name == "helpers":
                element = fw.config().getHelperByName(_item).getSettings()
                element_settings["version"] = element.getVersion()
                element_settings["short"] = element.getShort()
                element_settings["description"] = element.getDescription()
                element_settings["family"] = element.getFamily()
                element_settings["module"] = element.getModule()
                element_settings["port"] = element.getPorts()
            elif setting_name == "ipsets":
                element = fw.config().getIPSetByName(_item).getSettings()
                element_settings["version"] = element.getVersion()
                element_settings["short"] = element.getShort()
                element_settings["description"] = element.getDescription()
                element_settings["options"] = element.getOptions()
                element_settings["entries"] = element.getEntries()
            elif setting_name == "policies":
                element = fw.config().getPolicyByName(_item).getSettings()
                element_settings = element.getSettingsDict()
            settings[_item] = element_settings
        return settings


def main():

    module_args = dict(detailed=dict(type="bool", default=False, required=False))

    results = dict(changed=False, firewall_config=dict())

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    if not HAS_FIREWALLD:
        module.fail_json(msg="firewalld not installed")

    if module.check_mode:
        module.exit_json(**results)

    results["firewall_config"] = config_to_dict(module)

    module.exit_json(**results)


########################################################

if __name__ == "__main__":
    main()
