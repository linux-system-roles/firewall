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

from __future__ import absolute_import, division, print_function, unicode_literals

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
  online:
    description:
      When true, use the D-Bus API to query the status from the running system.
      Otherwise, use firewall-offline-cmd(1). Offline mode is (currently)
      incompatible with "detailed" mode.
    type: bool
    required: false
    default: true
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
from ansible.module_utils.firewall_lsr.get_config import config_to_dict, HAS_FIREWALLD


def main():

    module_args = dict(
        detailed=dict(type="bool", default=False, required=False),
        online=dict(type="bool", default=True, required=False),
    )

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
