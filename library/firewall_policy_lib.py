#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Red Hat, Inc.
# Reusing some firewalld code
#
# Authors:
# Roy Lenferink <lenferinkroy@gmail.com>
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
module: firewall_policy_lib
short_description: Module for firewall policies role
requirements:
  - python3-firewall or python-firewall
description:
  Manage firewall with firewalld on Fedora and RHEL-7+.
author: "Roy Lenferink (@rlenferink)"
options:
  online:
    description:
      When true, use the D-Bus API to query the status from the running system.
      Otherwise, use firewall-offline-cmd(1). Offline mode is
      incompatible with "runtime" mode.
    type: bool
    required: false
    default: true
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
      policy:
        description:
          The policy name string.
        required: true
        type: str
      egress_zone:
        description:
          The firewalld Policy egress-zone.
        required: false
        type: str
      ingress_zone:
        description:
          The firewalld Policy ingress-zone.
        required: false
        type: str
      rich_rule:
        description:
          List of rich rule strings.
          For the format see L(Syntax for firewalld rich language rules,
          https://firewalld.org/documentation/man-pages/firewalld.richlanguage.html).
        required: false
        type: list
        elements: str
        default: []
      target:
        description:
          The firewalld Policy target.
          If the state is set to C(absent), this will reset the target to default.
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
        required: false
        type: bool
      state:
        description:
          Ensure presence or absence of entries.  Use C(present) and C(absent) only
          for zone-only operations, service-only operations, or target operations.
        required: false
        type: str
        choices: ["enabled", "disabled", "present", "absent"]
"""

EXAMPLES = """
- name: Configure firewall policies with config_list
  firewall_policy_lib:
    config_list:
      - policy: strict-output
        ingress_zone: HOST
        egress_zone: ANY
        permanent: true
        rich_rule:
          - "..."
          - "..."
"""

from ansible.module_utils.basic import AnsibleModule

try:
    import firewall.config

    FW_VERSION = firewall.config.VERSION

    from firewall.client import (
        FirewallClient,
        Rich_Rule,
        FirewallClientPolicySettings,
    )

    HAS_FIREWALLD = True
except ImportError:
    HAS_FIREWALLD = False

try:
    if HAS_FIREWALLD:
        firewall.config.FIREWALLD_POLICIES

    HAS_POLICIES = True
except AttributeError:
    HAS_POLICIES = False


# Above: adapted from firewall-cmd source code
class OnlineAPIBackend:
    """Implement operations with the FirewallClient() API.

    This requires firewalld to be running.
    """

    def __init__(self, module, permanent, runtime, state, policy):
        self.module = module
        self.state = state
        self.permanent = permanent
        self.runtime = runtime
        self.policy = policy

        self.fw = FirewallClient()

        # Set exception handler
        def exception_handler(exception_message):
            module.fail_json(msg=exception_message)

        self.fw.setExceptionHandler(exception_handler)

        self.changed = False
        self.need_reload = False

        # Check if the policy exists and store settings
        policy_exists = False
        if runtime:
            policy_exists = policy in self.fw.getPolicies()
        if permanent:
            policy_exists = policy in self.fw.config().getPolicyNames()

        if policy_exists:
            self._store_policy()
        else:
            self.fw_policy = None
            self.fw_settings = None

        self.policy_exists = policy_exists

    def _store_policy(self):
        self.fw_policy = self.fw.config().getPolicyByName(self.policy)
        self.fw_settings = self.fw_policy.getSettings()

    def set_policy(self):
        if self.state == "present" and not self.policy_exists:
            if not self.module.check_mode:
                self.fw.config().addPolicy(self.policy, FirewallClientPolicySettings())
                self._store_policy()
                self.need_reload = True
            self.changed = True
        elif self.state == "absent" and self.policy_exists:
            if not self.module.check_mode:
                self.fw_policy.remove()
                self.need_reload = True
            self.changed = True
            self.fw_policy = None
            self.fw_settings = None

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

    def set_ingress_zone(self, ingress_zone):
        if self.state in ["enabled", "present"]:
            if (
                self.permanent
                and ingress_zone not in self.fw_settings.getIngressZones()
            ):
                if not self.module.check_mode:
                    self.fw_settings.addIngressZone(ingress_zone)
                    self.need_reload = True
                self.changed = True
        elif self.state in ["absent", "disabled"]:
            if self.permanent and ingress_zone in self.fw_settings.getIngressZones():
                if not self.module.check_mode:
                    self.fw_settings.removeIngressZone(ingress_zone)
                    self.need_reload = True
                self.changed = True

    def set_egress_zone(self, egress_zone):
        if self.state in ["enabled", "present"]:
            if self.permanent and egress_zone not in self.fw_settings.getEgressZones():
                if not self.module.check_mode:
                    self.fw_settings.addEgressZone(egress_zone)
                    self.need_reload = True
                self.changed = True
        elif self.state in ["absent", "disabled"]:
            if self.permanent and egress_zone in self.fw_settings.getEgressZones():
                if not self.module.check_mode:
                    self.fw_settings.removeEgressZone(egress_zone)
                    self.need_reload = True
                self.changed = True

    def set_rich_rule(self, rich_rule):
        for item in rich_rule:
            if self.state in ["enabled", "present"]:
                if self.permanent and not self.fw_settings.queryRichRule(item):
                    if not self.module.check_mode:
                        self.fw_settings.addRichRule(item)
                        self.need_reload = True
                    self.changed = True
            elif self.state in ["absent", "disabled"]:
                if self.permanent and self.fw_settings.queryRichRule(item):
                    if not self.module.check_mode:
                        self.fw_settings.removeRichRule(item)
                        self.need_reload = True
                    self.changed = True

    def finalize(self):
        if self.fw_policy and self.fw_settings:
            self.fw_policy.update(self.fw_settings)
        if self.need_reload:
            self.fw.reload()


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


def get_base_argument_spec():
    """Return the base argument spec for policy configuration parameters."""
    return dict(
        policy=dict(required=True, type="str"),
        ingress_zone=dict(required=False, type="str", default=None),
        egress_zone=dict(required=False, type="str", default=None),
        rich_rule=dict(required=False, type="list", elements="str", default=[]),
        target=dict(required=False, type="str", default=None),
        permanent=dict(required=False, type="bool", default=None),
        runtime=dict(required=False, type="bool", default=None),
        state=dict(
            choices=["enabled", "disabled", "present", "absent"],
            required=False,
            default=None,
        ),
    )


def get_full_argument_spec():
    full_spec = dict(
        config_list=dict(
            required=False,
            type="list",
            elements="dict",
            options=get_base_argument_spec(),
            default=[],
        ),
        online=dict(required=False, type="bool", default=True),
    )
    return full_spec


def process_single_config(
    module,
    config_params=None,
    backend=None,
    online_param=None,
):
    """
    Process a single configuration, either from module.params or from a config dict.

    Args:
        module: The Ansible module object
        config_params: Optional config dict to use instead of module.params
        backend: Optional backend object to use instead of creating a new one
        online_param: Whether firewalld is online

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
    policy = params["policy"]
    target = params["target"]
    ingress_zone = params["ingress_zone"]
    egress_zone = params["egress_zone"]

    permanent = params["permanent"]
    runtime = params["runtime"]
    state = params["state"]

    rich_rule = []
    for item in params["rich_rule"]:
        try:
            rule = str(Rich_Rule(rule_str=item))
            rich_rule.append(rule)
        except Exception as e:
            module.fail_json(msg="Rich Rule '%s' is not valid: %s" % (item, str(e)))

    if online_param is None:
        online = params["online"]
    else:
        online = online_param

    if permanent is None:
        permanent = True
    if runtime is None:
        runtime = online
    if not any((permanent, runtime)):
        module.fail_json(msg="One of permanent, runtime needs to be enabled")

    # Parameter checks
    if not HAS_FIREWALLD:
        module.fail_json(msg="No firewalld")

    if not HAS_POLICIES:
        module.fail_json(msg="No support for firewalld policies")

    if not online:
        module.fail_json(msg="This module does not support offline mode (yet)")

    # Pre-run version checking
    if lsr_parse_version(FW_VERSION) < lsr_parse_version("0.9.0"):
        module.fail_json(
            msg="Unsupported firewalld version %s, requires >= 0.9.0" % FW_VERSION
        )

    # Use provided backend or create a new one
    if backend is None:
        backend = OnlineAPIBackend(module, permanent, runtime, state, policy)
    else:
        # Update backend state for this config
        backend.permanent = permanent
        backend.runtime = runtime
        backend.state = state
        backend.policy = policy

    # Firewall modification starts here
    backend.set_policy()

    if target is not None:
        backend.set_target(target)
    if ingress_zone is not None:
        backend.set_ingress_zone(ingress_zone)
    if egress_zone is not None:
        backend.set_egress_zone(egress_zone)
    if rich_rule:
        backend.set_rich_rule(rich_rule)

    backend.finalize()
    return backend.changed


def main():
    module = AnsibleModule(
        argument_spec=get_full_argument_spec(),
        supports_check_mode=True,
    )

    if not HAS_FIREWALLD:
        module.fail_json(msg="No firewall backend could be imported.")

    config_list = module.params["config_list"]
    online = module.params["online"]

    # Check if any non-config_list parameters are set (except online)
    base_params = get_base_argument_spec()

    # Validate all configs
    for i, config in enumerate(config_list):
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

    changed = False
    if module.check_mode:
        # Exit early because either check_mode is True and we don't want to apply changes,
        # or no changes were made and no interfaces were changed, so we don't need to process
        # any changes.
        changed = True
        module.exit_json(
            changed=changed,
            diff="Check mode not implemented!",
            short_circuit=True,
        )

    # From here on, something has changed, and we need to process those changes

    # Process each configuration in the list normally
    for config in config_list:
        # Process this configuration
        if process_single_config(
            module,
            config_params=config,
            online_param=online,
        ):
            # Something changed
            changed = True

    module.exit_json(
        changed=changed,
        diff="",
        short_circuit=False,
    )


#################################################

if __name__ == "__main__":
    main()
