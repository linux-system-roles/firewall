# -*- coding: utf-8 -*-
#
# Copyright (C) 2016,2017,2020,2021,2024 Red Hat, Inc.
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

import copy
import os
import sys

try:
    import firewall.config

    from firewall.client import FirewallClient

    # firewall.core.io modules needed for xml file reading
    from firewall.core.io.zone import zone_reader
    from firewall.core.io.service import service_reader
    from firewall.core.io.icmptype import icmptype_reader
    from firewall.core.io.ipset import ipset_reader
    from firewall.core.io.helper import helper_reader
    from firewall.core.io.firewalld_conf import firewalld_conf

    HAS_FIREWALLD = True
    FALLBACK_ZONE = firewall.config.FALLBACK_ZONE
except ImportError:
    HAS_FIREWALLD = False
    FALLBACK_ZONE = "public"
try:
    if HAS_FIREWALLD:
        firewall.config.FIREWALLD_POLICIES
        from firewall.core.io.policy import policy_reader

    HAS_POLICIES = True
except AttributeError:
    HAS_POLICIES = False
except ImportError:
    HAS_POLICIES = False


def offline_cmd(module, args, defaults=False):
    # get the defaults by disabling the --system-config dir (ETC_FIREWALLD)
    conf_args = ["--system-config=/nonexisting"] if defaults else []
    cmd = ["firewall-offline-cmd"] + conf_args + args
    rc, out, err = module.run_command(cmd)
    if rc != 0:
        if (
            rc == 1
            and "No such file or directory: '/nonexisting/firewalld.conf'" in err
        ):
            pass
        else:
            module.fail_json(
                msg="Failed to execute firewall-offline-cmd: cmd [%s] rc [%s] out [%s] err [%s]"
                % (cmd.join(" "), rc, out, err)
            )
    return out.strip()


# EL7 does not have this method, so make our own
def export_config_dict(io_object):
    if HAS_FIREWALLD:
        try:
            object_dict = io_object.export_config_dict()
        except AttributeError:
            object_dict = {}
            for key, unused_value in io_object.IMPORT_EXPORT_STRUCTURE:
                if hasattr(io_object, key) and key != "UNUSED":
                    object_dict[key] = getattr(io_object, key)
        if isinstance(io_object, firewall.core.io.zone.Zone):
            if object_dict.get("target") == firewall.core.base.DEFAULT_ZONE_TARGET:
                # to correspond with online getTarget()
                object_dict["target"] = "default"
            if object_dict.get("forward_ports"):
                object_dict["forward_ports"] = normalize_forward_ports(
                    object_dict["forward_ports"]
                )
        return object_dict
    else:
        return {}


def normalize_settings(settings):
    # normalize the settings to remove empty values and set default values
    # this duplicates the logic in core/fw_zone.py:get_config_with_settings_dict()
    for kk, vv in list(settings.items()):
        if kk == "target" and vv == firewall.core.base.DEFAULT_ZONE_TARGET:
            settings[kk] = "default"
        elif vv or isinstance(vv, bool) or isinstance(vv, int):
            pass
        else:
            # remove the key if the value is empty
            del settings[kk]
    return settings


# not used - this method is extremely slow, but kept for reference
def fetch_settings_using_offline_cmd(module, setting_name):
    """
    Fetch firewall settings using firewall-offline-cmd.

    This function retrieves firewall configuration using the offline command interface,
    which can query either default settings or custom permanent settings.

    Args:
        module: Ansible module object (for running commands)
        setting_name: Type of setting to fetch ('zones', 'services', 'icmptypes',
                     'helpers', 'ipsets', 'policies')

    Returns:
        Dictionary with object names as keys and their settings as values
    """
    # Get list of items for this setting type
    setting_options = offline_cmd(
        module, ["--get-" + setting_name], defaults=True
    ).split()

    # Get detailed information for each item
    settings = {}

    for item in setting_options:
        element_settings = {}

        try:
            if setting_name == "zones":
                # Get zone details
                element_settings["services"] = offline_cmd(
                    module, ["--zone=" + item, "--list-services"], defaults=True
                ).split()
                element_settings["ports"] = [
                    tuple(p.split("/"))
                    for p in offline_cmd(
                        module, ["--zone=" + item, "--list-ports"], defaults=True
                    ).split()
                ]
                element_settings["protocols"] = offline_cmd(
                    module, ["--zone=" + item, "--list-protocols"], defaults=True
                ).split()
                element_settings["source_ports"] = [
                    tuple(p.split("/"))
                    for p in offline_cmd(
                        module, ["--zone=" + item, "--list-source-ports"], defaults=True
                    ).split()
                ]
                element_settings["icmp_blocks"] = offline_cmd(
                    module, ["--zone=" + item, "--list-icmp-blocks"], defaults=True
                ).split()
                element_settings["forward_ports"] = offline_cmd(
                    module, ["--zone=" + item, "--list-forward-ports"], defaults=True
                ).split()
                element_settings["interfaces"] = offline_cmd(
                    module, ["--zone=" + item, "--list-interfaces"], defaults=True
                ).split()
                element_settings["sources"] = offline_cmd(
                    module, ["--zone=" + item, "--list-sources"], defaults=True
                ).split()
                element_settings["rules_str"] = (
                    offline_cmd(
                        module, ["--zone=" + item, "--list-rich-rules"], defaults=True
                    ).split("\n")
                    if offline_cmd(
                        module, ["--zone=" + item, "--list-rich-rules"], defaults=True
                    )
                    else []
                )

                # Query masquerade (returns yes/no or error)
                try:
                    masq_result = offline_cmd(
                        module, ["--zone=" + item, "--query-masquerade"], defaults=True
                    )
                    element_settings["masquerade"] = masq_result == "yes"
                except Exception:
                    pass  # just omit the masquerade setting if it's not available

                # Get target
                try:
                    element_settings["target"] = offline_cmd(
                        module, ["--zone=" + item, "--get-target"], defaults=True
                    )
                except Exception:
                    pass  # just omit the target setting if it's not available

                # Get description and short
                try:
                    element_settings["description"] = offline_cmd(
                        module, ["--zone=" + item, "--get-description"], defaults=True
                    )
                except Exception:
                    pass  # just omit the description setting if it's not available

                try:
                    element_settings["short"] = offline_cmd(
                        module, ["--zone=" + item, "--get-short"], defaults=True
                    )
                except Exception:
                    pass  # just omit the short setting if it's not available

            elif setting_name == "services":
                # Get service details
                ports_output = offline_cmd(
                    module, ["--service=" + item, "--get-ports"], defaults=True
                )
                element_settings["ports"] = (
                    [tuple(p.split("/")) for p in ports_output.split()]
                    if ports_output
                    else []
                )

                element_settings["protocols"] = offline_cmd(
                    module, ["--service=" + item, "--get-protocols"], defaults=True
                ).split()

                modules_output = offline_cmd(
                    module, ["--service=" + item, "--get-modules"], defaults=True
                )
                element_settings["modules"] = (
                    modules_output.split() if modules_output else []
                )

                source_ports_output = offline_cmd(
                    module, ["--service=" + item, "--get-source-ports"], defaults=True
                )
                element_settings["source_ports"] = (
                    [tuple(p.split("/")) for p in source_ports_output.split()]
                    if source_ports_output
                    else []
                )

                try:
                    element_settings["description"] = offline_cmd(
                        module,
                        ["--service=" + item, "--get-description"],
                        defaults=True,
                    )
                except Exception:
                    pass  # just omit the description setting if it's not available

                try:
                    element_settings["short"] = offline_cmd(
                        module, ["--service=" + item, "--get-short"], defaults=True
                    )
                except Exception:
                    pass  # just omit the short setting if it's not available

            elif setting_name == "icmptypes":
                # Get icmptype details
                dest_output = offline_cmd(
                    module, ["--icmptype=" + item, "--get-destinations"], defaults=True
                )
                element_settings["destination"] = (
                    dest_output.split() if dest_output else []
                )

                try:
                    element_settings["description"] = offline_cmd(
                        module,
                        ["--icmptype=" + item, "--get-description"],
                        defaults=True,
                    )
                except Exception:
                    pass  # just omit the description setting if it's not available

                try:
                    element_settings["short"] = offline_cmd(
                        module, ["--icmptype=" + item, "--get-short"], defaults=True
                    )
                except Exception:
                    pass  # just omit the short setting if it's not available

            elif setting_name == "helpers":
                # Get helper details
                element_settings["family"] = offline_cmd(
                    module, ["--helper=" + item, "--get-family"], defaults=True
                )

                element_settings["module"] = offline_cmd(
                    module, ["--helper=" + item, "--get-module"], defaults=True
                )

                ports_output = offline_cmd(
                    module, ["--helper=" + item, "--get-ports"], defaults=True
                )
                element_settings["ports"] = (
                    [tuple(p.split("/")) for p in ports_output.split()]
                    if ports_output
                    else []
                )

                try:
                    element_settings["description"] = offline_cmd(
                        module, ["--helper=" + item, "--get-description"], defaults=True
                    )
                except Exception:
                    pass  # just omit the description setting if it's not available

                try:
                    element_settings["short"] = offline_cmd(
                        module, ["--helper=" + item, "--get-short"], defaults=True
                    )
                except Exception:
                    pass  # just omit the short setting if it's not available

            elif setting_name == "ipsets":
                # Get ipset details
                element_settings["type"] = offline_cmd(
                    module, ["--ipset=" + item, "--get-type"], defaults=True
                )

                entries_output = offline_cmd(
                    module, ["--ipset=" + item, "--get-entries"], defaults=True
                )
                element_settings["entries"] = (
                    entries_output.split("\n") if entries_output else []
                )

                try:
                    element_settings["description"] = offline_cmd(
                        module, ["--ipset=" + item, "--get-description"], defaults=True
                    )
                except Exception:
                    pass  # just omit the description setting if it's not available

                try:
                    element_settings["short"] = offline_cmd(
                        module, ["--ipset=" + item, "--get-short"], defaults=True
                    )
                except Exception:
                    pass  # just omit the short setting if it's not available

                # Get options if available
                try:
                    options_output = offline_cmd(
                        module, ["--ipset=" + item, "--get-options"], defaults=True
                    )
                    element_settings["options"] = (
                        options_output.split() if options_output else []
                    )
                except Exception:
                    pass  # just omit the options setting if it's not available

            elif setting_name == "policies":
                # Get policy details (similar to zones)
                element_settings["services"] = offline_cmd(
                    module, ["--policy=" + item, "--list-services"], defaults=True
                ).split()

                element_settings["ports"] = [
                    tuple(p.split("/"))
                    for p in offline_cmd(
                        module, ["--policy=" + item, "--list-ports"], defaults=True
                    ).split()
                ]

                element_settings["protocols"] = offline_cmd(
                    module, ["--policy=" + item, "--list-protocols"], defaults=True
                ).split()

                element_settings["icmp_blocks"] = offline_cmd(
                    module, ["--policy=" + item, "--list-icmp-blocks"], defaults=True
                ).split()

                element_settings["forward_ports"] = offline_cmd(
                    module, ["--policy=" + item, "--list-forward-ports"], defaults=True
                ).split()

                element_settings["rules_str"] = (
                    offline_cmd(
                        module, ["--policy=" + item, "--list-rich-rules"], defaults=True
                    ).split("\n")
                    if offline_cmd(
                        module, ["--policy=" + item, "--list-rich-rules"], defaults=True
                    )
                    else []
                )

                # Get ingress/egress zones
                try:
                    element_settings["ingress_zones"] = offline_cmd(
                        module,
                        ["--policy=" + item, "--list-ingress-zones"],
                        defaults=True,
                    ).split()
                except Exception:
                    pass  # just omit the ingress_zones setting if it's not available

                try:
                    element_settings["egress_zones"] = offline_cmd(
                        module,
                        ["--policy=" + item, "--list-egress-zones"],
                        defaults=True,
                    ).split()
                except Exception:
                    pass  # just omit the egress_zones setting if it's not available

                try:
                    element_settings["target"] = offline_cmd(
                        module, ["--policy=" + item, "--get-target"], defaults=True
                    )
                except Exception:
                    pass  # just omit the target setting if it's not available

                try:
                    element_settings["description"] = offline_cmd(
                        module, ["--policy=" + item, "--get-description"], defaults=True
                    )
                except Exception:
                    pass  # just omit the description setting if it's not available

                try:
                    element_settings["short"] = offline_cmd(
                        module, ["--policy=" + item, "--get-short"], defaults=True
                    )
                except Exception:
                    pass  # just omit the short setting if it's not available

            settings[item] = normalize_settings(element_settings)

        except Exception as e:
            # If we can't get details for an item, log warning and skip
            module.warn(
                "Failed to get details for "
                + setting_name
                + " '"
                + item
                + "': "
                + str(e)
            )
            continue

    return settings


def config_to_dict(module, detailed=None, online=None):
    if detailed is None:
        detailed = module.params.get("detailed", False)
    if online is None:
        online = module.params.get("online", True)
    config = {}
    defaults = {}
    custom_permanent = {}
    setting_list = ["zones", "services", "icmptypes", "helpers", "ipsets"]

    if HAS_POLICIES:
        setting_list.append("policies")

    defaults = fetch_settings_from_xml_files(module, setting_list, defaults=True)
    config["default"] = defaults
    custom_permanent = fetch_settings_from_xml_files(
        module, setting_list, defaults=False
    )
    custom_permanent_with_defaults = merge_with_defaults(custom_permanent, defaults)
    config["custom_permanent_with_defaults"] = custom_permanent_with_defaults
    if custom_permanent:
        config["custom_permanent"] = custom_permanent
        config["custom"] = custom_permanent  # legacy compatibility
    # this is the built-in default zone if there is no firewalld.conf
    config["fallback_default_zone"] = FALLBACK_ZONE
    # get firewalld.conf settings
    fc = firewalld_conf(firewall.config.FIREWALLD_CONF)
    fc.read()
    config["firewalld_conf"] = {"allow_zone_drifting": fc.get("AllowZoneDrifting")}
    if online:
        fw = FirewallClient()

        current_settings = fetch_online_settings(fw, setting_list, detailed)
        # NOTE: In some cases, the current settings may not include the default settings read from the XML files,
        # for example, the icmptype beyond-scope cannot be loaded by the firewalld server because it is not
        # supported by the kernel, so it will not show up in the online list of icmptypes.  Rather than
        # trying to duplicate that logic here, and only keep the list of supported icmptypes, we merge the
        # the current settings with the defaults to get the full list of settings.
        current_settings_with_defaults = merge_with_defaults(current_settings, defaults)
        config["current"] = current_settings_with_defaults
        config["custom_runtime_with_defaults"] = current_settings_with_defaults
        config["default_zone"] = fw.getDefaultZone()
        # the current settings include the custom permanent with defaults settings, so we need to diff them to get the custom runtime settings
        dict_diff_normalizers = DEFAULT_NORMALIZERS
        custom_runtime = recursive_dict_diff(
            current_settings_with_defaults,
            custom_permanent_with_defaults,
            dict_diff_normalizers,
        )
        if custom_runtime:
            config["runtime_only"] = custom_runtime
    else:
        config["default_zone"] = offline_cmd(module, ["--get-default-zone"])

    return config


def normalize_value(value, normalizers=None):
    """
    Normalize a value using provided normalization functions.

    Args:
        value: The value to normalize
        normalizers: Optional dict or callable for normalization
                    - If callable: applied to the value
                    - If dict: keys are types or paths, values are normalization functions

    Returns:
        Normalized value
    """
    if normalizers is None:
        return value

    if callable(normalizers):
        return normalizers(value)

    # For dict-based normalizers, try type-based lookup
    if isinstance(normalizers, dict):
        value_type = type(value).__name__
        if value_type in normalizers:
            return normalizers[value_type](value)

    return value


def normalize_list(lst, normalizers=None):
    """
    Normalize and sort a list for comparison.

    Args:
        lst: List to normalize
        normalizers: Optional normalization functions

    Returns:
        Sorted list with normalized values
    """
    if not isinstance(lst, list):
        return lst

    # Normalize each item in the list
    normalized = [normalize_value(item, normalizers) for item in lst]

    # Sort the list for comparison (handle mixed types carefully)
    try:
        return sorted(normalized)
    except TypeError:
        # If items aren't directly comparable, convert to strings for sorting
        return sorted(normalized, key=str)


DEFAULT_NORMALIZERS = {
    "str": lambda s: s.strip().lower(),
    "list": lambda ll: sorted([x.strip() for x in ll]),
}


def recursive_dict_diff(dict1, dict2, normalizers, path=""):
    """
    Recursively compare two dictionaries and return only the differences.

    This function compares dict1 against dict2 and returns a new dictionary
    containing only the keys/values from dict1 that are different from dict2
    or don't exist in dict2.

    Args:
        dict1: First dictionary (the one to extract differences from)
        dict2: Second dictionary (the reference to compare against)
        normalizers: Optional dict of normalization functions for value comparison
                    Keys can be:
                    - Type names (e.g., 'str', 'int', 'list')
                    - Path patterns (e.g., 'zones.*.services')
                    Values are callables that normalize the value
        path: Internal parameter for tracking the current path in nested dicts

    Returns:
        Dictionary containing only the differences from dict1
    """
    if dict1 is None and dict2 is None:
        return None
    if dict1 is None:
        return None
    if dict2 is None:
        return dict1

    if not isinstance(dict1, dict) or not isinstance(dict2, dict):
        # For non-dict values, normalize and compare
        norm1 = normalize_value(dict1, normalizers)
        norm2 = normalize_value(dict2, normalizers)

        if isinstance(dict1, list) and isinstance(dict2, list):
            # Compare lists (normalized for comparison)
            normalized1 = normalize_list(dict1, normalizers)
            normalized2 = normalize_list(dict2, normalizers)
            if normalized1 != normalized2:
                return list(set(normalized1) - set(normalized2))
            return None
        elif norm1 != norm2:
            return dict1
        return None

    diff = {}

    # Check all keys in dict1
    for key in dict1:
        current_path = "%s.%s" % (path, key) if path else key

        if key not in dict2:
            # Key exists in dict1 but not in dict2
            diff[key] = dict1[key]
        else:
            # Key exists in both, compare values
            value1 = dict1[key]
            value2 = dict2[key]

            if isinstance(value1, dict) and isinstance(value2, dict):
                # Recursively compare nested dictionaries
                nested_diff = recursive_dict_diff(
                    value1, value2, normalizers, current_path
                )
                if nested_diff:
                    diff[key] = nested_diff
            elif isinstance(value1, list) and isinstance(value2, list):
                # Compare lists (normalized for comparison)
                normalized1 = normalize_list(value1, normalizers)
                normalized2 = normalize_list(value2, normalizers)
                if normalized1 != normalized2:
                    diff[key] = list(set(normalized1) - set(normalized2))
            else:
                # Compare scalar values (with normalization)
                norm1 = normalize_value(value1, normalizers)
                norm2 = normalize_value(value2, normalizers)
                if norm1 != norm2:
                    diff[key] = value1

    return diff if diff else None


def recursive_show_diffs(dict1, dict2, normalizers, ignore_interface=False, path=""):
    """
    Recursively compare two dictionaries and return before/after differences.

    This function compares dict1 against dict2 and returns a dictionary with
    'before' and 'after' keys showing the values from dict1 and dict2 respectively
    for any elements that differ.

    Args:
        dict1: First dictionary (the "before" state)
        dict2: Second dictionary (the "after" state)
        normalizers: Optional dict of normalization functions for value comparison
                    Keys can be:
                    - Type names (e.g., 'str', 'int', 'list')
                    - Path patterns (e.g., 'zones.*.services')
                    Values are callables that normalize the value
        ignore_interface: If True, ignore changes to the interface list
        path: Internal parameter for tracking the current path in nested dicts

    Returns:
        Dictionary with 'before' and 'after' keys containing the differences,
        or None if no differences found
    """
    # If ignore_interface is True, we need to ignore changes to the interface list.
    # This is because the interface list is not part of the firewall configuration,
    # it is managed by the NetworkManager, and the InMemoryBackend has no way to
    # know if a change to the interface list is actually a change to the firewall configuration.
    # we are lucky because the only key named "interface" is in the zone configuration.  If
    # in the future there is another key named "interface" in some other object or at some
    # other level, we will need to modify this code to use path e.g. "zones.*.interface".

    if dict1 is None and dict2 is None:
        return None
    if dict1 is None and dict2 is not None:
        return {"before": None, "after": dict2}
    if dict2 is None and dict1 is not None:
        return {"before": dict1, "after": None}

    if not isinstance(dict1, dict) or not isinstance(dict2, dict):
        # For non-dict values, normalize and compare
        norm1 = normalize_value(dict1, normalizers)
        norm2 = normalize_value(dict2, normalizers)

        if isinstance(dict1, list) and isinstance(dict2, list):
            # Compare lists (normalized for comparison)
            normalized1 = normalize_list(dict1, normalizers)
            normalized2 = normalize_list(dict2, normalizers)
            if normalized1 != normalized2:
                return {"before": dict1, "after": dict2}
            return None
        elif norm1 != norm2:
            return {"before": dict1, "after": dict2}
        return None

    before = {}
    after = {}

    # Check all keys in dict1
    for key in dict1:
        if ignore_interface and key == "interfaces":
            continue
        current_path = "%s.%s" % (path, key) if path else key

        if key not in dict2:
            if dict1[key] in [None, [], {}, ""]:
                pass  # missing key is same as empty value
            else:
                # Key exists in dict1 but not in dict2
                before[key] = dict1[key]
        elif key == "forward":
            pass  # we don't allow setting forward in zones, so we don't compare it
        else:
            # Key exists in both, compare values
            value1 = dict1[key]
            value2 = dict2[key]

            if isinstance(value1, dict) and isinstance(value2, dict):
                # Recursively compare nested dictionaries
                nested_result = recursive_show_diffs(
                    value1, value2, normalizers, current_path
                )
                if nested_result:
                    before[key] = nested_result["before"]
                    after[key] = nested_result["after"]
            elif isinstance(value1, list) and isinstance(value2, list):
                # Compare lists (normalized for comparison)
                normalized1 = normalize_list(value1, normalizers)
                normalized2 = normalize_list(value2, normalizers)
                if normalized1 != normalized2:
                    before[key] = value1
                    after[key] = value2
            else:
                # Compare scalar values (with normalization)
                norm1 = normalize_value(value1, normalizers)
                norm2 = normalize_value(value2, normalizers)
                if norm1 != norm2:
                    before[key] = value1
                    after[key] = value2

    # Check for keys only in dict2
    for key in dict2:
        if ignore_interface and key == "interfaces":
            continue
        if key not in dict1:
            if dict2[key] in [None, [], {}, ""]:
                pass  # missing key is same as empty value
            else:
                # Key exists in dict2 but not in dict1
                after[key] = dict2[key]

    if before or after:
        return {"before": before, "after": after}
    return None


def _recursive_merge_with_defaults(custom, defaults):
    if isinstance(custom, dict) and isinstance(defaults, dict):
        return_value = {}
        for key in defaults:
            if key in custom:
                return_value[key] = _recursive_merge_with_defaults(
                    custom[key], defaults[key]
                )
            else:
                return_value[key] = copy.deepcopy(defaults[key])
        for key in custom:
            if key not in defaults:
                return_value[key] = copy.deepcopy(custom[key])
    else:
        return_value = copy.deepcopy(custom)
    return return_value


def merge_with_defaults(custom, defaults):
    """
    Merge default settings into custom settings.

    This function merges default firewall configuration settings into custom
    settings. For each top-level configuration type (zones, services, icmptypes,
    helpers, ipsets, policies), if an item exists in defaults but not in custom,
    it will be copied from defaults to custom.

    Args:
        custom: Dictionary with custom settings (will be modified in place)
        defaults: Dictionary with default settings

    Returns:
        The modified custom dictionary with defaults merged in
    """
    # Top-level keys that contain named items to merge
    if not custom:
        return defaults
    if not defaults:
        return custom
    if not isinstance(defaults, dict) or not isinstance(custom, dict):
        return copy.deepcopy(custom)
    return _recursive_merge_with_defaults(custom, defaults)


def normalize_forward_ports(forward_ports):
    fwd_ports_list_of_tuples = []
    for fwd_port in forward_ports:
        fwd_port_tuple = []
        for ii in fwd_port:
            if ii == "":
                fwd_port_tuple.append(None)
            else:
                fwd_port_tuple.append(ii)
        fwd_ports_list_of_tuples.append(tuple(fwd_port_tuple))
    return fwd_ports_list_of_tuples


def fetch_online_settings(fw, setting_list, detailed=False):
    """
    Fetch firewall runtime settings using the online FirewallClient API.

    Args:
        fw: FirewallClient object
        setting_list: List of setting types to fetch (e.g., ['zones', 'services', 'icmptypes', 'helpers', 'ipsets', 'policies'])
        detailed: If True, fetch detailed information for each object; if False, return only names

    Returns:
        Dictionary with setting types as keys and their data as values
    """
    all_settings = {}

    for setting_name in setting_list:
        # Get list of items for this setting type using the runtime API
        if setting_name == "zones":
            setting_options = fw.getZones()
        elif setting_name == "services":
            setting_options = fw.listServices()
        elif setting_name == "icmptypes":
            setting_options = fw.listIcmpTypes()
        elif setting_name == "helpers":
            setting_options = fw.getHelpers()
        elif setting_name == "ipsets":
            setting_options = fw.getIPSets()
        elif setting_name == "policies":
            setting_options = fw.getPolicies()
        else:
            continue

        if not detailed:
            all_settings[setting_name] = setting_options
        else:
            settings = {}
            for _item in setting_options:
                element_settings = {}
                if setting_name == "zones":
                    element = fw.getZoneSettings(_item)
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
                        element_settings["masquerade"] = element.getMasquerade()
                        element_settings["forward_ports"] = element.getForwardPorts()
                        element_settings["interfaces"] = element.getInterfaces()
                        element_settings["sources"] = element.getSources()
                        element_settings["rules_str"] = element.getRichRules()
                        element_settings["protocols"] = element.getProtocols()
                        element_settings["source_ports"] = element.getSourcePorts()
                        element_settings["icmp_block_inversion"] = (
                            element.getIcmpBlockInversion()
                        )
                    # normalize the elements
                    if "forward_ports" in element_settings:
                        element_settings["forward_ports"] = normalize_forward_ports(
                            element_settings["forward_ports"]
                        )
                elif setting_name == "services":
                    element = fw.getServiceSettings(_item)
                    try:
                        element_settings = element.getSettingsDict()
                    except AttributeError:
                        element_settings["version"] = element.getVersion()
                        element_settings["short"] = element.getShort()
                        element_settings["description"] = element.getDescription()
                        element_settings["ports"] = element.getPorts()
                        element_settings["protocols"] = element.getProtocols()
                        element_settings["source_ports"] = element.getSourcePorts()
                        element_settings["destination"] = element.getDestinations()
                        element_settings["modules"] = element.getModules()
                        if hasattr(element, "getHelpers"):
                            element_settings["helpers"] = element.getHelpers()
                elif setting_name == "icmptypes":
                    element = fw.getIcmpTypeSettings(_item)
                    element_settings["version"] = element.getVersion()
                    element_settings["short"] = element.getShort()
                    element_settings["description"] = element.getDescription()
                    element_settings["destination"] = element.getDestinations()
                elif setting_name == "helpers":
                    element = fw.getHelperSettings(_item)
                    element_settings["version"] = element.getVersion()
                    element_settings["short"] = element.getShort()
                    element_settings["description"] = element.getDescription()
                    element_settings["family"] = element.getFamily()
                    element_settings["module"] = element.getModule()
                    element_settings["ports"] = element.getPorts()
                elif setting_name == "ipsets":
                    element = fw.getIPSetSettings(_item)
                    element_settings["version"] = element.getVersion()
                    element_settings["short"] = element.getShort()
                    element_settings["description"] = element.getDescription()
                    element_settings["options"] = element.getOptions()
                    element_settings["entries"] = element.getEntries()
                    element_settings["type"] = element.getType()
                elif setting_name == "policies":
                    element = fw.getPolicySettings(_item)
                    element_settings = element.getSettingsDict()
                settings[_item] = normalize_settings(element_settings)
            all_settings[setting_name] = settings

    return all_settings


def cvt_str(string_value):
    if sys.version_info >= (3, 0):
        return string_value
    else:
        return str(string_value)


def fetch_settings_from_xml_files(module, setting_list, defaults=False):
    """
    Fetch firewall settings using FirewallConfig reader API to read XML files.

    This function reads firewall configuration files directly using the
    firewall.core.io reader functions (zone_reader, service_reader, etc.)
    to parse XML configuration files.

    Args:
        module: Ansible module object (for error handling)
        setting_list: List of setting types to fetch ('zones', 'services', etc.)
        defaults: If True, read from USR_LIB_FIREWALLD (default configs);
                 if False, read from ETC_FIREWALLD (custom configs)

    Returns:
        Dictionary with setting types as keys and their data as values
    """

    # Determine root directory based on defaults parameter
    root_dir = cvt_str(
        firewall.config.USR_LIB_FIREWALLD if defaults else firewall.config.ETC_FIREWALLD
    )

    all_settings = {}

    for setting_name in setting_list:
        # Construct the directory path for this setting type
        setting_dir = cvt_str(os.path.join(root_dir, setting_name))

        # Check if directory exists
        if not os.path.exists(setting_dir) or not os.path.isdir(setting_dir):
            continue

        # Get list of XML files in this directory
        try:
            xml_files = [
                cvt_str(f) for f in os.listdir(setting_dir) if f.endswith(".xml")
            ]
        except OSError:
            continue

        if not xml_files:
            continue

        # Get detailed information for each item
        settings = {}

        for xml_file in xml_files:
            item_name = xml_file[:-4]  # Remove .xml extension
            file_path = cvt_str(os.path.join(setting_dir, xml_file))

            try:
                # Read the configuration file using appropriate reader
                if setting_name == "zones":
                    obj = zone_reader(xml_file, setting_dir)
                elif setting_name == "services":
                    obj = service_reader(xml_file, setting_dir)
                elif setting_name == "icmptypes":
                    obj = icmptype_reader(xml_file, setting_dir)
                elif setting_name == "ipsets":
                    obj = ipset_reader(xml_file, setting_dir)
                elif setting_name == "helpers":
                    obj = helper_reader(xml_file, setting_dir)
                elif setting_name == "policies":
                    obj = policy_reader(xml_file, setting_dir)
                else:
                    continue

                # Extract and normalize settings from the object
                settings[item_name] = normalize_settings(export_config_dict(obj))

            except Exception as e:
                # If we can't read a file, log warning and continue
                module.warn(
                    "Failed to read "
                    + setting_name
                    + " configuration from "
                    + file_path
                    + ": "
                    + str(e)
                )
                continue

        if settings:
            all_settings[setting_name] = settings

    return all_settings


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
                    element_settings["masquerade"] = element.getMasquerade()
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
                    if hasattr(element, "getHelpers"):
                        element_settings["helpers"] = element.getHelpers()
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
                element_settings["ports"] = element.getPorts()
            elif setting_name == "ipsets":
                element = fw.config().getIPSetByName(_item).getSettings()
                element_settings["version"] = element.getVersion()
                element_settings["short"] = element.getShort()
                element_settings["description"] = element.getDescription()
                element_settings["options"] = element.getOptions()
                element_settings["entries"] = element.getEntries()
                element_settings["type"] = element.getType()
            elif setting_name == "policies":
                element = fw.config().getPolicyByName(_item).getSettings()
                element_settings = element.getSettingsDict()
            settings[_item] = normalize_settings(element_settings)
        return settings
