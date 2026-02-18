# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Rich Megginson <rmeggins@redhat.com>
# SPDX-License-Identifier: GPL-2.0-or-later
#
"""Unit tests for get_config module"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import sys
import os
import unittest

# Add module_utils to path for importing
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "..", "module_utils", "firewall_lsr"),
)

# pylint: disable=import-error, no-name-in-module
from get_config import recursive_dict_diff, recursive_show_diffs, merge_with_defaults


class TestRecursiveDictDiff(unittest.TestCase):
    """Tests for recursive_dict_diff function"""

    def test_both_none(self):
        """Test when both arguments are None"""
        result = recursive_dict_diff(None, None, None)
        self.assertIsNone(result)

    def test_dict1_none(self):
        """Test when dict1 is None"""
        result = recursive_dict_diff(None, {"key": "value"}, None)
        self.assertIsNone(result)

    def test_dict2_none(self):
        """Test when dict2 is None"""
        dict1 = {"key": "value"}
        result = recursive_dict_diff(dict1, None, None)
        self.assertEqual(result, dict1)

    def test_identical_dicts(self):
        """Test when both dicts are identical"""
        dict1 = {"key": "value", "nested": {"a": 1, "b": 2}}
        dict2 = {"key": "value", "nested": {"a": 1, "b": 2}}
        result = recursive_dict_diff(dict1, dict2, None)
        self.assertIsNone(result)

    def test_simple_diff(self):
        """Test simple value difference"""
        dict1 = {"key": "value1"}
        dict2 = {"key": "value2"}
        result = recursive_dict_diff(dict1, dict2, None)
        self.assertEqual(result, {"key": "value1"})

    def test_key_only_in_dict1(self):
        """Test key exists only in dict1"""
        dict1 = {"key1": "value1", "key2": "value2"}
        dict2 = {"key1": "value1"}
        result = recursive_dict_diff(dict1, dict2, None)
        self.assertEqual(result, {"key2": "value2"})

    def test_key_only_in_dict2(self):
        """Test key exists only in dict2 - should not be in diff"""
        dict1 = {"key1": "value1"}
        dict2 = {"key1": "value1", "key2": "value2"}
        result = recursive_dict_diff(dict1, dict2, None)
        self.assertIsNone(result)

    def test_nested_dict_diff(self):
        """Test nested dictionary differences"""
        dict1 = {"zones": {"internal": {"ports": [("443", "tcp")]}}}
        dict2 = {"zones": {"internal": {"ports": [("443", "tcp"), ("8443", "tcp")]}}}
        result = recursive_dict_diff(dict1, dict2, None)
        # Lists are compared and only the difference from dict1 is returned
        self.assertIsNotNone(result)

    def test_deeply_nested_diff(self):
        """Test deeply nested dictionary differences"""
        dict1 = {"level1": {"level2": {"level3": {"value": "old"}}}}
        dict2 = {"level1": {"level2": {"level3": {"value": "new"}}}}
        result = recursive_dict_diff(dict1, dict2, None)
        self.assertEqual(result, {"level1": {"level2": {"level3": {"value": "old"}}}})

    def test_list_diff(self):
        """Test list differences"""
        dict1 = {"items": ["a", "b", "c"]}
        dict2 = {"items": ["a", "b"]}
        result = recursive_dict_diff(dict1, dict2, None)
        self.assertEqual(result, {"items": ["c"]})

    def test_list_identical(self):
        """Test identical lists"""
        dict1 = {"items": ["a", "b", "c"]}
        dict2 = {"items": ["a", "b", "c"]}
        result = recursive_dict_diff(dict1, dict2, None)
        self.assertIsNone(result)

    def test_mixed_types(self):
        """Test dict with mixed value types"""
        dict1 = {"string": "hello", "number": 42, "list": [1, 2, 3], "nested": {"a": 1}}
        dict2 = {"string": "hello", "number": 42, "list": [1, 2, 3], "nested": {"a": 1}}
        result = recursive_dict_diff(dict1, dict2, None)
        self.assertIsNone(result)

    def test_mixed_types_with_diff(self):
        """Test dict with mixed value types and differences"""
        dict1 = {"string": "hello", "number": 42, "list": [1, 2, 3], "nested": {"a": 1}}
        dict2 = {"string": "world", "number": 42, "list": [1, 2], "nested": {"a": 2}}
        result = recursive_dict_diff(dict1, dict2, None)
        self.assertIn("string", result)
        self.assertEqual(result["string"], "hello")
        self.assertIn("list", result)
        self.assertIn("nested", result)

    def test_with_normalizers(self):
        """Test with normalization functions"""
        normalizers = {"str": lambda s: s.strip().lower()}
        dict1 = {"key": "  VALUE  "}
        dict2 = {"key": "value"}
        result = recursive_dict_diff(dict1, dict2, normalizers)
        # After normalization, values should be equal
        self.assertIsNone(result)


class TestRecursiveShowDiffs(unittest.TestCase):
    """Tests for recursive_show_diffs function"""

    def test_both_none(self):
        """Test when both arguments are None"""
        result = recursive_show_diffs(None, None, None)
        self.assertIsNone(result)

    def test_dict1_none(self):
        """Test when dict1 is None"""
        dict2 = {"key": "value"}
        result = recursive_show_diffs(None, dict2, None)
        self.assertEqual(result, {"before": None, "after": dict2})

    def test_dict2_none(self):
        """Test when dict2 is None"""
        dict1 = {"key": "value"}
        result = recursive_show_diffs(dict1, None, None)
        self.assertEqual(result, {"before": dict1, "after": None})

    def test_identical_dicts(self):
        """Test when both dicts are identical"""
        dict1 = {"key": "value", "nested": {"a": 1, "b": 2}}
        dict2 = {"key": "value", "nested": {"a": 1, "b": 2}}
        result = recursive_show_diffs(dict1, dict2, None)
        self.assertIsNone(result)

    def test_simple_diff(self):
        """Test simple value difference shows before and after"""
        dict1 = {"key": "value1"}
        dict2 = {"key": "value2"}
        result = recursive_show_diffs(dict1, dict2, None)
        self.assertEqual(result["before"], {"key": "value1"})
        self.assertEqual(result["after"], {"key": "value2"})

    def test_key_only_in_dict1(self):
        """Test key exists only in dict1"""
        dict1 = {"key1": "value1", "key2": "value2"}
        dict2 = {"key1": "value1"}
        result = recursive_show_diffs(dict1, dict2, None)
        self.assertEqual(result["before"], {"key2": "value2"})
        self.assertEqual(result["after"], {})

    def test_key_only_in_dict2(self):
        """Test key exists only in dict2"""
        dict1 = {"key1": "value1"}
        dict2 = {"key1": "value1", "key2": "value2"}
        result = recursive_show_diffs(dict1, dict2, None)
        self.assertEqual(result["before"], {})
        self.assertEqual(result["after"], {"key2": "value2"})

    def test_nested_dict_diff(self):
        """Test nested dictionary differences - the example from the spec"""
        dict1 = {"zones": {"internal": {"ports": (("443", "tcp"),)}}}
        dict2 = {"zones": {"internal": {"ports": (("443", "tcp"), ("8443", "tcp"))}}}
        result = recursive_show_diffs(dict1, dict2, None)
        self.assertIsNotNone(result)
        self.assertEqual(
            result["before"]["zones"]["internal"]["ports"], (("443", "tcp"),)
        )
        self.assertEqual(
            result["after"]["zones"]["internal"]["ports"],
            (("443", "tcp"), ("8443", "tcp")),
        )

    def test_deeply_nested_diff(self):
        """Test deeply nested dictionary differences"""
        dict1 = {"level1": {"level2": {"level3": {"value": "old"}}}}
        dict2 = {"level1": {"level2": {"level3": {"value": "new"}}}}
        result = recursive_show_diffs(dict1, dict2, None)
        self.assertEqual(
            result["before"], {"level1": {"level2": {"level3": {"value": "old"}}}}
        )
        self.assertEqual(
            result["after"], {"level1": {"level2": {"level3": {"value": "new"}}}}
        )

    def test_list_diff(self):
        """Test list differences"""
        dict1 = {"items": ["a", "b"]}
        dict2 = {"items": ["a", "b", "c"]}
        result = recursive_show_diffs(dict1, dict2, None)
        self.assertEqual(result["before"]["items"], ["a", "b"])
        self.assertEqual(result["after"]["items"], ["a", "b", "c"])

    def test_list_identical(self):
        """Test identical lists"""
        dict1 = {"items": ["a", "b", "c"]}
        dict2 = {"items": ["a", "b", "c"]}
        result = recursive_show_diffs(dict1, dict2, None)
        self.assertIsNone(result)

    def test_multiple_differences(self):
        """Test multiple differences at same level"""
        dict1 = {"a": 1, "b": 2, "c": 3}
        dict2 = {"a": 10, "b": 2, "c": 30}
        result = recursive_show_diffs(dict1, dict2, None)
        self.assertEqual(result["before"]["a"], 1)
        self.assertEqual(result["after"]["a"], 10)
        self.assertEqual(result["before"]["c"], 3)
        self.assertEqual(result["after"]["c"], 30)
        self.assertNotIn("b", result["before"])
        self.assertNotIn("b", result["after"])

    def test_complex_nested_diff(self):
        """Test complex nested structure with multiple differences"""
        dict1 = {
            "zones": {
                "public": {
                    "services": ["ssh", "http"],
                    "ports": [("80", "tcp")],
                    "target": "default",
                },
                "internal": {"services": ["ssh"], "ports": []},
            }
        }
        customzone = {
            "ports": [("8080", "tcp"), ("8081", "tcp")],
            "services": ["ssh", "http", "https"],
            "target": "DROP",
        }
        dict2 = {
            "zones": {
                "public": {
                    "services": ["ssh", "http", "https"],
                    "ports": [("80", "tcp")],
                    "target": "ACCEPT",
                },
                "internal": {"services": ["ssh"], "ports": []},
                "customzone": customzone,
            }
        }
        result = recursive_show_diffs(dict1, dict2, None)
        self.assertIsNotNone(result)
        self.assertIn("zones", result["before"])
        self.assertIn("zones", result["after"])
        self.assertIn("public", result["before"]["zones"])
        self.assertIn("public", result["after"]["zones"])
        # services and target changed, ports stayed same
        self.assertIn("services", result["before"]["zones"]["public"])
        self.assertIn("services", result["after"]["zones"]["public"])
        self.assertEqual(
            result["before"]["zones"]["public"]["services"], ["ssh", "http"]
        )
        self.assertEqual(
            result["after"]["zones"]["public"]["services"], ["ssh", "http", "https"]
        )
        self.assertIn("target", result["before"]["zones"]["public"])
        self.assertIn("target", result["after"]["zones"]["public"])
        self.assertEqual(result["before"]["zones"]["public"]["target"], "default")
        self.assertEqual(result["after"]["zones"]["public"]["target"], "ACCEPT")
        self.assertNotIn("ports", result["before"]["zones"]["public"])
        self.assertNotIn("ports", result["after"]["zones"]["public"])
        # internal zone should not be in diff
        self.assertNotIn("internal", result["before"]["zones"])
        self.assertNotIn("internal", result["after"]["zones"])
        # customzone should be in diff
        self.assertNotIn("customzone", result["before"]["zones"])
        self.assertEqual(result["after"]["zones"]["customzone"], customzone)

    def test_with_normalizers(self):
        """Test with normalization functions"""
        normalizers = {"str": lambda s: s.strip().lower()}
        dict1 = {"key": "  VALUE  "}
        dict2 = {"key": "value"}
        result = recursive_show_diffs(dict1, dict2, normalizers)
        # After normalization, values should be equal
        self.assertIsNone(result)

    def test_non_dict_values_with_diff(self):
        """Test comparing non-dict values directly"""
        # When both inputs are non-dicts, compare them directly
        result = recursive_show_diffs("old", "new", None)
        self.assertEqual(result, {"before": "old", "after": "new"})

    def test_non_dict_values_identical(self):
        """Test comparing identical non-dict values"""
        result = recursive_show_diffs("same", "same", None)
        self.assertIsNone(result)

    def test_list_values_directly(self):
        """Test comparing lists directly (not as dict values)"""
        list1 = [1, 2, 3]
        list2 = [1, 2, 3, 4]
        result = recursive_show_diffs(list1, list2, None)
        self.assertEqual(result, {"before": list1, "after": list2})

    def test_empty_dicts(self):
        """Test comparing empty dicts"""
        result = recursive_show_diffs({}, {}, None)
        self.assertIsNone(result)

    def test_one_empty_dict(self):
        """Test comparing empty dict with non-empty dict"""
        dict1 = {}
        dict2 = {"key": "value"}
        result = recursive_show_diffs(dict1, dict2, None)
        self.assertEqual(result["before"], {})
        self.assertEqual(result["after"], {"key": "value"})


class TestMergeWithDefaults(unittest.TestCase):
    """Tests for merge_with_defaults function"""

    def test_both_none(self):
        """Test when both arguments are None"""
        result = merge_with_defaults(None, None)
        self.assertIsNone(result)

    def test_custom_none(self):
        """Test when custom is None, returns defaults"""
        defaults = {"zones": {"public": {"target": "default"}}}
        result = merge_with_defaults(None, defaults)
        self.assertEqual(result, defaults)

    def test_defaults_none(self):
        """Test when defaults is None, returns custom"""
        custom = {"zones": {"internal": {"target": "ACCEPT"}}}
        result = merge_with_defaults(custom, None)
        self.assertEqual(result, custom)

    def test_merge_missing_zone(self):
        """Test merging a zone that exists in defaults but not custom"""
        custom = {"zones": {"internal": {"target": "ACCEPT"}}}
        defaults = {
            "zones": {
                "public": {"target": "default", "services": ["ssh"]},
                "internal": {"target": "default", "services": []},
            }
        }
        result = merge_with_defaults(custom, defaults)
        # internal should keep custom settings
        self.assertEqual(result["zones"]["internal"]["target"], "ACCEPT")
        # public should be copied from defaults
        self.assertIn("public", result["zones"])
        self.assertEqual(result["zones"]["public"]["target"], "default")
        self.assertEqual(result["zones"]["public"]["services"], ["ssh"])

    def test_merge_missing_service(self):
        """Test merging a service that exists in defaults but not custom"""
        custom = {"services": {"custom-svc": {"ports": [("8080", "tcp")]}}}
        defaults = {
            "services": {
                "ssh": {"ports": [("22", "tcp")]},
                "http": {"ports": [("80", "tcp")]},
            }
        }
        result = merge_with_defaults(custom, defaults)
        # custom-svc should remain
        self.assertIn("custom-svc", result["services"])
        # ssh and http should be added from defaults
        self.assertIn("ssh", result["services"])
        self.assertIn("http", result["services"])
        self.assertEqual(result["services"]["ssh"]["ports"], [("22", "tcp")])

    def test_merge_all_types(self):
        """Test merging all configuration types"""
        custom = {
            "zones": {"myzone": {}},
            "services": {"mysvc": {}},
        }
        defaults = {
            "zones": {"public": {"target": "default"}},
            "services": {"ssh": {"ports": [("22", "tcp")]}},
            "icmptypes": {"echo-request": {"destination": ["ipv4", "ipv6"]}},
            "helpers": {"ftp": {"module": "nf_conntrack_ftp"}},
            "ipsets": {"myset": {"type": "hash:ip"}},
            "policies": {"mypolicy": {"target": "CONTINUE"}},
        }
        result = merge_with_defaults(custom, defaults)
        # Custom items preserved
        self.assertIn("myzone", result["zones"])
        self.assertIn("mysvc", result["services"])
        # Default items merged
        self.assertIn("public", result["zones"])
        self.assertIn("ssh", result["services"])
        self.assertIn("echo-request", result["icmptypes"])
        self.assertIn("ftp", result["helpers"])
        self.assertIn("myset", result["ipsets"])
        self.assertIn("mypolicy", result["policies"])

    def test_no_overwrite_existing(self):
        """Test that existing custom items are not overwritten by defaults"""
        custom = {
            "zones": {"public": {"target": "ACCEPT", "services": ["http", "https"]}}
        }
        defaults = {"zones": {"public": {"target": "default", "services": ["ssh"]}}}
        result = merge_with_defaults(custom, defaults)
        # Custom settings should be preserved, not overwritten
        self.assertEqual(result["zones"]["public"]["target"], "ACCEPT")
        self.assertEqual(result["zones"]["public"]["services"], ["http", "https"])

    def test_empty_custom(self):
        """Test merging into empty custom dict"""
        custom = {}
        defaults = {
            "zones": {"public": {"target": "default"}},
            "services": {"ssh": {"ports": [("22", "tcp")]}},
        }
        result = merge_with_defaults(custom, defaults)
        self.assertIn("zones", result)
        self.assertIn("public", result["zones"])
        self.assertIn("services", result)
        self.assertIn("ssh", result["services"])

    def test_empty_defaults(self):
        """Test merging with empty defaults dict"""
        custom = {"zones": {"internal": {"target": "ACCEPT"}}}
        defaults = {}
        result = merge_with_defaults(custom, defaults)
        self.assertEqual(result, custom)

    def test_custom_missing_category(self):
        """Test when custom is missing entire category that exists in defaults"""
        custom = {"zones": {"internal": {"target": "ACCEPT"}}}
        defaults = {
            "zones": {"public": {"target": "default"}},
            "services": {"ssh": {"ports": [("22", "tcp")]}},
        }
        result = merge_with_defaults(custom, defaults)
        # zones should have both
        self.assertIn("internal", result["zones"])
        self.assertIn("public", result["zones"])
        # services should be created with default items
        self.assertIn("services", result)
        self.assertIn("ssh", result["services"])

    def test_ignores_non_merge_keys(self):
        """Test that keys not in merge_keys are ignored"""
        custom = {"other_key": "custom_value"}
        defaults = {"other_key": "default_value", "zones": {"public": {}}}
        result = merge_with_defaults(custom, defaults)
        # other_key in custom should remain unchanged
        self.assertEqual(result["other_key"], "custom_value")
        # zones should be merged
        self.assertIn("zones", result)
        self.assertIn("public", result["zones"])


if __name__ == "__main__":
    unittest.main()
