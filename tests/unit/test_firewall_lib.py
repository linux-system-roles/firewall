# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Rich Megginson <rmeggins@redhat.com>
# SPDX-License-Identifier: GPL-2.0-or-later
#
""" Unit tests for kernel_settings module """

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import unittest
import pytest

try:
    from unittest.mock import call, MagicMock, Mock, patch
except ImportError:
    from mock import call, MagicMock, Mock, patch

import firewall_lib


TEST_METHODS = [
    "Service",
    "Port",
    "SourcePort",
    "ForwardPort",
    "Masquerade",
    "RichRule",
    "Source",
    "Interface",
    "IcmpBlock",
    "IcmpBlockInversion",
    "Target",
]
TEST_STATES = ["enabled", "disabled"]
SERVICES_PRESENT = ["https", "ipsec", "ldaps"]
TEST_DATA = {
    "Service": {
        "input": {"service": SERVICES_PRESENT},
        "enabled": {
            "expected": {
                "runtime": [
                    call("default", service, 0) for service in SERVICES_PRESENT
                ],
                "permanent": [call(service) for service in SERVICES_PRESENT],
            }
        },
        "disabled": {
            "expected": {
                "runtime": [call("default", service) for service in SERVICES_PRESENT],
                "permanent": [call(service) for service in SERVICES_PRESENT],
            }
        },
    },
    "Port": {
        "input": {"port": ["8081/tcp", "161-162/udp"]},
        "enabled": {
            "expected": {
                "runtime": [
                    call("default", "8081", "tcp", 0),
                    call("default", "161-162", "udp", 0),
                ],
                "permanent": [call("8081", "tcp"), call("161-162", "udp")],
            }
        },
        "disabled": {
            "expected": {
                "runtime": [
                    call("default", "8081", "tcp"),
                    call("default", "161-162", "udp"),
                ],
                "permanent": [call("8081", "tcp"), call("161-162", "udp")],
            }
        },
    },
    "SourcePort": {
        "input": {"source_port": ["8081/tcp", "161-162/udp"]},
        "enabled": {
            "expected": {
                "runtime": [
                    call("default", "8081", "tcp", 0),
                    call("default", "161-162", "udp", 0),
                ],
                "permanent": [call("8081", "tcp"), call("161-162", "udp")],
            }
        },
        "disabled": {
            "expected": {
                "runtime": [
                    call("default", "8081", "tcp"),
                    call("default", "161-162", "udp"),
                ],
                "permanent": [call("8081", "tcp"), call("161-162", "udp")],
            }
        },
    },
    "ForwardPort": {
        "input": {"forward_port": ["8081/tcp;port;addr", "161-162/udp;port;addr"]},
        "enabled": {
            "expected": {
                "runtime": [
                    call("default", "8081", "tcp", "port", "addr", 0),
                    call("default", "161-162", "udp", "port", "addr", 0),
                ],
                "permanent": [
                    call("8081", "tcp", "port", "addr"),
                    call("161-162", "udp", "port", "addr"),
                ],
            }
        },
        "disabled": {
            "expected": {
                "runtime": [
                    call("default", "8081", "tcp", "port", "addr"),
                    call("default", "161-162", "udp", "port", "addr"),
                ],
                "permanent": [
                    call("8081", "tcp", "port", "addr"),
                    call("161-162", "udp", "port", "addr"),
                ],
            }
        },
    },
    "Masquerade": {
        "input": {"enabled": {"masquerade": True}, "disabled": {"masquerade": False}},
        "enabled": {
            "expected": {"runtime": [call("default", 0)], "permanent": [call()]}
        },
        "disabled": {"expected": {"runtime": [call("default")], "permanent": [call()]}},
    },
    "RichRule": {
        "input": {"rich_rule": ['rule protocol value="30" reject']},
        "enabled": {
            "expected": {
                "runtime": [call("default", 'rule protocol value="30" accept', 0)],
                "permanent": [call('rule protocol value="30" accept')],
                "rich_rule_mock": {
                    "return_value.__str__.return_value": 'rule protocol value="30" accept'
                },
            }
        },
        "disabled": {
            "expected": {
                "runtime": [call("default", 'rule protocol value="30" accept')],
                "permanent": [call('rule protocol value="30" accept')],
                "rich_rule_mock": {
                    "return_value.__str__.return_value": 'rule protocol value="30" accept'
                },
            }
        },
    },
    "Source": {
        "input": {
            "source": ["192.0.2.0/24"],
        },
        "enabled": {
            "expected": {
                "runtime": [call("default", "192.0.2.0/24")],
                "permanent": [call("192.0.2.0/24")],
            }
        },
        "disabled": {
            "expected": {
                "runtime": [call("default", "192.0.2.0/24")],
                "permanent": [call("192.0.2.0/24")],
            }
        },
    },
    "Interface": {
        "input": {
            "interface": ["eth2"],
        },
        "enabled": {
            "expected": {
                "runtime": [call("default", "eth2")],
            }
        },
        "disabled": {
            "expected": {
                "runtime": [call("default", "eth2")],
                "permanent": [call("eth2")],
            }
        },
    },
    "InterfacePciId": {
        "input": {"interface_pci_id": ["600D:7C1D"]},
        "enabled": {
            "expected": {
                "runtime": [call("default", "600D:7C1D")],
            },
        },
        "disabled": {
            "expected": {
                "runtime": [call("default", "600D:7C1D")],
                "permanent": [call("600D:7C1D")],
            },
        },
    },
    "IcmpBlock": {
        "input": {
            "icmp_block": ["echo-request"],
        },
        "enabled": {
            "expected": {
                "runtime": [call("default", "echo-request", 0)],
                "permanent": [call("echo-request")],
            }
        },
        "disabled": {
            "expected": {
                "runtime": [call("default", "echo-request")],
                "permanent": [call("echo-request")],
            }
        },
    },
    "IcmpBlockInversion": {
        "input": {
            "enabled": {"icmp_block_inversion": True},
            "disabled": {"icmp_block_inversion": False},
        },
        "enabled": {"expected": {"runtime": [call("default")], "permanent": [call()]}},
        "disabled": {"expected": {"runtime": [call("default")], "permanent": [call()]}},
    },
    "Target": {
        "input": {
            "target": "ACCEPT",
        },
        "enabled": {
            "expected": {
                "permanent": [call("ACCEPT")],
                "query_mock": {"getTarget.return_value": "default"},
                "called_mock_name": "setTarget",
            }
        },
        "disabled": {
            "expected": {
                "permanent": [call("default")],
                "query_mock": {"getTarget.return_value": "DROP"},
                "called_mock_name": "setTarget",
            }
        },
    },
}

TEST_PARAMS = [
    (method, state, TEST_DATA[method]["input"], TEST_DATA[method][state]["expected"])
    for method in TEST_METHODS
    for state in TEST_STATES
]


class MockException(Exception):
    pass


class MockAnsibleModule(MagicMock):
    def __call__(self, **kwargs):
        am = self.return_value
        am.call_params = {}
        if not isinstance(am.params, dict):
            am.params = {}
        for kk, vv in kwargs["argument_spec"].items():
            am.call_params[kk] = vv.get("default")
            if kk not in am.params:
                am.params[kk] = am.call_params[kk]
        am.supports_check_mode = kwargs["supports_check_mode"]
        am.fail_json = Mock(side_effect=MockException())
        am.exit_json = Mock()
        am.log = Mock()
        am.warn = Mock()
        if not isinstance(am.check_mode, bool):
            am.check_mode = False
        return am


class FirewallInterfaceTests(unittest.TestCase):
    """class to test Firewall interface tests"""

    @patch("firewall_lib.FirewallClientZoneSettings", create=True)
    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.8", create=True)
    def test_handle_interface_offline_true(self, zone_settings, firewall_class):
        module = Mock()
        zone = "dmz"
        item = "eth2"
        fw = firewall_class.return_value
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw.config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw.config.getZoneByName.getSettings.return_value = fw_settings
        fw_offline = True
        fw.config.get_zones.return_value = ["dmz"]
        fw_zone_two = Mock()
        fw.config.get_zone.return_value = fw_zone_two
        fw_zone_two.interfaces = ["eth2"]

        firewall_lib.handle_interface_permanent(
            zone, item, fw_zone, fw_settings, fw, fw_offline, module
        )
        called_mock = getattr(fw_settings, "addInterface")
        assert [call("eth2")] == called_mock.call_args_list

    @patch("firewall_lib.FirewallClientZoneSettings", create=True)
    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.8", create=True)
    def test_handle_interface_offline_false(self, zone_settings, firewall_class):
        module = Mock()
        zone = "dmz"
        item = "eth2"
        fw = firewall_class.return_value
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw.config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw.config.getZoneByName.getSettings.return_value = fw_settings
        fw_offline = False
        fw.config.get_zones.return_value = ["dmz"]
        fw_zone_two = Mock()
        fw.config.get_zone.return_value = fw_zone_two
        fw_zone_two.interfaces = ["eth2"]

        firewall_lib.handle_interface_permanent(
            zone, item, fw_zone, fw_settings, fw, fw_offline, module
        )
        called_mock = getattr(fw_settings, "addInterface")
        assert [call("eth2")] == called_mock.call_args_list

    @patch("firewall_lib.nm_get_connection_of_interface", create=True)
    def test_try_get_connection_of_interface(self, nm_get_connection_of_interface):
        nm_get_connection_of_interface.return_value = Mock()

        result = firewall_lib.try_get_connection_of_interface("eth0")

        assert result == nm_get_connection_of_interface.return_value

        nm_get_connection_of_interface.side_effect = Exception()

        result = firewall_lib.try_get_connection_of_interface("any input")

        assert result is None

    @patch("firewall_lib.NM_IMPORTED", True)
    @patch("firewall_lib.try_get_connection_of_interface")
    @patch("firewall_lib.nm_get_zone_of_connection", create=True, return_value="")
    @patch("firewall_lib.nm_set_zone_of_connection", create=True)
    def test_try_set_zone_of_interface_nm_imported(
        self,
        nm_set_zone_of_interface,
        nm_get_zone_of_connection,
        try_get_connection_of_interface,
    ):
        try_get_connection_of_interface.return_value = Mock()

        module = Mock()
        module.log = Mock()
        _zone = ""
        interface = "eth0"

        result = firewall_lib.try_set_zone_of_interface(module, _zone, interface)

        assert result == (True, False)
        module.log.assert_called_with(
            msg="The interface is under control of NetworkManager and already bound to 'the default zone'"
        )

        _zone = "trusted"

        result = firewall_lib.try_set_zone_of_interface(module, _zone, interface)

        assert result == (True, True)

        module.check_mode = True

        result = firewall_lib.try_set_zone_of_interface(module, _zone, interface)

        assert result == (True, True)

        try_get_connection_of_interface.return_value = None

        result = firewall_lib.try_set_zone_of_interface(module, _zone, interface)

        assert result == (False, False)

    @patch("firewall_lib.NM_IMPORTED", False)
    def test_try_set_zone_of_interface_nm_not_imported(self):
        result = firewall_lib.try_set_zone_of_interface(
            Mock(), "any input", "any input"
        )

        assert result == (False, False)

        result = firewall_lib.try_set_zone_of_interface(Mock(), "", "eth0")

        assert result == (False, False)


class FirewallLibParsers(unittest.TestCase):
    """test param to profile conversion and vice versa"""

    # def assertRegex(self, text, expected_regex, msg=None):
    #     """Fail the test unless the text matches the regular expression."""
    #     assert re.search(expected_regex, text)

    # def setUp(self):
    #     self.test_root_dir = tempfile.mkdtemp(suffix=".lsr")
    #     os.environ["TEST_ROOT_DIR"] = self.test_root_dir
    #     self.test_cleanup = kernel_settings.setup_for_testing()
    #     self.tuned_config = tuned.utils.global_config.GlobalConfig()
    #     self.logger = Mock()

    # def tearDown(self):
    #     self.test_cleanup()
    #     shutil.rmtree(self.test_root_dir)
    #     del os.environ["TEST_ROOT_DIR"]

    def test_parse_port(self):
        """Test the code that parses port values."""

        module = Mock()
        item = "a/b"
        rc = firewall_lib.parse_port(module, item)
        self.assertEqual(("a", "b"), rc)

    def test_parse_forward_port(self):
        """Test the code that parses port values."""

        module = Mock()
        module.fail_json = Mock(side_effect=MockException())
        item = "aaa"
        with self.assertRaises(MockException):
            rc = firewall_lib.parse_forward_port(module, item)
        module.fail_json.assert_called_with(msg="improper forward_port format: aaa")
        item = "a/b;;"
        rc = firewall_lib.parse_forward_port(module, item)
        self.assertEqual(("a", "b", None, None), rc)

    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.pci_ids", {"600D:7C1D": ["eth0"]})
    def test_parse_pci_id(self, am_class):
        am = am_class.return_value

        am.params = {"interface_pci_id": ["123G:1111"]}
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="PCI id 123G:1111 does not match format: XXXX:XXXX (X = hexadecimal number)"
        )

        am.params = {"interface_pci_id": ["600D:7C1D"]}
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(msg="Options invalid without state option set")


@patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
class FirewallLibMain(unittest.TestCase):
    """Test main function."""

    @patch("firewall_lib.HAS_FIREWALLD", False)
    def test_main_error_no_firewall_backend(self, am_class):
        with self.assertRaises(MockException):
            firewall_lib.main()
        am_class.return_value.fail_json.assert_called_with(
            msg="No firewall backend could be imported."
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_main_error_no_params(self, am_class):
        with self.assertRaises(MockException):
            firewall_lib.main()
        am_class.return_value.fail_json.assert_called_with(
            msg="One of service, port, source_port, forward_port, "
            "masquerade, rich_rule, source, interface, icmp_block, "
            "icmp_block_inversion, target, zone, set_default_zone, "
            "ipset or firewalld_conf needs to be set"
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_main_error_state_required_for_options(self, am_class):
        am = am_class.return_value
        am.params = {"permanent": True, "source": ["192.0.2.0/24"]}
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(msg="Options invalid without state option set")

    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_main_error_timeout_icmp_block_inversion(self, am_class):
        am = am_class.return_value
        am.params = {"icmp_block_inversion": True, "timeout": 1}
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="timeout can not be used with icmp_block_inversion only"
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_main_error_timeout_source(self, am_class):
        am = am_class.return_value
        am.params = {"source": ["192.0.2.0/24"], "timeout": 1}
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(msg="timeout can not be used with source only")

    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_main_error_source_without_permanent(self, am_class):
        am = am_class.return_value
        am.params = {"source": ["192.0.2.0/24"]}
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(msg="source cannot be set without permanent")

    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_main_error_zone_operation_invalid_options(self, am_class):
        am = am_class.return_value
        am.params = {
            "zone": "customzone",
            "state": "present",
            "permanent": True,
            "description": "This element shouldn't be here for this operation",
        }
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="short, description, port, source_port, helper_module, protocol, "
            "destination, ipset_type or ipset_entries cannot be set while zone is "
            "specified and state is set to present or absent"
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_main_error_service_and_zone_operations(self, am_class):
        am = am_class.return_value
        am.params = {
            "zone": "customzone",
            "service": "customservice",
            "permanent": True,
            "state": "present",
        }
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="2 of {zone, service, ipset} while state present/absent, expected 1"
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_main_error_service_operation_with_invalid_options(self, am_class):
        am = am_class.return_value
        am.params = {
            "service": "customservice",
            "state": "present",
            "permanent": True,
            "target": "accept",
        }
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="Both service and target cannot be set while state is either present or absent"
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_main_error_add_multiple_services(self, am_class):
        am = am_class.return_value
        am.params = {
            "service": ["customservice", "othercustomservice"],
            "permanent": True,
            "state": "present",
        }
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="can only add, modify, or remove one service at a time"
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_main_error_add_service_permanent_false(self, am_class):
        am = am_class.return_value
        am.params = {
            "service": ["customservice"],
            "state": "present",
        }
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="permanent must be enabled for service configuration. Additionally, service runtime configuration is not possible"
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_permanent_runtime_offline(self, am_class):
        am = am_class.return_value
        am.params = {
            "icmp_block_inversion": True,
            "permanent": False,
            "runtime": False,
        }
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="One of permanent, runtime needs to be enabled"
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_timeout_with_disabled_state(self, am_class):
        am = am_class.return_value
        am.params = {"source": ["192.0.2.0/24"], "state": "disabled", "timeout": 1}
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="timeout can not be used with state: disabled"
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_masquerade_with_disabled_state(self, am_class):
        am = am_class.return_value
        am.params = {
            "source": ["192.0.2.0/24"],
            "state": "disabled",
            "masquerade": True,
        }
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="masquerade can not be used with state: disabled"
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_icmp_block_inversion_with_disabled_state(self, am_class):
        am = am_class.return_value
        am.params = {
            "source": ["192.0.2.0/24"],
            "state": "disabled",
            "icmp_block_inversion": True,
        }
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="icmp_block_inversion can not be used with state: disabled"
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_main_error_timeout_interface(self, am_class):
        am = am_class.return_value
        am.params = {"interface": ["eth2"], "timeout": 1}
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="timeout can not be used with interface only"
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_main_error_timeout_target(self, am_class):
        am = am_class.return_value
        am.params = {"timeout": 1, "target": ""}
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(msg="timeout can not be used with target only")

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.8", create=True)
    def test_firewalld_offline_version_disconnected(self, firewall_class, am_class):
        am = am_class.return_value
        am.params = {
            "icmp_block_inversion": True,
            "permanent": True,
        }
        fw = firewall_class.return_value
        fw.connected = False
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="Unsupported firewalld version 0.3.8 requires >= 0.3.9"
        )

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.2.8", create=True)
    def test_firewalld_offline_version_connected(self, firewall_class, am_class):
        am = am_class.return_value
        am.params = {
            "icmp_block_inversion": True,
            "permanent": True,
        }
        fw = firewall_class.return_value
        fw.connected = True
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="Unsupported firewalld version 0.2.8, requires >= 0.2.11"
        )

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.8", create=True)
    def test_set_default_zone(self, firewall_class, am_class):
        am = am_class.return_value
        am.params = {
            "set_default_zone": "public",
        }
        fw = firewall_class.return_value
        fw.connected = True
        firewall_lib = Mock()
        firewall_lib.set_the_default_zone()
        firewall_lib.set_the_default_zone.assert_called()

    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.8", create=True)
    @patch("firewall_lib.FirewallClient", create=True)
    def test_main_error_enable_undefined_service(self, fw_class, am_class):
        am = am_class.return_value
        am.params = {
            "service": ["http-alt"],
            "state": "enabled",
        }
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(msg="INVALID SERVICE - http-alt")

    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.8", create=True)
    @patch("firewall_lib.FirewallClient", create=True)
    def test_main_warning_enable_undefined_service_in_check_mode(
        self, fw_class, am_class
    ):
        am = am_class.return_value
        am.params = {
            "service": ["http-alt"],
            "state": "enabled",
        }
        am.check_mode = True
        firewall_lib.main()
        am.warn.assert_called_with(
            "Service does not exist - http-alt."
            + " Ensure that you define the service in the playbook before running it in diff mode"
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.9.0", create=True)
    def test_allow_zone_drifting_runtime(self, am_class):
        am = am_class.return_value
        am.params = {"firewalld_conf": {"allow_zone_drifting": False}}
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="firewalld_conf can only be used with permanent"
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "1.0.0", create=True)
    @patch("firewall_lib.FirewallClient", create=True)
    def test_allow_zone_drifting_deprecated(self, firewall_class, am_class):
        am = am_class.return_value
        am.params = {
            "firewalld_conf": {"allow_zone_drifting": True},
            "permanent": True,
        }
        firewall_lib.main()
        am.warn.assert_called_with(
            "AllowZoneDrifting is deprecated in this version of firewalld and no longer supported"
        )
        am.exit_json.assert_called_with(changed=False, __firewall_changed=False)

    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.9.0", create=True)
    @patch("firewall_lib.FirewallClient", create=True)
    def test_allow_zone_zone_drifting_proper_usage(self, firewall_class, am_class):
        am = am_class.return_value
        am.params = {"firewalld_conf": dict(), "permanent": True}

        for option in [True, False]:
            am.params["firewalld_conf"]["allow_zone_drifting"] = option
            firewall_lib.main()

    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.9.0", create=True)
    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.try_set_zone_of_interface")
    def test_nm_integration_interfaces(
        self, try_set_zone_of_interface, firewall_class, am_class
    ):
        am = am_class.return_value
        am.params = {
            "interface": "eth0",
            "zone": "public",
            "permanent": True,
        }
        available_zones = ["public"]

        fw = firewall_class.return_value
        fw.zone = Mock()
        fw.zone.get_zones.return_value = available_zones
        fw.config = Mock()
        fw.config.get_zone.return_value = Mock()

        fw_config = Mock()
        fw_config.getZoneNames.return_value = available_zones
        fw.config.return_value = fw_config

        return_values = [(True, True), (True, False)]
        for state in ["enabled", "disabled"]:
            am.params["state"] = state
            for rv in return_values:
                try_set_zone_of_interface.return_value = rv
                firewall_lib.main()
                am.exit_json.assert_called_with(changed=rv[1], __firewall_changed=rv[1])

    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.9.0", create=True)
    def test_ipset_operation_with_services_set(self, am_class):
        am = am_class.return_value
        am.params = {
            "ipset": "test",
            "service": "test",
            "state": "present",
            "permanent": True,
        }

        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="2 of {zone, service, ipset} while state present/absent, expected 1"
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.9.0", create=True)
    def test_service_operation_with_ipset_settings_error(self, am_class):
        am = am_class.return_value
        am.params = {
            "service": "test",
            "ipset_entries": ["8.8.8.8"],
            "ipset_type": "hash:ip",
            "state": "present",
            "permanent": True,
        }

        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="ipset parameters cannot be set when configuring services"
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.9.0", create=True)
    def test_ipset_operation_with_target_set(self, am_class):
        am = am_class.return_value
        am.params = {
            "ipset": "test",
            "target": "DROP",
            "state": "present",
            "permanent": True,
        }

        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(msg="Only one of {ipset, target} can be set")

    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.9.0", create=True)
    def test_ipset_operation_with_permanent_false(self, am_class):
        am = am_class.return_value
        am.params = {
            "ipset": "test",
            "state": "present",
        }

        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="permanent must be enabled for ipset configuration"
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.9.0", create=True)
    def test_short_with_state_absent(self, am_class):
        am = am_class.return_value
        am.params = {
            "ipset": "test",
            "state": "absent",
            "short": "test",
        }

        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="short, description and ipset_type can only be used when "
            "state is present"
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.9.0", create=True)
    @patch("firewall_lib.FirewallClient", create=True)
    def test_create_ipset_without_type(self, fw_class, am_class):
        am = am_class.return_value
        am.params = {
            "ipset": "test",
            "state": "present",
            "short": "test",
            "permanent": True,
        }

        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="ipset_type needed when creating a new ipset"
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.9.0", create=True)
    @patch("firewall_lib.FirewallClient", create=True)
    def test_create_ipset_name_conflict(self, fw_class, am_class):
        am = am_class.return_value
        am.params = {
            "ipset": "test",
            "ipset_type": "hash:mac",
            "state": "present",
            "short": "test",
            "permanent": True,
        }

        fw = fw_class.return_value
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_config.getIPSetNames.return_value = ["test"]
        fw_ipset = Mock()
        fw_config.getIPSetByName.return_value = fw_ipset
        fw_ipset_settings = Mock()
        fw_ipset.getSettings.return_value = fw_ipset_settings
        ipset_type = "hash:ip"
        fw_ipset_settings.getType.return_value = ipset_type

        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="Name conflict when creating ipset - "
            "ipset test of type hash:ip already exists"
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.9.0", create=True)
    @patch("firewall_lib.FirewallClient", create=True)
    def test_remove_ipset_while_in_use(self, fw_class, am_class):
        am = am_class.return_value
        am.params = {
            "ipset": "test",
            "state": "absent",
            "permanent": True,
        }

        fw = fw_class.return_value
        fw.getZoneOfSource.return_value = "public"
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_config.getIPSetNames.return_value = ["test"]
        fw_config.getZoneOfSource.return_value = "public"
        fw_ipset = Mock()
        fw_config.getIPSetByName.return_value = fw_ipset
        fw_ipset_settings = Mock()
        fw_ipset.getSettings.return_value = fw_ipset_settings

        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="Remove ipset:test from all permanent and runtime "
            "zones before attempting to remove it"
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.9.0", create=True)
    @patch("firewall_lib.FirewallClient", create=True)
    def test_remove_ipset_while_in_use_check_mode(self, fw_class, am_class):
        am = am_class.return_value
        am.params = {
            "ipset": "test",
            "state": "absent",
            "permanent": True,
        }
        am.check_mode = True

        fw = fw_class.return_value
        fw.getZoneOfSource.return_value = "public"
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_config.getIPSetNames.return_value = ["test"]
        fw_config.getZoneOfSource.return_value = "public"
        fw_ipset = Mock()
        fw_config.getIPSetByName.return_value = fw_ipset
        fw_ipset_settings = Mock()
        fw_ipset.getSettings.return_value = fw_ipset_settings

        firewall_lib.main()
        am.warn.assert_called_with(
            "Ensure ipset:test is removed from all "
            "zones before attempting to remove it. "
            "Enabled zones: permanent - public | runtime - public"
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.9.0", create=True)
    @patch("firewall_lib.FirewallClient", create=True)
    def test_add_bad_ipset_in_check_mode(self, fw_class, am_class):
        am = am_class.return_value
        am.params = {
            "source": ["ipset:test"],
            "state": "enabled",
            "permanent": True,
        }
        am.check_mode = True

        fw = fw_class.return_value
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_config.getIPSetNames.return_value = []

        firewall_lib.main()
        am.warn.assert_called_with(
            "%s does not exist - ensure it is defined in a previous task before "
            "running play outside check mode" % am.params["source"][0]
        )

    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.9.0", create=True)
    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.FirewallClientIPSetSettings", create=True)
    def test_create_ipset(self, fw_ipset_settings_class, fw_class, am_class):
        am = am_class.return_value
        am.params = {
            "ipset": "test",
            "ipset_type": "hash:ip",
            "ipset_entries": ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
            "description": "test ipset",
            "short": "Test",
            "state": "present",
            "permanent": True,
        }

        fw = fw_class.return_value

        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_config.getIPSetNames.return_value = []
        fw_config.getIPSetByName = Mock()

        fw_ipset_settings = fw_ipset_settings_class.return_value
        fw_ipset_settings.addEntry = Mock()
        fw_ipset_settings.queryEntry = Mock(return_value=False)

        fw_ipset = fw_config.getIPSetByName.return_value
        fw_ipset.update = Mock()
        fw_ipset.getSettings.return_value = fw_ipset_settings

        firewall_lib.main()

        fw_ipset_settings.setType.assert_called_with(am.params["ipset_type"])
        fw_config.getIPSetByName.assert_called_with(am.params["ipset"])
        fw_ipset.getSettings.assert_called_once()
        fw_ipset_settings.addEntry.assert_called()
        fw_ipset.update.assert_called()

        am.check_mode = True
        fw_ipset_settings.addEntry.reset_mock()
        fw_ipset.update.reset_mock()

        firewall_lib.main()

        fw_ipset_settings_class.assert_called_with()
        fw_ipset_settings.addEntry.assert_not_called()
        fw_ipset.update.assert_not_called()

    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.9.0", create=True)
    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.FirewallClientIPSetSettings", create=True)
    def test_remove_ipset_entries(self, fw_ipset_settings_class, fw_class, am_class):
        am = am_class.return_value
        am.params = {
            "ipset": "test",
            "ipset_entries": ["3.3.3.3"],
            "state": "absent",
            "permanent": True,
        }

        fw = fw_class.return_value
        fw_ipset_settings = fw_ipset_settings_class.return_value

        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_config.getIPSetNames.return_value = ["test"]
        fw_config.getIPSetByName = Mock()

        fw_ipset = fw_config.getIPSetByName.return_value
        fw_ipset.update = Mock()
        fw_ipset.remove = Mock()
        fw_ipset.getSettings.return_value = fw_ipset_settings

        fw_ipset_settings.removeEntry = Mock()

        firewall_lib.main()

        fw_ipset.getSettings.assert_called_once()
        fw_ipset_settings.removeEntry.assert_called_with(am.params["ipset_entries"][0])
        fw_ipset.update.assert_called()

        am.check_mode = True
        fw_ipset.update.reset_mock()
        fw_ipset_settings.removeEntry.reset_mock()

        firewall_lib.main()

        fw_ipset.update.assert_not_called()
        fw_ipset_settings.removeEntry.assert_not_called()

        fw_ipset.remove.assert_not_called()

    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.9.0", create=True)
    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.FirewallClientIPSetSettings", create=True)
    def test_remove_ipset(self, fw_ipset_settings_class, fw_class, am_class):
        am = am_class.return_value
        am.params = {
            "ipset": "test",
            "state": "absent",
            "permanent": True,
        }

        fw = fw_class.return_value
        fw_ipset_settings = fw_ipset_settings_class.return_value

        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_config.getIPSetNames.return_value = ["test"]
        fw_config.getIPSetByName = Mock()

        fw_ipset = fw_config.getIPSetByName.return_value
        fw_ipset.remove = Mock()
        fw_ipset.getSettings.return_value = fw_ipset_settings

        fw.getZoneOfSource.return_value = None
        fw_config.getZoneOfSource.return_value = None

        firewall_lib.main()

        fw_ipset.remove.assert_called()

        am.check_mode = True
        fw_ipset.remove.reset_mock()

        firewall_lib.main()

        fw_ipset.remove.assert_not_called()


@pytest.mark.parametrize("method,state,input,expected", TEST_PARAMS)
def test_module_parameters(method, state, input, expected):
    am_class_patcher = patch(
        "firewall_lib.AnsibleModule", new_callable=MockAnsibleModule
    )
    am_class = am_class_patcher.start()
    fw_client_patcher = patch("firewall_lib.FirewallClient", create=True)
    fw_client = fw_client_patcher.start()
    has_fw_patcher = patch("firewall_lib.HAS_FIREWALLD", True)
    has_fw_patcher.start()
    fw_ver_patcher = patch("firewall_lib.FW_VERSION", "0.3.8", create=True)
    fw_ver_patcher.start()
    rich_rule_patcher = patch("firewall_lib.Rich_Rule", create=True)
    rich_rule = rich_rule_patcher.start()

    try:
        params_state = state
        if state in input:  # e.g. parameter does not support state disabled
            input = input[state]
            params_state = "enabled"
        am = am_class.return_value
        permanent = "permanent" in expected
        runtime = "runtime" in expected
        am.params = {
            "permanent": permanent,
            "state": params_state,
            "runtime": runtime,
            "timeout": 0,
        }
        am.params.update(input)
        if "called_mock_name" in expected:
            called_mock_name = expected["called_mock_name"]
        elif state == "enabled":
            if method == "Interface" and runtime:
                called_mock_name = "changeZoneOfInterface"
            else:
                called_mock_name = "add" + method
        else:
            called_mock_name = "remove" + method
        if "query_mock" in expected:
            query_mock = expected["query_mock"]
        elif state == "enabled":
            query_mock = {"query" + method + ".return_value": False}
        else:
            query_mock = {"query" + method + ".return_value": True}

        fw = fw_client.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_config.getServiceNames.return_value = SERVICES_PRESENT
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        if runtime:
            fw.configure_mock(**query_mock)
        if permanent:
            fw_settings.configure_mock(**query_mock)
        if "rich_rule_mock" in expected:
            rich_rule.configure_mock(**expected["rich_rule_mock"])
        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        if runtime:
            called_mock = getattr(fw, called_mock_name)
            assert expected["runtime"] == called_mock.call_args_list
        if permanent:
            called_mock = getattr(fw_settings, called_mock_name)
            assert expected["permanent"] == called_mock.call_args_list
        am.exit_json.assert_called_once_with(changed=True, __firewall_changed=True)
    finally:
        am_class_patcher.stop()
        fw_client_patcher.stop()
        has_fw_patcher.stop()
        fw_ver_patcher.stop()
        rich_rule_patcher.stop()


class FirewallVersionTest(unittest.TestCase):
    """class to test lsr_parse_version"""

    def test_lsr_parse_version(self):
        ver = firewall_lib.lsr_parse_version("")
        assert ver == [0]
        ver = firewall_lib.lsr_parse_version("a.b")
        assert ver == [0, 0]
        ver = firewall_lib.lsr_parse_version("1")
        assert ver == [1]
        ver = firewall_lib.lsr_parse_version("1.2")
        assert ver == [1, 2]
        ver = firewall_lib.lsr_parse_version("1.2.3")
        assert ver == [1, 2, 3]
        ver = firewall_lib.lsr_parse_version("1.2.3.4")
        assert ver == [1, 2, 3, 4]
        ver_b = firewall_lib.lsr_parse_version("0.3")
        assert ver_b < ver
        ver_b = firewall_lib.lsr_parse_version("1.2.3")
        assert ver_b < ver
        ver_b = firewall_lib.lsr_parse_version("1.2.4")
        assert ver_b > ver
