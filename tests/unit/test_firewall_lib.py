# SPDX-License-Identifier: GPL-2.0-or-later
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Rich Megginson <rmeggins@redhat.com>
#
"""Unit tests for kernel_settings module"""

from __future__ import absolute_import, division, print_function, unicode_literals

__metaclass__ = type

import unittest
import copy
import pytest

try:
    from unittest.mock import call, MagicMock, Mock, patch
except ImportError:
    from mock import call, MagicMock, Mock, patch

import firewall_lib

# offline API does not support everything, marker for these
NOT_SUPPORTED = "not-supported"

TEST_METHODS = [
    "Service",
    "Port",
    "SourcePort",
    "ForwardPort",
    "Masquerade",
    "RichRule",
    "Source",
    "Interface",
    "InterfacePciId",
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
                "offline": [
                    ("--zone", "public", "--add-service=https"),
                    ("--zone", "public", "--add-service=ipsec"),
                    ("--zone", "public", "--add-service=ldaps"),
                ],
            },
            "offline_cmd": {
                ("--get-services",): " ".join(SERVICES_PRESENT),
                ("--zone", "public", "--query-service=https"): 1,
                ("--zone", "public", "--query-service=ipsec"): 1,
                ("--zone", "public", "--query-service=ldaps"): 1,
            },
        },
        "disabled": {
            "expected": {
                "runtime": [call("default", service) for service in SERVICES_PRESENT],
                "permanent": [call(service) for service in SERVICES_PRESENT],
                "offline": [
                    ("--zone", "public", "--remove-service-from-zone=https"),
                    ("--zone", "public", "--remove-service-from-zone=ipsec"),
                    ("--zone", "public", "--remove-service-from-zone=ldaps"),
                ],
            },
            "offline_cmd": {
                ("--zone", "public", "--query-service=https"): 0,
                ("--zone", "public", "--query-service=ipsec"): 0,
                ("--zone", "public", "--query-service=ldaps"): 0,
            },
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
                "offline": [
                    (
                        "--zone",
                        "public",
                        "--add-port=8081/tcp",
                    ),
                    (
                        "--zone",
                        "public",
                        "--add-port=161-162/udp",
                    ),
                ],
            },
            "offline_cmd": {
                ("--zone", "public", "--query-port=8081/tcp"): 1,
                ("--zone", "public", "--query-port=161-162/udp"): 1,
            },
        },
        "disabled": {
            "expected": {
                "runtime": [
                    call("default", "8081", "tcp"),
                    call("default", "161-162", "udp"),
                ],
                "permanent": [call("8081", "tcp"), call("161-162", "udp")],
                "offline": [
                    (
                        "--zone",
                        "public",
                        "--remove-port=8081/tcp",
                    ),
                    (
                        "--zone",
                        "public",
                        "--remove-port=161-162/udp",
                    ),
                ],
            },
            "offline_cmd": {
                ("--zone", "public", "--query-port=8081/tcp"): 0,
                ("--zone", "public", "--query-port=161-162/udp"): 0,
            },
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
                "offline": [
                    (
                        "--zone",
                        "public",
                        "--add-source-port=8081/tcp",
                    ),
                    (
                        "--zone",
                        "public",
                        "--add-source-port=161-162/udp",
                    ),
                ],
            },
            "offline_cmd": {
                ("--zone", "public", "--query-source-port=8081/tcp"): 1,
                ("--zone", "public", "--query-source-port=161-162/udp"): 1,
            },
        },
        "disabled": {
            "expected": {
                "runtime": [
                    call("default", "8081", "tcp"),
                    call("default", "161-162", "udp"),
                ],
                "permanent": [call("8081", "tcp"), call("161-162", "udp")],
                "offline": [
                    (
                        "--zone",
                        "public",
                        "--remove-source-port=8081/tcp",
                    ),
                    (
                        "--zone",
                        "public",
                        "--remove-source-port=161-162/udp",
                    ),
                ],
            },
            "offline_cmd": {
                ("--zone", "public", "--query-source-port=8081/tcp"): 0,
                ("--zone", "public", "--query-source-port=161-162/udp"): 0,
            },
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
                "offline": [
                    (
                        "--zone",
                        "public",
                        "--add-forward-port=port=8081:proto=tcp:toport=port:toaddr=addr",
                    ),
                    (
                        "--zone",
                        "public",
                        "--add-forward-port=port=161-162:proto=udp:toport=port:toaddr=addr",
                    ),
                ],
            },
            "offline_cmd": {
                (
                    "--zone",
                    "public",
                    "--query-forward-port=port=8081:proto=tcp:toport=port:toaddr=addr",
                ): 1,
                (
                    "--zone",
                    "public",
                    "--query-forward-port=port=161-162:proto=udp:toport=port:toaddr=addr",
                ): 1,
            },
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
                "offline": [
                    (
                        "--zone",
                        "public",
                        "--remove-forward-port=port=8081:proto=tcp:toport=port:toaddr=addr",
                    ),
                    (
                        "--zone",
                        "public",
                        "--remove-forward-port=port=161-162:proto=udp:toport=port:toaddr=addr",
                    ),
                ],
            },
            "offline_cmd": {
                (
                    "--zone",
                    "public",
                    "--query-forward-port=port=8081:proto=tcp:toport=port:toaddr=addr",
                ): 0,
                (
                    "--zone",
                    "public",
                    "--query-forward-port=port=161-162:proto=udp:toport=port:toaddr=addr",
                ): 0,
            },
        },
    },
    "Masquerade": {
        "input": {"enabled": {"masquerade": True}, "disabled": {"masquerade": False}},
        "enabled": {
            "expected": {
                "runtime": [call("default", 0)],
                "permanent": [call()],
                "offline": [("--zone", "public", "--add-masquerade")],
            },
            "offline_cmd": {
                ("--zone", "public", "--query-masquerade"): 1,
            },
        },
        "disabled": {
            "expected": {
                "runtime": [call("default")],
                "permanent": [call()],
                "offline": [("--zone", "public", "--remove-masquerade")],
            },
            "offline_cmd": {
                ("--zone", "public", "--query-masquerade"): 0,
            },
        },
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
                "offline": [
                    (
                        "--zone",
                        "public",
                        '--add-rich-rule=rule protocol value="30" accept',
                    ),
                ],
            },
            "offline_cmd": {
                (
                    "--zone",
                    "public",
                    '--query-rich-rule=rule protocol value="30" accept',
                ): 1,
            },
        },
        "disabled": {
            "expected": {
                "runtime": [call("default", 'rule protocol value="30" accept')],
                "permanent": [call('rule protocol value="30" accept')],
                "rich_rule_mock": {
                    "return_value.__str__.return_value": 'rule protocol value="30" accept'
                },
                "offline": [
                    (
                        "--zone",
                        "public",
                        '--remove-rich-rule=rule protocol value="30" accept',
                    ),
                ],
            },
            "offline_cmd": {
                (
                    "--zone",
                    "public",
                    '--query-rich-rule=rule protocol value="30" accept',
                ): 0,
            },
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
                "offline": [
                    (
                        "--zone",
                        "public",
                        "--add-source=192.0.2.0/24",
                    ),
                ],
            },
            "offline_cmd": {
                ("--zone", "public", "--query-source=192.0.2.0/24"): 1,
            },
        },
        "disabled": {
            "expected": {
                "runtime": [call("default", "192.0.2.0/24")],
                "permanent": [call("192.0.2.0/24")],
                "offline": [
                    (
                        "--zone",
                        "public",
                        "--remove-source=192.0.2.0/24",
                    ),
                ],
            },
            "offline_cmd": {
                ("--zone", "public", "--query-source=192.0.2.0/24"): 0,
            },
        },
    },
    "Interface": {
        "input": {
            "interface": ["eth2"],
        },
        "enabled": {
            "expected": {
                "runtime": [call("default", "eth2")],
                "permanent": [call("eth2")],
                "offline": [
                    (
                        "--zone",
                        "public",
                        "--change-interface=eth2",
                    ),
                ],
            },
            "offline_cmd": {
                ("--zone", "public", "--query-interface=eth2"): 1,
            },
        },
        "disabled": {
            "expected": {
                "runtime": [call("default", "eth2")],
                "permanent": [call("eth2")],
                "offline": [
                    (
                        "--zone",
                        "public",
                        "--remove-interface=eth2",
                    ),
                ],
            },
            "offline_cmd": {
                ("--zone", "public", "--query-interface=eth2"): 0,
            },
        },
    },
    "InterfacePciId": {
        "input": {"interface_pci_id": ["600D:7C1D"]},
        "enabled": {
            "expected": {
                "runtime": [call("default", "eth42")],
                "permanent": [call("eth42")],
                "offline": NOT_SUPPORTED,
            },
        },
        "disabled": {
            "expected": {
                "runtime": [call("default", "eth42")],
                "permanent": [call("eth42")],
                "offline": NOT_SUPPORTED,
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
                "offline": [
                    ("--zone", "public", "--add-icmp-block=echo-request"),
                ],
            },
            "offline_cmd": {
                ("--zone", "public", "--query-icmp-block=echo-request"): 1,
            },
        },
        "disabled": {
            "expected": {
                "runtime": [call("default", "echo-request")],
                "permanent": [call("echo-request")],
                "offline": [
                    ("--zone", "public", "--remove-icmp-block=echo-request"),
                ],
            },
            "offline_cmd": {
                ("--zone", "public", "--query-icmp-block=echo-request"): 0,
            },
        },
    },
    "IcmpBlockInversion": {
        "input": {
            "enabled": {"icmp_block_inversion": True},
            "disabled": {"icmp_block_inversion": False},
        },
        "enabled": {
            "expected": {
                "runtime": [call("default")],
                "permanent": [call()],
                "offline": [("--zone", "public", "--add-icmp-block-inversion")],
            },
            "offline_cmd": {
                ("--zone", "public", "--query-icmp-block-inversion"): 1,
            },
        },
        "disabled": {
            "expected": {
                "runtime": [call("default")],
                "permanent": [call()],
                "offline": [("--zone", "public", "--remove-icmp-block-inversion")],
            },
            "offline_cmd": {
                ("--zone", "public", "--query-icmp-block-inversion"): 0,
            },
        },
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
                "offline": [
                    ("--zone", "public", "--set-target", "ACCEPT"),
                ],
            },
            "offline_cmd": {
                ("--zone", "public", "--get-target"): "default",
            },
        },
        "disabled": {
            "expected": {
                "permanent": [call("default")],
                "query_mock": {"getTarget.return_value": "DROP"},
                "called_mock_name": "setTarget",
                "offline": [
                    ("--zone", "public", "--set-target", "default"),
                ],
            },
            "offline_cmd": {
                ("--zone", "public", "--get-target"): "DROP",
            },
        },
    },
}

TEST_PARAMS = [
    (
        method,
        state,
        TEST_DATA[method]["input"],
        TEST_DATA[method][state]["expected"],
        TEST_DATA[method][state].get("offline_cmd", {}),
    )
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
        am.debug = Mock(side_effect=(lambda *args: print("DBG:", *args)))
        am.warn = Mock()
        if not isinstance(am.check_mode, bool):
            am.check_mode = False
        return am


class FirewallInterfaceTests(unittest.TestCase):
    """class to test Firewall interface tests"""

    @patch("firewall_lib.nm_get_connection_of_interface", create=True)
    def test_try_get_connection_of_interface(self, nm_get_connection_of_interface):
        nm_get_connection_of_interface.return_value = Mock()

        result = firewall_lib.try_get_connection_of_interface("eth0")

        assert result == nm_get_connection_of_interface.return_value

        nm_get_connection_of_interface.side_effect = Exception()

        result = firewall_lib.try_get_connection_of_interface("any input")

        assert result is None

    @patch("firewall_lib.open", create=True)
    @patch("firewall_lib.nm_get_client", create=True)
    @patch("firewall_lib.nm_get_interfaces", create=True)
    def test_get_interface_pci_file_not_found(
        self, nm_get_interfaces, nm_get_client, mock_open
    ):
        nm_get_interfaces.return_value = ["eth0", "eth1"]

        def get_device(iface):
            device = Mock()
            device.get_udi.return_value = "/sys/devices/pci/{0}".format(iface)
            return device

        nm_get_client.return_value.get_device_by_iface.side_effect = get_device

        def open_side_effect(path):
            if path.endswith("eth1/device/vendor"):
                mock_file = MagicMock()
                mock_file.__enter__ = Mock(return_value=mock_file)
                mock_file.__exit__ = Mock(return_value=False)
                mock_file.readline.return_value = "0x8086\n"
                return mock_file
            if path.endswith("eth1/device/device"):
                mock_file = MagicMock()
                mock_file.__enter__ = Mock(return_value=mock_file)
                mock_file.__exit__ = Mock(return_value=False)
                mock_file.readline.return_value = "0x1234\n"
                return mock_file
            raise IOError(2, "No such file or directory", path)

        mock_open.side_effect = open_side_effect

        result = firewall_lib.get_interface_pci()

        assert result == {"8086:1234": ["eth1"]}

    @patch("firewall_lib.NM_IMPORTED", True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.pci_ids", {"600D:7C1D": ["eth0"]})
    @patch("firewall_lib.get_interface_pci", create=True, return_value={})
    def test_parse_pci_id(self, get_interface_pci, am_class):
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
            "destination, ipset_type, ipset_entries, or ipset_options cannot be set while zone is "
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
        warning_msg = "AllowZoneDrifting is deprecated in this version of firewalld and no longer supported"
        if getattr(am, "warn", None):
            am.warn.assert_called_with(warning_msg)
            am.exit_json.assert_called_with(
                changed=False,
                __firewall_changed=False,
                short_circuit=False,
                warnings=[],
            )
        else:
            am.exit_json.assert_called_with(
                changed=False,
                __firewall_changed=False,
                short_circuit=False,
                warnings=[warning_msg],
            )

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
            "interface": ["eth0"],
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
        fw_config.getServiceNames.return_value = ["ssh"]
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_settings.queryService.return_value = False
        fw_settings.addService = Mock()
        fw_zone.getSettings.return_value = fw_settings
        fw.config.return_value = fw_config

        return_values = [(True, True), (True, False)]
        for state in ["enabled", "disabled"]:
            am.params["state"] = state
            for rv in return_values:
                try_set_zone_of_interface.return_value = rv
                fw_settings.queryService.return_value = state == "disabled"
                firewall_lib.main()
                am.exit_json.assert_called_with(
                    changed=rv[1],
                    __firewall_changed=rv[1],
                    short_circuit=False,
                    warnings=[],
                )

        for state in ["enabled", "disabled"]:
            am.params["state"] = state
            am.params["service"] = ["ssh"]
            for rv in return_values:
                try_set_zone_of_interface.return_value = rv
                fw_settings.queryService.return_value = state == "disabled"
                firewall_lib.main()
                am.exit_json.assert_called_with(
                    changed=True,
                    __firewall_changed=True,
                    short_circuit=False,
                    warnings=[],
                )

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

    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.9.0", create=True)
    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.FirewallClientIPSetSettings", create=True)
    def test_create_ipset_ipv6(self, fw_ipset_settings_class, fw_class, am_class):
        am = am_class.return_value
        am.params = {
            "ipset": "test",
            "ipset_type": "hash:ip",
            "ipset_entries": ["2001:db8::1", "2001:db8::2", "2001:db8::3"],
            "description": "test ipset ipv6",
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
    def test_create_ipset_mixed(self, fw_ipset_settings_class, fw_class, am_class):
        am = am_class.return_value
        am.params = {
            "ipset": "test",
            "ipset_type": "hash:ip",
            "ipset_entries": [
                "2001:db8::1",
                "2001:db8::2",
                "2001:db8::3",
                "1.1.1.1",
                "2.2.2.2",
                "3.3.3.3",
            ],
            "description": "test ipset mixed",
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

        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="Address types cannot be mixed in ipset entries - "
            + str(am.params["ipset_entries"])
        )


@pytest.mark.parametrize("method,state,input,expected,_offline_cmd", TEST_PARAMS)
def test_module_parameters(method, state, input, expected, _offline_cmd):
    am_class_patcher = patch(
        "firewall_lib.AnsibleModule", new_callable=MockAnsibleModule
    )
    am_class = am_class_patcher.start()
    fw_client_patcher = patch("firewall_lib.FirewallClient", create=True)
    fw_client = fw_client_patcher.start()
    has_fw_patcher = patch("firewall_lib.HAS_FIREWALLD", True)
    has_fw_patcher.start()
    has_nm_patcher = patch("firewall_lib.NM_IMPORTED", True)
    has_nm_patcher.start()
    fw_ver_patcher = patch("firewall_lib.FW_VERSION", "0.3.8", create=True)
    fw_ver_patcher.start()
    rich_rule_patcher = patch("firewall_lib.Rich_Rule", create=True)
    rich_rule = rich_rule_patcher.start()
    fw_get_pci_patcher = patch(
        "firewall_lib.get_interface_pci", return_value={"600D:7C1D": ["eth42"]}
    )
    fw_get_pci_patcher.start()

    try:
        params_state = state
        if state in input:  # e.g. parameter does not support state disabled
            input = input[state]
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

        # InterfacePciId uses set_interface() as well, same backend API
        if method == "InterfacePciId":
            method = "Interface"

        if "called_mock_name" in expected:
            called_mock_name = expected["called_mock_name"]
        elif state == "enabled":
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
            # special case: set_interface uses unique API for runtime
            if method == "Interface" and state == "enabled":
                runtime_called_mock_name = "changeZoneOfInterface"
            else:
                runtime_called_mock_name = called_mock_name
            called_mock = getattr(fw, runtime_called_mock_name)
            assert expected["runtime"] == called_mock.call_args_list
        if permanent:
            called_mock = getattr(fw_settings, called_mock_name)
            assert expected["permanent"] == called_mock.call_args_list
        am.exit_json.assert_called_once_with(
            changed=True, __firewall_changed=True, short_circuit=False, warnings=[]
        )
    finally:
        am_class_patcher.stop()
        fw_client_patcher.stop()
        has_fw_patcher.stop()
        fw_ver_patcher.stop()
        rich_rule_patcher.stop()
        fw_get_pci_patcher.stop()


@pytest.mark.parametrize("method,state,input,expected,offline_cmd", TEST_PARAMS)
def test_module_parameters_offline(method, state, input, expected, offline_cmd):
    am_class_patcher = patch(
        "firewall_lib.AnsibleModule", new_callable=MockAnsibleModule
    )
    am_class = am_class_patcher.start()
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
        am = am_class.return_value
        permanent = "permanent" in expected
        am.params = {
            "permanent": permanent,
            "state": params_state,
            "online": False,
            "timeout": 0,
        }
        am.params.update(input)

        called_cmds = []

        def mock_run_command(args, check_rc=False):
            assert args[0] == "firewall-offline-cmd"
            args = tuple(args[1:])
            # test-specific query calls from TEST_DATA
            try:
                res = offline_cmd[args]
                if isinstance(res, int):
                    # --query-* return result as exit code
                    rc = res
                    out = ""
                else:
                    rc = 0
                    out = res
            except KeyError:
                # common query calls
                if args[0] == "--get-default-zone":
                    out = "public"
                    rc = 0
                elif args[0] == "--get-services":
                    out = " ".join(SERVICES_PRESENT)
                    rc = 0
                else:
                    # unhandled call (usually setters), record it as mocked
                    called_cmds.append(args)
                    out = ""
                    rc = 0
            if rc != 0 and check_rc:
                am.fail_json("%r exited with %i" % (args, rc))

            return (rc, out, "")

        am.run_command = Mock(side_effect=mock_run_command)
        if "rich_rule_mock" in expected:
            rich_rule.configure_mock(**expected["rich_rule_mock"])
        if expected["offline"] == NOT_SUPPORTED:
            with pytest.raises(MockException):
                firewall_lib.main()
            am.fail_json.assert_called_once()
        else:
            firewall_lib.main()
            assert called_cmds == expected["offline"]
            am.exit_json.assert_called_once_with(
                changed=True, __firewall_changed=True, short_circuit=False, warnings=[]
            )
    finally:
        am_class_patcher.stop()
        has_fw_patcher.stop()
        fw_ver_patcher.stop()
        rich_rule_patcher.stop()


@pytest.mark.parametrize(
    "options",
    [
        {},  # role defaults to runtime
        {"runtime": True},
        {"runtime": True, "permanent": True},
    ],
)
@patch("firewall_lib.HAS_FIREWALLD", True)
@patch("firewall_lib.FW_VERSION", "0.9.0", create=True)
@patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
def test_offline_no_runtime(am_class, options):
    am = am_class.return_value
    am.params = {
        "online": False,
        "set_default_zone": "public",
    }
    am.params.update(options)
    with pytest.raises(MockException):
        firewall_lib.main()
    am.fail_json.assert_called_with(
        msg="runtime mode is not supported in offline environments"
    )


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


class TestPolicies:
    """Exercise policy scopes with real firewalld settings and mocked I/O."""

    @pytest.fixture(autouse=True)
    def policy_api(self, monkeypatch):
        # Most unit-test hosts do not have python-firewall and D-Bus bindings.
        # Use small settings objects there; run the same tests against the real
        # classes automatically when those libraries are installed.
        if firewall_lib.HAS_POLICIES:
            return

        class Settings:
            def __init__(self, settings=None):
                self.settings = {
                    "target": "CONTINUE",
                    "rich_rules": [],
                    "ingress_zones": [],
                    "egress_zones": [],
                }
                self.settings.update(copy.deepcopy(settings or {}))

            def getSettingsDict(self):
                return self.settings

            def getDisable(self):
                return self.settings.get("disable", False)

            def getIngressZones(self):
                return self.settings["ingress_zones"]

            def getEgressZones(self):
                return self.settings["egress_zones"]

        monkeypatch.setattr(firewall_lib, "HAS_POLICIES", True)
        monkeypatch.setattr(firewall_lib, "FirewallClient", Mock(), raising=False)
        monkeypatch.setattr(
            firewall_lib, "FirewallClientPolicySettings", Settings, raising=False
        )
        monkeypatch.setattr(firewall_lib, "Policy", Mock(), raising=False)
        monkeypatch.setattr(
            firewall_lib,
            "export_config_dict",
            lambda obj: {"target": "CONTINUE", "disable": False},
        )
        monkeypatch.setattr(
            firewall_lib, "Rich_Rule", lambda rule_str: rule_str, raising=False
        )

    @staticmethod
    def module(check_mode=False):
        module = Mock()
        module.check_mode = check_mode

        def fail_json(**kwargs):
            raise ValueError(kwargs["msg"])

        module.fail_json.side_effect = fail_json
        return module

    @staticmethod
    def params(**kwargs):
        params = dict(
            policy="test-policy",
            state="present",
            permanent=True,
            runtime=False,
            rich_rule=[],
        )
        params.update(kwargs)
        return params

    def run_config(self, module, params, backend=None, online=True):
        return firewall_lib.process_single_config(
            module,
            [],
            config_params=params,
            backend=backend,
            online_param=online,
            __called_from_role_param=True,
        )

    def memory(self, module, online=True):
        config = {
            "default_zone": "public",
            "default": {"zones": {"public": {}}},
            "custom_permanent_with_defaults": {"zones": {"public": {}}},
            "custom_runtime_with_defaults": {"zones": {"public": {}}},
        }
        with patch.object(firewall_lib, "config_to_dict", return_value=config):
            return firewall_lib.InMemoryBackend(module, online)

    @pytest.mark.parametrize("online", [True, False])
    def test_memory_lifecycle_and_idempotence(self, online):
        module = self.module(True)
        backend = self.memory(module, online)
        params = self.params(
            runtime=online,
            ingress_zone="HOST",
            egress_zone="ANY",
            target="ACCEPT",
            rich_rule=['rule family="ipv4" source address="192.0.2.0/24" accept'],
        )
        assert self.run_config(module, params, backend, online)
        policy = backend.working_config_permanent["policies"]["test-policy"]
        assert policy["ingress_zones"] == ["HOST"]
        assert policy["egress_zones"] == ["ANY"]
        assert policy["target"] == "ACCEPT"
        assert policy["rich_rule"] == [
            'rule family="ipv4" source address="192.0.2.0/24" accept'
        ]
        backend.changed = False
        assert not self.run_config(module, params, backend, online)
        # Remove settings without deleting the object.
        params["state"] = "absent"
        assert self.run_config(module, params, backend, online)
        policy = backend.working_config_permanent["policies"]["test-policy"]
        assert not policy["ingress_zones"]
        assert policy["target"] == "CONTINUE"
        assert self.run_config(
            module, self.params(state="absent", runtime=online), backend, online
        )
        assert "test-policy" not in backend.working_config_permanent["policies"]
        backend.changed = False
        assert not self.run_config(
            module, self.params(state="absent", runtime=online), backend, online
        )

    def test_memory_runtime_and_permanent_are_independent(self):
        module = self.module()
        backend = self.memory(module)
        self.run_config(module, self.params(runtime=True), backend)
        rule = 'rule family="ipv4" source address="192.0.2.0/24" accept'
        self.run_config(
            module,
            self.params(
                state="enabled", permanent=False, runtime=True, rich_rule=[rule]
            ),
            backend,
        )
        assert (
            "rich_rule"
            not in backend.working_config_permanent["policies"]["test-policy"]
        )
        assert backend.working_config_runtime["policies"]["test-policy"][
            "rich_rule"
        ] == [rule]
        self.run_config(
            module, self.params(state="enabled", ingress_zone="HOST"), backend
        )
        assert (
            "ingress_zones"
            not in backend.working_config_runtime["policies"]["test-policy"]
        )
        # A target change with runtime requested reloads permanent configuration.
        self.run_config(
            module, self.params(state="enabled", runtime=True, target="ACCEPT"), backend
        )
        assert (
            "rich_rule" not in backend.working_config_runtime["policies"]["test-policy"]
        )

    @pytest.mark.parametrize("check_mode", [True, False])
    def test_online_create(self, check_mode):
        module = self.module(check_mode)
        with patch.object(firewall_lib, "FirewallClient") as client:
            fw = client.return_value
            fw.config().getPolicyNames.return_value = []
            fw.getPolicies.return_value = []
            params = self.params(runtime=True, ingress_zone="HOST", egress_zone="ANY")
            assert self.run_config(module, params)
            assert fw.config().addPolicy.call_count == (0 if check_mode else 1)
            assert fw.reload.call_count == (0 if check_mode else 1)
            fw.setPolicySettings.assert_not_called()
            fw.config().getZoneByName.assert_not_called()
            if not check_mode:
                settings = fw.config().addPolicy.call_args[0][1]
                assert settings.getIngressZones() == ["HOST"]
                assert settings.getEgressZones() == ["ANY"]

    @pytest.mark.parametrize(
        "permanent,runtime", [(True, False), (False, True), (True, True)]
    )
    @pytest.mark.parametrize("check_mode", [True, False])
    def test_online_update_scopes(self, permanent, runtime, check_mode):
        module = self.module(check_mode)
        with patch.object(firewall_lib, "FirewallClient") as client:
            fw = client.return_value
            fw.config().getPolicyNames.return_value = ["test-policy"]
            fw.getPolicies.return_value = ["test-policy"]
            fw.config().getPolicyByName().getSettings.return_value = (
                firewall_lib.FirewallClientPolicySettings()
            )
            fw.getPolicySettings.return_value = (
                firewall_lib.FirewallClientPolicySettings()
            )
            assert self.run_config(
                module,
                self.params(
                    state="enabled",
                    permanent=permanent,
                    runtime=runtime,
                    ingress_zone="HOST",
                ),
            )
            assert fw.config().getPolicyByName().update.call_count == int(
                permanent and not check_mode
            )
            assert fw.setPolicySettings.call_count == int(runtime and not check_mode)
            fw.reload.assert_not_called()

    @pytest.mark.parametrize("check_mode", [True, False])
    def test_online_delete(self, check_mode):
        with patch.object(firewall_lib, "FirewallClient") as client:
            fw = client.return_value
            fw.config().getPolicyNames.return_value = ["test-policy"]
            fw.getPolicies.return_value = ["test-policy"]
            assert self.run_config(
                self.module(check_mode), self.params(state="absent", runtime=True)
            )
            assert fw.config().getPolicyByName().remove.call_count == int(
                not check_mode
            )
            assert fw.reload.call_count == int(not check_mode)
            fw.config().getPolicyByName().update.assert_not_called()

    def test_online_idempotence_and_policy_switch(self):
        with patch.object(firewall_lib, "FirewallClient") as client:
            fw = client.return_value
            fw.config().getPolicyNames.return_value = ["first", "second"]
            fw.getPolicies.return_value = ["first", "second"]
            settings = firewall_lib.FirewallClientPolicySettings(
                {"ingress_zones": ["HOST"]}
            )
            fw.config().getPolicyByName().getSettings.return_value = settings
            fw.getPolicySettings.return_value = settings
            for policy in ("first", "second"):
                assert not self.run_config(
                    self.module(),
                    self.params(policy=policy, runtime=True, ingress_zone="HOST"),
                )
                fw.config().getPolicyByName.assert_called_with(policy)
            fw.config().getPolicyByName().update.assert_not_called()
            fw.setPolicySettings.assert_not_called()
            fw.reload.assert_not_called()

    @pytest.mark.parametrize("check_mode", [True, False])
    def test_offline_create(self, check_mode):
        module = self.module(check_mode)
        module.run_command.return_value = (0, "", "")
        assert self.run_config(
            module,
            self.params(ingress_zone="HOST", egress_zone="ANY", target="ACCEPT"),
            online=False,
        )
        commands = [c[0][0][1:] for c in module.run_command.call_args_list]
        assert commands[0] == ["--get-policies"]
        if check_mode:
            assert len(commands) == 1
        else:
            assert ["--new-policy=test-policy"] in commands
            assert ["--policy=test-policy", "--add-ingress-zone=HOST"] in commands
            assert ["--policy=test-policy", "--add-egress-zone=ANY"] in commands
            assert ["--policy=test-policy", "--set-target=ACCEPT"] in commands

    def test_offline_remove_setting_and_delete(self):
        module = self.module()
        module.run_command.side_effect = lambda cmd, check_rc=True: (
            (1, "no", "") if cmd[-1] == "--query-disable" else (0, "test-policy", "")
        )
        assert self.run_config(
            module, self.params(state="disabled", ingress_zone="HOST"), online=False
        )
        module.run_command.assert_called_with(
            [
                "firewall-offline-cmd",
                "--policy=test-policy",
                "--remove-ingress-zone=HOST",
            ],
            check_rc=True,
        )
        assert self.run_config(module, self.params(state="absent"), online=False)
        module.run_command.assert_called_with(
            ["firewall-offline-cmd", "--delete-policy=test-policy"], check_rc=True
        )

    @pytest.mark.parametrize(
        "options,message",
        [
            ({"zone": "public"}, "cannot be used with policy"),
            ({"interface": ["eth0"]}, "cannot be used with policy"),
            ({"state": None}, "require state"),
            ({"permanent": False, "runtime": True}, "require permanent"),
            ({"target": "default"}, "Policy target must"),
            ({"target": "%%REJECT%%"}, "Policy target must"),
        ],
    )
    def test_invalid_policy_options(self, options, message):
        with pytest.raises(ValueError, match=message):
            self.run_config(self.module(), self.params(**options))

    def test_unsupported_policies(self):
        with patch.object(firewall_lib, "HAS_POLICIES", False):
            with pytest.raises(ValueError, match="requires firewalld"):
                self.run_config(self.module(), self.params())

    def test_orphan_policy_options_and_zone_targets(self):
        for params in (
            {"ingress_zone": "HOST"},
            {"egress_zone": "ANY"},
            {"target": "CONTINUE"},
        ):
            with pytest.raises(ValueError, match="require policy"):
                self.run_config(self.module(), params)

    def test_missing_policy_and_offline_runtime(self):
        with pytest.raises(ValueError, match="does not exist"):
            self.run_config(
                self.module(), self.params(state="enabled"), self.memory(self.module())
            )
        with pytest.raises(ValueError, match="offline environments"):
            self.run_config(self.module(), self.params(runtime=True), online=False)

    def test_invalid_rich_rule(self):
        with patch.object(
            firewall_lib, "Rich_Rule", side_effect=ValueError("invalid rule")
        ):
            with pytest.raises(ValueError, match="is not valid"):
                self.run_config(self.module(), self.params(rich_rule=["not a rule"]))

    @pytest.mark.parametrize("check_mode", [True, False])
    def test_online_target_drift_reloads(self, check_mode):
        with patch.object(firewall_lib, "FirewallClient") as client:
            fw = client.return_value
            fw.config().getPolicyNames.return_value = ["test-policy"]
            fw.getPolicies.return_value = ["test-policy"]
            fw.config().getPolicyByName().getSettings.return_value = (
                firewall_lib.FirewallClientPolicySettings({"target": "ACCEPT"})
            )
            fw.getPolicySettings.return_value = (
                firewall_lib.FirewallClientPolicySettings()
            )
            assert self.run_config(
                self.module(check_mode), self.params(runtime=True, target="ACCEPT")
            )
            fw.config().getPolicyByName().update.assert_not_called()
            fw.setPolicySettings.assert_not_called()
            assert fw.reload.call_count == int(not check_mode)

    def test_delete_runtime_policy_after_permanent_deletion(self):
        module = self.module()
        backend = self.memory(module)
        self.run_config(module, self.params(runtime=True), backend)
        self.run_config(module, self.params(state="absent"), backend)
        assert "test-policy" in backend.working_config_runtime["policies"]
        backend.changed = False
        assert self.run_config(
            module, self.params(state="absent", runtime=True), backend
        )
        assert "test-policy" not in backend.working_config_runtime["policies"]
        with patch.object(firewall_lib, "FirewallClient") as client:
            fw = client.return_value
            fw.config().getPolicyNames.return_value = []
            fw.getPolicies.return_value = ["test-policy"]
            assert self.run_config(module, self.params(state="absent", runtime=True))
            fw.config().getPolicyByName.assert_not_called()
            fw.reload.assert_called_once_with()

    def test_activate_existing_permanent_policy(self):
        module = self.module()
        backend = self.memory(module)
        self.run_config(module, self.params(), backend)
        backend.changed = False
        assert self.run_config(module, self.params(runtime=True), backend)
        assert "test-policy" in backend.working_config_runtime["policies"]
        with patch.object(firewall_lib, "FirewallClient") as client:
            fw = client.return_value
            fw.config().getPolicyNames.return_value = ["test-policy"]
            fw.getPolicies.return_value = []
            fw.config().getPolicyByName().getSettings.return_value = (
                firewall_lib.FirewallClientPolicySettings()
            )
            assert self.run_config(module, self.params(runtime=True))
            fw.config().getPolicyByName().update.assert_not_called()
            fw.reload.assert_called_once_with()

    @pytest.mark.parametrize(
        "option,value,key,expected",
        [
            ("service", ["http"], "services", ["http"]),
            ("port", ["8080/tcp"], "ports", [("8080", "tcp")]),
            ("source_port", ["1024-2048/udp"], "source_ports", [("1024-2048", "udp")]),
            ("protocol", ["icmp"], "protocols", ["icmp"]),
            ("icmp_block", ["echo-request"], "icmp_blocks", ["echo-request"]),
            (
                "forward_port",
                ["8080/tcp;;192.0.2.1"],
                "forward_ports",
                [("8080", "tcp", None, "192.0.2.1")],
            ),
            ("masquerade", True, "masquerade", True),
        ],
    )
    @pytest.mark.parametrize(
        "permanent,runtime", [(True, False), (False, True), (True, True)]
    )
    def test_memory_policy_primitives(
        self, option, value, key, expected, permanent, runtime
    ):
        module = self.module(True)
        backend = self.memory(module)
        self.run_config(module, self.params(runtime=True), backend)
        params = self.params(
            state="enabled", permanent=permanent, runtime=runtime, **{option: value}
        )
        backend.changed = False
        assert self.run_config(module, params, backend)
        for selected, config in (
            (permanent, backend.working_config_permanent),
            (runtime, backend.working_config_runtime),
        ):
            actual = config["policies"]["test-policy"].get(key)
            assert actual == expected if selected else not actual
        backend.changed = False
        assert not self.run_config(module, params, backend)
        # absent with primitives must remove settings, never delete the policy.
        params["state"] = "absent"
        assert self.run_config(module, params, backend)
        for config in (
            backend.working_config_permanent,
            backend.working_config_runtime,
        ):
            assert "test-policy" in config["policies"]
            assert not config["policies"]["test-policy"].get(key)
        backend.changed = False
        assert not self.run_config(module, params, backend)

    @pytest.mark.parametrize("check_mode", [True, False])
    @pytest.mark.parametrize(
        "permanent,runtime", [(True, False), (False, True), (True, True)]
    )
    def test_online_policy_primitives(self, check_mode, permanent, runtime):
        with patch.object(firewall_lib, "FirewallClient") as client:
            fw = client.return_value
            fw.config().getPolicyNames.return_value = ["test-policy"]
            fw.getPolicies.return_value = ["test-policy"]
            settings = firewall_lib.FirewallClientPolicySettings()
            fw.config().getPolicyByName().getSettings.return_value = settings
            fw.getPolicySettings.return_value = settings
            params = self.params(
                state="enabled",
                permanent=permanent,
                runtime=runtime,
                service=["http"],
                port=["8080/tcp"],
                source_port=["1024/udp"],
                protocol=["icmp"],
                icmp_block=["echo-request"],
                masquerade=True,
                forward_port=["8080/tcp;;192.0.2.1"],
            )
            assert self.run_config(self.module(check_mode), params)
            fw.reload.assert_not_called()
            assert fw.config().getPolicyByName().update.call_count == int(
                permanent and not check_mode
            )
            assert fw.setPolicySettings.call_count == int(runtime and not check_mode)
            if not check_mode:
                args = (
                    fw.config().getPolicyByName().update.call_args[0][0]
                    if permanent
                    else fw.setPolicySettings.call_args[0][1]
                )
                desired = args.getSettingsDict()
                assert desired["services"] == ["http"]
                assert desired["ports"] == [("8080", "tcp")]
                assert desired["source_ports"] == [("1024", "udp")]
                assert desired["protocols"] == ["icmp"]
                assert desired["icmp_blocks"] == ["echo-request"]
                assert desired["masquerade"] is True
                assert desired["forward_ports"] == [("8080", "tcp", "", "192.0.2.1")]

    @pytest.mark.parametrize("check_mode", [True, False])
    @pytest.mark.parametrize(
        "state,verb,rc", [("enabled", "add", 1), ("disabled", "remove", 0)]
    )
    def test_offline_policy_primitives(self, check_mode, state, verb, rc):
        module = self.module(check_mode)

        def command(cmd, check_rc=True):
            if cmd[-1] == "--get-policies":
                return 0, "test-policy", ""
            if cmd[-1] == "--query-disable":
                return 1, "no", ""
            return (rc if "--query-" in cmd[-1] else 0), "", ""

        module.run_command.side_effect = command
        params = self.params(
            state=state,
            service=["http"],
            port=["8080/tcp"],
            source_port=["1024/udp"],
            protocol=["icmp"],
            icmp_block=["echo-request"],
            masquerade=True,
            forward_port=[{"port": "8080", "proto": "tcp", "toaddr": "192.0.2.1"}],
        )
        assert self.run_config(module, params, online=False)
        mutations = [
            entry[0][0][-1]
            for entry in module.run_command.call_args_list
            if entry[0][0][-1].startswith(("--add-", "--remove-"))
        ]
        assert mutations == (
            []
            if check_mode
            else (["--remove-masquerade"] if state == "disabled" else [])
            + [
                "--%s-service=http" % verb,
                "--%s-port=8080/tcp" % verb,
                "--%s-source-port=1024/udp" % verb,
                "--%s-protocol=icmp" % verb,
                "--%s-icmp-block=echo-request" % verb,
                "--%s-forward-port=port=8080:proto=tcp:toaddr=192.0.2.1" % verb,
            ]
            + (["--add-masquerade"] if state == "enabled" else [])
        )

    def test_false_masquerade_does_not_delete_policy(self):
        module = self.module()
        backend = self.memory(module)
        self.run_config(module, self.params(masquerade=True), backend)
        self.run_config(module, self.params(state="absent", masquerade=False), backend)
        assert (
            backend.working_config_permanent["policies"]["test-policy"]["masquerade"]
            is False
        )

    @pytest.mark.parametrize(
        "first,second,message",
        [
            ({"ingress_zone": "HOST"}, {"ingress_zone": "public"}, "cannot mix"),
            ({"egress_zone": "ANY"}, {"egress_zone": "public"}, "cannot mix"),
            ({"ingress_zone": "HOST"}, {"egress_zone": "HOST"}, "both"),
            ({"ingress_zone": "HOST"}, {"masquerade": True}, "masquerade"),
            (
                {"egress_zone": "ANY"},
                {"forward_port": ["8080/tcp;80;"]},
                "requires toaddr",
            ),
        ],
    )
    def test_accumulated_policy_constraints(self, first, second, message):
        module = self.module(True)
        backend = self.memory(module)
        self.run_config(module, self.params(**first), backend)
        with pytest.raises(ValueError, match=message):
            self.run_config(module, self.params(state="enabled", **second), backend)

    @pytest.mark.parametrize("side", ["ingress", "egress"])
    @pytest.mark.parametrize(
        "existing,added",
        [
            ("HOST", "public"),
            ("ANY", "public"),
            ("public", "HOST"),
            ("public", "ANY"),
            ("HOST", "ANY"),
            ("ANY", "HOST"),
        ],
    )
    @pytest.mark.parametrize("backend_type", ["memory", "online", "offline"])
    @pytest.mark.parametrize("check_mode", [True, False])
    def test_symbolic_zones_are_exclusive(
        self, side, existing, added, backend_type, check_mode
    ):
        module = self.module(check_mode)
        params = self.params(state="enabled", **{side + "_zone": added})
        memberships = {side + "_zones": [existing], "target": "CONTINUE"}
        if backend_type == "memory":
            backend = self.memory(module)
            backend.working_config_permanent["policies"] = {"test-policy": memberships}
            with pytest.raises(ValueError, match="cannot mix"):
                self.run_config(module, params, backend)
            assert backend.working_config_permanent["policies"]["test-policy"][
                side + "_zones"
            ] == [existing]
            assert not backend.changed
        elif backend_type == "online":
            with patch.object(firewall_lib, "FirewallClient") as client:
                fw = client.return_value
                fw.config().getPolicyNames.return_value = ["test-policy"]
                fw.config().getPolicyByName().getSettings.return_value = (
                    firewall_lib.FirewallClientPolicySettings(memberships)
                )
                with pytest.raises(ValueError, match="cannot mix"):
                    self.run_config(module, params)
                fw.config().getPolicyByName().update.assert_not_called()
                fw.config().addPolicy.assert_not_called()
                fw.setPolicySettings.assert_not_called()
                fw.reload.assert_not_called()
        else:

            def command(cmd, check_rc=True):
                if cmd[-1] == "--get-policies":
                    return 0, "test-policy", ""
                if cmd[-1] == "--list-%s-zones" % side:
                    return 0, existing, ""
                if cmd[-1] == "--query-masquerade":
                    return 1, "no", ""
                return 0, "", ""

            module.run_command.side_effect = command
            with pytest.raises(ValueError, match="cannot mix"):
                self.run_config(module, params, online=False)
            for entry in module.run_command.call_args_list:
                assert not any(
                    arg.startswith(("--add-", "--remove-", "--new-", "--set-"))
                    for arg in entry[0][0]
                )

    @pytest.mark.parametrize("backend_type", ["memory", "online"])
    def test_runtime_symbolic_conflict_does_not_change_permanent(self, backend_type):
        module = self.module()
        params = self.params(state="enabled", runtime=True, ingress_zone="public")
        permanent = {"target": "CONTINUE", "ingress_zones": []}
        runtime = {"target": "CONTINUE", "ingress_zones": ["HOST"]}
        if backend_type == "memory":
            backend = self.memory(module)
            backend.working_config_permanent["policies"] = {"test-policy": permanent}
            backend.working_config_runtime["policies"] = {"test-policy": runtime}
            with pytest.raises(ValueError, match="cannot mix"):
                self.run_config(module, params, backend)
            assert (
                backend.working_config_permanent["policies"]["test-policy"] == permanent
            )
            assert not backend.changed
        else:
            with patch.object(firewall_lib, "FirewallClient") as client:
                fw = client.return_value
                fw.config().getPolicyNames.return_value = ["test-policy"]
                fw.getPolicies.return_value = ["test-policy"]
                fw.config().getPolicyByName().getSettings.return_value = (
                    firewall_lib.FirewallClientPolicySettings(permanent)
                )
                fw.getPolicySettings.return_value = (
                    firewall_lib.FirewallClientPolicySettings(runtime)
                )
                with pytest.raises(ValueError, match="cannot mix"):
                    self.run_config(module, params)
                fw.config().getPolicyByName().update.assert_not_called()
                fw.setPolicySettings.assert_not_called()
                fw.reload.assert_not_called()

    @pytest.mark.parametrize("side", ["ingress", "egress"])
    @pytest.mark.parametrize("symbol", ["HOST", "ANY"])
    def test_remove_symbol_before_adding_regular_zones(self, side, symbol):
        module = self.module(True)
        backend = self.memory(module)
        self.run_config(module, self.params(**{side + "_zone": symbol}), backend)
        backend.changed = False
        assert not self.run_config(
            module, self.params(**{side + "_zone": symbol}), backend
        )
        self.run_config(
            module, self.params(state="disabled", **{side + "_zone": symbol}), backend
        )
        for zone in ("public", "internal"):
            self.run_config(
                module, self.params(state="enabled", **{side + "_zone": zone}), backend
            )
        assert backend.working_config_permanent["policies"]["test-policy"][
            side + "_zones"
        ] == ["public", "internal"]

    @pytest.mark.parametrize("desired", [True, False])
    @pytest.mark.parametrize(
        "permanent,runtime", [(True, False), (False, True), (True, True)]
    )
    @pytest.mark.parametrize("state", ["enabled", "disabled"])
    def test_is_disabled_memory_scopes(self, desired, permanent, runtime, state):
        module = self.module(True)
        backend = self.memory(module)
        self.run_config(
            module, self.params(runtime=True, is_disabled=not desired), backend
        )
        backend.changed = False
        params = self.params(
            state=state, permanent=permanent, runtime=runtime, is_disabled=desired
        )
        assert self.run_config(module, params, backend)
        for selected, config in (
            (permanent, backend.working_config_permanent),
            (runtime, backend.working_config_runtime),
        ):
            assert config["policies"]["test-policy"]["disable"] == (
                desired if selected else not desired
            )
        backend.changed = False
        assert not self.run_config(module, params, backend)

    def test_omitted_is_disabled_leaves_flag(self):
        assert firewall_lib.get_base_argument_spec()["is_disabled"]["default"] is None
        module = self.module(True)
        backend = self.memory(module)
        self.run_config(module, self.params(is_disabled=True), backend)
        backend.changed = False
        assert not self.run_config(module, self.params(state="enabled"), backend)
        assert (
            backend.working_config_permanent["policies"]["test-policy"]["disable"]
            is True
        )
        assert self.run_config(
            module, self.params(state="enabled", is_disabled=False), backend
        )
        assert (
            backend.working_config_permanent["policies"]["test-policy"]["disable"]
            is False
        )

    @pytest.mark.parametrize("desired", [True, False])
    @pytest.mark.parametrize("check_mode", [True, False])
    @pytest.mark.parametrize(
        "permanent,runtime", [(True, False), (False, True), (True, True)]
    )
    def test_is_disabled_online(self, desired, check_mode, permanent, runtime):
        with patch.object(firewall_lib, "FirewallClient") as client:
            fw = client.return_value
            fw.config().getPolicyNames.return_value = ["test-policy"]
            fw.getPolicies.return_value = ["test-policy"]
            old = firewall_lib.FirewallClientPolicySettings({"disable": not desired})
            fw.config().getPolicyByName().getSettings.return_value = old
            fw.getPolicySettings.return_value = old
            params = self.params(
                state="enabled",
                is_disabled=desired,
                permanent=permanent,
                runtime=runtime,
            )
            assert self.run_config(self.module(check_mode), params)
            fw.reload.assert_not_called()
            assert fw.config().getPolicyByName().update.call_count == int(
                permanent and not check_mode
            )
            assert fw.setPolicySettings.call_count == int(runtime and not check_mode)
            if permanent and not check_mode:
                assert (
                    fw.config()
                    .getPolicyByName()
                    .update.call_args[0][0]
                    .getSettingsDict()["disable"]
                    == desired
                )
            if runtime and not check_mode:
                assert (
                    fw.setPolicySettings.call_args[0][1].getSettingsDict()["disable"]
                    == desired
                )
            current = firewall_lib.FirewallClientPolicySettings({"disable": desired})
            fw.config().getPolicyByName().getSettings.return_value = current
            fw.getPolicySettings.return_value = current
            fw.reset_mock()
            assert not self.run_config(self.module(check_mode), params)
            fw.config().getPolicyByName().update.assert_not_called()
            fw.setPolicySettings.assert_not_called()

    @pytest.mark.parametrize(
        "desired,explicit", [(True, True), (False, True), (False, False)]
    )
    @pytest.mark.parametrize("check_mode", [True, False])
    def test_is_disabled_offline(self, desired, check_mode, explicit):
        module = self.module(check_mode)
        current = not desired

        def command(cmd, check_rc=True):
            if cmd[-1] == "--get-policies":
                return 0, "test-policy", ""
            if cmd[-1] == "--query-disable":
                return (0, "yes", "") if current else (1, "no", "")
            if cmd[-1] == "--query-masquerade":
                return 1, "no", ""
            return 0, "", ""

        module.run_command.side_effect = command
        params = self.params(state="enabled")
        if explicit:
            params["is_disabled"] = desired
        changed = self.run_config(module, params, online=False)
        mutations = [
            entry[0][0][-1]
            for entry in module.run_command.call_args_list
            if entry[0][0][-1] in ("--add-disable", "--remove-disable")
        ]
        if explicit:
            assert changed
            assert mutations == (
                []
                if check_mode
                else ["--add-disable" if desired else "--remove-disable"]
            )
        else:
            assert not changed
            assert mutations == []
        current = desired if explicit else current
        module.run_command.reset_mock()
        assert not self.run_config(module, params, online=False)
        repeat = [
            entry[0][0][-1]
            for entry in module.run_command.call_args_list
            if entry[0][0][-1] in ("--add-disable", "--remove-disable")
        ]
        assert repeat == []

    @pytest.mark.parametrize("check_mode", [True, False])
    def test_create_disabled_policy_offline(self, check_mode):
        module = self.module(check_mode)
        module.run_command.return_value = (0, "", "")
        assert self.run_config(module, self.params(is_disabled=True), online=False)
        commands = [entry[0][0][-1] for entry in module.run_command.call_args_list]
        assert commands == (
            ["--get-policies"]
            if check_mode
            else ["--get-policies", "--new-policy=test-policy", "--add-disable"]
        )

    def test_is_disabled_unsupported_firewalld(self):
        with patch.object(firewall_lib, "FirewallClientPolicySettings", object):
            with pytest.raises(ValueError, match="does not support"):
                self.run_config(self.module(), self.params(is_disabled=True))
            module = self.module()
            module.run_command.return_value = (0, "test-policy", "")
            assert not self.run_config(
                module, self.params(state="enabled"), online=False
            )
            assert not any(
                arg.startswith(("--add-", "--remove-", "--new-", "--set-"))
                for entry in module.run_command.call_args_list
                for arg in entry[0][0]
            )
        assert "disable" not in firewall_lib.policy_settings(
            {"target": "CONTINUE"}, {"state": "enabled", "is_disabled": False}
        )

    @pytest.mark.parametrize("value", ["yes", 1, [], {}])
    def test_is_disabled_invalid_values(self, value):
        with pytest.raises(ValueError, match="must be a boolean"):
            self.run_config(self.module(), self.params(is_disabled=value))

    def test_is_disabled_requires_policy(self):
        with pytest.raises(ValueError, match="requires policy"):
            self.run_config(self.module(), {"is_disabled": True, "state": "enabled"})

    def test_absent_is_disabled_sets_flag_without_deleting(self):
        module = self.module(True)
        backend = self.memory(module)
        self.run_config(module, self.params(), backend)
        assert self.run_config(
            module, self.params(state="absent", is_disabled=True), backend
        )
        policy = backend.working_config_permanent["policies"]["test-policy"]
        assert policy["disable"] is True
        assert self.run_config(
            module, self.params(state="absent", is_disabled=False), backend
        )
        assert "test-policy" not in backend.working_config_permanent["policies"]

    def test_reload_discards_runtime_sources_and_preserves_interfaces(self):
        module = self.module()
        backend = self.memory(module)
        backend.working_config_runtime["zones"]["public"]["interfaces"] = ["eth0"]
        backend.working_config_permanent["zones"]["public"]["sources"] = [
            "198.51.100.0/24"
        ]
        backend.working_config_runtime["zones"]["public"]["sources"] = ["192.0.2.10"]
        backend.working_config_runtime["zones"]["public"]["services"] = ["http"]
        backend.working_config_runtime["zones"]["custom"] = {"interfaces": ["eth1"]}
        before_permanent = copy.deepcopy(backend.working_config_permanent)
        before_runtime = copy.deepcopy(backend.working_config_runtime)
        self.run_config(module, self.params(runtime=True, target="ACCEPT"), backend)
        diff = firewall_lib.get_diffs(
            before_permanent,
            before_runtime,
            "public",
            {},
            backend.working_config_permanent,
            backend.working_config_runtime,
            "public",
            {},
            False,
        )
        assert diff["runtime"]["removed"]["zones"]["public"]["sources"] == [
            "192.0.2.10"
        ]
        assert diff["runtime"]["added"]["zones"]["public"]["sources"] == [
            "198.51.100.0/24"
        ]
        public = backend.working_config_runtime["zones"]["public"]
        assert sorted(public["interfaces"]) == ["eth0", "eth1"]
        assert public["sources"] == ["198.51.100.0/24"]
        assert "services" not in public
        assert "custom" not in backend.working_config_runtime["zones"]
        assert (
            backend.working_config_runtime["policies"]["test-policy"]["target"]
            == "ACCEPT"
        )

    @pytest.mark.parametrize(
        "lists,params,message",
        [
            (
                {"--list-egress-zones": "HOST"},
                {"masquerade": True},
                "masquerade",
            ),
            (
                {"--list-egress-zones": "ANY"},
                {"forward_port": ["8080/tcp;80;"]},
                "requires toaddr",
            ),
            (
                {
                    "--list-egress-zones": "ANY",
                    "--list-forward-ports": "port=8080:proto=tcp:toport=80:toaddr=",
                },
                {"service": ["http"]},
                "requires toaddr",
            ),
        ],
    )
    def test_offline_constraints_run_before_changes(self, lists, params, message):
        module = self.module()

        def command(cmd, check_rc=True):
            if cmd[-1] == "--get-policies":
                return 0, "test-policy", ""
            if cmd[-1] == "--query-masquerade":
                return 1, "no", ""
            if cmd[-1] in lists:
                return 0, lists[cmd[-1]], ""
            return 0, "", ""

        module.run_command.side_effect = command
        with pytest.raises(ValueError, match=message):
            self.run_config(
                module, self.params(state="enabled", **params), online=False
            )
        for entry in module.run_command.call_args_list:
            assert not any(
                arg.startswith(("--add-", "--remove-", "--new-", "--set-"))
                for arg in entry[0][0]
            )

    @pytest.mark.parametrize("zone_key", ["ingress_zone", "egress_zone"])
    @pytest.mark.parametrize("check_mode", [False, True])
    def test_offline_clears_masquerade_before_adding_host(self, zone_key, check_mode):
        module = self.module(check_mode)
        current = {"masquerade": True, "zones": []}
        flag = zone_key.replace("_", "-")

        def command(cmd, check_rc=True):
            arg = cmd[-1]
            if arg == "--get-policies":
                return 0, "test-policy", ""
            if arg == "--query-masquerade":
                return (0 if current["masquerade"] else 1), "", ""
            if arg == "--list-" + flag + "s":
                return 0, " ".join(current["zones"]), ""
            if arg == "--query-" + flag + "=HOST":
                return (0 if "HOST" in current["zones"] else 1), "", ""
            if arg == "--remove-masquerade":
                current["masquerade"] = False
            if arg == "--add-" + flag + "=HOST":
                # firewalld rejects this intermediate state even if a later
                # command would clear masquerading.
                assert not current["masquerade"]
                current["zones"].append("HOST")
            return 0, "", ""

        module.run_command.side_effect = command
        params = self.params(state="enabled", masquerade=False, **{zone_key: "HOST"})
        assert self.run_config(module, params, online=False)
        if check_mode:
            assert current == {"masquerade": True, "zones": []}
        else:
            assert current == {"masquerade": False, "zones": ["HOST"]}
            assert not self.run_config(module, params, online=False)
