# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Rich Megginson <rmeggins@redhat.com>
# SPDX-License-Identifier: GPL-2.0-or-later
#
""" Unit tests for kernel_settings module """

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import unittest

try:
    from unittest.mock import call, MagicMock, Mock, patch
except ImportError:
    from mock import call, MagicMock, Mock, patch

import firewall_lib


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
        am.check_mode = False
        return am


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


class FirewallLibMain(unittest.TestCase):
    """Test main function."""

    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    def test_main_error_no_firewall_backend(self, am_class):
        with self.assertRaises(MockException):
            firewall_lib.main()
        am_class.return_value.fail_json.assert_called_with(
            msg="No firewall backend could be imported."
        )

    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_main_error_no_params(self, am_class):
        with self.assertRaises(MockException):
            firewall_lib.main()
        am_class.return_value.fail_json.assert_called_with(
            msg="One of service, port, source_port, forward_port, masquerade, rich_rule, source, "
            "interface, icmp_block, icmp_block_inversion, target or zone needs to be set"
        )

    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_main_error_timeout_icmp_block_inversion(self, am_class):
        am = am_class.return_value
        am.params = {"icmp_block_inversion": True, "timeout": 1}
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="timeout can not be used with icmp_block_inverson only"
        )

    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_main_error_timeout_source(self, am_class):
        am = am_class.return_value
        am.params = {"source": ["192.0.2.0/24"], "timeout": 1}
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(msg="timeout can not be used with source only")

    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_permanent_runtime_offline(self, am_class):
        am = am_class.return_value
        am.params = {
            "icmp_block_inversion": True,
            "permanent": False,
            "runtime": False,
            "offline": False,
        }
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="One of permanent, runtime or offline needs to be enabled"
        )

    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_timeout_with_disabled_state(self, am_class):
        am = am_class.return_value
        am.params = {"source": ["192.0.2.0/24"], "state": "disabled", "timeout": 1}
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="timeout can not be used with state: disabled"
        )

    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
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

    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
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

    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_main_error_timeout_interface(self, am_class):
        am = am_class.return_value
        am.params = {"interface": ["eth2"], "timeout": 1}
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="timeout can not be used with interface only"
        )

    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_main_error_timeout_target(self, am_class):
        am = am_class.return_value
        am.params = {"timeout": 1, "target": ""}
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(msg="timeout can not be used with target only")

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    def test_firewalld_running(self, am_class, firewall_class):
        am = am_class.return_value
        am.params = {
            "icmp_block_inversion": True,
            "permanent": False,
            "runtime": True,
            "offline": False,
        }
        fw = firewall_class.return_value
        fw.connected = False
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="Firewalld is not running and offline operation is declined."
        )

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.8", create=True)
    def test_firewalld_offline_version_disconnected(self, am_class, firewall_class):
        am = am_class.return_value
        am.params = {
            "icmp_block_inversion": True,
            "permanent": False,
            "offline": True,
        }
        fw = firewall_class.return_value
        fw.connected = False
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="Unsupported firewalld version 0.3.8, offline operation requires >= 0.3.9"
        )

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.2.8", create=True)
    def test_firewalld_offline_version_connected(self, am_class, firewall_class):
        am = am_class.return_value
        am.params = {
            "icmp_block_inversion": True,
            "permanent": False,
            "offline": True,
        }
        fw = firewall_class.return_value
        fw.connected = True
        with self.assertRaises(MockException):
            firewall_lib.main()
        am.fail_json.assert_called_with(
            msg="Unsupported firewalld version 0.2.8, requires >= 0.2.11"
        )

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_service_enabled_state(self, am_class, firewall_class):
        am = am_class.return_value
        am.params = {
            "permanent": False,
            "offline": True,
            "service": ["https", "ipsec", "ldaps"],
            "state": "enabled",
            "runtime": True,
            "timeout": 0,
        }
        fw = firewall_class.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        fw.queryService.return_value = False
        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        call_list = [
            call("default", "https", 0),
            call("default", "ipsec", 0),
            call("default", "ldaps", 0),
        ]
        self.assertEqual(call_list, fw.addService.call_args_list)
        am.exit_json.assert_called_once_with(changed=True)

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_service_disabled_state(self, am_class, firewall_class):
        am = am_class.return_value
        am.params = {
            "permanent": True,
            "offline": True,
            "service": ["https", "ipsec", "ldaps"],
            "state": "disabled",
            "runtime": False,
        }
        # firewall_class.set_params(True)
        fw = firewall_class.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        fw_settings.queryService.return_value = True

        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        call_list = [call("https"), call("ipsec"), call("ldaps")]
        self.assertEqual(call_list, fw_settings.removeService.call_args_list)
        am.exit_json.assert_called_once_with(changed=True)

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_port_enabled_state(self, am_class, firewall_class):
        am = am_class.return_value
        am.params = {
            "permanent": False,
            "offline": True,
            "port": ["8081/tcp", "161-162/udp"],
            "state": "enabled",
            "runtime": True,
            "timeout": 0,
        }
        fw = firewall_class.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        fw.queryPort.return_value = False
        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        call_list = [
            call("default", "8081", "tcp", 0),
            call("default", "161-162", "udp", 0),
        ]
        self.assertEqual(call_list, fw.addPort.call_args_list)
        am.exit_json.assert_called_once_with(changed=True)

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_port_disabled_state(self, am_class, firewall_class):
        am = am_class.return_value
        am.params = {
            "permanent": False,
            "offline": True,
            "port": ["8081/tcp", "161-162/udp"],
            "state": "disabled",
            "runtime": True,
        }
        fw = firewall_class.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        fw.queryPort.return_value = True
        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        call_list = [call("default", "8081", "tcp"), call("default", "161-162", "udp")]
        self.assertEqual(call_list, fw.removePort.call_args_list)
        am.exit_json.assert_called_once_with(changed=True)

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_source_port_enabled_state(self, am_class, firewall_class):
        am = am_class.return_value
        am.params = {
            "permanent": False,
            "offline": True,
            "source_port": ["8081/tcp", "161-162/udp"],
            "state": "enabled",
            "runtime": True,
            "timeout": 0,
        }
        fw = firewall_class.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        fw.querySourcePort.return_value = False
        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        call_list = [
            call("default", "8081", "tcp", 0),
            call("default", "161-162", "udp", 0),
        ]
        self.assertEqual(call_list, fw.addSourcePort.call_args_list)
        am.exit_json.assert_called_once_with(changed=True)

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_source_port_disabled_state(self, am_class, firewall_class):
        am = am_class.return_value
        am.params = {
            "permanent": False,
            "offline": True,
            "source_port": ["8081/tcp", "161-162/udp"],
            "state": "disabled",
            "runtime": True,
        }
        fw = firewall_class.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        fw.querySourcePort.return_value = True
        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        call_list = [call("default", "8081", "tcp"), call("default", "161-162", "udp")]
        self.assertEqual(call_list, fw.removeSourcePort.call_args_list)
        am.exit_json.assert_called_once_with(changed=True)

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_forward_port_enabled_state(self, am_class, firewall_class):
        am = am_class.return_value
        am.params = {
            "permanent": False,
            "offline": True,
            "forward_port": ["8081/tcp;port;addr", "161-162/udp;port;addr"],
            "state": "enabled",
            "runtime": True,
            "timeout": 0,
        }
        fw = firewall_class.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        fw.queryForwardPort.return_value = False
        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        call_list = [
            call("default", "8081", "tcp", "port", "addr", 0),
            call("default", "161-162", "udp", "port", "addr", 0),
        ]
        self.assertEqual(call_list, fw.addForwardPort.call_args_list)
        am.exit_json.assert_called_once_with(changed=True)

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_forward_port_disabled_state(self, am_class, firewall_class):
        am = am_class.return_value
        am.params = {
            "permanent": False,
            "offline": True,
            "forward_port": ["8081/tcp;port;addr", "161-162/udp;port;addr"],
            "state": "disabled",
            "runtime": True,
        }
        fw = firewall_class.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        fw.queryForwardPort.return_value = True
        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        call_list = [
            call("default", "8081", "tcp", "port", "addr"),
            call("default", "161-162", "udp", "port", "addr"),
        ]
        self.assertEqual(call_list, fw.removeForwardPort.call_args_list)
        am.exit_json.assert_called_once_with(changed=True)

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_masquerade_enabled_state(self, am_class, firewall_class):
        am = am_class.return_value
        am.params = {
            "permanent": False,
            "offline": True,
            "masquerade": True,
            "state": "enabled",
            "runtime": True,
        }
        fw = firewall_class.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        fw.queryMasquerade.return_value = False
        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        fw.addMasquerade.assert_called_once()
        am.exit_json.assert_called_once_with(changed=True)

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_masquerade_disabled_state(self, am_class, firewall_class):
        am = am_class.return_value
        am.params = {
            "permanent": False,
            "offline": True,
            "masquerade": False,
            "state": "enabled",
            "runtime": True,
        }
        fw = firewall_class.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        fw.queryMasquerade.return_value = True
        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        fw.removeMasquerade.assert_called_once()
        am.exit_json.assert_called_once_with(changed=True)

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.Rich_Rule", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_rich_rule_enabled_state(
        self, am_class, rich_rule_class, firewall_class
    ):
        am = am_class.return_value
        am.params = {
            "permanent": True,
            "offline": True,
            "rich_rule": ['rule protocol value="30" accept'],
            "state": "enabled",
            "runtime": True,
        }
        rule = rich_rule_class.return_value
        rule.__str__.return_value = 'rule protocol value="30" accept'
        fw = firewall_class.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        fw_settings.queryRichRule.return_value = False
        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        call_list = [call('rule protocol value="30" accept')]
        self.assertEqual(call_list, fw_settings.addRichRule.call_args_list)
        am.exit_json.assert_called_once_with(changed=True)

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.Rich_Rule", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_rich_rule_disabled_state(
        self, am_class, rich_rule_class, firewall_class
    ):
        am = am_class.return_value
        am.params = {
            "permanent": True,
            "offline": True,
            "rich_rule": ['rule protocol value="30" reject'],
            "state": "disabled",
            "runtime": False,
        }
        rule = rich_rule_class.return_value
        rule.__str__.return_value = 'rule protocol value="30" reject'
        fw = firewall_class.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        fw_settings.queryRichRule.return_value = True
        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        call_list = [call('rule protocol value="30" reject')]
        self.assertEqual(call_list, fw_settings.removeRichRule.call_args_list)
        am.exit_json.assert_called_once_with(changed=True)

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_source_enabled_state(self, am_class, firewall_class):
        am = am_class.return_value
        am.params = {
            "permanent": True,
            "offline": True,
            "source": ["192.0.2.0/24"],
            "state": "enabled",
            "runtime": False,
        }
        fw = firewall_class.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        fw_settings.querySource.return_value = False
        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        call_list = [call("192.0.2.0/24")]
        self.assertEqual(call_list, fw_settings.addSource.call_args_list)
        am.exit_json.assert_called_once_with(changed=True)

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_source_disabled_state(self, am_class, firewall_class):
        am = am_class.return_value
        am.params = {
            "permanent": True,
            "offline": True,
            "source": ["192.0.2.0/24"],
            "state": "disabled",
            "runtime": False,
        }
        fw = firewall_class.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        fw_settings.querySource.return_value = True
        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        call_list = [call("192.0.2.0/24")]
        self.assertEqual(call_list, fw_settings.removeSource.call_args_list)
        am.exit_json.assert_called_once_with(changed=True)

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_interface_enabled_state(self, am_class, firewall_class):
        am = am_class.return_value
        am.params = {
            "permanent": True,
            "offline": True,
            "interface": ["eth2"],
            "state": "enabled",
            "runtime": False,
        }
        fw = firewall_class.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        fw_settings.queryInterface.return_value = False
        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        call_list = [call("eth2")]
        self.assertEqual(call_list, fw_settings.addInterface.call_args_list)
        am.exit_json.assert_called_once_with(changed=True)

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_interface_disabled_state(self, am_class, firewall_class):
        am = am_class.return_value
        am.params = {
            "permanent": True,
            "offline": True,
            "interface": ["eth2"],
            "state": "disabled",
            "runtime": False,
        }
        fw = firewall_class.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        fw_settings.queryInterface.return_value = True
        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        call_list = [call("eth2")]
        self.assertEqual(call_list, fw_settings.removeInterface.call_args_list)
        am.exit_json.assert_called_once_with(changed=True)

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_icmp_block_inversion_enabled_state(
        self, am_class, firewall_class
    ):
        am = am_class.return_value
        am.params = {
            "permanent": True,
            "offline": True,
            "icmp_block_inversion": True,
            "runtime": False,
        }
        fw = firewall_class.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        fw_settings.queryIcmpBlockInversion.return_value = False
        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        fw_settings.addIcmpBlockInversion.assert_called_once()
        am.exit_json.assert_called_once_with(changed=True)

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_icmp_block_inversion_disabled_state(
        self, am_class, firewall_class
    ):
        am = am_class.return_value
        am.params = {
            "permanent": True,
            "icmp_block_inversion": False,
            "runtime": False,
        }
        fw = firewall_class.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        fw_settings.queryIcmpBlockInversion.return_value = True
        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        fw_settings.removeIcmpBlockInversion.assert_called_once()
        am.exit_json.assert_called_once_with(changed=True)

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_icmp_block_enabled_state(self, am_class, firewall_class):
        am = am_class.return_value
        am.params = {
            "permanent": True,
            "offline": True,
            "icmp_block": ["echo-request"],
            "state": "enabled",
            "runtime": False,
        }
        fw = firewall_class.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        fw_settings.queryIcmpBlock.return_value = False
        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        call_list = [call("echo-request")]
        self.assertEqual(call_list, fw_settings.addIcmpBlock.call_args_list)
        am.exit_json.assert_called_once_with(changed=True)

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_icmp_block_disabled_state(self, am_class, firewall_class):
        am = am_class.return_value
        am.params = {
            "permanent": True,
            "offline": True,
            "icmp_block": ["echo-request"],
            "state": "disabled",
            "runtime": False,
        }
        fw = firewall_class.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        fw_settings.queryIcmpBlock.return_value = True
        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        call_list = [call("echo-request")]
        self.assertEqual(call_list, fw_settings.removeIcmpBlock.call_args_list)
        am.exit_json.assert_called_once_with(changed=True)

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_firewall_target_enabled_state(self, am_class, firewall_class):
        am = am_class.return_value
        am.params = {
            "permanent": True,
            "offline": True,
            "target": "default",
            "state": "enabled",
            "runtime": False,
        }
        fw = firewall_class.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        fw_settings.getTarget.return_value = "ACCEPT"
        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        fw_settings.setTarget.assert_called_once()
        am.exit_json.assert_called_once_with(changed=True)

    @patch("firewall_lib.FirewallClient", create=True)
    @patch("firewall_lib.AnsibleModule", new_callable=MockAnsibleModule)
    @patch("firewall_lib.HAS_FIREWALLD", True)
    @patch("firewall_lib.FW_VERSION", "0.3.11", create=True)
    def test_apply_permanent_changes(self, am_class, firewall_class):
        am = am_class.return_value
        am.params = {
            "permanent": True,
            "offline": True,
            "target": None,
            "runtime": False,
            "icmp_block_inversion": True,
        }
        fw = firewall_class.return_value
        fw.connected = True
        fw.getDefaultZone = Mock(return_value="default")
        fw_config = Mock()
        fw.config.return_value = fw_config
        fw_zone = Mock()
        fw_config.getZoneByName.return_value = fw_zone
        fw_settings = Mock()
        fw_zone.getSettings.return_value = fw_settings
        firewall_lib.main()
        fw.setExceptionHandler.assert_called_once()
        fw_zone.update.assert_called_once()
        am.exit_json.assert_called_once_with(changed=False)
