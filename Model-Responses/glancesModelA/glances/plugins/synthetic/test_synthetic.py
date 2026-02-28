#
# This file is part of Glances.
#
# SPDX-FileCopyrightText: 2024 Nicolas Hennion <nicolas@nicolargo.com>
#
# SPDX-License-Identifier: LGPL-3.0-only
#

"""Unit tests for the Synthetic monitoring plugin.

This test file uses extensive mocking to avoid importing the full Glances
framework, which may have Python version compatibility issues.
"""

import time
import unittest
from unittest.mock import MagicMock, patch
from datetime import datetime
import sys

# Mock all glances modules before any imports
mock_logger = MagicMock()
mock_timer = MagicMock()


class MockCounter:
    """Mock Counter class from timer module."""
    def __init__(self):
        self._start = time.time()

    def get(self):
        return time.time() - self._start


mock_timer.Counter = MockCounter

# Set up the module mocks
sys.modules['glances'] = MagicMock()
sys.modules['glances.logger'] = MagicMock()
sys.modules['glances.logger'].logger = MagicMock()
sys.modules['glances.timer'] = mock_timer


class MockGlancesPluginModel:
    """Mock base class for the plugin."""

    def __init__(self, args=None, config=None, stats_init_value=None, fields_description=None):
        self.args = args
        self.config = config
        self.stats_init_value = stats_init_value or []
        self.fields_description = fields_description or {}
        self.stats = []
        self.plugin_name = 'synthetic'
        self.display_curse = False
        self._limits = {}
        self.views = {}
        self.input_method = 'local'

    def is_disabled(self):
        return False

    def is_enabled(self):
        return True

    def get_init_value(self):
        return self.stats_init_value.copy() if isinstance(self.stats_init_value, list) else {}

    def curse_add_line(self, msg, decoration="DEFAULT", optional=False, additional=False, splittable=False):
        return {'msg': msg, 'decoration': decoration, 'optional': optional}

    def curse_new_line(self):
        return self.curse_add_line('\n')

    def exit(self):
        pass

    @staticmethod
    def _check_decorator(func):
        return func

    @staticmethod
    def _log_result_decorator(func):
        return func


sys.modules['glances.plugins'] = MagicMock()
sys.modules['glances.plugins.plugin'] = MagicMock()
sys.modules['glances.plugins.plugin.model'] = MagicMock()
sys.modules['glances.plugins.plugin.model'].GlancesPluginModel = MockGlancesPluginModel

# Now import the plugin source code directly
import importlib.util
import os

plugin_path = os.path.join(os.path.dirname(__file__), '..', 'inputs', 'glances', 'plugins', 'synthetic', '__init__.py')
spec = importlib.util.spec_from_file_location("synthetic_plugin", plugin_path)
synthetic_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(synthetic_module)

SyntheticPlugin = synthetic_module.SyntheticPlugin
fields_description = synthetic_module.fields_description
DEFAULT_REFRESH = synthetic_module.DEFAULT_REFRESH
DEFAULT_TIMEOUT = synthetic_module.DEFAULT_TIMEOUT
DEFAULT_HTTP_METHOD = synthetic_module.DEFAULT_HTTP_METHOD
DEFAULT_SQL_QUERY = synthetic_module.DEFAULT_SQL_QUERY
REQUESTS_AVAILABLE = synthetic_module.REQUESTS_AVAILABLE


class MockConfig:
    """Mock configuration object for testing."""

    def __init__(self, config_data=None):
        self._data = config_data or {}

    def has_section(self, section):
        return section in self._data

    def get_value(self, section, option, default=None):
        if section in self._data and option in self._data[section]:
            return self._data[section][option]
        return default

    def get_int_value(self, section, option, default=0):
        value = self.get_value(section, option, default)
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def get_bool_value(self, section, option, default=True):
        value = self.get_value(section, option, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', '1', 'yes')
        return default


class MockArgs:
    """Mock arguments object for testing."""

    def __init__(self):
        self.time = 2
        self.disable_history = True
        self.disable_synthetic = False


class TestSyntheticPlugin(unittest.TestCase):
    """Test cases for the Synthetic plugin."""

    def setUp(self):
        """Set up test fixtures."""
        self.args = MockArgs()

    def test_plugin_initialization_no_config(self):
        """Test plugin initializes correctly without configuration."""
        plugin = SyntheticPlugin(args=self.args, config=None)

        self.assertEqual(plugin.plugin_name, 'synthetic')
        self.assertEqual(plugin._probes, [])
        self.assertTrue(plugin.display_curse)

    def test_plugin_initialization_empty_section(self):
        """Test plugin initializes with empty synthetic section."""
        config = MockConfig({'synthetic': {}})
        plugin = SyntheticPlugin(args=self.args, config=config)

        self.assertEqual(plugin._probes, [])

    def test_plugin_load_http_probe(self):
        """Test loading HTTP probe from configuration."""
        config = MockConfig({
            'synthetic': {
                'refresh': '30',
                'timeout': '10',
                'http_1_url': 'https://example.com/health',
                'http_1_label': 'Example API',
                'http_1_method': 'GET',
                'http_1_expected_status': '200',
            }
        })
        plugin = SyntheticPlugin(args=self.args, config=config)

        self.assertEqual(len(plugin._probes), 1)
        probe = plugin._probes[0]
        self.assertEqual(probe['type'], 'http')
        self.assertEqual(probe['url'], 'https://example.com/health')
        self.assertEqual(probe['label'], 'Example API')
        self.assertEqual(probe['method'], 'GET')
        self.assertEqual(probe['expected_status'], 200)

    def test_plugin_load_sql_probe(self):
        """Test loading SQL probe from configuration."""
        config = MockConfig({
            'synthetic': {
                'sql_1_connection': 'postgresql://localhost/test',
                'sql_1_label': 'Test DB',
                'sql_1_db_type': 'postgresql',
                'sql_1_query': 'SELECT 1',
            }
        })
        plugin = SyntheticPlugin(args=self.args, config=config)

        self.assertEqual(len(plugin._probes), 1)
        probe = plugin._probes[0]
        self.assertEqual(probe['type'], 'sql')
        self.assertEqual(probe['connection'], 'postgresql://localhost/test')
        self.assertEqual(probe['label'], 'Test DB')
        self.assertEqual(probe['db_type'], 'postgresql')

    def test_plugin_load_multiple_probes(self):
        """Test loading multiple probes from configuration."""
        config = MockConfig({
            'synthetic': {
                'http_1_url': 'https://api1.example.com',
                'http_1_label': 'API 1',
                'http_2_url': 'https://api2.example.com',
                'http_2_label': 'API 2',
                'sql_1_connection': 'sqlite:///test.db',
                'sql_1_label': 'SQLite DB',
                'sql_1_db_type': 'sqlite',
            }
        })
        plugin = SyntheticPlugin(args=self.args, config=config)

        self.assertEqual(len(plugin._probes), 3)

    def test_get_key(self):
        """Test get_key returns 'label'."""
        plugin = SyntheticPlugin(args=self.args, config=None)
        self.assertEqual(plugin.get_key(), 'label')

    def test_get_alert_ok(self):
        """Test get_alert returns OK for successful probe."""
        plugin = SyntheticPlugin(args=self.args, config=None)
        probe = {'status': 'OK', 'latency_ms': 100}
        self.assertEqual(plugin.get_alert(probe), 'OK')

    def test_get_alert_timeout(self):
        """Test get_alert returns WARNING for timeout."""
        plugin = SyntheticPlugin(args=self.args, config=None)
        probe = {'status': 'TIMEOUT'}
        self.assertEqual(plugin.get_alert(probe), 'WARNING')

    def test_get_alert_error(self):
        """Test get_alert returns CRITICAL for error."""
        plugin = SyntheticPlugin(args=self.args, config=None)
        probe = {'status': 'ERROR'}
        self.assertEqual(plugin.get_alert(probe), 'CRITICAL')

    def test_get_alert_pending(self):
        """Test get_alert returns CAREFUL for pending check."""
        plugin = SyntheticPlugin(args=self.args, config=None)
        probe = {'status': None}
        self.assertEqual(plugin.get_alert(probe), 'CAREFUL')

    def test_get_probe_stats_format(self):
        """Test that probe stats have required keys."""
        config = MockConfig({
            'synthetic': {
                'http_1_url': 'https://example.com',
                'http_1_label': 'Test',
            }
        })
        plugin = SyntheticPlugin(args=self.args, config=config)

        # Set some values on the probe
        plugin._probes[0]['status'] = 'OK'
        plugin._probes[0]['latency_ms'] = 50.5
        plugin._probes[0]['last_check_timestamp'] = datetime.now().isoformat()

        stats = plugin._get_probe_stats()

        self.assertEqual(len(stats), 1)
        stat = stats[0]

        # Check required keys
        self.assertIn('label', stat)
        self.assertIn('status', stat)
        self.assertIn('latency_ms', stat)
        self.assertIn('last_check_timestamp', stat)
        self.assertEqual(stat['label'], 'Test')
        self.assertEqual(stat['status'], 'OK')
        self.assertEqual(stat['latency_ms'], 50.5)

    def test_http_probe_execution_success(self):
        """Test successful HTTP probe execution."""
        if not REQUESTS_AVAILABLE:
            self.skipTest("requests library not available")

        config = MockConfig({
            'synthetic': {
                'http_1_url': 'https://example.com',
                'http_1_label': 'Test',
            }
        })
        plugin = SyntheticPlugin(args=self.args, config=config)

        # Mock successful response
        with patch.object(synthetic_module, 'requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.request.return_value = mock_response

            plugin._run_http_probe(plugin._probes[0])

            self.assertEqual(plugin._probes[0]['status'], 'OK')
            self.assertIsNotNone(plugin._probes[0]['latency_ms'])
            self.assertEqual(plugin._probes[0]['status_code'], 200)

    def test_http_probe_execution_timeout(self):
        """Test HTTP probe timeout handling."""
        if not REQUESTS_AVAILABLE:
            self.skipTest("requests library not available")

        import requests

        config = MockConfig({
            'synthetic': {
                'http_1_url': 'https://example.com',
                'http_1_label': 'Test',
                'http_1_timeout': '5',
            }
        })
        plugin = SyntheticPlugin(args=self.args, config=config)

        with patch.object(synthetic_module, 'requests') as mock_requests:
            mock_requests.exceptions = requests.exceptions
            mock_requests.request.side_effect = requests.exceptions.Timeout()

            plugin._run_http_probe(plugin._probes[0])

            self.assertEqual(plugin._probes[0]['status'], 'TIMEOUT')

    def test_http_probe_wrong_status_code(self):
        """Test HTTP probe with unexpected status code."""
        if not REQUESTS_AVAILABLE:
            self.skipTest("requests library not available")

        config = MockConfig({
            'synthetic': {
                'http_1_url': 'https://example.com',
                'http_1_label': 'Test',
                'http_1_expected_status': '200',
            }
        })
        plugin = SyntheticPlugin(args=self.args, config=config)

        with patch.object(synthetic_module, 'requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_requests.request.return_value = mock_response

            plugin._run_http_probe(plugin._probes[0])

            self.assertEqual(plugin._probes[0]['status'], 'ERROR')
            self.assertIn('Expected 200', plugin._probes[0]['error_message'])

    def test_parse_mysql_connection_string(self):
        """Test MySQL connection string parsing."""
        plugin = SyntheticPlugin(args=self.args, config=None)

        # Test full connection string
        result = plugin._parse_mysql_connection('user:password@localhost:3306/mydb')
        self.assertEqual(result.get('user'), 'user')
        self.assertEqual(result.get('password'), 'password')
        self.assertEqual(result.get('host'), 'localhost')
        self.assertEqual(result.get('port'), 3306)
        self.assertEqual(result.get('database'), 'mydb')

    def test_msg_curse_empty(self):
        """Test curse output with no probes."""
        plugin = SyntheticPlugin(args=self.args, config=None)
        plugin.stats = []

        result = plugin.msg_curse(args=self.args, max_width=80)
        self.assertEqual(result, [])

    def test_msg_curse_with_probes(self):
        """Test curse output with probes."""
        config = MockConfig({
            'synthetic': {
                'http_1_url': 'https://example.com',
                'http_1_label': 'Test API',
            }
        })
        plugin = SyntheticPlugin(args=self.args, config=config)

        # Set up stats
        plugin.stats = [{
            'label': 'Test API',
            'status': 'OK',
            'latency_ms': 42.5,
            'type': 'http',
        }]

        result = plugin.msg_curse(args=self.args, max_width=80)

        # Should have header and at least one data row
        self.assertGreater(len(result), 0)

        # Check that we have the title
        title_found = any(
            'SYNTHETIC' in str(item.get('msg', ''))
            for item in result
        )
        self.assertTrue(title_found)

    def test_fields_description_complete(self):
        """Test that fields_description is properly defined."""
        required_fields = ['label', 'status', 'latency_ms', 'last_check_timestamp']
        for field in required_fields:
            self.assertIn(field, fields_description)
            self.assertIn('description', fields_description[field])

    def test_http_probe_default_label(self):
        """Test HTTP probe uses URL as default label."""
        config = MockConfig({
            'synthetic': {
                'http_1_url': 'https://example.com/api',
            }
        })
        plugin = SyntheticPlugin(args=self.args, config=config)

        self.assertEqual(len(plugin._probes), 1)
        probe = plugin._probes[0]
        self.assertEqual(probe['label'], 'https://example.com/api')

    def test_http_probe_custom_headers(self):
        """Test HTTP probe with custom headers parsing."""
        config = MockConfig({
            'synthetic': {
                'http_1_url': 'https://example.com',
                'http_1_label': 'Test',
                'http_1_headers': 'Authorization:Bearer token,X-Custom:value',
            }
        })
        plugin = SyntheticPlugin(args=self.args, config=config)

        probe = plugin._probes[0]
        self.assertIn('headers', probe)
        self.assertEqual(probe['headers'].get('Authorization'), 'Bearer token')
        self.assertEqual(probe['headers'].get('X-Custom'), 'value')

    def test_sql_probe_default_query(self):
        """Test SQL probe uses default query."""
        config = MockConfig({
            'synthetic': {
                'sql_1_connection': 'postgresql://localhost/test',
                'sql_1_label': 'Test DB',
                'sql_1_db_type': 'postgresql',
            }
        })
        plugin = SyntheticPlugin(args=self.args, config=config)

        probe = plugin._probes[0]
        self.assertEqual(probe['query'], DEFAULT_SQL_QUERY)

    def test_plugin_update_returns_stats(self):
        """Test update method returns probe stats."""
        config = MockConfig({
            'synthetic': {
                'http_1_url': 'https://example.com',
                'http_1_label': 'Test',
            }
        })
        plugin = SyntheticPlugin(args=self.args, config=config)

        # Mock thread to avoid actual execution
        with patch.object(plugin, '_run_probes'):
            plugin.input_method = 'local'
            result = plugin.update()

        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['label'], 'Test')


class TestConstants(unittest.TestCase):
    """Test module constants."""

    def test_default_values(self):
        """Test default configuration values."""
        self.assertEqual(DEFAULT_REFRESH, 30)
        self.assertEqual(DEFAULT_TIMEOUT, 10)
        self.assertEqual(DEFAULT_HTTP_METHOD, 'GET')
        self.assertEqual(DEFAULT_SQL_QUERY, 'SELECT 1')


class TestProbeStatusOutput(unittest.TestCase):
    """Test probe status output formatting."""

    def setUp(self):
        self.args = MockArgs()

    def test_status_display_ok(self):
        """Test OK status displays latency."""
        config = MockConfig({
            'synthetic': {
                'http_1_url': 'https://example.com',
                'http_1_label': 'Test',
            }
        })
        plugin = SyntheticPlugin(args=self.args, config=config)
        plugin.stats = [{
            'label': 'Test',
            'status': 'OK',
            'latency_ms': 42.5,
            'type': 'http',
        }]

        result = plugin.msg_curse(args=self.args, max_width=80)

        # Find the latency display
        latency_found = any(
            '42ms' in str(item.get('msg', '')) or '43ms' in str(item.get('msg', ''))
            for item in result
        )
        self.assertTrue(latency_found)

    def test_status_display_timeout(self):
        """Test TIMEOUT status displays appropriately."""
        config = MockConfig({
            'synthetic': {
                'http_1_url': 'https://example.com',
                'http_1_label': 'Test',
            }
        })
        plugin = SyntheticPlugin(args=self.args, config=config)
        plugin.stats = [{
            'label': 'Test',
            'status': 'TIMEOUT',
            'latency_ms': None,
            'type': 'http',
        }]

        result = plugin.msg_curse(args=self.args, max_width=80)

        # Find the timeout display
        timeout_found = any(
            'Timeout' in str(item.get('msg', ''))
            for item in result
        )
        self.assertTrue(timeout_found)

    def test_status_display_error(self):
        """Test ERROR status displays appropriately."""
        config = MockConfig({
            'synthetic': {
                'http_1_url': 'https://example.com',
                'http_1_label': 'Test',
            }
        })
        plugin = SyntheticPlugin(args=self.args, config=config)
        plugin.stats = [{
            'label': 'Test',
            'status': 'ERROR',
            'latency_ms': None,
            'type': 'http',
        }]

        result = plugin.msg_curse(args=self.args, max_width=80)

        # Find the error display
        error_found = any(
            'Error' in str(item.get('msg', ''))
            for item in result
        )
        self.assertTrue(error_found)


if __name__ == '__main__':
    unittest.main()
