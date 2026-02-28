#!/usr/bin/env python
#
# This file is part of Glances.
#
# SPDX-FileCopyrightText: 2024 Nicolas Hennion <nicolas@nicolargo.com>
#
# SPDX-License-Identifier: LGPL-3.0-only
#

"""Unit tests for the Synthetic monitoring plugin."""

from __future__ import annotations

import time
import unittest
from unittest.mock import MagicMock, Mock, patch, PropertyMock
import threading

import sys
import os

# Check for optional dependencies
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import sqlalchemy
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False


class MockLogger:
    """Mock logger for testing."""
    def debug(self, *args, **kwargs): pass
    def info(self, *args, **kwargs): pass
    def warning(self, *args, **kwargs): pass
    def error(self, *args, **kwargs): pass


class MockCounter:
    """Mock Counter class."""
    def __init__(self):
        self._start = time.time()

    def start(self):
        self._start = time.time()

    def get(self):
        return time.time() - self._start


class MockGlancesPluginModel:
    """Mock GlancesPluginModel for standalone testing."""

    def __init__(self, args=None, config=None, stats_init_value=None, fields_description=None, items_history_list=None):
        self.args = args
        self.config = config
        self.stats = stats_init_value if stats_init_value is not None else []
        self.fields_description = fields_description
        self.plugin_name = 'synthetic'
        self.display_curse = True
        self._limits = {}
        self.input_method = 'local'

    def is_disabled(self):
        return False

    def get_stat_name(self, header=None):
        return f"{self.plugin_name}_{header}" if header else self.plugin_name

    def manage_threshold(self, stat_name, ret):
        pass

    def curse_add_line(self, msg, decoration="DEFAULT", optional=False, additional=False, splittable=False):
        return {'msg': msg, 'decoration': decoration, 'optional': optional, 'additional': additional, 'splittable': splittable}

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


# Define fields_description here for standalone testing
fields_description = {
    'label': {'description': 'User-defined label for the probe.'},
    'type': {'description': 'Probe type (http or sql).'},
    'target': {'description': 'Target URL or connection string.'},
    'status': {'description': 'Probe status (ok, error, timeout, or scanning).'},
    'latency_ms': {'description': 'Response latency in milliseconds.', 'unit': 'ms'},
    'last_check_timestamp': {'description': 'Unix timestamp of the last check.'},
    'status_code': {'description': 'HTTP status code (for HTTP probes only).'},
    'error_message': {'description': 'Error message if probe failed.'},
}


class ProbeScanner(threading.Thread):
    """Thread for running synthetic probes - copy from plugin for testing."""

    def __init__(self, probes):
        super().__init__()
        self.daemon = True
        self._stopper = threading.Event()
        self._probes = probes

    def run(self):
        for probe in self._probes:
            if self.stopped():
                break
            if probe['type'] == 'http':
                self._run_http_probe(probe)
            elif probe['type'] == 'sql':
                self._run_sql_probe(probe)
            probe['key'] = 'indice'

    def stop(self):
        self._stopper.set()

    def stopped(self):
        return self._stopper.is_set()

    def _run_http_probe(self, probe):
        if not REQUESTS_AVAILABLE:
            probe['status'] = 'error'
            probe['error_message'] = 'requests library not available'
            probe['last_check_timestamp'] = time.time()
            return

        try:
            counter = MockCounter()

            method = probe.get('method', 'GET')
            if method == 'HEAD':
                response = requests.head(
                    probe['target'],
                    timeout=probe['timeout'],
                    verify=probe.get('ssl_verify', True),
                    allow_redirects=True
                )
            else:
                response = requests.get(
                    probe['target'],
                    timeout=probe['timeout'],
                    verify=probe.get('ssl_verify', True),
                    allow_redirects=True
                )

            latency_seconds = counter.get()
            probe['latency_ms'] = latency_seconds * 1000
            probe['status_code'] = response.status_code
            probe['last_check_timestamp'] = time.time()

            expected_status = probe.get('expected_status', 200)
            if response.status_code == expected_status:
                probe['status'] = 'ok'
                probe['error_message'] = None
            else:
                probe['status'] = 'error'
                probe['error_message'] = f'Unexpected status code: {response.status_code}'

        except requests.Timeout:
            probe['status'] = 'timeout'
            probe['latency_ms'] = None
            probe['error_message'] = 'Request timed out'
            probe['last_check_timestamp'] = time.time()
        except requests.RequestException as e:
            probe['status'] = 'error'
            probe['latency_ms'] = None
            probe['error_message'] = str(e)
            probe['last_check_timestamp'] = time.time()
        except Exception as e:
            probe['status'] = 'error'
            probe['latency_ms'] = None
            probe['error_message'] = str(e)
            probe['last_check_timestamp'] = time.time()

    def _run_sql_probe(self, probe):
        if not SQLALCHEMY_AVAILABLE:
            probe['status'] = 'error'
            probe['error_message'] = 'sqlalchemy library not available'
            probe['last_check_timestamp'] = time.time()
            return

        from sqlalchemy import create_engine, text

        engine = None
        connection = None

        try:
            counter = MockCounter()

            engine = create_engine(
                probe['target'],
                connect_args={'connect_timeout': probe['timeout']}
                if 'sqlite' not in probe['target'].lower()
                else {}
            )

            connection = engine.connect()
            query = probe.get('query', 'SELECT 1')
            connection.execute(text(query))

            latency_seconds = counter.get()
            probe['latency_ms'] = latency_seconds * 1000
            probe['status'] = 'ok'
            probe['error_message'] = None
            probe['last_check_timestamp'] = time.time()

        except Exception as e:
            error_str = str(e).lower()
            if 'timeout' in error_str or 'timed out' in error_str:
                probe['status'] = 'timeout'
            else:
                probe['status'] = 'error'
            probe['latency_ms'] = None
            probe['error_message'] = str(e)
            probe['last_check_timestamp'] = time.time()
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass
            if engine is not None:
                try:
                    engine.dispose()
                except Exception:
                    pass


class SyntheticPlugin(MockGlancesPluginModel):
    """Synthetic plugin implementation for testing."""

    _section = 'synthetic'

    def __init__(self, args=None, config=None):
        super().__init__(
            args=args,
            config=config,
            stats_init_value=[],
            fields_description=fields_description
        )
        self.args = args
        self.config = config
        self.display_curse = True
        self._probes = self._load_probes(config)
        self._thread = None

    def _load_probes(self, config):
        probes = []

        if config is None:
            return probes

        if not config.has_section(self._section):
            return probes

        default_refresh = config.get_int_value(self._section, 'refresh', default=60)
        default_timeout = config.get_int_value(self._section, 'timeout', default=10)

        # Load HTTP probes
        for i in range(1, 256):
            prefix = f'http_{i}_'
            url = config.get_value(self._section, f'{prefix}url')

            if url is None:
                continue

            probe = {
                'type': 'http',
                'label': config.get_value(self._section, f'{prefix}label', default=url),
                'target': url,
                'method': config.get_value(self._section, f'{prefix}method', default='GET').upper(),
                'timeout': config.get_int_value(self._section, f'{prefix}timeout', default=default_timeout),
                'refresh': config.get_int_value(self._section, f'{prefix}refresh', default=default_refresh),
                'expected_status': config.get_int_value(self._section, f'{prefix}expected_status', default=200),
                'ssl_verify': config.get_bool_value(self._section, f'{prefix}ssl_verify', default=True),
                'indice': f'http_{i}',
                'status': None,
                'latency_ms': None,
                'last_check_timestamp': None,
                'status_code': None,
                'error_message': None,
            }
            probes.append(probe)

        # Load SQL probes
        for i in range(1, 256):
            prefix = f'sql_{i}_'
            connection_string = config.get_value(self._section, f'{prefix}connection_string')

            if connection_string is None:
                continue

            probe = {
                'type': 'sql',
                'label': config.get_value(self._section, f'{prefix}label', default=f'sql_{i}'),
                'target': connection_string,
                'query': config.get_value(self._section, f'{prefix}query', default='SELECT 1'),
                'timeout': config.get_int_value(self._section, f'{prefix}timeout', default=default_timeout),
                'refresh': config.get_int_value(self._section, f'{prefix}refresh', default=default_refresh),
                'indice': f'sql_{i}',
                'status': None,
                'latency_ms': None,
                'last_check_timestamp': None,
                'error_message': None,
            }
            probes.append(probe)

        return probes

    def exit(self):
        if self._thread is not None:
            self._thread.stop()
        super().exit()

    def get_key(self):
        return 'indice'

    def update(self):
        if self.input_method == 'local':
            thread_is_running = self._thread is not None and self._thread.is_alive()
            if not thread_is_running and self._probes:
                self._thread = ProbeScanner(self._probes)
                self._thread.start()
            self.stats = self._probes
        else:
            self.stats = []
        return self.stats

    def get_alert(self, probe, header=None, log=False):
        status = probe.get('status')
        if status is None:
            ret = 'CAREFUL'
        elif status == 'ok':
            ret = 'OK'
        elif status == 'error':
            ret = 'CRITICAL'
        elif status == 'timeout':
            ret = 'WARNING'
        else:
            ret = 'DEFAULT'
        stat_name = self.get_stat_name(header=header)
        self.manage_threshold(stat_name, ret)
        return ret

    def msg_curse(self, args=None, max_width=None):
        ret = []
        if not self.stats or self.is_disabled():
            return ret
        if max_width:
            name_max_width = max_width - 12
        else:
            return ret

        msg = '{:{width}}'.format('SYNTHETIC', width=name_max_width)
        ret.append(self.curse_add_line(msg, "TITLE"))
        msg = '{:>12}'.format('Latency')
        ret.append(self.curse_add_line(msg))

        for probe in self.stats:
            ret.append(self.curse_new_line())
            label = probe.get('label', probe.get('indice', 'unknown'))
            if len(label) > name_max_width:
                label = label[:name_max_width - 1] + '…'
            msg = '{:{width}}'.format(label, width=name_max_width)
            ret.append(self.curse_add_line(msg))

            status = probe.get('status')
            latency = probe.get('latency_ms')

            if status is None:
                latency_str = 'Scanning'
            elif status == 'ok' and latency is not None:
                latency_str = f'{latency:.0f}ms'
            elif status == 'timeout':
                latency_str = 'Timeout'
            elif status == 'error':
                latency_str = 'Error'
            else:
                latency_str = 'N/A'

            msg = '{:>12}'.format(latency_str)
            ret.append(self.curse_add_line(msg, self.get_alert(probe, header=probe.get('indice', ''))))

        return ret


class MockConfig:
    """Mock configuration object for testing."""

    def __init__(self, sections=None):
        self._sections = sections or {}

    def has_section(self, section):
        return section in self._sections

    def get_value(self, section, key, default=None):
        if section in self._sections:
            return self._sections[section].get(key, default)
        return default

    def get_int_value(self, section, key, default=0):
        value = self.get_value(section, key, default)
        if value is None:
            return default
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    def get_bool_value(self, section, key, default=True):
        value = self.get_value(section, key, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', '1', 'yes')
        return default

    def get_float_value(self, section, key, default=0.0):
        value = self.get_value(section, key, default)
        if value is None:
            return default
        try:
            return float(value)
        except (ValueError, TypeError):
            return default

    def items(self, section):
        return self._sections.get(section, {}).items()


class MockArgs:
    """Mock args object for testing."""

    def __init__(self):
        self.disable_synthetic = False
        self.enable_synthetic = True
        self.disable_history = True
        self.time = 2


class TestFieldsDescription(unittest.TestCase):
    """Test field descriptions are properly defined."""

    def test_required_fields_present(self):
        """Test that all required fields are defined."""
        required_fields = ['label', 'status', 'latency_ms', 'last_check_timestamp']
        for field in required_fields:
            self.assertIn(field, fields_description, f"Field '{field}' missing from fields_description")

    def test_fields_have_description(self):
        """Test that all fields have descriptions."""
        for field, info in fields_description.items():
            self.assertIn('description', info, f"Field '{field}' missing 'description' key")
            self.assertIsInstance(info['description'], str, f"Field '{field}' description is not a string")


class TestSyntheticPluginInit(unittest.TestCase):
    """Test SyntheticPlugin initialization."""

    def test_init_without_config(self):
        """Test plugin initialization without config."""
        args = MockArgs()
        plugin = SyntheticPlugin(args=args, config=None)

        self.assertEqual(plugin.stats, [])
        self.assertTrue(plugin.display_curse)

    def test_init_without_section(self):
        """Test plugin initialization when section is missing."""
        args = MockArgs()
        config = MockConfig(sections={})
        plugin = SyntheticPlugin(args=args, config=config)

        self.assertEqual(plugin._probes, [])

    def test_init_with_http_probes(self):
        """Test plugin initialization with HTTP probes."""
        args = MockArgs()
        config = MockConfig(sections={
            'synthetic': {
                'refresh': '60',
                'timeout': '10',
                'http_1_url': 'https://example.com/health',
                'http_1_label': 'Example API',
                'http_1_method': 'GET',
                'http_1_timeout': '5',
                'http_1_expected_status': '200',
            }
        })
        plugin = SyntheticPlugin(args=args, config=config)

        self.assertEqual(len(plugin._probes), 1)
        probe = plugin._probes[0]
        self.assertEqual(probe['type'], 'http')
        self.assertEqual(probe['label'], 'Example API')
        self.assertEqual(probe['target'], 'https://example.com/health')
        self.assertEqual(probe['method'], 'GET')
        self.assertEqual(probe['timeout'], 5)
        self.assertEqual(probe['expected_status'], 200)

    def test_init_with_sql_probes(self):
        """Test plugin initialization with SQL probes."""
        args = MockArgs()
        config = MockConfig(sections={
            'synthetic': {
                'refresh': '60',
                'timeout': '10',
                'sql_1_connection_string': 'postgresql://user:pass@localhost/db',
                'sql_1_label': 'Primary DB',
                'sql_1_query': 'SELECT 1',
            }
        })
        plugin = SyntheticPlugin(args=args, config=config)

        self.assertEqual(len(plugin._probes), 1)
        probe = plugin._probes[0]
        self.assertEqual(probe['type'], 'sql')
        self.assertEqual(probe['label'], 'Primary DB')
        self.assertEqual(probe['target'], 'postgresql://user:pass@localhost/db')
        self.assertEqual(probe['query'], 'SELECT 1')

    def test_init_with_mixed_probes(self):
        """Test plugin initialization with both HTTP and SQL probes."""
        args = MockArgs()
        config = MockConfig(sections={
            'synthetic': {
                'http_1_url': 'https://example.com',
                'http_1_label': 'HTTP Probe',
                'sql_1_connection_string': 'sqlite:///test.db',
                'sql_1_label': 'SQL Probe',
            }
        })
        plugin = SyntheticPlugin(args=args, config=config)

        self.assertEqual(len(plugin._probes), 2)
        types = {p['type'] for p in plugin._probes}
        self.assertEqual(types, {'http', 'sql'})


class TestSyntheticPluginMethods(unittest.TestCase):
    """Test SyntheticPlugin methods."""

    def setUp(self):
        """Set up test fixtures."""
        self.args = MockArgs()
        self.config = MockConfig(sections={
            'synthetic': {
                'http_1_url': 'https://example.com',
                'http_1_label': 'Test Probe',
            }
        })
        self.plugin = SyntheticPlugin(args=self.args, config=self.config)

    def test_get_key(self):
        """Test get_key returns correct key."""
        self.assertEqual(self.plugin.get_key(), 'indice')

    def test_get_alert_ok_status(self):
        """Test get_alert returns OK for successful probe."""
        probe = {'status': 'ok', 'indice': 'test_1'}
        alert = self.plugin.get_alert(probe)
        self.assertEqual(alert, 'OK')

    def test_get_alert_error_status(self):
        """Test get_alert returns CRITICAL for error status."""
        probe = {'status': 'error', 'indice': 'test_1'}
        alert = self.plugin.get_alert(probe)
        self.assertEqual(alert, 'CRITICAL')

    def test_get_alert_timeout_status(self):
        """Test get_alert returns WARNING for timeout status."""
        probe = {'status': 'timeout', 'indice': 'test_1'}
        alert = self.plugin.get_alert(probe)
        self.assertEqual(alert, 'WARNING')

    def test_get_alert_none_status(self):
        """Test get_alert returns CAREFUL for None status."""
        probe = {'status': None, 'indice': 'test_1'}
        alert = self.plugin.get_alert(probe)
        self.assertEqual(alert, 'CAREFUL')


class TestProbeScanner(unittest.TestCase):
    """Test ProbeScanner thread."""

    def test_scanner_initialization(self):
        """Test ProbeScanner initializes correctly."""
        probes = [{'type': 'http', 'label': 'test', 'target': 'http://example.com'}]
        scanner = ProbeScanner(probes)

        self.assertTrue(scanner.daemon)
        self.assertFalse(scanner.stopped())

    def test_scanner_stop(self):
        """Test ProbeScanner can be stopped."""
        probes = []
        scanner = ProbeScanner(probes)
        scanner.stop()

        self.assertTrue(scanner.stopped())


@unittest.skipUnless(REQUESTS_AVAILABLE, "requests library not available")
class TestHTTPProbes(unittest.TestCase):
    """Test HTTP probe execution."""

    def test_http_probe_success(self):
        """Test successful HTTP probe."""
        probes = [{
            'type': 'http',
            'label': 'Test',
            'target': 'https://httpbin.org/status/200',
            'method': 'GET',
            'timeout': 10,
            'expected_status': 200,
            'ssl_verify': True,
            'indice': 'http_1',
            'status': None,
            'latency_ms': None,
            'last_check_timestamp': None,
            'status_code': None,
            'error_message': None,
        }]

        scanner = ProbeScanner(probes)

        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_get.return_value = mock_response

            scanner._run_http_probe(probes[0])

        self.assertEqual(probes[0]['status'], 'ok')
        self.assertEqual(probes[0]['status_code'], 200)
        self.assertIsNotNone(probes[0]['latency_ms'])
        self.assertIsNotNone(probes[0]['last_check_timestamp'])
        self.assertIsNone(probes[0]['error_message'])

    def test_http_probe_wrong_status(self):
        """Test HTTP probe with unexpected status code."""
        probes = [{
            'type': 'http',
            'label': 'Test',
            'target': 'https://example.com',
            'method': 'GET',
            'timeout': 10,
            'expected_status': 200,
            'ssl_verify': True,
            'indice': 'http_1',
            'status': None,
            'latency_ms': None,
            'last_check_timestamp': None,
            'status_code': None,
            'error_message': None,
        }]

        scanner = ProbeScanner(probes)

        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 500
            mock_get.return_value = mock_response

            scanner._run_http_probe(probes[0])

        self.assertEqual(probes[0]['status'], 'error')
        self.assertEqual(probes[0]['status_code'], 500)
        self.assertIn('500', probes[0]['error_message'])

    def test_http_probe_timeout(self):
        """Test HTTP probe timeout handling."""
        probes = [{
            'type': 'http',
            'label': 'Test',
            'target': 'https://example.com',
            'method': 'GET',
            'timeout': 1,
            'expected_status': 200,
            'ssl_verify': True,
            'indice': 'http_1',
            'status': None,
            'latency_ms': None,
            'last_check_timestamp': None,
            'status_code': None,
            'error_message': None,
        }]

        scanner = ProbeScanner(probes)

        with patch('requests.get') as mock_get:
            mock_get.side_effect = requests.Timeout("Connection timed out")
            scanner._run_http_probe(probes[0])

        self.assertEqual(probes[0]['status'], 'timeout')
        self.assertIsNone(probes[0]['latency_ms'])
        self.assertIsNotNone(probes[0]['error_message'])

    def test_http_probe_connection_error(self):
        """Test HTTP probe connection error handling."""
        probes = [{
            'type': 'http',
            'label': 'Test',
            'target': 'https://invalid.example.com',
            'method': 'GET',
            'timeout': 1,
            'expected_status': 200,
            'ssl_verify': True,
            'indice': 'http_1',
            'status': None,
            'latency_ms': None,
            'last_check_timestamp': None,
            'status_code': None,
            'error_message': None,
        }]

        scanner = ProbeScanner(probes)

        with patch('requests.get') as mock_get:
            mock_get.side_effect = requests.ConnectionError("Connection refused")
            scanner._run_http_probe(probes[0])

        self.assertEqual(probes[0]['status'], 'error')
        self.assertIsNone(probes[0]['latency_ms'])
        self.assertIsNotNone(probes[0]['error_message'])

    def test_http_probe_head_method(self):
        """Test HTTP probe with HEAD method."""
        probes = [{
            'type': 'http',
            'label': 'Test',
            'target': 'https://example.com',
            'method': 'HEAD',
            'timeout': 10,
            'expected_status': 200,
            'ssl_verify': True,
            'indice': 'http_1',
            'status': None,
            'latency_ms': None,
            'last_check_timestamp': None,
            'status_code': None,
            'error_message': None,
        }]

        scanner = ProbeScanner(probes)

        with patch('requests.head') as mock_head:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_head.return_value = mock_response

            scanner._run_http_probe(probes[0])

        mock_head.assert_called_once()
        self.assertEqual(probes[0]['status'], 'ok')


@unittest.skipUnless(SQLALCHEMY_AVAILABLE, "sqlalchemy library not available")
class TestSQLProbes(unittest.TestCase):
    """Test SQL probe execution."""

    def test_sql_probe_success(self):
        """Test successful SQL probe."""
        probes = [{
            'type': 'sql',
            'label': 'Test DB',
            'target': 'sqlite:///:memory:',
            'query': 'SELECT 1',
            'timeout': 10,
            'indice': 'sql_1',
            'status': None,
            'latency_ms': None,
            'last_check_timestamp': None,
            'error_message': None,
        }]

        scanner = ProbeScanner(probes)
        scanner._run_sql_probe(probes[0])

        self.assertEqual(probes[0]['status'], 'ok')
        self.assertIsNotNone(probes[0]['latency_ms'])
        self.assertIsNotNone(probes[0]['last_check_timestamp'])
        self.assertIsNone(probes[0]['error_message'])

    def test_sql_probe_invalid_connection(self):
        """Test SQL probe with invalid connection string."""
        probes = [{
            'type': 'sql',
            'label': 'Test DB',
            'target': 'postgresql://invalid:invalid@nonexistent:5432/db',
            'query': 'SELECT 1',
            'timeout': 1,
            'indice': 'sql_1',
            'status': None,
            'latency_ms': None,
            'last_check_timestamp': None,
            'error_message': None,
        }]

        scanner = ProbeScanner(probes)
        scanner._run_sql_probe(probes[0])

        self.assertIn(probes[0]['status'], ['error', 'timeout'])
        self.assertIsNone(probes[0]['latency_ms'])
        self.assertIsNotNone(probes[0]['error_message'])


class TestMsgCurse(unittest.TestCase):
    """Test curse output generation."""

    def setUp(self):
        """Set up test fixtures."""
        self.args = MockArgs()
        self.config = MockConfig(sections={
            'synthetic': {
                'http_1_url': 'https://example.com',
                'http_1_label': 'Test Probe',
            }
        })
        self.plugin = SyntheticPlugin(args=self.args, config=self.config)

    def test_msg_curse_empty_stats(self):
        """Test msg_curse with empty stats."""
        self.plugin.stats = []
        result = self.plugin.msg_curse(args=self.args, max_width=80)
        self.assertEqual(result, [])

    def test_msg_curse_with_stats(self):
        """Test msg_curse with probe stats."""
        self.plugin.stats = [{
            'indice': 'http_1',
            'label': 'Test API',
            'status': 'ok',
            'latency_ms': 45.5,
        }]

        result = self.plugin.msg_curse(args=self.args, max_width=80)

        self.assertGreater(len(result), 0)
        messages = [item['msg'] for item in result if 'msg' in item]
        self.assertTrue(any('SYNTHETIC' in msg for msg in messages))

    def test_msg_curse_no_max_width(self):
        """Test msg_curse without max_width."""
        self.plugin.stats = [{'status': 'ok', 'latency_ms': 10}]
        result = self.plugin.msg_curse(args=self.args, max_width=None)
        self.assertEqual(result, [])

    def test_msg_curse_status_formats(self):
        """Test various status format outputs."""
        test_cases = [
            ({'status': None, 'latency_ms': None}, 'Scanning'),
            ({'status': 'ok', 'latency_ms': 100.5}, 'ms'),  # Check for ms suffix
            ({'status': 'timeout', 'latency_ms': None}, 'Timeout'),
            ({'status': 'error', 'latency_ms': None}, 'Error'),
        ]

        for probe_data, expected_substr in test_cases:
            probe = {'indice': 'test', 'label': 'Test', **probe_data}
            self.plugin.stats = [probe]
            result = self.plugin.msg_curse(args=self.args, max_width=80)
            messages = [item['msg'] for item in result if 'msg' in item]
            found = any(expected_substr in msg for msg in messages)
            self.assertTrue(found, f"Expected '{expected_substr}' in output for {probe_data}")


class TestProbeOutputFormat(unittest.TestCase):
    """Test that probe output matches expected format."""

    def test_probe_contains_required_keys(self):
        """Test that probe dictionaries contain all required keys."""
        args = MockArgs()
        config = MockConfig(sections={
            'synthetic': {
                'http_1_url': 'https://example.com',
                'http_1_label': 'Test',
            }
        })
        plugin = SyntheticPlugin(args=args, config=config)

        required_keys = ['label', 'status', 'latency_ms', 'last_check_timestamp']

        for probe in plugin._probes:
            for key in required_keys:
                self.assertIn(key, probe, f"Probe missing required key: {key}")

    def test_http_probe_has_type(self):
        """Test HTTP probes have correct type."""
        args = MockArgs()
        config = MockConfig(sections={
            'synthetic': {
                'http_1_url': 'https://example.com',
            }
        })
        plugin = SyntheticPlugin(args=args, config=config)

        for probe in plugin._probes:
            if probe['indice'].startswith('http'):
                self.assertEqual(probe['type'], 'http')

    def test_sql_probe_has_type(self):
        """Test SQL probes have correct type."""
        args = MockArgs()
        config = MockConfig(sections={
            'synthetic': {
                'sql_1_connection_string': 'sqlite:///:memory:',
            }
        })
        plugin = SyntheticPlugin(args=args, config=config)

        for probe in plugin._probes:
            if probe['indice'].startswith('sql'):
                self.assertEqual(probe['type'], 'sql')


class TestMultipleProbes(unittest.TestCase):
    """Test handling of multiple probes."""

    def test_multiple_http_probes(self):
        """Test loading multiple HTTP probes."""
        args = MockArgs()
        config = MockConfig(sections={
            'synthetic': {
                'http_1_url': 'https://api1.example.com',
                'http_1_label': 'API 1',
                'http_2_url': 'https://api2.example.com',
                'http_2_label': 'API 2',
                'http_3_url': 'https://api3.example.com',
                'http_3_label': 'API 3',
            }
        })
        plugin = SyntheticPlugin(args=args, config=config)

        self.assertEqual(len(plugin._probes), 3)

        labels = {p['label'] for p in plugin._probes}
        self.assertEqual(labels, {'API 1', 'API 2', 'API 3'})

    def test_probes_have_unique_indices(self):
        """Test all probes have unique indices."""
        args = MockArgs()
        config = MockConfig(sections={
            'synthetic': {
                'http_1_url': 'https://api1.example.com',
                'http_2_url': 'https://api2.example.com',
                'sql_1_connection_string': 'sqlite:///:memory:',
                'sql_2_connection_string': 'sqlite:///:memory:',
            }
        })
        plugin = SyntheticPlugin(args=args, config=config)

        indices = [p['indice'] for p in plugin._probes]
        self.assertEqual(len(indices), len(set(indices)), "Probe indices should be unique")


if __name__ == '__main__':
    unittest.main()
