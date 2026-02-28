#
# This file is part of Glances.
#
# SPDX-FileCopyrightText: 2024 Nicolas Hennion <nicolas@nicolargo.com>
#
# SPDX-License-Identifier: LGPL-3.0-only
#

"""Synthetic monitoring plugin - Active health probes (HTTP/HTTPS and SQL)."""

import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from glances.logger import logger
from glances.plugins.plugin.model import GlancesPluginModel
from glances.timer import Counter

# Optional imports for probe types
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("requests library not available. HTTP probes will be disabled.")

# SQL database drivers - try to import common ones
SQL_DRIVERS = {}

try:
    import psycopg2
    SQL_DRIVERS['postgresql'] = psycopg2
except ImportError:
    pass

try:
    import mysql.connector
    SQL_DRIVERS['mysql'] = mysql.connector
except ImportError:
    pass

try:
    import sqlite3
    SQL_DRIVERS['sqlite'] = sqlite3
except ImportError:
    pass

# Fields description
fields_description = {
    'label': {
        'description': 'User-defined label for the probe',
    },
    'type': {
        'description': 'Probe type (http, https, sql)',
    },
    'target': {
        'description': 'Target URL or connection string',
    },
    'status': {
        'description': 'Probe status (OK, ERROR, TIMEOUT)',
    },
    'latency_ms': {
        'description': 'Response latency in milliseconds',
        'unit': 'number',
    },
    'last_check_timestamp': {
        'description': 'ISO timestamp of the last check',
    },
    'status_code': {
        'description': 'HTTP status code (for HTTP probes)',
        'unit': 'number',
    },
    'error_message': {
        'description': 'Error message if probe failed',
    },
}

# Default configuration values
DEFAULT_REFRESH = 30
DEFAULT_TIMEOUT = 10
DEFAULT_HTTP_METHOD = 'GET'
DEFAULT_SQL_QUERY = 'SELECT 1'


class SyntheticPlugin(GlancesPluginModel):
    """Glances synthetic monitoring plugin.

    Performs active health probes (HTTP/HTTPS and SQL) to measure service
    responses and latency.
    """

    def __init__(self, args=None, config=None):
        """Init the plugin."""
        super().__init__(
            args=args,
            config=config,
            stats_init_value=[],
            fields_description=fields_description
        )
        self.args = args
        self.config = config
        self.display_curse = True

        # Load probe configurations
        self._probes = self._load_probes(config)

        # Background thread for async probing
        self._thread = None
        self._executor = None

    def _load_probes(self, config):
        """Load probe definitions from configuration file."""
        probes = []

        if config is None:
            logger.debug("No configuration file available. Cannot load synthetic probes.")
            return probes

        section = 'synthetic'
        if not config.has_section(section):
            logger.debug(f"No [{section}] section in configuration file.")
            return probes

        logger.debug(f"Loading [{section}] probes from configuration")

        # Global settings for the section
        global_refresh = config.get_int_value(section, 'refresh', DEFAULT_REFRESH)
        global_timeout = config.get_int_value(section, 'timeout', DEFAULT_TIMEOUT)

        # Load HTTP probes
        for i in range(1, 256):
            prefix = f'http_{i}_'
            url = config.get_value(section, f'{prefix}url')
            if url is None:
                continue

            probe = {
                'id': f'http_{i}',
                'type': 'http',
                'url': url,
                'label': config.get_value(section, f'{prefix}label', default=url),
                'method': config.get_value(section, f'{prefix}method', default=DEFAULT_HTTP_METHOD).upper(),
                'timeout': config.get_int_value(section, f'{prefix}timeout', global_timeout),
                'refresh': config.get_int_value(section, f'{prefix}refresh', global_refresh),
                'expected_status': config.get_int_value(section, f'{prefix}expected_status', 200),
                'verify_ssl': config.get_bool_value(section, f'{prefix}verify_ssl', True),
                'status': None,
                'latency_ms': None,
                'last_check_timestamp': None,
                'error_message': None,
                'status_code': None,
                'key': 'label',
            }

            # Optional headers
            headers_str = config.get_value(section, f'{prefix}headers')
            if headers_str:
                try:
                    probe['headers'] = dict(h.split(':') for h in headers_str.split(','))
                except ValueError:
                    probe['headers'] = {}
            else:
                probe['headers'] = {}

            logger.debug(f"Loaded HTTP probe: {probe['label']} -> {probe['url']}")
            probes.append(probe)

        # Load SQL probes
        for i in range(1, 256):
            prefix = f'sql_{i}_'
            connection_string = config.get_value(section, f'{prefix}connection')
            if connection_string is None:
                continue

            probe = {
                'id': f'sql_{i}',
                'type': 'sql',
                'connection': connection_string,
                'label': config.get_value(section, f'{prefix}label', default=f'SQL Probe {i}'),
                'db_type': config.get_value(section, f'{prefix}db_type', default='postgresql'),
                'query': config.get_value(section, f'{prefix}query', default=DEFAULT_SQL_QUERY),
                'timeout': config.get_int_value(section, f'{prefix}timeout', global_timeout),
                'refresh': config.get_int_value(section, f'{prefix}refresh', global_refresh),
                'status': None,
                'latency_ms': None,
                'last_check_timestamp': None,
                'error_message': None,
                'key': 'label',
            }

            logger.debug(f"Loaded SQL probe: {probe['label']} -> {probe['db_type']}")
            probes.append(probe)

        logger.debug(f"Total synthetic probes loaded: {len(probes)}")
        return probes

    def exit(self):
        """Cleanup on exit."""
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=1)
        if self._executor is not None:
            self._executor.shutdown(wait=False)
        super().exit()

    def get_key(self):
        """Return the key of the list."""
        return 'label'

    @GlancesPluginModel._check_decorator
    @GlancesPluginModel._log_result_decorator
    def update(self):
        """Update the synthetic probes."""
        if self.input_method == 'local':
            # Only run probes if no thread is currently running
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._run_probes, daemon=True)
                self._thread.start()
        else:
            # Not available in SNMP mode
            self.stats = []

        # Return current state (probes are updated asynchronously)
        self.stats = self._get_probe_stats()
        return self.stats

    def _run_probes(self):
        """Run all probes asynchronously."""
        if not self._probes:
            return

        with ThreadPoolExecutor(max_workers=min(len(self._probes), 10)) as executor:
            futures = {}
            for probe in self._probes:
                if probe['type'] == 'http':
                    futures[executor.submit(self._run_http_probe, probe)] = probe
                elif probe['type'] == 'sql':
                    futures[executor.submit(self._run_sql_probe, probe)] = probe

            for future in as_completed(futures):
                probe = futures[future]
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Probe {probe['label']} failed: {e}")
                    probe['status'] = 'ERROR'
                    probe['error_message'] = str(e)
                    probe['last_check_timestamp'] = datetime.now().isoformat()

    def _run_http_probe(self, probe):
        """Execute an HTTP/HTTPS probe."""
        if not REQUESTS_AVAILABLE:
            probe['status'] = 'ERROR'
            probe['error_message'] = 'requests library not available'
            probe['last_check_timestamp'] = datetime.now().isoformat()
            return

        counter = Counter()
        try:
            response = requests.request(
                method=probe['method'],
                url=probe['url'],
                timeout=probe['timeout'],
                verify=probe['verify_ssl'],
                headers=probe.get('headers', {}),
                allow_redirects=True,
            )

            latency = counter.get() * 1000  # Convert to ms
            probe['latency_ms'] = round(latency, 2)
            probe['status_code'] = response.status_code
            probe['last_check_timestamp'] = datetime.now().isoformat()

            if response.status_code == probe['expected_status']:
                probe['status'] = 'OK'
                probe['error_message'] = None
            else:
                probe['status'] = 'ERROR'
                probe['error_message'] = f"Expected {probe['expected_status']}, got {response.status_code}"

        except requests.exceptions.Timeout:
            probe['status'] = 'TIMEOUT'
            probe['latency_ms'] = probe['timeout'] * 1000
            probe['error_message'] = 'Request timed out'
            probe['last_check_timestamp'] = datetime.now().isoformat()
        except requests.exceptions.RequestException as e:
            probe['status'] = 'ERROR'
            probe['latency_ms'] = round(counter.get() * 1000, 2)
            probe['error_message'] = str(e)
            probe['last_check_timestamp'] = datetime.now().isoformat()

    def _run_sql_probe(self, probe):
        """Execute a SQL probe."""
        db_type = probe.get('db_type', 'postgresql')

        if db_type not in SQL_DRIVERS:
            probe['status'] = 'ERROR'
            probe['error_message'] = f"Database driver for '{db_type}' not available"
            probe['last_check_timestamp'] = datetime.now().isoformat()
            return

        driver = SQL_DRIVERS[db_type]
        counter = Counter()

        try:
            if db_type == 'sqlite':
                conn = driver.connect(probe['connection'], timeout=probe['timeout'])
            elif db_type == 'postgresql':
                conn = driver.connect(probe['connection'], connect_timeout=probe['timeout'])
            elif db_type == 'mysql':
                conn = driver.connect(
                    **self._parse_mysql_connection(probe['connection']),
                    connection_timeout=probe['timeout']
                )
            else:
                conn = driver.connect(probe['connection'])

            cursor = conn.cursor()
            cursor.execute(probe['query'])
            cursor.fetchone()
            cursor.close()
            conn.close()

            latency = counter.get() * 1000
            probe['latency_ms'] = round(latency, 2)
            probe['status'] = 'OK'
            probe['error_message'] = None
            probe['last_check_timestamp'] = datetime.now().isoformat()

        except Exception as e:
            probe['status'] = 'ERROR'
            probe['latency_ms'] = round(counter.get() * 1000, 2)
            probe['error_message'] = str(e)
            probe['last_check_timestamp'] = datetime.now().isoformat()

    def _parse_mysql_connection(self, connection_string):
        """Parse MySQL connection string into dict."""
        # Simple parsing for common format: user:password@host:port/database
        result = {}
        try:
            if '@' in connection_string:
                auth, rest = connection_string.split('@', 1)
                if ':' in auth:
                    result['user'], result['password'] = auth.split(':', 1)
                else:
                    result['user'] = auth

                if '/' in rest:
                    host_port, result['database'] = rest.split('/', 1)
                else:
                    host_port = rest

                if ':' in host_port:
                    result['host'], port = host_port.split(':', 1)
                    result['port'] = int(port)
                else:
                    result['host'] = host_port
        except Exception:
            pass
        return result

    def _get_probe_stats(self):
        """Get current probe statistics as list of dicts."""
        stats = []
        for probe in self._probes:
            stat = {
                'label': probe['label'],
                'type': probe['type'],
                'status': probe.get('status'),
                'latency_ms': probe.get('latency_ms'),
                'last_check_timestamp': probe.get('last_check_timestamp'),
                'key': 'label',
            }

            # Add type-specific fields
            if probe['type'] == 'http':
                stat['target'] = probe.get('url')
                stat['status_code'] = probe.get('status_code')
            elif probe['type'] == 'sql':
                stat['target'] = probe.get('db_type', 'sql')

            if probe.get('error_message'):
                stat['error_message'] = probe['error_message']

            stats.append(stat)
        return stats

    def get_alert(self, probe, header=None):
        """Return alert status based on probe status."""
        status = probe.get('status')

        if status is None:
            return 'CAREFUL'  # Not yet checked
        elif status == 'OK':
            return 'OK'
        elif status == 'TIMEOUT':
            return 'WARNING'
        else:  # ERROR
            return 'CRITICAL'

    def msg_curse(self, args=None, max_width=None):
        """Return the dict to display in the curse interface."""
        ret = []

        if not self.stats or self.is_disabled():
            return ret

        # Determine column widths
        if max_width:
            name_max_width = max_width - 18
        else:
            logger.debug(f"No max_width defined for the {self.plugin_name} plugin")
            return ret

        # Header
        msg = '{:{width}}'.format('SYNTHETIC', width=name_max_width)
        ret.append(self.curse_add_line(msg, "TITLE"))

        # Data rows
        for probe in self.stats:
            ret.append(self.curse_new_line())

            # Label (truncated if needed)
            label = probe['label']
            if len(label) > name_max_width:
                label = label[:name_max_width - 1] + '…'
            msg = '{:{width}}'.format(label, width=name_max_width)
            ret.append(self.curse_add_line(msg))

            # Status and latency
            status = probe.get('status')
            latency = probe.get('latency_ms')

            if status is None:
                status_str = 'Checking'
            elif status == 'OK' and latency is not None:
                status_str = f'{latency:.0f}ms'
            elif status == 'TIMEOUT':
                status_str = 'Timeout'
            else:
                status_str = 'Error'

            msg = f'{status_str:>10}'
            ret.append(self.curse_add_line(msg, self.get_alert(probe)))

        return ret
