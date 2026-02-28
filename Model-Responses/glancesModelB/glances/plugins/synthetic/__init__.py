#
# This file is part of Glances.
#
# SPDX-FileCopyrightText: 2024 Nicolas Hennion <nicolas@nicolargo.com>
#
# SPDX-License-Identifier: LGPL-3.0-only
#

"""Synthetic monitoring plugin for active health probes (HTTP/HTTPS and SQL)."""

import threading
import time
from datetime import datetime

from glances.logger import logger
from glances.plugins.plugin.model import GlancesPluginModel
from glances.timer import Counter

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("Missing 'requests' library, HTTP probes will not be available")

try:
    import sqlalchemy
    from sqlalchemy import create_engine, text
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False
    logger.warning("Missing 'sqlalchemy' library, SQL probes will not be available")

fields_description = {
    'label': {
        'description': 'User-defined label for the probe.',
    },
    'type': {
        'description': 'Probe type (http or sql).',
    },
    'target': {
        'description': 'Target URL or connection string.',
    },
    'status': {
        'description': 'Probe status (ok, error, timeout, or scanning).',
    },
    'latency_ms': {
        'description': 'Response latency in milliseconds.',
        'unit': 'ms',
    },
    'last_check_timestamp': {
        'description': 'Unix timestamp of the last check.',
    },
    'status_code': {
        'description': 'HTTP status code (for HTTP probes only).',
    },
    'error_message': {
        'description': 'Error message if probe failed.',
    },
}


class SyntheticPlugin(GlancesPluginModel):
    """Glances synthetic monitoring plugin."""

    _section = 'synthetic'

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

        self._probes = self._load_probes(config)
        self._thread = None

    def _load_probes(self, config):
        """Load probe definitions from configuration file."""
        probes = []

        if config is None:
            logger.debug("No configuration file available. Cannot load synthetic probes.")
            return probes

        if not config.has_section(self._section):
            logger.debug(f"No [{self._section}] section in the configuration file.")
            return probes

        logger.debug(f"Loading [{self._section}] section from configuration file")

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
            logger.debug(f"Loaded HTTP probe: {probe['label']} -> {probe['target']}")
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
            logger.debug(f"Loaded SQL probe: {probe['label']}")
            probes.append(probe)

        logger.info(f"Loaded {len(probes)} synthetic probe(s)")
        return probes

    def exit(self):
        """Overwrite exit method to stop threads."""
        if self._thread is not None:
            self._thread.stop()
        super().exit()

    def get_key(self):
        """Return the key of the list."""
        return 'indice'

    @GlancesPluginModel._check_decorator
    @GlancesPluginModel._log_result_decorator
    def update(self):
        """Update the synthetic probes stats."""
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
        """Return the alert status for a probe."""
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
        """Return the dict to display in the curse interface."""
        ret = []

        if not self.stats or self.is_disabled():
            return ret

        if max_width:
            name_max_width = max_width - 12
        else:
            logger.debug(f"No max_width defined for the {self.plugin_name} plugin.")
            return ret

        # Header
        msg = '{:{width}}'.format('SYNTHETIC', width=name_max_width)
        ret.append(self.curse_add_line(msg, "TITLE"))
        msg = '{:>12}'.format('Latency')
        ret.append(self.curse_add_line(msg))

        # Data
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


class ProbeScanner(threading.Thread):
    """Thread for running synthetic probes."""

    def __init__(self, probes):
        """Initialize the scanner thread."""
        super().__init__()
        self.daemon = True
        self._stopper = threading.Event()
        self._probes = probes
        logger.debug(f"ProbeScanner initialized with {len(probes)} probes")

    def run(self):
        """Run the probe scanning."""
        for probe in self._probes:
            if self.stopped():
                break

            if probe['type'] == 'http':
                self._run_http_probe(probe)
            elif probe['type'] == 'sql':
                self._run_sql_probe(probe)

            probe['key'] = 'indice'

    def stop(self):
        """Stop the thread."""
        logger.debug("Stopping ProbeScanner thread")
        self._stopper.set()

    def stopped(self):
        """Check if thread is stopped."""
        return self._stopper.is_set()

    def _run_http_probe(self, probe):
        """Execute an HTTP probe."""
        if not REQUESTS_AVAILABLE:
            probe['status'] = 'error'
            probe['error_message'] = 'requests library not available'
            probe['last_check_timestamp'] = time.time()
            return

        try:
            counter = Counter()

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
            logger.debug(f"HTTP probe error for {probe['label']}: {e}")

    def _run_sql_probe(self, probe):
        """Execute a SQL probe."""
        if not SQLALCHEMY_AVAILABLE:
            probe['status'] = 'error'
            probe['error_message'] = 'sqlalchemy library not available'
            probe['last_check_timestamp'] = time.time()
            return

        engine = None
        connection = None

        try:
            counter = Counter()

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
            logger.debug(f"SQL probe error for {probe['label']}: {e}")
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
