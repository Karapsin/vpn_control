"""Historical source factories stay bound to their original public input bytes.

These controls generate source only. They do not admit artifacts or run native
entry points, and they do not patch the current public MCP namespace.
"""
import hashlib
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from agent_tools import windows_msi_public_scenario as current_public
from agent_tools import windows_cp117_installed_base_observe as current_installed
from agent_tools.tests.fixtures import historical_source
from agent_tools.tests.fixtures.windows_cp117_historical_factory import context


class HistoricalPackageSourceTests(unittest.TestCase):
    def test_actual_current_producer_keeps_functions_and_restores_public_input(self):
        original = current_installed.public
        current_precise = current_installed.precise
        producer = current_installed.body_current
        with context.historical_current_package() as installed:
            self.assertIs(installed, current_installed)
            self.assertIs(installed.precise, current_precise)
            self.assertIs(installed.body_current, producer)
            self.assertIs(producer.__globals__, installed.__dict__)
            self.assertTrue(producer(installed.PAIR_EXPECTED))
            self.assertEqual(hashlib.sha256(Path(installed.public.__file__).read_bytes()).hexdigest(),
                             installed.PUBLIC_SHA)
        self.assertIs(current_installed.public, original)
        self.assertIs(current_installed.precise, current_precise)
        self.assertIs(current_installed.body_current, producer)

    def test_actual_package_factory_uses_exact_historical_public_source(self):
        with context.historical_factories():
            installed = context.installed()
            body = installed.body(installed.PAIR_EXPECTED)
            self.assertTrue(body)
            source = Path(installed.public.__file__)
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),
                             installed.PUBLIC_SHA)
            self.assertIsNot(installed.public, current_public)
            historical_source.verify(installed.public, source, installed.PUBLIC_SHA)

    def test_actual_package_guard_refuses_foreign_source_and_pair(self):
        with context.historical_factories(), tempfile.TemporaryDirectory() as td:
            installed = context.installed()
            foreign = Path(td) / 'foreign-public.py'
            foreign.write_bytes(b'# harmless foreign source\n')
            with patch.object(installed, 'public',
                              types.SimpleNamespace(__file__=str(foreign))):
                with self.assertRaisesRegex(ValueError, '^package-fixed-source$'):
                    installed.body(installed.PAIR_EXPECTED)
            with self.assertRaisesRegex(ValueError, '^package-fixed-pair$'):
                installed.body({**installed.PAIR_EXPECTED, 'targetVersion': '2.2.3'})

    def test_lifetime_restores_reference_and_current_public_bindings(self):
        installed = context.installed()
        original = installed.public
        current_file = current_public.__file__
        current_status = current_public._status_result
        current_body = Path(current_file).read_bytes()
        with context.historical_factories():
            self.assertIsNot(installed.public, original)
            self.assertIs(current_public._status_result, current_status)
            self.assertEqual(current_public.__file__, current_file)
        self.assertIs(installed.public, original)
        self.assertIs(current_public._status_result, current_status)
        self.assertIs(current_status.__globals__, current_public.__dict__)
        self.assertEqual(Path(current_file).read_bytes(), current_body)

    def test_source_loader_refuses_drift_before_execution(self):
        with context.historical_factories(), tempfile.TemporaryDirectory() as td:
            installed = context.installed()
            foreign = Path(td) / 'drifted-public.source'
            foreign.write_bytes(Path(installed.public.__file__).read_bytes() + b'\n')
            with self.assertRaisesRegex(ValueError, '^historical_source_binding_changed$'):
                historical_source.load(foreign, installed.PUBLIC_SHA)
