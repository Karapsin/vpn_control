#!/usr/bin/env python3
"""Causal regressions for the executable Python platform-contract probes."""
from __future__ import annotations

import unittest

import check_python_platform_contracts as subject


class ImportProbeTest(unittest.TestCase):
    def test_causal_module_scope_pwd_import_fails_when_pwd_is_absent(self):
        result = subject.probe_source_with_unavailable_imports("import pwd\n", ("pwd",))
        self.assertNotEqual(0, result.returncode)
        self.assertIn("No module named 'pwd'", result.stderr)

    def test_lazy_pwd_import_is_accepted_at_the_real_module_boundary(self):
        for probe in subject.IMPORT_PROBES:
            result = subject.probe_import(subject.SCRIPTS / probe.path, probe.unavailable_modules)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)


class OsMockProbeTest(unittest.TestCase):
    def test_causal_missing_create_fails_when_the_windows_like_os_object_lacks_getsid(self):
        source = '''from types import SimpleNamespace
from unittest import mock
os_surface = SimpleNamespace()
with mock.patch.object(os_surface, "getsid", return_value=123):
    assert os_surface.getsid(0) == 123
'''
        result = subject.probe_source_with_unavailable_imports(source, ())
        self.assertNotEqual(0, result.returncode)
        self.assertIn("does not have the attribute 'getsid'", result.stderr)

    def test_create_true_accepts_the_windows_like_os_object_and_executes_getsid(self):
        source = '''from types import SimpleNamespace
from unittest import mock
os_surface = SimpleNamespace()
with mock.patch.object(os_surface, "getsid", return_value=123, create=True):
    assert os_surface.getsid(0) == 123
'''
        result = subject.probe_source_with_unavailable_imports(source, ())
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_manifested_transient_and_sustained_monitor_methods_pass(self):
        for probe in subject.METHOD_PROBES:
            result = subject.probe_test_methods(probe)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)


class ManifestTest(unittest.TestCase):
    def test_all_explicit_contracts_pass(self):
        self.assertEqual([], subject.check_contracts())


if __name__ == "__main__":
    unittest.main()
