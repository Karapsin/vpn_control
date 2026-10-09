#!/usr/bin/env python3
"""Causal regressions for the executable Python platform-contract probes."""
from __future__ import annotations

import ast
import json
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
    def test_absent_getuid_probe_exercises_real_guest_file_gate(self):
        result = subject.probe_absent_getuid()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_windows_phase_recorder_probe_exercises_real_receipt_publication(self):
        result = subject.probe_windows_phase_recorder()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_windows_android_probe_rejects_before_private_write(self):
        result = subject.probe_windows_android_installer_boundary()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

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


class AndroidTestCapabilityProbeTest(unittest.TestCase):
    @staticmethod
    def without_skip(module, method):
        """Remove a guard while retaining the actual test and production bodies."""
        tree = ast.parse((subject.SCRIPTS / (module + ".py")).read_text(encoding="utf-8"))
        class_name, method_name = method.split(".")
        case = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name)
        body = next(node for node in case.body if isinstance(node, ast.FunctionDef) and node.name == method_name)
        body.decorator_list = []
        return ast.unparse(tree)

    def test_missing_preflight_guard_executes_real_body_and_fails_without_directory_flags(self):
        module = "test_android_no_update_tls_preflight"
        method = "PreflightScriptTest.test_push_failure_after_owned_staging_removes_stage_and_restores_public_adbd"
        result = subject.probe_windows_android_test_suites({module: self.without_skip(module, method)})
        self.assertNotEqual(0, result.returncode)
        summary = json.loads(result.stdout.splitlines()[-1])
        self.assertIn(module + "." + method, summary["errors"])
        self.assertIn("AttributeError: O_DIRECTORY", result.stderr)

    def test_missing_installer_guard_reaches_actual_windows_private_write_refusal(self):
        module = "test_android_installer_lifecycle"
        method = "InstallerEarlyReplyEvidenceTest.test_all_four_replies_are_private_create_only_and_oversized_data_is_explicitly_bounded"
        result = subject.probe_windows_android_test_suites({module: self.without_skip(module, method)})
        self.assertNotEqual(0, result.returncode)
        summary = json.loads(result.stdout.splitlines()[-1])
        self.assertIn(module + "." + method, summary["errors"])
        self.assertIn("ValueError: Installer CLI evidence requires POSIX file APIs", result.stderr)

    def test_real_suites_keep_exact_posix_skips_and_portable_windows_coverage(self):
        result = subject.probe_windows_android_test_suites()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        summary = json.loads(result.stdout.splitlines()[-1])
        expected = {module + "." + method for module, methods in subject.ANDROID_POSIX_METHODS.items() for method in methods}
        self.assertEqual(expected, set(summary["skipped"]))
        self.assertEqual(set(subject.ANDROID_WINDOWS_METHODS), set(summary["portablePassed"]))
        self.assertGreater(summary["passed"], len(subject.ANDROID_WINDOWS_METHODS))
        self.assertEqual([], summary["errors"])
        self.assertEqual([], summary["failures"])


class ManifestTest(unittest.TestCase):
    def test_all_explicit_contracts_pass(self):
        self.assertEqual([], subject.check_contracts())


if __name__ == "__main__":
    unittest.main()
