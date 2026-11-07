#!/usr/bin/env python3
"""Causal regressions for the executable Python platform-contract probes."""
from __future__ import annotations

import ast
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
from unittest.mock import patch

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


class FixtureStorageTestCapabilityProbeTest(unittest.TestCase):
    FIXTURES = subject.SCRIPTS / "tests/fixtures/windows_fixture_storage_capabilities"
    MODULE = "test_fixture_storage_host"

    @classmethod
    def provenance(cls):
        return json.loads((cls.FIXTURES / "provenance.json").read_bytes())

    @classmethod
    def beforeimage(cls):
        """Complete test source from Windows run 40383276339, kept byte-for-byte."""
        filename, entry = next(iter(cls.provenance()["files"].items()))
        raw = (cls.FIXTURES / filename).read_bytes()
        if len(raw) != entry["bytes"] or hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise AssertionError("preserved storage-host test beforeimage changed")
        return raw.decode("utf-8")

    @classmethod
    def ids(cls, methods):
        return {cls.MODULE + "." + method for method in methods}

    def test_unfixed_storage_host_suite_reproduces_recorded_windows_lock_refusal(self):
        result = subject.probe_windows_fixture_storage_test_suite(self.beforeimage())
        details = result.stdout + result.stderr
        self.assertNotEqual(0, result.returncode, details)
        self.assertTrue(result.stdout.splitlines(), details)
        summary = json.loads(result.stdout.splitlines()[-1])
        original = self.provenance()["originalFailure"]
        self.assertEqual({original["test"]: original["excerpt"]}, summary["errors"], details)
        self.assertEqual({}, summary["failures"], details)
        self.assertEqual(self.ids(subject.FIXTURE_STORAGE_LINUX_METHODS), set(summary["skipped"]), details)
        self.assertEqual(self.ids(subject.FIXTURE_STORAGE_WINDOWS_METHODS), set(summary["portablePassed"]), details)
        self.assertEqual(8, summary["testsRun"], details)
        # The broad ValueError assertion also passed on Windows for the wrong
        # reason: unsupported locking, rather than an unsafe ledger directory.
        self.assertEqual(4, summary["passed"], details)

    def test_fixed_storage_host_suite_keeps_exact_platform_skips_and_portable_coverage(self):
        result = subject.probe_windows_fixture_storage_test_suite()
        details = result.stdout + result.stderr
        self.assertEqual(0, result.returncode, details)
        summary = json.loads(result.stdout.splitlines()[-1])
        expected = self.ids((*subject.FIXTURE_STORAGE_POSIX_METHODS, *subject.FIXTURE_STORAGE_LINUX_METHODS))
        self.assertEqual(expected, set(summary["skipped"]), details)
        self.assertEqual(self.ids(subject.FIXTURE_STORAGE_WINDOWS_METHODS), set(summary["portablePassed"]), details)
        self.assertEqual({}, summary["errors"], details)
        self.assertEqual({}, summary["failures"], details)
        self.assertEqual(8, summary["testsRun"], details)
        self.assertEqual(3, summary["passed"], details)


class VisualTestCapabilityProbeTest(unittest.TestCase):
    FIXTURES = subject.SCRIPTS / "tests/fixtures/windows_visual_test_capabilities"

    @classmethod
    def provenance(cls):
        return json.loads((cls.FIXTURES / "provenance.json").read_bytes())

    @classmethod
    def beforeimages(cls):
        """Whole unfixed modules from Windows run 40187428207, authenticated by raw SHA-256."""
        sources = {}
        for name, entry in cls.provenance()["files"].items():
            raw = (cls.FIXTURES / name).read_bytes()
            if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
                raise AssertionError("preserved visual test beforeimage changed: " + name)
            sources[Path(entry["path"]).stem] = raw.decode("utf-8")
        return sources

    @staticmethod
    def final_line(line):
        # Windows prints [WinError n]; the POSIX CreateProcess model raises [Errno n].
        line = re.sub(r"\[(?:WinError|Errno) \d+\] ", "", line)
        # Tracebacks may append an interpreter-specific name suggestion. CPython
        # 3.15 offers '.AF_APPLETALK.AF_UNIX' because socket.AddressFamily keeps
        # its AF_UNIX member after the probe removes socket.AF_UNIX; Windows
        # CPython has neither, so only the exception and message are compared.
        return re.sub(r"\. Did you mean\b.*\?$", "", line)

    def test_unfixed_visual_tests_reproduce_every_recorded_windows_failure(self):
        result = subject.probe_windows_visual_test_suites(self.beforeimages())
        details = result.stdout + result.stderr
        self.assertNotEqual(0, result.returncode, details)
        self.assertTrue(result.stdout.splitlines(), details)
        summary = json.loads(result.stdout.splitlines()[-1])
        observed = {**{test: ("error", line) for test, line in summary["errors"].items()},
                    **{test: ("failure", line) for test, line in summary["failures"].items()}}
        recorded = {test: (kind, case) for kind, failure in self.provenance()["failureTypes"].items()
                    for test, case in failure["cases"].items()}
        self.assertEqual(set(recorded), set(observed), details)
        for test, (kind, case) in recorded.items():
            with self.subTest(failure=kind, test=test):
                self.assertEqual(case["outcome"], observed[test][0], details)
                self.assertEqual(self.final_line(case["excerpt"]), self.final_line(observed[test][1]), details)
        self.assertEqual([], summary["skipped"], details)
        self.assertEqual(set(subject.VISUAL_WINDOWS_METHODS), set(summary["portablePassed"]), details)

    def test_fixed_visual_tests_skip_exactly_the_recorded_cases_and_keep_portable_coverage(self):
        result = subject.probe_windows_visual_test_suites()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        summary = json.loads(result.stdout.splitlines()[-1])
        expected = {module + "." + method for module, methods in subject.VISUAL_POSIX_METHODS.items() for method in methods}
        recorded = {test for failure in self.provenance()["failureTypes"].values() for test in failure["cases"]}
        self.assertEqual(recorded, expected)
        self.assertEqual(expected, set(summary["skipped"]))
        self.assertEqual(set(subject.VISUAL_WINDOWS_METHODS), set(summary["portablePassed"]))
        self.assertEqual({}, summary["errors"])
        self.assertEqual({}, summary["failures"])


class VisualProbeInterpreterSuggestionTest(unittest.TestCase):
    """The exact macOS CPython 3.15 probe line against the unfixed and fixed comparison."""
    FIXTURES = subject.SCRIPTS / "tests/fixtures/visual_probe_interpreter_suggestion"
    METHOD = "test_unfixed_visual_tests_reproduce_every_recorded_windows_failure"

    @classmethod
    def provenance(cls):
        return json.loads((cls.FIXTURES / "provenance.json").read_bytes())

    @classmethod
    def before(cls):
        """The whole unfixed module of macOS run 40232090293, authenticated by raw SHA-256."""
        provenance = cls.provenance()
        path = cls.FIXTURES / provenance["beforeimage"]
        raw = path.read_bytes()
        actual = (hashlib.sha256(raw).hexdigest(), len(raw))
        if actual != (provenance["sourceSha256"], provenance["sourceBytes"]):
            raise AssertionError("preserved test module beforeimage changed: %s %r" % (path.name, actual))
        # A file loader lets tracebacks show beforeimage lines without CPython
        # 3.15's missing __spec__.loader DeprecationWarning from linecache.
        name = "_test_python_platform_contracts_before"
        module = importlib.util.module_from_spec(
            importlib.util.spec_from_loader(name, importlib.machinery.SourceFileLoader(name, str(path))))
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
        return module

    @staticmethod
    def macos_summary(ci):
        """Probe summary as on the runner: AF_UNIX cases print the CI line, the rest their Windows line."""
        summary = {"errors": {}, "failures": {}, "skipped": [], "portablePassed": sorted(subject.VISUAL_WINDOWS_METHODS)}
        for kind, failure in VisualTestCapabilityProbeTest.provenance()["failureTypes"].items():
            for test, case in failure["cases"].items():
                summary[case["outcome"] + "s"][test] = ci["observedLine"] if kind == ci["failureType"] else case["excerpt"]
        return summary

    def run_case(self, case_class, summary):
        """Run one whole test method while the probe returns the macOS summary."""
        result = unittest.TestResult()
        completed = subprocess.CompletedProcess(["probe"], 1, json.dumps(summary, sort_keys=True) + "\n", "")
        with mock.patch.object(subject, "probe_windows_visual_test_suites", return_value=completed) as probe:
            case_class(self.METHOD).run(result)
        return result, [sorted(call.args[0]) if call.args else call for call in probe.call_args_list]

    def test_exact_macos_suggestion_line_fails_unfixed_comparison_and_passes_fixed(self):
        provenance = self.provenance()
        ci = provenance["ciFailure"]
        trace = ci["trace"]
        windows = VisualTestCapabilityProbeTest.provenance()["failureTypes"][ci["failureType"]]["cases"]
        summary = self.macos_summary(ci)
        old, old_calls = self.run_case(self.before().VisualTestCapabilityProbeTest, summary)
        new, new_calls = self.run_case(VisualTestCapabilityProbeTest, summary)

        def details():
            return "\n".join([json.dumps(provenance, indent=2), json.dumps(summary, indent=2, sort_keys=True),
                              "unfixed probe calls: %r" % (old_calls,), "fixed probe calls: %r" % (new_calls,),
                              *("unfixed %s\n%s" % (test, text) for test, text in old.failures + old.errors),
                              *("fixed %s\n%s" % (test, text) for test, text in new.failures + new.errors)])

        # The regression input is the authenticated CI evidence for the recorded Windows cases.
        self.assertFalse(provenance["nativeFailureClaimed"], details())
        self.assertEqual(ci["traceSha256"], hashlib.sha256(("\n".join(trace) + "\n").encode()).hexdigest(), details())
        self.assertEqual(["- " + ci["recordedLine"], "+ " + ci["observedLine"]], trace[-2:], details())
        self.assertEqual(set(windows), set(ci["cases"]), details())
        self.assertEqual({ci["recordedLine"]}, {case["excerpt"] for case in windows.values()}, details())
        self.assertEqual(["(failure=%r, test=%r)" % (ci["failureType"], test) for test in ci["cases"]],
                         [header[header.rindex(" (failure="):].strip() for header in ci["failureHeaders"]], details())
        self.assertEqual(ci["failureHeaders"][0], trace[1], details())
        sources = [["test_visual_platform", "test_visual_target"]]
        # Unfixed: exactly the five CI subtests fail at the CI statement with the CI message.
        self.assertEqual((1, 5, 0, sources), (old.testsRun, len(old.failures), len(old.errors), old_calls), details())
        self.assertEqual({(ci["failureType"], test) for test in ci["cases"]},
                         {tuple(getattr(subtest, "params", {}).get(key) for key in ("failure", "test"))
                          for subtest, _ in old.failures}, details())
        for _, text in old.failures:
            lines = [line for line in text.splitlines() if line.strip()]
            self.assertGreaterEqual(len(lines), 6, details())
            self.assertEqual(trace[3], lines[0], details())
            self.assertTrue(lines[1].endswith(trace[4][trace[4].index('", line '):]), details())
            self.assertEqual(trace[5], lines[2], details())
            self.assertEqual(trace[-3:], lines[-3:], details())
        # Fixed: the same observation keeps every recorded Windows outcome and passes.
        self.assertEqual((1, 0, 0, sources), (new.testsRun, len(new.failures), len(new.errors), new_calls), details())


# Proposed additive class for scripts/test_python_platform_contracts.py.
# Uses its existing ast, hashlib, json, Path, unittest and subject imports.
class AndroidPersistedStartCapabilityProbeTest(unittest.TestCase):
    BEFORE_SOURCE = subject.ROOT / "agent_tools/tests/fixtures/android_persisted_start/test-portability.before.source"
    CURRENT_SOURCE_OVERRIDE = None

    def current_source(self):
        if self.CURRENT_SOURCE_OVERRIDE is not None:
            return self.CURRENT_SOURCE_OVERRIDE
        return (subject.ROOT / "agent_tools/tests/test_android_persisted_start.py").read_text(encoding="utf-8")

    @staticmethod
    def without_guard(source, class_name, method_name=None):
        """Retain the real suite and bodies while removing the named boundary."""
        tree = ast.parse(source)
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name)
        selected = owner if method_name is None else next(node for node in owner.body
            if isinstance(node, ast.FunctionDef) and node.name == method_name)
        if not selected.decorator_list:
            raise AssertionError("The causal control must remove a real platform boundary")
        selected.decorator_list = []
        return ast.unparse(tree)

    def failed_probe(self, source):
        result = subject.probe_windows_android_persisted_start_test_suite(source)
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        return json.loads(result.stdout.splitlines()[-1])

    def test_preserved_whole_beforeimage_cannot_discover_without_pwd(self):
        raw = self.BEFORE_SOURCE.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
            "e2f01038406d5169d4c7903643d240328effb4f1ec76db5d53cab935ae9d12c3")
        result = subject.probe_windows_android_persisted_start_test_suite(raw.decode("utf-8"))
        self.assertNotEqual(0, result.returncode)
        self.assertIn("No module named 'pwd'", result.stderr)

    def test_missing_controller_guard_reaches_actual_whole_source_fcntl_import(self):
        source = self.without_guard(self.current_source(), "AdmissionSamplingTests")
        summary = self.failed_probe(source)
        self.assertEqual("ModuleNotFoundError: No module named 'fcntl'",
            summary["errors"]["AdmissionSamplingTests.test_actual_one_shot_then_sampled_owner_reaches_real_final_validation"])

    def test_missing_socket_guard_reaches_real_lazy_pwd_import(self):
        source = self.without_guard(self.current_source(), "PrivilegedCompositionTests")
        summary = self.failed_probe(source)
        self.assertEqual("ModuleNotFoundError: No module named 'pwd'",
            summary["errors"]["PrivilegedCompositionTests.test_actual_owned_fixture_setup_avoids_unix_socket_path_overflow"])

    def test_missing_reader_guard_reaches_actual_emitted_fcntl_import(self):
        method = "test_original_absent_sdk_template_is_preserved_by_actual_emitted_observer"
        source = self.without_guard(self.current_source(), "PersistedStartTests", method)
        summary = self.failed_probe(source)
        self.assertEqual("ModuleNotFoundError: No module named 'fcntl'",
            summary["errors"]["PersistedStartTests." + method])

    def test_missing_renderer_guards_reaches_real_windows_path_refusal(self):
        source = self.current_source()
        methods = (
            ("AllocationCoverageTests", "test_real_renderer_seals_qualified_coverage_and_validates_receipts"),
            ("PersistedStartTests", "test_plan_preserves_exact_argv_originals_and_external_journal"),
        )
        for owner, method in methods:
            source = self.without_guard(source, owner, method)
        summary = self.failed_probe(source)
        for owner, method in methods:
            self.assertEqual("ValueError: persisted_start_external_job_root_required",
                summary["errors"][owner + "." + method])

    def test_posix_authority_fixture_refuses_real_windows_record_validation(self):
        source = self.current_source()
        original = '"path": str(LOCAL_AUTHORITY_ROOT / "reservations.json")'
        self.assertEqual(source.count(original), 1)
        source = source.replace(original, '"path": "/owned/reservations.json"')
        summary = self.failed_probe(source)
        self.assertEqual("ValueError: persisted_start_reservation_record_invalid",
            summary["errors"]["PersistedStartTests.test_all_matching_claims_are_counted_without_guessing_retirement"])

    def test_actual_suite_keeps_exact_windows_methods_and_platform_boundaries(self):
        result = subject.probe_windows_android_persisted_start_test_suite(self.CURRENT_SOURCE_OVERRIDE)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        summary = json.loads(result.stdout.splitlines()[-1])
        expected_skips = set(subject.ANDROID_PERSISTED_POSIX_METHODS) | set(subject.ANDROID_PERSISTED_LINUX_METHODS)
        self.assertEqual(36, summary["testsRun"])
        self.assertEqual(18, summary["passed"])
        self.assertEqual(expected_skips, set(summary["skipped"]))
        self.assertEqual(set(subject.ANDROID_PERSISTED_WINDOWS_METHODS), set(summary["portablePassed"]))
        self.assertEqual({}, summary["errors"])
        self.assertEqual({}, summary["failures"])


class ManifestTest(unittest.TestCase):
    def test_all_explicit_contracts_pass(self):
        self.assertEqual([], subject.check_contracts())


class WindowsNativePacketCapabilityProbeTest(unittest.TestCase):
    @staticmethod
    def without_powershell(**kwargs):
        """Remove runtime discovery only; execute the unchanged whole helper."""
        with tempfile.TemporaryDirectory(prefix="packet-no-powershell-") as empty_path:
            with patch.dict(os.environ, {"PATH": empty_path}):
                os.environ.pop("VPN_CONTROL_TEST_POWERSHELL", None)
                return subject.probe_windows_native_packet_recipe_test_suite(**kwargs)

    def summary(self, result):
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        summary = json.loads(result.stdout.splitlines()[-1])
        self.assertEqual(10, summary["testsRun"])
        self.assertEqual(8, len(summary["posixTestIds"]))
        self.assertEqual(2, len(summary["diagnosticTestIds"]))
        self.assertEqual([], summary["errors"])
        self.assertEqual([], summary["failures"])
        return summary

    def test_windows_like_suite_skips_posix_and_absent_powershell_separately(self):
        summary = self.summary(self.without_powershell())
        self.assertIsNone(summary["diagnosticPowerShellRuntime"])
        self.assertEqual(set(summary["testIds"]), {item["test"] for item in summary["skipped"]})
        diagnostic = next(item for item in summary["skipped"]
                          if item["test"] in summary["diagnosticTestIds"])
        self.assertIn("PowerShell runtime unavailable", diagnostic["reason"])

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "getuid"),
                         "requires POSIX descriptor operations")
    def test_posix_suite_retains_all_eight_bodies_when_powershell_is_absent(self):
        summary = self.summary(self.without_powershell(windows_like=False))
        self.assertEqual(set(summary["posixTestIds"]), set(summary["passed"]))
        self.assertEqual(set(summary["diagnosticTestIds"]), {item["test"] for item in summary["skipped"]})

    def test_explicit_powershell_runs_diagnostic_while_windows_like_posix_tests_skip(self):
        runtime = (os.environ.get("VPN_CONTROL_TEST_POWERSHELL")
                   or (shutil.which("powershell.exe") if os.name == "nt" else None)
                   or shutil.which("pwsh"))
        if runtime is None:
            self.skipTest("PowerShell runtime unavailable; explicit-runtime coverage requires the runtime")
        runtime = os.path.abspath(shutil.which(runtime) or runtime)
        with tempfile.TemporaryDirectory(prefix="packet-explicit-powershell-") as empty_path:
            with patch.dict(os.environ, {"PATH": empty_path, "VPN_CONTROL_TEST_POWERSHELL": runtime}):
                summary = self.summary(subject.probe_windows_native_packet_recipe_test_suite())
        self.assertEqual(runtime, summary["diagnosticPowerShellRuntime"])
        self.assertEqual(set(summary["diagnosticTestIds"]), set(summary["passed"]))
        self.assertEqual(set(summary["posixTestIds"]), {item["test"] for item in summary["skipped"]})

    def test_whole_suite_probe_rejects_the_stale_total_case_count(self):
        result = self.without_powershell(expected_tests=8)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("exact helper case count changed", result.stderr)
        self.assertEqual(10, json.loads(result.stdout.splitlines()[-1])["testsRun"])


if __name__ == "__main__":
    unittest.main()
