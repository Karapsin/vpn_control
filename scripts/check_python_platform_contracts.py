#!/usr/bin/env python3
"""Run explicit Python portability probes under missing platform capabilities.

The manifest contains only previously observed boundaries.  It is not a
repository-wide API scan: each probe imports or executes the exact code that
would otherwise first fail on an unsupported platform.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


@dataclass(frozen=True)
class ImportProbe:
    path: str
    unavailable_modules: tuple[str, ...]


@dataclass(frozen=True)
class TestMethodProbe:
    module: str
    methods: tuple[str, ...]


# Add entries only for a concrete portability regression.  The pwd probes
# verify lazy import at the real module boundary.  The monitor methods replace
# their OS object without getsid, then use create=True to supply that API.
IMPORT_PROBES = (
    ImportProbe("linux_fixture_auth.py", ("pwd",)),
    ImportProbe("linux_public_install_fixture.py", ("pwd",)),
)
METHOD_PROBES = (
    TestMethodProbe(
        "test_macos_vm_resource_monitor",
        (
            "MonitorTest.test_transient_warning_does_not_stop_owned_vm",
            "MonitorTest.test_sustained_warning_with_headroom_does_not_stop",
        ),
    ),
)

ANDROID_POSIX_METHODS = {
    "test_android_no_update_tls_preflight": (
        "PreflightScriptTest.test_packaged_cli_adb_environment_selects_absolute_driver_binary_before_fixture_work",
        "PreflightScriptTest.test_packaged_cli_subprocesses_receive_selected_adb_environment",
        "PreflightScriptTest.test_apex_target_and_colon_zero_baseline_are_used_and_restored",
        "PreflightScriptTest.test_changed_zygote_cleanup_records_failure_but_restores_public_and_receipt",
        "PreflightScriptTest.test_exact_empty_proxy_restore_survives_real_adb_shell_flattening",
        "PreflightScriptTest.test_five_field_cleanup_refuses_drift_replay_and_bad_postread",
        "PreflightScriptTest.test_injected_action_failure_still_reaches_terminal_fixture_cleanup",
        "PreflightScriptTest.test_lost_bind_mount_response_preserves_staging_and_records_unknown_mount",
        "PreflightScriptTest.test_lost_setup_reply_still_restores_measured_owned_five_fields",
        "PreflightScriptTest.test_main_preserves_route_when_single_fenced_cleanup_remove_fails",
        "PreflightScriptTest.test_main_rejects_current_hash_staged_ca_filename_before_bind",
        "PreflightScriptTest.test_main_rejects_staged_certificate_label_before_bind",
        "PreflightScriptTest.test_native_companion_proxy_residue_is_restored_after_action_failure",
        "PreflightScriptTest.test_presence_only_drift_before_setup_refuses_reverse_and_proxy",
        "PreflightScriptTest.test_push_failure_after_owned_staging_removes_stage_and_restores_public_adbd",
        "PreflightScriptTest.test_same_byte_baseline_exchange_before_setup_refuses_effects",
        "PreflightScriptTest.test_tls_fixture_cold_action_follows_ca_bind_public_adbd_and_transport",
    ),
    "test_android_installer_lifecycle": (
        "InstallerLifecycleTest.test_bad_base_hash_rejects_before_fixture_launch",
        "InstallerLifecycleTest.test_duplicate_run_marker_rejects_before_fixture_or_guest_effect",
        "InstallerLifecycleTest.test_governed_callback_rejects_missing_mismatched_and_foreign_session_evidence",
        "InstallerLifecycleTest.test_installed_callback_requires_distinct_handoff_ready_callback_before_fixture_launch",
        "InstallerLifecycleTest.test_main_forwards_file_callback_and_fixture_identity_without_stdin",
        "InstallerLifecycleTest.test_main_forwards_handoff_ready_to_two_phase_action",
        "InstallerLifecycleTest.test_preexisting_continue_file_rejects_before_fixture_launch",
        "InstallerLifecycleTest.test_private_continue_file_accepts_only_literal_continue",
        "InstallerLifecycleTest.test_private_continue_file_rejects_wrong_mode",
        "InstallerEarlyReplyEvidenceTest.test_all_four_replies_are_private_create_only_and_oversized_data_is_explicitly_bounded",
        "InstallerEarlyReplyEvidenceTest.test_check_and_download_reply_survives_result_or_owner_guard_before_probe",
        "InstallerEarlyReplyEvidenceTest.test_invoke_retains_exact_stdout_whitespace_and_nonjson_invocation_failure",
        "InstallerEarlyReplyEvidenceTest.test_noninteractive_and_interactive_guard_failures_retain_immediate_reply",
        "InstallerEarlyReplyEvidenceTest.test_rejected_cli_records_remain_private_in_exceptions_and_formatted_stderr",
        "InstallerEarlyReplyEvidenceTest.test_reply_writer_rejects_unsafe_parent_and_unbound_identity_before_publication",
    ),
}
ANDROID_WINDOWS_METHODS = (
    "test_android_no_update_tls_preflight.PreflightScriptTest.test_emulator_identity_accepts_legacy_or_boot_only_and_rejects_missing_or_conflict",
    "test_android_installer_lifecycle.WindowsAdmissionTest.test_windows_driver_rejects_before_creating_any_evidence",
    "test_android_installer_lifecycle.StrictInstallerAdmissionTest.test_unsupported_private_backend_rejects_before_public_or_download",
    "test_android_installer_lifecycle.InstallerLifecycleTest.test_windows_stat_boundary_keeps_two_phase_owner_replacement_flow",
    "test_android_installer_lifecycle.InstallerEarlyReplyEvidenceTest.test_uncaught_terminal_guard_stderr_and_other_record_guards_never_dump_payload",
)


def probe_windows_android_test_suites(
    source_overrides: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the real Android test bodies with only their module-local OS unavailable.

    Overrides let causal tests execute preserved unfixed test sources against the
    same probe. The host os module and Android privacy implementation stay intact.
    """
    methods = json.dumps(ANDROID_POSIX_METHODS)
    portable = json.dumps(ANDROID_WINDOWS_METHODS)
    return _run(f'''import builtins
from contextlib import ExitStack, redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import sys
from types import ModuleType
import unittest
from unittest.mock import patch

class WindowsOs:
    name = "nt"
    def __getattr__(self, name):
        if name in {{"getuid", "geteuid", "O_DIRECTORY", "O_NOFOLLOW"}}:
            raise AttributeError(name)
        return getattr(os, name)

surface = WindowsOs()
original_import = builtins.__import__
def local_import(name, *args, **kwargs):
    return surface if name == "os" else original_import(name, *args, **kwargs)

sources = json.load(sys.stdin)
expected = {methods}
portable = set({portable})
suite = unittest.TestSuite()
modules = []
for name in expected:
    path = Path(name + ".py").resolve()
    module = ModuleType(name)
    module.__file__ = str(path)
    module.__dict__["__builtins__"] = dict(vars(builtins), __import__=local_import)
    sys.modules[name] = module
    exec(compile(sources.get(name, path.read_text(encoding="utf-8")), str(path), "exec"), module.__dict__)
    modules.append(module)
    suite.addTests(unittest.TestLoader().loadTestsFromModule(module))

class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passed = set()
    def addSuccess(self, test):
        self.passed.add(test.id())
        super().addSuccess(test)

from agent_tools import android_installer_target as target
original_which = shutil.which
def windows_lookup(*args, **kwargs):
    # Use shutil's real Windows discovery branch, including PATHEXT, while the
    # surrounding host filesystem and pathlib keep their actual OS semantics.
    from types import SimpleNamespace
    with patch.object(sys, "platform", "win32"), patch.dict(os.environ, {{"PATHEXT": ".exe"}}), \\
         patch.object(shutil, "_winapi", SimpleNamespace(NeedCurrentDirectoryForExePath=lambda _: False), create=True):
        return original_which(*args, **kwargs)
with ExitStack() as stack:
    stack.enter_context(patch.object(modules[0].preflight, "os", surface))
    stack.enter_context(patch.object(modules[1].driver, "os", surface))
    stack.enter_context(patch.object(target, "os", surface))
    stack.enter_context(patch.object(shutil, "which", side_effect=windows_lookup))
    stack.enter_context(redirect_stdout(io.StringIO()))
    result = unittest.TextTestRunner(verbosity=1, resultclass=Result).run(suite)
skipped = {{test.id() for test, reason in result.skipped}}
required_skips = {{module + "." + method for module, names in expected.items() for method in names}}
summary = {{"testsRun": result.testsRun, "passed": len(result.passed),
    "skipped": sorted(skipped), "failures": [test.id() for test, _ in result.failures],
    "errors": [test.id() for test, _ in result.errors],
    "portablePassed": sorted(portable & result.passed)}}
print(json.dumps(summary, sort_keys=True))
assert required_skips == skipped, "Android tests have missing POSIX skips or skipped portable coverage"
assert portable <= result.passed, "Portable Windows admission/redaction coverage was skipped"
raise SystemExit(not result.wasSuccessful())
''', input_text=json.dumps(source_overrides or {}))


def probe_absent_getuid() -> subprocess.CompletedProcess[str]:
    """Exercise the guest fixture's actual file gate with Windows-like os."""
    return _run('''from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
import native_fixture_preflight as fixture
with TemporaryDirectory() as raw:
    path = Path(raw) / "workspace.json"
    path.write_text("{}", encoding="utf-8")
    with patch.object(fixture, "os", SimpleNamespace()):
        assert fixture._regular_user_file(path, 1024) is False
        assert fixture._settings(path, "https://fixture.example/test")["workspace"] is False
''')


def probe_windows_phase_recorder() -> subprocess.CompletedProcess[str]:
    """Exercise real receipt publication without Windows-missing POSIX APIs."""
    return _run('''import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import prepare_desktop_update_fixture as fixture
class WindowsOs:
    def __getattr__(self, name):
        if name in {"getuid", "geteuid", "O_DIRECTORY", "O_NOFOLLOW"}:
            raise AttributeError(name)
        return getattr(os, name)
with TemporaryDirectory() as raw:
    root = Path(raw)
    recorder = fixture.PhaseRecorder(root / ".rag_index/build-timings", "a" * 40,
        "windows-fixture", "12345678-1234-4234-9234-123456789abc", "windows-builder")
    with patch.object(fixture, "os", WindowsOs()), patch.object(fixture.platform, "system", return_value="Windows"), \\
         patch.object(fixture, "require_windows_private_acl") as acl:
        reference = recorder.finish("gradle", "base", recorder.start())
    assert (root / reference["path"]).is_file()
    assert len(acl.call_args_list) == 3
''')


def probe_windows_android_installer_boundary() -> subprocess.CompletedProcess[str]:
    """Require a clear rejection before Android evidence is created on Windows."""
    return _run('''import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
import android_installer_lifecycle as driver
from agent_tools import android_installer_target as target
class WindowsOs:
    name = "nt"
    def __getattr__(self, name):
        if name in {"getuid", "geteuid", "O_DIRECTORY", "O_NOFOLLOW"}:
            raise AttributeError(name)
        return getattr(os, name)
with TemporaryDirectory() as raw:
    path = Path(raw) / "intent.json"
    with patch.object(target, "os", WindowsOs()):
        try:
            target._write_private(path, {"state": "test"})
        except ValueError as error:
            assert "POSIX" in str(error)
        else:
            raise AssertionError("Windows private write was accepted")
    assert not path.exists()
    parsed = SimpleNamespace(api="35", device_port="123",
        reconciliation_timeout_seconds=1.0, reconciliation_poll_seconds=1.0)
    with patch.object(driver, "os", SimpleNamespace(name="nt")), \\
         patch.object(driver, "parse_args", return_value=parsed):
        try:
            driver.main()
        except SystemExit as error:
            assert "POSIX" in str(error)
        else:
            raise AssertionError("Windows lifecycle was accepted")
''')


def _run(source: str, *, timeout: int = 30, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", source], cwd=SCRIPTS, text=True,
        capture_output=True, timeout=timeout, check=False, input=input_text,
    )


def probe_source_with_unavailable_imports(source: str, unavailable_modules: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    """Execute source after making named imports fail, in an isolated process."""
    unavailable = json.dumps(list(unavailable_modules))
    encoded = json.dumps(source)
    program = f'''import builtins
blocked = set({unavailable})
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name.split('.', 1)[0] in blocked:
        raise ModuleNotFoundError(f"No module named {{name!r}}")
    return original(name, *args, **kwargs)
builtins.__import__ = guarded
exec(compile({encoded}, "platform-probe", "exec"), {{"__name__": "platform_probe"}})
'''
    return _run(program)


def probe_import(path: Path, unavailable_modules: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    return probe_source_with_unavailable_imports(path.read_text(encoding="utf-8"), unavailable_modules)


def probe_test_methods(probe: TestMethodProbe) -> subprocess.CompletedProcess[str]:
    methods = json.dumps(list(probe.methods))
    program = f'''import importlib
import unittest
module = importlib.import_module({probe.module!r})
suite = unittest.TestLoader().loadTestsFromNames({methods}, module)
result = unittest.TextTestRunner(verbosity=1).run(suite)
raise SystemExit(not result.wasSuccessful())
'''
    return _run(program)


def _failure(name: str, result: subprocess.CompletedProcess[str]) -> str:
    output = (result.stdout + result.stderr).strip()
    return f"{name} failed with exit {result.returncode}: {output[-1000:]}"


def check_contracts(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    for probe in IMPORT_PROBES:
        result = probe_import(root / "scripts" / probe.path, probe.unavailable_modules)
        if result.returncode:
            errors.append(_failure(f"blocked-import {probe.path}", result))
    for probe in METHOD_PROBES:
        result = probe_test_methods(probe)
        if result.returncode:
            errors.append(_failure(f"capability-method {probe.module}", result))
    result = probe_absent_getuid()
    if result.returncode:
        errors.append(_failure("absent-os-getuid native_fixture_preflight", result))
    for name, probe in (("windows-phase-recorder", probe_windows_phase_recorder),
                        ("windows-android-installer", probe_windows_android_installer_boundary),
                        ("windows-android-test-suites", probe_windows_android_test_suites)):
        result = probe()
        if result.returncode:
            errors.append(_failure(name, result))
    return errors


def main() -> int:
    errors = check_contracts()
    if errors:
        print("Python platform contract check failed:", file=sys.stderr)
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Python platform contracts OK ({len(IMPORT_PROBES)} import probes, {len(METHOD_PROBES) + 4} capability probes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
