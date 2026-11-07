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
        "agent_tools.tests.test_ssh_direct_inventory_diagnostic",
        ("PortableInventoryImportTests.test_unsupported_import_and_discovery_skip_before_posix_dependencies",),
    ),
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
# Visual cases observed failing on the Windows runner (run 40187428207).
VISUAL_POSIX_METHODS = {
    "test_visual_platform": (
        # The qualified capture provider is a socketserver.UnixStreamServer.
        "VisualPlatformTest.test_android_capture_handles_native_python_crlf_before_any_device_mutation",
        "VisualPlatformTest.test_android_capture_rejects_a_foreign_avd_before_any_device_mutation",
        "VisualPlatformTest.test_android_capture_rejects_stale_owned_geometry_before_any_mutation_or_output",
        "VisualPlatformTest.test_android_capture_removes_native_python_crlf_from_scene_arguments_after_device_guard",
        "VisualPlatformTest.test_local_android_capture_guard_ignores_inherited_hosted_provider",
        # Visual start admission takes the POSIX-only StoragePlans lock.
        "VisualPlatformTest.test_low_available_memory_denies_before_visual_start",
        "VisualPlatformTest.test_resource_reservation_rejects_same_platform_and_malformed_top_level",
    ),
    "test_visual_target": (
        # The QMP peer and its custody check use AF_UNIX sockets.
        "VisualTargetTests.test_foreign_socket_peer_holding_another_disk_is_never_mutated",
        "VisualTargetTests.test_missing_stop_target_cannot_send_power_to_default_vm",
        "VisualTargetTests.test_reused_peer_pid_birth_is_rejected_before_capabilities_or_power",
        "VisualTargetTests.test_unsafe_actual_disk_parent_returns_typed_blocker_without_power",
        "VisualTargetTests.test_valid_selected_disk_and_actual_peer_owner_accept_one_power_packet",
        # CreateProcess runs neither a '#!' fake nor POSIX /bin/bash.
        "VisualTargetTests.test_actual_generated_adb_caller_never_freezes_foreign_avd_on_selected_port",
        "VisualTargetTests.test_actual_hosted_workflow_caller_forwards_its_created_avd",
        "VisualTargetTests.test_full_marker_refuses_missing_target_before_ready_write",
        "VisualTargetTests.test_marker_forwards_exact_selected_target_and_failed_probe_never_marks_ready",
        "VisualTargetTests.test_windows_bootstrap_full_shell_cannot_create_default_disk_without_target",
    ),
}
# Siblings that pass on the Windows runner. The probe does not model Git Bash,
# so a portable entry must not launch the test's POSIX shell.
VISUAL_WINDOWS_METHODS = (
    "test_visual_platform.VisualPlatformTest.test_low_disk_blocks_emulator_before_reservation_or_process",
    "test_visual_platform.VisualPlatformTest.test_unsupported_lock_host_fails_before_reservation_or_launch",
    "test_visual_target.VisualTargetTests.test_capture_rejects_target_before_output_creation_or_driver",
    "test_visual_target.VisualTargetTests.test_wrong_or_missing_selectors_refuse_all_mutation_paths_before_processes",
)

# VM-host enrollment needs the POSIX ledger lock; /proc coverage needs Linux.
# Windows run 40383276339 exposed the missing enrollment-test guards.
FIXTURE_STORAGE_POSIX_METHODS = (
    "EnrollmentTest.test_unenrolled_host_refuses_then_enroll_admits_and_is_idempotent",
    "EnrollmentTest.test_unsafe_existing_ledger_refuses",
)
FIXTURE_STORAGE_LINUX_METHODS = (
    "LinuxCoverageTest.test_changed_actor_identity_refuses_without_claim",
    "LinuxCoverageTest.test_read_only_descriptor_is_not_a_writable_disk",
    "LinuxCoverageTest.test_unregistered_running_disk_blocks_then_register_covers",
)
FIXTURE_STORAGE_WINDOWS_METHODS = (
    "EnrollmentTest.test_coverage_and_register_refuse_unenrolled",
    "EnrollmentTest.test_host_program_compiles_inline",
    "EnrollmentTest.test_resolve_requires_exactly_one_actor",
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


def probe_windows_visual_test_suites(
    source_overrides: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the observed visual test bodies with Windows CPython capabilities.

    AF_UNIX and every Unix socketserver class are removed. The test modules and
    the storage-plan lock see a module-local Windows os. On POSIX hosts launches
    follow CreateProcess: a '#!' file is not an executable image, the /bin and
    /usr/bin trees are absent and a child Python lacks AF_UNIX as well. Windows
    hosts supply these semantics natively. Overrides let causal tests execute
    preserved unfixed test sources against the same probe.
    """
    payload = {"sources": source_overrides or {}, "posix": VISUAL_POSIX_METHODS,
               "portable": VISUAL_WINDOWS_METHODS}
    return _run('''import builtins
from contextlib import ExitStack, redirect_stdout
import errno
import io
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
from types import ModuleType
import unittest
from unittest.mock import patch

payload = json.load(sys.stdin)
for variable in ("VPN_CONTROL_VISUAL_TARGET_BEFORE", "VPN_CONTROL_VISUAL_QMP_ANCESTRY_BEFORE"):
    os.environ.pop(variable, None)
if hasattr(socket, "AF_UNIX"):
    del socket.AF_UNIX
for name in [name for name in vars(socketserver) if "Unix" in name]:
    delattr(socketserver, name)

class WindowsOs:
    name = "nt"
    def __getattr__(self, name):
        if name in {"getuid", "geteuid", "O_DIRECTORY", "O_NOFOLLOW"}:
            raise AttributeError(name)
        return getattr(os, name)

surface = WindowsOs()
original_import = builtins.__import__
def local_import(name, *args, **kwargs):
    return surface if name == "os" else original_import(name, *args, **kwargs)

class CreateProcess(subprocess.Popen):
    def __init__(self, args, *rest, **kwargs):
        if os.name == "posix" and isinstance(args, (list, tuple)) and args and not kwargs.get("shell"):
            args = list(args)
            program = os.fspath(args[0])
            if program == sys.executable:
                if "-c" in args[1:]:
                    source = args.index("-c", 1) + 1
                    args[source] = "import socket as _windows;del _windows.AF_UNIX;" + args[source]
            elif program.startswith(("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/")):
                raise FileNotFoundError(errno.ENOENT, "The system cannot find the file specified")
            elif os.sep in program:
                image = os.path.join(os.fspath(kwargs.get("cwd") or ""), program)
                if os.path.isfile(image):
                    with open(image, "rb") as stream:
                        if stream.read(2) == b"#!":
                            raise OSError(errno.ENOEXEC, "%1 is not a valid Win32 application")
        super().__init__(args, *rest, **kwargs)

expected = payload["posix"]
portable = set(payload["portable"])
suite = unittest.TestSuite()
for name in ("test_visual_platform", "test_visual_target"):
    path = Path(name + ".py").resolve()
    module = ModuleType(name)
    module.__file__ = str(path)
    module.__dict__["__builtins__"] = dict(vars(builtins), __import__=local_import)
    sys.modules[name] = module
    source = payload["sources"].get(name) or path.read_text(encoding="utf-8")
    exec(compile(source, str(path), "exec"), module.__dict__)
    selected = [*expected[name], *(test[len(name) + 1:] for test in sorted(portable) if test.startswith(name + "."))]
    suite.addTests(unittest.TestLoader().loadTestsFromNames(selected, module))

class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passed = set()
    def addSuccess(self, test):
        self.passed.add(test.id())
        super().addSuccess(test)

def final_line(trace):
    return [line.strip() for line in trace.splitlines() if line.strip()][-1]

import native_fixture_storage
with ExitStack() as stack:
    stack.enter_context(patch.object(native_fixture_storage, "os", surface))
    stack.enter_context(patch.object(subprocess, "Popen", CreateProcess))
    stack.enter_context(redirect_stdout(io.StringIO()))
    result = unittest.TextTestRunner(verbosity=1, resultclass=Result).run(suite)
skipped = {test.id() for test, reason in result.skipped}
required_skips = {module + "." + method for module, names in expected.items() for method in names}
summary = {"testsRun": result.testsRun, "passed": len(result.passed), "skipped": sorted(skipped),
    "errors": {test.id(): final_line(trace) for test, trace in result.errors},
    "failures": {test.id(): final_line(trace) for test, trace in result.failures},
    "portablePassed": sorted(portable & result.passed)}
print(json.dumps(summary, sort_keys=True))
assert required_skips == skipped, "Visual tests have missing POSIX skips or skipped portable coverage"
assert portable <= result.passed, "Portable Windows visual coverage was skipped"
raise SystemExit(not result.wasSuccessful())
''', timeout=120, input_text=json.dumps(payload))


def probe_windows_fixture_storage_test_suite(
    source_override: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Execute the real storage-host suite with module-local Windows capabilities.

    Test discovery sees Windows os/sys surfaces and the actual storage lock sees
    Windows os. The host interpreter and pathlib retain their native semantics.
    A complete preserved source override reproduces the original CI error.
    """
    payload = {"source": source_override,
               "skipped": (*FIXTURE_STORAGE_POSIX_METHODS, *FIXTURE_STORAGE_LINUX_METHODS),
               "portable": FIXTURE_STORAGE_WINDOWS_METHODS}
    return _run('''import builtins
import json
import os
from pathlib import Path
import sys
from types import ModuleType
import unittest
from unittest.mock import patch

payload = json.load(sys.stdin)
class WindowsOs:
    name = "nt"
    def __getattr__(self, name):
        if name in {"getuid", "geteuid", "O_DIRECTORY", "O_NOFOLLOW"}:
            raise AttributeError(name)
        return getattr(os, name)

class WindowsSys:
    platform = "win32"
    def __getattr__(self, name):
        return getattr(sys, name)

surface = WindowsOs()
windows_sys = WindowsSys()
original_import = builtins.__import__
def local_import(name, *args, **kwargs):
    if name == "os":
        return surface
    if name == "sys":
        return windows_sys
    return original_import(name, *args, **kwargs)

name = "test_fixture_storage_host"
path = Path(name + ".py").resolve()
module = ModuleType(name)
module.__file__ = str(path)
module.__dict__["__builtins__"] = dict(vars(builtins), __import__=local_import)
sys.modules[name] = module
source = payload["source"] if payload["source"] is not None else path.read_text(encoding="utf-8")
exec(compile(source, str(path), "exec"), module.__dict__)
suite = unittest.TestLoader().loadTestsFromModule(module)

class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passed = set()
    def addSuccess(self, test):
        self.passed.add(test.id())
        super().addSuccess(test)

def final_line(trace):
    return [line.strip() for line in trace.splitlines() if line.strip()][-1]

import native_fixture_storage
with patch.object(native_fixture_storage, "os", surface):
    result = unittest.TextTestRunner(verbosity=1, resultclass=Result).run(suite)
skipped = {test.id() for test, reason in result.skipped}
required_skips = {name + "." + method for method in payload["skipped"]}
portable = {name + "." + method for method in payload["portable"]}
summary = {"testsRun": result.testsRun, "passed": len(result.passed), "skipped": sorted(skipped),
    "errors": {test.id(): final_line(trace) for test, trace in result.errors},
    "failures": {test.id(): final_line(trace) for test, trace in result.failures},
    "portablePassed": sorted(portable & result.passed)}
print(json.dumps(summary, sort_keys=True))
assert required_skips == skipped, "Storage-host tests have missing platform skips or skipped portable coverage"
assert portable <= result.passed, "Portable Windows storage-host coverage was skipped"
raise SystemExit(not result.wasSuccessful())
''', input_text=json.dumps(payload))


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
import sys
import unittest
sys.path.insert(0, {str(ROOT)!r})
module = importlib.import_module({probe.module!r})
suite = unittest.TestLoader().loadTestsFromNames({methods}, module)
result = unittest.TextTestRunner(verbosity=1).run(suite)
raise SystemExit(not result.wasSuccessful())
'''
    return _run(program)


def _failure(name: str, result: subprocess.CompletedProcess[str]) -> str:
    output = (result.stdout + result.stderr).strip()
    return f"{name} failed with exit {result.returncode}: {output[-1000:]}"


# Proposed additive definitions for scripts/check_python_platform_contracts.py.
# Reuses that module's ROOT, json, subprocess and _run; no test-module meta-probe.
ANDROID_PERSISTED_POSIX_METHODS = (
    'AdmissionSamplingTests.test_actual_one_shot_then_sampled_owner_reaches_real_final_validation',
    'AdmissionSamplingTests.test_admit_typed_readiness_change_retains_original_but_refuses_retry_data',
    'AdmissionSamplingTests.test_fifth_fresh_admission_uses_only_last_fully_validated_receipt',
    'AdmissionSamplingTests.test_final_candidate_still_requires_actual_renderer_validation',
    'AdmissionSamplingTests.test_five_unknown_replies_exhaust_without_plan_or_submit',
    'AdmissionSamplingTests.test_other_block_or_untyped_context_never_samples_again',
    'AdmissionSamplingTests.test_other_typed_readiness_results_keep_original_collection_behavior',
    'AdmissionSamplingTests.test_partial_drift_and_malformed_raw_stop_without_plan_or_submit',
    'AllocationCoverageTests.test_real_renderer_seals_qualified_coverage_and_validates_receipts',
    'PersistedStartTests.test_newly_absent_sdk_file_still_blocks_actual_emitted_observer',
    'PersistedStartTests.test_observer_executes_complete_namespace_and_refuses_coordinator',
    'PersistedStartTests.test_original_absent_sdk_template_is_preserved_by_actual_emitted_observer',
    'PersistedStartTests.test_plan_preserves_exact_argv_originals_and_external_journal',
    'PersistedStartTests.test_start_runtime_refuses_unqualified_installer_before_avd_reads',
    'PersistedStartTests.test_supervisor_preflight_reopens_names_after_inherited_fds_close',
    'PrivilegedCompositionTests.test_actual_final_caller_keeps_header_body_through_privileged_modes',
    'PrivilegedCompositionTests.test_actual_owned_fixture_setup_avoids_unix_socket_path_overflow',
)

ANDROID_PERSISTED_LINUX_METHODS = (
    'PersistedStartTests.test_unchanged_supervisor_waits_for_forked_launcher_descendant',
)

ANDROID_PERSISTED_WINDOWS_METHODS = (
    'AllocationCoverageTests.test_changed_or_ambiguous_bracket_and_catalog_refuse',
    'AllocationCoverageTests.test_complete_bridge_streams_remain_required',
    'AllocationCoverageTests.test_coverage_is_optional_and_conservative_without_a_capsule',
    'AllocationCoverageTests.test_failed_probe_keeps_both_complete_bridge_streams',
    'AllocationCoverageTests.test_qualified_same_generation_capacity_keeps_every_held_claim',
    'AllocationCoverageTests.test_unrepresented_native_allocation_is_charged_in_full',
    'AllocationCoverageTests.test_wrong_claim_or_local_chain_never_mints_coverage',
    'NativeAdvisoryHarnessTests.test_actual_advisory_call_uses_supported_route_timeout',
    'PersistedStartTests.test_all_matching_claims_are_counted_without_guessing_retirement',
    'PersistedStartTests.test_canonical_capacity_refuses_unknown_pressure_and_swap_out',
    'PersistedStartTests.test_canonical_capacity_retains_claims_and_avoids_available_double_count',
    'PersistedStartTests.test_missing_installer_capsule_cannot_create_a_start_plan',
    'PersistedStartTests.test_native_capacity_refusal_is_preserved',
    'PersistedStartTests.test_native_original_actor_absence_is_not_inferred_from_new_uuid',
    'PersistedStartTests.test_native_probe_clean_unknown_exit_is_retained_and_blocks',
    'PersistedStartTests.test_same_path_does_not_qualify_different_avd_configuration',
    'PersistedStartTests.test_tampered_reservation_bytes_refuse',
    'PersistedStartTests.test_unknown_or_incomplete_visibility_never_produces_start_plan',
)

def probe_windows_android_persisted_start_test_suite(
    source_override: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Discover the whole source; execute portable methods under missing POSIX capabilities.

    The source override admits retained whole beforeimages to the same actual
    probe. No synthetic replacement tests, POSIX host monkeypatch or recursion.
    """
    payload = {"root": str(ROOT), "source": source_override,
        "posix": ANDROID_PERSISTED_POSIX_METHODS,
        "linux": ANDROID_PERSISTED_LINUX_METHODS,
        "portable": ANDROID_PERSISTED_WINDOWS_METHODS}
    return _run(r'''
import builtins
from contextlib import ExitStack, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from types import ModuleType
import tempfile
import unittest
from unittest.mock import patch

payload = json.load(sys.stdin)
root = Path(payload["root"])
sys.path.insert(0, str(root))
path = root / "agent_tools/tests/test_android_persisted_start.py"
source = path.read_text(encoding="utf-8") if payload["source"] is None else payload["source"]
original_import = builtins.__import__
unavailable = {"pwd", "fcntl"}
def guarded_import(name, *args, **kwargs):
    if name.split(".", 1)[0] in unavailable:
        raise ModuleNotFoundError("No module named " + repr(name))
    return original_import(name, *args, **kwargs)

# Only the test module sees missing Windows APIs. Global pathlib and tempfile
# continue to operate on the actual host filesystem.
surface = ModuleType("os")
vars(surface).update(vars(os))
for name in ("getuid", "geteuid", "getgid", "getegid", "getgroups", "setuid",
             "setgid", "setgroups", "fork", "getsid", "setsid", "killpg",
             "O_DIRECTORY", "O_NOFOLLOW", "fstatvfs", "fchmod", "chown"):
    vars(surface).pop(name, None)
surface.name = "nt"
windows_sys = ModuleType("sys")
vars(windows_sys).update(vars(sys))
windows_sys.platform = "win32"
def local_import(name, *args, **kwargs):
    if name == "os": return surface
    if name == "sys": return windows_sys
    return guarded_import(name, *args, **kwargs)

original_tempdir = tempfile.TemporaryDirectory
def windows_tempdir(*args, **kwargs):
    if kwargs.get("dir") == "/tmp":
        raise FileNotFoundError(2, "Windows capability model has no literal /tmp", "/tmp")
    return original_tempdir(*args, **kwargs)

original_run = subprocess.run
def child_run(command, *args, **kwargs):
    # Preserve the absent modules in actual emitted Python child programs, too.
    # Otherwise a removed guard could accidentally borrow this POSIX host's fcntl.
    if (isinstance(command, (list, tuple)) and "-c" in command
            and Path(command[0]).resolve() == Path(sys.executable).resolve()):
        index = command.index("-c") + 1
        emitted = command[index]
        wrapper = ("import builtins\n_original=__import__\n"
            "def _blocked(name,*args,**kwargs):\n"
            " if name.split('.',1)[0] in {'pwd','fcntl'}:\n"
            "  raise ModuleNotFoundError('No module named '+repr(name))\n"
            " return _original(name,*args,**kwargs)\n"
            "builtins.__import__=_blocked\n"
            "exec(compile(" + repr(emitted) + ",'<exact-emitted-child-source>','exec'),"
            "{'__name__':'__main__'})\n")
        command = list(command); command[index] = wrapper
    return original_run(command, *args, **kwargs)

builtins.__import__ = guarded_import
name = "agent_tools.tests._android_persisted_platform_probe"
module = ModuleType(name)
module.__file__ = str(path)
module.__package__ = "agent_tools.tests"
module.__dict__["__builtins__"] = dict(vars(builtins), __import__=local_import)
sys.modules[name] = module
# Only this production module's Path binding is projected. Exact source-file
# reads retain the host filesystem; authority, localInputPins and remote job
# paths receive real Windows lexical semantics instead of borrowing PosixPath.
from pathlib import PureWindowsPath
from agent_tools import android_persisted_start as production_start
host_path = production_start.Path
source_file = production_start.__file__
def windows_semantic_path(value):
    if value == source_file: return host_path(value)
    return PureWindowsPath(value)
production_start.Path = windows_semantic_path
assert not PureWindowsPath("/owned/reservations.json").is_absolute()
assert PureWindowsPath("C:/vpn-control-owned-inert/reservations.json").is_absolute()

# Discovery executes the complete supplied test source before any selection.
exec(compile(source, str(path), "exec", dont_inherit=True), vars(module))
assert module.os.name == "nt" and module.sys.platform == "win32"
suite = unittest.TestLoader().loadTestsFromModule(module)

def short_id(test): return test.id().removeprefix(name + ".")
class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs); self.passed = set()
    def addSuccess(self, test):
        self.passed.add(short_id(test)); super().addSuccess(test)

def final_line(trace):
    lines = [line.strip() for line in trace.splitlines() if line.strip()]
    return lines[-1][-500:]

with ExitStack() as stack:
    stack.enter_context(patch.object(tempfile, "TemporaryDirectory", windows_tempdir))
    stack.enter_context(patch.object(subprocess, "run", child_run))
    stack.enter_context(redirect_stdout(io.StringIO()))
    result = unittest.TextTestRunner(stream=io.StringIO(), resultclass=Result).run(suite)
skipped = {short_id(test) for test, _ in result.skipped}
portable = set(payload["portable"])
required_skips = set(payload["posix"]) | set(payload["linux"])
summary = {"testsRun": result.testsRun, "passed": len(result.passed),
    "sourceSha256": hashlib.sha256(source.encode()).hexdigest(),
    "skipped": sorted(skipped), "portablePassed": sorted(result.passed),
    "errors": {short_id(test): final_line(trace) for test, trace in result.errors},
    "failures": {short_id(test): final_line(trace) for test, trace in result.failures}}
print(json.dumps(summary, sort_keys=True))
assert skipped == required_skips, "Persisted-start POSIX/Linux skips changed or portable coverage was skipped"
assert result.passed == portable, "Persisted-start portable Windows methods changed or failed"
assert result.testsRun == len(portable | required_skips), "Persisted-start discovery coverage changed"
raise SystemExit(not result.wasSuccessful())
''', input_text=json.dumps(payload))


def probe_windows_native_packet_recipe_test_suite(
    helper_path: Path | None = None,
    *, expected_tests: int = 10, windows_like: bool = True,
    temporary_root: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the complete registered helper under declared missing OS capabilities.

    The missing-API peer is local to the helper and its boundary source imports;
    the host os module, Python imports, and production privacy code stay intact.
    """
    return _run('''import builtins
import collections
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import types
import unittest

config = json.load(sys.stdin)
path = Path(config["helperPath"]).resolve(strict=True)
boundary_path = path.parent / "fixtures/windows_native_packet_recipe/boundary.py"
sys.dont_write_bytecode = True
if config["temporaryRoot"] is not None:
    tempfile.tempdir = config["temporaryRoot"]

class WindowsOs:
    name = "nt"
    def __getattr__(self, name):
        if name in {"O_NOFOLLOW", "getuid"}:
            raise AttributeError(name)
        return getattr(os, name)

surface = WindowsOs()
original_import = builtins.__import__
imports = []
def declared_import(name, globals=None, locals=None, fromlist=(), level=0):
    origin = None if globals is None else globals.get("__file__")
    if config["windowsLike"] and name == "os" and origin in {str(path), str(boundary_path)}:
        imports.append({"name": name, "source": origin, "declaredPeer": "WindowsOs", "missing": ["O_NOFOLLOW", "getuid"]})
        return surface
    return original_import(name, globals, locals, fromlist, level)

name = "_windows_native_recipe_capability_probe"
spec = importlib.util.spec_from_file_location(name, path)
module = importlib.util.module_from_spec(spec)
assert name not in sys.modules
sys.modules[name] = module
calls = collections.Counter()
owners = {}
def profile(frame, event, arg):
    origin = frame.f_code.co_filename
    if event == "call" and origin in {str(path), str(boundary_path)}:
        owner_name = frame.f_globals.get("__name__")
        registered = sys.modules.get(owner_name)
        assert registered is not None and registered.__dict__ is frame.f_globals
        calls[(origin, frame.f_code.co_name)] += 1
        owners[owner_name] = {"source": origin, "completeRegisteredNamespace": True}

prior_profile = sys.getprofile()
builtins.__import__ = declared_import
try:
    sys.setprofile(profile)
    spec.loader.exec_module(module)
    cases = (module.WindowsNativePacketRecipeTest, module.DiagnosticResultContainerPowerShellTest)
    original_functions = {case: {key: value for key, value in vars(case).items() if callable(value)}
                          for case in cases}
    loader = unittest.TestLoader()
    posix_ids = {test.id() for test in loader.loadTestsFromTestCase(cases[0])}
    diagnostic_ids = {test.id() for test in loader.loadTestsFromTestCase(cases[1])}
    suite = loader.loadTestsFromModule(module)
    test_ids = [test.id() for group in suite for test in group]
    output = io.StringIO()
    result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
    assert all(vars(case)[key] is value for case, functions in original_functions.items()
               for key, value in functions.items())
    assert all(case.__module__ == module.__name__ for case in cases)
    assert module.render_operator.__globals__ is module.__dict__
finally:
    sys.setprofile(prior_profile)
    builtins.__import__ = original_import

skipped_ids = {test.id() for test, reason in result.skipped}
failed_ids = {test.id() for test, error in result.failures + result.errors}
passed_ids = set(test_ids) - skipped_ids - failed_ids
powershell = (os.environ.get("VPN_CONTROL_TEST_POWERSHELL")
              or (shutil.which("powershell.exe") if config["windowsLike"] or os.name == "nt" else None)
              or shutil.which("pwsh"))
terminal = {
    "testsRun": result.testsRun,
    "testIds": test_ids,
    "skipped": [{"test": test.id(), "reason": reason} for test, reason in result.skipped],
    "failures": [{"test": test.id(), "traceback": error} for test, error in result.failures],
    "errors": [{"test": test.id(), "traceback": error} for test, error in result.errors],
    "successful": result.wasSuccessful(),
    "passed": sorted(passed_ids),
    "posixTestIds": sorted(posix_ids),
    "diagnosticTestIds": sorted(diagnostic_ids),
    "diagnosticPowerShellRuntime": powershell,
    "helperPath": str(path),
    "helperSha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    "boundaryPath": str(boundary_path),
    "boundarySha256": hashlib.sha256(boundary_path.read_bytes()).hexdigest(),
    "helperModule": module.__name__,
    "helperWholeRegisteredModuleCalls": calls[(str(path), "<module>")],
    "boundaryWholeRegisteredModuleCalls": calls[(str(boundary_path), "<module>")],
    "registeredModuleOwners": owners,
    "sourceCalls": [{"source": source, "function": function, "calls": count} for (source, function), count in sorted(calls.items())],
    "declaredOsPeerImports": imports,
    "callerFunctionsReplaced": False,
    "wholeHelperAndFixtureSourceUnmodified": True,
    "windowsLike": config["windowsLike"],
    "realNetworkOrGuestActions": False,
}
print(output.getvalue(), file=sys.stderr, end="")
print(json.dumps(terminal, sort_keys=True))
assert terminal["helperWholeRegisteredModuleCalls"] == 1
assert len(posix_ids) == 8 and len(diagnostic_ids) == 2, "exact helper class case counts changed"
assert set(test_ids) == posix_ids | diagnostic_ids, "unclassified helper coverage"
assert result.testsRun == config["expectedTests"], "exact helper case count changed"
if result.wasSuccessful():
    expected_posix_skips = posix_ids if config["windowsLike"] else set()
    assert skipped_ids & posix_ids == expected_posix_skips, "POSIX helper capability coverage changed"
    if powershell is None:
        assert skipped_ids & diagnostic_ids == diagnostic_ids, "unavailable PowerShell diagnostic did not skip"
    else:
        assert diagnostic_ids <= passed_ids, "available PowerShell diagnostic coverage skipped"
raise SystemExit(not result.wasSuccessful())
''', timeout=180, input_text=json.dumps({
        "helperPath": str(helper_path or ROOT / "agent_tools/tests/test_windows_native_packet_recipe.py"),
        "expectedTests": expected_tests,
        "windowsLike": windows_like,
        "temporaryRoot": None if temporary_root is None else str(temporary_root),
    }))


def probe_windows_main_input_bridge_test_suite(
    helper_path: Path | None = None, *, powershell_absent: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Whole routine suite with local absent-POSIX and optional absent-PS peers.

    Only test/boundary imports see these capability peers. Production module
    imports, original method objects and complete registered namespaces remain
    unchanged. No guest, network, credentials or input is involved.
    """
    return _run('''import builtins
import collections
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import types
import unittest

config = json.load(sys.stdin)
path = Path(config["helperPath"]).resolve(strict=True)
boundary = path.parent / "fixtures/windows_main_input_bridge/boundary.py"
origins = {str(path), str(boundary)}
original_import = builtins.__import__
class MissingPosix:
    name = "nt"
    environ = {key: value for key, value in os.environ.items()
               if not(config["powershellAbsent"] and key == "VPN_CONTROL_TEST_POWERSHELL")}
    def __getattr__(self, name):
        if name in {"getuid", "O_NOFOLLOW", "O_DIRECTORY", "pread", "fchmod"}:
            raise AttributeError(name)
        return getattr(os, name)
class MissingPowerShell:
    def which(self, executable):
        return None
    def __getattr__(self, name):
        return getattr(shutil, name)
def peer_import(name, globals=None, locals=None, fromlist=(), level=0):
    origin = None if globals is None else globals.get("__file__")
    if origin in origins and name == "os":
        return MissingPosix()
    if origin in origins and name == "shutil" and config["powershellAbsent"]:
        return MissingPowerShell()
    return original_import(name, globals, locals, fromlist, level)

module_name = "_windows_main_input_capability_profile"
spec = importlib.util.spec_from_file_location(module_name, path)
module = importlib.util.module_from_spec(spec)
sys.modules[module_name] = module
counts = collections.Counter()
registered = {}
def profile(frame, event, arg):
    if event != "call":
        return
    name = frame.f_globals.get("__name__", "")
    if name == module_name or name == "_windows_main_input_routine_boundary" or name.startswith("_windows_main_input_whole_current_"):
        owner = sys.modules.get(name)
        assert owner is not None and owner.__dict__ is frame.f_globals
        counts[(name, frame.f_code.co_name)] += 1
        registered[name] = {"file": frame.f_globals.get("__file__"), "completeRegisteredNamespace": True}

prior_profile = sys.getprofile()
builtins.__import__ = peer_import
try:
    sys.setprofile(profile)
    spec.loader.exec_module(module)
    cases = (module.WindowsMainInputBridgePosixTest, module.WindowsMainInputBridgePowerShellTest,
             module.WindowsMainInputBridgeHistoricalCausalTest, module.WindowsMainInputBridgeCatalogTest)
    loader = unittest.TestLoader()
    groups = {case.__name__: {test.id() for test in loader.loadTestsFromTestCase(case)} for case in cases}
    original_functions = {case: {key: value for key, value in vars(case).items() if callable(value)} for case in cases}
    suite = loader.loadTestsFromModule(module)
    output = io.StringIO()
    result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
    assert all(vars(case)[key] is value for case, functions in original_functions.items() for key, value in functions.items())
finally:
    sys.setprofile(prior_profile)
    builtins.__import__ = original_import

skipped = {test.id() for test, reason in result.skipped}
failed = {test.id() for test, error in result.failures + result.errors}
all_ids = set().union(*groups.values())
passed = all_ids - skipped - failed
posix_ids = groups["WindowsMainInputBridgePosixTest"] | groups["WindowsMainInputBridgeHistoricalCausalTest"]
ps_ids = groups["WindowsMainInputBridgePowerShellTest"]
catalog_ids = groups["WindowsMainInputBridgeCatalogTest"]
runtime = module._powershell
expected_skips = posix_ids | (ps_ids if runtime is None else set())
summary = {"testsRun": result.testsRun, "successful": result.wasSuccessful(), "passed": sorted(passed),
    "skipped": sorted(skipped), "failures": [{"test": test.id(), "error": error} for test, error in result.failures],
    "errors": [{"test": test.id(), "error": error} for test, error in result.errors],
    "sourceMethodObjectsUnchanged": True, "registeredWholeNamespaces": registered,
    "registeredWholeCalls": [{"module": key[0], "function": key[1], "calls": count} for key, count in sorted(counts.items())],
    "declaredMissingPosix": ["getuid", "O_NOFOLLOW", "O_DIRECTORY", "pread", "fchmod"],
    "powerShellIntentionallyUnavailable": config["powershellAbsent"], "actualPowerShellRuntime": runtime,
    "nativeNetworkCredentialsOrInput": False}
print(output.getvalue(), file=sys.stderr, end="")
print(json.dumps(summary, sort_keys=True))
assert len(groups["WindowsMainInputBridgePosixTest"]) == 33
assert len(groups["WindowsMainInputBridgePowerShellTest"]) == 8
assert len(groups["WindowsMainInputBridgeHistoricalCausalTest"]) == 13
assert len(groups["WindowsMainInputBridgeCatalogTest"]) == 2
assert result.testsRun == 56 and set(skipped) == expected_skips
assert catalog_ids <= passed
if runtime is not None:
    assert ps_ids <= passed, "available PowerShell current method coverage skipped"
assert counts[(module_name, "<module>")] == 1
assert counts[("_windows_main_input_routine_boundary", "<module>")] == 1
assert sum(count for (name, function), count in counts.items() if name.startswith("_windows_main_input_whole_current_") and function == "<module>") == 1
raise SystemExit(not result.wasSuccessful())
''', timeout=45, input_text=json.dumps({
        "helperPath": str(helper_path or ROOT / "agent_tools/tests/test_windows_main_input_bridge.py"),
        "powershellAbsent": powershell_absent,
    }))

def probe_windows_main_input_bridge_without_powershell() -> subprocess.CompletedProcess[str]:
    return probe_windows_main_input_bridge_test_suite(powershell_absent=True)


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
                        ("windows-android-test-suites", probe_windows_android_test_suites),
                        ("windows-visual-test-suites", probe_windows_visual_test_suites),
                        ("windows-fixture-storage-test-suite", probe_windows_fixture_storage_test_suite),
                        ("windows-android-persisted-start-test-suite", probe_windows_android_persisted_start_test_suite),
                        ("windows-native-packet-recipe-test-suite", probe_windows_native_packet_recipe_test_suite),
                        ("windows-main-input-bridge-test-suite", probe_windows_main_input_bridge_test_suite),
                        ("windows-main-input-bridge-without-powershell", probe_windows_main_input_bridge_without_powershell)):
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
    print(f"Python platform contracts OK ({len(IMPORT_PROBES)} import probes, {len(METHOD_PROBES) + 10} capability probes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
