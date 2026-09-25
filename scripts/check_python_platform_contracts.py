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


def _run(source: str, *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", source], cwd=SCRIPTS, text=True,
        capture_output=True, timeout=timeout, check=False,
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
    return errors


def main() -> int:
    errors = check_contracts()
    if errors:
        print("Python platform contract check failed:", file=sys.stderr)
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Python platform contracts OK ({len(IMPORT_PROBES)} import probes, {len(METHOD_PROBES) + 1} capability probes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
