"""Fail-closed, read-only VM fixture admission helpers.

This module deliberately neither starts nor stops a VM, executes an arbitrary
fixture, writes a reservation, nor retries an uncertain operation.  The MCP
surface may use these checks to prepare a later explicitly-owned action.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = REPO_ROOT / "scripts"
_SAFE_RESERVATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DESKTOP_UPDATE_PREFLIGHT = "desktop-update-entrypoint"
_DESKTOP_UPDATE_MODULES = (
    "prepare_desktop_update_fixture.py",
    "fixture_environment.py",
    "macos_packaging_jdk_preflight.py",
)
_GUEST_INPUT_CHECK = """import runpy, sys
module = runpy.run_path(sys.argv[1])
try:
    expected = module['GuestFixtureInput'](size=int(sys.argv[3]), sha256=sys.argv[4])
    module['assert_guest_fixture_input'](module['Path'](sys.argv[2]), expected)
except (OSError, ValueError) as error:
    print(str(error), file=sys.stderr)
    raise SystemExit(64)
"""


class VmWorkflowError(ValueError):
    """A fixture input or planned VM allocation cannot be admitted."""


def _require_input(value: Mapping[str, Any]) -> tuple[Path, int, str]:
    if not isinstance(value, Mapping):
        raise VmWorkflowError("fixture input must be an object")
    path, size, digest = value.get("path"), value.get("size"), value.get("sha256")
    if not isinstance(path, str) or not path:
        raise VmWorkflowError("fixture input path is required")
    if isinstance(size, bool) or not isinstance(size, int):
        raise VmWorkflowError("fixture input size must be an integer")
    if not isinstance(digest, str):
        raise VmWorkflowError("fixture input SHA-256 is required")
    return Path(path), size, digest


def _assert_guest_fixture_input(path: Path, size: int, digest: str) -> None:
    """Run the checked-in verifier in a fresh process, independent of CWD."""
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", _GUEST_INPUT_CHECK,
         str(SCRIPTS_ROOT / "guest_fixture_input.py"), str(path), str(size), digest],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        diagnostic = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "no diagnostic"
        raise VmWorkflowError(diagnostic)


def inspect_input(input: Mapping[str, Any], *, preflight: str | None = None) -> dict[str, Any]:
    """Verify one nonempty staged Python file, optionally using a named safe preflight.

    ``desktop-update-entrypoint`` is the sole execution preflight.  It calls the
    existing isolated staged-entrypoint import check for the checked-in desktop
    fixture only.  Arbitrary Python is never imported or executed here.
    """
    path, size, digest = _require_input(input)
    if path.suffix != ".py":
        raise VmWorkflowError("fixture input must be a Python file")
    try:
        _assert_guest_fixture_input(path, size, digest)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        raise VmWorkflowError(str(error)) from error

    result: dict[str, Any] = {
        "ok": True,
        "state": "ready",
        "path": str(path),
        "size": size,
        "sha256": digest,
        "preflight": "hash-only",
        "nativeActionAllowed": False,
    }
    if preflight is None:
        return result
    if preflight != _DESKTOP_UPDATE_PREFLIGHT:
        raise VmWorkflowError("preflight is not an approved no-action fixture preflight")

    if path.name != _DESKTOP_UPDATE_MODULES[0]:
        raise VmWorkflowError("desktop update preflight requires its declared entrypoint")
    modules = _require_canonical_staged_modules(path.parent)
    try:
        _isolated_staged_import(path.name, modules)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        raise VmWorkflowError(str(error)) from error
    result["preflight"] = preflight
    return result


def _require_canonical_staged_modules(directory: Path) -> dict[str, bytes]:
    """Require the only importable preflight payload to equal checked-in sources."""
    modules: dict[str, bytes] = {}
    for name in _DESKTOP_UPDATE_MODULES:
        canonical = SCRIPTS_ROOT / name
        staged = directory / name
        try:
            contents = canonical.read_bytes()
            _assert_guest_fixture_input(staged, len(contents), hashlib.sha256(contents).hexdigest())
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            raise VmWorkflowError(f"staged approved module differs from checked-in {name}: {error}") from error
        modules[name] = contents
    return modules


def _isolated_staged_import(entrypoint_name: str, modules: Mapping[str, bytes]) -> None:
    """Import a private copy of verified fixture bytes outside the MCP process."""
    command = (
        "import importlib.util, pathlib, sys; "
        "entrypoint = pathlib.Path(sys.argv[1]); "
        "sys.path.insert(0, str(entrypoint.parent)); "
        "spec = importlib.util.spec_from_file_location('staged_fixture_entrypoint', entrypoint); "
        "module = importlib.util.module_from_spec(spec); "
        "spec.loader.exec_module(module)"
    )
    with tempfile.TemporaryDirectory(prefix="vm-workflow-preflight-") as private_directory, \
            tempfile.TemporaryDirectory(prefix="vm-workflow-foreign-") as foreign_cwd:
        private_root = Path(private_directory)
        for name, contents in modules.items():
            target = private_root / name
            target.write_bytes(contents)
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", command, str(private_root / entrypoint_name)],
            cwd=foreign_cwd,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": ""},
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    if result.returncode != 0:
        diagnostic = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "no diagnostic"
        raise VmWorkflowError("staged fixture entrypoint import failed: " + diagnostic)


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise VmWorkflowError(f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise VmWorkflowError(f"{label} must be a non-negative integer")
    return value


def admit_plan(
    measurement: Mapping[str, Any],
    *,
    requested_memory_bytes: int,
    headroom_bytes: int,
    reservations: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Calculate a conservative VM allocation plan from explicit observations.

    The caller supplies the measurement; this is arithmetic, not a claim that a
    live host or VM was observed.  The returned reservation is deliberately not
    persisted, and it never authorizes a VM start.
    """
    if not isinstance(measurement, Mapping):
        raise VmWorkflowError("host measurement must be an object")
    physical = _positive_int(measurement.get("physicalMemoryBytes"), "physical memory")
    running = _nonnegative_int(measurement.get("runningConfiguredMemoryBytes"), "running configured memory")
    swap = measurement.get("swapUsedBytes")
    if isinstance(swap, bool) or not isinstance(swap, int) or swap < 0:
        raise VmWorkflowError("swap usage must be a non-negative integer")
    pressure = measurement.get("pressure")
    if isinstance(pressure, bool) or pressure not in ("normal", "1", 1):
        raise VmWorkflowError("host memory pressure is not normal")
    if swap != 0:
        raise VmWorkflowError("host swap use prevents VM admission")
    requested = _positive_int(requested_memory_bytes, "requested memory")
    headroom = _positive_int(headroom_bytes, "host headroom")

    reserved = 0
    reservation_ids: list[str] = []
    for reservation in reservations:
        if not isinstance(reservation, Mapping):
            raise VmWorkflowError("reservation must be an object")
        identifier = reservation.get("id")
        if not isinstance(identifier, str) or not _SAFE_RESERVATION_ID.fullmatch(identifier):
            raise VmWorkflowError("reservation id is unsafe")
        if identifier in reservation_ids:
            raise VmWorkflowError("reservation ids must be unique")
        reservation_ids.append(identifier)
        reserved += _positive_int(reservation.get("memoryBytes"), "reservation memory")

    required = running + reserved + requested + headroom
    if required > physical:
        raise VmWorkflowError(
            f"planned allocation needs {required} bytes but host reports {physical} bytes"
        )
    return {
        "ok": True,
        "state": "planned",
        "authorization": "none",
        "measurementSource": "caller-supplied",
        "physicalMemoryBytes": physical,
        "runningConfiguredMemoryBytes": running,
        "reservedMemoryBytes": reserved,
        "requestedMemoryBytes": requested,
        "headroomBytes": headroom,
        "requiredMemoryBytes": required,
        "availableMemoryBytes": physical - required,
        "reservation": {"memoryBytes": requested, "persisted": False},
        "nativeActionAllowed": False,
    }
