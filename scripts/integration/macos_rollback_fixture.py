#!/usr/bin/env python3
"""Bounded, durable macOS rollback fixture driver.

This is deliberately a driver, not an installer implementation.  It only speaks
to the public control CLI, holds one advisory shared lock that it owns, and
records enough evidence to resume inspection of an unknown job without replaying
it.  Run it only in an owned disposable macOS guest with an already-prepared
fixture server and task-local trust material.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Protocol
from uuid import UUID

_SCRIPT_ROOT = Path(__file__).resolve().parent.parent
if str(_SCRIPT_ROOT) not in sys.path: sys.path.insert(0, str(_SCRIPT_ROOT))
from macos_fixture_processes import FixtureProcessObserver, INITIAL_SERVE_OWNER, process_rows


class FixtureError(RuntimeError):
    pass


class FixtureTimeout(FixtureError):
    """A timeout deliberately leaves every external job and fixture input intact."""


class Step(str, Enum):
    BASE_VERIFIED = "base_verified"
    OWNER_READY = "owner_ready"
    UPDATE_READY = "update_ready"
    LOCK_HELD = "lock_held"
    INSTALL_ACCEPTED = "install_accepted"
    WAITING_FOR_EXIT = "waiting_for_exit"
    CANDIDATE_ARMED = "candidate_armed"
    HANDOFF_ACKNOWLEDGED = "handoff_acknowledged"
    OWNER_EXITED = "owner_exited"
    LOCK_RELEASED = "lock_released"
    TERMINAL = "terminal"
    BASE_RESTORED = "base_restored"
    CLEANED = "cleaned"


class ReceiptAuthority(str, Enum):
    USER_LOCAL = "user-local"
    MACHINE = "machine"


@dataclass(frozen=True)
class Identity:
    device: int
    inode: int
    sha256: str

    def as_json(self) -> dict[str, Any]:
        return {"device": self.device, "inode": self.inode, "sha256": self.sha256}


@dataclass(frozen=True)
class FixtureSpec:
    app: Path
    state_dir: Path
    expected_base_package: Path
    expected_target_package: Path
    expected_base_package_sha256: str
    expected_target_package_sha256: str
    expected_target_code_sha256: str
    expected_base_identity: Identity
    receipt_authority: ReceiptAuthority
    owner_home: Path
    timeout_seconds: float = 120.0
    poll_seconds: float = 0.2


class Boundary(Protocol):
    def now(self) -> float: ...
    def sleep(self, seconds: float) -> None: ...
    def identity(self, path: Path) -> Identity: ...
    def sha256(self, path: Path) -> str: ...
    def verify_signature(self, app: Path) -> None: ...
    def owner_ready(self, app: Path, state_dir: Path) -> int: ...
    def owner_alive(self, owner_pid: int, app: Path, state_dir: Path) -> bool: ...
    def public(self, app: Path, state_dir: Path, *args: str) -> dict[str, Any]: ...
    def receipt(self, job_id: str, authority: ReceiptAuthority, owner_home: Path) -> dict[str, Any]: ...
    def arm_immutable(self, candidate: Path, identity: Identity, job_id: str, authority: ReceiptAuthority) -> None: ...
    def clear_immutable(self, candidate: Path, identity: Identity, job_id: str, authority: ReceiptAuthority) -> None: ...
    def coordinator_absent(self, job_id: str, owner_pid: int) -> bool: ...
    def acquire_shared_launcher_lock(self, launcher: Path) -> object: ...
    def release_shared_launcher_lock(self, token: object) -> None: ...


def _exact_hash(value: str, label: str) -> str:
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise FixtureError(f"{label} must be a lowercase SHA-256")
    return value


def _require_ok(envelope: dict[str, Any], label: str) -> None:
    if envelope.get("ok") is not True:
        raise FixtureError(f"{label} did not return a successful public envelope")


def _canonical_uuid(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise FixtureError(f"{label} is not a UUID")
    try:
        if str(UUID(value)) != value:
            raise ValueError
    except ValueError as error:
        raise FixtureError(f"{label} is not a canonical UUID") from error
    return value


class RollbackFixture:
    """The causal fixture sequence.  No cleanup occurs before a proven terminal job."""

    def __init__(self, spec: FixtureSpec, boundary: Boundary, evidence: Callable[[dict[str, Any]], None]):
        self.spec = spec
        self.boundary = boundary
        self.evidence = evidence
        self.steps: list[Step] = []
        self.lock: object | None = None
        self.candidate: Path | None = None
        self.job_id: str | None = None
        self.operation_id: str | None = None
        self.controller_id: str | None = None
        self.owner_pid: int | None = None
        self.armed_identity: Identity | None = None
        self.terminal = False

    def record(self, step: Step, **values: Any) -> None:
        if step in self.steps:
            raise FixtureError(f"step repeated: {step.value}")
        self.steps.append(step)
        self.evidence({"step": step.value, **values})

    def wait_for(self, label: str, predicate: Callable[[], Any]) -> Any:
        deadline = self.boundary.now() + self.spec.timeout_seconds
        while self.boundary.now() < deadline:
            value = predicate()
            if value:
                return value
            self.boundary.sleep(self.spec.poll_seconds)
        raise FixtureTimeout(f"timed out waiting for {label}; preserved unknown job and inputs")

    def verify_base(self) -> None:
        for package, expected, label in (
            (self.spec.expected_base_package, self.spec.expected_base_package_sha256, "base package"),
            (self.spec.expected_target_package, self.spec.expected_target_package_sha256, "target package"),
        ):
            if self.boundary.sha256(package) != _exact_hash(expected, label):
                raise FixtureError(f"{label} identity changed")
        self.boundary.verify_signature(self.spec.app)
        actual = self.boundary.identity(self.spec.app)
        if actual != self.spec.expected_base_identity:
            raise FixtureError("installed base path/code/inode identity changed")
        self.record(Step.BASE_VERIFIED, base=actual.as_json())

    def run(self) -> None:
        self.verify_base()
        self.owner_pid = self.wait_for("owned base owner", lambda: self.boundary.owner_ready(self.spec.app, self.spec.state_dir))
        self.record(Step.OWNER_READY, ownerPid=self.owner_pid)
        ready = self.boundary.public(self.spec.app, self.spec.state_dir, "updates", "status")
        _require_ok(ready, "updates status")
        if ready.get("data", {}).get("phase") != "ready":
            raise FixtureError("target update is not ready")
        controller = ready.get("controllerId")
        if not isinstance(controller, str) or not controller:
            raise FixtureError("ready update status omitted controller identity")
        self.controller_id = controller
        self.record(Step.UPDATE_READY)

        self.lock = self.boundary.acquire_shared_launcher_lock(self.spec.app / "Contents/MacOS/vpn-control")
        self.record(Step.LOCK_HELD)
        accepted = self.boundary.public(self.spec.app, self.spec.state_dir,
            "--controller-id", self.controller_id, "--async", "updates", "install")
        _require_ok(accepted, "async updates install")
        if accepted.get("code") != "ACCEPTED" or accepted.get("final") is not False:
            raise FixtureError("async install was not accepted")
        operation = accepted.get("operationId")
        self.operation_id = _canonical_uuid(operation, "async install operation")
        if accepted.get("controllerId") != self.controller_id:
            raise FixtureError("async install controller identity changed")
        self.record(Step.INSTALL_ACCEPTED, operationId=operation, controllerId=self.controller_id,
                    requestId=accepted.get("requestId"), initialHandoffReady=accepted.get("data", {}).get("handoffReady"))

        acknowledgement = self.wait_for("same-operation public handoff acknowledgement", self._ready_operation)
        data = acknowledgement["data"]
        self.job_id = _canonical_uuid(data.get("jobId"), "handoff job")
        self.candidate = self.spec.app.parent / f".vpn-control-stage-{self.job_id}.app"
        self.boundary.verify_signature(self.candidate)
        if self.boundary.identity(self.candidate).sha256 != _exact_hash(self.spec.expected_target_code_sha256, "target code"):
            raise FixtureError("candidate code identity changed")
        receipt = self.boundary.receipt(self.job_id, self.spec.receipt_authority, self.spec.owner_home)
        if receipt.get("jobId") != self.job_id or receipt.get("phase") != "WAITING_FOR_EXIT" or receipt.get("code") != "OK":
            raise FixtureError("handoff receipt is not exact protected waiting state")
        self.record(Step.WAITING_FOR_EXIT, jobId=self.job_id, receipt=receipt)
        candidate_identity = self.boundary.identity(self.candidate)
        self.boundary.arm_immutable(self.candidate, candidate_identity, self.job_id, self.spec.receipt_authority)
        self.armed_identity = candidate_identity
        self.record(Step.CANDIDATE_ARMED, candidate=str(self.candidate), candidateIdentity=candidate_identity.as_json())
        self.record(Step.HANDOFF_ACKNOWLEDGED, operationId=self.operation_id, jobId=self.job_id)

        self.wait_for("original owner exit", lambda: not self.boundary.owner_alive(self.owner_pid, self.spec.app, self.spec.state_dir))
        self.record(Step.OWNER_EXITED, ownerPid=self.owner_pid)
        self.boundary.release_shared_launcher_lock(self.lock)
        self.lock = None
        self.record(Step.LOCK_RELEASED)
        terminal = self.wait_for("exact terminal failed receipt", self._failed_receipt)
        self.terminal = True
        self.record(Step.TERMINAL, receipt=terminal)
        self.boundary.verify_signature(self.spec.app)
        restored = self.boundary.identity(self.spec.app)
        if restored != self.spec.expected_base_identity:
            raise FixtureError("base bundle was not restored to its exact original identity")
        self.record(Step.BASE_RESTORED, base=restored.as_json())
        self.wait_for("coordinator absence after terminal", lambda: self.boundary.coordinator_absent(self.job_id, self.owner_pid))
        if self.armed_identity is None or self.boundary.identity(self.candidate) != self.armed_identity:
            raise FixtureError("armed candidate identity changed before cleanup")
        self.boundary.clear_immutable(self.candidate, self.armed_identity, self.job_id, self.spec.receipt_authority)
        self.record(Step.CLEANED, candidate=str(self.candidate))

    def _ready_operation(self) -> dict[str, Any] | None:
        status = self.boundary.public(self.spec.app, self.spec.state_dir,
            "--controller-id", self.controller_id, "operations", "status", self.operation_id)
        _require_ok(status, "operation status polling")
        if status.get("operationId") != self.operation_id or status.get("controllerId") != self.controller_id:
            raise FixtureError("operation status identity changed")
        data = status.get("data", {})
        if data.get("handoffReady") is not True:
            return None
        _canonical_uuid(data.get("jobId"), "handoff job")
        return status

    def _failed_receipt(self) -> dict[str, Any] | None:
        assert self.job_id is not None
        receipt = self.boundary.receipt(self.job_id, self.spec.receipt_authority, self.spec.owner_home)
        if receipt and receipt.get("jobId") != self.job_id:
            raise FixtureError("terminal receipt identity changed")
        if receipt.get("jobId") == self.job_id and receipt.get("phase") == "FAILED" and receipt.get("code") == "PERSISTENCE_FAILED":
            return receipt
        if receipt.get("phase") in ("SUCCEEDED", "CANCELLED"):
            raise FixtureError("rollback job reached an unexpected terminal result")
        return None


class MacBoundary:
    """The intentionally small real boundary; tests use an injected fake instead."""

    def now(self) -> float: return time.monotonic()
    def sleep(self, seconds: float) -> None: time.sleep(seconds)
    command_timeout = 30
    def sha256(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""): digest.update(block)
        return digest.hexdigest()
    def identity(self, path: Path) -> Identity:
        metadata = path.stat()
        digest = hashlib.sha256()
        if path.is_dir():
            for entry in sorted(path.rglob("*"), key=lambda item: item.relative_to(path).as_posix()):
                relative = entry.relative_to(path).as_posix().encode()
                digest.update(relative + b"\0")
                if entry.is_file(): digest.update(self.sha256(entry).encode())
        else: digest.update(self.sha256(path).encode())
        return Identity(metadata.st_dev, metadata.st_ino, digest.hexdigest())
    def verify_signature(self, app: Path) -> None:
        subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], check=True, capture_output=True, text=True, timeout=self.command_timeout)
    def _json(self, argv: list[str]) -> dict[str, Any]:
        completed = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=self.command_timeout)
        if completed.returncode != 0: raise FixtureError(f"public command failed with exit {completed.returncode}")
        try: return json.loads(completed.stdout)
        except json.JSONDecodeError as error: raise FixtureError("public command did not emit JSON") from error
    def public(self, app: Path, state_dir: Path, *args: str) -> dict[str, Any]:
        return self._json([str(app / "Contents/MacOS/vpn-control"), "--state-dir", str(state_dir), "--json", *args])
    def owner_ready(self, app: Path, state_dir: Path) -> int:
        status = self.public(app, state_dir, "status")
        _require_ok(status, "owner status")
        raw = subprocess.run(["/bin/ps", "-axo", "pid=,lstart=,command="], check=True, capture_output=True, text=True, timeout=self.command_timeout).stdout
        owner = FixtureProcessObserver((app / "Contents/MacOS/vpn-control").as_posix(), state_dir.as_posix()).identify(process_rows(raw), INITIAL_SERVE_OWNER)
        return owner.pid if owner is not None else 0
    def owner_alive(self, owner_pid: int, app: Path, state_dir: Path) -> bool:
        raw = subprocess.run(["/bin/ps", "-axo", "pid=,lstart=,command="], check=True, capture_output=True, text=True, timeout=self.command_timeout).stdout
        owner = FixtureProcessObserver((app / "Contents/MacOS/vpn-control").as_posix(), state_dir.as_posix()).identify(process_rows(raw), INITIAL_SERVE_OWNER)
        return owner is not None and owner.pid == owner_pid
    def _machine(self, action: str, job_id: str, candidate: Path | None = None, identity: Identity | None = None) -> str:
        script = Path(__file__).resolve()
        parser_dependency = script.parent / "macos_fixture_processes.py"
        for component in (script, parser_dependency, *script.parents):
            metadata = component.stat()
            if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
                raise FixtureError("machine helper path must be root-owned and non-writable")
        argv = ["/usr/bin/sudo", "-n", "/usr/bin/python3", str(script), "--machine-helper", action, "--job-id", job_id]
        if candidate is not None and identity is not None:
            argv += ["--candidate", str(candidate), "--identity", f"{identity.device}:{identity.inode}:{identity.sha256}"]
        return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=self.command_timeout).stdout
    def receipt(self, job_id: str, authority: ReceiptAuthority, owner_home: Path) -> dict[str, Any]:
        if authority is ReceiptAuthority.MACHINE:
            try: return json.loads(self._machine("receipt", job_id))
            except (subprocess.SubprocessError, json.JSONDecodeError): return {}
        path = owner_home / "Library/Application Support/vpn-control-install-jobs" / job_id / "status.json"
        try: return json.loads(path.read_text())
        except (OSError, json.JSONDecodeError): return {}
    def arm_immutable(self, candidate: Path, identity: Identity, job_id: str, authority: ReceiptAuthority) -> None:
        if authority is ReceiptAuthority.MACHINE: self._machine("arm", job_id, candidate, identity)
        elif self.identity(candidate) == identity: subprocess.run(["/usr/bin/chflags", "uchg", str(candidate)], check=True, timeout=self.command_timeout)
        else: raise FixtureError("local candidate identity changed")
    def clear_immutable(self, candidate: Path, identity: Identity, job_id: str, authority: ReceiptAuthority) -> None:
        if authority is ReceiptAuthority.MACHINE: self._machine("clear", job_id, candidate, identity)
        elif self.identity(candidate) == identity: subprocess.run(["/usr/bin/chflags", "nouchg", str(candidate)], check=True, timeout=self.command_timeout)
        else: raise FixtureError("local candidate identity changed")
    def coordinator_absent(self, job_id: str, owner_pid: int) -> bool:
        needle = f"--coordinate {job_id} {owner_pid}"
        raw = subprocess.run(["/bin/ps", "-axo", "command="], check=True, capture_output=True, text=True).stdout
        return not any(needle in line and "vpn-control-install-worker" in line for line in raw.splitlines())
    def acquire_shared_launcher_lock(self, launcher: Path) -> object:
        import fcntl
        handle = launcher.open("rb")
        fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
        return handle
    def release_shared_launcher_lock(self, token: object) -> None:
        import fcntl
        handle = token
        assert hasattr(handle, "fileno")
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def _parse_identity(value: str) -> Identity:
    try:
        device, inode, sha256 = value.split(":", 2)
        return Identity(int(device), int(inode), _exact_hash(sha256, "base code"))
    except (TypeError, ValueError) as error:
        raise argparse.ArgumentTypeError("expected DEVICE:INODE:SHA256") from error


def _machine_helper(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--machine-helper", choices=("receipt", "arm", "clear"), required=True)
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--identity", type=_parse_identity)
    args = parser.parse_args(argv)
    if os.geteuid() != 0 or _canonical_uuid(args.job_id, "machine job") != args.job_id:
        raise FixtureError("machine helper requires root and canonical job")
    if args.machine_helper == "receipt":
        if args.candidate is not None or args.identity is not None: raise FixtureError("receipt accepts no candidate")
        path = Path("/Library/Application Support/vpn-control-install-jobs") / args.job_id / "status.json"
        print(json.dumps(json.loads(path.read_text()), sort_keys=True)); return 0
    candidate, identity = args.candidate, args.identity
    expected = Path("/Applications") / f".vpn-control-stage-{args.job_id}.app"
    if candidate != expected or identity is None or MacBoundary().identity(candidate) != identity:
        raise FixtureError("machine helper candidate identity changed")
    subprocess.run(["/usr/bin/chflags", "uchg" if args.machine_helper == "arm" else "nouchg", str(candidate)], check=True,
                   timeout=MacBoundary.command_timeout)
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--machine-helper" in argv: return _machine_helper(argv)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True, help="owned installed base .app path")
    parser.add_argument("--state-dir", type=Path, required=True, help="new, owned fixture state directory")
    parser.add_argument("--base-package", type=Path, required=True)
    parser.add_argument("--target-package", type=Path, required=True)
    parser.add_argument("--base-package-sha256", required=True)
    parser.add_argument("--target-package-sha256", required=True)
    parser.add_argument("--target-code-sha256", required=True)
    parser.add_argument("--base-identity", type=_parse_identity, required=True, help="DEVICE:INODE:CODE_SHA256")
    parser.add_argument("--receipt-authority", choices=[item.value for item in ReceiptAuthority], required=True)
    parser.add_argument("--owner-home", type=Path)
    parser.add_argument("--evidence", type=Path, required=True, help="new evidence JSONL file")
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    parser.add_argument("--poll-seconds", type=float, default=0.2)
    args = parser.parse_args(argv)
    if sys.platform != "darwin": parser.error("this driver runs only inside the owned macOS guest")
    # The caller starts the owned original-user service before this driver, so the
    # state directory is intentionally pre-existing.  The evidence destination is
    # the durable run boundary and must never overwrite another attempt.
    if not args.state_dir.is_dir() or args.evidence.exists(): parser.error("an existing owned state directory and fresh evidence path are required")
    if (args.receipt_authority == ReceiptAuthority.USER_LOCAL.value) != (args.owner_home is not None):
        parser.error("--owner-home is required only for user-local receipt authority")
    if args.timeout_seconds <= 0 or args.poll_seconds <= 0: parser.error("timeouts must be positive")
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    with args.evidence.open("x", encoding="utf-8") as output:
        def evidence(event: dict[str, Any]) -> None:
            output.write(json.dumps(event, sort_keys=True) + "\n"); output.flush(); os.fsync(output.fileno())
        spec = FixtureSpec(args.app, args.state_dir, args.base_package, args.target_package,
            args.base_package_sha256, args.target_package_sha256,
            args.target_code_sha256, args.base_identity, ReceiptAuthority(args.receipt_authority), args.owner_home or Path("/"),
            args.timeout_seconds, args.poll_seconds)
        fixture = RollbackFixture(spec, MacBoundary(), evidence)
        try: fixture.run()
        finally:
            # An interrupted/unknown operation keeps the immutable candidate and our record intact.
            if fixture.lock is not None and fixture.terminal:
                fixture.boundary.release_shared_launcher_lock(fixture.lock)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
