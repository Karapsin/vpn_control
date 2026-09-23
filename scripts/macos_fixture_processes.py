#!/usr/bin/env python3
"""Observe the four fixed process roles used by a macOS update fixture.

macOS ``ps ... command`` is display text, not an argv API.  This observer is
therefore deliberately limited to the fixture's absolute, whitespace-free app
and state paths and to the four launch forms emitted by the desktop app.  It
returns no identity when a role is absent or ambiguous.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
import re
import subprocess
import time
from typing import Any, Callable, Iterable, Mapping, Sequence
from uuid import UUID


INITIAL_SERVE_OWNER = "initial-serve-owner"
INTERNAL_HEADLESS_OWNER = "internal-headless-owner"
FRONTEND_OWNER = "frontend-owner"
PLAIN_RETURN_GUI = "plain-return-gui"

_ROLES = frozenset((
    INITIAL_SERVE_OWNER,
    INTERNAL_HEADLESS_OWNER,
    FRONTEND_OWNER,
    PLAIN_RETURN_GUI,
))
_PS_ROW = re.compile(
    r"^\s*(\d+)\s+([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d+\s+"
    r"\d\d:\d\d:\d\d\s+\d{4})\s+(\S.*)$"
)


class FixtureProcessError(ValueError):
    """The fixture supplied an observation that cannot safely be interpreted."""


class FixtureReadinessTimeout(TimeoutError):
    """The observed role did not produce a successful read-only status in time."""

    def __init__(self, last_observation: Mapping[str, object] | None):
        self.last_observation = last_observation
        super().__init__("timed out waiting for process role and successful public status")


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    started: str
    argv: tuple[str, ...]


@dataclass(frozen=True)
class PublicStatusReadiness:
    """The role and successful status snapshot admitted by the observer."""

    process: ProcessIdentity
    status: Mapping[str, Any]
    stdout: str


def _fixed_path(value: str, name: str) -> str:
    if not value or not value.startswith("/") or any(char.isspace() for char in value):
        raise FixtureProcessError(f"{name} must be an absolute path without whitespace")
    # The command column has no escaping contract.  These characters would make
    # split display text look like an argv parser even for a fixed fixture.
    if any(char in value for char in "\\\"'\\"):
        raise FixtureProcessError(f"{name} contains a character unsupported by ps observation")
    return value


def process_rows(output: str) -> list[ProcessIdentity]:
    """Parse the fixed ``pid=,lstart=,command=`` layout without shell parsing."""
    rows: list[ProcessIdentity] = []
    for line in output.splitlines():
        match = _PS_ROW.fullmatch(line)
        if match is None:
            continue
        argv = tuple(match.group(3).split())
        if not argv:
            continue
        rows.append(ProcessIdentity(int(match.group(1)), match.group(2), argv))
    return rows


class FixtureProcessObserver:
    """Exact role matcher for one bounded macOS fixture app/state pair."""

    def __init__(self, app: str, state_dir: str):
        self.app = _fixed_path(app, "app")
        self.state_dir = _fixed_path(state_dir, "state_dir")

    def expected_argv(self, role: str, frontend_owner: str | None = None) -> tuple[str, ...]:
        if role not in _ROLES:
            raise FixtureProcessError(f"unknown fixture process role: {role}")
        if role == INITIAL_SERVE_OWNER:
            return (self.app, "--state-dir", self.state_dir, "serve")
        if role == INTERNAL_HEADLESS_OWNER:
            return (self.app, "--headless-controller", "--state-dir", self.state_dir)
        if role == PLAIN_RETURN_GUI:
            return (self.app, "--state-dir", self.state_dir)
        if frontend_owner is None:
            raise FixtureProcessError("frontend owner UUID is required")
        try:
            if str(UUID(frontend_owner)) != frontend_owner:
                raise ValueError
        except (ValueError, AttributeError) as error:
            raise FixtureProcessError("frontend owner must be a canonical UUID") from error
        return (self.app, "--frontend-owner", frontend_owner, "--state-dir", self.state_dir)

    def identify(self, rows: Iterable[ProcessIdentity], role: str,
                 frontend_owner: str | None = None) -> ProcessIdentity | None:
        expected = self.expected_argv(role, frontend_owner)
        matches = [row for row in rows if row.argv == expected]
        return matches[0] if len(matches) == 1 else None

    def returned_gui_after(self, rows: Iterable[ProcessIdentity],
                           prior: ProcessIdentity) -> ProcessIdentity | None:
        """Return a new GUI generation; reject PID reuse and coarse start ties."""
        current = self.identify(rows, PLAIN_RETURN_GUI)
        if current is None or current.pid == prior.pid or current.started == prior.started:
            return None
        return current


def wait_for_public_status_readiness(
    observer: FixtureProcessObserver,
    rows: Callable[[], Iterable[ProcessIdentity]],
    role: str,
    run: Callable[[Sequence[str], float], object],
    evidence_sink: Callable[[Mapping[str, object]], None],
    *,
    frontend_owner: str | None = None,
    timeout_seconds: float = 30,
    poll_seconds: float = 0.2,
    now: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> PublicStatusReadiness:
    """Wait for one exact role and its read-only public ``status`` response.

    The caller owns evidence persistence.  Every command attempt is sent to
    ``evidence_sink`` with its argv, exit code, stdout, and stderr, including
    failures.  This helper invokes only ``--json status`` and never infers that
    an absent role is dead.
    """
    timeout_seconds = _positive_finite_timing(timeout_seconds, "timeout_seconds")
    poll_seconds = _positive_finite_timing(poll_seconds, "poll_seconds")
    deadline = now() + timeout_seconds
    last_observation: Mapping[str, object] | None = None
    command = (observer.app, "--state-dir", observer.state_dir, "--json", "status")

    while True:
        remaining_seconds = deadline - now()
        if remaining_seconds <= 0:
            raise FixtureReadinessTimeout(last_observation)
        process = observer.identify(rows(), role, frontend_owner)
        if process is None:
            last_observation = {"role": role, "rolePresent": False}
            evidence_sink(last_observation)
        else:
            try:
                completed = run(command, remaining_seconds)
            except subprocess.TimeoutExpired as error:
                exit_code, stdout, stderr, timed_out = None, _timeout_text(error.stdout), _timeout_text(error.stderr), True
            else:
                exit_code = getattr(completed, "returncode", None)
                stdout = getattr(completed, "stdout", None)
                stderr = getattr(completed, "stderr", None)
                timed_out = False
                if not isinstance(exit_code, int) or not isinstance(stdout, str) or not isinstance(stderr, str):
                    raise FixtureProcessError("public status runner returned an invalid result")
            status: Mapping[str, Any] | None = None
            if exit_code == 0:
                try:
                    decoded = json.loads(stdout)
                except json.JSONDecodeError:
                    decoded = None
                if isinstance(decoded, dict) and decoded.get("ok") is True:
                    status = decoded
            last_observation = {
                "role": role,
                "rolePresent": True,
                "process": {"pid": process.pid, "started": process.started, "argv": list(process.argv)},
                "command": list(command),
                "exit": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "statusOk": status is not None,
                "timedOut": timed_out,
            }
            evidence_sink(last_observation)
            if status is not None:
                return PublicStatusReadiness(process, status, stdout)

        remaining_seconds = deadline - now()
        if remaining_seconds <= 0:
            raise FixtureReadinessTimeout(last_observation)
        sleep(min(poll_seconds, remaining_seconds))


def _positive_finite_timing(value: float, name: str) -> float:
    """Accept only timing values that preserve a bounded polling deadline."""
    if isinstance(value, bool):
        raise FixtureProcessError(f"{name} must be finite and positive")
    try:
        numeric = float(value)
    except (TypeError, ValueError) as error:
        raise FixtureProcessError(f"{name} must be finite and positive") from error
    if not math.isfinite(numeric) or numeric <= 0:
        raise FixtureProcessError(f"{name} must be finite and positive")
    return numeric


def _timeout_text(value: str | bytes | None) -> str:
    """Retain subprocess timeout output in the string evidence schema."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value if isinstance(value, str) else ""
