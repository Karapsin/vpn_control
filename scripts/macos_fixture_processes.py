#!/usr/bin/env python3
"""Observe the four fixed process roles used by a macOS update fixture.

macOS ``ps ... command`` is display text, not an argv API.  This observer is
therefore deliberately limited to the fixture's absolute, whitespace-free app
and state paths and to the four launch forms emitted by the desktop app.  It
returns no identity when a role is absent or ambiguous.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable
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


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    started: str
    argv: tuple[str, ...]


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
