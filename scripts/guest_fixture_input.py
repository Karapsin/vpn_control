#!/usr/bin/env python3
"""Verify one public fixture helper before its guest-side probe or build starts."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
from typing import Callable, TypeVar


_SHA256 = re.compile(r"[0-9a-f]{64}")
_T = TypeVar("_T")
_GUEST_VERIFY_AND_EXEC = """import hashlib, os, stat, sys
path, expected_size, expected_sha256, *command = sys.argv[1:]
try:
    expected_size = int(expected_size)
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('guest fixture helper is not a regular file')
    if info.st_size != expected_size:
        raise ValueError('guest fixture helper size mismatch: expected %s, got %s' % (expected_size, info.st_size))
    with open(path, 'rb') as source:
        actual_sha256 = hashlib.sha256(source.read()).hexdigest()
    if actual_sha256 != expected_sha256:
        raise ValueError('guest fixture helper SHA-256 mismatch')
except (OSError, ValueError) as error:
    print(str(error), file=sys.stderr)
    raise SystemExit(64)
os.execvp(command[0], command)
"""


class FixtureInputError(ValueError):
    """The guest helper is absent, incomplete, stale, or not the expected input."""


@dataclass(frozen=True)
class GuestFixtureInput:
    size: int
    sha256: str

    @classmethod
    def from_contents(cls, contents: bytes) -> "GuestFixtureInput":
        if not contents:
            raise FixtureInputError("expected guest fixture helper must not be empty")
        return cls(len(contents), hashlib.sha256(contents).hexdigest())

    def __post_init__(self) -> None:
        if self.size <= 0:
            raise FixtureInputError("expected guest fixture helper size must be positive")
        if _SHA256.fullmatch(self.sha256) is None:
            raise FixtureInputError("expected guest fixture helper SHA-256 must be lowercase hex")


def assert_guest_fixture_input(path: Path, expected: GuestFixtureInput) -> None:
    """Require an exact, regular transferred helper before an irreversible launch."""
    try:
        status = path.lstat()
    except FileNotFoundError as error:
        raise FixtureInputError(f"guest fixture helper is missing: {path}") from error
    if path.is_symlink() or not path.is_file():
        raise FixtureInputError(f"guest fixture helper is not a regular file: {path}")
    if status.st_size != expected.size:
        raise FixtureInputError(
            f"guest fixture helper size mismatch: expected {expected.size}, got {status.st_size}"
        )
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected.sha256:
        raise FixtureInputError(f"guest fixture helper SHA-256 mismatch: {path}")


def launch_after_verified_input(path: Path, expected: GuestFixtureInput, launch: Callable[[], _T]) -> _T:
    """Run *launch* only after the transferred helper matches its public identity."""
    assert_guest_fixture_input(path, expected)
    return launch()


def guest_probe_argv(helper_path: str, expected: GuestFixtureInput, probe_argv: tuple[str, ...]) -> tuple[str, ...]:
    """Return a guest argv that verifies *helper_path* before it execs the probe.

    The verifier travels as a fixed public ``python3 -c`` argument, never as a
    transferred file or stdin payload. Pass the tuple to a structured guest
    executor; do not join it into a shell command.
    """
    if not (PurePosixPath(helper_path).is_absolute() or PureWindowsPath(helper_path).is_absolute()):
        raise FixtureInputError("guest fixture helper path must be absolute")
    if not probe_argv or any(not value or "\x00" in value for value in probe_argv):
        raise FixtureInputError("guest probe argv must contain non-empty, NUL-free arguments")
    return (
        "python3", "-c", _GUEST_VERIFY_AND_EXEC, helper_path,
        str(expected.size), expected.sha256, *probe_argv,
    )
