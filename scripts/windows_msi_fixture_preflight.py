#!/usr/bin/env python3
"""Fail-closed local admission for a Windows MSI fixture before side effects.

This module deliberately handles only non-secret evidence: a credential *path*
and PPM prompt pixels.  It never reads or returns credential bytes.  Callers
must run ``admit_credential_path`` before creating an installer intent, then
use ``match_uac_after_expansion`` immediately before typing a credential.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import argparse
from dataclasses import dataclass
from pathlib import Path


class FixturePreflightError(ValueError):
    """A local fixture input is not safe to use."""


@dataclass(frozen=True)
class PromptIdentity:
    """The stable identity shared by both observed phases of one UAC prompt."""

    qemu_identity: str
    operation_id: str
    prompt_id: str

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) and value for value in self.__dict__.values()):
            raise FixturePreflightError("prompt identity fields must be non-empty strings")


@dataclass(frozen=True)
class UacProfile:
    width: int
    height: int
    compact_title_rect: tuple[int, int, int, int]
    expanded_title_rect: tuple[int, int, int, int]
    account_rect: tuple[int, int, int, int]
    password_rect: tuple[int, int, int, int]
    compact_title_sha256: str
    expanded_title_sha256: str
    account_sha256: str
    max_empty_password_dark_pixels: int


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _checked_hash(value: str, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise FixturePreflightError(f"{label} must be a lowercase SHA-256")
    return value


def _crop(frame: bytes, rect: tuple[int, int, int, int], width: int, height: int) -> bytes:
    header = f"P6\n{width} {height}\n255\n".encode()
    if not isinstance(frame, bytes) or not frame.startswith(header) or len(frame) != len(header) + width * height * 3:
        raise FixturePreflightError("UAC frame has unexpected PPM dimensions")
    if (not isinstance(rect, tuple) or len(rect) != 4 or
            any(isinstance(value, bool) or not isinstance(value, int) for value in rect)):
        raise FixturePreflightError("UAC crop is invalid")
    x0, y0, x1, y1 = rect
    if not (0 <= x0 < x1 <= width and 0 <= y0 < y1 <= height):
        raise FixturePreflightError("UAC crop is outside the frame")
    pixels = frame[len(header):]
    return b"".join(pixels[(row * width + x0) * 3:(row * width + x1) * 3] for row in range(y0, y1))


def _title(frame: bytes, profile: UacProfile, rect: tuple[int, int, int, int], expected_title: str,
           phase: str) -> None:
    if not isinstance(profile.width, int) or not isinstance(profile.height, int) or profile.width <= 0 or profile.height <= 0:
        raise FixturePreflightError("UAC dimensions are invalid")
    if _sha256(_crop(frame, rect, profile.width, profile.height)) != _checked_hash(expected_title, f"{phase} title"):
        raise FixturePreflightError(f"{phase} UAC app title did not match")


def _selected_account_and_empty_password(frame: bytes, profile: UacProfile) -> None:
    if _sha256(_crop(frame, profile.account_rect, profile.width, profile.height)) != _checked_hash(profile.account_sha256, "selected account"):
        raise FixturePreflightError("selected UAC account did not match")
    password = _crop(frame, profile.password_rect, profile.width, profile.height)
    dark = sum(max(password[offset:offset + 3]) < 110 for offset in range(0, len(password), 3))
    limit = profile.max_empty_password_dark_pixels
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0 or dark > limit:
        raise FixturePreflightError("UAC password field is not empty")


def match_uac_after_expansion(*, compact_frame: bytes, expanded_frame: bytes,
                              expected_identity: PromptIdentity,
                              compact_identity: PromptIdentity,
                              expanded_identity: PromptIdentity,
                              profile: UacProfile) -> dict[str, str]:
    """Admit the re-rasterized title only across one correlated prompt expansion.

    Matching the expanded title alone is insufficient: the compact title must
    have matched first, and both observations must bind to the same QEMU,
    operation, and prompt identity. The compact frame predates account selection;
    the selected account and empty field are checked in the expanded frame before
    a caller can access a credential.
    """
    if compact_identity != expected_identity or expanded_identity != expected_identity:
        raise FixturePreflightError("UAC prompt identity changed between phases")
    # The compact UAC prompt appears before an approver has been selected.  Its
    # title is the only stable evidence available in that phase.  More choices
    # then moves/re-rasterizes the dialog; account and password admission apply
    # only to the selected, expanded frame.
    _title(compact_frame, profile, profile.compact_title_rect, profile.compact_title_sha256, "compact")
    _title(expanded_frame, profile, profile.expanded_title_rect, profile.expanded_title_sha256, "expanded")
    _selected_account_and_empty_password(expanded_frame, profile)
    return {"qemuIdentity": expected_identity.qemu_identity,
            "operationId": expected_identity.operation_id,
            "promptId": expected_identity.prompt_id,
            "phase": "expanded"}


def cp175_uac_profile() -> UacProfile:
    """Return the reviewed CP175 profile from retained native UAC evidence.

    The compact title was captured at y=298.  After More choices the dialog
    moved, and the same executable title was rasterized at y=174.  The account
    and empty-password checks are intentionally only for the expanded screen.
    """
    return UacProfile(
        width=1280, height=800,
        compact_title_rect=(435, 298, 700, 328),
        expanded_title_rect=(435, 174, 700, 204),
        account_rect=(434, 382, 701, 411),
        password_rect=(451, 447, 801, 468),
        compact_title_sha256="c10989f0d2e81e9adeb7792d2bf12abaec8c48084c7a6fd0d04a9e10565cc2f7",
        expanded_title_sha256="de6a91a0b90909809fa832520aefcf0ca9d32002e954a89a8a7d3a91b9d1bdc0",
        account_sha256="e9c655c82976a31fdb25ade72dc3ab63ed6123c803b70dfe4534f5d9ce4a30de",
        max_empty_password_dark_pixels=19,
    )


def _path_ancestors(path: Path) -> list[Path]:
    if not path.is_absolute():
        raise FixturePreflightError("credential path must be absolute")
    result: list[Path] = []
    parent = path.parent
    while True:
        result.append(parent)
        if parent.parent == parent:
            return result
        parent = parent.parent


def admit_credential_path(path: Path | str, *, owner_uid: int | None = None) -> None:
    """Require an owner-only regular credential and non-writable ancestry.

    A root-owned sticky ancestor is accepted only while every lower ancestor has
    remained protected.  This permits normal ``/tmp``-style system paths but
    rejects a configured project directory with mode 0777 before an installer
    intent or credential read can occur.
    """
    credential = Path(path)
    getuid = getattr(os, "getuid", None)
    if owner_uid is None and not callable(getuid):
        raise FixturePreflightError("credential admission requires POSIX owner metadata")
    uid = getuid() if owner_uid is None else owner_uid
    if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0:
        raise FixturePreflightError("credential owner identity is invalid")
    protected_below = True
    try:
        for ancestor in _path_ancestors(credential):
            metadata = os.lstat(ancestor)
            mode = stat.S_IMODE(metadata.st_mode)
            sticky_root = metadata.st_uid == 0 and bool(mode & stat.S_ISVTX)
            writable = bool(mode & 0o022)
            if (not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or
                    metadata.st_uid not in {0, uid} or (writable and not (sticky_root and protected_below))):
                raise FixturePreflightError("credential ancestry is not owner-only")
            if writable:
                protected_below = False
        metadata = os.lstat(credential)
    except OSError as error:
        raise FixturePreflightError("credential path is unavailable") from error
    if (stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or
            metadata.st_uid != uid or stat.S_IMODE(metadata.st_mode) & 0o077 or metadata.st_size <= 0):
        raise FixturePreflightError("credential file is not owner-only")


def _write_receipt(path: Path, receipt: dict[str, str]) -> None:
    """Publish only non-secret admission facts through an owner-only replace."""
    if not path.is_absolute():
        raise FixturePreflightError("preflight receipt path must be absolute")
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".windows-msi-preflight-", dir=path.parent)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(receipt, handle, sort_keys=True, separators=(",", ":")); handle.write("\n")
                handle.flush(); os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary): os.unlink(temporary)
    except OSError as error:
        raise FixturePreflightError("preflight receipt cannot be written safely") from error


def _observed_identity(path: Path, frame: bytes, phase: str) -> PromptIdentity:
    """Read the identity recorded by the capture owner for these exact pixels.

    The capture owner writes version, phase, frameSha256, qemuIdentity,
    operationId and promptId together for each observation. These records bind
    the two phases; the input driver must separately recheck current prompt
    freshness immediately before accessing a credential.
    """
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise FixturePreflightError("UAC observation is unavailable or invalid") from error
    fields = {"version", "phase", "frameSha256", "qemuIdentity", "operationId", "promptId"}
    if (not isinstance(record, dict) or set(record) != fields or
            type(record["version"]) is not int or record["version"] != 1 or record["phase"] != phase):
        raise FixturePreflightError("UAC observation fields or phase are invalid")
    if _checked_hash(record["frameSha256"], "observed frame") != _sha256(frame):
        raise FixturePreflightError("UAC observation does not match its frame")
    return PromptIdentity(record["qemuIdentity"], record["operationId"], record["promptId"])


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Windows MSI UAC and credential-path preflight")
    parser.add_argument("--profile", choices=("cp175",), default="cp175")
    parser.add_argument("--credential-only", action="store_true",
                        help="admit only the configured credential path before creating an MSI intent")
    parser.add_argument("--credential-path", type=Path, required=True,
                        help="configured credential file; metadata only, never read")
    parser.add_argument("--compact-frame", type=Path)
    parser.add_argument("--expanded-frame", type=Path)
    parser.add_argument("--compact-observation", type=Path,
                        help="compact capture metadata with prompt identity and exact frame SHA-256")
    parser.add_argument("--expanded-observation", type=Path,
                        help="expanded capture metadata with prompt identity and exact frame SHA-256")
    parser.add_argument("--qemu-identity")
    parser.add_argument("--operation-id")
    parser.add_argument("--prompt-id")
    parser.add_argument("--receipt", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        # This runs before frame handling or any installer/credential operation.
        admit_credential_path(arguments.credential_path)
        if arguments.credential_only:
            if any(value is not None for value in (arguments.compact_frame, arguments.expanded_frame,
                                                    arguments.compact_observation, arguments.expanded_observation,
                                                    arguments.qemu_identity, arguments.operation_id,
                                                    arguments.prompt_id)):
                raise FixturePreflightError("credential-only preflight does not accept UAC inputs")
            receipt = {"phase": "credential-path", "credentialPathAdmitted": "true"}
            _write_receipt(arguments.receipt, receipt)
            print(json.dumps({"state": "admitted", **receipt}, sort_keys=True))
            return 0
        if any(value is None for value in (arguments.compact_frame, arguments.expanded_frame,
                                           arguments.compact_observation, arguments.expanded_observation,
                                           arguments.qemu_identity, arguments.operation_id,
                                           arguments.prompt_id)):
            raise FixturePreflightError("compact and expanded UAC frames, capture observations and expected prompt identity are required")
        identity = PromptIdentity(arguments.qemu_identity, arguments.operation_id, arguments.prompt_id)
        compact_frame = arguments.compact_frame.read_bytes()
        expanded_frame = arguments.expanded_frame.read_bytes()
        compact_identity = _observed_identity(arguments.compact_observation, compact_frame, "compact")
        expanded_identity = _observed_identity(arguments.expanded_observation, expanded_frame, "expanded")
        receipt = match_uac_after_expansion(
            compact_frame=compact_frame, expanded_frame=expanded_frame,
            expected_identity=identity, compact_identity=compact_identity, expanded_identity=expanded_identity,
            profile=cp175_uac_profile())
        receipt["compactFrameSha256"] = _sha256(compact_frame)
        receipt["expandedFrameSha256"] = _sha256(expanded_frame)
        receipt["credentialPathAdmitted"] = "true"
        _write_receipt(arguments.receipt, receipt)
    except (OSError, FixturePreflightError) as error:
        parser.error(str(error))
    print(json.dumps({"state": "admitted", **receipt}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
