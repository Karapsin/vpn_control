"""Publish fixed disposable-fixture signals without exposing incomplete contents.

The caller owns the fixture directory. This utility controls no processes and
changes no directory permissions. Unknown publication is never an instruction to
retry: the already running reader may have consumed the signal.
"""
from __future__ import annotations

import argparse
import json
import os
import uuid
from pathlib import Path

SIGNALS = {
    "release-authorization": b"continue\n",
    "release-ready": b"continue\n",
    "release-running": b"continue\n",
    "release-tun_running": b"continue\n",
    "retry-owned-cleanup": b"retry\n",
}


def _write_payload(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        count = os.write(descriptor, payload[offset:])
        if count <= 0:
            raise OSError("Fixture signal write made no progress")
        offset += count
    os.fsync(descriptor)


def _error(error: OSError) -> dict[str, object]:
    return {"type": type(error).__name__, "errno": error.errno,
            "winerror": getattr(error, "winerror", None)}


def _remove_stage(stage: Path, receipt: dict[str, object]) -> None:
    try:
        os.unlink(stage)
    except FileNotFoundError:
        receipt["stagedPath"] = None
    except OSError as error:
        receipt["cleanupError"] = _error(error)
    else:
        receipt["stagedPath"] = None


def publish_fixture_signal(destination: Path) -> dict[str, object]:
    destination = Path(destination).absolute()
    if destination.name not in SIGNALS:
        raise ValueError("A fixed fixture signal name is required")
    stage = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.pending")
    receipt: dict[str, object] = {
        "published": False, "destination": str(destination), "stagedPath": str(stage),
        "error": None, "cleanupError": None,
    }
    try:
        descriptor = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    except OSError as error:
        # No successful exclusive creation means no ownership of this path.
        receipt["stagedPath"] = None
        receipt["error"] = _error(error)
        return receipt
    try:
        try:
            _write_payload(descriptor, SIGNALS[destination.name])
        finally:
            os.close(descriptor)
    except OSError as error:
        receipt["error"] = _error(error)
        _remove_stage(stage, receipt)
        return receipt
    try:
        # A hard link publishes complete bytes atomically and cannot replace an
        # existing signal. Unsupported filesystems fail explicitly; no copy fallback.
        os.link(stage, destination)
    except OSError as error:
        # Preserve the stage even if a wrapper lost the result after publication.
        # Neither the exception nor an absent result proves that the reader waited.
        receipt["published"] = None
        receipt["error"] = _error(error)
        return receipt
    receipt["published"] = True
    _remove_stage(stage, receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        receipt = publish_fixture_signal(args.destination)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(receipt))
    return 0 if receipt["published"] is True and receipt["stagedPath"] is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
