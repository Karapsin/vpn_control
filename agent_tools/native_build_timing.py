"""Read-only, source-bound timing report for independently emitted build phases."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping


_SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_PHASES = ("gradle", "runtime-prep", "packaging", "upload", "guest-staging")
_MAX_RECEIPTS = 32
_MAX_BYTES = 4096
_MAX_DURATION_NS = 24 * 60 * 60 * 1_000_000_000


def report(root: Path, current_source: str, request: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(request, Mapping) or set(request) != {"sourceSha", "pipelineId", "runId", "receipts"}:
        raise ValueError("Build timing report requires exact source, pipeline, run and receipts.")
    source, pipeline, run = request["sourceSha"], request["pipelineId"], request["runId"]
    if source != current_source or not isinstance(source, str) or not _SHA.fullmatch(source):
        raise ValueError("Build timing source must be the checked-out exact Git SHA.")
    if not isinstance(pipeline, str) or not _TOKEN.fullmatch(pipeline) or not isinstance(run, str) or not _UUID.fullmatch(run):
        raise ValueError("Build timing pipeline or run identity is invalid.")
    supplied = request["receipts"]
    if not isinstance(supplied, list) or len(supplied) > _MAX_RECEIPTS:
        raise ValueError("Build timing receipts must be a bounded list.")
    durations: dict[str, list[int]] = {phase: [] for phase in _PHASES}
    seen: set[str] = set()
    for item in supplied:
        if not isinstance(item, Mapping) or set(item) != {"path", "sha256"}:
            raise ValueError("Build timing receipt reference is invalid.")
        name, expected = item["path"], item["sha256"]
        if (not isinstance(name, str) or not re.fullmatch(r"\.rag_index/build-timings/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.json", name) or
                name in seen or not isinstance(expected, str) or not _HASH.fullmatch(expected)):
            raise ValueError("Build timing receipt path or hash is invalid.")
        seen.add(name)
        record = _read(root, name, expected)
        if set(record) != {"schemaVersion", "sourceSha", "pipelineId", "runId", "hostAlias",
                           "phase", "startedMonotonicNs", "finishedMonotonicNs"} or type(record["schemaVersion"]) is not int or record["schemaVersion"] != 1:
            raise ValueError("Build timing receipt schema is invalid.")
        if record["sourceSha"] != source or record["pipelineId"] != pipeline or record["runId"] != run:
            raise ValueError("Build timing receipt belongs to another source or run.")
        if not isinstance(record["hostAlias"], str) or not _TOKEN.fullmatch(record["hostAlias"]):
            raise ValueError("Build timing host alias is invalid.")
        phase = record["phase"]
        start, finish = record["startedMonotonicNs"], record["finishedMonotonicNs"]
        if (phase not in _PHASES or type(start) is not int or type(finish) is not int or
                start < 0 or not 0 < finish - start <= _MAX_DURATION_NS):
            raise ValueError("Build timing phase or monotonic duration is invalid.")
        durations[phase].append(finish - start)
    phases = [{"phase": phase, "state": "measured" if durations[phase] else "unmeasured",
               "durationMs": round(sum(durations[phase]) / 1_000_000, 3) if durations[phase] else None,
               "sampleCount": len(durations[phase])} for phase in _PHASES]
    measured = [item for item in phases if item["state"] == "measured"]
    largest = max(measured, key=lambda item: item["durationMs"])["phase"] if measured else None
    return {"state": "measured" if measured else "unmeasured", "sourceSha": source,
            "pipelineId": pipeline, "runId": run, "phases": phases,
            "allPhasesMeasured": len(measured) == len(_PHASES),
            "largestMeasuredPhase": largest,
            "totalMeasuredMs": round(sum(item["durationMs"] for item in measured), 3),
            "nativeActionAllowed": False, "productAction": False}


def _read(root: Path, name: str, expected: str) -> dict[str, Any]:
    owner = getattr(os, "getuid", lambda: None)()
    if owner is None:
        raise ValueError("Build timing read requires local owner identity.")
    for path in (root, root / ".rag_index", root / ".rag_index" / "build-timings"):
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISDIR(info.st_mode):
            raise ValueError("Build timing directory is unsafe.")
        if path != root and (info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("Build timing directory ownership is unsafe.")
    path = root / name
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        raw = stream.read(_MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or
            stat.S_IMODE(info.st_mode) != 0o600 or len(raw) > _MAX_BYTES or
            (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) !=
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or
            len(raw) != info.st_size or
            hashlib.sha256(raw).hexdigest() != expected):
        raise ValueError("Build timing receipt bytes or ownership are invalid.")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Build timing receipt JSON is invalid.") from error
    if not isinstance(value, dict):
        raise ValueError("Build timing receipt must be an object.")
    return value
