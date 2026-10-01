"""One-shot, fail-closed CP117 lease continuation after the fixed stage recovery.

This adapter creates a *new* campaign lease.  It deliberately never reopens the
closed campaign or resubmits the lost fixture-stage correlation.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from typing import Any, Mapping

from . import windows_cp117_lease as lease
from . import windows_msi_base_prepare as base
from . import windows_msi_http_transfer as transfer
from . import windows_msi_public_scenario as public
from . import windows_update_fixture_stage as stage
from . import windows_update_fixture_stage_recovery as recovery


class WindowsCp117CampaignRebaseError(ValueError):
    pass


_DIR = ".rag_index/windows-cp117-campaign-rebase"
_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
_VERSION = "2.1.19"


def _request(value: Mapping[str, Any]) -> dict[str, str]:
    fields = {"host", "leaseId", "previousLeaseId", "sourceSha",
              "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"}
    if not isinstance(value, Mapping) or set(value) != fields or value.get("host") != "archlinux":
        raise WindowsCp117CampaignRebaseError("CP117 campaign rebase requires exact inputs.")
    for name, pattern in (("leaseId", _UUID), ("previousLeaseId", _UUID), ("sourceSha", _SHA),
                          ("fixtureReceiptArtifactId", _ARTIFACT), ("baseMsiArtifactId", _ARTIFACT),
                          ("targetMsiArtifactId", _ARTIFACT)):
        if not isinstance(value.get(name), str) or not pattern.fullmatch(value[name]):
            raise WindowsCp117CampaignRebaseError("Invalid CP117 campaign rebase " + name + ".")
    if any(str(uuid.UUID(value[name])) != value[name] for name in ("leaseId", "previousLeaseId")):
        raise WindowsCp117CampaignRebaseError("CP117 campaign rebase IDs are not canonical.")
    if value["leaseId"] == value["previousLeaseId"]:
        raise WindowsCp117CampaignRebaseError("CP117 campaign rebase must create a new lease.")
    return dict(value)


def _journal(root: Path) -> Path:
    path = root / _DIR
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise WindowsCp117CampaignRebaseError("CP117 campaign rebase journal is unsafe.")
    return path


def _write_once(path: Path, value: Mapping[str, Any]) -> None:
    raw = (json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(raw) > 8192:
        raise WindowsCp117CampaignRebaseError("CP117 campaign rebase receipt is too large.")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _history(root: Path, request: Mapping[str, str], descriptor: tuple[Any, ...]) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    """Prove the exact recovered stage and its base terminal evidence."""
    if request["previousLeaseId"] == request["leaseId"]:
        raise WindowsCp117CampaignRebaseError("CP117 campaign rebase reuses a lease.")
    intent = stage._read_intent(root, recovery._CORRELATION)
    if intent is None or intent.get("leaseId") != request["previousLeaseId"]:
        raise WindowsCp117CampaignRebaseError("CP117 campaign rebase previous lease changed.")
    previous = stage._request(intent.get("request", {}))
    for name in ("sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"):
        if previous[name] != request[name]:
            raise WindowsCp117CampaignRebaseError("CP117 campaign rebase artifact pair changed.")
    env, socket, pid, ticks, sid = descriptor
    if (intent.get("environment"), intent.get("socketPath"), intent.get("pid"), intent.get("startTicks"), intent.get("expectedSid")) != (env, socket, pid, ticks, sid):
        raise WindowsCp117CampaignRebaseError("CP117 campaign rebase QEMU generation changed.")
    pair = public._admit_pair(root, request["sourceSha"], request["fixtureReceiptArtifactId"],
                              request["baseMsiArtifactId"], request["targetMsiArtifactId"])
    if pair.get("baseVersion") != _VERSION or intent.get("sourceFingerprint") != pair.get("sourceFingerprint"):
        raise WindowsCp117CampaignRebaseError("CP117 campaign rebase requires installed base 2.1.19.")
    evidence, cleanup = recovery._evidence(intent, descriptor)
    receipt = recovery._read_receipt(root)
    expected_receipt = {"version": 1, "correlationId": recovery._CORRELATION,
                        "leaseId": request["previousLeaseId"],
                        "guestGeneration": {"socketPath": socket, "qemuPid": pid, "startTicks": ticks},
                        "evidenceSha256": evidence, "cleanupReceiptSha256": cleanup,
                        "state": "recovered"}
    if receipt != expected_receipt:
        raise WindowsCp117CampaignRebaseError("The fixed fixture-stage recovery is not closed.")
    record = transfer._intent(root, request["previousLeaseId"])
    if record is not None:
        required_transfer = {
            "correlationId": request["previousLeaseId"], "sourceSha": request["sourceSha"],
            "baseMsiArtifactId": request["baseMsiArtifactId"], "environment": env,
            "socketPath": socket, "qemuPid": pid, "startTicks": ticks, "expectedSid": sid,
        }
        if any(record.get(name) != expected for name, expected in required_transfer.items()):
            raise WindowsCp117CampaignRebaseError("CP117 campaign rebase base terminal binding changed.")
    terminal = transfer._terminal_intent(root, record) if record is not None else None
    if terminal is None:
        raise WindowsCp117CampaignRebaseError("CP117 campaign rebase base terminal receipt is unavailable.")
    return intent, pair, terminal, cleanup


def _idle(root: Path) -> bool:
    observed = base.readiness(root, {"host": "archlinux", "expectedCurrentVersion": _VERSION})
    return (observed.get("state") == "ready" and observed.get("ready") is True
            and observed.get("code") == "READY" and observed.get("installedVersion") == _VERSION
            and observed.get("productCount") == 1 and observed.get("activeCount") == 0
            and observed.get("activeProcesses") == [])


def _previous_closed(root: Path, request: Mapping[str, str], descriptor: tuple[Any, ...], config: Any,
                     target: Any, cleanup: str) -> None:
    directory, lock = lease._locked(root)
    try:
        if lease._active(directory) is not None:
            raise WindowsCp117CampaignRebaseError("CP117 campaign is still active or unknown.")
        closed = lease._closed(directory, request["previousLeaseId"])
        old_request = {**request, "correlationId": request["previousLeaseId"]}
        expected = base._campaign_identity(old_request, descriptor)
        if (closed is None or closed.get("identity") != expected or closed.get("lastOutcome") != "failed-cleaned"
                or closed.get("lastEvidenceSha256") != cleanup
                or closed.get("server") != "stopped" or closed.get("credentials") != "absent"
                or not lease._remote_confirm(base._campaign_remote(config, target), "status", closed, None)):
            raise WindowsCp117CampaignRebaseError("Closed CP117 campaign proof is unavailable.")
    finally:
        os.close(lock)


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Reserve one continuation lease after all old-stage evidence is revalidated."""
    root = Path(root).resolve(strict=True)
    request = _request(value)
    unknown = {"state": "unknown", "leaseId": request["leaseId"], "replayAllowed": False}
    try:
        config, target, descriptor = base._descriptor(root)
        intent, pair, terminal, cleanup = _history(root, request, descriptor)
        _previous_closed(root, request, descriptor, config, target, cleanup)
        if not _idle(root):
            raise WindowsCp117CampaignRebaseError("CP117 campaign rebase guest is not freshly idle.")
        journal = _journal(root)
        lock = os.open(journal / ".environment.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(lock)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise WindowsCp117CampaignRebaseError("CP117 campaign rebase lock is unsafe.")
            fcntl.flock(lock, fcntl.LOCK_EX)
            _write_once(journal / (request["leaseId"] + ".json"), {
                "version": 1, "request": request, "previousStageCorrelationId": recovery._CORRELATION,
                "previousLeaseId": request["previousLeaseId"], "baseTerminalReceiptSha256": terminal,
                "guestGeneration": {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]},
                "sourceFingerprint": pair["sourceFingerprint"],
            })
        finally:
            os.close(lock)
        identity = base._campaign_identity({**request, "correlationId": request["leaseId"]}, descriptor)
        opened = lease.begin(root, identity, base._campaign_remote(config, target))
        if opened.get("state") != "active":
            return unknown
        return {"state": "active", "leaseId": request["leaseId"], "previousLeaseId": request["previousLeaseId"],
                "baseTerminalReceiptSha256": terminal, "replayAllowed": False}
    except (OSError, ValueError, KeyError, TypeError, WindowsCp117CampaignRebaseError,
            lease.Cp117LeaseError, base.WindowsMsiBasePrepareError, transfer.WindowsMsiHttpTransferError,
            stage.WindowsUpdateFixtureStageError, recovery.WindowsUpdateFixtureStageRecoveryError):
        return unknown
