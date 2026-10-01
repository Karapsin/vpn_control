"""One fixed successor for CP117's retired e66 campaign.

The historical e66 stage used the campaign lease itself as its correlation.
It is therefore deliberately excluded from the normal stage-history route:
that route correctly rejects a prior lease which is also the current lease.
This module is the narrowly bounded replacement.  It never starts, stages,
or transfers fixture bytes; it can only close e66 after its immutable
retirement proof and reserve one distinct successor with the same artifacts.
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
from . import windows_cp117_campaign_status as campaign_status
from . import windows_msi_base_prepare as base
from . import windows_msi_owner_liveness as owner_liveness
from . import windows_update_fixture_http_stage as e66


class WindowsCp117E66SuccessorError(ValueError):
    pass


_DIR = ".rag_index/windows-cp117-e66-successor"
_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
_OLD = e66._E66_LEASE
_UNKNOWN = {"state": "unknown", "replayAllowed": False, "nativeActionAllowed": False}

_REMOTE_NEW_ABSENT = base._QGA + r'''import fcntl
root,env,old,new,oldsha=sys.argv[1:]
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()
try:
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-cp117-campaign')
 for path in (root,parent,group):
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 fd=os.open(os.path.join(group,'.environment.lock'),os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 try:
  fcntl.flock(fd,fcntl.LOCK_SH)
  def read(path):
   info=os.lstat(path)
   if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError()
   return json.load(open(path,encoding='utf-8'))
  if os.path.exists(os.path.join(group,'active.json')) or os.path.exists(os.path.join(group,new+'.closed.json')):raise ValueError()
  if digest(read(os.path.join(group,old+'.closed.json')))!=oldsha:raise ValueError()
 finally:os.close(fd)
 print('{"version":1,"state":"absent"}')
except Exception:print('{"version":1,"state":"unknown"}')
'''


def _request(value: Mapping[str, Any]) -> dict[str, str]:
    fields = {"host", "oldLeaseId", "newLeaseId", "sourceSha", "fixtureReceiptArtifactId",
              "baseMsiArtifactId", "targetMsiArtifactId"}
    if not isinstance(value, Mapping) or set(value) != fields or value.get("host") != "archlinux":
        raise WindowsCp117E66SuccessorError("E66 successor requires exact CP117 inputs.")
    if value.get("oldLeaseId") != _OLD or not isinstance(value.get("newLeaseId"), str) or not _UUID.fullmatch(value["newLeaseId"]):
        raise WindowsCp117E66SuccessorError("E66 successor lease IDs are invalid.")
    if str(uuid.UUID(value["newLeaseId"])) != value["newLeaseId"] or value["newLeaseId"] == _OLD:
        raise WindowsCp117E66SuccessorError("E66 successor must use one distinct canonical lease.")
    for name, pattern in (("sourceSha", re.compile(r"[0-9a-f]{40}\Z")),
                          ("fixtureReceiptArtifactId", _ARTIFACT), ("baseMsiArtifactId", _ARTIFACT),
                          ("targetMsiArtifactId", _ARTIFACT)):
        if not isinstance(value.get(name), str) or not pattern.fullmatch(value[name]):
            raise WindowsCp117E66SuccessorError("E66 successor artifact input is invalid.")
    return dict(value)


def _journal(root: Path, create: bool) -> Path | None:
    path = root / _DIR
    if create:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        info = path.lstat()
    except OSError:
        return None
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise WindowsCp117E66SuccessorError("E66 successor journal is unsafe.")
    return path


def _read(path: Path) -> dict[str, Any] | None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 8192:
            raise WindowsCp117E66SuccessorError("E66 successor receipt is unsafe.")
        try:
            value = json.load(stream)
        except (TypeError, ValueError) as error:
            raise WindowsCp117E66SuccessorError("E66 successor receipt is invalid.") from error
    return value if isinstance(value, dict) else None


def _write_once(path: Path, value: Mapping[str, Any]) -> None:
    raw = (json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _idle(root: Path) -> bool:
    observed = base.readiness(root, {"host": "archlinux", "expectedCurrentVersion": "2.1.19"})
    if not (observed.get("state") == "ready" and observed.get("ready") is True and observed.get("code") == "READY"
            and observed.get("productCount") == 1 and observed.get("activeCount") == 0
            and observed.get("activeProcesses") == [] and observed.get("ownedExplorerCount") == 1):
        return False
    owner = owner_liveness.observe(root, {"host": "archlinux"})
    return (owner.get("state") in {"absent", "blocked"} and owner.get("ownerProcesses") == "none"
            and owner.get("installerProcesses") == "none" and owner.get("consentProcesses") == "none"
            and owner.get("runtimeProcesses") == "none" and owner.get("runtimeOff") is True
            and owner.get("stateLeaves") in {"none", "one"})


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _retirement_receipt(receipt: Mapping[str, Any], receipt_sha: str, descriptor: tuple[Any, ...]) -> None:
    fields = {"correlationId", "leaseId", "sourceFingerprint", "bundleSha256", "guestGeneration",
              "transcriptSha256", "coreSha256", "remoteStage", "remoteCampaign"}
    if (not isinstance(receipt, Mapping) or set(receipt) != fields or receipt.get("correlationId") != e66._E66_CORRELATION
            or receipt.get("leaseId") != _OLD or receipt.get("guestGeneration") != {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}
            or receipt.get("remoteStage") != "absent" or receipt.get("remoteCampaign") != "confirmed"
            or not isinstance(receipt_sha, str) or not _HASH.fullmatch(receipt_sha) or _digest(receipt) != receipt_sha
            or any(not isinstance(receipt.get(name), str) or not _HASH.fullmatch(receipt[name])
                   for name in ("sourceFingerprint", "bundleSha256", "transcriptSha256", "coreSha256"))):
        raise WindowsCp117E66SuccessorError("E66 retirement receipt changed.")


def _admission(root: Path, request: Mapping[str, str]) -> tuple[Any, Any, tuple[Any, ...], Mapping[str, Any], str, Mapping[str, Any], Mapping[str, Any]]:
    """Return only the retired e66 record which can be closed into a successor."""
    state, details = e66._e66_retirement_admission(root, reconcile_pending=False)
    if state != "retired" or details is None:
        raise WindowsCp117E66SuccessorError("E66 retirement is incomplete or unknown.")
    _root, record, config, target, _remote, receipt, receipt_sha = details
    old_request = record.get("request") if isinstance(record, Mapping) else None
    if not isinstance(old_request, Mapping) or any(old_request.get(name) != request[name] for name in
                                                   ("sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId")):
        raise WindowsCp117E66SuccessorError("E66 successor artifact binding changed.")
    descriptor = base._descriptor(root)[2]
    _retirement_receipt(receipt, receipt_sha, descriptor)
    expected = base._campaign_identity({**old_request, "correlationId": _OLD}, descriptor)
    directory, lock = lease._locked(root)
    try:
        active = lease._active(directory)
        if (active is None or active.get("identity") != expected or active.get("state") != "active"
                or active.get("role") is not None or active.get("correlationId") is not None
                or active.get("server") != "stopped" or active.get("credentials") != "absent"
                or active.get("lastOutcome") != "failed-cleaned" or active.get("lastEvidenceSha256") != receipt_sha):
            raise WindowsCp117E66SuccessorError("E66 active campaign is not the retired idle record.")
    finally:
        os.close(lock)
    if not isinstance(receipt_sha, str) or not _HASH.fullmatch(receipt_sha) or not _idle(root):
        raise WindowsCp117E66SuccessorError("E66 successor guest is not freshly idle.")
    return config, target, descriptor, old_request, receipt_sha, receipt, active


def _cleanup(descriptor: tuple[Any, ...], receipt_sha: str) -> dict[str, Any]:
    return {"guestGeneration": {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]},
            "serverStopped": True, "credentialsCleaned": True, "protectedJobsTerminalCleaned": True,
            "activeInstallerProcessesAbsent": True,
            "cleanupReceiptSha256": hashlib.sha256((receipt_sha + ":e66-successor-close").encode()).hexdigest()}


def _inspect_readonly(root: Path, lease_id: str) -> dict[str, Any]:
    """Inspect existing campaign receipts without creating the lease directory."""
    directory = root / lease._DIR
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsCp117E66SuccessorError("CP117 campaign journal is unsafe.")
    active = lease._active(directory)
    if active is not None and active["identity"]["leaseId"] == lease_id:
        return {"state": active["state"], "leaseId": lease_id, "record": active}
    closed = lease._closed(directory, lease_id)
    return {"state": "closed" if closed is not None else "unknown", "leaseId": lease_id, "record": closed}


def _initial_idle(observed: Mapping[str, Any], identity: Mapping[str, Any]) -> bool:
    record = observed.get("record")
    return (observed.get("state") == "active" and isinstance(record, Mapping)
            and record.get("identity") == identity and record.get("role") is None
            and record.get("correlationId") is None and record.get("server") == "stopped"
            and record.get("credentials") == "absent" and record.get("sequence") == 0
            and record.get("lastEvidenceSha256") is None and record.get("lastOutcome") is None)


def _receipt_binding(root: Path, request: Mapping[str, str]) -> tuple[Any, Any, tuple[Any, ...], Mapping[str, Any], str]:
    """Validate the durable successor intent after e66 is no longer active."""
    journal = _journal(root, False)
    if journal is None:
        raise WindowsCp117E66SuccessorError("E66 successor intent is unavailable.")
    stored = _read(journal / (request["newLeaseId"] + ".json"))
    descriptor = base._descriptor(root)[2]
    fields = {"version", "request", "oldLeaseId", "retirementReceiptSha256", "cleanupReceiptSha256",
              "retirementReceipt", "guestGeneration"}
    if (stored is None or set(stored) != fields or stored.get("version") != 1 or _request(stored.get("request", {})) != request
            or stored.get("oldLeaseId") != _OLD or stored.get("guestGeneration") != {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}
            or not isinstance(stored.get("cleanupReceiptSha256"), str) or not _HASH.fullmatch(stored["cleanupReceiptSha256"])):
        raise WindowsCp117E66SuccessorError("E66 successor intent changed.")
    _retirement_receipt(stored["retirementReceipt"], stored["retirementReceiptSha256"], descriptor)
    if stored["cleanupReceiptSha256"] != _cleanup(descriptor, stored["retirementReceiptSha256"])["cleanupReceiptSha256"]:
        raise WindowsCp117E66SuccessorError("E66 successor cleanup proof changed.")
    old_request = {"correlationId": e66._E66_CORRELATION, "sourceSha": request["sourceSha"],
                   "fixtureReceiptArtifactId": request["fixtureReceiptArtifactId"], "baseMsiArtifactId": request["baseMsiArtifactId"],
                   "targetMsiArtifactId": request["targetMsiArtifactId"]}
    config, target, _unused = base._descriptor(root)
    return config, target, descriptor, old_request, stored["retirementReceiptSha256"]


def _remote_new_absent(config: Any, target: Any, old_closed: Mapping[str, Any], new_lease: str) -> bool:
    try:
        raw = base._remote(config, _REMOTE_NEW_ABSENT, (str(target.fixture_transfer_root), "windows-cp117", _OLD,
                           new_lease, _digest(old_closed)), None, 30)
        return json.loads(raw) == {"version": 1, "state": "absent"} if raw is not None else False
    except (OSError, ValueError, TypeError, base.WindowsMsiBasePrepareError):
        return False


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read only: expose a partial close/open without retrying either mutation."""
    try:
        root_path = Path(root).resolve(strict=True); request = _request(value)
        _config, _target, descriptor, old_request, retired = _receipt_binding(root_path, request)
        old = _inspect_readonly(root_path, _OLD)
        new = _inspect_readonly(root_path, request["newLeaseId"])
        expected_old = base._campaign_identity({**old_request, "correlationId": _OLD}, descriptor)
        expected_new = base._campaign_identity({**old_request, "correlationId": request["newLeaseId"]}, descriptor)
        old_record = old.get("record")
        old_is_bound = (isinstance(old_record, Mapping) and old_record.get("identity") == expected_old
                          and old_record.get("role") is None and old_record.get("correlationId") is None
                          and old_record.get("server") == "stopped" and old_record.get("credentials") == "absent"
                          and old_record.get("lastOutcome") == "failed-cleaned"
                          and ((old.get("state") == "active" and old_record.get("lastEvidenceSha256") == retired)
                               or (old.get("state") in {"pending-close", "closed"} and old_record.get("lastEvidenceSha256") == _cleanup(descriptor, retired)["cleanupReceiptSha256"])))
        if old.get("state") == "closed" and old_is_bound and _initial_idle(new, expected_new):
            return {"state": "active", "leaseId": request["newLeaseId"], "replayAllowed": False, "nativeActionAllowed": False}
        if old.get("state") != "closed" and old_is_bound:
            return {"state": "closing", "leaseId": request["newLeaseId"], "nextAction": "inspect-close-progress", **{k: v for k, v in _UNKNOWN.items() if k != "state"}}
        if old.get("state") == "closed" and old_is_bound and new.get("state") in {"pending-remote", "unknown"}:
            return {"state": "opening", "leaseId": request["newLeaseId"], "nextAction": "inspect-open-progress", **{k: v for k, v in _UNKNOWN.items() if k != "state"}}
    except (OSError, ValueError, TypeError, WindowsCp117E66SuccessorError, lease.Cp117LeaseError):
        pass
    return dict(_UNKNOWN)


def reconcile(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Continue only a durable partial transition by remote readback, never replay.

    A pending close may use lease's fixed status/finalize reconciliation.  A
    pending successor reservation uses its status readback.  This route never
    calls ``close`` or ``begin`` and therefore cannot repeat either mutation.
    """
    try:
        root_path = Path(root).resolve(strict=True); request = _request(value)
        config, target, descriptor, old_request, retired = _receipt_binding(root_path, request)
        if not _idle(root_path):
            return dict(_UNKNOWN)
        remote = base._campaign_remote(config, target)
        old = lease.inspect(root_path, _OLD)
        expected_old = base._campaign_identity({**old_request, "correlationId": _OLD}, descriptor)
        expected_new = base._campaign_identity({**old_request, "correlationId": request["newLeaseId"]}, descriptor)
        if old.get("state") == "pending-close":
            old = lease.reconcile(root_path, _OLD, remote)
            if old.get("state") != "closed":
                return dict(_UNKNOWN)
        elif old.get("state") == "closed":
            old_closed = _inspect_readonly(root_path, _OLD).get("record")
            cleanup = _cleanup(descriptor, retired)["cleanupReceiptSha256"]
            if (not isinstance(old_closed, Mapping) or old_closed.get("identity") != expected_old
                    or old_closed.get("role") is not None or old_closed.get("correlationId") is not None
                    or old_closed.get("server") != "stopped" or old_closed.get("credentials") != "absent"
                    or old_closed.get("lastOutcome") != "failed-cleaned"
                    or old_closed.get("lastEvidenceSha256") != cleanup
                    or not campaign_status._remote_closed_proof(config, target, old_closed, expected_new)):
                return dict(_UNKNOWN)
        else:
            return dict(_UNKNOWN)
        new = lease.inspect(root_path, request["newLeaseId"])
        if new.get("state") == "pending-remote":
            new = lease.reconcile(root_path, request["newLeaseId"], remote)
        current = _inspect_readonly(root_path, request["newLeaseId"])
        return ({"state": "active", "leaseId": request["newLeaseId"], "replayAllowed": False,
                 "nativeActionAllowed": False}
                if new.get("state") == "active" and _initial_idle(current, expected_new) else dict(_UNKNOWN))
    except (OSError, ValueError, TypeError, KeyError, WindowsCp117E66SuccessorError, lease.Cp117LeaseError,
            base.WindowsMsiBasePrepareError, e66.WindowsUpdateFixtureHttpStageError):
        return dict(_UNKNOWN)


def resume_begin(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Reserve the successor once after a durably confirmed close-before-begin gap."""
    try:
        root_path = Path(root).resolve(strict=True); request = _request(value)
        config, target, descriptor, old_request, retired = _receipt_binding(root_path, request)
        cleanup_sha = _cleanup(descriptor, retired)["cleanupReceiptSha256"]
        directory, lock = lease._locked(root_path)
        try:
            if lease._active(directory) is not None:
                return dict(_UNKNOWN)
            old_closed = lease._closed(directory, _OLD)
            expected_old = base._campaign_identity({**old_request, "correlationId": _OLD}, descriptor)
            if (old_closed is None or old_closed.get("identity") != expected_old or old_closed.get("role") is not None
                    or old_closed.get("correlationId") is not None or old_closed.get("server") != "stopped"
                    or old_closed.get("credentials") != "absent" or old_closed.get("lastOutcome") != "failed-cleaned"
                    or old_closed.get("lastEvidenceSha256") != cleanup_sha):
                return dict(_UNKNOWN)
        finally:
            os.close(lock)
        remote = base._campaign_remote(config, target)
        if (not lease._remote_confirm(remote, "status", old_closed, None)
                or not _remote_new_absent(config, target, old_closed, request["newLeaseId"]) or not _idle(root_path)):
            return dict(_UNKNOWN)
        journal = _journal(root_path, False)
        if journal is None:
            return dict(_UNKNOWN)
        marker = journal / (request["newLeaseId"] + ".begin.json")
        marker_value = {"version": 1, "newLeaseId": request["newLeaseId"],
                        "oldCleanupReceiptSha256": cleanup_sha}
        lock = os.open(journal / ".environment.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if marker.exists():
                if _read(marker) != marker_value:
                    return dict(_UNKNOWN)
            else:
                _write_once(marker, marker_value)
            identity = base._campaign_identity({**old_request, "correlationId": request["newLeaseId"]}, descriptor)
            # Retain the successor lock through reservation so concurrent
            # callers cannot both consume the same absence observation.
            opened = lease.begin(root_path, identity, remote)
        finally:
            os.close(lock)
        return ({"state": "active", "leaseId": request["newLeaseId"], "replayAllowed": False,
                 "nativeActionAllowed": False} if opened.get("state") == "active" else dict(_UNKNOWN))
    except (OSError, ValueError, TypeError, KeyError, WindowsCp117E66SuccessorError, lease.Cp117LeaseError,
            base.WindowsMsiBasePrepareError, e66.WindowsUpdateFixtureHttpStageError):
        return dict(_UNKNOWN)


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Durably close only retired e66, then reserve one successor; never replay loss."""
    try:
        root_path = Path(root).resolve(strict=True); request = _request(value)
        config, target, descriptor, old_request, receipt_sha, receipt, old_active = _admission(root_path, request)
        journal = _journal(root_path, True)
        assert journal is not None
        lock = os.open(journal / ".environment.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(lock)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise WindowsCp117E66SuccessorError("E66 successor lock is unsafe.")
            fcntl.flock(lock, fcntl.LOCK_EX)
            cleanup = _cleanup(descriptor, receipt_sha)
            _write_once(journal / (request["newLeaseId"] + ".json"), {"version": 1, "request": request,
                        "oldLeaseId": _OLD, "retirementReceiptSha256": receipt_sha,
                        "cleanupReceiptSha256": cleanup["cleanupReceiptSha256"], "retirementReceipt": receipt,
                        "guestGeneration": cleanup["guestGeneration"]})
        finally:
            os.close(lock)
        remote = base._campaign_remote(config, target)
        if lease.close(root_path, _OLD, cleanup, remote, expected_current=old_active).get("state") != "closed":
            return dict(_UNKNOWN)
        identity = base._campaign_identity({**old_request, "correlationId": request["newLeaseId"]}, descriptor)
        opened = lease.begin(root_path, identity, remote)
        if opened.get("state") != "active":
            return dict(_UNKNOWN)
        return {"state": "active", "leaseId": request["newLeaseId"], "replayAllowed": False, "nativeActionAllowed": False}
    except (OSError, ValueError, TypeError, KeyError, WindowsCp117E66SuccessorError, lease.Cp117LeaseError,
            base.WindowsMsiBasePrepareError, e66.WindowsUpdateFixtureHttpStageError):
        return dict(_UNKNOWN)
