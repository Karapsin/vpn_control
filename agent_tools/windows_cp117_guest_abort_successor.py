"""Reserve one new CP117 campaign after the fixed lost guest-create abort.

The abort is a terminal fact for one correlation.  This module only closes its
exact idle campaign and opens a distinct lease with the same source and MSI
artifacts.  It never recreates, downloads, or executes the abandoned guest
operation.
"""
from __future__ import annotations

import fcntl
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from typing import Any, Mapping

from . import windows_cp117_campaign_status as campaign_status
from . import windows_cp117_lease as lease
from . import windows_msi_base_prepare as base
from . import windows_msi_owner_liveness as owner_liveness
from . import windows_update_fixture_guest_create_abort as abort
from . import windows_update_fixture_http_stage as http


class WindowsCp117GuestAbortSuccessorError(ValueError):
    pass


_DIR = ".rag_index/windows-cp117-guest-abort-successor"
_OLD = abort._LEASE
_CORRELATION = abort._CORRELATION
_SOURCE = abort._SOURCE
_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
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
    required = {"host", "oldLeaseId", "newLeaseId", "sourceSha", "fixtureReceiptArtifactId",
                "baseMsiArtifactId", "targetMsiArtifactId"}
    if not isinstance(value, Mapping) or set(value) != required or value.get("host") != "archlinux":
        raise WindowsCp117GuestAbortSuccessorError("Guest abort successor requires exact CP117 inputs.")
    if value.get("oldLeaseId") != _OLD or value.get("sourceSha") != _SOURCE:
        raise WindowsCp117GuestAbortSuccessorError("Guest abort successor is bound to one retired campaign.")
    new = value.get("newLeaseId")
    if not isinstance(new, str) or not _UUID.fullmatch(new) or str(uuid.UUID(new)) != new or new == _OLD:
        raise WindowsCp117GuestAbortSuccessorError("Guest abort successor requires one distinct canonical lease.")
    for field in ("fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"):
        if not isinstance(value.get(field), str) or not _ARTIFACT.fullmatch(value[field]):
            raise WindowsCp117GuestAbortSuccessorError("Guest abort successor artifact is invalid.")
    return dict(value)


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(dict(value), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _journal(root: Path, create: bool) -> Path | None:
    path = root / _DIR
    if create:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
    try: info = path.lstat()
    except OSError: return None
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise WindowsCp117GuestAbortSuccessorError("Guest abort successor journal is unsafe.")
    return path


def _read(path: Path) -> dict[str, Any] | None:
    try: fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError: return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 12288:
            raise WindowsCp117GuestAbortSuccessorError("Guest abort successor receipt is unsafe.")
        try: value = json.load(stream)
        except (TypeError, ValueError) as error: raise WindowsCp117GuestAbortSuccessorError("Guest abort successor receipt is invalid.") from error
    return value if isinstance(value, dict) else None


def _write_once(path: Path, value: Mapping[str, Any]) -> None:
    raw = (json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try: os.fsync(parent)
    finally: os.close(parent)


def _idle(root: Path) -> bool:
    ready = base.readiness(root, {"host": "archlinux", "expectedCurrentVersion": "2.1.19"})
    if not (ready.get("state") == "ready" and ready.get("ready") is True and ready.get("code") == "READY"
            and ready.get("productCount") == 1 and ready.get("activeCount") == 0
            and ready.get("activeProcesses") == [] and ready.get("ownedExplorerCount") == 1):
        return False
    owner = owner_liveness.observe(root, {"host": "archlinux"})
    return (owner.get("state") in {"absent", "blocked"} and owner.get("ownerProcesses") == "none"
            and owner.get("installerProcesses") == "none" and owner.get("consentProcesses") == "none"
            and owner.get("runtimeProcesses") == "none" and owner.get("runtimeOff") is True
            and owner.get("stateLeaves") in {"none", "one"})


def _cleanup(descriptor: tuple[Any, ...], receipt_sha: str) -> dict[str, Any]:
    return {"guestGeneration": {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]},
            "serverStopped": True, "credentialsCleaned": True, "protectedJobsTerminalCleaned": True,
            "activeInstallerProcessesAbsent": True,
            "cleanupReceiptSha256": hashlib.sha256((receipt_sha + ":guest-abort-successor-close").encode()).hexdigest()}


def _inspect(root: Path, lease_id: str) -> dict[str, Any]:
    directory = root / lease._DIR; info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise WindowsCp117GuestAbortSuccessorError("CP117 campaign journal is unsafe.")
    active = lease._active(directory)
    if active is not None and active["identity"]["leaseId"] == lease_id:
        return {"state": active["state"], "record": active}
    closed = lease._closed(directory, lease_id)
    return {"state": "closed" if closed is not None else "unknown", "record": closed}


def _initial_idle(observed: Mapping[str, Any], identity: Mapping[str, Any]) -> bool:
    record = observed.get("record")
    return (observed.get("state") == "active" and isinstance(record, Mapping) and record.get("identity") == identity
            and record.get("role") is None and record.get("correlationId") is None and record.get("server") == "stopped"
            and record.get("credentials") == "absent" and record.get("sequence") == 0
            and record.get("lastEvidenceSha256") is None and record.get("lastOutcome") is None)


def _receipt_binding(root: Path, request: Mapping[str, str]) -> tuple[Any, Any, tuple[Any, ...], Mapping[str, Any], str, int, Mapping[str, Any]]:
    journal = _journal(root, False)
    if journal is None: raise WindowsCp117GuestAbortSuccessorError("Guest abort successor intent is unavailable.")
    stored = _read(journal / (request["newLeaseId"] + ".json")); descriptor = base._descriptor(root)[2]
    fields = {"version", "request", "oldLeaseId", "abortReceipt", "abortReceiptSha256", "cleanupReceiptSha256", "guestGeneration", "bundleSize", "authorityBinding"}
    if (stored is None or set(stored) != fields or stored.get("version") != 1 or _request(stored.get("request", {})) != request
            or stored.get("oldLeaseId") != _OLD or stored.get("guestGeneration") != {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}):
        raise WindowsCp117GuestAbortSuccessorError("Guest abort successor intent changed.")
    receipt = stored.get("abortReceipt")
    if not isinstance(receipt, Mapping) or not isinstance(stored.get("abortReceiptSha256"), str) or not _SHA.fullmatch(stored["abortReceiptSha256"]) or _digest(receipt) != stored["abortReceiptSha256"]:
        raise WindowsCp117GuestAbortSuccessorError("Guest abort receipt changed.")
    expected_receipt, expected_sha = abort._receipt_value({"request": {"fixtureReceiptArtifactId": request["fixtureReceiptArtifactId"], "baseMsiArtifactId": request["baseMsiArtifactId"], "targetMsiArtifactId": request["targetMsiArtifactId"]}, "sourceFingerprint": receipt.get("sourceFingerprint"), "bundleSha256": receipt.get("bundleSha256")}, descriptor)
    if dict(receipt) != expected_receipt or stored["abortReceiptSha256"] != expected_sha or stored.get("cleanupReceiptSha256") != _cleanup(descriptor, expected_sha)["cleanupReceiptSha256"]:
        raise WindowsCp117GuestAbortSuccessorError("Guest abort successor proof changed.")
    authority = stored.get("authorityBinding")
    expected_authority = {"correlationId": _CORRELATION, "socketPath": descriptor[1], "pid": descriptor[2], "startTicks": descriptor[3], "leaseId": _OLD, "sourceSha": _SOURCE, "sourceFingerprint": receipt["sourceFingerprint"], "bundleSha256": receipt["bundleSha256"], "expectedSid": descriptor[4], "fixtureReceiptArtifactId": request["fixtureReceiptArtifactId"], "baseMsiArtifactId": request["baseMsiArtifactId"], "targetMsiArtifactId": request["targetMsiArtifactId"]}
    size = stored.get("bundleSize")
    if authority != expected_authority or type(size) is not int or not 0 < size <= 1075838976:
        raise WindowsCp117GuestAbortSuccessorError("Guest abort authority binding changed.")
    old_request = {"correlationId": _CORRELATION, "sourceSha": _SOURCE,
                   "fixtureReceiptArtifactId": request["fixtureReceiptArtifactId"], "baseMsiArtifactId": request["baseMsiArtifactId"], "targetMsiArtifactId": request["targetMsiArtifactId"]}
    config, target, _ = base._descriptor(root)
    return config, target, descriptor, old_request, expected_sha, size, authority


def _remote_marker_clean(config: Any, target: Any, bundle_sha: str, bundle_size: int, authority: Mapping[str, Any]) -> bool:
    """Read the fixed abort marker.  It neither replays nor repairs cleanup."""
    try:
        encoded = base64.b64encode(json.dumps(dict(authority), sort_keys=True, separators=(",", ":")).encode()).decode("ascii")
        raw = base._remote(config, abort._REMOTE_ABORT, (str(target.fixture_transfer_root), _CORRELATION,
                           bundle_sha, str(bundle_size), encoded, "status"), None, 30)
        return (json.loads(raw) if raw is not None else None) == {"state": "cleaned"}
    except (OSError, ValueError, TypeError, base.WindowsMsiBasePrepareError): return False


def _remote_new_absent(config: Any, target: Any, old_closed: Mapping[str, Any], new_lease: str) -> bool:
    try:
        raw = base._remote(config, _REMOTE_NEW_ABSENT, (str(target.fixture_transfer_root), "windows-cp117", _OLD, new_lease, _digest(old_closed)), None, 30)
        return json.loads(raw) == {"version": 1, "state": "absent"} if raw is not None else False
    except (OSError, ValueError, TypeError, base.WindowsMsiBasePrepareError): return False


def _admission(root: Path, request: Mapping[str, str]) -> tuple[Any, Any, tuple[Any, ...], Mapping[str, Any], Mapping[str, Any], str, Mapping[str, Any], int, Mapping[str, Any]]:
    state, details = abort._admission(root)
    if state != "retired" or details is None: raise WindowsCp117GuestAbortSuccessorError("Guest-create abort is incomplete or unknown.")
    root_path, record, config, target, descriptor, receipt, receipt_sha = details
    if (record.get("leaseId") != _OLD or record.get("request", {}).get("correlationId") != _CORRELATION
            or any(record["request"].get(k) != request[k] for k in ("sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"))):
        raise WindowsCp117GuestAbortSuccessorError("Guest abort successor artifact binding changed.")
    # A retired local role alone is insufficient: the remote terminal marker is
    # checked by the abort adapter before the old campaign can be consumed.
    if not isinstance(receipt_sha, str) or not _SHA.fullmatch(receipt_sha) or not _idle(root_path):
        raise WindowsCp117GuestAbortSuccessorError("Guest abort successor guest is not freshly idle.")
    identity = base._campaign_identity({**record["request"], "correlationId": _OLD}, descriptor)
    directory, lock = lease._locked(root_path)
    try:
        active = lease._active(directory)
        if (active is None or active.get("identity") != identity or active.get("state") != "active" or active.get("role") is not None
                or active.get("correlationId") is not None or active.get("server") != "stopped" or active.get("credentials") != "absent"
                or active.get("lastOutcome") != "failed-cleaned" or active.get("lastEvidenceSha256") != receipt_sha):
            raise WindowsCp117GuestAbortSuccessorError("Guest abort campaign is not the retired idle record.")
    finally: os.close(lock)
    # Keep both sides of retirement present at the point that consumes it.
    # The abort module deliberately accepts response recovery, so a local
    # receipt without this exact remote cleaned marker is never enough here.
    binding = base64.b64encode(json.dumps(http._authority_binding(record, descriptor), sort_keys=True,
                                           separators=(",", ":")).encode()).decode("ascii")
    raw = base._remote(config, abort._REMOTE_ABORT, (str(target.fixture_transfer_root), _CORRELATION,
                       record["bundleSha256"], str(record["bundleSize"]), binding, "status"), None, 30)
    if (json.loads(raw) if raw is not None else None) != {"state": "cleaned"}:
        raise WindowsCp117GuestAbortSuccessorError("Guest abort remote cleanup is not confirmed.")
    if not lease._remote_confirm(base._campaign_remote(config, target), "status", active, None):
        raise WindowsCp117GuestAbortSuccessorError("Guest abort remote campaign is not confirmed.")
    return config, target, descriptor, record["request"], receipt, receipt_sha, active, record["bundleSize"], http._authority_binding(record, descriptor)


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        root_path = Path(root).resolve(strict=True); request = _request(value)
        config, target, descriptor, old_request, retired, size, authority = _receipt_binding(root_path, request)
        old, new = _inspect(root_path, _OLD), _inspect(root_path, request["newLeaseId"])
        expected_old = base._campaign_identity({**old_request, "correlationId": _OLD}, descriptor)
        expected_new = base._campaign_identity({**old_request, "correlationId": request["newLeaseId"]}, descriptor)
        old_record = old.get("record"); cleanup = _cleanup(descriptor, retired)["cleanupReceiptSha256"]
        old_ok = isinstance(old_record, Mapping) and old_record.get("identity") == expected_old and old_record.get("role") is None and old_record.get("correlationId") is None and old_record.get("server") == "stopped" and old_record.get("credentials") == "absent" and old_record.get("lastOutcome") == "failed-cleaned" and ((old.get("state") == "active" and old_record.get("lastEvidenceSha256") == retired) or (old.get("state") in {"pending-close", "closed"} and old_record.get("lastEvidenceSha256") == cleanup))
        if not old_ok or not _remote_marker_clean(config, target, authority["bundleSha256"], size, authority): return dict(_UNKNOWN)
        remote = base._campaign_remote(config, target)
        if old.get("state") == "closed":
            if not campaign_status._remote_closed_proof(config, target, old_record, expected_new): return dict(_UNKNOWN)
            if _initial_idle(new, expected_new): return {"state": "active", "leaseId": request["newLeaseId"], "replayAllowed": False, "nativeActionAllowed": False}
            return {"state": "opening", "leaseId": request["newLeaseId"], "nextAction": "inspect-open-progress", **{k:v for k,v in _UNKNOWN.items() if k != "state"}}
        if not lease._remote_confirm(remote, "status", old_record, None): return dict(_UNKNOWN)
        return {"state": "closing", "leaseId": request["newLeaseId"], "nextAction": "inspect-close-progress", **{k:v for k,v in _UNKNOWN.items() if k != "state"}}
    except (OSError, ValueError, TypeError, KeyError, WindowsCp117GuestAbortSuccessorError, lease.Cp117LeaseError): pass
    return dict(_UNKNOWN)


def reconcile(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read back partial close/open only; never resubmit either mutation."""
    try:
        root_path = Path(root).resolve(strict=True); request = _request(value)
        config, target, descriptor, old_request, retired, size, authority = _receipt_binding(root_path, request)
        if not _idle(root_path) or not _remote_marker_clean(config, target, authority["bundleSha256"], size, authority): return dict(_UNKNOWN)
        remote = base._campaign_remote(config, target); old = lease.inspect(root_path, _OLD)
        expected_old = base._campaign_identity({**old_request, "correlationId": _OLD}, descriptor)
        expected_new = base._campaign_identity({**old_request, "correlationId": request["newLeaseId"]}, descriptor)
        if old.get("state") == "pending-close": old = lease.reconcile(root_path, _OLD, remote)
        if old.get("state") != "closed": return dict(_UNKNOWN)
        closed = _inspect(root_path, _OLD).get("record")
        if not isinstance(closed, Mapping) or closed.get("identity") != expected_old or closed.get("lastEvidenceSha256") != _cleanup(descriptor, retired)["cleanupReceiptSha256"] or not campaign_status._remote_closed_proof(config, target, closed, expected_new): return dict(_UNKNOWN)
        new = lease.inspect(root_path, request["newLeaseId"])
        if new.get("state") == "pending-remote": new = lease.reconcile(root_path, request["newLeaseId"], remote)
        return {"state": "active", "leaseId": request["newLeaseId"], "replayAllowed": False, "nativeActionAllowed": False} if new.get("state") == "active" and _initial_idle(_inspect(root_path, request["newLeaseId"]), expected_new) else dict(_UNKNOWN)
    except (OSError, ValueError, TypeError, KeyError, WindowsCp117GuestAbortSuccessorError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError): return dict(_UNKNOWN)


def resume_begin(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Consume a durable close-before-begin gap once, after remote readback."""
    try:
        root_path = Path(root).resolve(strict=True); request = _request(value)
        config, target, descriptor, old_request, retired, size, authority = _receipt_binding(root_path, request); cleanup = _cleanup(descriptor, retired)["cleanupReceiptSha256"]
        directory, lock = lease._locked(root_path)
        try:
            if lease._active(directory) is not None: return dict(_UNKNOWN)
            closed = lease._closed(directory, _OLD); expected = base._campaign_identity({**old_request, "correlationId": _OLD}, descriptor)
            if not isinstance(closed, Mapping) or closed.get("identity") != expected or closed.get("lastEvidenceSha256") != cleanup: return dict(_UNKNOWN)
        finally: os.close(lock)
        remote = base._campaign_remote(config, target)
        if (not _remote_marker_clean(config, target, authority["bundleSha256"], size, authority)
                or not lease._remote_confirm(remote, "status", closed, None)
                or not _remote_new_absent(config, target, closed, request["newLeaseId"]) or not _idle(root_path)): return dict(_UNKNOWN)
        journal = _journal(root_path, False)
        if journal is None: return dict(_UNKNOWN)
        marker = journal / (request["newLeaseId"] + ".begin.json"); marker_value = {"version": 1, "newLeaseId": request["newLeaseId"], "oldCleanupReceiptSha256": cleanup}
        lock = os.open(journal / ".environment.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if marker.exists():
                if _read(marker) != marker_value: return dict(_UNKNOWN)
            else: _write_once(marker, marker_value)
            opened = lease.begin(root_path, base._campaign_identity({**old_request, "correlationId": request["newLeaseId"]}, descriptor), remote)
        finally: os.close(lock)
        return {"state": "active", "leaseId": request["newLeaseId"], "replayAllowed": False, "nativeActionAllowed": False} if opened.get("state") == "active" else dict(_UNKNOWN)
    except (OSError, ValueError, TypeError, KeyError, WindowsCp117GuestAbortSuccessorError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError): return dict(_UNKNOWN)


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Persist exact abort proof, CAS-close the old campaign, and reserve a new lease."""
    try:
        root_path = Path(root).resolve(strict=True); request = _request(value)
        config, target, descriptor, old_request, receipt, receipt_sha, old_active, bundle_size, authority = _admission(root_path, request)
        journal = _journal(root_path, True); assert journal is not None
        lock = os.open(journal / ".environment.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX); cleanup = _cleanup(descriptor, receipt_sha)
            _write_once(journal / (request["newLeaseId"] + ".json"), {"version": 1, "request": request, "oldLeaseId": _OLD, "abortReceipt": receipt, "abortReceiptSha256": receipt_sha, "cleanupReceiptSha256": cleanup["cleanupReceiptSha256"], "guestGeneration": cleanup["guestGeneration"], "bundleSize": bundle_size, "authorityBinding": authority})
        finally: os.close(lock)
        remote = base._campaign_remote(config, target)
        if lease.close(root_path, _OLD, cleanup, remote, expected_current=old_active).get("state") != "closed": return dict(_UNKNOWN)
        opened = lease.begin(root_path, base._campaign_identity({**old_request, "correlationId": request["newLeaseId"]}, descriptor), remote)
        return {"state": "active", "leaseId": request["newLeaseId"], "replayAllowed": False, "nativeActionAllowed": False} if opened.get("state") == "active" else dict(_UNKNOWN)
    except (OSError, ValueError, TypeError, KeyError, WindowsCp117GuestAbortSuccessorError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError, http.WindowsUpdateFixtureHttpStageError): return dict(_UNKNOWN)


def workflow(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if action == "start": return start(root, inputs)
    if action == "status": return status(root, inputs)
    if action == "reconcile": return reconcile(root, inputs)
    if action == "resume-begin": return resume_begin(root, inputs)
    raise WindowsCp117GuestAbortSuccessorError("Unknown guest abort successor action.")
