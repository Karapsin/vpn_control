"""Reserve one new CP117 campaign after the fixed lost-download abort.

The lost submission identified by ``windows_update_fixture_download_abort``
is terminal.  This adapter consumes that exact terminal record once: it closes
the old idle campaign with compare-and-swap, then reserves a distinct idle
campaign.  It never recreates the download, serves bytes, or runs an MSI.
"""
from __future__ import annotations

import base64
import fcntl
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
from . import windows_update_fixture_download_abort as abort
from . import windows_update_fixture_http_stage as http


class WindowsCp117DownloadAbortSuccessorError(ValueError):
    pass


_DIR = ".rag_index/windows-cp117-download-abort-successor"
_OLD, _CORRELATION, _SOURCE = abort._LEASE, abort._CORRELATION, abort._SOURCE
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
    required = {"host", "oldLeaseId", "newLeaseId", "sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"}
    if not isinstance(value, Mapping) or set(value) != required or value.get("host") != "archlinux":
        raise WindowsCp117DownloadAbortSuccessorError("Download abort successor requires exact CP117 inputs.")
    if value.get("oldLeaseId") != _OLD or value.get("sourceSha") != _SOURCE:
        raise WindowsCp117DownloadAbortSuccessorError("Download abort successor is bound to one retired campaign.")
    new = value.get("newLeaseId")
    if not isinstance(new, str) or not _UUID.fullmatch(new) or str(uuid.UUID(new)) != new or new == _OLD:
        raise WindowsCp117DownloadAbortSuccessorError("Download abort successor requires a distinct canonical lease.")
    for field in ("fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"):
        if not isinstance(value.get(field), str) or not _ARTIFACT.fullmatch(value[field]):
            raise WindowsCp117DownloadAbortSuccessorError("Download abort successor artifact is invalid.")
    return dict(value)


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(dict(value), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _journal(root: Path, create: bool) -> Path | None:
    path = root / _DIR
    if create: path.mkdir(parents=True, mode=0o700, exist_ok=True)
    try: info = path.lstat()
    except OSError: return None
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise WindowsCp117DownloadAbortSuccessorError("Download abort successor journal is unsafe.")
    return path


def _read(path: Path) -> dict[str, Any] | None:
    try: fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError: return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 12288:
            raise WindowsCp117DownloadAbortSuccessorError("Download abort successor receipt is unsafe.")
        try: value = json.load(stream)
        except (TypeError, ValueError) as error: raise WindowsCp117DownloadAbortSuccessorError("Download abort successor receipt is invalid.") from error
    return value if isinstance(value, dict) else None


def _write_once(path: Path, value: Mapping[str, Any]) -> None:
    raw = (json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try: os.fsync(parent)
    finally: os.close(parent)


def _idle(root: Path) -> bool:
    ready = base.readiness(root, {"host": "archlinux", "expectedCurrentVersion": "2.1.19"})
    if not (ready.get("state") == "ready" and ready.get("ready") is True and ready.get("code") == "READY" and ready.get("productCount") == 1 and ready.get("activeCount") == 0 and ready.get("activeProcesses") == [] and ready.get("ownedExplorerCount") == 1): return False
    owner = owner_liveness.observe(root, {"host": "archlinux"})
    return (owner.get("state") in {"absent", "blocked"} and owner.get("ownerProcesses") == "none" and owner.get("installerProcesses") == "none" and owner.get("consentProcesses") == "none" and owner.get("runtimeProcesses") == "none" and owner.get("runtimeOff") is True and owner.get("stateLeaves") in {"none", "one"})


def _cleanup(descriptor: tuple[Any, ...], receipt_sha: str) -> dict[str, Any]:
    return {"guestGeneration": {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}, "serverStopped": True, "credentialsCleaned": True, "protectedJobsTerminalCleaned": True, "activeInstallerProcessesAbsent": True, "cleanupReceiptSha256": hashlib.sha256((receipt_sha + ":download-abort-successor-close").encode()).hexdigest()}


def _inspect(root: Path, lease_id: str) -> dict[str, Any]:
    directory = root / lease._DIR; info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700: raise WindowsCp117DownloadAbortSuccessorError("CP117 campaign journal is unsafe.")
    active = lease._active(directory)
    if active is not None and active["identity"]["leaseId"] == lease_id: return {"state": active["state"], "record": active}
    closed = lease._closed(directory, lease_id)
    return {"state": "closed" if closed is not None else "unknown", "record": closed}


def _initial_idle(observed: Mapping[str, Any], identity: Mapping[str, Any]) -> bool:
    record = observed.get("record")
    return (observed.get("state") == "active" and isinstance(record, Mapping) and record.get("identity") == identity and record.get("role") is None and record.get("correlationId") is None and record.get("server") == "stopped" and record.get("credentials") == "absent" and record.get("sequence") == 0 and record.get("lastEvidenceSha256") is None and record.get("lastOutcome") is None)


def _receipt_binding(root: Path, request: Mapping[str, str]) -> tuple[Any, Any, tuple[Any, ...], Mapping[str, Any], str, int, Mapping[str, Any]]:
    journal = _journal(root, False)
    if journal is None: raise WindowsCp117DownloadAbortSuccessorError("Download abort successor intent is unavailable.")
    stored = _read(journal / (request["newLeaseId"] + ".json")); descriptor = base._descriptor(root)[2]
    fields = {"version", "request", "oldLeaseId", "abortReceipt", "abortReceiptSha256", "cleanupReceiptSha256", "guestGeneration", "bundleSize", "authorityBinding"}
    if stored is None or set(stored) != fields or stored.get("version") != 1 or _request(stored.get("request", {})) != request or stored.get("oldLeaseId") != _OLD or stored.get("guestGeneration") != {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}: raise WindowsCp117DownloadAbortSuccessorError("Download abort successor intent changed.")
    receipt, receipt_sha = stored.get("abortReceipt"), stored.get("abortReceiptSha256")
    if not isinstance(receipt, Mapping) or not isinstance(receipt_sha, str) or not _SHA.fullmatch(receipt_sha) or _digest(receipt) != receipt_sha: raise WindowsCp117DownloadAbortSuccessorError("Download abort receipt changed.")
    expected_receipt = {"correlationId": _CORRELATION, "leaseId": _OLD, "sourceSha": _SOURCE, "bundleSha256": receipt.get("bundleSha256"), "sourceFingerprint": receipt.get("sourceFingerprint"), "guestGeneration": stored["guestGeneration"], "listener": "stopped-unserved", "guestLeaf": "retained-empty-created", "task": "absent", "runtimeAndInstaller": "absent"}
    size, authority = stored.get("bundleSize"), stored.get("authorityBinding")
    expected_authority = {"correlationId": _CORRELATION, "socketPath": descriptor[1], "pid": descriptor[2], "startTicks": descriptor[3], "leaseId": _OLD, "sourceSha": _SOURCE, "sourceFingerprint": receipt.get("sourceFingerprint"), "bundleSha256": receipt.get("bundleSha256"), "expectedSid": descriptor[4], "fixtureReceiptArtifactId": request["fixtureReceiptArtifactId"], "baseMsiArtifactId": request["baseMsiArtifactId"], "targetMsiArtifactId": request["targetMsiArtifactId"]}
    if dict(receipt) != expected_receipt or stored.get("cleanupReceiptSha256") != _cleanup(descriptor, receipt_sha)["cleanupReceiptSha256"] or type(size) is not int or not 0 < size <= 1075838976 or authority != expected_authority: raise WindowsCp117DownloadAbortSuccessorError("Download abort successor proof changed.")
    config, target, _ = base._descriptor(root)
    old_request = {"correlationId": _CORRELATION, "sourceSha": _SOURCE, "fixtureReceiptArtifactId": request["fixtureReceiptArtifactId"], "baseMsiArtifactId": request["baseMsiArtifactId"], "targetMsiArtifactId": request["targetMsiArtifactId"]}
    return config, target, descriptor, old_request, receipt_sha, size, authority


def _remote_marker_clean(config: Any, target: Any, bundle_sha: str, bundle_size: int, authority: Mapping[str, Any]) -> bool:
    try:
        encoded = base64.b64encode(json.dumps(dict(authority), sort_keys=True, separators=(",", ":")).encode()).decode("ascii")
        raw = base._remote(config, abort._REMOTE_ABORT, (str(target.fixture_transfer_root), _CORRELATION, bundle_sha, str(bundle_size), encoded, "status"), None, 30)
        return (json.loads(raw) if raw is not None else None) == {"state": "cleaned"}
    except (OSError, ValueError, TypeError, base.WindowsMsiBasePrepareError): return False


def _remote_new_absent(config: Any, target: Any, old_closed: Mapping[str, Any], new_lease: str) -> bool:
    try:
        raw = base._remote(config, _REMOTE_NEW_ABSENT, (str(target.fixture_transfer_root), "windows-cp117", _OLD, new_lease, _digest(old_closed)), None, 30)
        return json.loads(raw) == {"version": 1, "state": "absent"} if raw is not None else False
    except (OSError, ValueError, TypeError, base.WindowsMsiBasePrepareError): return False


def _retained_empty_guest(root: Path, descriptor: tuple[Any, ...]) -> bool:
    """Re-observe the preserved guest evidence without repairing anything."""
    try:
        root_path, _record, config, _target, observed = abort._retired_binding(root)
        return root_path == root and observed == descriptor and abort._guest(config, descriptor) == "empty"
    except (OSError, ValueError, TypeError, abort.WindowsUpdateFixtureDownloadAbortError, base.WindowsMsiBasePrepareError):
        return False


def _admission(root: Path, request: Mapping[str, str]) -> tuple[Any, Any, tuple[Any, ...], Mapping[str, Any], Mapping[str, Any], str, Mapping[str, Any], int, Mapping[str, Any]]:
    state, details = abort._admission(root)
    if state != "retired" or details is None: raise WindowsCp117DownloadAbortSuccessorError("Download abort is incomplete or unknown.")
    root_path, record, config, target, descriptor, receipt, receipt_sha = details
    if record.get("leaseId") != _OLD or record.get("request", {}).get("correlationId") != _CORRELATION or any(record["request"].get(k) != request[k] for k in ("sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId")): raise WindowsCp117DownloadAbortSuccessorError("Download abort successor artifact binding changed.")
    if not isinstance(receipt_sha, str) or not _SHA.fullmatch(receipt_sha) or not _idle(root_path): raise WindowsCp117DownloadAbortSuccessorError("Download abort successor guest is not freshly idle.")
    identity = base._campaign_identity({**record["request"], "correlationId": _OLD}, descriptor)
    directory, lock = lease._locked(root_path)
    try:
        active = lease._active(directory)
        if active is None or active.get("identity") != identity or active.get("state") != "active" or active.get("role") is not None or active.get("correlationId") is not None or active.get("server") != "stopped" or active.get("credentials") != "absent" or active.get("lastOutcome") != "failed-cleaned" or active.get("lastEvidenceSha256") != receipt_sha: raise WindowsCp117DownloadAbortSuccessorError("Download abort campaign is not the retired idle record.")
    finally: os.close(lock)
    authority = http._authority_binding(record, descriptor)
    if not _remote_marker_clean(config, target, record["bundleSha256"], record["bundleSize"], authority) or not lease._remote_confirm(base._campaign_remote(config, target), "status", active, None): raise WindowsCp117DownloadAbortSuccessorError("Download abort remote cleanup is not confirmed.")
    return config, target, descriptor, record["request"], receipt, receipt_sha, active, record["bundleSize"], authority


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        root_path = Path(root).resolve(strict=True); request = _request(value); config, target, descriptor, old_request, retired, size, authority = _receipt_binding(root_path, request)
        old, new = _inspect(root_path, _OLD), _inspect(root_path, request["newLeaseId"]); expected_old = base._campaign_identity({**old_request, "correlationId": _OLD}, descriptor); expected_new = base._campaign_identity({**old_request, "correlationId": request["newLeaseId"]}, descriptor); old_record = old.get("record"); cleanup = _cleanup(descriptor, retired)["cleanupReceiptSha256"]
        old_ok = isinstance(old_record, Mapping) and old_record.get("identity") == expected_old and old_record.get("role") is None and old_record.get("correlationId") is None and old_record.get("server") == "stopped" and old_record.get("credentials") == "absent" and old_record.get("lastOutcome") == "failed-cleaned" and ((old.get("state") == "active" and old_record.get("lastEvidenceSha256") == retired) or (old.get("state") in {"pending-close", "closed"} and old_record.get("lastEvidenceSha256") == cleanup))
        if not old_ok or not _retained_empty_guest(root_path, descriptor) or not _remote_marker_clean(config, target, authority["bundleSha256"], size, authority): return dict(_UNKNOWN)
        # A response can be lost after `close` made its durable local
        # pending-close record.  Its remote status is intentionally checked by
        # reconcile (which may finalize the local close); treating it as a
        # normal active record here would compare the wrong remote state.
        if old.get("state") == "pending-close":
            return {"state": "closing", "leaseId": request["newLeaseId"], "nextAction": "inspect-close-progress", **{k:v for k,v in _UNKNOWN.items() if k != "state"}}
        if old.get("state") == "closed":
            if not campaign_status._remote_closed_proof(config, target, old_record, expected_new): return dict(_UNKNOWN)
            return {"state": "active", "leaseId": request["newLeaseId"], "replayAllowed": False, "nativeActionAllowed": False} if _initial_idle(new, expected_new) else {"state": "opening", "leaseId": request["newLeaseId"], "nextAction": "inspect-open-progress", **{k:v for k,v in _UNKNOWN.items() if k != "state"}}
        if not lease._remote_confirm(base._campaign_remote(config, target), "status", old_record, None): return dict(_UNKNOWN)
        # The immutable successor intent exists but the close has not begun.
        # `reconcile` intentionally cannot create that transition, so direct
        # callers to the only bounded CAS close recovery.
        return {"state": "closing", "leaseId": request["newLeaseId"], "nextAction": "resume-close", **{k:v for k,v in _UNKNOWN.items() if k != "state"}}
    except (OSError, ValueError, TypeError, KeyError, WindowsCp117DownloadAbortSuccessorError, lease.Cp117LeaseError): return dict(_UNKNOWN)


def reconcile(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read back partial close/open only; it never resubmits either mutation."""
    try:
        root_path = Path(root).resolve(strict=True); request = _request(value); config, target, descriptor, old_request, retired, size, authority = _receipt_binding(root_path, request)
        if not _idle(root_path) or not _retained_empty_guest(root_path, descriptor) or not _remote_marker_clean(config, target, authority["bundleSha256"], size, authority): return dict(_UNKNOWN)
        remote = base._campaign_remote(config, target); old = lease.inspect(root_path, _OLD); expected_old = base._campaign_identity({**old_request, "correlationId": _OLD}, descriptor); expected_new = base._campaign_identity({**old_request, "correlationId": request["newLeaseId"]}, descriptor)
        if old.get("state") == "pending-close": old = lease.reconcile(root_path, _OLD, remote)
        if old.get("state") != "closed": return dict(_UNKNOWN)
        closed = _inspect(root_path, _OLD).get("record")
        if not isinstance(closed, Mapping) or closed.get("identity") != expected_old or closed.get("lastEvidenceSha256") != _cleanup(descriptor, retired)["cleanupReceiptSha256"] or not campaign_status._remote_closed_proof(config, target, closed, expected_new): return dict(_UNKNOWN)
        new = lease.inspect(root_path, request["newLeaseId"])
        if new.get("state") == "pending-remote": new = lease.reconcile(root_path, request["newLeaseId"], remote)
        return {"state": "active", "leaseId": request["newLeaseId"], "replayAllowed": False, "nativeActionAllowed": False} if new.get("state") == "active" and _initial_idle(_inspect(root_path, request["newLeaseId"]), expected_new) else dict(_UNKNOWN)
    except (OSError, ValueError, TypeError, KeyError, WindowsCp117DownloadAbortSuccessorError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError): return dict(_UNKNOWN)


def resume_close(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Finish only the close that was durably intended before a lost reply.

    This is deliberately separate from ``resume_begin``.  A pending close is
    reconciled, never sent again, and a new lease is never opened in this
    action.
    """
    try:
        root_path = Path(root).resolve(strict=True); request = _request(value)
        _config, _target, descriptor, _old_request, stored_sha, stored_size, stored_authority = _receipt_binding(root_path, request)
        config, target, observed_descriptor, _request_record, receipt, receipt_sha, active, bundle_size, authority = _admission(root_path, request)
        if (observed_descriptor != descriptor or receipt_sha != stored_sha or bundle_size != stored_size
                or authority != stored_authority or _digest(receipt) != stored_sha):
            return dict(_UNKNOWN)
        cleanup = _cleanup(descriptor, stored_sha)
        remote = base._campaign_remote(config, target)
        closed = lease.close(root_path, _OLD, cleanup, remote, expected_current=active)
        return {"state": "closed", "leaseId": request["newLeaseId"], "replayAllowed": False, "nativeActionAllowed": False} if closed.get("state") == "closed" else dict(_UNKNOWN)
    except (OSError, ValueError, TypeError, KeyError, WindowsCp117DownloadAbortSuccessorError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError, http.WindowsUpdateFixtureHttpStageError):
        return dict(_UNKNOWN)


def resume_begin(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        root_path = Path(root).resolve(strict=True); request = _request(value); config, target, descriptor, old_request, retired, size, authority = _receipt_binding(root_path, request); cleanup = _cleanup(descriptor, retired)["cleanupReceiptSha256"]
        directory, lock = lease._locked(root_path)
        try:
            if lease._active(directory) is not None: return dict(_UNKNOWN)
            closed = lease._closed(directory, _OLD); expected = base._campaign_identity({**old_request, "correlationId": _OLD}, descriptor)
            if not isinstance(closed, Mapping) or closed.get("identity") != expected or closed.get("lastEvidenceSha256") != cleanup: return dict(_UNKNOWN)
        finally: os.close(lock)
        remote = base._campaign_remote(config, target)
        if not _retained_empty_guest(root_path, descriptor) or not _remote_marker_clean(config, target, authority["bundleSha256"], size, authority) or not lease._remote_confirm(remote, "status", closed, None) or not _remote_new_absent(config, target, closed, request["newLeaseId"]) or not _idle(root_path): return dict(_UNKNOWN)
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
    except (OSError, ValueError, TypeError, KeyError, WindowsCp117DownloadAbortSuccessorError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError): return dict(_UNKNOWN)


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        root_path = Path(root).resolve(strict=True); request = _request(value); config, target, descriptor, old_request, receipt, receipt_sha, old_active, bundle_size, authority = _admission(root_path, request)
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
    except (OSError, ValueError, TypeError, KeyError, WindowsCp117DownloadAbortSuccessorError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError, http.WindowsUpdateFixtureHttpStageError): return dict(_UNKNOWN)


def workflow(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if action == "start": return start(root, inputs)
    if action == "status": return status(root, inputs)
    if action == "reconcile": return reconcile(root, inputs)
    if action == "resume-close": return resume_close(root, inputs)
    if action == "resume-begin": return resume_begin(root, inputs)
    raise WindowsCp117DownloadAbortSuccessorError("Unknown download abort successor action.")
