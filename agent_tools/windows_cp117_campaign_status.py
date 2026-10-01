"""Read-only, bounded status for the current CP117 campaign.

This module deliberately makes no lease transition and provides no replay or
native-action permit.  It ties the local record to the current base intent,
the staged artifact pair, current QEMU generation, and the matching remote
journal before reporting a usable campaign state.
"""
from __future__ import annotations

import os
import json
import base64
import hashlib
from pathlib import Path
import stat
from typing import Any, Mapping

from . import windows_cp117_lease as lease
from . import windows_msi_base_prepare as base
from . import windows_cp117_campaign_rebase as rebase


class WindowsCp117CampaignStatusError(ValueError):
    pass


_UNKNOWN = {"state": "unknown", "nextAction": "inspect-prerequisites",
            "replayAllowed": False, "nativeActionAllowed": False}
_MISSING = {"state": "unknown", "nextAction": "missing-prerequisite",
            "replayAllowed": False, "nativeActionAllowed": False}
_ACTIVE_STATES = {"active", "role-active", "pending-remote", "pending-role", "pending-finish"}
_PHASES = {"local-active", "rebase-receipt", "old-history", "prior-closed",
           "prior-closed-remote", "guest-abort-receipt", "guest-abort-marker-binding",
           "guest-abort-receipt-local", "guest-abort-marker-remote",
           "guest-abort-old-close", "guest-abort-old-close-remote", "guest-abort-pair",
           "current-remote", "idle", "projection"}


_REMOTE_CLOSED_PROOF = base._QGA + r'''import fcntl
root,env,encoded=sys.argv[1:]
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def record(path):
 info=os.lstat(path)
 if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>16384:raise ValueError()
 with open(path,encoding='utf-8') as stream:return json.load(stream)
try:
 payload=json.loads(base64.b64decode(encoded,validate=True)); closed=payload['closed']; current=payload['currentIdentity']
 if set(payload)!={'closed','currentIdentity'} or not isinstance(closed,dict) or not isinstance(current,dict):raise ValueError()
 old=closed['identity']
 if old['host']!='archlinux' or old['environment']!=env or old['leaseId']==current['leaseId'] or not live(old['socketPath'],str(old['qemuPid']),str(old['startTicks'])) or not live(current['socketPath'],str(current['qemuPid']),str(current['startTicks'])):raise ValueError()
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-cp117-campaign')
 for path in (root,parent,group):
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 lock=os.open(os.path.join(group,'.environment.lock'),os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 try:
  info=os.fstat(lock)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError()
  fcntl.flock(lock,fcntl.LOCK_SH)
  remote_closed=record(os.path.join(group,old['leaseId']+'.closed.json')); remote_active=record(os.path.join(group,'active.json'))
  if digest(remote_closed)!=digest(closed) or remote_active.get('identity')!=current:raise ValueError()
 finally:os.close(lock)
 print(json.dumps({'version':1,'state':'confirmed','closedSha256':digest(closed)},sort_keys=True,separators=(',',':')))
except Exception:print('{"version":1,"state":"unknown"}')
'''


def _remote_closed_proof(config: Any, target: Any, closed: Mapping[str, Any],
                         current_identity: Mapping[str, Any]) -> bool:
    """Read one predecessor close while a distinct current lease is active."""
    try:
        encoded = base64.b64encode(json.dumps({"closed": closed, "currentIdentity": current_identity},
                                              sort_keys=True, separators=(",", ":")).encode()).decode()
        raw = base._remote(config, _REMOTE_CLOSED_PROOF,
                           (str(target.fixture_transfer_root), "windows-cp117", encoded), None, 30)
        expected = {"version": 1, "state": "confirmed",
                    "closedSha256": hashlib.sha256(json.dumps(closed, sort_keys=True,
                                                                separators=(",", ":")).encode()).hexdigest()}
        return json.loads(raw) == expected if raw is not None else False
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError):
        return False


def _result(state: str, next_action: str, record: Mapping[str, Any]) -> dict[str, Any]:
    identity = record["identity"]
    return {"state": state, "nextAction": next_action, "leaseId": identity["leaseId"],
            "sourceSha": identity["sourceSha"], "fixtureReceiptArtifactId": identity["fixtureReceiptArtifactId"],
            "baseMsiArtifactId": identity["baseMsiArtifactId"],
            "targetMsiArtifactId": identity["targetMsiArtifactId"],
            "guestGeneration": {"socketPath": identity["socketPath"], "qemuPid": identity["qemuPid"],
                                "startTicks": identity["startTicks"]},
            "role": record["role"], "replayAllowed": False, "nativeActionAllowed": False}


def _directory(root: Path) -> Path | None:
    directory = root / lease._DIR
    try:
        info = directory.lstat()
    except OSError:
        return None
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        return None
    return directory


def _base_binding(root: Path, record: Mapping[str, Any], descriptor: tuple[Any, ...]) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
    """Bind a lease to the one immutable base request and registered pair."""
    identity = record["identity"]
    intent = base._private_intent(root, identity["leaseId"])
    if intent is None:
        return None
    try:
        request = base._request(intent["request"])
        pair, _ = base._stage_artifact_readonly(root, intent)
        expected = base._campaign_identity({**request, "correlationId": identity["leaseId"]}, descriptor)
    except (OSError, ValueError, KeyError, TypeError, base.WindowsMsiBasePrepareError):
        return None
    if (identity != expected or pair.get("sourceSha") != identity["sourceSha"]
            or request.get("fixtureReceiptArtifactId") != identity["fixtureReceiptArtifactId"]
            or request.get("baseMsiArtifactId") != identity["baseMsiArtifactId"]
            or request.get("targetMsiArtifactId") != identity["targetMsiArtifactId"]):
        return None
    return intent, pair


def _read_rebase(path: Path) -> Mapping[str, Any] | None:
    """Read one rebase receipt without creating its journal or lock."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    except OSError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 8192):
            return None
        try:
            value = json.load(stream)
        except (TypeError, ValueError):
            return None
    return value if isinstance(value, dict) else None


def _rebase_binding(root: Path, record: Mapping[str, Any], descriptor: tuple[Any, ...],
                    config: Any, target: Any) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
    """Validate an active continuation against its closed predecessor and rebase receipt."""
    identity = record["identity"]
    directory = root / rebase._DIR
    try:
        info = directory.lstat()
    except OSError:
        return None
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        return None
    receipt = _read_rebase(directory / (identity["leaseId"] + ".json"))
    if receipt is None:
        return None
    required = {"version", "request", "previousStageCorrelationId", "previousLeaseId",
                "baseTerminalReceiptSha256", "guestGeneration", "sourceFingerprint"}
    if set(receipt) != required or receipt.get("version") != 1:
        return None
    try:
        request = rebase._request(receipt["request"])
        old_intent, pair, terminal, cleanup = rebase._history(root, request, descriptor)
    except (OSError, ValueError, TypeError, KeyError, rebase.WindowsCp117CampaignRebaseError,
            rebase.lease.Cp117LeaseError, rebase.base.WindowsMsiBasePrepareError,
            rebase.transfer.WindowsMsiHttpTransferError, rebase.stage.WindowsUpdateFixtureStageError,
            rebase.recovery.WindowsUpdateFixtureStageRecoveryError):
        return None
    if (request["leaseId"] != identity["leaseId"] or receipt["previousLeaseId"] != request["previousLeaseId"]
            or receipt["previousStageCorrelationId"] != rebase.recovery._CORRELATION
            or receipt["baseTerminalReceiptSha256"] != terminal
            or receipt["guestGeneration"] != {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}
            or receipt["sourceFingerprint"] != pair.get("sourceFingerprint")):
        return None
    expected = base._campaign_identity({**request, "correlationId": request["leaseId"]}, descriptor)
    if identity != expected:
        return None
    try:
        campaign_dir = root / lease._DIR
        previous = lease._closed(campaign_dir, request["previousLeaseId"])
        old_expected = base._campaign_identity({**request, "correlationId": request["previousLeaseId"]}, descriptor)
        old_ok = (previous is not None and previous.get("identity") == old_expected
                  and previous.get("lastOutcome") == "failed-cleaned" and previous.get("server") == "stopped"
                  and previous.get("credentials") == "absent" and previous.get("lastEvidenceSha256") == cleanup
                  and _remote_closed_proof(config, target, previous, identity))
    except (OSError, ValueError, TypeError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
        old_ok = False
    if not old_ok:
        return None
    return old_intent, pair


def _binding(root: Path, record: Mapping[str, Any], descriptor: tuple[Any, ...],
             config: Any, target: Any) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
    return (_base_binding(root, record, descriptor)
            or _rebase_binding(root, record, descriptor, config, target)
            or _e66_successor_binding(root, record, descriptor, config, target)
            or _guest_abort_successor_binding(root, record, descriptor, config, target)
            or _download_abort_successor_binding(root, record, descriptor, config, target)
            or _current_download_abort_successor_binding(root, record, descriptor, config, target))


def _e66_successor_binding(root: Path, record: Mapping[str, Any], descriptor: tuple[Any, ...],
                           config: Any, target: Any) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
    """Bind the distinct post-e66 lease without treating its old stage as replayable."""
    try:
        # This import is local: the successor's reconciliation uses the read-only
        # remote closed-proof helper in this module.
        from . import windows_cp117_e66_successor as successor
        identity = record["identity"]
        journal = successor._journal(root, False)
        if journal is None:
            return None
        stored = successor._read(journal / (identity["leaseId"] + ".json"))
        if stored is None:
            return None
        request = successor._request(stored["request"])
        if request["newLeaseId"] != identity["leaseId"]:
            return None
        _config, _target, current_descriptor, old_request, retired = successor._receipt_binding(root, request)
        if current_descriptor != descriptor or identity != base._campaign_identity(
                {**old_request, "correlationId": request["newLeaseId"]}, descriptor):
            return None
        old = lease._closed(root / lease._DIR, successor._OLD)
        if (old is None or old.get("identity") != base._campaign_identity(
                    {**old_request, "correlationId": successor._OLD}, descriptor)
                or old.get("lastOutcome") != "failed-cleaned"
                or old.get("lastEvidenceSha256") != successor._cleanup(descriptor, retired)["cleanupReceiptSha256"]
                or old.get("credentials") != "absent"
                or not _remote_closed_proof(config, target, old, identity)):
            return None
        pair = rebase.public._admit_pair(root, request["sourceSha"], request["fixtureReceiptArtifactId"],
                                          request["baseMsiArtifactId"], request["targetMsiArtifactId"])
        if stored["retirementReceipt"].get("sourceFingerprint") != pair.get("sourceFingerprint"):
            return None
        return stored, pair
    except (OSError, ValueError, TypeError, KeyError, lease.Cp117LeaseError,
            base.WindowsMsiBasePrepareError):
        return None


def _guest_abort_successor_binding(root: Path, record: Mapping[str, Any], descriptor: tuple[Any, ...],
                                  config: Any, target: Any) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
    """Bind a new lease only to the exact, remotely closed guest-abort campaign."""
    detail = _guest_abort_successor_diagnostic_binding(root, record, descriptor, config, target)
    return None if isinstance(detail, str) else detail


def _download_abort_successor_binding(root: Path, record: Mapping[str, Any], descriptor: tuple[Any, ...],
                                     config: Any, target: Any) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
    """Bind the download-abort successor to its retained empty-guest proof."""
    try:
        from . import windows_cp117_download_abort_successor as successor
        identity = record["identity"]
        journal = successor._journal(root, False)
        if journal is None:
            return None
        stored = successor._read(journal / (identity["leaseId"] + ".json"))
        if stored is None:
            return None
        request = successor._request(stored["request"])
        if request["newLeaseId"] != identity["leaseId"]:
            return None
        marker_config, marker_target, current_descriptor, old_request, retired, bundle_size, authority = successor._receipt_binding(root, request)
        if current_descriptor != descriptor or identity != base._campaign_identity(
                {**old_request, "correlationId": request["newLeaseId"]}, descriptor):
            return None
        marker_root, marker_record, retained_config, _retained_target, marker_descriptor = successor.abort._retired_binding(root)
        if (marker_root != root or marker_descriptor != descriptor
                or marker_record.get("request") != {**old_request, "host": "archlinux"}
                or not successor.abort._receipt(marker_root, stored["abortReceipt"], create=False)
                or successor.abort._guest(retained_config, marker_descriptor) != "empty"
                or not successor._remote_marker_clean(marker_config, marker_target, authority["bundleSha256"], bundle_size, authority)):
            return None
        old = lease._closed(root / lease._DIR, successor._OLD)
        if (old is None or old.get("identity") != base._campaign_identity(
                    {**old_request, "correlationId": successor._OLD}, descriptor)
                or old.get("role") is not None or old.get("correlationId") is not None
                or old.get("lastOutcome") != "failed-cleaned"
                or old.get("lastEvidenceSha256") != successor._cleanup(descriptor, retired)["cleanupReceiptSha256"]
                or old.get("server") != "stopped" or old.get("credentials") != "absent"
                or not _remote_closed_proof(config, target, old, identity)):
            return None
        pair = rebase.public._admit_pair(root, request["sourceSha"], request["fixtureReceiptArtifactId"],
                                          request["baseMsiArtifactId"], request["targetMsiArtifactId"])
        if stored["abortReceipt"].get("sourceFingerprint") != pair.get("sourceFingerprint"):
            return None
        return stored, pair
    except (OSError, ValueError, TypeError, KeyError, lease.Cp117LeaseError,
            base.WindowsMsiBasePrepareError):
        return None


def _current_download_abort_successor_binding(root: Path, record: Mapping[str, Any], descriptor: tuple[Any, ...],
                                             config: Any, target: Any) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
    """Bind the current successor through its isolated immutable receipt.

    The current recovery deliberately has a private implementation module so
    that its fixed retired campaign cannot alter historical recovery globals.
    Status must read that same isolated receipt and prove the old close; merely
    accepting a matching active lease would allow an unbound new campaign.
    """
    try:
        from . import windows_cp117_download_abort_current_successor as successor
        impl = successor._impl
        identity = record["identity"]
        journal = impl._journal(root, False)
        if journal is None:
            return None
        stored = impl._read(journal / (identity["leaseId"] + ".json"))
        if stored is None:
            return None
        request = successor._request(stored["request"])
        if request["newLeaseId"] != identity["leaseId"]:
            return None
        marker_config, marker_target, current_descriptor, old_request, retired, bundle_size, authority = impl._receipt_binding(root, request)
        if current_descriptor != descriptor or identity != base._campaign_identity(
                {**old_request, "correlationId": request["newLeaseId"]}, descriptor):
            return None
        marker_root, marker_record, retained_config, _retained_target, marker_descriptor = impl.abort._retired_binding(root)
        if (marker_root != root or marker_descriptor != descriptor
                or marker_record.get("request") != {**old_request, "host": "archlinux"}
                or not impl.abort._receipt(marker_root, stored["abortReceipt"], create=False)
                or impl.abort._guest(retained_config, marker_descriptor) != "empty"
                or not impl._remote_marker_clean(marker_config, marker_target, authority["bundleSha256"], bundle_size, authority)):
            return None
        old = lease._closed(root / lease._DIR, successor._OLD)
        if (old is None or old.get("identity") != base._campaign_identity(
                    {**old_request, "correlationId": successor._OLD}, descriptor)
                or old.get("role") is not None or old.get("correlationId") is not None
                or old.get("lastOutcome") != "failed-cleaned"
                or old.get("lastEvidenceSha256") != impl._cleanup(descriptor, retired)["cleanupReceiptSha256"]
                or old.get("server") != "stopped" or old.get("credentials") != "absent"
                or not _remote_closed_proof(config, target, old, identity)):
            return None
        pair = rebase.public._admit_pair(root, request["sourceSha"], request["fixtureReceiptArtifactId"],
                                          request["baseMsiArtifactId"], request["targetMsiArtifactId"])
        if stored["abortReceipt"].get("sourceFingerprint") != pair.get("sourceFingerprint"):
            return None
        return stored, pair
    except (OSError, ValueError, TypeError, KeyError, lease.Cp117LeaseError,
            base.WindowsMsiBasePrepareError):
        return None


def _guest_abort_successor_diagnostic_binding(root: Path, record: Mapping[str, Any], descriptor: tuple[Any, ...],
                                             config: Any, target: Any) -> tuple[Mapping[str, Any], Mapping[str, Any]] | str:
    """Classify each fixed guest-abort successor proof without native effects."""
    try:
        # Keep this import local: the successor module depends on this module's
        # read-only remote close proof for its recovery and status paths.
        from . import windows_cp117_guest_abort_successor as successor
        identity = record["identity"]
        journal = successor._journal(root, False)
        if journal is None:
            return "guest-abort-receipt"
        stored = successor._read(journal / (identity["leaseId"] + ".json"))
        if stored is None:
            return "guest-abort-receipt"
        request = successor._request(stored["request"])
        if request["newLeaseId"] != identity["leaseId"]:
            return "guest-abort-receipt"
        _config, _target, current_descriptor, old_request, retired, bundle_size, authority = successor._receipt_binding(root, request)
        if current_descriptor != descriptor or identity != base._campaign_identity(
                {**old_request, "correlationId": request["newLeaseId"]}, descriptor):
            return "guest-abort-receipt"
        # The successor start admission proved the remote cleaned marker before
        # closing the old campaign.  Re-read that exact marker here because the
        # status route can be called long after the close and must not promote a
        # new lease from a durable local receipt alone.
        try:
            marker_root, marker_record, marker_config, marker_target, marker_descriptor = successor.abort._retired_local_binding(root)
            marker_receipt, marker_sha = successor.abort._receipt_value(marker_record, marker_descriptor)
        except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError):
            return "guest-abort-marker-binding"
        # The stage record is a normal HTTP-stage request and therefore carries
        # the fixed host field.  The successor's old-request projection omits
        # that transport constant because campaign identity supplies it.
        marker_request = {**old_request, "host": "archlinux"}
        if (marker_descriptor != descriptor or marker_record.get("request") != marker_request
                or marker_sha != retired):
            return "guest-abort-marker-binding"
        if not successor.abort._receipt(marker_root, marker_receipt, create=False):
            return "guest-abort-receipt-local"
        # The immutable successor receipt carries the exact authority bytes that
        # its start path used to query the remote marker. Recomputing authority
        # from a later local record can disagree even when the proven marker is
        # still clean.
        if not successor._remote_marker_clean(_config, _target, authority["bundleSha256"], bundle_size, authority):
            return "guest-abort-marker-remote"
        old = lease._closed(root / lease._DIR, successor._OLD)
        if (old is None or old.get("identity") != base._campaign_identity(
                    {**old_request, "correlationId": successor._OLD}, descriptor)
                or old.get("role") is not None or old.get("correlationId") is not None
                or old.get("lastOutcome") != "failed-cleaned"
                or old.get("lastEvidenceSha256") != successor._cleanup(descriptor, retired)["cleanupReceiptSha256"]
                or old.get("server") != "stopped" or old.get("credentials") != "absent"):
            return "guest-abort-old-close"
        if not _remote_closed_proof(config, target, old, identity):
            return "guest-abort-old-close-remote"
        try:
            pair = rebase.public._admit_pair(root, request["sourceSha"], request["fixtureReceiptArtifactId"],
                                              request["baseMsiArtifactId"], request["targetMsiArtifactId"])
        except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError):
            return "guest-abort-pair"
        receipt = stored.get("abortReceipt")
        if not isinstance(receipt, Mapping) or receipt.get("sourceFingerprint") != pair.get("sourceFingerprint"):
            return "guest-abort-pair"
        return stored, pair
    except (OSError, ValueError, TypeError, KeyError, lease.Cp117LeaseError,
            base.WindowsMsiBasePrepareError):
        return "guest-abort-receipt"


def _has_guest_abort_successor_receipt(root: Path, record: Mapping[str, Any]) -> bool:
    """Select the guest-abort diagnosis only when its lease receipt exists."""
    try:
        from . import windows_cp117_guest_abort_successor as successor
        journal = successor._journal(root, False)
        if journal is None:
            return False
        (journal / (record["identity"]["leaseId"] + ".json")).lstat()
        return True
    except (OSError, ValueError, TypeError, KeyError):
        return False


def _rebase_diagnostic_binding(root: Path, record: Mapping[str, Any], descriptor: tuple[Any, ...],
                               config: Any, target: Any) -> tuple[Mapping[str, Any], Mapping[str, Any]] | str:
    """Return a bounded failing rebase gate; never expose receipt contents."""
    identity = record["identity"]
    directory = root / rebase._DIR
    try:
        info = directory.lstat()
    except OSError:
        return "rebase-receipt"
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        return "rebase-receipt"
    receipt = _read_rebase(directory / (identity["leaseId"] + ".json"))
    required = {"version", "request", "previousStageCorrelationId", "previousLeaseId",
                "baseTerminalReceiptSha256", "guestGeneration", "sourceFingerprint"}
    if receipt is None or set(receipt) != required or receipt.get("version") != 1:
        return "rebase-receipt"
    try:
        request = rebase._request(receipt["request"])
        old_intent, pair, terminal, cleanup = rebase._history(root, request, descriptor)
    except (OSError, ValueError, TypeError, KeyError, rebase.WindowsCp117CampaignRebaseError,
            rebase.lease.Cp117LeaseError, rebase.base.WindowsMsiBasePrepareError,
            rebase.transfer.WindowsMsiHttpTransferError, rebase.stage.WindowsUpdateFixtureStageError,
            rebase.recovery.WindowsUpdateFixtureStageRecoveryError):
        return "old-history"
    if (request["leaseId"] != identity["leaseId"] or receipt["previousLeaseId"] != request["previousLeaseId"]
            or receipt["previousStageCorrelationId"] != rebase.recovery._CORRELATION
            or receipt["baseTerminalReceiptSha256"] != terminal
            or receipt["guestGeneration"] != {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}
            or receipt["sourceFingerprint"] != pair.get("sourceFingerprint")):
        return "rebase-receipt"
    if identity != base._campaign_identity({**request, "correlationId": request["leaseId"]}, descriptor):
        return "projection"
    try:
        previous = lease._closed(root / lease._DIR, request["previousLeaseId"])
        old_expected = base._campaign_identity({**request, "correlationId": request["previousLeaseId"]}, descriptor)
    except (OSError, ValueError, TypeError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
        return "prior-closed"
    if (previous is None or previous.get("identity") != old_expected or previous.get("lastOutcome") != "failed-cleaned"
            or previous.get("server") != "stopped" or previous.get("credentials") != "absent"
            or previous.get("lastEvidenceSha256") != cleanup):
        return "prior-closed"
    try:
        if not _remote_closed_proof(config, target, previous, identity):
            return "prior-closed-remote"
    except (OSError, ValueError, TypeError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
        return "prior-closed-remote"
    return old_intent, pair


def _idle_base(root: Path, pair: Mapping[str, Any]) -> bool:
    version = pair.get("baseVersion")
    if not isinstance(version, str):
        return False
    try:
        observed = base.readiness(root, {"host": "archlinux", "expectedCurrentVersion": version})
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError):
        return False
    return (observed.get("state") == "ready" and observed.get("ready") is True
            and observed.get("installedVersion") == version and observed.get("productCount") == 1
            and observed.get("activeCount") == 0 and observed.get("activeProcesses") == [])


def _bound_closed(root: Path, directory: Path, descriptor: tuple[Any, ...], config: Any,
                  target: Any) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
    """Find one unambiguous, locally valid historical record without mutation."""
    candidates: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    try:
        names = [item.name for item in directory.iterdir()]
    except OSError:
        return None
    for name in names:
        if not name.endswith(".closed.json"):
            continue
        lease_id = name.removesuffix(".closed.json")
        if not lease._UUID.fullmatch(lease_id):
            return None
        try:
            record = lease._closed(directory, lease_id)
        except (OSError, ValueError, lease.Cp117LeaseError):
            return None
        if record is None:
            return None
        bound = _binding(root, record, descriptor, config, target)
        if bound is not None:
            candidates.append((record, bound[1]))
    return candidates[0] if len(candidates) == 1 else None


def status(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Return the current campaign state without creating files or guest effects."""
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}:
        raise WindowsCp117CampaignStatusError("Exact CP117 host is required.")
    root = Path(root).resolve(strict=True)
    directory = _directory(root)
    if directory is None:
        return dict(_MISSING)
    try:
        config, target, descriptor = base._descriptor(root)
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError):
        return dict(_MISSING)
    try:
        active = lease._active(directory)
    except (OSError, ValueError, lease.Cp117LeaseError):
        return dict(_UNKNOWN)
    if active is None:
        closed = _bound_closed(root, directory, descriptor, config, target)
        if closed is None:
            return dict(_MISSING)
        record, pair = closed
        try:
            remote_ok = lease._remote_confirm(base._campaign_remote(config, target), "status", record, None)
        except (OSError, ValueError, TypeError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
            remote_ok = False
        if not remote_ok or not _idle_base(root, pair):
            return dict(_UNKNOWN)
        return _result("closed", "inspect-closed-campaign", record)
    bound = _binding(root, active, descriptor, config, target)
    if bound is None:
        return dict(_UNKNOWN)
    _intent, pair = bound
    local_state = active["state"]
    if local_state == "pending-close":
        # A close can be partially visible locally; only the remote journal can
        # establish a terminal close, so this remains a read-only closing state.
        return _result("closing", "inspect-close-progress", active)
    if local_state not in _ACTIVE_STATES:
        return dict(_UNKNOWN)
    try:
        remote_ok = lease._remote_confirm(base._campaign_remote(config, target), "status", active, None)
    except (OSError, ValueError, TypeError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
        remote_ok = False
    if not remote_ok:
        return dict(_UNKNOWN)
    # The base installer role itself is the only legitimate interval before a
    # 2.1.19 idle installation exists. Every later role requires that proof.
    if active["role"] != "base" and not _idle_base(root, pair):
        return dict(_UNKNOWN)
    return _result("active", "inspect-active-role" if active["role"] else "inspect-active-campaign", active)


def diagnose(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Classify why status is unknown using finite, read-only campaign gates."""
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}:
        raise WindowsCp117CampaignStatusError("Exact CP117 host is required.")
    root = Path(root).resolve(strict=True)
    directory = _directory(root)
    if directory is None:
        phase = "local-active"
    else:
        try:
            config, target, descriptor = base._descriptor(root)
            active = lease._active(directory)
        except (OSError, ValueError, TypeError, KeyError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
            active = None
            phase = "local-active"
        else:
            if active is None:
                phase = "local-active"
            else:
                bound = _base_binding(root, active, descriptor)
                if bound is None:
                    # A present original intent means this is not a continuation;
                    # do not mislabel its failed identity projection as rebase data.
                    if base._private_intent(root, active["identity"]["leaseId"]) is not None:
                        phase = "projection"
                    else:
                        detail = _rebase_diagnostic_binding(root, active, descriptor, config, target)
                        if not isinstance(detail, str):
                            bound = detail
                        elif _has_guest_abort_successor_receipt(root, active):
                            guest_abort_detail = _guest_abort_successor_diagnostic_binding(
                                root, active, descriptor, config, target)
                            if isinstance(guest_abort_detail, str):
                                phase = guest_abort_detail
                            else:
                                bound = guest_abort_detail
                        else:
                            phase = detail
                if bound is not None:
                    if active["state"] not in _ACTIVE_STATES and active["state"] != "pending-close":
                        phase = "projection"
                    else:
                        try:
                            remote_ok = lease._remote_confirm(base._campaign_remote(config, target), "status", active, None)
                        except (OSError, ValueError, TypeError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
                            remote_ok = False
                        if not remote_ok:
                            phase = "current-remote"
                        elif active["role"] != "base" and not _idle_base(root, bound[1]):
                            phase = "idle"
                        else:
                            phase = "projection"
    assert phase in _PHASES
    return {"state": "unknown", "phase": phase, "replayAllowed": False, "nativeActionAllowed": False}


def guest_abort_successor_diagnostic(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only proof phase for the one guest-abort successor campaign."""
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}:
        raise WindowsCp117CampaignStatusError("Exact CP117 host is required.")
    root = Path(root).resolve(strict=True)
    directory = _directory(root)
    phase = "guest-abort-receipt"
    if directory is not None:
        try:
            config, target, descriptor = base._descriptor(root)
            active = lease._active(directory)
        except (OSError, ValueError, TypeError, KeyError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
            active = None
        if active is not None:
            detail = _guest_abort_successor_diagnostic_binding(root, active, descriptor, config, target)
            if isinstance(detail, str):
                phase = detail
            elif active.get("state") not in _ACTIVE_STATES and active.get("state") != "pending-close":
                phase = "projection"
            else:
                try:
                    remote_ok = lease._remote_confirm(base._campaign_remote(config, target), "status", active, None)
                except (OSError, ValueError, TypeError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
                    remote_ok = False
                if not remote_ok:
                    phase = "current-remote"
                elif active.get("role") != "base" and not _idle_base(root, detail[1]):
                    phase = "idle"
                else:
                    phase = "projection"
    assert phase in _PHASES
    return {"state": "diagnosed", "phase": phase, "replayAllowed": False, "nativeActionAllowed": False}
