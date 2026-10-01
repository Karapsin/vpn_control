"""One-correlation, fail-closed retirement for CP117's lost guest-create result.

The guest-create submission is deliberately never retried.  This adapter can
only retire its already-reserved stage role after fresh observations prove the
one-use HTTP listener stopped without serving and that the guest leaf and the
matching PowerShell child are absent.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import base64
from typing import Any, Mapping

from . import windows_cp117_lease as lease
from . import windows_msi_base_prepare as base
from . import windows_update_fixture_http_stage as http


class WindowsUpdateFixtureGuestCreateAbortError(ValueError):
    pass


_CORRELATION = "727a4097-e57c-46f6-ba42-5492cd4af4da"
_SOURCE = "19be9df22cbab8086c26e5ca907d9569a5a28a08"
_LEASE = "68393b94-144c-405c-bc8d-bc61afa38d65"
_GROUP = ".rag_index/windows-update-fixture-guest-create-abort"
_UNKNOWN = {"state": "unknown", "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}

# This is intentionally separate from http._REMOTE_CLEANUP: that generic
# helper also accepts a served listener, whereas this one can retire only the
# known unserved attempt.  Its closed marker is the recovery receipt after a
# lost SSH response; it carries a hash of the exact authority binding.
_REMOTE_ABORT = r'''import base64,hashlib,json,os,re,secrets,shutil,stat,sys
root,corr,digest,size,encoded,action=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
def private_dir(p):
 i=os.lstat(p)
 if not stat.S_ISDIR(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700:raise ValueError()
def private_json(p,n):
 i=os.lstat(p)
 if not stat.S_ISREG(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600 or not 0<i.st_size<=n:raise ValueError()
 with open(p,'rb') as f:return json.loads(f.read())
try:
 binding=json.loads(base64.b64decode(encoded,validate=True));length=int(size)
 if action not in ('cleanup','status') or not os.path.isabs(root) or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',corr) or not re.fullmatch(r'[0-9a-f]{64}',digest) or not 0<length<=1075838976 or not isinstance(binding,dict) or binding.get('correlationId')!=corr or binding.get('bundleSha256')!=digest:raise ValueError()
 parent=os.path.join(root,'windows-cp117');http_group=os.path.join(parent,'windows-update-fixture-http-stage');authority_group=os.path.join(parent,'windows-update-fixture-stage');stage=os.path.join(http_group,corr);marker=os.path.join(http_group,corr+'.guest-create-aborted.json')
 for p in (root,parent,http_group,authority_group):private_dir(p)
 marker_base={'correlationId':corr,'bindingSha256':hashlib.sha256(json.dumps(binding,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'served':False}
 def save(v):
  tmp=marker+'.tmp-'+secrets.token_hex(16);fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  with os.fdopen(fd,'wb') as f:f.write((json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode());f.flush();os.fsync(f.fileno())
  os.replace(tmp,marker);d=os.open(http_group,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(d);os.close(d)
 if os.path.lexists(marker):
  marker_value=private_json(marker,512)
  if not isinstance(marker_value,dict) or marker_value.get('state') not in ('pending','cleaned') or {k:v for k,v in marker_value.items() if k!='state'}!=marker_base:raise ValueError()
  if marker_value['state']=='cleaned':
   if os.path.lexists(stage):raise ValueError()
   out({'state':'cleaned'});raise SystemExit(0)
  if action=='status':out({'state':'pending'});raise SystemExit(0)
  if os.path.lexists(stage):
   private_dir(stage)
   if private_json(os.path.join(stage,'binding.json'),512)!={'sha256':digest,'length':length} or private_json(os.path.join(stage,'listener-done.json'),128)!={'served':False}:raise ValueError()
   for name in os.listdir(stage):
    p=os.path.join(stage,name)
    if not os.path.isfile(p) or os.path.islink(p):raise ValueError()
   shutil.rmtree(stage)
  save(dict(marker_base,state='cleaned'));out({'state':'cleaned'});raise SystemExit(0)
 if action=='status':out({'state':'absent'});raise SystemExit(0)
 private_dir(stage);private_dir(os.path.join(authority_group,corr))
 if private_json(os.path.join(authority_group,corr,'binding.json'),4096)!=binding or private_json(os.path.join(stage,'binding.json'),512)!={'sha256':digest,'length':length} or private_json(os.path.join(stage,'listener-done.json'),128)!={'served':False}:raise ValueError()
 for name in os.listdir(stage):
  p=os.path.join(stage,name)
  if not os.path.isfile(p) or os.path.islink(p):raise ValueError()
 save(dict(marker_base,state='pending'))
 shutil.rmtree(stage)
 save(dict(marker_base,state='cleaned'))
 out({'state':'cleaned'})
except Exception:out({'state':'unknown'})
'''


def _request(value: Mapping[str, Any]) -> None:
    if not isinstance(value, Mapping) or value != {"correlationId": _CORRELATION}:
        raise WindowsUpdateFixtureGuestCreateAbortError("Guest-create abort requires its exact correlationId.")


def _directory(root: Path, create: bool) -> Path | None:
    path = root / _GROUP
    if not path.exists() and not path.is_symlink():
        if not create:
            return None
        path.mkdir(mode=0o700, parents=True)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsUpdateFixtureGuestCreateAbortError("Guest-create abort journal is unsafe.")
    return path


def _read_private(path: Path) -> dict[str, Any] | None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 8192):
            raise WindowsUpdateFixtureGuestCreateAbortError("Guest-create abort receipt is unsafe.")
        try:
            value = json.load(stream)
        except (TypeError, ValueError) as error:
            raise WindowsUpdateFixtureGuestCreateAbortError("Guest-create abort receipt is invalid.") from error
    return value if isinstance(value, dict) else None


def _receipt(root: Path, value: Mapping[str, Any], *, create: bool) -> bool:
    directory = _directory(root, create)
    if directory is None:
        return False
    path = directory / (_CORRELATION + ".json")
    old = _read_private(path)
    if old is not None:
        return old == dict(value)
    if not create:
        return False
    raw = (json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return True


def _receipt_value(record: Mapping[str, Any], descriptor: tuple[Any, ...]) -> tuple[dict[str, Any], str]:
    _env, socket, pid, ticks, _sid = descriptor
    request = record["request"]
    evidence = {"correlationId": _CORRELATION, "leaseId": _LEASE, "sourceSha": _SOURCE,
                "fixtureReceiptArtifactId": request["fixtureReceiptArtifactId"],
                "baseMsiArtifactId": request["baseMsiArtifactId"],
                "targetMsiArtifactId": request["targetMsiArtifactId"],
                "sourceFingerprint": record["sourceFingerprint"], "bundleSha256": record["bundleSha256"],
                "guestGeneration": {"socketPath": socket, "qemuPid": pid, "startTicks": ticks},
                # This is written before the destructive host cleanup.  A
                # response loss therefore preserves the observations that
                # admitted the cleanup and leaves a safe retry path.
                "hostStage": "complete", "hostCleanup": "required", "listener": "stopped-unserved",
                "guestLeaf": "absent", "guestCreateChild": "absent"}
    return evidence, hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _campaign(root: Path, record: Mapping[str, Any], descriptor: tuple[Any, ...], config: Any, target: Any,
              evidence_sha: str, *, allow_retired: bool) -> str:
    """Confirm the exact campaign before mutation, or recognize its exact close."""
    directory, lock = lease._locked(root)
    try:
        active = lease._active(directory)
        closed = lease._closed(directory, _LEASE) if active is None else None
        identity = base._campaign_identity({**record["request"], "correlationId": _LEASE}, descriptor)
        current = active if active is not None else closed
        if current is None or current.get("identity") != identity:
            return "campaign-identity"
        if current.get("server") != "stopped" or current.get("credentials") != "absent":
            return "campaign-server"
        if current.get("state") == "pending-finish":
            return "pending-finish"
        if (allow_retired and current.get("state") == "active" and current.get("role") is None
                and current.get("lastOutcome") == "failed-cleaned"
                and current.get("lastEvidenceSha256") == evidence_sha):
            return "retired"
        if (current.get("state") == "role-active" and current.get("role") == "stage"
                and current.get("correlationId") == _CORRELATION):
            if not lease._remote_confirm(base._campaign_remote(config, target), "status", current, None):
                return "campaign-remote"
            return "armed"
        return "campaign-role"
    finally:
        os.close(lock)


def _host_stage(root: Path, record: Mapping[str, Any], descriptor: tuple[Any, ...], config: Any, target: Any) -> str:
    """Observe the frozen host leaf without imposing the generic core phase.

    ``host_stage_probe`` correctly admits listener startup only from
    ``host-staged``.  This recovery observes the same exact remote binding
    after the shared core advanced to ``guest-created``.
    """
    try:
        binding = base64.b64encode(json.dumps(http._authority_binding(record, descriptor),
                                               sort_keys=True, separators=(",", ":")).encode()).decode("ascii")
        raw = base._remote(config, http._REMOTE_HOST_STAGE_PROBE,
                           (str(target.fixture_transfer_root), _CORRELATION, record["bundleSha256"],
                            str(record["bundleSize"]), binding), None, 60)
        observed = json.loads(raw) if raw is not None and len(raw) <= 128 else None
        if observed == {"state": "complete"}:
            return "complete"
        if observed == {"state": "absent"}:
            return "absent"
        if observed == {"state": "partial"}:
            return "partial"
    except (OSError, ValueError, TypeError, base.WindowsMsiBasePrepareError):
        pass
    return "unknown"


def _guest_state(config: Any, descriptor: tuple[Any, ...]) -> str:
    """Run the existing parser-only guest census without requiring stage role."""
    try:
        _env, socket, pid, ticks, sid = descriptor
        create = http.stage._create_script(_CORRELATION, sid)
        script = http._guest_create_diagnostic_script(_CORRELATION, sid, create)
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        if len(encoded) > 30000:
            return "script-invalid"
        raw = base._remote(config, http._REMOTE_QGA_GUEST_CREATE_DIAGNOSTIC,
                           (socket, str(pid), str(ticks), encoded), None, 90)
        observed = json.loads(raw) if raw is not None and len(raw) <= 256 else None
        if observed == {"state": "leaf-absent", "interpreter": "absent"}:
            return "absent"
        if isinstance(observed, dict) and observed.get("interpreter") == "present":
            return "interpreter-present"
        if isinstance(observed, dict) and observed.get("state") in {"leaf-directory", "leaf-type", "leaf-reparse"}:
            return "leaf-present"
        return "wrapper-unknown"
    except (AttributeError, OSError, ValueError, TypeError, base.WindowsMsiBasePrepareError):
        return "wrapper-unknown"


def _guest_absent(config: Any, descriptor: tuple[Any, ...]) -> bool:
    return _guest_state(config, descriptor) == "absent"


def _marker(config: Any, target: Any, record: Mapping[str, Any], descriptor: tuple[Any, ...]) -> str:
    try:
        binding = base64.b64encode(json.dumps(http._authority_binding(record, descriptor), sort_keys=True, separators=(",", ":")).encode()).decode("ascii")
        raw = base._remote(config, _REMOTE_ABORT, (str(target.fixture_transfer_root), _CORRELATION,
                           record["bundleSha256"], str(record["bundleSize"]), binding, "status"), None, 30)
        observed = json.loads(raw) if raw is not None else None
        return observed["state"] if observed in ({"state": "absent"}, {"state": "pending"}, {"state": "cleaned"}) else "unknown"
    except (OSError, ValueError, TypeError, base.WindowsMsiBasePrepareError):
        return "unknown"


def _retired_local_binding(root: Path) -> tuple[Path, dict[str, Any], Any, Any, tuple[Any, ...]]:
    """Read the exact frozen HTTP/stage binding after its role was released.

    This deliberately omits only ``_record``'s active-role verifier.  Every
    artifact, source, VM generation, stage intent and shared core equality is
    retained; callers must still prove the exact retired campaign receipt.
    """
    root_path = Path(root).resolve(strict=True)
    record = http._read(root_path, _CORRELATION)
    if record is None:
        raise WindowsUpdateFixtureGuestCreateAbortError("Retired HTTP record is unavailable.")
    http._artifact(Path(record["bundlePath"]), record["bundleSha256"], record["bundleSize"])
    request = http._request(record["request"])
    config, target, descriptor = base._descriptor(root_path)
    pair = http.stage.public._admit_pair(root_path, request["sourceSha"], request["fixtureReceiptArtifactId"],
                                         request["baseMsiArtifactId"], request["targetMsiArtifactId"])
    intent = http.stage._read_intent(root_path, _CORRELATION)
    core = http.large_transfer.read(root_path, _CORRELATION)
    if (request.get("correlationId") != _CORRELATION or record.get("leaseId") != _LEASE
            or request.get("sourceSha") != _SOURCE or record.get("sourceFingerprint") != pair.get("sourceFingerprint")
            or intent is None or intent.get("request") != request or intent.get("leaseId") != _LEASE
            or intent.get("sourceFingerprint") != pair.get("sourceFingerprint")
            or intent.get("bundleSha256") != record["bundleSha256"] or intent.get("bundleSize") != record["bundleSize"]
            or core is None or core.get("phase") != "guest-created"
            or core.get("binding") != http._large_binding(record, descriptor)
            or core.get("sha256") != record["bundleSha256"] or core.get("length") != record["bundleSize"]):
        raise WindowsUpdateFixtureGuestCreateAbortError("Retired HTTP binding changed.")
    env, socket, pid, ticks, sid = descriptor
    if any(intent.get(name) != expected for name, expected in (("environment", env), ("socketPath", socket),
            ("pid", pid), ("startTicks", ticks), ("expectedSid", sid))):
        raise WindowsUpdateFixtureGuestCreateAbortError("Retired guest generation changed.")
    return root_path, record, config, target, descriptor


def _admission(root: Path) -> tuple[str, tuple[Any, ...] | None]:
    """Read every fact required for a close.  Every uncertain fact blocks it."""
    try:
        try:
            root_path, record, config, target = http._record(root, _CORRELATION, campaign_mode="stage-or-idle")
            descriptor = base._descriptor(root_path)[2]
            retired_loader = False
        except (OSError, ValueError, KeyError, TypeError, http.WindowsUpdateFixtureHttpStageError,
                base.WindowsMsiBasePrepareError):
            try:
                root_path, record, config, target, descriptor = _retired_local_binding(root)
            except (OSError, ValueError, KeyError, TypeError, WindowsUpdateFixtureGuestCreateAbortError,
                    http.WindowsUpdateFixtureHttpStageError, base.WindowsMsiBasePrepareError):
                return "retired-binding-invalid", None
            retired_loader = True
        if (record.get("leaseId") != _LEASE or record["request"].get("sourceSha") != _SOURCE
                or record["request"].get("correlationId") != _CORRELATION):
            return "binding", None
        try:
            core = http.large_transfer.read(root_path, _CORRELATION)
        except (OSError, ValueError, KeyError, TypeError, http.large_transfer.WindowsLargeArtifactTransferError):
            return "retired-shared-core-invalid", None
        if core is None or core.get("phase") != "guest-created":
            return "shared-phase", None
        try:
            evidence, digest = _receipt_value(record, descriptor)
            preclean = _receipt(root_path, evidence, create=False)
        except (OSError, ValueError, KeyError, TypeError, WindowsUpdateFixtureGuestCreateAbortError):
            return "retired-receipt-invalid", None
        try:
            campaign_state = _campaign(root_path, record, descriptor, config, target, digest, allow_retired=True)
        except (OSError, ValueError, KeyError, TypeError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
            return "retired-campaign-invalid", None
        if retired_loader and campaign_state != "retired":
            return "retired-campaign-" + campaign_state, None
        marker = _marker(config, target, record, descriptor) if preclean else "absent"
        if preclean and marker == "unknown":
            return "retired-marker-invalid", None
        if campaign_state == "retired":
            if not preclean or marker != "cleaned":
                return "retired-marker-invalid", None
            guest = _guest_state(config, descriptor)
            if guest != "absent":
                return "retired-guest-" + guest, None
            return "retired", (root_path, record, config, target, descriptor, evidence, digest)
        if not _guest_absent(config, descriptor):
            return "guest-create", None
        if preclean:
            if marker not in {"cleaned", "pending", "absent"}:
                return "cleanup-marker", None
            if marker == "absent":
                # A crash after the durable local evidence but before SSH must
                # not strand the role.  Re-observe the original terminal host
                # facts before allowing its first cleanup.
                host = _host_stage(root_path, record, descriptor, config, target)
                listener = http.listener_status(root_path, {"correlationId": _CORRELATION})
                if host != "complete":
                    return "host-stage-" + host, None
                if listener.get("state") != "stopped":
                    return "listener", None
        else:
            host = _host_stage(root_path, record, descriptor, config, target)
            if host != "complete":
                return "host-stage-" + host, None
            listener = http.listener_status(root_path, {"correlationId": _CORRELATION})
            if listener.get("state") != "stopped":
                return "listener", None
        state = campaign_state
        if state == "retired":
            return "retired", (root_path, record, config, target, descriptor, evidence, digest)
        if state == "pending-finish":
            return "pending-finish", (root_path, record, config, target, descriptor, evidence, digest)
        if state != "armed":
            return state, None
        phase = ("ready-cleaned" if marker == "cleaned" else
                 "ready-pending" if marker == "pending" else "ready") if preclean else "ready"
        return phase, (root_path, record, config, target, descriptor, evidence, digest)
    except (AttributeError, OSError, ValueError, KeyError, TypeError, http.WindowsUpdateFixtureHttpStageError,
            base.WindowsMsiBasePrepareError, lease.Cp117LeaseError):
        return "unknown", None


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only admission diagnostic.  It never creates a journal or replays QGA."""
    _request(value)
    state, _details = _admission(Path(root).resolve(strict=True))
    return {"state": "diagnosed", "correlationId": _CORRELATION, "phase": state,
            "abortAllowed": state in {"ready", "ready-pending", "ready-cleaned"}, "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}


def abort(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Remove only this terminal unserved HTTP leaf, then finish the stage role."""
    _request(value)
    try:
        state, details = _admission(Path(root).resolve(strict=True))
        if state == "retired" and details is not None:
            return {"state": "retired", "correlationId": _CORRELATION, **{k: v for k, v in _UNKNOWN.items() if k != "state"}}
        if state == "pending-finish" and details is not None:
            root_path, _record, config, target, _descriptor, _evidence, _digest = details
            if lease.reconcile(root_path, _LEASE, base._campaign_remote(config, target)).get("state") != "active":
                return {**_UNKNOWN, "correlationId": _CORRELATION}
            state, details = _admission(root_path)
            if state == "retired":
                return {"state": "retired", "correlationId": _CORRELATION, **{k: v for k, v in _UNKNOWN.items() if k != "state"}}
        if state not in {"ready", "ready-pending", "ready-cleaned"} or details is None:
            return {**_UNKNOWN, "correlationId": _CORRELATION}
        root_path, record, config, target, descriptor, evidence, digest = details
        if not _receipt(root_path, evidence, create=True):
            return {**_UNKNOWN, "correlationId": _CORRELATION}
        binding = base64.b64encode(json.dumps(http._authority_binding(record, descriptor), sort_keys=True, separators=(",", ":")).encode()).decode("ascii")
        if state in {"ready", "ready-pending"}:
            # Fixed recovery cleanup rejects served=true and writes its exact marker.
            raw = base._remote(config, _REMOTE_ABORT, (str(target.fixture_transfer_root), _CORRELATION,
                               record["bundleSha256"], str(record["bundleSize"]), binding, "cleanup"), None, 30)
            if (json.loads(raw) if raw is not None else None) != {"state": "cleaned"}:
                return {**_UNKNOWN, "correlationId": _CORRELATION}
        finished = lease.finish_role(root_path, _LEASE, "stage", _CORRELATION, digest,
                                     "failed-cleaned", base._campaign_remote(config, target))
        if finished.get("state") != "active":
            return {**_UNKNOWN, "correlationId": _CORRELATION}
        return {"state": "retired", "correlationId": _CORRELATION,
                "cleanupReceiptSha256": digest, **{k: v for k, v in _UNKNOWN.items() if k != "state"}}
    except (AttributeError, OSError, ValueError, KeyError, TypeError, http.WindowsUpdateFixtureHttpStageError,
            base.WindowsMsiBasePrepareError, lease.Cp117LeaseError):
        return {**_UNKNOWN, "correlationId": _CORRELATION}


def workflow(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if action == "status":
        return status(root, inputs)
    if action == "abort":
        return abort(root, inputs)
    raise WindowsUpdateFixtureGuestCreateAbortError("Unknown guest-create abort action.")
