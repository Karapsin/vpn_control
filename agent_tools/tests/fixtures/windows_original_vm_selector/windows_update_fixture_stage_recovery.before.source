"""Fail-closed recovery for CP117's one lost fixture-stage submission.

The stage request used a one-shot QGA stream.  Its host receipt was lost after
the remote binding was written, before a dispatch receipt existed.  This module
does not replay that stream.  It can close only that correlation after observing
that the original QGA create task is gone and its guest leaf never appeared.
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
import time
from typing import Any, Mapping

from . import windows_cp117_lease as lease
from . import windows_msi_base_prepare as base
from . import windows_msi_http_transfer as transfer
from . import windows_msi_public_scenario as public
from . import windows_update_fixture_stage as stage


class WindowsUpdateFixtureStageRecoveryError(ValueError):
    pass


# This is intentionally a one-correlation recovery.  A later uncertain stage
# needs its own diagnosis and regression before it can ever share this route.
_CORRELATION = "7f278204-a8da-419b-baf5-d98fb94a1526"
_GROUP = ".rag_index/windows-update-fixture-stage-recovery"
_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


def _request(value: Mapping[str, Any]) -> None:
    if not isinstance(value, Mapping) or set(value) != {"host"} or value.get("host") != "archlinux":
        raise WindowsUpdateFixtureStageRecoveryError("Stage recovery requires the owned CP117 host.")


def _directory(root: Path) -> Path:
    path = root / _GROUP
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsUpdateFixtureStageRecoveryError("Stage recovery journal is unsafe.")
    return path


def _receipt_path(root: Path) -> Path:
    return _directory(root) / (_CORRELATION + ".json")


def _read_receipt(root: Path) -> dict[str, Any] | None:
    path = _receipt_path(root)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8192):
            raise WindowsUpdateFixtureStageRecoveryError("Stage recovery receipt is unsafe.")
        try:
            value = json.load(stream)
        except (TypeError, ValueError) as error:
            raise WindowsUpdateFixtureStageRecoveryError("Stage recovery receipt is invalid.") from error
    required = {"version", "correlationId", "leaseId", "guestGeneration", "evidenceSha256",
                "cleanupReceiptSha256", "state"}
    if (not isinstance(value, dict) or set(value) != required or value.get("version") != 1
            or value.get("correlationId") != _CORRELATION or value.get("state") not in {"remote-cleaned", "recovered"}
            or not isinstance(value.get("leaseId"), str) or not _UUID.fullmatch(value["leaseId"])
            or not isinstance(value.get("evidenceSha256"), str) or not _HASH.fullmatch(value["evidenceSha256"])
            or not isinstance(value.get("cleanupReceiptSha256"), str) or not _HASH.fullmatch(value["cleanupReceiptSha256"])
            or value.get("guestGeneration") is None):
        raise WindowsUpdateFixtureStageRecoveryError("Stage recovery receipt is invalid.")
    return value


def _write_receipt(root: Path, value: Mapping[str, Any]) -> None:
    path = _receipt_path(root)
    current = _read_receipt(root)
    if current is not None:
        if current != dict(value):
            raise WindowsUpdateFixtureStageRecoveryError("Stage recovery receipt changed.")
        return
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _replace_receipt(root: Path, old: Mapping[str, Any], new: Mapping[str, Any]) -> None:
    path = _receipt_path(root)
    directory = _directory(root)
    lock = os.open(directory / ".environment.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise WindowsUpdateFixtureStageRecoveryError("Stage recovery lock is unsafe.")
        fcntl.flock(lock, fcntl.LOCK_EX)
        if _read_receipt(root) != dict(old):
            raise WindowsUpdateFixtureStageRecoveryError("Stage recovery receipt changed.")
        temporary = path.parent / ("." + path.name + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write((json.dumps(new, sort_keys=True, separators=(",", ":")) + "\n").encode())
                stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, path)
            parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    finally:
        os.close(lock)


def _bound(root: Path, receipt_state: str | None) -> tuple[dict[str, Any], dict[str, Any], Any, Any, tuple[Any, ...]]:
    intent = stage._read_intent(root, _CORRELATION)
    if intent is None:
        raise WindowsUpdateFixtureStageRecoveryError("The fixed stage intent is unavailable.")
    request = stage._request(intent["request"])
    if request["correlationId"] != _CORRELATION:
        raise WindowsUpdateFixtureStageRecoveryError("Stage recovery correlation changed.")
    pair = public._admit_pair(root, request["sourceSha"], request["fixtureReceiptArtifactId"],
                              request["baseMsiArtifactId"], request["targetMsiArtifactId"])
    config, target, descriptor = base._descriptor(root)
    env, socket, pid, ticks, sid = descriptor
    if (env != "windows-cp117" or intent.get("sourceFingerprint") != pair.get("sourceFingerprint")
            or any(intent.get(key) != expected for key, expected in (
                ("environment", env), ("socketPath", socket), ("pid", pid),
                ("startTicks", ticks), ("expectedSid", sid)))
            or not isinstance(intent.get("leaseId"), str) or not _UUID.fullmatch(intent["leaseId"])):
        raise WindowsUpdateFixtureStageRecoveryError("Stage recovery binding changed.")
    identity = base._campaign_identity({**request, "correlationId": intent["leaseId"]}, descriptor)
    directory, lock = lease._locked(root)
    try:
        active = lease._active(directory)
        closed = lease._closed(directory, intent["leaseId"]) if active is None else None
        if active is not None and active["identity"] != identity:
            raise WindowsUpdateFixtureStageRecoveryError("Stage campaign identity changed.")
        if closed is not None and closed["identity"] != identity:
            raise WindowsUpdateFixtureStageRecoveryError("Closed stage campaign identity changed.")
        if _campaign_resume_detail(root, intent, descriptor, active, closed, receipt_state) is None:
            raise WindowsUpdateFixtureStageRecoveryError("Stage campaign state is not recoverable.")
    finally:
        os.close(lock)
    return intent, pair, config, target, descriptor


def _predecessor_evidence(root: Path, intent: Mapping[str, Any], descriptor: tuple[Any, ...]) -> str:
    """Bind stage's inherited evidence to the verified base terminal receipt."""
    record = transfer._intent(root, intent["leaseId"])
    if record is None:
        raise WindowsUpdateFixtureStageRecoveryError("Base predecessor receipt is unavailable.")
    env, socket, pid, ticks, sid = descriptor
    request = intent["request"]
    if (record.get("sourceSha") != request["sourceSha"] or record.get("baseMsiArtifactId") != request["baseMsiArtifactId"]
            or record.get("environment") != env or record.get("socketPath") != socket
            or record.get("qemuPid") != pid or record.get("startTicks") != ticks
            or record.get("expectedSid") != sid):
        raise WindowsUpdateFixtureStageRecoveryError("Base predecessor binding changed.")
    terminal = transfer._terminal_intent(root, record)
    if terminal is None:
        raise WindowsUpdateFixtureStageRecoveryError("Base predecessor terminal receipt is unavailable.")
    return terminal


def _campaign_resume_detail(root: Path, intent: Mapping[str, Any], descriptor: tuple[Any, ...],
                            active: Mapping[str, Any] | None, closed: Mapping[str, Any] | None,
                            receipt_state: str | None) -> str | None:
    """Classify only the durable state transitions this recovery can resume."""
    evidence, cleanup = _evidence(intent, descriptor)
    stage_active = (active is not None and active.get("state") == "role-active"
                    and active.get("role") == "stage" and active.get("correlationId") == _CORRELATION
                    and active.get("server") == "stopped" and active.get("credentials") == "absent")
    if stage_active:
        try:
            predecessor = _predecessor_evidence(root, intent, descriptor)
        except (OSError, ValueError, KeyError, TypeError, WindowsUpdateFixtureStageRecoveryError,
                transfer.WindowsMsiHttpTransferError):
            return None
        if active.get("lastOutcome") == "succeeded" and active.get("lastEvidenceSha256") == predecessor:
            return "active-role"
        return None
    post_finish = (active is not None and active.get("state") == "active" and active.get("role") is None
                   and active.get("correlationId") is None and active.get("server") == "stopped"
                   and active.get("credentials") == "absent" and active.get("lastOutcome") == "failed-cleaned"
                   and active.get("lastEvidenceSha256") == evidence)
    closed_exact = (closed is not None and closed.get("state") == "closed" and closed.get("role") is None
                    and closed.get("correlationId") is None and closed.get("server") == "stopped"
                    and closed.get("credentials") == "absent" and closed.get("lastOutcome") == "failed-cleaned"
                    and closed.get("lastEvidenceSha256") == cleanup)
    if receipt_state is None:
        return "active-role" if stage_active else None
    if receipt_state == "remote-cleaned":
        if stage_active:
            return "active-role"
        if post_finish:
            return "post-finish"
        return "closed" if closed_exact else None
    if receipt_state == "recovered":
        return "closed" if closed_exact else None
    return None


def _campaign_detail(root: Path, intent: Mapping[str, Any], descriptor: tuple[Any, ...], config: Any,
                     target: Any, receipt_state: str | None) -> str:
    """Read the exact campaign record without creating its journal or exposing it."""
    directory = root / lease._DIR
    try:
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            return "record-unsafe"
        active = lease._read(directory / "active.json")
        closed = lease._closed(directory, intent["leaseId"]) if active is None else None
        identity = base._campaign_identity({**intent["request"], "correlationId": intent["leaseId"]}, descriptor)
    except (OSError, ValueError, KeyError, TypeError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
        return "record-unsafe"
    record = active if active is not None else closed
    if record is None:
        return "record-missing"
    if record.get("identity") != identity:
        return "identity-mismatch"
    try:
        detail = _campaign_resume_detail(root, intent, descriptor, active, closed, receipt_state)
    except (OSError, ValueError, KeyError, TypeError, WindowsUpdateFixtureStageRecoveryError,
            transfer.WindowsMsiHttpTransferError):
        detail = None
    if detail is None:
        return "resume-state"
    expected = active if detail in {"active-role", "post-finish"} else closed
    assert expected is not None
    try:
        if not lease._remote_confirm(base._campaign_remote(config, target), "status", expected, None):
            return "remote-confirm"
    except (OSError, ValueError, TypeError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
        return "remote-confirm"
    return detail


_REMOTE_RECOVER = base._QGA + lease.remote_role_guard() + r'''import fcntl,time
root,env,lease_id,corr,sock,pid,ticks,sid,source,fingerprint,bundle_hash,size_text,receipt_id,base_id,target_id,create_encoded,action=sys.argv[1:]
def out(value):print(json.dumps(value,sort_keys=True,separators=(',',':')))
def directory(path):
 info=os.lstat(path)
 return stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o700
def private(path):
 info=os.lstat(path)
 return stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o600 and info.st_size<=8192
def submitter():
 marker=b'submission-uncertain';needle=corr.encode()
 for name in os.listdir('/proc'):
  if not name.isdigit() or int(name)==os.getpid():continue
  try:raw=open('/proc/'+name+'/cmdline','rb').read(1048576)
  except FileNotFoundError:continue
  except OSError:return 'unknown'
  if marker in raw and needle in raw:return 'active'
 return 'absent'
def guest_observation():
 encoded_literal=base64.b64encode(create_encoded.encode()).decode()
 script="$ErrorActionPreference='Stop';$needle=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+encoded_literal+"'));$leaf='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-update-fixture-"+corr+"';try{$items=@(Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" -ErrorAction Stop|Where-Object {$_.CommandLine -and $_.CommandLine.Contains($needle)});$create=if($items.Count -eq 0){'absent'}else{'active'};$guest=if(-not (Test-Path -LiteralPath $leaf)){'absent'}else{'present'};[Console]::Out.WriteLine(([pscustomobject]@{version=1;createTask=$create;guestStage=$guest}|ConvertTo-Json -Compress))}catch{[Console]::Out.WriteLine('{\"version\":1,\"createTask\":\"unknown\",\"guestStage\":\"unknown\"}');exit 1}"
 encoded=base64.b64encode(script.encode('utf-16le')).decode()
 if len(encoded)>=30000:raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(40):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if item.get('exitcode')!=0 or item.get('out-truncated') is not False or item.get('err-truncated') is not False:raise ValueError()
 raw=base64.b64decode(item.get('out-data',''),validate=True)
 if not 0<len(raw)<=512:raise ValueError()
 lines=[line for line in decode(raw).splitlines() if line.startswith('{') and line.endswith('}')]
 value=json.loads(lines[0]) if len(lines)==1 else None
 if value not in ({'version':1,'createTask':'absent','guestStage':'absent'},{'version':1,'createTask':'active','guestStage':'absent'},{'version':1,'createTask':'absent','guestStage':'present'},{'version':1,'createTask':'active','guestStage':'present'}):raise ValueError()
 return value
try:
 if action not in ('cleanup','reconcile','diagnose') or env!='windows-cp117' or not live(sock,pid,ticks) or not 0<int(size_text)<=1075838976:raise ValueError()
 require_campaign_role(root,env,lease_id,'stage',corr,source,receipt_id,base_id,target_id,sock,pid,ticks)
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-update-fixture-stage');job=os.path.join(group,corr)
 if not all(directory(path) for path in (root,parent,group)):raise ValueError()
 lock=os.open(os.path.join(group,'.environment.lock'),os.O_RDWR|getattr(os,'O_NOFOLLOW',0))
 try:
  info=os.fstat(lock)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError()
  fcntl.flock(lock,fcntl.LOCK_EX)
  empty_job=False
  stage_kind=None
  if action=='cleanup':
   if not directory(job) or set(os.listdir(job))!={'binding.json'} or not private(os.path.join(job,'binding.json')):raise ValueError()
   binding=json.load(open(os.path.join(job,'binding.json'),encoding='utf-8'))
  elif os.path.lexists(job):
   if not directory(job):raise ValueError()
   if action=='reconcile':
    if os.listdir(job):raise ValueError()
    empty_job=True
   else:
    names=set(os.listdir(job))
    if names==set():stage_kind='empty'
    elif names=={'binding.json'} and private(os.path.join(job,'binding.json')):
     binding=json.load(open(os.path.join(job,'binding.json'),encoding='utf-8'));stage_kind='binding-only'
    else:raise ValueError()
  elif action=='diagnose':stage_kind='absent'
  elif action=='reconcile':stage_kind='absent'
  else:raise ValueError()
  expected={'correlationId':corr,'socketPath':sock,'pid':int(pid),'startTicks':int(ticks),'leaseId':lease_id,'sourceSha':source,'sourceFingerprint':fingerprint,'bundleSha256':bundle_hash,'expectedSid':sid,'fixtureReceiptArtifactId':receipt_id,'baseMsiArtifactId':base_id,'targetMsiArtifactId':target_id}
  if action=='cleanup' and binding!=expected:raise ValueError()
  if action=='diagnose' and stage_kind=='binding-only' and binding!=expected:raise ValueError()
  host=submitter()
  if host!='absent':out({'state':'blocked','correlationId':corr,'hostSubmitter':host,'createTask':'unknown','guestStage':'unknown'});raise SystemExit(0)
  first=guest_observation()
  if first!={'version':1,'createTask':'absent','guestStage':'absent'}:out({'state':'blocked','correlationId':corr,'hostSubmitter':'absent','createTask':first['createTask'],'guestStage':first['guestStage']});raise SystemExit(0)
  time.sleep(1)
  host=submitter()
  if host!='absent':out({'state':'blocked','correlationId':corr,'hostSubmitter':host,'createTask':'unknown','guestStage':'unknown'});raise SystemExit(0)
  second=guest_observation()
  if second!={'version':1,'createTask':'absent','guestStage':'absent'}:out({'state':'blocked','correlationId':corr,'hostSubmitter':'absent','createTask':second['createTask'],'guestStage':second['guestStage']});raise SystemExit(0)
  if action=='cleanup':
   os.unlink(os.path.join(job,'binding.json'));os.rmdir(job)
   parentfd=os.open(group,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
   try:os.fsync(parentfd)
   finally:os.close(parentfd)
  elif empty_job:
   os.rmdir(job)
   parentfd=os.open(group,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
   try:os.fsync(parentfd)
   finally:os.close(parentfd)
 finally:os.close(lock)
 if action=='diagnose':out({'state':'observed','correlationId':corr,'stage':stage_kind,'hostSubmitter':'absent','createTask':'absent','guestStage':'absent'})
 else:out({'state':'remote-cleaned' if action=='cleanup' else 'remote-absent-reconciled','correlationId':corr,'hostSubmitter':'absent','createTask':'absent','guestStage':'absent'})
except Exception:out({'state':'unknown','correlationId':corr})
'''


def _remote_observation(intent: Mapping[str, Any], pair: Mapping[str, Any], config: Any, target: Any,
                        descriptor: tuple[Any, ...], action: str) -> dict[str, Any] | None:
    env, socket, pid, ticks, sid = descriptor
    create = stage._create_script(_CORRELATION, sid)
    create_encoded = base64.b64encode(create.encode("utf-16le")).decode("ascii")
    raw = base._remote(config, _REMOTE_RECOVER, (str(target.fixture_transfer_root), env, intent["leaseId"],
        _CORRELATION, socket, str(pid), str(ticks), sid, intent["request"]["sourceSha"],
        pair["sourceFingerprint"], intent["bundleSha256"], str(intent["bundleSize"]),
        intent["request"]["fixtureReceiptArtifactId"], intent["request"]["baseMsiArtifactId"],
        intent["request"]["targetMsiArtifactId"], create_encoded, action), None, 120)
    try:
        observed = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None
    if action == "diagnose":
        expected = {"state": "observed", "correlationId": _CORRELATION, "stage": None,
                    "hostSubmitter": "absent", "createTask": "absent", "guestStage": "absent"}
        if (not isinstance(observed, dict) or set(observed) != set(expected)
                or observed.get("state") != "observed" or observed.get("correlationId") != _CORRELATION
                or observed.get("stage") not in {"absent", "empty", "binding-only"}
                or observed.get("hostSubmitter") not in {"absent", "active", "unknown"}
                or observed.get("createTask") not in {"absent", "active", "unknown"}
                or observed.get("guestStage") not in {"absent", "present", "unknown"}):
            return None
        return observed
    expected = {"state": "remote-cleaned" if action == "cleanup" else "remote-absent-reconciled",
                        "correlationId": _CORRELATION, "hostSubmitter": "absent",
                        "createTask": "absent", "guestStage": "absent"}
    return observed if observed == expected else None


def _remote_observe(intent: Mapping[str, Any], pair: Mapping[str, Any], config: Any, target: Any,
                    descriptor: tuple[Any, ...], action: str) -> bool:
    return _remote_observation(intent, pair, config, target, descriptor, action) is not None


def _remote_cleanup(intent: Mapping[str, Any], pair: Mapping[str, Any], config: Any, target: Any,
                    descriptor: tuple[Any, ...]) -> bool:
    return _remote_observe(intent, pair, config, target, descriptor, "cleanup")


def _remote_absence_reconciled(intent: Mapping[str, Any], pair: Mapping[str, Any], config: Any, target: Any,
                               descriptor: tuple[Any, ...]) -> bool:
    """Recover only a lost unlink receipt, with a fresh no-submitter proof."""
    return _remote_observe(intent, pair, config, target, descriptor, "reconcile")


def diagnose(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only bounded diagnosis for the fixed lost-stage recovery.

    The projection names a gate only. It deliberately excludes paths, process
    IDs, account names, raw receipts, and installer details.
    """
    _request(value)
    root = Path(root).resolve(strict=True)
    result = {"state": "diagnosed", "correlationId": _CORRELATION,
              "recoveryAllowed": False, "nativeActionAllowed": False}
    try:
        intent = stage._read_intent(root, _CORRELATION)
        if intent is None:
            return {**result, "phase": "local-intent"}
        request = stage._request(intent["request"])
        if request["correlationId"] != _CORRELATION:
            return {**result, "phase": "local-intent"}
    except (OSError, ValueError, KeyError, TypeError, stage.WindowsUpdateFixtureStageError):
        return {**result, "phase": "local-intent"}
    try:
        pair = public._admit_pair(root, request["sourceSha"], request["fixtureReceiptArtifactId"],
                                  request["baseMsiArtifactId"], request["targetMsiArtifactId"])
        if intent.get("sourceFingerprint") != pair.get("sourceFingerprint"):
            return {**result, "phase": "local-artifact"}
    except (OSError, ValueError, KeyError, TypeError):
        return {**result, "phase": "local-artifact"}
    try:
        config, target, descriptor = base._descriptor(root)
        env, socket, pid, ticks, sid = descriptor
        if (env != "windows-cp117" or any(intent.get(key) != expected for key, expected in (
                ("environment", env), ("socketPath", socket), ("pid", pid),
                ("startTicks", ticks), ("expectedSid", sid)))):
            return {**result, "phase": "local-descriptor"}
    except (OSError, ValueError, KeyError, TypeError):
        return {**result, "phase": "local-descriptor"}
    receipt = _read_receipt(root)
    detail = _campaign_detail(root, intent, descriptor, config, target,
                               receipt["state"] if receipt is not None else None)
    if detail not in {"active-role", "post-finish", "closed"}:
        return {**result, "phase": "campaign", "campaignDetail": detail}
    try:
        _bound(root, receipt["state"] if receipt is not None else None)
    except (OSError, ValueError, KeyError, TypeError, WindowsUpdateFixtureStageRecoveryError,
            lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
        return {**result, "phase": "campaign", "campaignDetail": "local-admission"}
    if receipt is not None and receipt["state"] == "recovered":
        return {**result, "phase": "recovered", "recoveryAllowed": True}
    # A remote-cleaned receipt was fsynced only after the guarded remote
    # cleanup. Its resume states no longer hold the stage role, so invoking
    # the role-guarded remote observer would manufacture a false failure.
    if receipt is not None and receipt["state"] == "remote-cleaned":
        return ({**result, "phase": "idle"} if not _idle(root, pair)
                else {**result, "phase": "closure", "recoveryAllowed": True})
    observed = _remote_observation(intent, pair, config, target, descriptor, "diagnose")
    if observed is None:
        return {**result, "phase": "remote-stage"}
    if observed["hostSubmitter"] != "absent":
        return {**result, "phase": "host-submitter"}
    if observed["createTask"] != "absent":
        return {**result, "phase": "qga-create-task"}
    if observed["guestStage"] != "absent":
        return {**result, "phase": "guest-stage"}
    if not _idle(root, pair):
        return {**result, "phase": "idle"}
    if receipt is not None:
        return {**result, "phase": "closure", "recoveryAllowed": True}
    return {**result, "phase": "remote-" + observed["stage"], "recoveryAllowed": True}


def _evidence(intent: Mapping[str, Any], descriptor: tuple[Any, ...]) -> tuple[str, str]:
    _env, socket, pid, ticks, _sid = descriptor
    proof = {"correlationId": _CORRELATION, "leaseId": intent["leaseId"],
             "guestGeneration": {"socketPath": socket, "qemuPid": pid, "startTicks": ticks},
             "binding": "exact", "remoteStage": "binding-only-cleaned",
             "createTask": "absent", "guestStage": "absent", "dispatch": "absent"}
    evidence = hashlib.sha256(json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return evidence, hashlib.sha256((evidence + ":campaign-closed").encode()).hexdigest()


def _idle(root: Path, pair: Mapping[str, Any]) -> bool:
    """A stage cannot claim an installer-free close from its own missing receipt."""
    version = pair.get("baseVersion")
    if not isinstance(version, str):
        return False
    observed = base.readiness(root, {"host": "archlinux", "expectedCurrentVersion": version})
    return (observed.get("state") == "ready" and observed.get("ready") is True
            and observed.get("code") == "READY" and observed.get("installedVersion") == version
            and observed.get("productCount") == 1 and observed.get("activeCount") == 0
            and observed.get("activeProcesses") == [])


def _campaign_closed(root: Path, intent: Mapping[str, Any], descriptor: tuple[Any, ...],
                     config: Any, target: Any, evidence: str, cleanup: str) -> bool:
    remote = base._campaign_remote(config, target)
    directory, lock = lease._locked(root)
    try:
        active = lease._active(directory)
        closed = lease._closed(directory, intent["leaseId"]) if active is None else None
        identity = base._campaign_identity({**intent["request"], "correlationId": intent["leaseId"]}, descriptor)
        if active is not None and active["identity"] != identity:
            raise WindowsUpdateFixtureStageRecoveryError("Stage campaign identity changed.")
        if closed is not None and closed["identity"] != identity:
            raise WindowsUpdateFixtureStageRecoveryError("Closed stage campaign identity changed.")
    finally:
        os.close(lock)
    if closed is not None:
        if (closed["lastOutcome"] != "failed-cleaned" or closed["lastEvidenceSha256"] != cleanup
                or closed["server"] != "stopped" or closed["credentials"] != "absent"):
            return False
        return lease.reconcile(root, intent["leaseId"], remote).get("state") == "closed"
    if active is not None and active["state"] == "role-active" and active["role"] == "stage" and \
            active["correlationId"] == _CORRELATION and active["server"] == "stopped" and \
            active["credentials"] == "absent":
        if not lease._remote_confirm(remote, "status", active, None):
            return False
        finished = lease.finish_role(root, intent["leaseId"], "stage", _CORRELATION, evidence,
                                     "failed-cleaned", remote)
        if finished.get("state") != "active":
            return False
        active = finished
    if active is not None:
        if (active["state"] != "active" or active["role"] is not None or active["server"] != "stopped"
                or active["credentials"] != "absent" or active["lastOutcome"] != "failed-cleaned"
                or active["lastEvidenceSha256"] != evidence
                or not lease._remote_confirm(remote, "status", active, None)):
            return False
        closing = {"guestGeneration": {"socketPath": descriptor[1], "qemuPid": descriptor[2],
                                         "startTicks": descriptor[3]}, "serverStopped": True,
                   "credentialsCleaned": True, "protectedJobsTerminalCleaned": True,
                   "activeInstallerProcessesAbsent": True, "cleanupReceiptSha256": cleanup}
        if lease.close(root, intent["leaseId"], closing, remote).get("state") != "closed":
            return False
    return lease.reconcile(root, intent["leaseId"], remote).get("state") == "closed"


def _remove_bundle(root: Path, intent: Mapping[str, Any]) -> bool:
    path = root / ".rag_index/windows-update-fixture-stage" / (_CORRELATION + ".zip")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return True
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size != intent.get("bundleSize")):
            return False
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != intent.get("bundleSha256"):
        return False
    path.unlink()
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return True


def recover(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Close and archive the one diagnosed pre-dispatch stage, never replay it."""
    _request(value)
    root = Path(root).resolve(strict=True)
    unknown = {"state": "unknown", "correlationId": _CORRELATION, "replayAllowed": False}
    try:
        receipt = _read_receipt(root)
        intent, pair, config, target, descriptor = _bound(root, receipt["state"] if receipt is not None else None)
        evidence, cleanup = _evidence(intent, descriptor)
        expected = {"version": 1, "correlationId": _CORRELATION, "leaseId": intent["leaseId"],
                    "guestGeneration": {"socketPath": descriptor[1], "qemuPid": descriptor[2],
                                        "startTicks": descriptor[3]}, "evidenceSha256": evidence,
                    "cleanupReceiptSha256": cleanup}
        if receipt is not None and {key: receipt[key] for key in expected} != expected:
            raise WindowsUpdateFixtureStageRecoveryError("Stage recovery receipt binding changed.")
        if receipt is None:
            first = stage.diagnose(root, {"correlationId": _CORRELATION})
            second = stage.diagnose(root, {"correlationId": _CORRELATION})
            exact = {"state": "unknown", "correlationId": _CORRELATION, "binding": "exact",
                     "phase": "guest-stage-absent", "replayAllowed": False,
                     "nativeActionAllowed": False}
            if first == exact and second == exact:
                cleaned = _remote_cleanup(intent, pair, config, target, descriptor)
                if not cleaned and not _remote_absence_reconciled(intent, pair, config, target, descriptor):
                    return unknown
            else:
                absent = {**exact, "phase": "remote-stage-absent"}
                # An exact empty job has no binding.json, so the diagnostic
                # intentionally classifies it as binding mismatch.  The fixed
                # reconcile program below rechecks that it is truly empty
                # before removing it; no other mismatch is admitted.
                empty = {**exact, "binding": "mismatch", "phase": "remote-binding-mismatch"}
                if ((first != absent or second != absent) and (first != empty or second != empty)) \
                        or not _remote_absence_reconciled(intent, pair, config, target, descriptor):
                    return unknown
            receipt = {**expected, "state": "remote-cleaned"}
            _write_receipt(root, receipt)
        elif receipt["state"] != "remote-cleaned":
            return unknown
        if not _idle(root, pair) or not _campaign_closed(root, intent, descriptor, config, target, evidence, cleanup):
            return unknown
        if not _remove_bundle(root, intent):
            return unknown
        recovered = {**expected, "state": "recovered"}
        if receipt != recovered:
            _replace_receipt(root, receipt, recovered)
        return {"state": "recovered", "correlationId": _CORRELATION,
                "cleanupReceiptSha256": cleanup, "replayAllowed": False}
    except (OSError, ValueError, KeyError, TypeError, WindowsUpdateFixtureStageRecoveryError,
            stage.WindowsUpdateFixtureStageError, base.WindowsMsiBasePrepareError, lease.Cp117LeaseError):
        return unknown
