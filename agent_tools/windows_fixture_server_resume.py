"""One-shot resume of CP117 server start after proven pre-dispatch rejection."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Mapping

from . import windows_cp117_lease as lease
from . import windows_msi_base_prepare as base
from . import windows_msi_public_scenario as public
from . import windows_update_fixture_server as server
from . import windows_update_fixture_stage as stage


_CORRELATION = "316e6189-5be0-4ea0-bca1-a3905816d815"
_INTENT_DIR = ".rag_index/windows-fixture-server-resume"


class WindowsFixtureServerResumeError(ValueError):
    pass


_REMOTE_PRE_DISPATCH = base._QGA + lease.remote_role_guard() + r'''import json,os,stat,sys,time
root,env,lease_id,corr,sock,pid,ticks,source,receipt_id,base_id,target_id=sys.argv[1:]
def out(value):print(json.dumps(value,sort_keys=True,separators=(',',':')))
try:
 if env!='windows-cp117' or not live(sock,pid,ticks):raise ValueError()
 require_campaign_role(root,env,lease_id,'server-start',corr,source,receipt_id,base_id,target_id,sock,pid,ticks)
 group=os.path.join(root,env,'windows-update-fixture-server');info=os.lstat(group)
 if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 if os.path.lexists(os.path.join(group,corr)):
  out({'state':'blocked','phase':'remote-journal'});raise SystemExit(0)
 task='VpnControlMcpFixtureServer-'+corr
 ps="$ErrorActionPreference='Stop';$t=Get-ScheduledTask -TaskPath '\\' -TaskName '"+task+"' -ErrorAction SilentlyContinue;$p=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.ProcessId -ne $PID -and $_.CommandLine -like '*"+corr+"*'});if($null -ne $t -or $p.Count -ne 0){exit 7}"
 encoded=base64.b64encode(ps.encode('utf-16le')).decode();child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(120):
  result=call(sock,'guest-exec-status',{'pid':child})
  if result.get('exited') is True:break
  if result.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 out({'state':'ready' if result.get('exitcode')==0 else 'blocked','phase':'guest-absence'})
except SystemExit:raise
except Exception:out({'state':'unknown','phase':'preflight'})
'''


def _request(value: Mapping[str, Any]) -> str:
    if not isinstance(value, Mapping) or set(value) != {"serverCorrelationId"} or value.get("serverCorrelationId") != _CORRELATION:
        raise WindowsFixtureServerResumeError("Only the exact pre-dispatch CP117 server attempt can resume.")
    return _CORRELATION


def _intent_path(root: Path) -> Path:
    return root / _INTENT_DIR / (_CORRELATION + ".json")


def _read_resume_intent(root: Path) -> dict[str, Any] | None:
    try:
        fd = os.open(_intent_path(root), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 1024):
            raise WindowsFixtureServerResumeError("Resume intent is unsafe.")
        value = json.load(stream)
    return value if isinstance(value, dict) else None


def _reserve(root: Path, value: Mapping[str, Any]) -> None:
    directory = root / _INTENT_DIR
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsFixtureServerResumeError("Resume intent directory is unsafe.")
    raw = (json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(_intent_path(root), os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try: os.fsync(parent)
    finally: os.close(parent)


def _admit(root: Path) -> tuple[Any, Any, dict[str, Any], dict[str, Any], tuple[Any, ...], str, str]:
    intent = server._read_intent(root, _CORRELATION)
    if intent is None:
        raise WindowsFixtureServerResumeError("Original server intent is absent.")
    request = server._request(intent.get("request", {}))
    config, target, descriptor = base._descriptor(root)
    env, socket, pid, ticks, sid = descriptor
    if (env != "windows-cp117" or (socket, pid, ticks, sid) !=
            (intent.get("socketPath"), intent.get("qemuPid"), intent.get("startTicks"), intent.get("originalSid"))):
        raise WindowsFixtureServerResumeError("Guest generation changed.")
    pair = public._admit_pair(root, request["sourceSha"], request["fixtureReceiptArtifactId"],
                              request["baseMsiArtifactId"], request["targetMsiArtifactId"])
    staged = stage.status(root, {"correlationId": request["stageCorrelationId"]})
    script_hash = staged.get("fileHashes", {}).get("server/prepare_desktop_update_fixture.py")
    if (staged.get("state") != "staged-not-server-ready" or staged.get("sourceSha") != request["sourceSha"]
            or staged.get("targetMsiSha256") != pair["targetMsiSha256"]
            or not isinstance(script_hash, str) or not server._HASH.fullmatch(script_hash)):
        raise WindowsFixtureServerResumeError("Exact stage changed.")
    tls = server._private_tls_descriptor(root, request)
    python = {"path": intent.get("pythonPath"), "sha256": intent.get("pythonExeSha256"),
              "version": intent.get("pythonVersion")}
    if (not isinstance(python["path"], str) or not server._PYTHON_PATH.fullmatch(python["path"])
            or not isinstance(python["sha256"], str) or not server._HASH.fullmatch(python["sha256"])):
        raise WindowsFixtureServerResumeError("Frozen signed Python identity changed.")
    arguments = server._launch_arguments(request, tls)
    script = server._launch_script(request, pair, tls, python, script_hash, arguments)
    command_hash = hashlib.sha256(script.encode("utf-16le")).hexdigest()
    if (command_hash != intent.get("commandSha256")
            or hashlib.sha256(arguments.encode()).hexdigest() != intent.get("launchArgumentsSha256")
            or pair["sourceFingerprint"] != intent.get("sourceFingerprint")
            or pair["targetMsiSha256"] != intent.get("targetMsiSha256")
            or tls["certificateSha256"] != intent.get("certificateSha256")
            or tls["privateKeySha256"] != intent.get("privateKeySha256")
            or tls["trustStoreSha256"] != intent.get("trustStoreSha256")):
        raise WindowsFixtureServerResumeError("Frozen server command changed.")
    directory, lock = lease._locked(root)
    try:
        current = lease._active(directory)
        expected = base._campaign_identity({**request, "correlationId": request["leaseId"]}, descriptor)
        if (not isinstance(current, Mapping) or current.get("identity") != expected
                or current.get("state") != "role-active" or current.get("role") != "server-start"
                or current.get("correlationId") != _CORRELATION or current.get("server") != "starting"
                or current.get("credentials") != "ready"):
            raise WindowsFixtureServerResumeError("Server-start role changed.")
        if not lease._remote_confirm(base._campaign_remote(config, target), "status", current, None):
            raise WindowsFixtureServerResumeError("Remote server-start role changed.")
    finally:
        os.close(lock)
    return config, target, request, pair, descriptor, script, command_hash


def _preflight(config: Any, target: Any, request: Mapping[str, str], descriptor: tuple[Any, ...]) -> bool:
    env, socket, pid, ticks, _sid = descriptor
    raw = base._remote(config, _REMOTE_PRE_DISPATCH,
                       (str(target.fixture_transfer_root), env, request["leaseId"], _CORRELATION,
                        socket, str(pid), str(ticks), request["sourceSha"],
                        request["fixtureReceiptArtifactId"], request["baseMsiArtifactId"],
                        request["targetMsiArtifactId"]), None, 60)
    try: result = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError): result = None
    return result == {"state": "ready", "phase": "guest-absence"}


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    correlation = _request(value)
    unknown = {"state": "unknown", "serverCorrelationId": correlation, "replayAllowed": False,
               "nativeActionAllowed": False, "productAction": False}
    try:
        root_path = Path(root).resolve(strict=True)
        if _read_resume_intent(root_path) is not None:
            return unknown
        config, target, request, pair, descriptor, script, command_hash = _admit(root_path)
        if not _preflight(config, target, request, descriptor):
            return unknown
        _reserve(root_path, {"version": 1, "serverCorrelationId": correlation,
                             "commandSha256": command_hash, "guestGeneration": list(descriptor[1:4])})
        env, socket, pid, ticks, sid = descriptor
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        raw = base._remote(config, server._REMOTE_START,
                           (str(target.fixture_transfer_root), env, request["leaseId"], correlation,
                            request["stageCorrelationId"], socket, str(pid), str(ticks), sid,
                            request["sourceSha"], pair["sourceFingerprint"],
                            request["fixtureReceiptArtifactId"], request["baseMsiArtifactId"],
                            request["targetMsiArtifactId"], encoded, command_hash), None, 120)
        try: result = json.loads(raw) if raw is not None else None
        except (TypeError, ValueError): result = None
        if result == {"state": "submitted", "serverCorrelationId": correlation}:
            return {"state": "submitted", "serverCorrelationId": correlation,
                    "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
    except (OSError, ValueError, KeyError, TypeError, FileExistsError, WindowsFixtureServerResumeError,
            lease.Cp117LeaseError, base.WindowsMsiBasePrepareError,
            server.WindowsUpdateFixtureServerError):
        pass
    return unknown
