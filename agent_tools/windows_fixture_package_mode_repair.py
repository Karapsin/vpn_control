"""One-shot CP117 repair for the ZIP-extraction ReadOnly MSI attribute.

This intentionally narrow recovery route can only set the ReadOnly bit on the
single target MSI proved by the existing CP117 stage/server records.  It never
accepts a guest path, command, artifact, or credential from its public input.
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

from . import windows_msi_base_prepare as base
from . import windows_msi_public_scenario as public
from . import windows_update_fixture_server as server
from . import windows_update_fixture_stage as stage


class WindowsFixturePackageModeRepairError(ValueError):
    pass


_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_LEAF = re.compile(r"packages/target/([A-Za-z0-9_.+-]{1,176}\.msi)\Z", re.IGNORECASE)
_GROUP = ".rag_index/windows-fixture-package-mode-repair"


def _canonical(value: Any) -> bool:
    return isinstance(value, str) and bool(_UUID.fullmatch(value)) and str(uuid.UUID(value)) == value


def _request(value: Mapping[str, Any]) -> dict[str, str]:
    fields = {"serverCorrelationId", "repairCorrelationId"}
    if not isinstance(value, Mapping) or set(value) != fields or not all(_canonical(value.get(k)) for k in fields):
        raise WindowsFixturePackageModeRepairError("Package-mode repair requires exact correlations.")
    if value["serverCorrelationId"] == value["repairCorrelationId"]:
        raise WindowsFixturePackageModeRepairError("Package-mode repair correlations must differ.")
    return dict(value)


def _status_request(value: Mapping[str, Any]) -> str:
    if not isinstance(value, Mapping) or set(value) != {"repairCorrelationId"} or not _canonical(value.get("repairCorrelationId")):
        raise WindowsFixturePackageModeRepairError("Package-mode repair status requires exact correlation.")
    return value["repairCorrelationId"]


def _path(root: Path, correlation: str) -> Path:
    return root / _GROUP / (correlation + ".json")


def _read(root: Path, correlation: str) -> dict[str, Any] | None:
    try:
        fd = os.open(_path(root, correlation), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
                or not 0 < info.st_size <= 16384):
            raise WindowsFixturePackageModeRepairError("Package-mode repair intent is unsafe.")
        try: record = json.load(stream)
        except (TypeError, ValueError) as error: raise WindowsFixturePackageModeRepairError("Package-mode repair intent is invalid.") from error
    if not isinstance(record, dict) or set(record) != {"version", "request", "stageCorrelationId", "targetMsiSha256", "targetLeaf", "guestGeneration"}:
        raise WindowsFixturePackageModeRepairError("Package-mode repair intent is invalid.")
    request = _request(record.get("request", {}))
    generation = record.get("guestGeneration")
    if (record.get("version") != 1 or request["repairCorrelationId"] != correlation
            or not _canonical(record.get("stageCorrelationId")) or not _HASH.fullmatch(record.get("targetMsiSha256", ""))
            or not isinstance(record.get("targetLeaf"), str) or not _LEAF.fullmatch("packages/target/" + record["targetLeaf"])
            or not isinstance(generation, dict) or set(generation) != {"socketPath", "qemuPid", "startTicks"}
            or not isinstance(generation["socketPath"], str) or type(generation["qemuPid"]) is not int or generation["qemuPid"] <= 0
            or type(generation["startTicks"]) is not int or generation["startTicks"] <= 0):
        raise WindowsFixturePackageModeRepairError("Package-mode repair intent is invalid.")
    return record


def _reserve(root: Path, record: Mapping[str, Any]) -> None:
    directory = root / _GROUP
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise WindowsFixturePackageModeRepairError("Package-mode repair journal is unsafe.")
    lock = os.open(directory / ".lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise WindowsFixturePackageModeRepairError("Package-mode repair journal is unsafe.")
        fcntl.flock(lock, fcntl.LOCK_EX)
        if _read(root, record["request"]["repairCorrelationId"]) is not None:
            raise WindowsFixturePackageModeRepairError("Package-mode repair correlation already exists.")
        raw = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        fd = os.open(_path(root, record["request"]["repairCorrelationId"]), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(parent)
        finally: os.close(parent)
    finally: os.close(lock)


_PS = r'''$ErrorActionPreference='Stop'
$path=@PATH@;$sha=@SHA@;$mutate=@MUTATE@
$out=@{version=1;file='absent';reparse='unknown';hash='unknown';readOnly='unknown';mutation='none'}
try {
 $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
 if($item.PSIsContainer){throw 'DIR'}
 $out.file='present'
 $out.reparse=if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){'present'}else{'absent'}
 if($out.reparse -ne 'absent'){throw 'REPARSE'}
 $actual=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
 $out.hash=if($actual -ceq $sha){'exact'}else{'mismatch'}
 if($out.hash -ne 'exact'){throw 'HASH'}
 $out.readOnly=if(($item.Attributes -band [IO.FileAttributes]::ReadOnly) -ne 0){'set'}else{'absent'}
 if($mutate){
  if($out.readOnly -ne 'absent'){throw 'ATTR'}
  $item.Attributes=$item.Attributes -bor [IO.FileAttributes]::ReadOnly
  $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
  $out.reparse=if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){'present'}else{'absent'}
  $actual=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  $out.hash=if($actual -ceq $sha){'exact'}else{'mismatch'}
  $out.readOnly=if(($item.Attributes -band [IO.FileAttributes]::ReadOnly) -ne 0){'set'}else{'absent'}
  $out.mutation=if($out.reparse -eq 'absent' -and $out.hash -eq 'exact' -and $out.readOnly -eq 'set'){'set'}else{'failed'}
 }
}catch{}
$out|ConvertTo-Json -Compress'''

_SYNTAX_PS = r'''$ErrorActionPreference='Stop';$source=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('@SOURCE@'));$tokens=$null;$errors=$null;[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)|Out-Null;[Console]::Out.WriteLine((@{version=1;syntax=$(if($errors.Count -eq 0){'valid'}else{'invalid'})}|ConvertTo-Json -Compress))'''

_REMOTE = base._QGA + r'''import time
sock,pid,ticks,encoded=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
phase='binding'
try:
 if not live(sock,pid,ticks):raise ValueError()
 phase='guest-launch'
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 phase='guest-wait'
 for _ in range(80):
  result=call(sock,'guest-exec-status',{'pid':child})
  if result.get('exited') is True:break
  if result.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 phase='guest-exit'
 if result.get('exitcode')!=0:raise ValueError()
 phase='guest-truncated'
 if result.get('out-truncated',False) is not False or result.get('err-truncated',False) is not False:raise ValueError()
 phase='guest-output'
 raw=base64.b64decode(result.get('out-data',''),validate=True)
 if not 0<len(raw)<=1024:raise ValueError()
 phase='guest-parse'
 out({'state':'observed','result':json.loads(decode(raw))})
except Exception:out({'state':'diagnosed','phase':phase})'''


def _target(stage_intent: Mapping[str, Any], target_sha: str) -> str:
    files = stage_intent.get("fileHashes")
    candidates = [(key, value) for key, value in files.items()] if isinstance(files, dict) else []
    matches = [(key, value, _LEAF.fullmatch(key)) for key, value in candidates if isinstance(key, str) and _LEAF.fullmatch(key)]
    if len(matches) != 1 or matches[0][1] != target_sha:
        raise WindowsFixturePackageModeRepairError("Exact staged target MSI changed.")
    return matches[0][2].group(1)


def _bound(root: Path, request: Mapping[str, str], *, require_failure: bool = True) -> tuple[dict[str, Any], Any, tuple[Any, ...]]:
    intent = server._read_intent(root, request["serverCorrelationId"])
    if intent is None or server._request(intent.get("request", {}))["serverCorrelationId"] != request["serverCorrelationId"]:
        raise WindowsFixturePackageModeRepairError("Exact server intent is unavailable.")
    server_request = server._request(intent["request"])
    stage_intent = stage._read_intent(root, server_request["stageCorrelationId"])
    expected_stage_request = {"host": server_request["host"], "correlationId": server_request["stageCorrelationId"],
                              "sourceSha": server_request["sourceSha"], "fixtureReceiptArtifactId": server_request["fixtureReceiptArtifactId"],
                              "baseMsiArtifactId": server_request["baseMsiArtifactId"], "targetMsiArtifactId": server_request["targetMsiArtifactId"]}
    if stage_intent is None or stage_intent.get("request") != expected_stage_request:
        raise WindowsFixturePackageModeRepairError("Exact stage intent changed.")
    pair = public._admit_pair(root, server_request["sourceSha"], server_request["fixtureReceiptArtifactId"], server_request["baseMsiArtifactId"], server_request["targetMsiArtifactId"])
    if intent.get("targetMsiSha256") != pair.get("targetMsiSha256"):
        raise WindowsFixturePackageModeRepairError("Exact server target changed.")
    staged = stage.status(root, {"correlationId": server_request["stageCorrelationId"]})
    if staged.get("state") != "staged-not-server-ready" or staged.get("targetMsiSha256") != pair["targetMsiSha256"]:
        raise WindowsFixturePackageModeRepairError("Exact stage is unavailable.")
    if require_failure:
        static = server.diagnose_static(root, {"serverCorrelationId": request["serverCorrelationId"]})
        task = server.diagnose_status(root, {"serverCorrelationId": request["serverCorrelationId"]})
        if static != {"state":"observed", "serverCorrelationId":request["serverCorrelationId"], "import":"ok", "certificate":"ok", "resources":"failed", "resourceGate":"package-mode", "replayAllowed":False}:
            raise WindowsFixturePackageModeRepairError("Package-mode cause is not exact.")
        if (task.get("state") != "observed" or task.get("task") != "ready" or task.get("lastResult") != 1
                or task.get("ready") != "absent" or task.get("stateContent") != "empty"
                or task.get("stageAcl") != "expected" or task.get("stateAcl") != "expected"):
            raise WindowsFixturePackageModeRepairError("Server failure evidence is not exact.")
    config, _target_host, descriptor = base._descriptor(root)
    env, socket, pid, ticks, _sid = descriptor
    if env != "windows-cp117" or any(intent.get(k) != v for k, v in (("socketPath", socket), ("qemuPid", pid), ("startTicks", ticks))):
        raise WindowsFixturePackageModeRepairError("Current CP117 generation changed.")
    return {"stageCorrelationId": server_request["stageCorrelationId"], "targetMsiSha256": pair["targetMsiSha256"], "targetLeaf": _target(stage_intent, pair["targetMsiSha256"]), "guestGeneration":{"socketPath":socket,"qemuPid":pid,"startTicks":ticks}}, config, descriptor


def _script(record: Mapping[str, Any], mutate: bool) -> str:
    leaf = record["targetLeaf"]
    path = r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-fixture-" + record["stageCorrelationId"] + "\\content\\packages\\target\\" + leaf
    return _PS.replace("@PATH@", public._ps_literal(path)).replace("@SHA@", public._ps_literal(record["targetMsiSha256"])).replace("@MUTATE@", "$true" if mutate else "$false")


def _run_script(config: Any, descriptor: tuple[Any, ...], script: str) -> dict[str, Any] | None:
    env, socket, pid, ticks, _sid = descriptor
    if env != "windows-cp117": return None
    raw = base._remote(config, _REMOTE, (socket, str(pid), str(ticks), base64.b64encode(script.encode("utf-16le")).decode()), None, 30)
    try: outer = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError): return None
    if (isinstance(outer, dict) and set(outer) == {"state", "phase"}
            and outer.get("state") == "diagnosed"
            and outer.get("phase") in {"binding", "guest-launch", "guest-wait", "guest-exit",
                                       "guest-truncated", "guest-output", "guest-parse"}):
        return {"version": 0, "phase": outer["phase"]}
    value = outer.get("result") if isinstance(outer, dict) and outer.get("state") == "observed" else None
    return value if isinstance(value, dict) else None


def _syntax(config: Any, descriptor: tuple[Any, ...], record: Mapping[str, Any]) -> str:
    source = base64.b64encode(_script(record, True).encode("utf-16le")).decode()
    script = _SYNTAX_PS.replace("@SOURCE@", source)
    value = _run_script(config, descriptor, script)
    return value["syntax"] if (isinstance(value, dict) and set(value) == {"version", "syntax"}
                               and value.get("version") == 1 and value.get("syntax") in {"valid", "invalid"}) else "unknown"


def _observe(config: Any, descriptor: tuple[Any, ...], record: Mapping[str, Any], mutate: bool) -> dict[str, Any] | None:
    env, socket, pid, ticks, _sid = descriptor
    if env != "windows-cp117" or record["guestGeneration"] != {"socketPath":socket, "qemuPid":pid, "startTicks":ticks}:
        return None
    value = _run_script(config, descriptor, _script(record, mutate))
    if not isinstance(value, dict) or set(value) != {"version", "file", "reparse", "hash", "readOnly", "mutation"} or value.get("version") != 1:
        return value if isinstance(value, dict) and set(value) == {"version", "phase"} and value.get("version") == 0 else None
    if value.get("file") not in {"absent", "present"} or value.get("reparse") not in {"unknown", "absent", "present"} or value.get("hash") not in {"unknown", "exact", "mismatch"} or value.get("readOnly") not in {"unknown", "absent", "set"} or value.get("mutation") not in {"none", "set", "failed"}:
        return None
    return value


def _unknown(correlation: str) -> dict[str, Any]:
    return {"state":"unknown", "repairCorrelationId":correlation, "replayAllowed":False, "nativeActionAllowed":False}


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    root = Path(root).resolve(strict=True); request = _request(value); correlation = request["repairCorrelationId"]
    if _read(root, correlation) is not None:
        return _unknown(correlation)
    binding, config, descriptor = _bound(root, request)
    record = {"version":1, "request":request, **binding}
    if _syntax(config, descriptor, record) != "valid":
        raise WindowsFixturePackageModeRepairError("Fixed package-mode repair script is not admitted.")
    _reserve(root, record)  # durable 0600 intent before the sole attribute mutation
    observed = _observe(config, descriptor, record, True)
    if observed != {"version":1,"file":"present","reparse":"absent","hash":"exact","readOnly":"set","mutation":"set"}:
        return _unknown(correlation)
    return {"state":"repaired", "repairCorrelationId":correlation, "replayAllowed":False, "nativeActionAllowed":False}


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    root = Path(root).resolve(strict=True); correlation = _status_request(value); record = _read(root, correlation)
    if record is None: return _unknown(correlation)
    try:
        request = _request(record["request"])
        binding, config, descriptor = _bound(root, request, require_failure=False)
        if any(record[k] != binding[k] for k in ("stageCorrelationId", "targetMsiSha256", "targetLeaf", "guestGeneration")):
            return _unknown(correlation)
        observed = _observe(config, descriptor, record, False)
    except (OSError, ValueError, TypeError, KeyError, WindowsFixturePackageModeRepairError):
        return _unknown(correlation)
    if observed == {"version":1,"file":"present","reparse":"absent","hash":"exact","readOnly":"set","mutation":"none"}:
        return {"state":"repaired", "repairCorrelationId":correlation, "replayAllowed":False, "nativeActionAllowed":False}
    return _unknown(correlation)


def collect(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    return status(root, value)


def diagnose(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Return only finite read-only phase and file facts for one consumed intent."""
    root = Path(root).resolve(strict=True); correlation = _status_request(value)
    record = _read(root, correlation)
    if record is None:
        return {"state": "diagnosed", "repairCorrelationId": correlation,
                "phase": "intent-absent", "replayAllowed": False}
    phase = "binding"
    try:
        request = _request(record["request"])
        binding, config, descriptor = _bound(root, request, require_failure=False)
        if any(record[k] != binding[k] for k in ("stageCorrelationId", "targetMsiSha256", "targetLeaf", "guestGeneration")):
            raise WindowsFixturePackageModeRepairError("Binding changed.")
        phase = "remote"
        observed = _observe(config, descriptor, record, False)
    except (OSError, ValueError, TypeError, KeyError, WindowsFixturePackageModeRepairError):
        observed = None
    if isinstance(observed, dict) and set(observed) == {"version", "phase"} and observed.get("version") == 0:
        phase = observed["phase"]
        if phase == "guest-exit":
            syntax = _syntax(config, descriptor, record)
            phase = "syntax-invalid" if syntax == "invalid" else "guest-exit"
    elif isinstance(observed, dict) and observed.get("version") == 1:
        phase = ("attribute-set" if observed == {"version":1,"file":"present","reparse":"absent",
                                                "hash":"exact","readOnly":"set","mutation":"none"}
                 else "file-fact")
    return {"state": "diagnosed", "repairCorrelationId": correlation,
            "phase": phase, "replayAllowed": False}
