"""Bounded CP117 ACL exercise before a future fixture server role is claimed.

The prior server attempt reached ``probe-events`` and then failed with an OWNER
RIGHTS principal.  This preflight runs the same staged fixture helper against a
new, nonce-named directory only.  QGA executes as SYSTEM, so it proves the
CPython 0700 ACL and SYSTEM-context normalizer behavior, not an original-user
token.  It never reads or changes the failed server state, campaign journal,
Scheduler, package artifacts, or product runtime.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
import re
import uuid
from typing import Any, Mapping

from . import windows_msi_base_prepare as base
from . import windows_update_fixture_server as server
from . import windows_update_fixture_stage as stage


class WindowsFixtureAclPreflightError(ValueError):
    pass


_STAGE_CORRELATION = "e848bed2-5bea-47bc-a85a-6cf17b1fcc6a"
_FAILED_SERVER_CORRELATION = "316e6189-5be0-4ea0-bca1-a3905816d815"
_EXPECTED_INPUT = {"stageCorrelationId": _STAGE_CORRELATION}
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_PYTHON_PATH = re.compile(r"C:\\(?:Program Files\\Python3(?:1[1-4])|Users\\vpncp117\\AppData\\Local\\Programs\\Python\\Python3(?:1[1-4]))\\python\.exe\Z", re.I)
_APP_PARENT = r"C:\Users\vpncp117\AppData\Local\VpnControl"
_UNKNOWN = {"state": "unknown", "stageCorrelationId": _STAGE_CORRELATION,
            "phase": "unknown", "comparison": "unknown", "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}


# The guest program carries no host supplied path, SID, credential, command, or
# task name.  The nonce is used only in the exact disposable directory name and
# is never returned.  ``probe_events_path`` and ``windows_acl_receipt`` are the
# exact ACL helpers staged with the fixture source.
_EXERCISE_CODE = r'''import importlib.util,json,os,pathlib,shutil,stat,sys
stage=pathlib.Path(sys.argv[1]);nonce=sys.argv[2];entry=stage/'server'/'prepare_desktop_update_fixture.py'
out={'version':1,'modes':{'fixture-0700':{'initial':'unknown','normalizer':'unknown'},'control-0777':{'initial':'unknown','normalizer':'unknown'}}}
root=pathlib.Path(r'C:\Users\vpncp117\AppData\Local\VpnControl')/('mcp-acl-preflight-'+nonce)
created=False
def unsafe(path):
 try:
  item=os.lstat(path)
  return stat.S_ISLNK(item.st_mode) or bool(getattr(item,'st_file_attributes',0)&getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0))
 except Exception:return True
try:
 if not entry.is_file() or entry.is_symlink() or not root.parent.is_dir() or unsafe(root.parent) or root.exists():raise ValueError()
 root.mkdir(mode=0o777)
 created=True
 if not root.is_dir() or unsafe(root):raise ValueError()
 spec=importlib.util.spec_from_file_location('fixture_acl_preflight',entry);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 module.require_windows_private_acl(root,private=True,directory=True)
 def compare(path):
  receipt=module.windows_acl_receipt(path,private=True,establish=False);acl=receipt.get('acl') if isinstance(receipt,dict) else None;current=receipt.get('currentSid') if isinstance(receipt,dict) else None;full=0x1F01FF;expected={'S-1-5-18','S-1-5-32-544',current}
  exact=(receipt.get('protected') is True and receipt.get('isDirectory') is True and isinstance(current,str) and isinstance(acl,list) and len(acl)==3 and {item.get('sid') for item in acl if isinstance(item,dict)}==expected and all(isinstance(item,dict) and item.get('type')=='Allow' and item.get('inherited') is False and item.get('propagation')==0 and item.get('rights')==full and item.get('inheritance')==3 for item in acl))
  values={item.get('sid') for item in acl if isinstance(item,dict)} if isinstance(acl,list) else set()
  return 'owner-rights' if 'S-1-3-4' in values else 'match' if exact else 'mismatch'
 try:
  events=root/'fixture-0700';events.mkdir(mode=0o700)
  if not events.is_dir() or unsafe(events):raise ValueError()
  out['modes']['fixture-0700']['initial']=compare(events)
  module.require_windows_private_acl(events,private=True,directory=True)
  out['modes']['fixture-0700']['normalizer']=compare(events)
 except Exception:pass
 try:
  control=root/'control-0777';control.mkdir(mode=0o777)
  if not control.is_dir() or unsafe(control):raise ValueError()
  out['modes']['control-0777']['initial']=compare(control)
  module.require_windows_private_acl(control,private=True,directory=True)
  out['modes']['control-0777']['normalizer']=compare(control)
 except Exception:pass
except Exception:pass
finally:
 try:
  if created and root.exists():
   if unsafe(root):raise ValueError()
   shutil.rmtree(root)
   if root.exists():raise ValueError()
 except Exception:out={'version':1,'modes':{'fixture-0700':{'initial':'unknown','normalizer':'unknown'},'control-0777':{'initial':'unknown','normalizer':'unknown'}}}
print(json.dumps(out,separators=(',',':')))'''


_REMOTE_EXERCISE = base._QGA + r'''import base64,json,time
sock,pid,ticks,python,expected_sha,stage,nonce,code=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
phase='binding'
try:
 if not live(sock,pid,ticks):raise ValueError()
 phase='python-verify'
 path64=base64.b64encode(python.encode('utf-16le')).decode()
 verifier="$ErrorActionPreference='Stop';$p=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('"+path64+"'));$sig=Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop;if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Python Software Foundation'){throw 'SIGNER'};[Console]::Out.Write((Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant())"
 check=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(verifier.encode('utf-16le')).decode()],'capture-output':True})['pid']
 if type(check) is not int or check<=0:raise ValueError()
 for _ in range(80):
  status=call(sock,'guest-exec-status',{'pid':check})
  if status.get('exited') is True:break
  if status.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if status.get('exitcode')!=0 or status.get('out-truncated',False) is not False or status.get('err-truncated',False) is not False or decode(base64.b64decode(status.get('out-data',''),validate=True)).strip().lower()!=expected_sha:raise ValueError()
 phase='guest-launch'
 child=call(sock,'guest-exec',{'path':python,'arg':['-I','-B','-c',base64.b64decode(code,validate=True).decode(),stage,nonce],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 phase='guest-wait'
 for _ in range(120):
  result=call(sock,'guest-exec-status',{'pid':child})
  if result.get('exited') is True:break
  if result.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 phase='guest-exit-nonzero'
 if result.get('exitcode')!=0:raise ValueError()
 phase='guest-output-truncation'
 if result.get('out-truncated',False) is not False or result.get('err-truncated',False) is not False:raise ValueError()
 phase='guest-output-length'
 raw=base64.b64decode(result.get('out-data',''),validate=True)
 if not 0<len(raw)<=256:raise ValueError()
 phase='guest-output-parse'
 out({'state':'observed','result':json.loads(decode(raw))})
except Exception:out({'state':'unknown','phase':phase})'''


_REMOTE_STATUS = base._QGA + r'''import base64,json,time
sock,pid,ticks,python,expected_sha=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
phase='binding'
try:
 if not live(sock,pid,ticks):raise ValueError()
 phase='guest-launch'
 path64=base64.b64encode(python.encode('utf-16le')).decode()
 script="$ErrorActionPreference='Stop';$parent='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl';$p=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('"+path64+"'));$items=@(Get-ChildItem -LiteralPath $parent -Force -ErrorAction Stop|Where-Object {$_.Name -like 'mcp-acl-preflight-*'});$count=if($items.Count -eq 0){'zero'}elseif($items.Count -eq 1){'one'}else{'multiple'};$sig=Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop;$hash=(Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant();@{version=1;scratch=$count;signatureValid=($sig.Status -eq 'Valid');signerMatches=($sig.SignerCertificate.Subject -match 'Python Software Foundation');shaMatches=($hash -ceq '@HASH@')}|ConvertTo-Json -Compress".replace('@HASH@',expected_sha)
 encoded=base64.b64encode(script.encode('utf-16le')).decode()
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
 if result.get('exitcode')!=0 or result.get('out-truncated',False) is not False or result.get('err-truncated',False) is not False:raise ValueError()
 phase='guest-output'
 raw=base64.b64decode(result.get('out-data',''),validate=True)
 if not 0<len(raw)<=512:raise ValueError()
 phase='guest-parse'
 out({'state':'observed','result':json.loads(decode(raw))})
except Exception:out({'state':'unknown','phase':phase})'''


def _inputs(value: Mapping[str, Any]) -> None:
    if not isinstance(value, Mapping) or dict(value) != _EXPECTED_INPUT:
        raise WindowsFixtureAclPreflightError("ACL preflight requires the fixed CP117 stage.")


def _bound(root: Path) -> tuple[Any, tuple[Any, ...], str, str, str]:
    """Bind the frozen source, current CP117 generation, and signed interpreter."""
    intent = server._read_intent(root, _FAILED_SERVER_CORRELATION)
    if not isinstance(intent, Mapping):
        raise WindowsFixtureAclPreflightError("Frozen CP117 server intent is unavailable.")
    request = server._request(intent.get("request", {}))
    if request.get("stageCorrelationId") != _STAGE_CORRELATION:
        raise WindowsFixtureAclPreflightError("Frozen CP117 stage changed.")
    config, _target, descriptor = base._descriptor(root)
    environment, socket, pid, ticks, sid = descriptor
    if (environment != "windows-cp117" or (socket, pid, ticks, sid) !=
            (intent.get("socketPath"), intent.get("qemuPid"), intent.get("startTicks"),
             intent.get("originalSid"))):
        raise WindowsFixtureAclPreflightError("CP117 VM generation changed.")
    staged = stage.status(root, {"correlationId": _STAGE_CORRELATION})
    hashes = staged.get("fileHashes") if isinstance(staged, Mapping) else None
    source_hash = hashes.get("server/prepare_desktop_update_fixture.py") if isinstance(hashes, Mapping) else None
    if (staged.get("state") != "staged-not-server-ready" or staged.get("sourceSha") != request["sourceSha"]
            or not isinstance(source_hash, str) or not _HASH.fullmatch(source_hash)):
        raise WindowsFixtureAclPreflightError("Frozen fixture source is unavailable.")
    python = intent.get("pythonPath")
    python_sha = intent.get("pythonExeSha256")
    if not isinstance(python, str) or not _PYTHON_PATH.fullmatch(python) or not isinstance(python_sha, str) or not _HASH.fullmatch(python_sha):
        raise WindowsFixtureAclPreflightError("Frozen signed Python is unavailable.")
    content = (r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-fixture-"
               + _STAGE_CORRELATION + r"\content")
    return config, descriptor, python, python_sha, content


def _project(raw: Any) -> dict[str, Any]:
    if (isinstance(raw, Mapping) and set(raw) == {"state", "phase"} and raw.get("state") == "unknown"
            and raw.get("phase") in {"binding", "python-verify", "guest-launch", "guest-wait",
                                       "guest-exit-nonzero", "guest-output-truncation",
                                       "guest-output-length", "guest-output-parse"}):
        return {**_UNKNOWN, "phase": raw["phase"]}
    if not isinstance(raw, Mapping) or set(raw) != {"state", "result"} or raw.get("state") != "observed":
        return dict(_UNKNOWN)
    result = raw["result"]
    modes = result.get("modes") if isinstance(result, Mapping) else None
    names = {"fixture-0700", "control-0777"}
    if (not isinstance(result, Mapping) or set(result) != {"version", "modes"} or result.get("version") != 1
            or not isinstance(modes, Mapping) or set(modes) != names):
        return dict(_UNKNOWN)
    sanitized = {}
    for name in sorted(names):
        mode = modes[name]
        if (not isinstance(mode, Mapping) or set(mode) != {"initial", "normalizer"}
                or mode.get("initial") not in {"match", "owner-rights", "mismatch", "unknown"}
                or mode.get("normalizer") not in {"match", "owner-rights", "mismatch", "unknown"}):
            return dict(_UNKNOWN)
        sanitized[name] = {"initial": mode["initial"], "normalizer": mode["normalizer"]}
    ready = (sanitized["fixture-0700"] == {"initial": "match", "normalizer": "match"}
             and sanitized["control-0777"]["normalizer"] == "match")
    return {"state": "ready" if ready else "blocked", "stageCorrelationId": _STAGE_CORRELATION,
            "modes": sanitized, "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}


def preflight(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Exercise the staged ACL helper before a server role or task can be created."""
    _inputs(inputs)
    root_path = Path(root).resolve(strict=True)
    try:
        config, descriptor, python, python_sha, content = _bound(root_path)
        _environment, socket, pid, ticks, _sid = descriptor
        nonce = str(uuid.uuid4())
        raw = base._remote(config, _REMOTE_EXERCISE,
                           (socket, str(pid), str(ticks), python, python_sha, content, nonce,
                            base64.b64encode(_EXERCISE_CODE.encode()).decode()), None, 45)
        return _project(json.loads(raw) if raw is not None else None)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError,
            WindowsFixtureAclPreflightError, server.WindowsUpdateFixtureServerError,
            stage.WindowsUpdateFixtureStageError, base.WindowsMsiBasePrepareError):
        return dict(_UNKNOWN)


def status(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Read the disposable-scratch census and frozen Python state without mutation."""
    _inputs(inputs)
    root_path = Path(root).resolve(strict=True)
    unknown = {"state": "unknown", "stageCorrelationId": _STAGE_CORRELATION,
               "scratch": "unknown", "signatureValid": "unknown", "signerMatches": "unknown",
               "shaMatches": "unknown", "phase": "unknown", "replayAllowed": False, "nativeActionAllowed": False,
               "productAction": False}
    try:
        config, descriptor, python, python_sha, _content = _bound(root_path)
        _environment, socket, pid, ticks, _sid = descriptor
        raw = base._remote(config, _REMOTE_STATUS, (socket, str(pid), str(ticks), python, python_sha), None, 30)
        value = json.loads(raw) if raw is not None else None
        if (isinstance(value, Mapping) and set(value) == {"state", "phase"} and value.get("state") == "unknown"
                and value.get("phase") in {"binding", "guest-launch", "guest-wait", "guest-exit", "guest-output", "guest-parse"}):
            return {**unknown, "phase": value["phase"]}
        result = value.get("result") if isinstance(value, Mapping) and set(value) == {"state", "result"} and value.get("state") == "observed" else None
        if (not isinstance(result, Mapping) or set(result) != {"version", "scratch", "signatureValid", "signerMatches", "shaMatches"}
                or result.get("version") != 1 or result.get("scratch") not in {"zero", "one", "multiple"}
                or any(type(result.get(key)) is not bool for key in ("signatureValid", "signerMatches", "shaMatches"))):
            return unknown
        return {"state": "observed", "stageCorrelationId": _STAGE_CORRELATION,
                "scratch": result["scratch"], "signatureValid": result["signatureValid"],
                "signerMatches": result["signerMatches"], "shaMatches": result["shaMatches"],
                "phase": "complete", "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError,
            WindowsFixtureAclPreflightError, server.WindowsUpdateFixtureServerError,
            stage.WindowsUpdateFixtureStageError, base.WindowsMsiBasePrepareError):
        return unknown
