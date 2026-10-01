"""Read-only CP117 observation of one persistent Windows Installer service process.

This diagnostic does not relax base readiness or authorize a product action.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping

from . import windows_msi_base_prepare as base
from . import windows_msi_public_scenario


class ServiceDiagnosticError(ValueError):
    pass


_CORRELATION = "c32cb108-4d48-407e-9153-40774559ba50"
_PROCESS_PID = 1932
_PROCESS_PARENT = 804
_PROCESS_STARTED_UTC = "2026-09-30T03:16:29.4825590Z"
_SOURCE = re.compile(r"[0-9a-f]{40}\Z")
_UNKNOWN = {"state": "unknown", "replayAllowed": False, "nativeActionAllowed": False,
            "productAction": False, "readinessAdmitted": False}


_PROCESS_PS = r'''$ErrorActionPreference='Stop'
$view=[ordered]@{state='observed';process='unknown';service='unknown';commandShape='unknown';otherInstallers='unknown';transaction='unknown';classification='unresolved'}
try {
 $p=Get-CimInstance Win32_Process -Filter 'ProcessId=1932' -ErrorAction Stop
 if ($null -eq $p) { $view.process='absent' }
 else {
  $started=$p.CreationDate.ToUniversalTime().ToString('o')
  if ($p.Name -cne 'msiexec.exe' -or $p.ProcessId -ne 1932 -or $started -cne '2026-09-30T03:16:29.4825590Z') { $view.process='generation-mismatch' }
  elseif ($p.ParentProcessId -ne 804 -or $p.SessionId -ne 0) { $view.process='identity-mismatch' }
  else {
   $owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop
   $view.process=$(if($owner.ReturnValue -eq 0 -and $owner.Sid -ceq 'S-1-5-18'){'exact'}else{'identity-mismatch'})
  }
  if ($null -eq $p.CommandLine) { $view.commandShape='unavailable' }
  elseif ($p.CommandLine -match '^\s*"?C:\\Windows\\System32\\msiexec\.exe"?\s+/V\s*$') { $view.commandShape='service-switch' }
  elseif ($p.CommandLine -match '(^|\s)/(?:i|x|package|uninstall|update|f|a|j)(\s|$)') { $view.commandShape='transaction-switch' }
  else { $view.commandShape='other' }
 }
 $svc=Get-CimInstance Win32_Service -Filter "Name='msiserver'" -ErrorAction Stop
 if ($null -eq $svc) { $view.service='absent' }
 elseif ($svc.ProcessId -eq 1932 -and $svc.State -eq 'Running') { $view.service='bound-running' }
 elseif ($svc.ProcessId -eq 1932) { $view.service='bound-not-running' }
 else { $view.service='different-pid' }
 $others=@(Get-CimInstance Win32_Process -Filter "Name='msiexec.exe'" -ErrorAction Stop|Where-Object {$_.ProcessId -ne 1932})
 $view.otherInstallers=$(if($others.Count -eq 0){'none'}elseif($others.Count -eq 1){'one'}elseif($others.Count -le 16){'many'}else{'unknown'})
 $view.transaction=$(if($view.otherInstallers -in @('one','many') -or $view.commandShape -eq 'transaction-switch'){'evidence-present'}elseif($view.otherInstallers -eq 'none'){'none-observed'}else{'unknown'})
 if ($view.process -eq 'absent') { $view.classification='process-absent' }
 elseif ($view.process -eq 'exact' -and $view.service -eq 'bound-running' -and $view.commandShape -eq 'service-switch' -and $view.transaction -eq 'none-observed') { $view.classification='service-idle-candidate' }
 elseif ($view.process -eq 'exact' -and $view.transaction -eq 'evidence-present') { $view.classification='active-transaction-evidence' }
} catch { $view.classification='unresolved' }
[Console]::Out.WriteLine(([pscustomobject]$view|ConvertTo-Json -Compress))
'''


_REMOTE = base._QGA + r'''import time
sock,pid,ticks=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks):raise ValueError()
 script=base64.b64decode('PS_B64').decode()
 encoded=base64.b64encode(script.encode('utf-16le')).decode('ascii')
 if len(encoded)>=30000:raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(40):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if (set(item)-{'exited','exitcode','out-data','err-data','out-truncated','err-truncated'}
  or type(item.get('exitcode')) is not int or item['exitcode']!=0
  or item.get('out-truncated',False) is not False or item.get('err-truncated',False) is not False):raise ValueError()
 raw=base64.b64decode(item.get('out-data',''),validate=True)
 if not 0<len(raw)<=1024:raise ValueError()
 lines=[v for v in decode(raw).splitlines() if v.startswith('{') and v.endswith('}')]
 value=json.loads(lines[0]) if len(lines)==1 else None
 if not isinstance(value,dict) or set(value)!={'state','process','service','commandShape','otherInstallers','transaction','classification'}:raise ValueError()
 out(value)
except Exception:out({'state':'unknown'})
'''.replace("PS_B64", base64.b64encode(_PROCESS_PS.encode()).decode())


_FIELDS = {"state", "process", "service", "commandShape", "otherInstallers", "transaction", "classification"}
_ENUMS = {
    "process": {"exact", "absent", "generation-mismatch", "identity-mismatch", "unknown"},
    "service": {"bound-running", "bound-not-running", "different-pid", "absent", "unknown"},
    "commandShape": {"service-switch", "transaction-switch", "other", "unavailable", "unknown"},
    "otherInstallers": {"none", "one", "many", "unknown"},
    "transaction": {"evidence-present", "none-observed", "unknown"},
    "classification": {"service-idle-candidate", "active-transaction-evidence", "process-absent", "unresolved"},
}


def _project(raw: bytes | None) -> dict[str, Any]:
    if raw is None or len(raw) > 1024:
        return dict(_UNKNOWN)
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return dict(_UNKNOWN)
    if not isinstance(value, dict) or set(value) != _FIELDS or value.get("state") != "observed":
        return dict(_UNKNOWN)
    for key, allowed in _ENUMS.items():
        if not isinstance(value[key], str) or value[key] not in allowed:
            return dict(_UNKNOWN)
    if (value["classification"] == "service-idle-candidate"
            and (value["process"] != "exact" or value["service"] != "bound-running"
                 or value["commandShape"] != "service-switch" or value["otherInstallers"] != "none"
                 or value["transaction"] != "none-observed")):
        return dict(_UNKNOWN)
    return {**value, "replayAllowed": False, "nativeActionAllowed": False,
            "productAction": False, "readinessAdmitted": False}


def _admit(root: Path) -> tuple[Any, tuple[str, str, int, int, str], str] | None:
    intent = base._private_intent(root, _CORRELATION)
    if intent is None:
        return None
    config, _target, descriptor = base._descriptor(root)
    env, socket, pid, ticks, sid = descriptor
    if any(intent.get(key) != expected for key, expected in (("environment", env), ("socketPath", socket),
            ("pid", pid), ("startTicks", ticks), ("expectedSid", sid))):
        return None
    request = intent.get("request")
    pair = intent.get("pair")
    if (not isinstance(request, dict) or not isinstance(pair, dict)
            or request.get("correlationId") != _CORRELATION
            or not isinstance(request.get("sourceSha"), str) or not _SOURCE.fullmatch(request["sourceSha"])
            or pair.get("sourceSha") != request["sourceSha"] or pair.get("baseVersion") != "2.1.19"):
        return None
    terminal = base.status(root, {"correlationId": _CORRELATION})
    if (terminal.get("state") != "terminal" or terminal.get("result") != "PASSED"
            or terminal.get("stage") != "READBACK" or terminal.get("exitCode") != 0
            or terminal.get("sourceSha") != request["sourceSha"]
            or terminal.get("baseArtifactId") != request.get("baseMsiArtifactId")):
        return None
    return config, descriptor, request["sourceSha"]


def _preflight_script() -> str:
    body = base64.b64encode(_PROCESS_PS.encode("utf-16le")).decode()
    return r'''$ErrorActionPreference='Stop'
try {
 $body=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('@BODY@'))
 $tokens=$null;$errors=$null
 [System.Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)|Out-Null
 if($errors.Count -ne 0){throw 'SYNTAX'}
 [Console]::Out.WriteLine('{"version":1,"code":"OK"}')
} catch { [Console]::Out.WriteLine('{"version":1,"code":"FAILED"}');exit 1 }
'''.replace("@BODY@", body)


def workflow(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Fixed read-only facade for one observed CP117 installer service process."""
    if (not isinstance(action, str) or action not in {"preflight", "status"}
            or not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}):
        raise ServiceDiagnosticError("Exact CP117 service diagnostic action and host are required.")
    try:
        root = Path(root).resolve(strict=True)
        admitted = _admit(root)
        if admitted is None:
            return dict(_UNKNOWN)
        config, (_env, socket, pid, ticks, _sid), source = admitted
        if action == "preflight":
            encoded = base64.b64encode(_preflight_script().encode("utf-16le")).decode()
            if len(encoded) >= 30000:
                return dict(_UNKNOWN)
            raw = base._remote(config, windows_msi_public_scenario._REMOTE_PREFLIGHT,
                               (socket, str(pid), str(ticks), encoded), None, 30)
            value = json.loads(raw) if raw is not None else None
            if value != {"state": "passed", "checks": ["ps5-parse", "gzip", "utf8-pipeline"]}:
                return dict(_UNKNOWN)
            return {"state": "passed", "correlationId": _CORRELATION, "sourceSha": source,
                    "replayAllowed": False, "nativeActionAllowed": False,
                    "productAction": False, "readinessAdmitted": False}
        raw = base._remote(config, _REMOTE, (socket, str(pid), str(ticks)), None, 30)
        value = _project(raw)
        if value.get("state") != "observed":
            return dict(_UNKNOWN)
        return {**value, "correlationId": _CORRELATION, "sourceSha": source}
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        return dict(_UNKNOWN)
