"""Read-only, source-bound CP117 owner-liveness census."""

from __future__ import annotations

import base64
import json
from pathlib import Path
import re
from typing import Any, Mapping

from . import windows_msi_base_prepare as base


class WindowsMsiOwnerLivenessError(ValueError):
    pass


_CORRELATION = "c32cb108-4d48-407e-9153-40774559ba50"
_SOURCE = re.compile(r"[0-9a-f]{40}\Z")
_UNKNOWN = {"state": "unknown", "replayAllowed": False, "nativeActionAllowed": False}
_COUNTS = {"none", "one", "many", "ambiguous"}
_LEAVES = {"none", "one", "both", "ambiguous"}


_LIVENESS_PS = r'''$ErrorActionPreference='Stop'
try {
 $sid='__SID__';$expectedHash='__CLI_HASH__';$expectedVersion='2.1.19'
 $install='C:\Users\vpncp117\AppData\Local\vpn-control';$cli=Join-Path $install 'vpn-control-cli.exe';$gui=Join-Path $install 'vpn-control.exe'
 $state='C:\Users\vpncp117\AppData\Local\VpnControl\cp166\state'
 $cliItem=Get-Item -LiteralPath $cli -Force -ErrorAction Stop
 if($cliItem.PSIsContainer -or (($cliItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or (Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedHash){throw 'CLI'}
 $products=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',('Registry::HKEY_USERS\'+$sid+'\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'),('Registry::HKEY_USERS\'+$sid+'\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') -ErrorAction SilentlyContinue|Where-Object {$_.DisplayName -eq 'vpn-control'})
 if($products.Count -ne 1 -or $products[0].DisplayVersion -cne $expectedVersion -or $products[0].InstallLocation.TrimEnd('\') -cne $install){throw 'PRODUCT'}
 function C([object[]]$items){if($items.Count -eq 0){'none'}elseif($items.Count -eq 1){'one'}elseif($items.Count -le 16){'many'}else{'ambiguous'}}
 $all=@(Get-CimInstance Win32_Process -ErrorAction Stop)
 $apps=@($all|Where-Object {$_.Name -in @('vpn-control.exe','vpn-control-cli.exe')})
 $ownerState=C $apps
 foreach($app in $apps){
  $owner=Invoke-CimMethod -InputObject $app -MethodName GetOwnerSid -ErrorAction Stop
  $expected=if($app.Name -ceq 'vpn-control-cli.exe'){$cli}else{$gui}
  if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $sid -or $app.SessionId -ne 1 -or $app.ExecutablePath -cne $expected){$ownerState='ambiguous'}
 }
 $installerState=C @($all|Where-Object {$_.Name -ceq 'msiexec.exe'})
 $consentState=C @($all|Where-Object {$_.Name -ceq 'consent.exe'})
 $runtimeState=C @($all|Where-Object {$_.Name -ceq 'sing-box.exe'})
 $leafPaths=@((Join-Path $state 'vpn-control.lock'),(Join-Path $state 'activation.port'));$present=0;$leafAmbiguous=$false
 foreach($leaf in $leafPaths){
  try{
   if(Test-Path -LiteralPath $leaf){$item=Get-Item -LiteralPath $leaf -Force -ErrorAction Stop;if($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){$leafAmbiguous=$true}else{$present++}}
  }catch{$leafAmbiguous=$true}
 }
 $leaves=if($leafAmbiguous){'ambiguous'}elseif($present -eq 0){'none'}elseif($present -eq 1){'one'}elseif($present -eq 2){'both'}else{'ambiguous'}
 $runtimeOff=($runtimeState -eq 'none')
 $result=if($ownerState -eq 'none' -and $installerState -eq 'none' -and $consentState -eq 'none' -and $runtimeOff -and $leaves -eq 'none'){'absent'}else{'blocked'}
 [Console]::Out.WriteLine(([pscustomobject]@{version=1;state=$result;ownerProcesses=$ownerState;installerProcesses=$installerState;consentProcesses=$consentState;runtimeProcesses=$runtimeState;stateLeaves=$leaves;runtimeOff=$runtimeOff}|ConvertTo-Json -Compress))
}catch{[Console]::Out.WriteLine('{"version":1,"state":"unknown"}')}
'''


_REMOTE = base._QGA + r'''import time
sock,pid,ticks,sid,cli_hash=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks):raise ValueError()
 script=LIVENESS_PS.replace('__SID__',sid).replace('__CLI_HASH__',cli_hash)
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(script.encode('utf-16le')).decode()],'capture-output':True}).get('pid')
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(160):
  observed=call(sock,'guest-exec-status',{'pid':child})
  if observed.get('exited') is True:break
  if observed.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if type(observed.get('exitcode')) is not int or observed['exitcode']!=0 or observed.get('out-truncated') is True or observed.get('err-truncated') is True:raise ValueError()
 raw=base64.b64decode(observed.get('out-data',''),validate=True)
 if not 0<len(raw)<=1024:raise ValueError()
 lines=[line for line in decode(raw).splitlines() if line.startswith('{') and line.endswith('}')]
 if len(lines)!=1:raise ValueError()
 value=json.loads(lines[0])
 fields={'version','state','ownerProcesses','installerProcesses','consentProcesses','runtimeProcesses','stateLeaves','runtimeOff'}
 if not isinstance(value,dict) or set(value)!=fields or value.get('version')!=1 or value.get('state') not in {'absent','blocked'}:raise ValueError()
 if any(value.get(key) not in COUNTS for key in ('ownerProcesses','installerProcesses','consentProcesses','runtimeProcesses')) or value.get('stateLeaves') not in LEAVES or type(value.get('runtimeOff')) is not bool:raise ValueError()
 if value['runtimeOff'] != (value['runtimeProcesses']=='none') or (value['state']=='absent' and not (value['ownerProcesses']=='none' and value['installerProcesses']=='none' and value['consentProcesses']=='none' and value['runtimeOff'] and value['stateLeaves']=='none')):raise ValueError()
 out(value)
except Exception:out({'version':1,'state':'unknown'})
'''.replace("LIVENESS_PS", repr(_LIVENESS_PS)).replace("COUNTS", repr(_COUNTS)).replace("LEAVES", repr(_LEAVES))


def _admit(root: Path) -> tuple[Any, tuple[str, str, int, int, str], str, str] | None:
    intent = base._private_intent(root, _CORRELATION)
    if intent is None or not isinstance(intent.get("request"), dict):
        return None
    request = intent["request"]
    config, _target, descriptor = base._descriptor(root)
    env, socket, pid, ticks, sid = descriptor
    if (env != "windows-cp117" or request.get("correlationId") != _CORRELATION
            or not isinstance(request.get("sourceSha"), str) or not _SOURCE.fullmatch(request["sourceSha"])
            or any(intent.get(key) != expected for key, expected in (("environment", env), ("socketPath", socket),
                ("pid", pid), ("startTicks", ticks), ("expectedSid", sid)))):
        return None
    pair, _size = base._stage_artifact_readonly(root, intent)
    if (pair.get("sourceSha") != request["sourceSha"] or pair.get("baseVersion") != "2.1.19"
            or not isinstance(pair.get("baseCliSha256"), str)):
        return None
    return config, descriptor, request["sourceSha"], pair["baseCliSha256"]


def _project(raw: bytes | None, source: str) -> dict[str, Any]:
    try:
        value = json.loads(raw) if raw is not None else {}
    except (TypeError, ValueError):
        return dict(_UNKNOWN)
    fields = {"version", "state", "ownerProcesses", "installerProcesses", "consentProcesses", "runtimeProcesses", "stateLeaves", "runtimeOff"}
    if (not isinstance(value, dict) or set(value) != fields or value.get("version") != 1
            or value.get("state") not in {"absent", "blocked"}
            or any(value.get(key) not in _COUNTS for key in ("ownerProcesses", "installerProcesses", "consentProcesses", "runtimeProcesses"))
            or value.get("stateLeaves") not in _LEAVES or type(value.get("runtimeOff")) is not bool
            or value["runtimeOff"] != (value["runtimeProcesses"] == "none")
            or (value["state"] == "absent" and not (value["ownerProcesses"] == "none" and value["installerProcesses"] == "none" and value["consentProcesses"] == "none" and value["runtimeOff"] and value["stateLeaves"] == "none"))):
        return dict(_UNKNOWN)
    return {"state": value["state"], "sourceSha": source, "correlationId": _CORRELATION,
            "ownerProcesses": value["ownerProcesses"], "installerProcesses": value["installerProcesses"],
            "consentProcesses": value["consentProcesses"], "runtimeProcesses": value["runtimeProcesses"],
            "stateLeaves": value["stateLeaves"], "runtimeOff": value["runtimeOff"],
            "replayAllowed": False, "nativeActionAllowed": False}


def observe(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Read all fixed liveness categories without starting or stopping a process."""
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}:
        raise WindowsMsiOwnerLivenessError("Exact CP117 host is required.")
    try:
        admitted = _admit(Path(root).resolve(strict=True))
        if admitted is None:
            return dict(_UNKNOWN)
        config, (_env, socket, pid, ticks, sid), source, cli_hash = admitted
        return _project(base._remote(config, _REMOTE, (socket, str(pid), str(ticks), sid, cli_hash), None, 60), source)
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError):
        return dict(_UNKNOWN)
