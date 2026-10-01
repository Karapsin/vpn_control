"""Read-only identity census for the already running CP117 base CLI owner."""
from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path
import re
import uuid
from typing import Any, Mapping

from . import windows_msi_base_prepare as base, windows_credential_probe_ssh, windows_msi_public_scenario


class WindowsMsiOwnerCensusError(ValueError):
    pass


_BASE_CORRELATION = "c32cb108-4d48-407e-9153-40774559ba50"
_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_UTC = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z\Z")
_UNKNOWN = {"state": "unknown", "replayAllowed": False, "nativeActionAllowed": False}


_CENSUS_PS = r'''$ErrorActionPreference='Stop'
try {
 $sid='__SID__';$expectedHash='__CLI_HASH__';$expectedVersion='2.1.19'
 $cli='C:\Users\vpncp117\AppData\Local\vpn-control\vpn-control-cli.exe'
 $state='C:\Users\vpncp117\AppData\Local\VpnControl\cp166\state'
 $file=Get-Item -LiteralPath $cli -Force -ErrorAction Stop
 if($file.PSIsContainer -or (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'CLI_FILE' }
 $hash=(Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant()
 if($hash -cne $expectedHash) { throw 'CLI_HASH' }
 $products=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',('Registry::HKEY_USERS\'+$sid+'\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'),('Registry::HKEY_USERS\'+$sid+'\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') -ErrorAction SilentlyContinue|Where-Object {$_.DisplayName -eq 'vpn-control'})
 if($products.Count -ne 1 -or $products[0].DisplayVersion -cne $expectedVersion -or $products[0].InstallLocation.TrimEnd('\') -cne 'C:\Users\vpncp117\AppData\Local\vpn-control') { throw 'PRODUCT' }
 $stateItem=Get-Item -LiteralPath $state -Force -ErrorAction Stop
 if(-not $stateItem.PSIsContainer -or (($stateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'STATE' }
 $stateAcl=Get-Acl -LiteralPath $state
 $stateOwner=([Security.Principal.NTAccount]::new($stateAcl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
 if($stateOwner -cne $sid) { throw 'STATE_OWNER' }
 $directoryAllowedSids=@($sid,'S-1-5-18','S-1-5-32-544')
 $stateRead=$false;$stateCreate=$false
 foreach($rule in $stateAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
  if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and [int]$rule.FileSystemRights -ne 0) {
   if($rule.IdentityReference.Value -notin $directoryAllowedSids) { throw 'STATE_ACL' }
   if($rule.IdentityReference.Value -ceq $sid) {
    if(($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ListDirectory) -ne 0) { $stateRead=$true }
    if(($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::CreateFiles) -ne 0) { $stateCreate=$true }
   }
  }
 }
 if(-not $stateRead -or -not $stateCreate) { throw 'STATE_ACCESS' }
 $lockPath=Join-Path $state 'vpn-control.lock';$endpointPath=Join-Path $state 'activation.port'
 foreach($path in @($lockPath,$endpointPath)) {
  $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
  if($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or $item.Length -lt 1 -or $item.Length -gt 4096) { throw 'STATE_FILE' }
 $acl=Get-Acl -LiteralPath $path
  if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $sid) { throw 'STATE_OWNER' }
  $fileAllowedSids=@($sid,'S-1-5-18','S-1-5-32-544')
  $ownerRead=$false
  foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
   if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and [int]$rule.FileSystemRights -ne 0) {
    if($rule.IdentityReference.Value -notin $fileAllowedSids) { throw 'STATE_ACL' }
    if($rule.IdentityReference.Value -ceq $sid) {
     if(($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData) -ne 0) { $ownerRead=$true }
    }
   }
  }
  if(-not $ownerRead) { throw 'STATE_READ' }
 }
 $lock=(Get-Content -LiteralPath $lockPath -Raw -ErrorAction Stop).Trim()
 if($lock -notmatch '^[1-9][0-9]{0,9}$') { throw 'LOCK' }
 $childPid=[int]$lock
 $child=Get-CimInstance Win32_Process -Filter ('ProcessId='+$childPid)
 if($null -eq $child -or $child.ParentProcessId -le 0) { throw 'CHILD' }
 $parentPid=[int]$child.ParentProcessId
 $parent=Get-CimInstance Win32_Process -Filter ('ProcessId='+$parentPid)
 if($null -eq $parent -or $parentPid -eq $childPid) { throw 'PARENT' }
 foreach($process in @($parent,$child)) {
  $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
  if($process.Name -cne 'vpn-control-cli.exe' -or $process.ExecutablePath -cne $cli -or $process.SessionId -ne 1 -or $owner.ReturnValue -ne 0 -or $owner.Sid -cne $sid) { throw 'OWNER' }
 }
 $parentTime=$parent.CreationDate.ToUniversalTime().ToString('o');$childTime=$child.CreationDate.ToUniversalTime().ToString('o')
 if($parentTime -ceq $childTime) { throw 'GENERATION' }
 $endpoint=Get-Content -LiteralPath $endpointPath -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop
 $controller=[string]$endpoint.controllerId
 if($endpoint.schemaVersion -ne 1 -or $controller -notmatch '^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$' -or [guid]::Parse($controller).ToString() -cne $controller -or $endpoint.port -lt 1 -or $endpoint.port -gt 65535 -or $endpoint.token -notmatch '^[A-Za-z0-9_-]{43}$') { throw 'ENDPOINT' }
 $raw=@(& $cli --state-dir $state --json --controller-id $controller --timeout-seconds 15 status 2>$null)
 if($LASTEXITCODE -ne 0 -or $raw.Count -ne 1 -or $raw[0] -isnot [string] -or $raw[0].Length -lt 2 -or $raw[0].Length -gt 8192) { throw 'PUBLIC_STATUS' }
 $public=ConvertFrom-Json -InputObject $raw[0] -ErrorAction Stop
 if($public.schemaVersion -ne 1 -or $public.ok -ne $true -or $public.final -ne $true -or $public.code -cne 'OK' -or $public.controllerId -cne $controller -or $public.data.runtimeRunning -ne $false) { throw 'PUBLIC_RESULT' }
 [Console]::Out.WriteLine(([pscustomobject]@{version=1;state='observed';controllerId=$controller;parentPid=$parentPid;parentStartedAtUtc=$parentTime;childPid=$childPid;childStartedAtUtc=$childTime;installedCliSha256=$hash;runtimeRunning=$false}|ConvertTo-Json -Compress))
} catch { [Console]::Out.WriteLine('{"version":1,"state":"unknown"}');exit 1 }
'''


_REMOTE = base._QGA + r'''sock,pid,ticks,sid,cli_hash=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks):raise ValueError()
 script=CENSUS_PS.replace('__SID__',sid).replace('__CLI_HASH__',cli_hash)
 started=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(script.encode('utf-16le')).decode()],'capture-output':True})
 child=started.get('pid')
 if type(child) is not int or child<=0:raise ValueError()
 import time
 for attempt in range(160):
  observed=call(sock,'guest-exec-status',{'pid':child})
  if type(observed.get('exited')) is not bool:raise ValueError()
  if observed['exited']:break
  time.sleep(.25)
 else:raise ValueError()
 if (type(observed.get('exitcode')) is not int or observed['exitcode']!=0
     or ('out-truncated' in observed and type(observed['out-truncated']) is not bool)
     or ('err-truncated' in observed and type(observed['err-truncated']) is not bool)
     or observed.get('out-truncated') is True or observed.get('err-truncated') is True):raise ValueError()
 raw=base64.b64decode(observed.get('out-data',''),validate=True)
 if not 0<len(raw)<=4096:raise ValueError()
 lines=[x for x in decode(raw).splitlines() if x.startswith('{') and x.endswith('}')]
 if len(lines)!=1:raise ValueError()
 out(json.loads(lines[0]))
except Exception:out({'version':1,'state':'unknown'})
'''.replace('CENSUS_PS', repr(_CENSUS_PS))


def _preflight_script() -> str:
    sample = _CENSUS_PS.replace("__SID__", "S-1-5-21-1-2-3-1002").replace("__CLI_HASH__", "a" * 64)
    packed = base64.b64encode(gzip.compress(sample.encode("utf-16le"), mtime=0)).decode()
    return r'''$ErrorActionPreference='Stop'
try {
 $input=[IO.MemoryStream]::new([Convert]::FromBase64String('@SCRIPT@'))
 $zip=[IO.Compression.GzipStream]::new($input,[IO.Compression.CompressionMode]::Decompress)
 $output=[IO.MemoryStream]::new();$zip.CopyTo($output)
 $body=[Text.Encoding]::Unicode.GetString($output.ToArray())
 $zip.Dispose();$input.Dispose();$output.Dispose()
 $tokens=$null;$errors=$null
 [System.Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)|Out-Null
 if($errors.Count -ne 0){throw 'SYNTAX'}
 [Console]::Out.WriteLine('{"version":1,"code":"OK"}')
}catch{[Console]::Out.WriteLine('{"version":1,"code":"FAILED"}');exit 1}
'''.replace("@SCRIPT@", packed)


def preflight(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Parse the fixed census program in owned CP117 PowerShell 5.1."""
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}:
        raise WindowsMsiOwnerCensusError("Exact CP117 host is required.")
    root = Path(root).resolve(strict=True)
    try:
        config, _target, (env, socket, pid, ticks, _sid) = base._descriptor(root)
        if env != "windows-cp117":
            return {"state": "unknown", "checks": []}
        encoded = base64.b64encode(_preflight_script().encode("utf-16le")).decode()
        if len(encoded) >= 30000:
            return {"state": "unknown", "checks": []}
        raw = windows_credential_probe_ssh._run_ssh(config, "archlinux",
            windows_credential_probe_ssh._remote_command(windows_msi_public_scenario._REMOTE_PREFLIGHT,
                socket, str(pid), str(ticks), encoded), None, 30)
        value = json.loads(raw) if raw is not None else {}
        if (not isinstance(value, dict) or set(value) != {"state", "checks"}
                or value["state"] not in {"passed", "failed"}
                or value["checks"] != ["ps5-parse", "gzip", "utf8-pipeline"]):
            return {"state": "unknown", "checks": []}
        return {"state": value["state"], "checks": ["ps5-parse", "gzip"]}
    except (OSError, ValueError, TypeError, KeyError):
        return {"state": "unknown", "checks": []}


def _project(raw: bytes | None, sid_source: str, cli_hash: str) -> dict[str, Any]:
    try:
        value = json.loads(raw) if raw is not None else {}
    except (TypeError, ValueError):
        return dict(_UNKNOWN)
    fields = {"version", "state", "controllerId", "parentPid", "parentStartedAtUtc",
              "childPid", "childStartedAtUtc", "installedCliSha256", "runtimeRunning"}
    if (not isinstance(value, dict) or set(value) != fields or value.get("version") != 1
            or value.get("state") != "observed" or value.get("runtimeRunning") is not False
            or not isinstance(value.get("controllerId"), str) or not _UUID.fullmatch(value["controllerId"])
            or str(uuid.UUID(value["controllerId"])) != value["controllerId"]
            or any(type(value.get(name)) is not int or value[name] <= 0 for name in ("parentPid", "childPid"))
            or value["parentPid"] == value["childPid"]
            or any(not isinstance(value.get(name), str) or not _UTC.fullmatch(value[name])
                   for name in ("parentStartedAtUtc", "childStartedAtUtc"))
            or value["parentStartedAtUtc"] == value["childStartedAtUtc"]
            or value.get("installedCliSha256") != cli_hash):
        return dict(_UNKNOWN)
    return {"state": "observed", "sourceSha": sid_source, "controllerId": value["controllerId"],
            "installedCliSha256": cli_hash, "parentPid": value["parentPid"],
            "parentStartedAtUtc": value["parentStartedAtUtc"], "childPid": value["childPid"],
            "childStartedAtUtc": value["childStartedAtUtc"], "runtimeRunning": False,
            "replayAllowed": False, "nativeActionAllowed": False}


def workflow(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Discover current original-user owner identity; accepts no caller claims."""
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}:
        raise WindowsMsiOwnerCensusError("Exact CP117 host is required.")
    root = Path(root).resolve(strict=True)
    try:
        intent = base._private_intent(root, _BASE_CORRELATION)
        if intent is None:
            return dict(_UNKNOWN)
        request = intent["request"]
        pair, _ = base._stage_artifact_readonly(root, intent)
        config, _target, (env, socket, pid, ticks, sid) = base._descriptor(root)
        if (request.get("correlationId") != _BASE_CORRELATION
                or pair.get("sourceSha") != request.get("sourceSha")
                or pair.get("baseVersion") != "2.1.19"
                or any(intent.get(key) != expected for key, expected in (
                    ("environment", env), ("socketPath", socket), ("pid", pid),
                    ("startTicks", ticks), ("expectedSid", sid)))):
            return dict(_UNKNOWN)
        readiness = base.readiness(root, {"host": "archlinux", "expectedCurrentVersion": "2.1.19"})
        if (readiness.get("installedVersion") != "2.1.19" or readiness.get("productCount") != 1
                or readiness.get("state") not in {"ready", "blocked"}):
            return dict(_UNKNOWN)
        raw = base._remote(config, _REMOTE, (socket, str(pid), str(ticks), sid,
            pair["baseCliSha256"]), None, 90)
        return _project(raw, request["sourceSha"], pair["baseCliSha256"])
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError):
        return dict(_UNKNOWN)
