"""Bounded, read-only cause classification for the CP117 owner census.

The owner census intentionally returns a single fail-closed ``unknown`` result.
This observer rechecks the same fixed facts and returns only a small phase enum.
It never returns account data, paths, tokens, command output, or a replay permit.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
import re
from typing import Any, Mapping

from . import windows_msi_base_prepare as base


class WindowsMsiOwnerDiagnosticError(ValueError):
    pass


_CORRELATION = "c32cb108-4d48-407e-9153-40774559ba50"
_SOURCE = re.compile(r"[0-9a-f]{40}\Z")
_UNKNOWN = {"state": "unknown", "replayAllowed": False, "nativeActionAllowed": False}
_PHASES = {"cli", "product", "state-directory", "state-files", "endpoint-unavailable", "process", "endpoint", "public-status", "complete"}
_STATE_DIRECTORY_DETAILS = {"absent-or-unreadable", "type-or-reparse", "acl-error", "owner-mismatch",
                            "foreign-allow-ace-other",
                            "missing-owner-list-directory", "missing-owner-create-files"}
_STATE_FILE_DETAILS = {"lock-absent-or-unreadable", "lock-type-or-reparse", "lock-acl-error",
                       "lock-owner-mismatch", "lock-foreign-allow-ace-other",
                       "lock-missing-owner-read",
                       "lock-format", "endpoint-type-or-reparse",
                       "endpoint-acl-error", "endpoint-owner-mismatch", "endpoint-foreign-allow-ace-other",
                       "endpoint-missing-owner-read"}
_ENDPOINT_UNAVAILABLE_DETAILS = {"endpoint-absent-process-exact", "endpoint-unreadable-process-exact",
                                 "endpoint-absent-process-absent", "endpoint-unreadable-process-absent",
                                 "endpoint-absent-process-invalid", "endpoint-unreadable-process-invalid"}


_DIAGNOSTIC_PS = r'''$ErrorActionPreference='Stop'
$phase='cli'
$detail='not-applicable'
try {
 $sid='__SID__';$expectedHash='__CLI_HASH__';$expectedVersion='2.1.19'
 $cli='C:\Users\vpncp117\AppData\Local\vpn-control\vpn-control-cli.exe'
 $state='C:\Users\vpncp117\AppData\Local\VpnControl\cp166\state'
 function ProcessChainState([int]$expectedPid){
  try{
   $candidate=Get-CimInstance Win32_Process -Filter ('ProcessId='+$expectedPid)
   if($null -eq $candidate){return 'absent'}
   if($candidate.ParentProcessId -le 0){return 'invalid'}
   $candidateParent=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$candidate.ParentProcessId)
   if($null -eq $candidateParent -or $candidateParent.ProcessId -eq $candidate.ProcessId){return 'invalid'}
   foreach($candidateProcess in @($candidateParent,$candidate)){
    $candidateOwner=Invoke-CimMethod -InputObject $candidateProcess -MethodName GetOwnerSid
    if($candidateProcess.Name -cne 'vpn-control-cli.exe' -or $candidateProcess.ExecutablePath -cne $cli -or $candidateProcess.SessionId -ne 1 -or $candidateOwner.ReturnValue -ne 0 -or $candidateOwner.Sid -cne $sid){return 'invalid'}
   }
   if($candidateParent.CreationDate.ToUniversalTime().ToString('o') -ceq $candidate.CreationDate.ToUniversalTime().ToString('o')){return 'invalid'}
   return 'exact'
  }catch{return 'invalid'}
 }
 $file=Get-Item -LiteralPath $cli -Force -ErrorAction Stop
 if($file.PSIsContainer -or (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or (Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedHash){throw 'CLI'}
 $phase='product'
 $products=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',('Registry::HKEY_USERS\'+$sid+'\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'),('Registry::HKEY_USERS\'+$sid+'\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') -ErrorAction SilentlyContinue|Where-Object {$_.DisplayName -eq 'vpn-control'})
 if($products.Count -ne 1 -or $products[0].DisplayVersion -cne $expectedVersion -or $products[0].InstallLocation.TrimEnd('\') -cne 'C:\Users\vpncp117\AppData\Local\vpn-control'){throw 'PRODUCT'}
 $phase='state-directory'
 try{$stateItem=Get-Item -LiteralPath $state -Force -ErrorAction Stop}catch{$detail='absent-or-unreadable';throw}
 if(-not $stateItem.PSIsContainer -or (($stateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){$detail='type-or-reparse';throw 'STATE'}
 try{$acl=Get-Acl -LiteralPath $state -ErrorAction Stop}catch{$detail='acl-error';throw}
 try{$stateOwner=([Security.Principal.NTAccount]::new($acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value}catch{$detail='acl-error';throw}
 if($stateOwner -cne $sid){$detail='owner-mismatch';throw 'STATE_OWNER'}
 try{$rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))}catch{$detail='acl-error';throw}
 $directoryAllowedSids=@($sid,'S-1-5-18','S-1-5-32-544')
 $read=$false;$create=$false
 foreach($rule in $rules){
  if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and [int]$rule.FileSystemRights -ne 0){
   if($rule.IdentityReference.Value -notin $directoryAllowedSids){$detail='foreign-allow-ace-other';throw 'STATE_ACL'}
   if($rule.IdentityReference.Value -ceq $sid){
    if(($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ListDirectory) -ne 0){$read=$true}
    if(($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::CreateFiles) -ne 0){$create=$true}
   }
  }
 }
 if(-not $read){$detail='missing-owner-list-directory';throw 'STATE_ACCESS'}
 if(-not $create){$detail='missing-owner-create-files';throw 'STATE_ACCESS'}
 $phase='state-files';$lockPath=Join-Path $state 'vpn-control.lock';$endpointPath=Join-Path $state 'activation.port'
 foreach($path in @($lockPath,$endpointPath)){
  $fileKind=if($path -ceq $lockPath){'lock'}else{'endpoint'}
  try{$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop}catch{
   if($fileKind -ceq 'endpoint'){
    $endpointState=if($_.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::ObjectNotFound){'endpoint-absent'}else{'endpoint-unreadable'}
    $detail=$endpointState+'-process-'+(ProcessChainState ([int]$lock));$phase='endpoint-unavailable'
   }else{$detail=$fileKind+'-absent-or-unreadable'}
   throw
  }
  if($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or $item.Length -lt 1 -or $item.Length -gt 4096){$detail=$fileKind+'-type-or-reparse';throw 'STATE_FILE'}
  try{$fileAcl=Get-Acl -LiteralPath $path -ErrorAction Stop}catch{$detail=$fileKind+'-acl-error';throw}
  try{$fileOwner=$fileAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value}catch{$detail=$fileKind+'-acl-error';throw}
  if($fileOwner -cne $sid){$detail=$fileKind+'-owner-mismatch';throw 'STATE_OWNER'}
  $fileOwnerRead=$false
  try{$fileRules=@($fileAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))}catch{$detail=$fileKind+'-acl-error';throw}
  $fileAllowedSids=@($sid,'S-1-5-18','S-1-5-32-544')
  foreach($rule in $fileRules){
   if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and [int]$rule.FileSystemRights -ne 0){
    if($rule.IdentityReference.Value -notin $fileAllowedSids){$detail=$fileKind+'-foreign-allow-ace-other';throw 'STATE_ACL'}
    if($rule.IdentityReference.Value -ceq $sid){
     if(($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData) -ne 0){$fileOwnerRead=$true}
    }
   }
  }
 if(-not $fileOwnerRead){$detail=$fileKind+'-missing-owner-read';throw 'STATE_READ'}
  if($fileKind -ceq 'lock'){
   try{$lock=(Get-Content -LiteralPath $lockPath -Raw -ErrorAction Stop).Trim()}catch{$detail='lock-format';throw}
   if($lock -notmatch '^[1-9][0-9]{0,9}$'){$detail='lock-format';throw 'LOCK'}
  }
 }
 $phase='process';$child=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$lock)
 if($null -eq $child -or $child.ParentProcessId -le 0){throw 'CHILD'}
 $parent=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$child.ParentProcessId)
 if($null -eq $parent -or $parent.ProcessId -eq $child.ProcessId){throw 'PARENT'}
 foreach($process in @($parent,$child)){
  $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
  if($process.Name -cne 'vpn-control-cli.exe' -or $process.ExecutablePath -cne $cli -or $process.SessionId -ne 1 -or $owner.ReturnValue -ne 0 -or $owner.Sid -cne $sid){throw 'OWNER'}
 }
 if($parent.CreationDate.ToUniversalTime().ToString('o') -ceq $child.CreationDate.ToUniversalTime().ToString('o')){throw 'GENERATION'}
 $phase='endpoint';$endpoint=Get-Content -LiteralPath $endpointPath -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop
 $controller=[string]$endpoint.controllerId
 if($endpoint.schemaVersion -ne 1 -or $controller -notmatch '^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$' -or [guid]::Parse($controller).ToString() -cne $controller -or $endpoint.port -lt 1 -or $endpoint.port -gt 65535 -or $endpoint.token -notmatch '^[A-Za-z0-9_-]{43}$'){throw 'ENDPOINT'}
 $phase='public-status';$raw=@(& $cli --state-dir $state --json --controller-id $controller --timeout-seconds 15 status 2>$null)
 if($LASTEXITCODE -ne 0 -or $raw.Count -ne 1 -or $raw[0] -isnot [string] -or $raw[0].Length -lt 2 -or $raw[0].Length -gt 8192){throw 'PUBLIC_STATUS'}
 $public=ConvertFrom-Json -InputObject $raw[0] -ErrorAction Stop
 if($public.schemaVersion -ne 1 -or $public.ok -ne $true -or $public.final -ne $true -or $public.code -cne 'OK' -or $public.controllerId -cne $controller -or $public.data.runtimeRunning -ne $false){throw 'PUBLIC_RESULT'}
 $phase='complete'
} catch {}
[Console]::Out.WriteLine(([pscustomobject]@{version=1;state='diagnosed';phase=$phase;detail=$detail}|ConvertTo-Json -Compress))
'''


_REMOTE = base._QGA + r'''import time
sock,pid,ticks,sid,cli_hash=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks):raise ValueError()
 script=DIAGNOSTIC_PS.replace('__SID__',sid).replace('__CLI_HASH__',cli_hash)
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(script.encode('utf-16le')).decode()],'capture-output':True})
 child=child.get('pid')
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(160):
  observed=call(sock,'guest-exec-status',{'pid':child})
  if observed.get('exited') is True:break
  if observed.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if (type(observed.get('exitcode')) is not int or observed['exitcode']!=0 or observed.get('out-truncated') is True or observed.get('err-truncated') is True):raise ValueError()
 raw=base64.b64decode(observed.get('out-data',''),validate=True)
 if not 0<len(raw)<=1024:raise ValueError()
 lines=[line for line in decode(raw).splitlines() if line.startswith('{') and line.endswith('}')]
 if len(lines)!=1:raise ValueError()
 value=json.loads(lines[0])
 if not isinstance(value,dict) or set(value)!={'version','state','phase','detail'} or value.get('version')!=1 or value.get('state')!='diagnosed' or value.get('phase') not in PHASES:raise ValueError()
 if (value['phase']=='state-directory' and value.get('detail') not in STATE_DIRECTORY_DETAILS) or (value['phase']=='state-files' and value.get('detail') not in STATE_FILE_DETAILS) or (value['phase']=='endpoint-unavailable' and value.get('detail') not in ENDPOINT_UNAVAILABLE_DETAILS) or (value['phase'] not in {'state-directory','state-files','endpoint-unavailable'} and value.get('detail')!='not-applicable'):raise ValueError()
 out(value)
except Exception:out({'version':1,'state':'unknown'})
'''.replace("DIAGNOSTIC_PS", repr(_DIAGNOSTIC_PS)).replace("PHASES", repr(_PHASES)).replace("STATE_DIRECTORY_DETAILS", repr(_STATE_DIRECTORY_DETAILS)).replace("STATE_FILE_DETAILS", repr(_STATE_FILE_DETAILS)).replace("ENDPOINT_UNAVAILABLE_DETAILS", repr(_ENDPOINT_UNAVAILABLE_DETAILS))


def _local_admission(root: Path) -> tuple[Any, tuple[str, str, int, int, str], str, str] | None:
    """Return fixed source and QGA binding only when the base record remains exact."""
    intent = base._private_intent(root, _CORRELATION)
    if intent is None:
        return None
    request = intent.get("request")
    if not isinstance(request, dict) or request.get("correlationId") != _CORRELATION:
        return None
    config, _target, descriptor = base._descriptor(root)
    env, socket, pid, ticks, sid = descriptor
    if (env != "windows-cp117" or not isinstance(request.get("sourceSha"), str)
            or not _SOURCE.fullmatch(request["sourceSha"])
            or any(intent.get(key) != expected for key, expected in (
                ("environment", env), ("socketPath", socket), ("pid", pid),
                ("startTicks", ticks), ("expectedSid", sid)))):
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
    if (not isinstance(value, dict) or set(value) != {"version", "state", "phase", "detail"}
            or value.get("version") != 1 or value.get("state") != "diagnosed"
            or value.get("phase") not in _PHASES
            or (value["phase"] == "state-directory" and value.get("detail") not in _STATE_DIRECTORY_DETAILS)
            or (value["phase"] == "state-files" and value.get("detail") not in _STATE_FILE_DETAILS)
            or (value["phase"] == "endpoint-unavailable" and value.get("detail") not in _ENDPOINT_UNAVAILABLE_DETAILS)
            or (value["phase"] not in {"state-directory", "state-files", "endpoint-unavailable"} and value.get("detail") != "not-applicable")):
        return dict(_UNKNOWN)
    result = {"state": "diagnosed", "phase": value["phase"], "sourceSha": source,
            "correlationId": _CORRELATION, "replayAllowed": False, "nativeActionAllowed": False}
    if value["phase"] in {"state-directory", "state-files", "endpoint-unavailable"}:
        result["detail"] = value["detail"]
    return result


def diagnose(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Classify the fixed owner-census proof boundary without taking action."""
    if not isinstance(inputs, Mapping) or dict(inputs) != {"host": "archlinux"}:
        raise WindowsMsiOwnerDiagnosticError("Exact CP117 host is required.")
    try:
        admitted = _local_admission(Path(root).resolve(strict=True))
        if admitted is None:
            return dict(_UNKNOWN)
        config, (_env, socket, pid, ticks, sid), source, cli_hash = admitted
        raw = base._remote(config, _REMOTE, (socket, str(pid), str(ticks), sid, cli_hash), None, 60)
        return _project(raw, source)
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError):
        return dict(_UNKNOWN)
