"""CP117 original-owner network launch admission.

The already-running owner handles forwarded CLI update operations. A proxy and
trust store set on a forwarding CLI cannot configure that owner. This adapter
prepares a one-shot, original-user launch with explicit runtime-off admission.
Dispatch uses a fixed one-shot task with exact task/status/cleanup receipts;
no caller-supplied JVM flags or proof can unlock target/public work.
"""
from __future__ import annotations

import base64
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from typing import Any, Mapping

from . import windows_cp117_lease as lease
from . import windows_msi_base_prepare as base
from . import windows_update_fixture_server as server
from . import windows_fixture_credentials as credentials


class WindowsFixtureOwnerNetworkError(ValueError):
    pass


_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
_UTC = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z\Z")
_CLI = r"C:\Users\vpncp117\AppData\Local\vpn-control\vpn-control-cli.exe"
_STATE = r"C:\Users\vpncp117\AppData\Local\VpnControl\cp166\state"
_ROOT = r"C:\Users\vpncp117\AppData\Local\VpnControl"
_GROUP = ".rag_index/windows-fixture-owner-network"


def _ps(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _canonical(value: Any) -> bool:
    return isinstance(value, str) and bool(_UUID.fullmatch(value)) and str(uuid.UUID(value)) == value


def _request(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = {"host", "leaseId", "stageCorrelationId", "serverCorrelationId",
              "ownerNetworkCorrelationId", "sourceSha", "fixtureReceiptArtifactId",
              "baseMsiArtifactId", "targetMsiArtifactId", "controllerId", "ownerPid",
              "ownerStartedAtUtc"}
    if not isinstance(value, Mapping) or set(value) != fields or value.get("host") != "archlinux":
        raise WindowsFixtureOwnerNetworkError("Owner network request requires exact CP117 fields.")
    names = ("leaseId", "stageCorrelationId", "serverCorrelationId", "ownerNetworkCorrelationId",
             "controllerId")
    if not all(_canonical(value[name]) for name in names) or len({value[name] for name in names[:-1]}) != 4:
        raise WindowsFixtureOwnerNetworkError("Owner network UUIDs are invalid.")
    for name, pattern in (("sourceSha", _SHA), ("fixtureReceiptArtifactId", _ARTIFACT),
                          ("baseMsiArtifactId", _ARTIFACT), ("targetMsiArtifactId", _ARTIFACT),
                          ("ownerStartedAtUtc", _UTC)):
        if not isinstance(value[name], str) or not pattern.fullmatch(value[name]):
            raise WindowsFixtureOwnerNetworkError("Invalid owner network " + name + ".")
    if type(value["ownerPid"]) is not int or value["ownerPid"] <= 0:
        raise WindowsFixtureOwnerNetworkError("Owner network PID is invalid.")
    return dict(value)


def _binding(root: Path, request: Mapping[str, Any], *, allow_join: bool = False) -> dict[str, Any]:
    """Rebuild identity from private registries; the request is only a selector."""
    _config, _target, (env, socket, pid, ticks, sid) = base._descriptor(root)
    from . import windows_msi_target_prepare as target_prepare
    pair = target_prepare._pair(root, dict(request))
    live = server.verified_live_receipt(root, request["leaseId"])
    trusted = credentials.verified_descriptor(root, request["leaseId"], request["stageCorrelationId"])
    if (env != "windows-cp117" or not isinstance(live, dict) or not isinstance(trusted, dict)
            or live.get("leaseId") != request["leaseId"]
            or live.get("stageCorrelationId") != request["stageCorrelationId"]
            or live.get("serverCorrelationId") != request["serverCorrelationId"]
            or any(live.get(key) != request[key] for key in
                   ("sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"))
            or live.get("socketPath") != socket or live.get("qemuPid") != pid
            or live.get("startTicks") != ticks or live.get("originalSid") != sid
            or live.get("serverReady") is not True
            or type(live.get("serverPort")) is not int or not 1 <= live["serverPort"] <= 65535
            or trusted.get("peerCertificateSha256") != live.get("peerCertificateSha256")
            or trusted.get("paths", {}).get("trustStore") !=
                _ROOT + r"\mcp-update-credentials-" + request["stageCorrelationId"] + r"\fixture-trust.p12"
            or not isinstance(trusted.get("trustStoreSha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", trusted["trustStoreSha256"])):
        raise WindowsFixtureOwnerNetworkError("CP117 owner network binding is unavailable.")
    directory, lock = lease._locked(root)
    try:
        active = lease._active(directory)
        if (active is None or active["identity"]["leaseId"] != request["leaseId"]
                or active["identity"]["sourceSha"] != request["sourceSha"]
                or active["server"] != "live" or active["credentials"] != "ready"
                or not ((active["state"] == "active" and active["role"] is None) or
                        (active["state"] == "role-active" and active["role"] == "owner-network"
                         and active["correlationId"] == request["ownerNetworkCorrelationId"]) or
                        (allow_join and active["state"] == "role-active" and
                         active["role"] in {"network-probe", "target", "public"}))):
            raise WindowsFixtureOwnerNetworkError("CP117 owner network lease changed.")
    finally:
        os.close(lock)
    return {"socketPath": socket, "qemuPid": pid, "startTicks": ticks,
            "originalSid": sid, "baseCliSha256": pair["baseCliSha256"],
            "serverPort": live["serverPort"], "liveReceiptSha256": live["liveReceiptSha256"],
            "trustStore": trusted["paths"]["trustStore"],
            "trustStoreSha256": trusted["trustStoreSha256"],
            "leaseId": request["leaseId"], "sourceSha": request["sourceSha"],
            "fixtureReceiptArtifactId": request["fixtureReceiptArtifactId"],
            "baseMsiArtifactId": request["baseMsiArtifactId"],
            "targetMsiArtifactId": request["targetMsiArtifactId"],
            "stageCorrelationId": request["stageCorrelationId"],
            "serverCorrelationId": request["serverCorrelationId"],
            "ownerNetworkCorrelationId": request["ownerNetworkCorrelationId"]}


def _preflight_script(request: Mapping[str, Any], binding: Mapping[str, Any]) -> str:
    """Read-only runtime and original owner check before any public quit."""
    script = r'''$ErrorActionPreference='Stop'
try {
 $cli=@CLI@;$state=@STATE@;$trust=@TRUST@;$ownerPid=@OWNER_PID@;$ownerTime=@OWNER_TIME@
 $owner=Get-CimInstance Win32_Process -Filter ('ProcessId='+$ownerPid)
 $ownerSid=if($null -ne $owner){Invoke-CimMethod -InputObject $owner -MethodName GetOwnerSid}else{$null}
 $endpoint=Get-Content -LiteralPath (Join-Path $state 'activation.port') -Raw|ConvertFrom-Json
 $lock=(Get-Content -LiteralPath (Join-Path $state 'vpn-control.lock') -Raw).Trim()
 $active=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match '^(msiexec|consent|sing-box)\.exe$'})
 $ownerReady=$null -ne $owner -and $owner.Name -ceq 'vpn-control-cli.exe' -and
  $owner.ExecutablePath -ceq $cli -and $owner.CreationDate.ToUniversalTime().ToString('o') -ceq $ownerTime -and
  $owner.SessionId -eq 1 -and $ownerSid.ReturnValue -eq 0 -and $ownerSid.Sid -ceq @SID@ -and
  $endpoint.schemaVersion -eq 1 -and $endpoint.controllerId -ceq @CONTROLLER@ -and $lock -ceq [string]$ownerPid
 $hash=if([IO.File]::Exists($cli)){(Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant()}else{$null}
 $trustHash=if([IO.File]::Exists($trust)){(Get-FileHash -LiteralPath $trust -Algorithm SHA256).Hash.ToLowerInvariant()}else{$null}
 $safe=$ownerReady -and $hash -ceq @CLI_HASH@ -and $trustHash -ceq @TRUST_HASH@ -and $active.Count -eq 0
 ([pscustomobject]@{schemaVersion=1;code=$(if($safe){'OWNER_RUNTIME_CHECK'}else{'BLOCKED'});
  ownerPid=$(if($null -ne $owner){[int]$owner.ProcessId}else{$null});
  ownerStartedAtUtc=$(if($null -ne $owner){$owner.CreationDate.ToUniversalTime().ToString('o')}else{$null});
  controllerId=$endpoint.controllerId;cliSha256=$hash;trustStoreSha256=$trustHash;
  activeProcessCount=$active.Count}|ConvertTo-Json -Compress)
}catch{[Console]::Out.WriteLine('{"schemaVersion":1,"code":"UNKNOWN"}');exit 1}
'''
    values = {"CLI": _CLI, "STATE": _STATE, "TRUST": binding["trustStore"],
              "OWNER_PID": request["ownerPid"], "OWNER_TIME": request["ownerStartedAtUtc"],
              "SID": binding["originalSid"], "CONTROLLER": request["controllerId"],
              "CLI_HASH": binding["baseCliSha256"], "TRUST_HASH": binding["trustStoreSha256"]}
    for key, value in values.items():
        script = script.replace("@" + key + "@", str(value) if key == "OWNER_PID" else _ps(str(value)))
    if re.search(r"@[A-Z][A-Z_]+@", script):
        raise WindowsFixtureOwnerNetworkError("Owner preflight template is incomplete.")
    return script


def _validate_preflight(request: Mapping[str, Any], binding: Mapping[str, Any],
                        observed: Mapping[str, Any]) -> None:
    expected = {"schemaVersion", "code", "ownerPid", "ownerStartedAtUtc", "controllerId",
                "cliSha256", "trustStoreSha256", "activeProcessCount"}
    if (not isinstance(observed, Mapping) or set(observed) != expected
            or observed["schemaVersion"] != 1 or observed["code"] != "OWNER_RUNTIME_CHECK"
            or type(observed["ownerPid"]) is not int or observed["ownerPid"] != request["ownerPid"]
            or observed["ownerStartedAtUtc"] != request["ownerStartedAtUtc"]
            or observed["controllerId"] != request["controllerId"]
            or observed["cliSha256"] != binding["baseCliSha256"]
            or observed["trustStoreSha256"] != binding["trustStoreSha256"]
            or type(observed["activeProcessCount"]) is not int
            or observed["activeProcessCount"] != 0):
        raise WindowsFixtureOwnerNetworkError("CP117 owner runtime-off preflight is unavailable.")


def _task_script(request: Mapping[str, Any], binding: Mapping[str, Any]) -> str:
    """Original limited user only: public quit, exact exit, then scoped serve."""
    script = r'''$ErrorActionPreference='Stop'
$cli=@CLI@;$state=@STATE@;$trust=@TRUST@;$oldPid=@OWNER_PID@;$oldTime=@OWNER_TIME@
$controller=@CONTROLLER@;$sid=@SID@;$port=@PORT@;$root=@ROOT@
try {
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 $limited=-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
 if($identity.User.Value -cne $sid -or (Get-Process -Id $PID).SessionId -ne 1 -or -not $limited){throw 'ORIGINAL_USER'}
 $old=Get-CimInstance Win32_Process -Filter ('ProcessId='+$oldPid)
 if($null -eq $old -or $old.ExecutablePath -cne $cli -or
    $old.CreationDate.ToUniversalTime().ToString('o') -cne $oldTime -or $old.SessionId -ne 1){throw 'OLD_OWNER'}
 $oldSid=Invoke-CimMethod -InputObject $old -MethodName GetOwnerSid
 if($oldSid.ReturnValue -ne 0 -or $oldSid.Sid -cne $sid){throw 'OLD_SID'}
 if((Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant() -cne @CLI_HASH@ -or
    (Get-FileHash -LiteralPath $trust -Algorithm SHA256).Hash.ToLowerInvariant() -cne @TRUST_HASH@){throw 'HASH_CHANGED'}
 if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match '^(msiexec|consent|sing-box)\.exe$'}).Count -ne 0){throw 'ACTIVE_PRODUCT'}
 $lock=(Get-Content -LiteralPath (Join-Path $state 'vpn-control.lock') -Raw).Trim()
 $endpoint=Get-Content -LiteralPath (Join-Path $state 'activation.port') -Raw|ConvertFrom-Json
 if($lock -cne [string]$oldPid -or $endpoint.schemaVersion -ne 1 -or $endpoint.controllerId -cne $controller){throw 'OWNER_ENDPOINT'}
 $status=& $cli --state-dir $state --json --controller-id $controller --timeout-seconds 15 status|ConvertFrom-Json
 if($LASTEXITCODE -ne 0 -or $status.code -cne 'OK' -or $status.final -ne $true -or
    $status.controllerId -cne $controller -or $status.data.runtimeRunning -ne $false){throw 'RUNTIME_ON'}
 $quit=& $cli --state-dir $state --json --controller-id $controller --timeout-seconds 30 quit|ConvertFrom-Json
 if($LASTEXITCODE -ne 0 -or $quit.code -cne 'OK' -or $quit.final -ne $true -or
    $quit.controllerId -cne $controller){throw 'PUBLIC_QUIT'}
 for($n=0;$n -lt 60;$n++){
  $still=Get-CimInstance Win32_Process -Filter ('ProcessId='+$oldPid)
  if($null -eq $still){break}
  if($still.CreationDate.ToUniversalTime().ToString('o') -cne $oldTime){throw 'PID_REUSED'}
  Start-Sleep -Milliseconds 250
 }
 if($null -ne (Get-CimInstance Win32_Process -Filter ('ProcessId='+$oldPid))){throw 'QUIT_NOT_EXITED'}
 if([IO.File]::Exists((Join-Path $state 'vpn-control.lock')) -or
    [IO.File]::Exists((Join-Path $state 'activation.port'))){throw 'OLD_ENDPOINT_REMAINS'}
 if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match '^(msiexec|consent|sing-box)\.exe$'}).Count -ne 0){throw 'RUNTIME_CHANGED'}
 $env:JAVA_TOOL_OPTIONS='-Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort='+$port+
  ' -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort='+$port+
  ' -Djavax.net.ssl.trustStore='+$trust+
  ' -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=changeit'
 $launched=Start-Process -FilePath $cli -ArgumentList @('--state-dir',$state,'serve') -PassThru
 if($null -eq $launched -or $launched.Id -le 0){throw 'SERVE_NOT_STARTED'}
 $newPid=[int]$launched.Id
 for($n=0;$n -lt 80;$n++){
  $new=Get-CimInstance Win32_Process -Filter ('ProcessId='+$newPid)
  if($null -ne $new -and [IO.File]::Exists((Join-Path $state 'activation.port')) -and
     [IO.File]::Exists((Join-Path $state 'vpn-control.lock'))){break}
  Start-Sleep -Milliseconds 250
 }
 if($null -eq $new -or $new.Name -cne 'vpn-control-cli.exe' -or $new.ExecutablePath -cne $cli -or
    $new.SessionId -ne 1 -or $newPid -eq $oldPid){throw 'NEW_OWNER'}
 $newSid=Invoke-CimMethod -InputObject $new -MethodName GetOwnerSid
 $newEndpoint=Get-Content -LiteralPath (Join-Path $state 'activation.port') -Raw|ConvertFrom-Json
 $newLock=(Get-Content -LiteralPath (Join-Path $state 'vpn-control.lock') -Raw).Trim()
 if($newSid.ReturnValue -ne 0 -or $newSid.Sid -cne $sid -or $newLock -cne [string]$newPid -or
    $newEndpoint.schemaVersion -ne 1 -or [string]::IsNullOrWhiteSpace($newEndpoint.controllerId) -or
    $newEndpoint.controllerId -ceq $controller){throw 'NEW_ENDPOINT'}
 $newTime=$new.CreationDate.ToUniversalTime().ToString('o')
 $newStatus=& $cli --state-dir $state --json --controller-id $newEndpoint.controllerId --timeout-seconds 15 status|ConvertFrom-Json
 if($LASTEXITCODE -ne 0 -or $newStatus.code -cne 'OK' -or $newStatus.final -ne $true -or
    $newStatus.controllerId -cne $newEndpoint.controllerId -or $newStatus.data.runtimeRunning -ne $false){throw 'NEW_RUNTIME'}
 ([pscustomobject]@{schemaVersion=1;correlationId=@CORR@;oldOwnerPid=$oldPid;oldOwnerStartedAtUtc=$oldTime;
  oldControllerId=$controller;newOwnerPid=$newPid;newOwnerStartedAtUtc=$newTime;
  newControllerId=$newEndpoint.controllerId;originalSid=$sid;sessionId=1;limited=$limited;
  cliSha256=@CLI_HASH@;proxyHost='127.0.0.1';proxyPort=$port;trustStoreSha256=@TRUST_HASH@;
  runtimeOff=$true;launchSource='limited-task-process-environment'}|ConvertTo-Json -Compress|
  Set-Content -LiteralPath (Join-Path $root 'result.json') -Encoding UTF8
 $resultPath=Join-Path $root 'result.json'
 $acl=Get-Acl -LiteralPath $resultPath
 $acl.SetAccessRuleProtection($true,$false)
 foreach($entry in @($acl.Access)){[void]$acl.RemoveAccessRuleSpecific($entry)}
 foreach($entrySid in @('S-1-5-18','S-1-5-32-544',$sid)){
  $rule=[Security.AccessControl.FileSystemAccessRule]::new(
   [Security.Principal.SecurityIdentifier]::new($entrySid),
   [Security.AccessControl.FileSystemRights]::FullControl,
   [Security.AccessControl.InheritanceFlags]::None,[Security.AccessControl.PropagationFlags]::None,
   [Security.AccessControl.AccessControlType]::Allow)
  [void]$acl.AddAccessRule($rule)
 }
 Set-Acl -LiteralPath $resultPath -AclObject $acl
}catch{exit 1}
'''
    values = {"CLI": _CLI, "STATE": _STATE, "TRUST": binding["trustStore"],
              "OWNER_PID": request["ownerPid"], "OWNER_TIME": request["ownerStartedAtUtc"],
              "CONTROLLER": request["controllerId"], "SID": binding["originalSid"],
              "PORT": binding["serverPort"],
              "ROOT": _ROOT + r"\mcp-owner-network-" + request["ownerNetworkCorrelationId"],
              "CLI_HASH": binding["baseCliSha256"], "TRUST_HASH": binding["trustStoreSha256"],
              "CORR": request["ownerNetworkCorrelationId"]}
    for key, value in values.items():
        script = script.replace("@" + key + "@", str(value) if key in {"OWNER_PID", "PORT"} else _ps(str(value)))
    if re.search(r"@[A-Z][A-Z_]+@", script):
        raise WindowsFixtureOwnerNetworkError("Owner launch template is incomplete.")
    return script


def _bootstrap_script(request: Mapping[str, Any], binding: Mapping[str, Any]) -> str:
    """SYSTEM registers exactly one limited interactive original-user task."""
    task = "VpnControlMcpOwnerNetwork-" + request["ownerNetworkCorrelationId"]
    packed = base64.b64encode(gzip.compress(_task_script(request, binding).encode("utf-16le"),
                                           mtime=0)).decode("ascii")
    script = r'''$ErrorActionPreference='Stop'
$root=@ROOT@;$task=@TASK@;$packed=@PACKED@
if([IO.Directory]::Exists($root) -or $null -ne (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)){
 throw 'EXISTING_OWNER_NETWORK'}
foreach($ancestor in @(@DRIVE_ROOT@,@USERS_ROOT@,@USER_ROOT@,@APPDATA_ROOT@,@LOCAL_ROOT@,@FIXTURE_ROOT@)){
 $entry=Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
 if(-not $entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'PATH_ANCESTOR'}
}
$parentAcl=Get-Acl -LiteralPath @FIXTURE_ROOT@
$parentOwner=$parentAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value
$allowed=@('S-1-5-18','S-1-5-32-544',@SID@)
if($parentOwner -notin $allowed){throw 'ANCESTOR_ACL'}
$write=[Security.AccessControl.FileSystemRights]::Write -bor
 [Security.AccessControl.FileSystemRights]::CreateDirectories -bor
 [Security.AccessControl.FileSystemRights]::Delete -bor
 [Security.AccessControl.FileSystemRights]::ChangePermissions
foreach($entry in @($parentAcl.Access)){
 $entrySid=$entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
 if($entry.AccessControlType -eq 'Allow' -and $entrySid -notin $allowed -and
    ($entry.FileSystemRights -band $write) -ne 0){throw 'ANCESTOR_ACL'}
}
$security=[Security.AccessControl.DirectorySecurity]::new()
$security.SetAccessRuleProtection($true,$false)
foreach($entrySid in @('S-1-5-18','S-1-5-32-544',@SID@)){
 $rule=[Security.AccessControl.FileSystemAccessRule]::new(
  [Security.Principal.SecurityIdentifier]::new($entrySid),
  [Security.AccessControl.FileSystemRights]::FullControl,
  ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
  [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
 [void]$security.AddAccessRule($rule)
}
$directory=[IO.DirectoryInfo]::new($root)
$directory.Create($security)
$bytes=[Convert]::FromBase64String($packed)
$input=[IO.MemoryStream]::new([byte[]]$bytes)
$gzip=[IO.Compression.GzipStream]::new($input,[IO.Compression.CompressionMode]::Decompress)
$output=[IO.MemoryStream]::new();$gzip.CopyTo($output)
$encoded=[Convert]::ToBase64String($output.ToArray())
$gzip.Dispose();$input.Dispose();$output.Dispose()
$action=New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$encoded)
$principal=New-ScheduledTaskPrincipal -UserId 'VPNMSIX64\vpncp117' -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskPath '\' -TaskName $task -Action $action -Principal $principal -Settings $settings|Out-Null
Start-ScheduledTask -TaskPath '\' -TaskName $task
([pscustomobject]@{schemaVersion=1;correlationId=@CORR@;taskName=$task;submitted=$true}|ConvertTo-Json -Compress)
'''
    values = {"ROOT": _ROOT + r"\mcp-owner-network-" + request["ownerNetworkCorrelationId"],
              "DRIVE_ROOT": "C:\\", "USERS_ROOT": r"C:\Users",
              "USER_ROOT": r"C:\Users\vpncp117", "APPDATA_ROOT": r"C:\Users\vpncp117\AppData",
              "LOCAL_ROOT": r"C:\Users\vpncp117\AppData\Local", "FIXTURE_ROOT": _ROOT,
              "TASK": task, "PACKED": packed, "SID": binding["originalSid"],
              "CORR": request["ownerNetworkCorrelationId"]}
    for key, value in values.items():
        script = script.replace("@" + key + "@", _ps(str(value)))
    if re.search(r"@[A-Z][A-Z_]+@", script):
        raise WindowsFixtureOwnerNetworkError("Owner bootstrap template is incomplete.")
    if len(base64.b64encode(script.encode("utf-16le"))) >= 30000:
        raise WindowsFixtureOwnerNetworkError("Owner bootstrap exceeds QGA command admission.")
    return script


def _observation_script(request: Mapping[str, Any], binding: Mapping[str, Any]) -> str:
    """Read task/result/new owner in SYSTEM without forwarding another CLI command."""
    task = "VpnControlMcpOwnerNetwork-" + request["ownerNetworkCorrelationId"]
    arguments = "-NoProfile -NonInteractive -EncodedCommand " + base64.b64encode(
        _task_script(request, binding).encode("utf-16le")).decode("ascii")
    argument_hash = hashlib.sha256(arguments.encode()).hexdigest()
    script = r'''$ErrorActionPreference='Stop'
try {
 foreach($ancestor in @(@DRIVE_ROOT@,@USERS_ROOT@,@USER_ROOT@,@APPDATA_ROOT@,@LOCAL_ROOT@,@FIXTURE_ROOT@,@ROOT@)){
  $entry=Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
  if(-not $entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'PATH_ANCESTOR'}
 }
 $rootAcl=Get-Acl -LiteralPath @ROOT@
 if(-not $rootAcl.AreAccessRulesProtected){throw 'ROOT_ACL'}
 $allowed=@('S-1-5-18','S-1-5-32-544',@SID@)
 foreach($rule in @($rootAcl.Access)){
  $ruleSid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
  if($rule.AccessControlType -ne 'Allow' -or $rule.IsInherited -or $ruleSid -notin $allowed){throw 'ROOT_ACL'}
 }
 $task=Get-ScheduledTask -TaskPath '\' -TaskName @TASK@ -ErrorAction SilentlyContinue
 $taskState='Ready';$taskExit=0;$cleanupHash=$null
 if($null -ne $task){
  $info=Get-ScheduledTaskInfo -TaskPath '\' -TaskName @TASK@ -ErrorAction Stop
  $actions=@($task.Actions)
  if($task.State -ne 'Ready' -or $info.LastTaskResult -ne 0 -or $actions.Count -ne 1 -or
     $actions[0].Execute -cne 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -or
     $task.Principal.UserId -cne 'VPNMSIX64\vpncp117' -or
     $task.Principal.RunLevel -ne 'Limited' -or $task.Principal.LogonType -ne 'Interactive'){
   throw 'TASK_IDENTITY'}
  $argHash=[Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$actions[0].Arguments))
  $hex=([BitConverter]::ToString($argHash)).Replace('-','').ToLowerInvariant()
  if($hex -cne @ARGUMENT_HASH@){throw 'TASK_COMMAND'}
 }else{
  $proofPath=Join-Path @ROOT@ 'task-cleanup.json'
  $proofItem=Get-Item -LiteralPath $proofPath -Force -ErrorAction Stop
  if($proofItem.PSIsContainer -or ($proofItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
     $proofItem.Length -lt 2 -or $proofItem.Length -gt 2048){throw 'CLEANUP_FILE'}
  $proofAcl=Get-Acl -LiteralPath $proofPath
  if(-not $proofAcl.AreAccessRulesProtected){throw 'CLEANUP_ACL'}
  foreach($rule in @($proofAcl.Access)){
   $ruleSid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
   if($rule.AccessControlType -ne 'Allow' -or $rule.IsInherited -or $ruleSid -notin $allowed){throw 'CLEANUP_ACL'}
  }
  $proof=Get-Content -LiteralPath $proofPath -Raw|ConvertFrom-Json
  if($proof.schemaVersion -ne 1 -or $proof.correlationId -cne @CORR@ -or
     $proof.taskName -cne @TASK@ -or $proof.actionSha256 -cne @ARGUMENT_HASH@ -or
     $proof.terminalExitCode -ne 0 -or $proof.taskWasPresent -ne $true){throw 'CLEANUP_PROOF'}
  $taskState='AbsentCleaned'
  $cleanupHash=(Get-FileHash -LiteralPath $proofPath -Algorithm SHA256).Hash.ToLowerInvariant()
 }
 $path=Join-Path @ROOT@ 'result.json'
 $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
 if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    $item.Length -lt 2 -or $item.Length -gt 8192){throw 'RESULT_FILE'}
 $acl=Get-Acl -LiteralPath $path
 if(-not $acl.AreAccessRulesProtected){throw 'RESULT_ACL'}
 foreach($rule in @($acl.Access)){
  $ruleSid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
  if($rule.AccessControlType -ne 'Allow' -or $rule.IsInherited -or $ruleSid -notin $allowed){throw 'RESULT_ACL'}
 }
 $record=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
 $old=Get-CimInstance Win32_Process -Filter ('ProcessId='+@OLD_PID@)
 if($null -ne $old -and $old.CreationDate.ToUniversalTime().ToString('o') -ceq @OLD_TIME@){throw 'OLD_OWNER_STILL_LIVE'}
 $new=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$record.newOwnerPid)
 $newSid=if($null -ne $new){Invoke-CimMethod -InputObject $new -MethodName GetOwnerSid}else{$null}
 $endpoint=Get-Content -LiteralPath (Join-Path @STATE@ 'activation.port') -Raw|ConvertFrom-Json
 $lock=(Get-Content -LiteralPath (Join-Path @STATE@ 'vpn-control.lock') -Raw).Trim()
 if($null -eq $new -or $new.Name -cne 'vpn-control-cli.exe' -or $new.ExecutablePath -cne @CLI@ -or
    $new.CreationDate.ToUniversalTime().ToString('o') -cne $record.newOwnerStartedAtUtc -or
    $new.SessionId -ne 1 -or $newSid.ReturnValue -ne 0 -or $newSid.Sid -cne @SID@ -or
    $endpoint.schemaVersion -ne 1 -or $endpoint.controllerId -cne $record.newControllerId -or
    $lock -cne [string]$record.newOwnerPid){throw 'NEW_OWNER_CHANGED'}
 if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match '^(msiexec|consent|sing-box)\.exe$'}).Count -ne 0){throw 'ACTIVE_PRODUCT'}
 ([pscustomobject]@{schemaVersion=1;correlationId=@CORR@;record=$record;
  taskState=$taskState;taskExitCode=$taskExit;cleanupProofSha256=$cleanupHash;
  ownerPid=[int]$new.ProcessId;ownerStartedAtUtc=$new.CreationDate.ToUniversalTime().ToString('o');
  controllerId=$endpoint.controllerId;originalSid=$newSid.Sid;sessionId=[int]$new.SessionId;
  activeProcessCount=0}|ConvertTo-Json -Depth 8 -Compress)
}catch{exit 1}
'''
    values = {"TASK": task, "ARGUMENT_HASH": argument_hash,
              "ROOT": _ROOT + r"\mcp-owner-network-" + request["ownerNetworkCorrelationId"],
              "DRIVE_ROOT": "C:\\", "USERS_ROOT": r"C:\Users",
              "USER_ROOT": r"C:\Users\vpncp117", "APPDATA_ROOT": r"C:\Users\vpncp117\AppData",
              "LOCAL_ROOT": r"C:\Users\vpncp117\AppData\Local", "FIXTURE_ROOT": _ROOT,
              "SID": binding["originalSid"], "OLD_PID": request["ownerPid"],
              "OLD_TIME": request["ownerStartedAtUtc"], "STATE": _STATE, "CLI": _CLI,
              "CORR": request["ownerNetworkCorrelationId"]}
    for key, value in values.items():
        script = script.replace("@" + key + "@", str(value) if key == "OLD_PID" else _ps(str(value)))
    if re.search(r"@[A-Z][A-Z_]+@", script):
        raise WindowsFixtureOwnerNetworkError("Owner observer template is incomplete.")
    if len(base64.b64encode(script.encode("utf-16le"))) >= 30000:
        raise WindowsFixtureOwnerNetworkError("Owner observer exceeds QGA command admission.")
    return script


def _cleanup_script(request: Mapping[str, Any], binding: Mapping[str, Any]) -> str:
    """Remove only the exact completed owner task; an existing proof permits readback."""
    task = "VpnControlMcpOwnerNetwork-" + request["ownerNetworkCorrelationId"]
    arguments = "-NoProfile -NonInteractive -EncodedCommand " + base64.b64encode(
        _task_script(request, binding).encode("utf-16le")).decode("ascii")
    action_hash = hashlib.sha256(arguments.encode()).hexdigest()
    script = r'''$ErrorActionPreference='Stop'
try {
 $root=@ROOT@;$sid=@SID@;$taskName=@TASK@;$proofPath=Join-Path $root 'task-cleanup.json'
 foreach($ancestor in @(@DRIVE_ROOT@,@USERS_ROOT@,@USER_ROOT@,@APPDATA_ROOT@,@LOCAL_ROOT@,@FIXTURE_ROOT@,$root)){
  $entry=Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
  if(-not $entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'PATH_ANCESTOR'}
 }
 $allowed=@('S-1-5-18','S-1-5-32-544',$sid)
 function GuardPrivate($path,$directory){
  $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
  if($item.PSIsContainer -ne $directory -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'PRIVATE_PATH'}
  if(-not $directory -and ($item.Length -lt 2 -or $item.Length -gt 8192)){throw 'PRIVATE_SIZE'}
  $acl=Get-Acl -LiteralPath $path
  if(-not $acl.AreAccessRulesProtected){throw 'PRIVATE_ACL'}
  foreach($rule in @($acl.Access)){
   $ruleSid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
   if($rule.AccessControlType -ne 'Allow' -or $rule.IsInherited -or $ruleSid -notin $allowed){throw 'PRIVATE_ACL'}
  }
 }
 GuardPrivate $root $true
 GuardPrivate (Join-Path $root 'result.json') $false
 $task=Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue
 if($null -ne $task){
  $info=Get-ScheduledTaskInfo -TaskPath '\' -TaskName $taskName -ErrorAction Stop
  $actions=@($task.Actions)
  if($task.State -ne 'Ready' -or $info.LastTaskResult -ne 0 -or $actions.Count -ne 1 -or
     $actions[0].Execute -cne 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -or
     $task.Principal.UserId -cne 'VPNMSIX64\vpncp117' -or
     $task.Principal.RunLevel -ne 'Limited' -or $task.Principal.LogonType -ne 'Interactive'){throw 'TASK_CHANGED'}
  $digest=[Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$actions[0].Arguments))
  if(([BitConverter]::ToString($digest)).Replace('-','').ToLowerInvariant() -cne @ACTION_HASH@){throw 'TASK_ACTION_CHANGED'}
  if(-not [IO.File]::Exists($proofPath)){
   $proof=[pscustomobject]@{schemaVersion=1;correlationId=@CORR@;taskName=$taskName;
    actionSha256=@ACTION_HASH@;terminalExitCode=0;taskWasPresent=$true}
   $proof|ConvertTo-Json -Compress|Set-Content -LiteralPath $proofPath -Encoding UTF8
   $acl=Get-Acl -LiteralPath $proofPath
   $acl.SetAccessRuleProtection($true,$false)
   foreach($entry in @($acl.Access)){[void]$acl.RemoveAccessRuleSpecific($entry)}
   foreach($entrySid in $allowed){
    $rule=[Security.AccessControl.FileSystemAccessRule]::new(
     [Security.Principal.SecurityIdentifier]::new($entrySid),
     [Security.AccessControl.FileSystemRights]::FullControl,
     [Security.AccessControl.InheritanceFlags]::None,[Security.AccessControl.PropagationFlags]::None,
     [Security.AccessControl.AccessControlType]::Allow)
    [void]$acl.AddAccessRule($rule)
   }
   Set-Acl -LiteralPath $proofPath -AclObject $acl
  }
  GuardPrivate $proofPath $false
  $proof=Get-Content -LiteralPath $proofPath -Raw|ConvertFrom-Json
  if($proof.schemaVersion -ne 1 -or $proof.correlationId -cne @CORR@ -or
     $proof.taskName -cne $taskName -or $proof.actionSha256 -cne @ACTION_HASH@ -or
     $proof.terminalExitCode -ne 0 -or $proof.taskWasPresent -ne $true){throw 'CLEANUP_PROOF_CHANGED'}
  Unregister-ScheduledTask -TaskPath '\' -TaskName $taskName -Confirm:$false -ErrorAction Stop
 }
 GuardPrivate $proofPath $false
 $proof=Get-Content -LiteralPath $proofPath -Raw|ConvertFrom-Json
 if($proof.schemaVersion -ne 1 -or $proof.correlationId -cne @CORR@ -or
    $proof.taskName -cne $taskName -or $proof.actionSha256 -cne @ACTION_HASH@ -or
    $proof.terminalExitCode -ne 0 -or $proof.taskWasPresent -ne $true -or
    $null -ne (Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue)){
  throw 'TASK_CLEANUP_UNKNOWN'}
 ([pscustomobject]@{schemaVersion=1;correlationId=@CORR@;taskName=$taskName;
  actionSha256=@ACTION_HASH@;taskAbsent=$true;
  cleanupProofSha256=(Get-FileHash -LiteralPath $proofPath -Algorithm SHA256).Hash.ToLowerInvariant()}|
  ConvertTo-Json -Compress)
}catch{exit 1}
'''
    values = {"ROOT": _ROOT + r"\mcp-owner-network-" + request["ownerNetworkCorrelationId"],
              "DRIVE_ROOT": "C:\\", "USERS_ROOT": r"C:\Users",
              "USER_ROOT": r"C:\Users\vpncp117", "APPDATA_ROOT": r"C:\Users\vpncp117\AppData",
              "LOCAL_ROOT": r"C:\Users\vpncp117\AppData\Local", "FIXTURE_ROOT": _ROOT,
              "SID": binding["originalSid"], "TASK": task,
              "ACTION_HASH": action_hash, "CORR": request["ownerNetworkCorrelationId"]}
    for key, value in values.items():
        script = script.replace("@" + key + "@", _ps(str(value)))
    if re.search(r"@[A-Z][A-Z_]+@", script) or len(base64.b64encode(script.encode("utf-16le"))) >= 30000:
        raise WindowsFixtureOwnerNetworkError("Owner cleanup exceeds QGA admission.")
    return script


def _validate_terminal(request: Mapping[str, Any], binding: Mapping[str, Any],
                       observed: Mapping[str, Any], provenance: Mapping[str, Any],
                       *, require_cleaned: bool = True) -> dict[str, Any]:
    """Correlate protected task, public quit and fresh replacement owner."""
    fields = {"schemaVersion", "correlationId", "record", "taskState", "taskExitCode",
              "cleanupProofSha256",
              "ownerPid", "ownerStartedAtUtc", "controllerId", "originalSid",
              "sessionId", "activeProcessCount"}
    record_fields = {"schemaVersion", "correlationId", "oldOwnerPid", "oldOwnerStartedAtUtc",
                     "oldControllerId", "newOwnerPid", "newOwnerStartedAtUtc",
                     "newControllerId", "originalSid", "sessionId", "limited",
                     "cliSha256", "proxyHost", "proxyPort", "trustStoreSha256",
                     "runtimeOff", "launchSource"}
    if not isinstance(observed, Mapping) or set(observed) != fields:
        raise WindowsFixtureOwnerNetworkError("Owner launch observation is incomplete.")
    record = observed["record"]
    if not isinstance(record, Mapping) or set(record) != record_fields:
        raise WindowsFixtureOwnerNetworkError("Owner launch result is incomplete.")
    if (observed["schemaVersion"] != 1 or observed["correlationId"] != request["ownerNetworkCorrelationId"]
            or observed["taskState"] not in {"Ready", "AbsentCleaned"}
            or (require_cleaned and observed["taskState"] != "AbsentCleaned")
            or (observed["taskState"] == "Ready" and observed["cleanupProofSha256"] is not None)
            or (observed["taskState"] == "AbsentCleaned" and
                (not isinstance(observed["cleanupProofSha256"], str) or
                 not re.fullmatch(r"[0-9a-f]{64}", observed["cleanupProofSha256"])))
            or type(observed["taskExitCode"]) is not int
            or observed["taskExitCode"] != 0 or type(observed["activeProcessCount"]) is not int
            or observed["activeProcessCount"] != 0 or observed["originalSid"] != binding["originalSid"]
            or type(observed["sessionId"]) is not int or observed["sessionId"] != 1
            or record["schemaVersion"] != 1 or record["correlationId"] != request["ownerNetworkCorrelationId"]
            or type(record["oldOwnerPid"]) is not int or record["oldOwnerPid"] != request["ownerPid"]
            or record["oldOwnerStartedAtUtc"] != request["ownerStartedAtUtc"]
            or record["oldControllerId"] != request["controllerId"]
            or type(record["newOwnerPid"]) is not int or record["newOwnerPid"] <= 0
            or record["newOwnerPid"] == request["ownerPid"]
            or not isinstance(record["newOwnerStartedAtUtc"], str)
            or not _UTC.fullmatch(record["newOwnerStartedAtUtc"])
            or not _canonical(record["newControllerId"])
            or record["newControllerId"] == request["controllerId"]
            or record["originalSid"] != binding["originalSid"]
            or type(record["sessionId"]) is not int or record["sessionId"] != 1
            or record["limited"] is not True or record["cliSha256"] != binding["baseCliSha256"]
            or record["proxyHost"] != "127.0.0.1" or type(record["proxyPort"]) is not int
            or record["proxyPort"] != binding["serverPort"]
            or record["trustStoreSha256"] != binding["trustStoreSha256"]
            or record["runtimeOff"] is not True
            or record["launchSource"] != "limited-task-process-environment"
            or type(observed["ownerPid"]) is not int
            or observed["ownerPid"] != record["newOwnerPid"]
            or observed["ownerStartedAtUtc"] != record["newOwnerStartedAtUtc"]
            or observed["controllerId"] != record["newControllerId"]):
        raise WindowsFixtureOwnerNetworkError("Owner launch generation or JVM source changed.")
    if (not isinstance(provenance, Mapping)
            or set(provenance) != {"state", "ownerNetworkCorrelationId", "bootstrapExitCode",
                                   "bindingSha256", "dispatchPid"}
            or provenance["state"] != "terminal"
            or provenance["ownerNetworkCorrelationId"] != request["ownerNetworkCorrelationId"]
            or type(provenance["bootstrapExitCode"]) is not int
            or provenance["bootstrapExitCode"] != 0
            or not isinstance(provenance["bindingSha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", provenance["bindingSha256"])
            or type(provenance["dispatchPid"]) is not int or provenance["dispatchPid"] <= 0):
        raise WindowsFixtureOwnerNetworkError("Owner bootstrap provenance is incomplete.")
    evidence = {"request": dict(request), "binding": dict(binding),
                "observation": dict(observed), "provenance": dict(provenance)}
    digest = hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"leaseId": request["leaseId"], "sourceSha": request["sourceSha"],
            "fixtureReceiptArtifactId": request["fixtureReceiptArtifactId"],
            "baseMsiArtifactId": request["baseMsiArtifactId"],
            "targetMsiArtifactId": request["targetMsiArtifactId"],
            "socketPath": binding["socketPath"], "qemuPid": binding["qemuPid"],
            "startTicks": binding["startTicks"], "originalSid": binding["originalSid"],
            "stageCorrelationId": request["stageCorrelationId"],
            "serverCorrelationId": request["serverCorrelationId"],
            "ownerNetworkCorrelationId": request["ownerNetworkCorrelationId"],
            "oldOwnerPid": request["ownerPid"],
            "oldOwnerStartedAtUtc": request["ownerStartedAtUtc"],
            "oldControllerId": request["controllerId"],
            "ownerPid": record["newOwnerPid"],
            "ownerStartedAtUtc": record["newOwnerStartedAtUtc"],
            "controllerId": record["newControllerId"],
            "ownerJvmNetworkVerified": False, "ownerJvmPid": record["newOwnerPid"],
            "ownerJvmStartedAtUtc": record["newOwnerStartedAtUtc"],
            "ownerJvmProxyPort": binding["serverPort"],
            "ownerJvmTrustStoreSha256": binding["trustStoreSha256"],
            "ownerTaskCleanupSha256": observed["cleanupProofSha256"],
            "liveReceiptSha256": binding["liveReceiptSha256"],
            "bootstrapBindingSha256": provenance["bindingSha256"],
            "bootstrapDispatchPid": provenance["dispatchPid"],
            "ownerLaunchReceiptSha256": digest}


def _read_native(root: Path, binding: Mapping[str, Any], script: str) -> dict[str, Any]:
    """Execute only a fixed, bounded QGA PowerShell observer on the owned VM."""
    config, _target, (env, socket, pid, ticks, sid) = base._descriptor(root)
    if ((env, socket, pid, ticks, sid) !=
            ("windows-cp117", binding["socketPath"], binding["qemuPid"],
             binding["startTicks"], binding["originalSid"])):
        raise WindowsFixtureOwnerNetworkError("Owned CP117 guest generation changed.")
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    if len(encoded) >= 30000:
        raise WindowsFixtureOwnerNetworkError("Owner observer exceeds QGA admission.")
    raw = base._remote(config, server._REMOTE_LIVE,
                       (socket, str(pid), str(ticks), encoded), None, 30)
    try:
        value = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError):
        value = None
    result = value.get("result") if isinstance(value, dict) and value.get("state") == "observed" else None
    if not isinstance(result, dict):
        raise WindowsFixtureOwnerNetworkError("CP117 owner native observation is unknown.")
    return result


def _preflight_native(root: Path, request: Mapping[str, Any],
                      binding: Mapping[str, Any]) -> dict[str, Any]:
    observed = _read_native(root, binding, _preflight_script(request, binding))
    _validate_preflight(request, binding, observed)
    return observed


def _observe_native(root: Path, request: Mapping[str, Any],
                    binding: Mapping[str, Any], provenance: Mapping[str, Any],
                    *, require_cleaned: bool = True) -> dict[str, Any]:
    observed = _read_native(root, binding, _observation_script(request, binding))
    return _validate_terminal(request, binding, observed, provenance,
                              require_cleaned=require_cleaned)


_REMOTE_CLEANUP = base._QGA + lease.remote_role_guard() + r'''import time
root,env,lease_id,corr,sock,pid,ticks,encoded,source,receipt_id,base_id,target_id=sys.argv[1:]
def out(value):print(json.dumps(value,sort_keys=True,separators=(',',':')))
try:
 if env!='windows-cp117' or len(encoded)>=30000 or not live(sock,pid,ticks):raise ValueError()
 require_campaign_role(root,env,lease_id,'owner-network',corr,source,receipt_id,base_id,target_id,sock,pid,ticks)
 child=call(sock,'guest-exec',{'path':'powershell.exe',
  'arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(80):
  result=call(sock,'guest-exec-status',{'pid':child})
  if result.get('exited') is True:break
  time.sleep(.2)
 else:raise ValueError()
 if result.get('exitcode')!=0 or result.get('out-truncated') is not False or result.get('err-truncated') is not False:raise ValueError()
 raw=base64.b64decode(result.get('out-data',''),validate=True)
 if not 0<len(raw)<=4096:raise ValueError()
 out({'state':'observed','result':json.loads(decode(raw))})
except Exception:out({'state':'unknown'})
'''


def _cleanup_native(root: Path, request: Mapping[str, Any], binding: Mapping[str, Any]) -> str:
    """Bounded exact task cleanup; a lost response can use protected guest proof."""
    config, target, (env, socket, pid, ticks, sid) = base._descriptor(root)
    if (env, socket, pid, ticks, sid) != ("windows-cp117", binding["socketPath"],
                                         binding["qemuPid"], binding["startTicks"],
                                         binding["originalSid"]):
        raise WindowsFixtureOwnerNetworkError("Owner cleanup guest generation changed.")
    encoded = base64.b64encode(_cleanup_script(request, binding).encode("utf-16le")).decode("ascii")
    raw = base._remote(config, _REMOTE_CLEANUP,
                       (str(target.fixture_transfer_root), "windows-cp117", request["leaseId"],
                        request["ownerNetworkCorrelationId"], socket, str(pid), str(ticks), encoded,
                        request["sourceSha"], request["fixtureReceiptArtifactId"],
                        request["baseMsiArtifactId"], request["targetMsiArtifactId"]), None, 30)
    try:
        value = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError):
        value = None
    result = value.get("result") if isinstance(value, dict) and value.get("state") == "observed" else None
    task = "VpnControlMcpOwnerNetwork-" + request["ownerNetworkCorrelationId"]
    arguments = "-NoProfile -NonInteractive -EncodedCommand " + base64.b64encode(
        _task_script(request, binding).encode("utf-16le")).decode("ascii")
    action_hash = hashlib.sha256(arguments.encode()).hexdigest()
    if (not isinstance(result, dict) or
            set(result) != {"schemaVersion", "correlationId", "taskName", "actionSha256",
                            "taskAbsent", "cleanupProofSha256"} or
            result["schemaVersion"] != 1 or
            result["correlationId"] != request["ownerNetworkCorrelationId"] or
            result["taskName"] != task or result["actionSha256"] != action_hash or
            result["taskAbsent"] is not True or
            not isinstance(result["cleanupProofSha256"], str) or
            not re.fullmatch(r"[0-9a-f]{64}", result["cleanupProofSha256"])):
        raise WindowsFixtureOwnerNetworkError("Owner task cleanup is unknown.")
    return result["cleanupProofSha256"]


def _intent_path(root: Path, correlation: str) -> Path:
    return root / _GROUP / (correlation + ".json")


def _terminal_path(root: Path, correlation: str) -> Path:
    return root / _GROUP / (correlation + ".receipt")


def _read_private(path: Path, limit: int = 16384) -> dict[str, Any] | None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > limit):
            raise WindowsFixtureOwnerNetworkError("Owner network journal is unsafe.")
        try:
            value = json.load(stream)
        except (TypeError, ValueError) as error:
            raise WindowsFixtureOwnerNetworkError("Owner network journal is invalid.") from error
    if not isinstance(value, dict):
        raise WindowsFixtureOwnerNetworkError("Owner network journal is invalid.")
    return value


def _write_private(path: Path, value: Mapping[str, Any]) -> None:
    body = (json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(body) > 16384:
        raise WindowsFixtureOwnerNetworkError("Owner network journal exceeds limit.")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(body); stream.flush(); os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _closed_prior_campaign(root: Path, intent: Mapping[str, Any]) -> bool:
    """A prior route is reusable only after exact local and remote lease closure."""
    try:
        prior_request = _request(intent["request"])
        prior_binding = intent["binding"]
        if not isinstance(prior_binding, dict):
            return False
        directory, lock = lease._locked(root)
        try:
            closed = lease._closed(directory, prior_request["leaseId"])
        finally:
            os.close(lock)
        if closed is None:
            return False
        identity = closed["identity"]
        if (identity["sourceSha"] != prior_request["sourceSha"]
                or any(identity[key] != prior_request[key] for key in
                       ("fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"))
                or identity["socketPath"] != prior_binding.get("socketPath")
                or identity["qemuPid"] != prior_binding.get("qemuPid")
                or identity["startTicks"] != prior_binding.get("startTicks")):
            return False
        config, target, _descriptor = base._descriptor(root)
        return lease._remote_confirm(base._campaign_remote(config, target),
                                     "status", closed, None)
    except (OSError, ValueError, TypeError, KeyError):
        return False


def _prior_history_closed(root: Path, directory: Path, current_correlation: str,
                          current_lease: str) -> None:
    entries = {item.name for item in directory.iterdir()} - {".environment.lock"}
    intents: dict[str, dict[str, Any]] = {}
    for name in entries:
        if name.endswith(".json") and _canonical(name[:-5]):
            correlation = name[:-5]
            intent = _read_intent(root, correlation)
            if intent is None:
                raise WindowsFixtureOwnerNetworkError("Owner network prior intent vanished.")
            intents[correlation] = intent
        elif name.endswith(".receipt") and _canonical(name[:-8]):
            continue
        else:
            raise WindowsFixtureOwnerNetworkError("Owner network has unknown prior history.")
    if current_correlation in intents:
        raise WindowsFixtureOwnerNetworkError("Owner network correlation was already used.")
    for name in entries:
        if name.endswith(".receipt") and name[:-8] not in intents:
            raise WindowsFixtureOwnerNetworkError("Owner network has orphan terminal receipt.")
    for intent in intents.values():
        if intent["request"].get("leaseId") == current_lease or not _closed_prior_campaign(root, intent):
            raise WindowsFixtureOwnerNetworkError("Owner network prior campaign is not remotely closed.")


def _reserve(root: Path, request: Mapping[str, Any], binding: Mapping[str, Any],
             command_sha256: str) -> None:
    directory = root / _GROUP
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink()
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsFixtureOwnerNetworkError("Owner network journal directory is unsafe.")
    fd = os.open(directory / ".environment.lock", os.O_RDWR | os.O_CREAT |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise WindowsFixtureOwnerNetworkError("Owner network journal lock is unsafe.")
        fcntl.flock(fd, fcntl.LOCK_EX)
        _prior_history_closed(root, directory, request["ownerNetworkCorrelationId"], request["leaseId"])
        _write_private(_intent_path(root, request["ownerNetworkCorrelationId"]),
                       {"request": dict(request), "binding": dict(binding),
                        "commandSha256": command_sha256})
    finally:
        os.close(fd)


def _read_intent(root: Path, correlation: str) -> dict[str, Any] | None:
    if not _canonical(correlation):
        raise WindowsFixtureOwnerNetworkError("Owner network correlation is invalid.")
    path = _intent_path(root, correlation)
    value = _read_private(path)
    if value is not None and (set(value) != {"request", "binding", "commandSha256"}
                              or value["request"].get("ownerNetworkCorrelationId") != correlation
                              or not isinstance(value["commandSha256"], str)
                              or not re.fullmatch(r"[0-9a-f]{64}", value["commandSha256"])):
        raise WindowsFixtureOwnerNetworkError("Owner network intent is invalid.")
    return value


_REMOTE_START = base._QGA + lease.remote_role_guard() + r'''import fcntl,re
root,env,lease_id,corr,sock,pid,ticks,encoded,command_hash,source,receipt_id,base_id,target_id=sys.argv[1:]
def out(value):print(json.dumps(value,sort_keys=True,separators=(',',':')))
def private_file(path):
 fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 with os.fdopen(fd,'rb') as file:
  info=os.fstat(file.fileno())
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>16384:raise ValueError()
  return json.load(file)
try:
 if env!='windows-cp117' or len(encoded)>=30000 or not live(sock,pid,ticks):raise ValueError()
 command=base64.b64decode(encoded,validate=True)
 if hashlib.sha256(command).hexdigest()!=command_hash:raise ValueError()
 require_campaign_role(root,env,lease_id,'owner-network',corr,source,receipt_id,base_id,target_id,sock,pid,ticks)
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-owner-network')
 if not os.path.exists(group):os.mkdir(group,0o700)
 info=os.lstat(group)
 if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 lock=os.open(os.path.join(group,'.environment.lock'),os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
 try:
  info=os.fstat(lock)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError()
  fcntl.flock(lock,fcntl.LOCK_EX)
  for name in os.listdir(group):
   if name=='.environment.lock':continue
   if not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',name) or name==corr:raise ValueError()
   old=os.path.join(group,name);old_info=os.lstat(old)
   if not stat.S_ISDIR(old_info.st_mode) or stat.S_ISLNK(old_info.st_mode) or old_info.st_uid!=os.geteuid() or stat.S_IMODE(old_info.st_mode)!=0o700:raise ValueError()
   old_binding=private_file(os.path.join(old,'binding.json'))
   if old_binding.get('ownerNetworkCorrelationId')!=name:raise ValueError()
   prior_lease=old_binding.get('leaseId')
   if not isinstance(prior_lease,str) or prior_lease==lease_id or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',prior_lease):raise ValueError()
   closed=private_file(os.path.join(parent,'windows-cp117-campaign',prior_lease+'.closed.json'))
   prior=closed.get('identity')
   if closed.get('state')!='closed' or closed.get('role') is not None or not isinstance(prior,dict) or prior.get('leaseId')!=prior_lease or prior.get('host')!='archlinux' or prior.get('environment')!=env or prior.get('sourceSha')!=old_binding.get('sourceSha') or any(prior.get(key)!=old_binding.get(key) for key in ('fixtureReceiptArtifactId','baseMsiArtifactId','targetMsiArtifactId','socketPath','qemuPid','startTicks')):raise ValueError()
  job=os.path.join(group,corr);os.mkdir(job,0o700)
 finally:os.close(lock)
 binding={'leaseId':lease_id,'ownerNetworkCorrelationId':corr,'socketPath':sock,
  'qemuPid':int(pid),'startTicks':int(ticks),'sourceSha':source,
  'fixtureReceiptArtifactId':receipt_id,'baseMsiArtifactId':base_id,
  'targetMsiArtifactId':target_id,'commandSha256':command_hash}
 item=os.open(os.path.join(job,'binding.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(item,'w',encoding='utf-8') as file:
  json.dump(binding,file,sort_keys=True,separators=(',',':'));file.flush();os.fsync(file.fileno())
 child=call(sock,'guest-exec',{'path':'powershell.exe',
  'arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 item=os.open(os.path.join(job,'dispatch.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(item,'w',encoding='utf-8') as file:
  json.dump({'pid':child},file);file.flush();os.fsync(file.fileno())
 out({'state':'submitted','ownerNetworkCorrelationId':corr})
except Exception:out({'state':'unknown','ownerNetworkCorrelationId':corr})
'''


_REMOTE_STATUS = base._QGA + r'''import fcntl
root,env,lease_id,corr,sock,pid,ticks,source,receipt_id,base_id,target_id,command_hash=sys.argv[1:]
def out(value):print(json.dumps(value,sort_keys=True,separators=(',',':')))
def private_file(path):
 fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 with os.fdopen(fd,'rb') as file:
  info=os.fstat(file.fileno())
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>8192:raise ValueError()
  return json.load(file)
try:
 if env!='windows-cp117' or not live(sock,pid,ticks):raise ValueError()
 job=os.path.join(root,env,'windows-owner-network',corr)
 for path in (root,os.path.join(root,env),os.path.dirname(job),job):
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 binding=private_file(os.path.join(job,'binding.json'))
 expected={'leaseId':lease_id,'ownerNetworkCorrelationId':corr,'socketPath':sock,
  'qemuPid':int(pid),'startTicks':int(ticks),'sourceSha':source,
  'fixtureReceiptArtifactId':receipt_id,'baseMsiArtifactId':base_id,
  'targetMsiArtifactId':target_id,'commandSha256':command_hash}
 if binding!=expected:raise ValueError()
 dispatch=private_file(os.path.join(job,'dispatch.json'))
 if set(dispatch)!={'pid'} or type(dispatch['pid']) is not int or dispatch['pid']<=0:raise ValueError()
 terminal=os.path.join(job,'bootstrap-terminal.json')
 lock=os.open(os.path.join(job,'.status.lock'),os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
 try:
  info=os.fstat(lock)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError()
  fcntl.flock(lock,fcntl.LOCK_EX)
  try:result=private_file(terminal)
  except FileNotFoundError:result=None
  if result is None:
   state=call(sock,'guest-exec-status',{'pid':dispatch['pid']})
   if state.get('exited') is not True:
    out({'state':'running','ownerNetworkCorrelationId':corr});raise SystemExit(0)
   result={'exited':state.get('exited'),'exitcode':state.get('exitcode'),
    'out-data':state.get('out-data')}
   raw=json.dumps(result,sort_keys=True,separators=(',',':')).encode()
   if len(raw)>8192:raise ValueError()
   fd=os.open(terminal,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
   with os.fdopen(fd,'wb') as file:file.write(raw);file.flush();os.fsync(file.fileno())
   directory=os.open(job,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(directory);os.close(directory)
 finally:os.close(lock)
 if set(result)!={'exited','exitcode','out-data'} or result['exited'] is not True or type(result['exitcode']) is not int or result['exitcode']!=0 or not isinstance(result['out-data'],str):raise ValueError()
 output=base64.b64decode(result['out-data'],validate=True)
 if len(output)>4096:raise ValueError()
 lines=[line for line in decode(output).splitlines() if line.startswith('{') and line.endswith('}')]
 if len(lines)!=1:raise ValueError()
 observed=json.loads(lines[0]);task='VpnControlMcpOwnerNetwork-'+corr
 if observed!={'schemaVersion':1,'correlationId':corr,'taskName':task,'submitted':True}:raise ValueError()
 out({'state':'terminal','ownerNetworkCorrelationId':corr,'bootstrapExitCode':0,
  'bindingSha256':hashlib.sha256(json.dumps(binding,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
  'dispatchPid':dispatch['pid']})
except Exception:out({'state':'unknown','ownerNetworkCorrelationId':corr})
'''


def _remote_provenance(root: Path, request: Mapping[str, Any],
                       binding: Mapping[str, Any], command_hash: str) -> dict[str, Any]:
    config, target, _descriptor = base._descriptor(root)
    raw = base._remote(config, _REMOTE_STATUS,
                       (str(target.fixture_transfer_root), "windows-cp117", request["leaseId"],
                        request["ownerNetworkCorrelationId"], binding["socketPath"],
                        str(binding["qemuPid"]), str(binding["startTicks"]), request["sourceSha"],
                        request["fixtureReceiptArtifactId"], request["baseMsiArtifactId"],
                        request["targetMsiArtifactId"], command_hash), None, 30)
    try:
        value = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError):
        value = None
    expected_binding = {"leaseId": request["leaseId"],
                        "ownerNetworkCorrelationId": request["ownerNetworkCorrelationId"],
                        "socketPath": binding["socketPath"], "qemuPid": binding["qemuPid"],
                        "startTicks": binding["startTicks"], "sourceSha": request["sourceSha"],
                        "fixtureReceiptArtifactId": request["fixtureReceiptArtifactId"],
                        "baseMsiArtifactId": request["baseMsiArtifactId"],
                        "targetMsiArtifactId": request["targetMsiArtifactId"],
                        "commandSha256": command_hash}
    digest = hashlib.sha256(json.dumps(expected_binding, sort_keys=True,
                                       separators=(",", ":")).encode()).hexdigest()
    if (not isinstance(value, dict) or set(value) != {"state", "ownerNetworkCorrelationId",
                                                     "bootstrapExitCode", "bindingSha256", "dispatchPid"}
            or value["state"] != "terminal"
            or value["ownerNetworkCorrelationId"] != request["ownerNetworkCorrelationId"]
            or type(value["bootstrapExitCode"]) is not int or value["bootstrapExitCode"] != 0
            or value["bindingSha256"] != digest
            or type(value["dispatchPid"]) is not int or value["dispatchPid"] <= 0):
        raise WindowsFixtureOwnerNetworkError("Owner bootstrap provenance is unknown.")
    return value


def _submit_candidate(root: Path, request: Mapping[str, Any],
                      binding: Mapping[str, Any]) -> dict[str, Any]:
    """Review candidate. Public start remains locked until independent review."""
    config, target, _descriptor = base._descriptor(root)
    _preflight_native(root, request, binding)
    command = _bootstrap_script(request, binding)
    encoded = base64.b64encode(command.encode("utf-16le")).decode("ascii")
    command_hash = hashlib.sha256(command.encode("utf-16le")).hexdigest()
    _reserve(root, request, binding, command_hash)
    claimed = lease.claim_role(root, request["leaseId"], "owner-network",
                               request["ownerNetworkCorrelationId"],
                               base._campaign_remote(config, target))
    if claimed.get("state") != "role-active":
        return {"state": "unknown", "ownerNetworkCorrelationId": request["ownerNetworkCorrelationId"],
                "replayAllowed": False}
    if _binding(root, request) != binding:
        raise WindowsFixtureOwnerNetworkError("Owner network binding changed after claim.")
    _preflight_native(root, request, binding)
    raw = base._remote(config, _REMOTE_START,
                       (str(target.fixture_transfer_root), "windows-cp117", request["leaseId"],
                        request["ownerNetworkCorrelationId"], binding["socketPath"],
                        str(binding["qemuPid"]), str(binding["startTicks"]), encoded,
                        command_hash, request["sourceSha"], request["fixtureReceiptArtifactId"],
                        request["baseMsiArtifactId"], request["targetMsiArtifactId"]), None, 30)
    try:
        result = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError):
        result = None
    state = "submitted" if result == {"state": "submitted",
                                    "ownerNetworkCorrelationId": request["ownerNetworkCorrelationId"]} else "unknown"
    return {"state": state, "ownerNetworkCorrelationId": request["ownerNetworkCorrelationId"],
            "replayAllowed": False}


def _terminal_receipt(root: Path, correlation: str) -> dict[str, Any] | None:
    value = _read_private(_terminal_path(root, correlation))
    if value is not None and (value.get("ownerNetworkCorrelationId") != correlation
                              or value.get("ownerJvmNetworkVerified") is not False
                              or not isinstance(value.get("ownerLaunchReceiptSha256"), str)
                              or not re.fullmatch(r"[0-9a-f]{64}", value["ownerLaunchReceiptSha256"])):
        raise WindowsFixtureOwnerNetworkError("Owner network terminal receipt is invalid.")
    return value


def _save_terminal(root: Path, receipt: Mapping[str, Any]) -> None:
    correlation = receipt["ownerNetworkCorrelationId"]
    prior = _terminal_receipt(root, correlation)
    if prior is not None:
        if prior != dict(receipt):
            raise WindowsFixtureOwnerNetworkError("Owner network terminal receipt changed.")
        return
    _write_private(_terminal_path(root, correlation), receipt)


def _unknown(correlation: str, *, cleanup: bool) -> dict[str, Any]:
    return {"state": "unknown", "ownerNetworkCorrelationId": correlation,
            "cleanupRequired": cleanup, "replayAllowed": False,
            "ownerJvmNetworkVerified": False}


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if (not isinstance(value, Mapping) or set(value) != {"ownerNetworkCorrelationId"}
            or not _canonical(value["ownerNetworkCorrelationId"])):
        raise WindowsFixtureOwnerNetworkError("Owner network status requires exact correlation.")
    root = Path(root).resolve(strict=True)
    correlation = value["ownerNetworkCorrelationId"]
    intent = _read_intent(root, correlation)
    if intent is None:
        return _unknown(correlation, cleanup=False)
    try:
        request = _request(intent["request"])
        binding = _binding(root, request, allow_join=True)
        if intent["binding"] != binding:
            raise WindowsFixtureOwnerNetworkError("Owner network intent binding changed.")
        if hashlib.sha256(_bootstrap_script(request, binding).encode("utf-16le")).hexdigest() != intent["commandSha256"]:
            raise WindowsFixtureOwnerNetworkError("Owner network command changed.")
        provenance = _remote_provenance(root, request, binding, intent["commandSha256"])
        directory, lock = lease._locked(root)
        try:
            current = lease._active(directory)
        finally:
            os.close(lock)
        if (current is None or current["identity"]["leaseId"] != request["leaseId"]
                or current["server"] != "live" or current["credentials"] != "ready"):
            raise WindowsFixtureOwnerNetworkError("Owner network campaign changed.")
        if (current["state"] == "role-active" and current["role"] == "owner-network"
                and current["correlationId"] == correlation):
            _observe_native(root, request, binding, provenance, require_cleaned=False)
            cleaned_hash = _cleanup_native(root, request, binding)
            receipt = _observe_native(root, request, binding, provenance)
            if receipt["ownerTaskCleanupSha256"] != cleaned_hash:
                return _unknown(correlation, cleanup=True)
            config, target, _descriptor = base._descriptor(root)
            finished = lease.finish_role(root, request["leaseId"], "owner-network", correlation,
                                         receipt["ownerLaunchReceiptSha256"], "succeeded",
                                         base._campaign_remote(config, target))
            if finished.get("state") != "active":
                return _unknown(correlation, cleanup=True)
        elif current["state"] == "active" and current["role"] is None:
            receipt = _observe_native(root, request, binding, provenance)
            prior = _terminal_receipt(root, correlation)
            if prior is None and (current["lastEvidenceSha256"] != receipt["ownerLaunchReceiptSha256"]
                                  or current["lastOutcome"] != "succeeded"):
                return _unknown(correlation, cleanup=True)
            if prior is not None and prior != receipt:
                return _unknown(correlation, cleanup=True)
        elif (current["state"] == "role-active"
              and current["role"] in {"network-probe", "target", "public"}):
            receipt = _observe_native(root, request, binding, provenance)
            if _terminal_receipt(root, correlation) != receipt:
                return _unknown(correlation, cleanup=True)
        else:
            return _unknown(correlation, cleanup=True)
        _save_terminal(root, receipt)
        return {"state": "correlated", "ownerNetworkCorrelationId": correlation,
                "ownerPid": receipt["ownerPid"], "ownerStartedAtUtc": receipt["ownerStartedAtUtc"],
                "controllerId": receipt["controllerId"],
                "ownerLaunchReceiptSha256": receipt["ownerLaunchReceiptSha256"],
                "cleanupRequired": True, "replayAllowed": False,
                "ownerJvmNetworkVerified": False}
    except (OSError, ValueError, TypeError, KeyError):
        return _unknown(correlation, cleanup=True)


def collect(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    return status(root, value)


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Submit one fixed task after exact admission; status owns reconciliation."""
    request = _request(value)
    root = Path(root).resolve(strict=True)
    existing = _read_intent(root, request["ownerNetworkCorrelationId"])
    if existing is not None:
        if existing["request"] != request:
            raise WindowsFixtureOwnerNetworkError("Owner network correlation belongs to another request.")
        return _unknown(request["ownerNetworkCorrelationId"], cleanup=True)
    binding = _binding(root, request)
    directory, lock = lease._locked(root)
    try:
        current = lease._active(directory)
        if (current is None or current.get("identity", {}).get("leaseId") != request["leaseId"]
                or current.get("state") != "active" or current.get("role") is not None):
            raise WindowsFixtureOwnerNetworkError("Owner network start requires an idle campaign.")
    finally:
        os.close(lock)
    return _submit_candidate(root, request, binding)


def verified_owner_jvm_receipt(root: Path | str, lease_id: str) -> dict[str, Any]:
    """Internal probe join; no static/request receipt can attest a JVM."""
    if not _canonical(lease_id):
        raise WindowsFixtureOwnerNetworkError("Owner network lease is invalid.")
    root = Path(root).resolve(strict=True)
    directory = root / _GROUP
    try:
        info = directory.lstat()
    except FileNotFoundError:
        raise WindowsFixtureOwnerNetworkError("OWNER_JVM_RECEIPT_UNAVAILABLE") from None
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink()
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsFixtureOwnerNetworkError("OWNER_JVM_RECEIPT_UNAVAILABLE")
    entries = [entry for entry in directory.iterdir() if entry.suffix == ".json"]
    selected = []
    for entry in entries:
        if not _canonical(entry.stem):
            raise WindowsFixtureOwnerNetworkError("OWNER_JVM_RECEIPT_UNAVAILABLE")
        candidate = _read_intent(root, entry.stem)
        if candidate is None:
            raise WindowsFixtureOwnerNetworkError("OWNER_JVM_RECEIPT_UNAVAILABLE")
        if candidate["request"].get("leaseId") == lease_id:
            selected.append(candidate)
        elif not _closed_prior_campaign(root, candidate):
            raise WindowsFixtureOwnerNetworkError("OWNER_JVM_RECEIPT_UNAVAILABLE")
    if len(selected) != 1:
        raise WindowsFixtureOwnerNetworkError("OWNER_JVM_RECEIPT_UNAVAILABLE")
    intent = selected[0]
    request = _request(intent["request"])
    binding = _binding(root, request, allow_join=True)
    if intent["binding"] != binding:
        raise WindowsFixtureOwnerNetworkError("OWNER_JVM_RECEIPT_UNAVAILABLE")
    provenance = _remote_provenance(root, request, binding, intent["commandSha256"])
    receipt = _observe_native(root, request, binding, provenance)
    if _terminal_receipt(root, request["ownerNetworkCorrelationId"]) != receipt:
        raise WindowsFixtureOwnerNetworkError("OWNER_JVM_RECEIPT_UNAVAILABLE")
    directory, lock = lease._locked(root)
    try:
        current = lease._active(directory)
        if (current is None or current["identity"]["leaseId"] != lease_id
                or current["server"] != "live" or current["credentials"] != "ready"
                or not ((current["state"] == "active" and current["role"] is None) or
                        (current["state"] == "role-active" and
                         current["role"] in {"network-probe", "target", "public"}))):
            raise WindowsFixtureOwnerNetworkError("OWNER_JVM_RECEIPT_UNAVAILABLE")
    finally:
        os.close(lock)
    return receipt
