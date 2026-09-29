"""Fail-closed CP117 original-owner HTTPS transport-probe evidence gate.

The public probe is only evidence when a fresh, private server event agrees with
the exact owner response and current server/credential generation. The native
dispatch is deliberately separate from validation so an uncertain scheduled
task can never be replayed as a new public request.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from typing import Any, Mapping

import base64
import gzip
import fcntl

from . import windows_fixture_credentials as credentials
from . import windows_msi_base_prepare as base
from . import windows_msi_public_scenario as public
from . import windows_update_fixture_server as server
from . import windows_update_fixture_stage as stage
from . import windows_cp117_lease as lease


_CLI = r"C:\Users\vpncp117\AppData\Local\vpn-control\vpn-control-cli.exe"
_STATE = r"C:\Users\vpncp117\AppData\Local\VpnControl\cp166\state"
_ROOT = r"C:\Users\vpncp117\AppData\Local\VpnControl"


def _ps(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _guest_root(correlation_id: str) -> str:
    if not _canonical(correlation_id):
        raise WindowsFixtureNetworkProbeError("Probe correlation is invalid.")
    return _ROOT + r"\mcp-network-probe-" + correlation_id


def _task_script(request: Mapping[str, Any], binding: Mapping[str, Any],
                 trust_store_path: str) -> str:
    """Fixed limited-user task. Only this process inherits proxy and trust."""
    expected_trust = (_ROOT + r"\mcp-update-credentials-" + request["stageCorrelationId"]
                      + r"\fixture-trust.p12")
    if trust_store_path != expected_trust:
        raise WindowsFixtureNetworkProbeError("Probe trust store escaped fixed credential path.")
    script = r'''$ErrorActionPreference='Stop'
$root=@ROOT@;$cli=@CLI@;$state=@STATE@;$trust=@TRUST@
$ownerPid=@OWNER_PID@;$ownerTime=@OWNER_TIME@;$controller=@CONTROLLER@
$sid=@SID@;$corr=@CORR@;$port=@PORT@
function Owner {
 $owner=Get-CimInstance Win32_Process -Filter ('ProcessId='+$ownerPid)
 if($null -eq $owner -or $owner.Name -cne 'vpn-control-cli.exe' -or
    $owner.CreationDate.ToUniversalTime().ToString('o') -cne $ownerTime -or
    $owner.SessionId -ne 1 -or $owner.ExecutablePath -cne $cli){throw 'OWNER_GENERATION'}
 $ownerSid=Invoke-CimMethod -InputObject $owner -MethodName GetOwnerSid
 if($ownerSid.ReturnValue -ne 0 -or $ownerSid.Sid -cne $sid){throw 'OWNER_SID'}
 $lock=Join-Path $state 'vpn-control.lock'
 if(-not [IO.File]::Exists($lock) -or (Get-Content -LiteralPath $lock -Raw).Trim() -cne [string]$ownerPid){throw 'OWNER_LOCK'}
 $endpoint=Get-Content -LiteralPath (Join-Path $state 'activation.port') -Raw|ConvertFrom-Json
 if($endpoint.schemaVersion -ne 1 -or $endpoint.controllerId -cne $controller){throw 'OWNER_ENDPOINT'}
}
try {
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 $limited=-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
 if($identity.User.Value -cne $sid -or (Get-Process -Id $PID).SessionId -ne 1 -or -not $limited){throw 'ORIGINAL_USER'}
 Owner
 if((Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant() -cne @CLI_HASH@){throw 'CLI_CHANGED'}
 if((Get-FileHash -LiteralPath $trust -Algorithm SHA256).Hash.ToLowerInvariant() -cne @TRUST_HASH@){throw 'TRUST_CHANGED'}
 if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match '^(msiexec|consent|sing-box)\.exe$'}).Count -ne 0){throw 'ACTIVE_PRODUCT'}
 $status=& $cli --state-dir $state --json --controller-id $controller --timeout-seconds 15 status|ConvertFrom-Json
 if($LASTEXITCODE -ne 0 -or $status.code -cne 'OK' -or $status.final -ne $true -or
    $status.controllerId -cne $controller -or $status.data.runtimeRunning -ne $false){throw 'OWNER_STATUS'}
 $env:JAVA_TOOL_OPTIONS='-Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort='+$port+
  ' -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort='+$port+
  ' -Djavax.net.ssl.trustStore='+$trust+
  ' -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=changeit'
 Owner
 $response=& $cli --state-dir $state --json --controller-id $controller --timeout-seconds 120 updates transport-probe $corr|ConvertFrom-Json
 $exitCode=$LASTEXITCODE
 if($exitCode -ne 0 -or $response.code -cne 'OK' -or $response.final -ne $true -or
    $response.controllerId -cne $controller){throw 'PUBLIC_PROBE'}
 $data=$response.data
 if($data.correlationId -cne $corr -or $data.manifestSha256 -cne @MANIFEST_HASH@ -or
    $data.peerCertificateSha256 -cne @PEER_HASH@ -or $data.manifestBuildNumber -ne @BUILD@ -or
    $data.availableVersion -cne @VERSION@ -or $data.assetSha256 -cne @TARGET_HASH@ -or
    $data.assetSizeBytes -ne @TARGET_SIZE@){throw 'PUBLIC_TARGET_CHANGED'}
 $record=[pscustomobject]@{schemaVersion=1;correlationId=$corr;originalSid=$identity.User.Value;
  sessionId=1;limited=$true;ownerPid=$ownerPid;ownerStartedAtUtc=$ownerTime;
  controllerId=$controller;cliSha256=@CLI_HASH@;proxyHost='127.0.0.1';proxyPort=$port;
  trustStoreSha256=@TRUST_HASH@;publicResponse=$response}
 $resultPath=Join-Path $root 'result.json'
 $record|ConvertTo-Json -Depth 12 -Compress|Set-Content -LiteralPath $resultPath -Encoding UTF8
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
    values = {"ROOT": _guest_root(request["probeCorrelationId"]), "CLI": _CLI,
              "STATE": _STATE, "TRUST": trust_store_path, "OWNER_PID": request["ownerPid"],
              "OWNER_TIME": request["ownerStartedAtUtc"], "CONTROLLER": request["controllerId"],
              "SID": binding["originalSid"], "CORR": request["probeCorrelationId"],
              "PORT": binding["serverPort"], "CLI_HASH": binding["baseCliSha256"],
              "TRUST_HASH": binding["trustStoreSha256"], "MANIFEST_HASH": binding["manifestSha256"],
              "PEER_HASH": binding["peerCertificateSha256"], "BUILD": binding["manifestBuildNumber"],
              "VERSION": binding["targetVersion"], "TARGET_HASH": binding["targetMsiSha256"],
              "TARGET_SIZE": binding["targetMsiSize"]}
    for key, value in values.items():
        script = script.replace("@" + key + "@", str(value) if key in {"OWNER_PID", "PORT", "BUILD", "TARGET_SIZE"}
                                else _ps(str(value)))
    if re.search(r"@[A-Z][A-Z_]+@", script):
        raise WindowsFixtureNetworkProbeError("Probe task template is incomplete.")
    return script


def _bootstrap_script(request: Mapping[str, Any], binding: Mapping[str, Any],
                      trust_store_path: str) -> str:
    """SYSTEM may register exactly one interactive, limited original-user task."""
    task_name = "VpnControlMcpNetworkProbe-" + request["probeCorrelationId"]
    packed = base64.b64encode(gzip.compress(
        _task_script(request, binding, trust_store_path).encode("utf-16le"), mtime=0)).decode("ascii")
    script = r'''$ErrorActionPreference='Stop'
$root=@ROOT@;$task=@TASK@;$packed=@PACKED@
if([IO.Directory]::Exists($root) -or $null -ne (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)){
 throw 'EXISTING_PROBE'}
[IO.Directory]::CreateDirectory($root)|Out-Null
$acl=Get-Acl -LiteralPath $root
$acl.SetAccessRuleProtection($true,$false)
foreach($entry in @($acl.Access)){[void]$acl.RemoveAccessRuleSpecific($entry)}
foreach($entrySid in @('S-1-5-18','S-1-5-32-544',@SID@)){
 $rule=[Security.AccessControl.FileSystemAccessRule]::new(
  [Security.Principal.SecurityIdentifier]::new($entrySid),
  [Security.AccessControl.FileSystemRights]::FullControl,
  ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
  [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
 [void]$acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $root -AclObject $acl
$bytes=[Convert]::FromBase64String($packed)
$input=[IO.MemoryStream]::new([byte[]]$bytes)
$gzip=[IO.Compression.GzipStream]::new($input,[IO.Compression.CompressionMode]::Decompress)
$output=[IO.MemoryStream]::new();$gzip.CopyTo($output)
$encoded=[Convert]::ToBase64String($output.ToArray())
$gzip.Dispose();$input.Dispose();$output.Dispose()
$action=New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$encoded)
$principal=New-ScheduledTaskPrincipal -UserId @ACCOUNT@ -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskPath '\' -TaskName $task -Action $action -Principal $principal -Settings $settings|Out-Null
Start-ScheduledTask -TaskPath '\' -TaskName $task
([pscustomobject]@{schemaVersion=1;correlationId=@CORR@;taskName=$task;submitted=$true}|ConvertTo-Json -Compress)
'''
    for key, value in {"ROOT": _guest_root(request["probeCorrelationId"]), "TASK": task_name,
                       "PACKED": packed, "ACCOUNT": r"VPNMSIX64\vpncp117",
                       "CORR": request["probeCorrelationId"], "SID": binding["originalSid"]}.items():
        script = script.replace("@" + key + "@", _ps(value))
    if len(base64.b64encode(script.encode("utf-16le"))) >= 30000:
        raise WindowsFixtureNetworkProbeError("Fixed probe bootstrap exceeds QGA bound.")
    return script


def _observation_script(request: Mapping[str, Any], binding: Mapping[str, Any]) -> str:
    """Read completed task and server event through QGA; never call the CLI."""
    event = (_ROOT + r"\mcp-update-fixture-" + request["stageCorrelationId"]
             + "\\server-state\\probe-events\\" + request["probeCorrelationId"] + ".json")
    task_name = "VpnControlMcpNetworkProbe-" + request["probeCorrelationId"]
    arguments = "-NoProfile -NonInteractive -EncodedCommand " + base64.b64encode(
        _task_script(request, binding, _ROOT + r"\mcp-update-credentials-"
                     + request["stageCorrelationId"] + r"\fixture-trust.p12").encode("utf-16le")).decode("ascii")
    digest = hashlib.sha256(arguments.encode()).hexdigest()
    script = r'''$ErrorActionPreference='Stop'
try {
 $root=@ROOT@;$eventPath=@EVENT@;$taskName=@TASK@;$sid=@SID@
 $task=Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction Stop
 $info=Get-ScheduledTaskInfo -TaskPath '\' -TaskName $taskName -ErrorAction Stop
 $action=@($task.Actions)
 if($task.State -ne 'Ready' -or $info.LastTaskResult -ne 0 -or $action.Count -ne 1 -or
    $action[0].Execute -cne 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -or
    $task.Principal.UserId -cne 'VPNMSIX64\vpncp117' -or
    $task.Principal.RunLevel -ne 'Limited' -or $task.Principal.LogonType -ne 'Interactive'){
   throw 'TASK_GENERATION'}
 $argumentHash=[Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$action[0].Arguments))
 $hex=([BitConverter]::ToString($argumentHash)).Replace('-','').ToLowerInvariant()
 if($hex -cne @ARGUMENT_HASH@){throw 'TASK_COMMAND_CHANGED'}
 $resultPath=Join-Path $root 'result.json'
 foreach($path in @($resultPath,$eventPath)){
  $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
  if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
     $item.Length -lt 2 -or $item.Length -gt 16384){throw 'PROOF_FILE_UNSAFE'}
  $acl=Get-Acl -LiteralPath $path -ErrorAction Stop
  if(-not $acl.AreAccessRulesProtected){throw 'PROOF_ACL_INHERITED'}
  $allowed=@('S-1-5-18','S-1-5-32-544',$sid)
  foreach($rule in @($acl.Access)){
   $ruleSid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
   if($rule.AccessControlType -ne 'Allow' -or $rule.IsInherited -or $ruleSid -notin $allowed){throw 'PROOF_ACL_UNSAFE'}
  }
 }
 $record=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
 $event=Get-Content -LiteralPath $eventPath -Raw|ConvertFrom-Json
 $owner=Get-CimInstance Win32_Process -Filter ('ProcessId='+@OWNER_PID@)
 $ownerSid=if($null -ne $owner){Invoke-CimMethod -InputObject $owner -MethodName GetOwnerSid}else{$null}
 $endpoint=Get-Content -LiteralPath (Join-Path @STATE@ 'activation.port') -Raw|ConvertFrom-Json
 $lock=(Get-Content -LiteralPath (Join-Path @STATE@ 'vpn-control.lock') -Raw).Trim()
 $ownerReady=$null -ne $owner -and $owner.Name -ceq 'vpn-control-cli.exe' -and
  $owner.ExecutablePath -ceq @CLI@ -and $owner.CreationDate.ToUniversalTime().ToString('o') -ceq @OWNER_TIME@ -and
  $owner.SessionId -eq 1 -and $ownerSid.ReturnValue -eq 0 -and $ownerSid.Sid -ceq $sid -and
  $endpoint.schemaVersion -eq 1 -and $endpoint.controllerId -ceq @CONTROLLER@ -and
  $lock -ceq @OWNER_PID_TEXT@
 if(-not $ownerReady){throw 'OWNER_CHANGED'}
 $observed=[ordered]@{originalSid=$record.originalSid;sessionId=$record.sessionId;limited=$record.limited;
  ownerPid=$record.ownerPid;ownerStartedAtUtc=$record.ownerStartedAtUtc;controllerId=$record.controllerId;
  cliSha256=$record.cliSha256;proxyHost=$record.proxyHost;proxyPort=$record.proxyPort;
  trustStoreSha256=$record.trustStoreSha256;taskState=[string]$task.State;taskExitCode=[int]$info.LastTaskResult;
  ownerJvmNetworkVerified=$false;ownerJvmPid=$null;ownerJvmStartedAtUtc=$null;
  ownerJvmProxyPort=$null;ownerJvmTrustStoreSha256=$null}
 ([pscustomobject]@{schemaVersion=1;correlationId=@CORR@;observed=$observed;
  publicResponse=$record.publicResponse;event=$event}|ConvertTo-Json -Depth 15 -Compress)
}catch{exit 1}
'''
    values = {"ROOT": _guest_root(request["probeCorrelationId"]), "EVENT": event,
              "TASK": task_name, "SID": binding["originalSid"], "ARGUMENT_HASH": digest,
              "OWNER_PID": request["ownerPid"], "STATE": _STATE, "CLI": _CLI,
              "OWNER_TIME": request["ownerStartedAtUtc"], "CONTROLLER": request["controllerId"],
              "OWNER_PID_TEXT": str(request["ownerPid"]), "CORR": request["probeCorrelationId"]}
    for key, value in values.items():
        script = script.replace("@" + key + "@", str(value) if key == "OWNER_PID" else _ps(str(value)))
    if re.search(r"@[A-Z][A-Z_]+@", script):
        raise WindowsFixtureNetworkProbeError("Probe observer template is incomplete.")
    if len(base64.b64encode(script.encode("utf-16le"))) >= 30000:
        raise WindowsFixtureNetworkProbeError("Fixed probe observer exceeds QGA bound.")
    return script


def _observe_native(root: Path, request: Mapping[str, Any], binding: Mapping[str, Any]) -> dict[str, Any]:
    config, _target, guest = base._descriptor(root)
    if (guest[0] != "windows-cp117" or (guest[1], guest[2], guest[3], guest[4]) !=
            (binding["socketPath"], binding["qemuPid"], binding["startTicks"], binding["originalSid"])):
        raise WindowsFixtureNetworkProbeError("Observed CP117 guest generation changed.")
    encoded = base64.b64encode(_observation_script(request, binding).encode("utf-16le")).decode("ascii")
    raw = base._remote(config, server._REMOTE_LIVE,
                       (binding["socketPath"], str(binding["qemuPid"]), str(binding["startTicks"]), encoded),
                       None, 30)
    try:
        value = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError):
        value = None
    result = value.get("result") if isinstance(value, dict) and value.get("state") == "observed" else None
    if (not isinstance(result, dict) or set(result) != {"schemaVersion", "correlationId", "observed",
                                                     "publicResponse", "event"}
            or result["schemaVersion"] != 1 or result["correlationId"] != request["probeCorrelationId"]):
        raise WindowsFixtureNetworkProbeError("Original-owner QGA observation is unknown.")
    manifest = server._fixture_manifest(root, request)
    manifest_bytes = len(json.dumps(manifest, separators=(",", ":")).encode())
    return _validate_evidence(binding, result["observed"], result["publicResponse"], result["event"],
                              manifest_bytes=manifest_bytes)


class WindowsFixtureNetworkProbeError(ValueError):
    pass


_GROUP = ".rag_index/windows-fixture-network-probe"
_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
_UTC = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z\Z")


def _canonical(value: Any) -> bool:
    return isinstance(value, str) and bool(_UUID.fullmatch(value)) and str(uuid.UUID(value)) == value


def _request(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = {"host", "leaseId", "stageCorrelationId", "serverCorrelationId", "probeCorrelationId",
              "sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId",
              "controllerId", "ownerPid", "ownerStartedAtUtc"}
    if not isinstance(value, Mapping) or set(value) != fields or value.get("host") != "archlinux":
        raise WindowsFixtureNetworkProbeError("Network probe requires exact CP117 fields.")
    if not all(_canonical(value[name]) for name in ("leaseId", "stageCorrelationId", "serverCorrelationId",
                                                    "probeCorrelationId", "controllerId")):
        raise WindowsFixtureNetworkProbeError("Network probe UUID is invalid.")
    if len({value[name] for name in ("leaseId", "stageCorrelationId", "serverCorrelationId",
                                       "probeCorrelationId")}) != 4:
        raise WindowsFixtureNetworkProbeError("Network probe correlations must be distinct.")
    for name, pattern in (("sourceSha", _SHA), ("fixtureReceiptArtifactId", _ARTIFACT),
                          ("baseMsiArtifactId", _ARTIFACT), ("targetMsiArtifactId", _ARTIFACT),
                          ("ownerStartedAtUtc", _UTC)):
        if not isinstance(value[name], str) or not pattern.fullmatch(value[name]):
            raise WindowsFixtureNetworkProbeError("Invalid network probe " + name + ".")
    if type(value["ownerPid"]) is not int or value["ownerPid"] <= 0:
        raise WindowsFixtureNetworkProbeError("Network probe owner PID is invalid.")
    return dict(value)


def _intent_path(root: Path, correlation_id: str) -> Path:
    return root / _GROUP / (correlation_id + ".json")


def _receipt_path(root: Path, correlation_id: str) -> Path:
    return root / _GROUP / (correlation_id + ".receipt")


def _journal_directory(root: Path) -> Path | None:
    directory = root / _GROUP
    try:
        info = directory.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink()
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsFixtureNetworkProbeError("Probe journal is unsafe.")
    return directory


def _terminal_receipt(root: Path, correlation_id: str) -> dict[str, Any] | None:
    if _journal_directory(root) is None:
        return None
    try:
        fd = os.open(_receipt_path(root, correlation_id), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384):
            raise WindowsFixtureNetworkProbeError("Terminal probe receipt is unsafe.")
        try:
            value = json.load(stream)
        except (TypeError, ValueError) as error:
            raise WindowsFixtureNetworkProbeError("Terminal probe receipt is invalid.") from error
    if (not isinstance(value, dict) or value.get("probeCorrelationId") != correlation_id
            or value.get("ownerTransportVerified") is not True):
        raise WindowsFixtureNetworkProbeError("Terminal probe receipt is invalid.")
    return value


def _write_terminal_receipt(root: Path, receipt: Mapping[str, Any]) -> None:
    correlation_id = receipt["probeCorrelationId"]
    prior = _terminal_receipt(root, correlation_id)
    if prior is not None:
        if prior != dict(receipt):
            raise WindowsFixtureNetworkProbeError("Terminal probe receipt changed.")
        return
    body = json.dumps(dict(receipt), sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if len(body) > 16384:
        raise WindowsFixtureNetworkProbeError("Terminal probe receipt is too large.")
    path = _receipt_path(root, correlation_id)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if fd >= 0:
            os.close(fd)
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _read_intent(root: Path, correlation_id: str) -> dict[str, Any] | None:
    if not _canonical(correlation_id):
        raise WindowsFixtureNetworkProbeError("Probe correlation is invalid.")
    if _journal_directory(root) is None:
        return None
    try:
        fd = os.open(_intent_path(root, correlation_id), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384):
            raise WindowsFixtureNetworkProbeError("Probe intent is unsafe.")
        try:
            value = json.load(stream)
        except (TypeError, ValueError) as error:
            raise WindowsFixtureNetworkProbeError("Probe intent is invalid.") from error
    if (not isinstance(value, dict) or set(value) != {"request", "binding", "state"}
            or not isinstance(value["request"], dict)
            or value["request"].get("probeCorrelationId") != correlation_id):
        raise WindowsFixtureNetworkProbeError("Probe intent is invalid.")
    return value


def _exact_binding(root: Path, request: Mapping[str, Any], live: Mapping[str, Any],
                   descriptor: Mapping[str, Any], pair: Mapping[str, Any],
                   guest: tuple[str, int, int, str]) -> dict[str, Any]:
    if any(live.get(key) != request[key] for key in
           ("leaseId", "sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId",
            "targetMsiArtifactId", "stageCorrelationId", "serverCorrelationId")):
        raise WindowsFixtureNetworkProbeError("Live server is bound to another campaign.")
    if any(live.get(key) != observed for key, observed in
           (("socketPath", guest[0]), ("qemuPid", guest[1]), ("startTicks", guest[2]),
            ("targetMsiSha256", pair["targetMsiSha256"]), ("targetMsiSize", pair["targetMsiSize"]),
            ("targetVersion", pair["targetVersion"]),
            ("peerCertificateSha256", descriptor.get("peerCertificateSha256")))):
        raise WindowsFixtureNetworkProbeError("Live server or guest generation changed.")
    if (live.get("serverReady") is not True or not isinstance(live.get("serverPort"), int)
            or type(live["serverPort"]) is not int or not 1 <= live["serverPort"] <= 65535
            or not isinstance(live.get("liveReceiptSha256"), str)
            or not _HASH.fullmatch(live["liveReceiptSha256"])):
        raise WindowsFixtureNetworkProbeError("Live server receipt is incomplete.")
    staged = stage.status(root, {"correlationId": request["stageCorrelationId"]})
    if staged.get("state") != "staged-not-server-ready":
        raise WindowsFixtureNetworkProbeError("Exact fixture stage changed.")
    return {"leaseId": request["leaseId"], "sourceSha": request["sourceSha"],
            "fixtureReceiptArtifactId": request["fixtureReceiptArtifactId"],
            "baseMsiArtifactId": request["baseMsiArtifactId"],
            "targetMsiArtifactId": request["targetMsiArtifactId"],
            "stageCorrelationId": request["stageCorrelationId"],
            "serverCorrelationId": request["serverCorrelationId"],
            "probeCorrelationId": request["probeCorrelationId"],
            "controllerId": request["controllerId"], "ownerPid": request["ownerPid"],
            "ownerStartedAtUtc": request["ownerStartedAtUtc"],
            "originalSid": guest[3], "socketPath": guest[0], "qemuPid": guest[1],
            "startTicks": guest[2], "serverInstanceId": live["serverInstanceId"],
            "serverPort": live["serverPort"], "liveReceiptSha256": live["liveReceiptSha256"],
            "manifestSha256": live["manifestSha256"], "manifestBuildNumber": live["manifestBuildNumber"],
            "peerCertificateSha256": live["peerCertificateSha256"],
            "trustStoreSha256": descriptor["trustStoreSha256"],
            "credentialProvisionId": descriptor["provisionId"],
            "targetVersion": pair["targetVersion"], "targetMsiSha256": pair["targetMsiSha256"],
            "targetMsiSize": pair["targetMsiSize"], "baseCliSha256": pair["baseCliSha256"]}


def _validate_evidence(binding: Mapping[str, Any], observed: Mapping[str, Any],
                       public_response: Mapping[str, Any], event: Mapping[str, Any],
                       *, manifest_bytes: int) -> dict[str, Any]:
    """Correlate native owner, public client TLS data, and server-only event."""
    owner_fields = {"originalSid", "sessionId", "limited", "ownerPid", "ownerStartedAtUtc",
                    "controllerId", "cliSha256", "proxyHost", "proxyPort", "trustStoreSha256",
                    "taskState", "taskExitCode", "ownerJvmNetworkVerified", "ownerJvmPid",
                    "ownerJvmStartedAtUtc", "ownerJvmProxyPort", "ownerJvmTrustStoreSha256"}
    if (not isinstance(observed, Mapping) or set(observed) != owner_fields
            or observed["originalSid"] != binding["originalSid"]
            or observed["sessionId"] != 1 or observed["limited"] is not True
            or observed["ownerPid"] != binding["ownerPid"]
            or observed["ownerStartedAtUtc"] != binding["ownerStartedAtUtc"]
            or observed["controllerId"] != binding["controllerId"]
            or observed["cliSha256"] != binding["baseCliSha256"]
            or observed["proxyHost"] != "127.0.0.1"
            or type(observed["proxyPort"]) is not int or observed["proxyPort"] != binding["serverPort"]
            or observed["trustStoreSha256"] != binding["trustStoreSha256"]
            or observed["taskState"] != "Ready" or type(observed["taskExitCode"]) is not int
            or observed["taskExitCode"] != 0
            or observed["ownerJvmNetworkVerified"] is not True
            or type(observed["ownerJvmPid"]) is not int
            or observed["ownerJvmPid"] != binding["ownerPid"]
            or observed["ownerJvmStartedAtUtc"] != binding["ownerStartedAtUtc"]
            or type(observed["ownerJvmProxyPort"]) is not int
            or observed["ownerJvmProxyPort"] != binding["serverPort"]
            or observed["ownerJvmTrustStoreSha256"] != binding["trustStoreSha256"]):
        raise WindowsFixtureNetworkProbeError("Original-owner probe task is not terminal and bound.")
    if (not isinstance(public_response, Mapping) or public_response.get("code") != "OK"
            or public_response.get("final") is not True
            or public_response.get("controllerId") != binding["controllerId"]
            or not isinstance(public_response.get("data"), Mapping)):
        raise WindowsFixtureNetworkProbeError("Public probe response is unavailable.")
    data = dict(public_response["data"])
    if (set(data) != {"correlationId", "manifestSha256", "peerCertificateSha256",
                      "manifestBuildNumber", "availableVersion", "assetSha256", "assetSizeBytes"}
            or data["correlationId"] != binding["probeCorrelationId"]
            or data["manifestSha256"] != binding["manifestSha256"]
            or data["peerCertificateSha256"] != binding["peerCertificateSha256"]
            or type(data["manifestBuildNumber"]) is not int
            or data["manifestBuildNumber"] != binding["manifestBuildNumber"]
            or data["availableVersion"] != binding["targetVersion"]
            or data["assetSha256"] != binding["targetMsiSha256"]
            or type(data["assetSizeBytes"]) is not int
            or data["assetSizeBytes"] != binding["targetMsiSize"]):
        raise WindowsFixtureNetworkProbeError("Public HTTPS probe disagrees with exact target.")
    live = {"serverInstanceId": binding["serverInstanceId"],
            "manifestSha256": binding["manifestSha256"],
            "peerCertificateSha256": binding["peerCertificateSha256"],
            "manifestBuildNumber": binding["manifestBuildNumber"],
            "targetVersion": binding["targetVersion"],
            "targetMsiSha256": binding["targetMsiSha256"],
            "targetMsiSize": binding["targetMsiSize"]}
    try:
        server._validate_probe_event(event, data, live,
                                     probe_correlation_id=binding["probeCorrelationId"],
                                     manifest_bytes=manifest_bytes)
    except ValueError as error:
        raise WindowsFixtureNetworkProbeError("Private server event does not prove this public TLS read.") from error
    receipt = {key: binding[key] for key in
               ("leaseId", "sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId",
                "targetMsiArtifactId", "stageCorrelationId", "serverCorrelationId",
                "probeCorrelationId", "controllerId", "ownerPid", "ownerStartedAtUtc",
                "originalSid", "socketPath", "qemuPid", "startTicks", "serverInstanceId",
                "liveReceiptSha256", "manifestSha256", "manifestBuildNumber",
                "peerCertificateSha256", "trustStoreSha256", "credentialProvisionId",
                "targetVersion", "targetMsiSha256", "targetMsiSize")}
    receipt["ownerTransportVerified"] = True
    receipt["ownerJvmNetworkVerified"] = True
    receipt["ownerJvmPid"] = binding["ownerPid"]
    receipt["ownerJvmStartedAtUtc"] = binding["ownerStartedAtUtc"]
    receipt["ownerJvmProxyPort"] = binding["serverPort"]
    receipt["ownerJvmTrustStoreSha256"] = binding["trustStoreSha256"]
    receipt["probeReceiptSha256"] = hashlib.sha256(json.dumps(
        receipt, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return receipt


def _current_binding(root: Path, request: Mapping[str, Any]) -> dict[str, Any]:
    config, target, guest_descriptor = base._descriptor(root)
    env, socket, pid, ticks, sid = guest_descriptor
    if env != "windows-cp117":
        raise WindowsFixtureNetworkProbeError("Owned CP117 generation changed.")
    pair = public._admit_pair(root, request["sourceSha"], request["fixtureReceiptArtifactId"],
                              request["baseMsiArtifactId"], request["targetMsiArtifactId"])
    live = server.verified_live_receipt(root, request["leaseId"])
    descriptor = credentials.verified_descriptor(root, request["leaseId"], request["stageCorrelationId"])
    directory, lock = lease._locked(root)
    try:
        current = lease._active(directory)
        identity = base._campaign_identity({**request, "correlationId": request["leaseId"]}, guest_descriptor)
        if (current is None or current.get("identity") != identity or current.get("server") != "live"
                or current.get("credentials") != "ready" or
                not ((current.get("state") == "active" and current.get("role") is None) or
                     (current.get("state") == "role-active" and
                      ((current.get("role") == "network-probe" and
                        current.get("correlationId") == request["probeCorrelationId"]) or
                       current.get("role") in {"target", "public"})))
                or not lease._remote_confirm(base._campaign_remote(config, target), "status", current, None)):
            raise WindowsFixtureNetworkProbeError("CP117 network probe lease is unknown.")
    finally:
        os.close(lock)
    return _exact_binding(root, request, live, descriptor, pair, (socket, pid, ticks, sid))


def _reserve(root: Path, request: Mapping[str, Any], binding: Mapping[str, Any]) -> None:
    """Persist the single probe intent before the lease or guest can change."""
    directory = root / _GROUP
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    _journal_directory(root)
    fd = os.open(directory / ".environment.lock", os.O_RDWR | os.O_CREAT |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise WindowsFixtureNetworkProbeError("Probe journal lock is unsafe.")
        fcntl.flock(fd, fcntl.LOCK_EX)
        if any(entry.suffix == ".json" for entry in directory.iterdir()):
            raise WindowsFixtureNetworkProbeError("Probe history requires explicit reconciliation.")
        body = json.dumps({"request": request, "binding": binding, "state": "reserved"},
                          sort_keys=True, separators=(",", ":")).encode() + b"\n"
        if len(body) > 16384:
            raise WindowsFixtureNetworkProbeError("Probe intent is too large.")
        item = os.open(_intent_path(root, request["probeCorrelationId"]),
                       os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            offset = 0
            while offset < len(body):
                written = os.write(item, body[offset:])
                if written <= 0:
                    raise WindowsFixtureNetworkProbeError("Probe intent write was incomplete.")
                offset += written
            os.fsync(item)
        finally:
            os.close(item)
        parent_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        os.close(fd)


_REMOTE_START = base._QGA + lease.remote_role_guard() + r'''import fcntl
root,env,lease_id,corr,sock,pid,ticks,encoded,command_hash,source,receipt_id,base_id,target_id=sys.argv[1:]
def out(value):print(json.dumps(value,sort_keys=True,separators=(',',':')))
try:
 if env!='windows-cp117' or len(encoded)>=30000 or not live(sock,pid,ticks):raise ValueError()
 command=base64.b64decode(encoded,validate=True)
 if hashlib.sha256(command).hexdigest()!=command_hash:raise ValueError()
 require_campaign_role(root,env,lease_id,'network-probe',corr,source,receipt_id,base_id,target_id,sock,pid,ticks)
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-network-probe')
 if not os.path.exists(group):os.mkdir(group,0o700)
 info=os.lstat(group)
 if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 lock=os.open(os.path.join(group,'.environment.lock'),os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
 try:
  info=os.fstat(lock)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError()
  fcntl.flock(lock,fcntl.LOCK_EX)
  if any(name!='.environment.lock' for name in os.listdir(group)):raise ValueError()
  job=os.path.join(group,corr);os.mkdir(job,0o700)
 finally:os.close(lock)
 binding={'leaseId':lease_id,'probeCorrelationId':corr,'socketPath':sock,
  'qemuPid':int(pid),'startTicks':int(ticks),'sourceSha':source,
  'fixtureReceiptArtifactId':receipt_id,'baseMsiArtifactId':base_id,
  'targetMsiArtifactId':target_id,'commandSha256':command_hash}
 path=os.path.join(job,'binding.json')
 item=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(item,'w',encoding='utf-8') as file:
  json.dump(binding,file,sort_keys=True,separators=(',',':'));file.flush();os.fsync(file.fileno())
 child=call(sock,'guest-exec',{'path':'powershell.exe',
  'arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 item=os.open(os.path.join(job,'dispatch.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(item,'w',encoding='utf-8') as file:
  json.dump({'pid':child},file);file.flush();os.fsync(file.fileno())
 out({'state':'submitted','probeCorrelationId':corr})
except Exception:out({'state':'unknown','probeCorrelationId':corr})
'''


def _submit_candidate(root: Path, request: Mapping[str, Any], binding: Mapping[str, Any],
                      trust_store_path: str) -> dict[str, Any]:
    """Review candidate; public start remains locked until cleanup is complete."""
    config, target, guest = base._descriptor(root)
    if guest[0] != "windows-cp117":
        raise WindowsFixtureNetworkProbeError("Owned CP117 guest changed.")
    command = _bootstrap_script(request, binding, trust_store_path)
    encoded = base64.b64encode(command.encode("utf-16le")).decode("ascii")
    command_hash = hashlib.sha256(command.encode("utf-16le")).hexdigest()
    _reserve(root, request, binding)
    claimed = lease.claim_role(root, request["leaseId"], "network-probe",
                               request["probeCorrelationId"], base._campaign_remote(config, target))
    if claimed.get("state") != "role-active":
        return _unknown(request["probeCorrelationId"], cleanup=True)
    raw = base._remote(config, _REMOTE_START,
                       (str(target.fixture_transfer_root), "windows-cp117", request["leaseId"],
                        request["probeCorrelationId"], binding["socketPath"],
                        str(binding["qemuPid"]), str(binding["startTicks"]), encoded,
                        command_hash, request["sourceSha"], request["fixtureReceiptArtifactId"],
                        request["baseMsiArtifactId"], request["targetMsiArtifactId"]), None, 30)
    try:
        result = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError):
        result = None
    if (not isinstance(result, dict) or set(result) != {"state", "probeCorrelationId"}
            or result["state"] != "submitted"
            or result["probeCorrelationId"] != request["probeCorrelationId"]):
        return _unknown(request["probeCorrelationId"], cleanup=True)
    return {"state": "submitted", "probeCorrelationId": request["probeCorrelationId"],
            "cleanupRequired": True, "replayAllowed": False, "ownerTransportVerified": False}


def _unknown(correlation_id: str, *, cleanup: bool) -> dict[str, Any]:
    return {"state": "unknown", "probeCorrelationId": correlation_id,
            "cleanupRequired": cleanup, "replayAllowed": False, "ownerTransportVerified": False}


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Admission-only until a protected original-user dispatcher is reviewed.

    A probe is an action with an irreversible server event and must not be run
    from a general QGA shell. This route therefore refuses to claim the lease or
    create an intent until its exact limited-user task dispatcher is available.
    """
    request = _request(value)
    root = Path(root).resolve(strict=True)
    existing = _read_intent(root, request["probeCorrelationId"])
    if existing is not None:
        if existing["request"] != request:
            raise WindowsFixtureNetworkProbeError("Probe correlation belongs to another request.")
        return _unknown(request["probeCorrelationId"], cleanup=True)
    _current_binding(root, request)
    raise WindowsFixtureNetworkProbeError("ORIGINAL_OWNER_PROBE_DISPATCH_UNAVAILABLE")


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"probeCorrelationId"} or not _canonical(value["probeCorrelationId"]):
        raise WindowsFixtureNetworkProbeError("Probe status requires exact correlation.")
    root = Path(root).resolve(strict=True)
    intent = _read_intent(root, value["probeCorrelationId"])
    if intent is None:
        return _unknown(value["probeCorrelationId"], cleanup=False)
    try:
        request = _request(intent["request"])
        binding = _current_binding(root, request)
        if intent["binding"] != binding:
            raise WindowsFixtureNetworkProbeError("Probe intent binding changed.")
        receipt = _observe_native(root, request, binding)
        config, target, _guest = base._descriptor(root)
        directory, lock = lease._locked(root)
        try:
            current = lease._active(directory)
            if (current is None or current["identity"]["leaseId"] != request["leaseId"]
                    or current["server"] != "live" or current["credentials"] != "ready"):
                raise WindowsFixtureNetworkProbeError("Probe campaign changed.")
        finally:
            os.close(lock)
        if current["state"] == "role-active" and current["role"] == "network-probe" and \
                current["correlationId"] == request["probeCorrelationId"]:
            finished = lease.finish_role(root, request["leaseId"], "network-probe",
                                         request["probeCorrelationId"], receipt["probeReceiptSha256"],
                                         "succeeded", base._campaign_remote(config, target))
            if finished.get("state") != "active":
                return _unknown(request["probeCorrelationId"], cleanup=True)
        elif current["state"] == "active" and current["role"] is None:
            prior = _terminal_receipt(root, request["probeCorrelationId"])
            if prior is None and (current["lastEvidenceSha256"] != receipt["probeReceiptSha256"]
                                  or current["lastOutcome"] != "succeeded"):
                return _unknown(request["probeCorrelationId"], cleanup=True)
            if prior is not None and prior != receipt:
                return _unknown(request["probeCorrelationId"], cleanup=True)
        elif current["state"] == "role-active" and current["role"] in {"target", "public"}:
            if _terminal_receipt(root, request["probeCorrelationId"]) != receipt:
                return _unknown(request["probeCorrelationId"], cleanup=True)
        else:
            return _unknown(request["probeCorrelationId"], cleanup=True)
        _write_terminal_receipt(root, receipt)
        return {"state": "correlated", "probeCorrelationId": request["probeCorrelationId"],
                "probeReceiptSha256": receipt["probeReceiptSha256"],
                "liveReceiptSha256": receipt["liveReceiptSha256"],
                "cleanupRequired": True, "replayAllowed": False, "ownerTransportVerified": True}
    except (OSError, ValueError, TypeError, KeyError):
        return _unknown(value["probeCorrelationId"], cleanup=True)


def collect(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    return status(root, value)


def verified_owner_network_receipt(root: Path | str, lease_id: str) -> dict[str, Any]:
    """Internal target/public join; no local/static receipt is native proof."""
    if not _canonical(lease_id):
        raise WindowsFixtureNetworkProbeError("Probe lease is invalid.")
    root = Path(root).resolve(strict=True)
    directory = root / _GROUP
    try:
        info = directory.lstat()
    except FileNotFoundError:
        raise WindowsFixtureNetworkProbeError("OWNER_NETWORK_RECEIPT_UNAVAILABLE") from None
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink()
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsFixtureNetworkProbeError("OWNER_NETWORK_RECEIPT_UNAVAILABLE")
    entries = [entry for entry in directory.iterdir() if entry.suffix == ".json"]
    if len(entries) != 1 or not _canonical(entries[0].stem):
        raise WindowsFixtureNetworkProbeError("OWNER_NETWORK_RECEIPT_UNAVAILABLE")
    intent = _read_intent(root, entries[0].stem)
    if intent is None or intent["request"].get("leaseId") != lease_id:
        raise WindowsFixtureNetworkProbeError("OWNER_NETWORK_RECEIPT_UNAVAILABLE")
    request = _request(intent["request"])
    binding = _current_binding(root, request)
    if intent["binding"] != binding:
        raise WindowsFixtureNetworkProbeError("OWNER_NETWORK_RECEIPT_UNAVAILABLE")
    receipt = _observe_native(root, request, binding)
    if _terminal_receipt(root, request["probeCorrelationId"]) != receipt:
        raise WindowsFixtureNetworkProbeError("OWNER_NETWORK_RECEIPT_UNAVAILABLE")
    directory, lock = lease._locked(root)
    try:
        current = lease._active(directory)
        if (current is None or current["identity"]["leaseId"] != lease_id
                or not ((current["state"] == "active" and current["role"] is None) or
                        (current["state"] == "role-active" and current["role"] in {"target", "public"}))
                or current["server"] != "live" or current["credentials"] != "ready"):
            raise WindowsFixtureNetworkProbeError("OWNER_NETWORK_RECEIPT_UNAVAILABLE")
    finally:
        os.close(lock)
    return receipt
