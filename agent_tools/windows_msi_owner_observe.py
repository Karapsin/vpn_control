"""One-shot, original-user CP117 owner observation without CLI owner startup."""
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

from . import ssh_transport, windows_credential_probe_ssh, windows_msi_base_prepare, windows_msi_public_scenario


class WindowsMsiOwnerObserveError(ValueError):
    pass


_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_TIME = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z\Z")
_TASK_UNKNOWN_CODES = {"UNKNOWN", "UNKNOWN_IDENTITY", "UNKNOWN_CLI_HASH", "UNKNOWN_PROCESS",
                       "UNKNOWN_ENDPOINT_FILE", "UNKNOWN_ENDPOINT_ACL", "UNKNOWN_ENDPOINT_BINDING",
                       "UNKNOWN_PUBLIC_STATUS", "UNKNOWN_PUBLIC_RESULT",
                       "UNKNOWN_QUIT_ADMISSION", "UNKNOWN_PUBLIC_QUIT",
                       "UNKNOWN_OWNER_EXIT", "UNKNOWN_POST_EXIT",
                       "UNKNOWN_TRANSPORT", "UNKNOWN_SNAPSHOT", "UNKNOWN_LOOPBACK_CONNECT",
                       "UNKNOWN_ENDPOINT_AUTH", "UNKNOWN_ENDPOINT_AUTH_WRITE",
                       "UNKNOWN_ENDPOINT_AUTH_READ", "UNKNOWN_ENDPOINT_AUTH_REPLY",
                       "UNKNOWN_SNAPSHOT_REQUEST",
                       "UNKNOWN_FRAMED_RESPONSE", "UNKNOWN_SNAPSHOT_PARSE"}
_GROUP = ".rag_index/windows-msi-owner-observe"
_GUEST = r"C:\Users\vpncp117\AppData\Local\VpnControl"
_CLI = r"C:\Users\vpncp117\AppData\Local\vpn-control\vpn-control-cli.exe"
_STATE = _GUEST + r"\cp166\state"
_PS = windows_msi_public_scenario._ps_literal


def _request(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = {"host", "correlationId", "sourceSha", "controllerId", "installedCliSha256",
              "parentPid", "parentStartedAtUtc", "childPid", "childStartedAtUtc"}
    if not isinstance(value, Mapping) or set(value) != fields or value.get("host") != "archlinux":
        raise WindowsMsiOwnerObserveError("Owner observation requires exact CP117 fields.")
    for field, pattern in (("correlationId", _UUID), ("sourceSha", _SHA), ("controllerId", _UUID),
                           ("installedCliSha256", _HASH), ("parentStartedAtUtc", _TIME),
                           ("childStartedAtUtc", _TIME)):
        if not isinstance(value[field], str) or not pattern.fullmatch(value[field]):
            raise WindowsMsiOwnerObserveError("Invalid owner observation " + field + ".")
    for field in ("correlationId", "controllerId"):
        if str(uuid.UUID(value[field])) != value[field]:
            raise WindowsMsiOwnerObserveError("Owner UUID is not canonical.")
    for field in ("parentPid", "childPid"):
        if type(value[field]) is not int or value[field] <= 0:
            raise WindowsMsiOwnerObserveError("Owner PID is invalid.")
    if value["parentPid"] == value["childPid"]:
        raise WindowsMsiOwnerObserveError("Owner generations overlap.")
    return dict(value)


def _quit_request(root: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    fields = {"host", "correlationId", "sourceSha", "controllerId", "installedCliSha256",
              "parentPid", "parentStartedAtUtc", "childPid", "childStartedAtUtc",
              "statusCorrelationId"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WindowsMsiOwnerObserveError("Owner quit requires exact fields.")
    base = _request({key: value[key] for key in fields - {"statusCorrelationId"}})
    prior = value["statusCorrelationId"]
    if not isinstance(prior, str) or not _UUID.fullmatch(prior) or prior == base["correlationId"]:
        raise WindowsMsiOwnerObserveError("Owner quit needs an exact earlier public status.")
    original = _read_intent(root, prior)
    if (original is None or original.get("request") != base | {"correlationId": prior}
            or _read_private_json(_closed_marker(root, prior)) != {
                "correlationId": prior, "commandSha256": original.get("commandSha256"),
                "state": "cleaned"}):
        raise WindowsMsiOwnerObserveError("Earlier public owner status is unavailable.")
    observed = status(root, {"correlationId": prior})
    if (observed.get("state") != "observed" or observed.get("controllerId") != base["controllerId"]
            or observed.get("runtimeRunning") is not False
            or observed.get("activeMode") is not None
            or observed.get("selectedLocationId") is not None
            or observed.get("activeLocationId") is not None):
        raise WindowsMsiOwnerObserveError("Public owner status does not admit a quit.")
    return {**base, "operation": "public-quit", "statusCorrelationId": prior}


def _intent_path(root: Path, correlation: str) -> Path:
    return root / _GROUP / (correlation + ".json")


def _closed_marker(root: Path, correlation: str) -> Path:
    return root / _GROUP / (correlation + ".closed.json")


def _pre_effect_marker(root: Path, correlation: str) -> Path:
    return root / _GROUP / (correlation + ".pre-effect.json")


def _read_private_json(path: Path) -> dict[str, Any]:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(file.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8192):
            raise WindowsMsiOwnerObserveError("Owner observation receipt is unsafe.")
        result = json.load(file)
    if not isinstance(result, dict):
        raise WindowsMsiOwnerObserveError("Owner observation receipt is invalid.")
    return result


def _read_intent(root: Path, correlation: str) -> dict[str, Any] | None:
    path = _intent_path(root, correlation)
    try: fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError: return None
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8192:
            raise WindowsMsiOwnerObserveError("Owner observation intent is unsafe.")
        value = json.load(file)
    if not isinstance(value, dict) or value.get("request", {}).get("correlationId") != correlation:
        raise WindowsMsiOwnerObserveError("Owner observation intent is invalid.")
    return value


def _reserve(root: Path, record: dict[str, Any]) -> None:
    directory = root / _GROUP
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise WindowsMsiOwnerObserveError("Owner observation journal is unsafe.")
    lock = os.open(directory / ".environment.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        entries = {item.name: item for item in directory.iterdir()}
        for item in entries.values():
            if item.name == ".environment.lock": continue
            if item.name.endswith((".cleanup.json", ".closed.json", ".pre-effect.json")):
                suffix = next(s for s in (".cleanup.json", ".closed.json", ".pre-effect.json")
                              if item.name.endswith(s))
                prior = item.name.removesuffix(suffix)
                if not _UUID.fullmatch(prior) or prior + ".json" not in entries:
                    raise WindowsMsiOwnerObserveError("CP117 owner observation journal has an orphan receipt.")
                continue
            if item.suffix != ".json" or not _UUID.fullmatch(item.stem):
                raise WindowsMsiOwnerObserveError("CP117 owner observation journal has an unknown entry.")
            previous = _read_intent(root, item.stem)
            closed = _read_private_json(_closed_marker(root, item.stem)) if _closed_marker(root, item.stem).exists() else None
            cleanup = _read_private_json(_cleanup_marker(root, item.stem)) if _cleanup_marker(root, item.stem).exists() else None
            rejected = _read_private_json(_pre_effect_marker(root, item.stem)) if _pre_effect_marker(root, item.stem).exists() else None
            clean = (closed == {"correlationId": item.stem,
                "commandSha256": previous.get("commandSha256") if previous else None,
                "state": "cleaned"} and cleanup == {"correlationId": item.stem,
                "commandSha256": previous.get("commandSha256") if previous else None} and rejected is None)
            pre_effect = (closed == {"correlationId": item.stem,
                "commandSha256": previous.get("commandSha256") if previous else None,
                "state": "pre-effect-rejected"} and cleanup is None and rejected == {
                "correlationId": item.stem,
                "commandSha256": previous.get("commandSha256") if previous else None,
                "oldRemoteSha256": _PRE_EFFECT_REJECTED_OLD_REMOTE_SHA256,
                "state": "pre-effect-rejected"} and previous is not None
                and _pre_effect_rejection_identity(previous))
            if previous is None or not (clean or pre_effect):
                raise WindowsMsiOwnerObserveError("CP117 has an active or unknown owner observation.")
        fd = os.open(_intent_path(root, record["request"]["correlationId"]),
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write((json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode())
            file.flush(); os.fsync(file.fileno())
        parent_fd = os.open(directory, os.O_RDONLY)
        try: os.fsync(parent_fd)
        finally: os.close(parent_fd)
    finally: os.close(lock)


def _record_closed(root: Path, correlation: str, command_hash: str,
                   state: str = "cleaned") -> None:
    marker = _closed_marker(root, correlation)
    if state not in {"cleaned", "pre-effect-rejected"}:
        raise WindowsMsiOwnerObserveError("Invalid owner observation closure state.")
    expected = {"correlationId": correlation, "commandSha256": command_hash, "state": state}
    try:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write((json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n").encode())
            file.flush(); os.fsync(file.fileno())
        directory_fd = os.open(marker.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
    except FileExistsError:
        if _read_private_json(marker) != expected:
            raise WindowsMsiOwnerObserveError("Owner observation closed receipt changed.")


def _task(correlation: str, request: Mapping[str, Any], sid: str) -> str:
    root = _GUEST + "\\mcp-owner-observe-" + correlation
    return r'''$ErrorActionPreference='Stop';$root=@ROOT@;$state=@STATE@;$cli=@CLI@
function P([string]$code,[object]$snapshot) {
 ([pscustomobject]@{version=1;correlationId=@CORR@;code=$code;originalSid=$identity.User.Value;sessionId=(Get-Process -Id $PID).SessionId;limited=$limited;snapshot=$snapshot}|ConvertTo-Json -Depth 8 -Compress)|Set-Content -LiteralPath (Join-Path $root 'result.json') -Encoding UTF8
}
$stage='IDENTITY'
try {
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 $limited=-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
 if($identity.User.Value -cne @SID@ -or (Get-Process -Id $PID).SessionId -ne 1 -or -not $limited){throw 'IDENTITY'}
 $stage='CLI_HASH'
 if((Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant() -cne @CLI_HASH@){throw 'CLI_HASH'}
 $stage='PROCESS'
 $parent=Get-CimInstance Win32_Process -Filter ('ProcessId='+@PARENT_PID@)
 $child=Get-CimInstance Win32_Process -Filter ('ProcessId='+@CHILD_PID@)
 if($null -eq $parent -or $null -eq $child -or $child.ParentProcessId -ne @PARENT_PID@ -or
  $parent.CreationDate.ToUniversalTime().ToString('o') -cne @PARENT_TIME@ -or
  $child.CreationDate.ToUniversalTime().ToString('o') -cne @CHILD_TIME@ -or
  $parent.SessionId -ne 1 -or $child.SessionId -ne 1 -or
  $parent.ExecutablePath -cne $cli -or $child.ExecutablePath -cne $cli){throw 'OWNER_GENERATION'}
 foreach($process in @($parent,$child)){
  $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
  if($owner.ReturnValue -ne 0 -or $owner.Sid -cne @SID@){throw 'OWNER_SID'}
 }
 $stage='ENDPOINT_FILE'
 $endpointPath=Join-Path $state 'activation.port'
 if(-not [IO.File]::Exists($endpointPath)){P 'ENDPOINT_ABSENT' $null;exit 0}
 $file=Get-Item -LiteralPath $endpointPath -Force
 if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -lt 1 -or $file.Length -gt 4096){throw 'ENDPOINT_FILE'}
 $stage='ENDPOINT_ACL'
 $acl=Get-Acl -LiteralPath $endpointPath
 if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne @SID@){throw 'ENDPOINT_OWNER'}
 $endpointAllowedSids=@(@SID@,'S-1-5-18','S-1-5-32-544')
 $ownerRead=$false
 foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
  if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and [int]$rule.FileSystemRights -ne 0){
   if($rule.IdentityReference.Value -notin $endpointAllowedSids){throw 'ENDPOINT_ACL'}
   if($rule.IdentityReference.Value -ceq @SID@){
    if(($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData) -ne 0){$ownerRead=$true}
   }
  }
 }
 if(-not $ownerRead){throw 'ENDPOINT_READ'}
 $bytes=[IO.File]::ReadAllBytes($endpointPath)
 if($bytes.Length -lt 1 -or $bytes.Length -gt 4096){throw 'ENDPOINT_SIZE'}
 $stage='ENDPOINT_BINDING'
 $endpoint=ConvertFrom-Json -InputObject ([Text.Encoding]::UTF8.GetString($bytes))
 if($endpoint.schemaVersion -ne 1 -or $endpoint.controllerId -cne @CONTROLLER@ -or $endpoint.port -lt 1 -or $endpoint.port -gt 65535){throw 'ENDPOINT_BINDING'}
 $token=$endpoint.token
 if($token -notmatch '^[A-Za-z0-9_-]{43}$'){throw 'ENDPOINT_TOKEN'}
 $stage='PUBLIC_STATUS'
 $raw=@(& $cli --state-dir $state --json --controller-id @CONTROLLER@ --timeout-seconds 15 status 2>$null)
 $exitCode=$LASTEXITCODE
 if($exitCode -ne 0 -or $raw.Count -ne 1 -or $raw[0] -isnot [string] -or
    $raw[0].Length -lt 2 -or $raw[0].Length -gt 8192){throw 'PUBLIC_STATUS'}
 $stage='PUBLIC_RESULT'
 $public=ConvertFrom-Json -InputObject $raw[0]
 if($public.schemaVersion -ne 1 -or $public.ok -ne $true -or $public.final -ne $true -or
    $public.code -cne 'OK' -or $public.controllerId -cne @CONTROLLER@ -or
    $null -eq $public.data -or $public.data.runtimeRunning -isnot [bool]){throw 'PUBLIC_RESULT'}
 $limitedSnapshot=[pscustomobject]@{controllerId=$public.controllerId;runtimeRunning=$public.data.runtimeRunning;configuredMode=$public.data.configuredMode;activeMode=$public.data.activeMode;selectedLocationId=$public.data.selectedLocationId;activeLocationId=$public.data.activeLocationId}
 P 'OBSERVED' $limitedSnapshot
}catch{P ('UNKNOWN_'+$stage) $null;exit 1}
'''.replace("@ROOT@", _PS(root)).replace("@STATE@", _PS(_STATE)).replace("@CLI@", _PS(_CLI)).replace("@CORR@", _PS(correlation)).replace("@SID@", _PS(sid)).replace("@CLI_HASH@", _PS(request["installedCliSha256"])).replace("@PARENT_PID@", str(request["parentPid"])).replace("@CHILD_PID@", str(request["childPid"])).replace("@PARENT_TIME@", _PS(request["parentStartedAtUtc"])).replace("@CHILD_TIME@", _PS(request["childStartedAtUtc"])).replace("@CONTROLLER@", _PS(request["controllerId"]))


def _quit_task(correlation: str, request: Mapping[str, Any], sid: str) -> str:
    task = _task(correlation, request, sid)
    marker = " P 'OBSERVED' $limitedSnapshot"
    if task.count(marker) != 1:
        raise WindowsMsiOwnerObserveError("Public status task changed before quit admission.")
    continuation = r''' $stage='QUIT_ADMISSION'
 if($limitedSnapshot.runtimeRunning -ne $false -or $null -ne $limitedSnapshot.activeMode -or
    $null -ne $limitedSnapshot.selectedLocationId -or $null -ne $limitedSnapshot.activeLocationId -or
    @(Get-CimInstance Win32_Process|Where-Object {$_.Name -match '^(sing-box|msiexec|consent)\.exe$'}).Count -ne 0){throw 'RUNTIME_OR_INSTALLER_ACTIVE'}
 $parentBefore=Get-CimInstance Win32_Process -Filter ('ProcessId='+@PARENT_PID@)
 $childBefore=Get-CimInstance Win32_Process -Filter ('ProcessId='+@CHILD_PID@)
 if($null -eq $parentBefore -or $null -eq $childBefore -or
    $parentBefore.CreationDate.ToUniversalTime().ToString('o') -cne @PARENT_TIME@ -or
    $childBefore.CreationDate.ToUniversalTime().ToString('o') -cne @CHILD_TIME@){throw 'OWNER_GENERATION_CHANGED'}
 $stage='PUBLIC_QUIT'
 $quitRaw=@(& $cli --state-dir $state --json --controller-id @CONTROLLER@ --timeout-seconds 30 quit 2>$null)
 $quitExit=$LASTEXITCODE
 if($quitExit -ne 0 -or $quitRaw.Count -ne 1 -or $quitRaw[0] -isnot [string] -or
    $quitRaw[0].Length -lt 2 -or $quitRaw[0].Length -gt 8192){throw 'PUBLIC_QUIT'}
 $quit=ConvertFrom-Json -InputObject $quitRaw[0]
 if($quit.schemaVersion -ne 1 -or $quit.ok -ne $true -or $quit.final -ne $true -or
    $quit.code -cne 'OK' -or $quit.controllerId -cne @CONTROLLER@){throw 'PUBLIC_QUIT_RESULT'}
 $stage='OWNER_EXIT'
 $parentExited=$false;$childExited=$false
 for($n=0;$n -lt 60;$n++){
  $parentNow=Get-CimInstance Win32_Process -Filter ('ProcessId='+@PARENT_PID@)
  $childNow=Get-CimInstance Win32_Process -Filter ('ProcessId='+@CHILD_PID@)
  if($null -ne $parentNow -and $parentNow.CreationDate.ToUniversalTime().ToString('o') -cne @PARENT_TIME@){throw 'PARENT_PID_REUSED'}
  if($null -ne $childNow -and $childNow.CreationDate.ToUniversalTime().ToString('o') -cne @CHILD_TIME@){throw 'CHILD_PID_REUSED'}
  $parentExited=$null -eq $parentNow;$childExited=$null -eq $childNow
  if($parentExited -and $childExited){break}
  Start-Sleep -Milliseconds 250
 }
 $stage='POST_EXIT'
 $endpointAbsent=-not [IO.File]::Exists($endpointPath)
 $runtimeAbsent=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match '^sing-box\.exe$'}).Count -eq 0
 $closing=[pscustomobject]@{controllerId=@CONTROLLER@;runtimeRunning=$false;
  configuredMode=$limitedSnapshot.configuredMode;activeMode=$null;
  selectedLocationId=$limitedSnapshot.selectedLocationId;activeLocationId=$null;
  parentExited=$parentExited;childExited=$childExited;endpointAbsent=$endpointAbsent;runtimeProcessAbsent=$runtimeAbsent}
 if($parentExited -and $childExited -and $endpointAbsent -and $runtimeAbsent){P 'QUIT_COMPLETED' $closing}
 else{P 'QUIT_PARTIAL' $closing}
'''.replace("@CONTROLLER@", _PS(request["controllerId"]))
    continuation = continuation.replace("@PARENT_PID@", str(request["parentPid"]))
    continuation = continuation.replace("@CHILD_PID@", str(request["childPid"]))
    continuation = continuation.replace("@PARENT_TIME@", _PS(request["parentStartedAtUtc"]))
    continuation = continuation.replace("@CHILD_TIME@", _PS(request["childStartedAtUtc"]))
    return task.replace(marker, continuation)


def _bootstrap(correlation: str, request: Mapping[str, Any], sid: str) -> str:
    root = _GUEST + "\\mcp-owner-observe-" + correlation
    name = "VpnControlMcpOwnerObserve-" + correlation
    body = _quit_task(correlation, request, sid) if request.get("operation") == "public-quit" else _task(correlation, request, sid)
    packed = base64.b64encode(gzip.compress(body.encode("utf-16le"), mtime=0)).decode()
    return r'''$ErrorActionPreference='Stop';$root=@ROOT@;$name=@NAME@
try{
 if([IO.Directory]::Exists($root) -or (Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction SilentlyContinue)){throw 'EXCLUSIVE'}
 [IO.Directory]::CreateDirectory($root)|Out-Null
 $compressed=[Convert]::FromBase64String(@PACKED@)
 $inputStream=[IO.MemoryStream]::new([byte[]]$compressed)
 $decompressor=[IO.Compression.GzipStream]::new($inputStream,[IO.Compression.CompressionMode]::Decompress)
 $outputStream=[IO.MemoryStream]::new();$decompressor.CopyTo($outputStream)
 $body=[Convert]::ToBase64String($outputStream.ToArray())
 $decompressor.Dispose();$inputStream.Dispose();$outputStream.Dispose()
 $action=New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$body)
 $principal=New-ScheduledTaskPrincipal -UserId 'VPNMSIX64\vpncp117' -LogonType Interactive -RunLevel Limited
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 Register-ScheduledTask -TaskPath '\' -TaskName $name -Action $action -Principal $principal -Settings $settings|Out-Null
 Start-ScheduledTask -TaskPath '\' -TaskName $name
 ([pscustomobject]@{version=1;correlationId=@CORR@;taskName=$name;triggered=$true}|ConvertTo-Json -Compress)
}catch{([pscustomobject]@{version=1;correlationId=@CORR@;triggered=$false}|ConvertTo-Json -Compress);exit 1}
'''.replace("@ROOT@", _PS(root)).replace("@NAME@", _PS(name)).replace("@PACKED@", _PS(packed)).replace("@CORR@", _PS(correlation))


def _cleanup_task_script(correlation: str) -> str:
    return r'''$ErrorActionPreference='Stop';$name='VpnControlMcpOwnerObserve-@CORR@';try{$task=Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction SilentlyContinue;if($task){if($task.State -ne 'Ready'){throw 'STATE'};Unregister-ScheduledTask -TaskPath '\' -TaskName $name -Confirm:$false};[Console]::Out.WriteLine('{"version":1,"code":"CLEANED"}')}catch{[Console]::Out.WriteLine('{"version":1,"code":"UNKNOWN"}');exit 1}'''.replace("@CORR@", correlation)


def _powershell_preflight_script(kind: str) -> str:
    request = {"host": "archlinux", "correlationId": "11111111-1111-4111-8111-111111111111",
               "sourceSha": "a" * 40, "controllerId": "22222222-2222-4222-8222-222222222222",
               "installedCliSha256": "b" * 64, "parentPid": 3640,
               "parentStartedAtUtc": "2026-09-25T10:18:47.4249100Z", "childPid": 5520,
               "childStartedAtUtc": "2026-09-25T10:18:47.7734480Z"}
    sid = "S-1-5-21-1-2-3-1002"
    packed = lambda source: base64.b64encode(gzip.compress(source.encode("utf-16le"), mtime=0)).decode()
    sources = {"task": _task(request["correlationId"], request, sid),
               "bootstrap": _bootstrap(request["correlationId"], request, sid),
               "quit-task": _quit_task(request["correlationId"], request, sid),
               "quit-bootstrap": _bootstrap(request["correlationId"],
                                            {**request, "operation": "public-quit"}, sid),
               "cleanup": _cleanup_task_script(request["correlationId"])}
    if kind not in sources: raise WindowsMsiOwnerObserveError("Unknown owner PS5 preflight component.")
    return r'''$ErrorActionPreference='Stop'
function Expand([string]$body){$inputStream=[IO.MemoryStream]::new([Convert]::FromBase64String($body));$decompressor=[IO.Compression.GzipStream]::new($inputStream,[IO.Compression.CompressionMode]::Decompress);$outputStream=[IO.MemoryStream]::new();$decompressor.CopyTo($outputStream);$source=[Text.Encoding]::Unicode.GetString($outputStream.ToArray());$decompressor.Dispose();$inputStream.Dispose();$outputStream.Dispose();return $source}
try{$tokens=$null;$errors=$null
 $source=Expand '@SOURCE@'
 [System.Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)|Out-Null
 if($errors.Count -ne 0){throw 'SYNTAX'}
 [Console]::Out.WriteLine('{"version":1,"code":"OK"}')
}catch{[Console]::Out.WriteLine('{"version":1,"code":"FAILED"}');exit 1}
'''.replace("@SOURCE@", packed(sources[kind]))


def powershell_preflight(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"host"} or value["host"] != "archlinux":
        raise WindowsMsiOwnerObserveError("Owner PS5 preflight requires exact host.")
    root = Path(root).resolve(strict=True)
    config, _, (env, socket, pid, ticks, _) = windows_msi_base_prepare._descriptor(root)
    if env != "windows-cp117": raise WindowsMsiOwnerObserveError("Owned CP117 guest identity changed.")
    states = []
    for kind in ("task", "bootstrap", "cleanup"):
        encoded = base64.b64encode(_powershell_preflight_script(kind).encode("utf-16le")).decode()
        if len(encoded) >= 30000: raise WindowsMsiOwnerObserveError("Owner PS5 preflight exceeds command admission.")
        raw = windows_credential_probe_ssh._run_ssh(config, "archlinux",
            windows_credential_probe_ssh._remote_command(windows_msi_public_scenario._REMOTE_PREFLIGHT,
                socket, str(pid), str(ticks), encoded), None, 30)
        try: result = json.loads(raw) if raw is not None else {}
        except (TypeError, ValueError): result = {}
        states.append(result.get("state") if isinstance(result, dict) else None)
        if states[-1] != "passed": break
    return {"state": "passed" if states == ["passed"] * 3 else
            "failed" if "failed" in states else "unknown", "productAction": False}


def quit_powershell_preflight(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"host"} or value["host"] != "archlinux":
        raise WindowsMsiOwnerObserveError("Owner quit PS5 preflight requires exact host.")
    root = Path(root).resolve(strict=True)
    config, _, (env, socket, pid, ticks, _) = windows_msi_base_prepare._descriptor(root)
    if env != "windows-cp117":
        raise WindowsMsiOwnerObserveError("Owned CP117 guest identity changed.")
    states = []
    for kind in ("quit-task", "quit-bootstrap", "cleanup"):
        encoded = base64.b64encode(_powershell_preflight_script(kind).encode("utf-16le")).decode()
        if len(encoded) >= 30000:
            raise WindowsMsiOwnerObserveError("Owner quit PS5 preflight exceeds command admission.")
        raw = windows_credential_probe_ssh._run_ssh(config, "archlinux",
            windows_credential_probe_ssh._remote_command(windows_msi_public_scenario._REMOTE_PREFLIGHT,
                socket, str(pid), str(ticks), encoded), None, 30)
        try: result = json.loads(raw) if raw is not None else {}
        except (TypeError, ValueError): result = {}
        states.append(result.get("state") if isinstance(result, dict) else None)
        if states[-1] != "passed": break
    return {"state": "passed" if states == ["passed"] * 3 else
            "failed" if "failed" in states else "unknown", "productAction": False}


_REMOTE_START_TEMPLATE = windows_msi_public_scenario._REMOTE_START.replace(
    "'windows-msi-public'", "'windows-msi-owner-observe'")
_REMOTE_GROUP_EXCLUSIVE = "if any(name!='.environment.lock' for name in os.listdir(group)): raise FileExistsError()"
_REMOTE_CLOSED_CHECK = r'''for name in os.listdir(group):
   if name=='.environment.lock':continue
   if len(name)!=36 or str(__import__('uuid').UUID(name))!=name:raise ValueError()
   prior=os.path.join(group,name)
   if not safe_dir(prior):raise ValueError()
   with open(os.path.join(prior,'binding.json'),encoding='utf-8') as file:old_binding=json.load(file)
   if set(old_binding)!={'socketPath','pid','startTicks','sourceSha','artifactIds','commandSha256'} or old_binding['artifactIds']!=[]:raise ValueError()
   with open(os.path.join(prior,'cleanup-intent.json'),encoding='utf-8') as file:old_intent=json.load(file)
   with open(os.path.join(prior,'cleanup-result.json'),encoding='utf-8') as file:old_result=json.load(file)
   task='VpnControlMcpOwnerObserve-'+name
   if old_intent!={'correlationId':name,'taskName':task} or old_result!={'version':1,'correlationId':name,'state':'cleaned','taskName':task}:raise ValueError()
  '''
_REMOTE_IMPORT = "import base64,fcntl,json,os,socket,stat,struct,sys,secrets\n"
_REMOTE_PUBLIC_KEYS = "'schema','leaseId','socketPath','pid','startTicks','encodedCommand','commandSha256','sourceSha','artifactIds'"
_REMOTE_OWNER_KEYS = "'schema','socketPath','pid','startTicks','encodedCommand','commandSha256','sourceSha','artifactIds'"
_REMOTE_PUBLIC_ROLE = "require_campaign_role(root,env,value['leaseId'],'public',corr,value['sourceSha'],*value['artifactIds'],sock,pid,ticks)"
if (not _REMOTE_START_TEMPLATE.count(_REMOTE_IMPORT) == 1
        or _REMOTE_GROUP_EXCLUSIVE not in _REMOTE_START_TEMPLATE
        or _REMOTE_PUBLIC_KEYS not in _REMOTE_START_TEMPLATE
        or _REMOTE_PUBLIC_ROLE not in _REMOTE_START_TEMPLATE
        or "len(value['artifactIds'])!=3" not in _REMOTE_START_TEMPLATE):
    raise WindowsMsiOwnerObserveError("Owner observation remote admission template changed.")
_REMOTE_START = _REMOTE_IMPORT + _REMOTE_START_TEMPLATE.split(_REMOTE_IMPORT, 1)[1]
_REMOTE_START = _REMOTE_START.replace(_REMOTE_GROUP_EXCLUSIVE, _REMOTE_CLOSED_CHECK.strip())
_REMOTE_START = _REMOTE_START.replace(_REMOTE_PUBLIC_KEYS, _REMOTE_OWNER_KEYS)
_REMOTE_START = _REMOTE_START.replace("len(value['artifactIds'])!=3", "len(value['artifactIds'])!=0")
_REMOTE_START = _REMOTE_START.replace(_REMOTE_PUBLIC_ROLE, "")

# One historical pre-guest rejection. The old owner observer submitted a payload
# without the installer-only lease and three artifacts that its inherited remote
# parser required. These pins allow only that exact unknown attempt to be closed
# as rejected after fresh native absence proof; they never turn it into a success.
_PRE_EFFECT_REJECTED_CORRELATION = "c9f7bd65-266b-4169-9662-7bb70ca8936d"
_PRE_EFFECT_REJECTED_SOURCE = "a876f46fa4582e6218d341ac7012fd31bc919758"
_PRE_EFFECT_REJECTED_COMMAND_SHA256 = "77eba28eaeed4afed1507fe9c4a36bd3a80cdf57847bf2ef29378a130941f13e"
_PRE_EFFECT_REJECTED_OLD_REMOTE_SHA256 = "4187b306932831391911e0768f24786d1f11a1bd3d8237a9a109f376010e4f20"
_PRE_EFFECT_REJECTED_QEMU = (589342, 520739)
_PRE_EFFECT_REJECTED_OWNER = (3640, "2026-09-25T10:18:47.4249100Z",
                              5520, "2026-09-25T10:18:47.7734480Z")


def _pre_effect_rejection_identity(intent: Mapping[str, Any]) -> bool:
    request = intent.get("request")
    if not isinstance(request, dict):
        return False
    if (request.get("correlationId") != _PRE_EFFECT_REJECTED_CORRELATION
            or request.get("sourceSha") != _PRE_EFFECT_REJECTED_SOURCE
            or intent.get("commandSha256") != _PRE_EFFECT_REJECTED_COMMAND_SHA256
            or (intent.get("pid"), intent.get("startTicks")) != _PRE_EFFECT_REJECTED_QEMU
            or (request.get("parentPid"), request.get("parentStartedAtUtc"),
                request.get("childPid"), request.get("childStartedAtUtc")) != _PRE_EFFECT_REJECTED_OWNER):
        return False
    return True


def _pre_effect_rejection_binding(intent: Mapping[str, Any]) -> bool:
    if not _pre_effect_rejection_identity(intent):
        return False
    old_remote = _REMOTE_START_TEMPLATE.replace(_REMOTE_GROUP_EXCLUSIVE, _REMOTE_CLOSED_CHECK.strip())
    if hashlib.sha256(old_remote.encode()).hexdigest() != _PRE_EFFECT_REJECTED_OLD_REMOTE_SHA256:
        return False
    # The exact old parser rejects before stage creation and before guest-exec.
    return (_REMOTE_PUBLIC_KEYS in old_remote and _REMOTE_PUBLIC_ROLE in old_remote
            and "len(value['artifactIds'])!=3" in old_remote)


def _record_pre_effect_rejection(root: Path, corr: str, intent: Mapping[str, Any]) -> None:
    if not _pre_effect_rejection_binding(intent):
        raise WindowsMsiOwnerObserveError("Pre-effect rejection identity changed.")
    marker = _pre_effect_marker(root, corr)
    expected = {"correlationId": corr, "commandSha256": intent["commandSha256"],
                "oldRemoteSha256": _PRE_EFFECT_REJECTED_OLD_REMOTE_SHA256,
                "state": "pre-effect-rejected"}
    try:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write((json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n").encode())
            file.flush(); os.fsync(file.fileno())
        directory_fd = os.open(marker.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
    except FileExistsError:
        if _read_private_json(marker) != expected:
            raise WindowsMsiOwnerObserveError("Pre-effect rejection marker changed.")
    _record_closed(root, corr, intent["commandSha256"], "pre-effect-rejected")


_REMOTE_PRE_EFFECT = windows_msi_base_prepare._QGA + r'''import time
root,env,corr,sock,pid,ticks=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if env!='windows-cp117' or not live(sock,pid,ticks):raise ValueError()
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-msi-owner-observe')
 for path in (root,parent,group):
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 if os.path.lexists(os.path.join(group,corr)):
  out({'state':'present','correlationId':corr});raise SystemExit(0)
 script="$ErrorActionPreference='Stop';$corr='"+corr+"';$task='VpnControlMcpOwnerObserve-'+$corr;$leaf='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-owner-observe-'+$corr;try{$registered=Get-ScheduledTask -TaskPath '\\' -TaskName $task -ErrorAction SilentlyContinue;if($registered -or [IO.Directory]::Exists($leaf) -or [IO.File]::Exists($leaf)){[Console]::Out.WriteLine('{\"version\":1,\"state\":\"present\"}')}else{[Console]::Out.WriteLine('{\"version\":1,\"state\":\"absent\"}')}}catch{[Console]::Out.WriteLine('{\"version\":1,\"state\":\"unknown\"}');exit 1}"
 encoded=base64.b64encode(script.encode('utf-16le')).decode('ascii')
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(40):
  observed=call(sock,'guest-exec-status',{'pid':child})
  if observed.get('exited') is True:break
  time.sleep(.25)
 else:raise ValueError()
 if observed.get('exitcode')!=0 or observed.get('out-truncated') is not False or observed.get('err-truncated') is not False:raise ValueError()
 raw=base64.b64decode(observed.get('out-data',''),validate=True)
 if not 0<len(raw)<=512:raise ValueError()
 lines=[x for x in decode(raw).splitlines() if x.startswith('{') and x.endswith('}')]
 if len(lines)!=1 or json.loads(lines[0])!={'version':1,'state':'absent'}:raise ValueError()
 out({'state':'absent','correlationId':corr})
except Exception:out({'state':'unknown','correlationId':corr})
'''


def _pre_effect_absence(root: Path, corr: str, intent: Mapping[str, Any],
                        config: Any, target: Any, descriptor: tuple[Any, ...]) -> bool:
    env, socket, pid, ticks, sid = descriptor
    if any(intent.get(key) != observed for key, observed in (("environment", env),
            ("socketPath", socket), ("pid", pid), ("startTicks", ticks), ("expectedSid", sid))):
        return False
    raw = windows_msi_base_prepare._remote(config, _REMOTE_PRE_EFFECT,
        (str(target.fixture_transfer_root), env, corr, socket, str(pid), str(ticks)), None, 30)
    try:
        observed = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError):
        return False
    return observed == {"state": "absent", "correlationId": corr}


def _close_prior(root: Path, config: Any, target: Any, descriptor: tuple[Any, ...]) -> None:
    directory = root / _GROUP
    if not directory.exists(): return
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsMsiOwnerObserveError("Owner observation journal is unsafe.")
    env, socket, pid, ticks, sid = descriptor
    for item in directory.iterdir():
        if not item.name.endswith(".json") or item.name.endswith((".cleanup.json", ".closed.json", ".pre-effect.json")):
            continue
        correlation = item.stem
        if not _UUID.fullmatch(correlation):
            raise WindowsMsiOwnerObserveError("Prior owner observation identity is invalid.")
        intent = _read_intent(root, correlation)
        if intent is None or any(intent.get(key) != observed for key, observed in (
                ("environment", env), ("socketPath", socket), ("pid", pid),
                ("startTicks", ticks), ("expectedSid", sid))):
            raise WindowsMsiOwnerObserveError("Prior owner observation guest identity changed.")
        rejected_path = _pre_effect_marker(root, correlation)
        if rejected_path.exists():
            expected = {"correlationId": correlation, "commandSha256": intent["commandSha256"],
                        "oldRemoteSha256": _PRE_EFFECT_REJECTED_OLD_REMOTE_SHA256,
                        "state": "pre-effect-rejected"}
            if (_read_private_json(rejected_path) != expected
                    or _read_private_json(_closed_marker(root, correlation)) != {
                        "correlationId": correlation, "commandSha256": intent["commandSha256"],
                        "state": "pre-effect-rejected"}
                    or not _pre_effect_rejection_identity(intent)
                    or not _pre_effect_absence(root, correlation, intent, config, target, descriptor)):
                raise WindowsMsiOwnerObserveError("Prior pre-effect rejection is no longer proven.")
            continue
        cleanup = _read_private_json(_cleanup_marker(root, correlation))
        if cleanup != {"correlationId": correlation, "commandSha256": intent.get("commandSha256")}:
            raise WindowsMsiOwnerObserveError("Prior owner observation cleanup intent changed.")
        raw = windows_msi_base_prepare._remote(config, _REMOTE_CLEANUP_STATUS,
            (str(target.fixture_transfer_root), env, correlation, intent["request"]["sourceSha"],
             intent["commandSha256"]), None, 30)
        try: result = json.loads(raw) if raw is not None else {}
        except (TypeError, ValueError): result = {}
        if result != {"state": "cleaned", "correlationId": correlation}:
            raise WindowsMsiOwnerObserveError("Prior owner observation has no exact remote cleanup receipt.")
        _record_closed(root, correlation, intent["commandSha256"])


def _start_validated(root: Path, request: dict[str, Any]) -> dict[str, Any]:
    corr = request["correlationId"]
    existing = _read_intent(root, corr)
    if existing is not None:
        if existing.get("request") != request: raise WindowsMsiOwnerObserveError("Correlation binds another owner observation.")
        return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    config, target, (env, socket, pid, ticks, sid) = windows_msi_base_prepare._descriptor(root)
    _close_prior(root, config, target, (env, socket, pid, ticks, sid))
    command = _bootstrap(corr, request, sid)
    encoded = base64.b64encode(command.encode("utf-16le")).decode()
    if len(encoded) >= 30000: raise WindowsMsiOwnerObserveError("Fixed owner observation exceeds command admission.")
    digest = hashlib.sha256(command.encode("utf-16le")).hexdigest()
    record = {"request": request, "environment": env, "socketPath": socket,
              "pid": pid, "startTicks": ticks, "expectedSid": sid, "commandSha256": digest}
    _reserve(root, record)
    payload = {"schema": 1, "socketPath": socket, "pid": pid, "startTicks": ticks,
               "encodedCommand": encoded, "commandSha256": digest, "sourceSha": request["sourceSha"], "artifactIds": []}
    raw = windows_credential_probe_ssh._run_ssh(config, "archlinux",
        windows_credential_probe_ssh._remote_command(_REMOTE_START, str(target.fixture_transfer_root), env, corr),
        windows_credential_probe_ssh._remote_payload(payload), 30)
    try: result = json.loads(raw) if raw is not None else {}
    except (TypeError, ValueError): result = {}
    return {"state": "submitted" if result.get("state") == "submitted" else "unknown",
            "correlationId": corr, "replayAllowed": False}


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    root = Path(root).resolve(strict=True)
    return _start_validated(root, _request(value))


def quit_start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    root = Path(root).resolve(strict=True)
    return _start_validated(root, _quit_request(root, value))


_REMOTE_STATUS = windows_msi_base_prepare._QGA + r'''root,env,corr,sock,pid,ticks,source,command_hash=sys.argv[1:]
os.umask(0o077)
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
reason='STAGE_BINDING'
try:
 stage=os.path.join(root,env,'windows-msi-owner-observe',corr);info=os.lstat(stage)
 if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 with open(os.path.join(stage,'binding.json'),encoding='utf-8') as file:binding=json.load(file)
 if binding!={'socketPath':sock,'pid':int(pid),'startTicks':int(ticks),'sourceSha':source,'artifactIds':[],'commandSha256':command_hash}:raise ValueError()
 reason='GUEST_GENERATION'
 if not live(sock,pid,ticks):raise ValueError()
 reason='DISPATCH_BINDING'
 with open(os.path.join(stage,'dispatch.json'),encoding='utf-8') as file:dispatch=json.load(file)
 if set(dispatch)!={'pid'} or type(dispatch['pid']) is not int or dispatch['pid']<=0:raise ValueError()
 receipt_path=os.path.join(stage,'bootstrap-result.json')
 if os.path.exists(receipt_path):
  reason='BOOTSTRAP_RECEIPT'
  info=os.lstat(receipt_path)
  if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>512:raise ValueError()
  with open(receipt_path,encoding='utf-8') as file:receipt=json.load(file)
  if set(receipt)!={'version','correlationId','pid','state','code'} or type(receipt['version']) is not int or receipt['version']!=1 or receipt['correlationId']!=corr or type(receipt['pid']) is not int or receipt['pid']!=dispatch['pid'] or (receipt['state'],receipt['code']) not in (('accepted','ACCEPTED'),('rejected','BOOTSTRAP_EXIT'),('rejected','BOOTSTRAP_OUTPUT')):raise ValueError()
 else:
  reason='BOOTSTRAP_STATUS'
  process=call(sock,'guest-exec-status',{'pid':dispatch['pid']})
  if process.get('exited') is not True:out({'state':'running','correlationId':corr});raise SystemExit(0)
  accepted=False;failure='BOOTSTRAP_EXIT'
  try:
   reason='BOOTSTRAP_EXIT'
   if process.get('exitcode')!=0:raise ValueError()
   failure='BOOTSTRAP_OUTPUT'
   reason='BOOTSTRAP_OUTPUT'
   output=base64.b64decode(process.get('out-data',''),validate=True)
   if len(output)>8192:raise ValueError()
   lines=[x for x in decode(output).splitlines() if x.startswith('{') and x.endswith('}')]
   accepted=(len(lines)==1 and json.loads(lines[0])=={'version':1,'correlationId':corr,'taskName':'VpnControlMcpOwnerObserve-'+corr,'triggered':True})
  except Exception:pass
  receipt={'version':1,'correlationId':corr,'pid':dispatch['pid'],'state':'accepted' if accepted else 'rejected','code':'ACCEPTED' if accepted else failure}
  with open(receipt_path,'x',encoding='utf-8') as file:json.dump(receipt,file,separators=(',',':'));file.flush();os.fsync(file.fileno())
  stage_fd=os.open(stage,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(stage_fd);os.close(stage_fd)
 reason='BOOTSTRAP_RECEIPT'
 if receipt['state']!='accepted':reason=receipt['code'];raise ValueError()
 reason='TASK_PENDING'
 raw=read(sock,'C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-owner-observe-'+corr+'\\result.json')
 if raw is None:out({'state':'running','correlationId':corr});raise SystemExit(0)
 reason='TASK_RESULT'
 out({'state':'observed','correlationId':corr,'result':json.loads(decode(raw))})
except Exception:
 if reason in ('BOOTSTRAP_STATUS','BOOTSTRAP_EXIT'):
  try:
   observed=read(sock,'C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-owner-observe-'+corr+'\\result.json')
   if observed is not None:
    result=json.loads(decode(observed))
    if isinstance(result,dict) and result.get('correlationId')==corr and result.get('code') in ('OBSERVED','QUIT_COMPLETED','QUIT_PARTIAL','ENDPOINT_ABSENT','UNKNOWN','UNKNOWN_IDENTITY','UNKNOWN_CLI_HASH','UNKNOWN_PROCESS','UNKNOWN_ENDPOINT_FILE','UNKNOWN_ENDPOINT_ACL','UNKNOWN_ENDPOINT_BINDING','UNKNOWN_PUBLIC_STATUS','UNKNOWN_PUBLIC_RESULT','UNKNOWN_QUIT_ADMISSION','UNKNOWN_PUBLIC_QUIT','UNKNOWN_OWNER_EXIT','UNKNOWN_POST_EXIT','UNKNOWN_TRANSPORT','UNKNOWN_SNAPSHOT','UNKNOWN_LOOPBACK_CONNECT','UNKNOWN_ENDPOINT_AUTH','UNKNOWN_ENDPOINT_AUTH_WRITE','UNKNOWN_ENDPOINT_AUTH_READ','UNKNOWN_ENDPOINT_AUTH_REPLY','UNKNOWN_SNAPSHOT_REQUEST','UNKNOWN_FRAMED_RESPONSE','UNKNOWN_SNAPSHOT_PARSE'):
     reason=reason+'_TASK_'+result['code']
  except Exception:pass
 out({'state':'unknown','correlationId':corr,'diagnostic':reason})
'''


def _classify(raw: bytes | None, corr: str, intent: Mapping[str, Any]) -> dict[str, Any]:
    unknown = {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    try: value = json.loads(raw) if raw is not None else {}
    except (TypeError, ValueError): return unknown
    if not isinstance(value, dict) or value.get("correlationId") != corr: return unknown
    if value.get("state") == "unknown" and (value.get("diagnostic") in {
            "STAGE_BINDING", "GUEST_GENERATION", "DISPATCH_BINDING", "BOOTSTRAP_STATUS",
            "BOOTSTRAP_EXIT", "BOOTSTRAP_OUTPUT", "BOOTSTRAP_RECEIPT", "TASK_PENDING", "TASK_RESULT",
            "BOOTSTRAP_STATUS_TASK_OBSERVED", "BOOTSTRAP_STATUS_TASK_ENDPOINT_ABSENT"}
            or value.get("diagnostic") in {prefix + code for prefix in
                ("BOOTSTRAP_STATUS_TASK_", "BOOTSTRAP_EXIT_TASK_") for code in _TASK_UNKNOWN_CODES}):
        return {**unknown, "diagnostic": value["diagnostic"]}
    if value.get("state") == "running": return {"state": "running", "correlationId": corr, "replayAllowed": False}
    result = value.get("result")
    if value.get("state") != "observed" or not isinstance(result, dict): return unknown
    if (set(result) != {"version", "correlationId", "code", "originalSid", "sessionId", "limited", "snapshot"}
            or type(result["version"]) is not int or result["version"] != 1
            or result["correlationId"] != corr or type(result["code"]) is not str
            or result["originalSid"] != intent["expectedSid"]
            or type(result["sessionId"]) is not int or result["sessionId"] != 1
            or result["limited"] is not True):
        return unknown
    if result["code"] in _TASK_UNKNOWN_CODES and result["snapshot"] is None:
        return {**unknown, "diagnostic": "TASK_" + result["code"]}
    if intent["request"].get("operation") == "public-quit":
        snapshot = result["snapshot"]
        expected = {"controllerId", "runtimeRunning", "configuredMode", "activeMode",
                    "selectedLocationId", "activeLocationId", "parentExited", "childExited",
                    "endpointAbsent", "runtimeProcessAbsent"}
        if (result["code"] not in {"QUIT_COMPLETED", "QUIT_PARTIAL"}
                or not isinstance(snapshot, dict) or set(snapshot) != expected
                or snapshot["controllerId"] != intent["request"]["controllerId"]
                or snapshot["runtimeRunning"] is not False or snapshot["activeMode"] is not None
                or snapshot["selectedLocationId"] is not None or snapshot["activeLocationId"] is not None
                or snapshot["configuredMode"] not in {"vpn", "proxy-only"}
                or any(type(snapshot[key]) is not bool for key in
                       ("parentExited", "childExited", "endpointAbsent", "runtimeProcessAbsent"))):
            return unknown
        complete = all(snapshot[key] for key in
                       ("parentExited", "childExited", "endpointAbsent", "runtimeProcessAbsent"))
        if (result["code"] == "QUIT_COMPLETED") != complete:
            return unknown
        return {"state": "quit-complete" if complete else "quit-partial",
                "correlationId": corr, "controllerId": snapshot["controllerId"],
                "runtimeRunning": False, "selectedLocationId": None, "activeLocationId": None,
                "parentExited": snapshot["parentExited"], "childExited": snapshot["childExited"],
                "endpointAbsent": snapshot["endpointAbsent"],
                "runtimeProcessAbsent": snapshot["runtimeProcessAbsent"],
                "replayAllowed": False}
    if result["code"] == "ENDPOINT_ABSENT" and result["snapshot"] is None:
        return {"state": "blocked", "code": "ENDPOINT_ABSENT", "correlationId": corr,
                "ownerStarted": False, "replayAllowed": False}
    snapshot = result["snapshot"]
    if result["code"] != "OBSERVED" or not isinstance(snapshot, dict) or set(snapshot) != {
            "controllerId", "runtimeRunning", "configuredMode", "activeMode", "selectedLocationId", "activeLocationId"}:
        return unknown
    if (snapshot["controllerId"] != intent["request"]["controllerId"]
            or type(snapshot["runtimeRunning"]) is not bool
            or type(snapshot["configuredMode"]) is not str or snapshot["configuredMode"] not in {"vpn", "proxy-only"}
            or (snapshot["activeMode"] is not None and
                (type(snapshot["activeMode"]) is not str or snapshot["activeMode"] not in {"vpn", "proxy-only"}))
            or any(x is not None and (type(x) is not str or not _HASH.fullmatch(x)) for x in
                   (snapshot["selectedLocationId"], snapshot["activeLocationId"]))):
        return unknown
    return {"state": "observed", "correlationId": corr, "controllerId": snapshot["controllerId"],
            "runtimeRunning": snapshot["runtimeRunning"], "configuredMode": snapshot["configuredMode"],
            "activeMode": snapshot["activeMode"], "selectedLocationId": snapshot["selectedLocationId"],
            "activeLocationId": snapshot["activeLocationId"], "ownerStarted": False, "replayAllowed": False}


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or not isinstance(value["correlationId"], str) or not _UUID.fullmatch(value["correlationId"]):
        raise WindowsMsiOwnerObserveError("Owner status requires exact correlationId.")
    root = Path(root).resolve(strict=True);corr = value["correlationId"]
    intent = _read_intent(root, corr)
    if intent is None: return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    descriptor = None
    try:
        config, target, (env, socket, pid, ticks, sid) = windows_msi_base_prepare._descriptor(root)
        descriptor = (env, socket, pid, ticks, sid)
        if any(intent.get(key) != observed for key, observed in (("environment", env), ("socketPath", socket),
                ("pid", pid), ("startTicks", ticks), ("expectedSid", sid))): raise ValueError()
        raw = windows_msi_base_prepare._remote(config, _REMOTE_STATUS,
            (str(target.fixture_transfer_root), env, corr, socket, str(pid), str(ticks),
             intent["request"]["sourceSha"], intent["commandSha256"]), None, 30)
    except (OSError, ValueError, KeyError): raw = None
    result = _classify(raw, corr, intent)
    if result.get("state") == "unknown" and result.get("diagnostic") == "STAGE_BINDING" and descriptor is not None:
        try:
            if _pre_effect_absence(root, corr, intent, config, target, descriptor):
                return {**result, "preEffectAbsent": True}
        except (OSError, ValueError, KeyError):
            pass
    return result


_REMOTE_CLEANUP = windows_msi_base_prepare._QGA + r'''import time
root,env,corr,sock,pid,ticks,source,command_hash,sid,expected_code=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 stage=os.path.join(root,env,'windows-msi-owner-observe',corr);info=os.lstat(stage)
 if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 binding=json.load(open(os.path.join(stage,'binding.json'),encoding='utf-8'))
 if binding!={'socketPath':sock,'pid':int(pid),'startTicks':int(ticks),'sourceSha':source,'artifactIds':[],'commandSha256':command_hash}:raise ValueError()
 if not live(sock,pid,ticks):raise ValueError()
 observed=read(sock,'C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-owner-observe-'+corr+'\\result.json')
 if observed is None:raise ValueError()
 terminal=json.loads(decode(observed))
 if not isinstance(terminal,dict) or set(terminal)!={'version','correlationId','code','originalSid','sessionId','limited','snapshot'} or type(terminal['version']) is not int or terminal['version']!=1 or terminal['correlationId']!=corr or terminal['originalSid']!=sid or type(terminal['sessionId']) is not int or terminal['sessionId']!=1 or terminal['limited'] is not True or expected_code not in ('OBSERVED','QUIT_COMPLETED','QUIT_PARTIAL','ENDPOINT_ABSENT','UNKNOWN','UNKNOWN_IDENTITY','UNKNOWN_CLI_HASH','UNKNOWN_PROCESS','UNKNOWN_ENDPOINT_FILE','UNKNOWN_ENDPOINT_ACL','UNKNOWN_ENDPOINT_BINDING','UNKNOWN_PUBLIC_STATUS','UNKNOWN_PUBLIC_RESULT','UNKNOWN_QUIT_ADMISSION','UNKNOWN_PUBLIC_QUIT','UNKNOWN_OWNER_EXIT','UNKNOWN_POST_EXIT','UNKNOWN_TRANSPORT','UNKNOWN_SNAPSHOT','UNKNOWN_LOOPBACK_CONNECT','UNKNOWN_ENDPOINT_AUTH','UNKNOWN_ENDPOINT_AUTH_WRITE','UNKNOWN_ENDPOINT_AUTH_READ','UNKNOWN_ENDPOINT_AUTH_REPLY','UNKNOWN_SNAPSHOT_REQUEST','UNKNOWN_FRAMED_RESPONSE','UNKNOWN_SNAPSHOT_PARSE') or terminal['code']!=expected_code:raise ValueError()
 if terminal['code'] not in ('OBSERVED','QUIT_COMPLETED','QUIT_PARTIAL') and terminal['snapshot'] is not None:raise ValueError()
 marker=os.path.join(stage,'cleanup-intent.json')
 with open(marker,'x',encoding='utf-8') as file:json.dump({'correlationId':corr,'taskName':'VpnControlMcpOwnerObserve-'+corr},file,separators=(',',':'));file.flush();os.fsync(file.fileno())
 stage_fd=os.open(stage,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(stage_fd);os.close(stage_fd)
 script=@CLEANUP_PS@.replace('@CORR@',corr)
 encoded=base64.b64encode(script.encode('utf-16le')).decode()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for i in range(40):
  state=call(sock,'guest-exec-status',{'pid':child})
  if state.get('exited') is True:break
  time.sleep(.25)
 else:raise ValueError()
 raw=base64.b64decode(state.get('out-data',''),validate=True)
 if len(raw)>4096:raise ValueError()
 lines=[x for x in decode(raw).splitlines() if x.startswith('{') and x.endswith('}')]
 if state.get('exitcode')!=0 or len(lines)!=1 or json.loads(lines[0])!={'version':1,'code':'CLEANED'}:raise ValueError()
 with open(os.path.join(stage,'cleanup-result.json'),'x',encoding='utf-8') as file:json.dump({'version':1,'correlationId':corr,'state':'cleaned','taskName':'VpnControlMcpOwnerObserve-'+corr},file,separators=(',',':'));file.flush();os.fsync(file.fileno())
 stage_fd=os.open(stage,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(stage_fd);os.close(stage_fd)
 out({'state':'cleaned','correlationId':corr})
except Exception:out({'state':'unknown','correlationId':corr})
'''.replace('@CLEANUP_PS@', repr(_cleanup_task_script('@CORR@')))


_REMOTE_CLEANUP_STATUS = r'''import json,os,stat,sys
root,env,corr,source,command_hash=sys.argv[1:]
try:
 stage=os.path.join(root,env,'windows-msi-owner-observe',corr)
 info=os.lstat(stage)
 if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 binding=json.load(open(os.path.join(stage,'binding.json'),encoding='utf-8'))
 if binding.get('sourceSha')!=source or binding.get('commandSha256')!=command_hash:raise ValueError()
 intent=json.load(open(os.path.join(stage,'cleanup-intent.json'),encoding='utf-8'))
 if intent!={'correlationId':corr,'taskName':'VpnControlMcpOwnerObserve-'+corr}:raise ValueError()
 result=json.load(open(os.path.join(stage,'cleanup-result.json'),encoding='utf-8'))
 if result!={'version':1,'correlationId':corr,'state':'cleaned','taskName':'VpnControlMcpOwnerObserve-'+corr}:raise ValueError()
 print(json.dumps({'state':'cleaned','correlationId':corr},separators=(',',':')))
except Exception:print(json.dumps({'state':'unknown','correlationId':corr},separators=(',',':')))
'''


def _cleanup_marker(root: Path, corr: str) -> Path:
    return root / _GROUP / (corr + ".cleanup.json")


def collect(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or not isinstance(value["correlationId"], str) or not _UUID.fullmatch(value["correlationId"]):
        raise WindowsMsiOwnerObserveError("Owner collect requires exact correlationId.")
    root = Path(root).resolve(strict=True);corr = value["correlationId"]
    observation = status(root, {"correlationId": corr})
    if (observation.get("state") == "unknown" and observation.get("diagnostic") == "STAGE_BINDING"
            and observation.get("preEffectAbsent") is True):
        intent = _read_intent(root, corr)
        if intent is None or not _pre_effect_rejection_binding(intent):
            return {**observation, "cleanupState": "not-attempted"}
        try:
            config, target, descriptor = windows_msi_base_prepare._descriptor(root)
            if not _pre_effect_absence(root, corr, intent, config, target, descriptor):
                return {**observation, "cleanupState": "not-attempted"}
            _record_pre_effect_rejection(root, corr, intent)
        except (OSError, ValueError, KeyError):
            return {**observation, "cleanupState": "unknown"}
        return {**observation, "preEffectRejected": True, "cleanupState": "not-required"}
    diagnostic = observation.get("diagnostic", "")
    terminal_code = next((code for code in _TASK_UNKNOWN_CODES if diagnostic in
                          ("BOOTSTRAP_STATUS_TASK_" + code, "BOOTSTRAP_EXIT_TASK_" + code)
                          or (code != "UNKNOWN" and diagnostic == "TASK_" + code)), None)
    terminal_unknown = observation["state"] == "unknown" and terminal_code is not None
    if observation["state"] not in {"observed", "blocked", "quit-complete", "quit-partial"} and not terminal_unknown:
        return {**observation, "cleanupState": "not-attempted"}
    intent = _read_intent(root, corr)
    assert intent is not None
    config, target, (env, socket, pid, ticks, sid) = windows_msi_base_prepare._descriptor(root)
    if any(intent.get(key) != observed for key, observed in (("environment", env), ("socketPath", socket),
            ("pid", pid), ("startTicks", ticks), ("expectedSid", sid))):
        return {**observation, "cleanupState": "unknown"}
    marker = _cleanup_marker(root, corr)
    first = False
    try:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write((json.dumps({"correlationId": corr, "commandSha256": intent["commandSha256"]},
                                   sort_keys=True, separators=(",", ":")) + "\n").encode())
            file.flush(); os.fsync(file.fileno())
        directory_fd = os.open(marker.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
        first = True
    except FileExistsError:
        with marker.open("rb") as file:
            info = os.fstat(file.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise WindowsMsiOwnerObserveError("Owner cleanup intent is unsafe.")
            saved = json.load(file)
        if saved != {"correlationId": corr, "commandSha256": intent["commandSha256"]}:
            raise WindowsMsiOwnerObserveError("Owner cleanup intent changed.")
    program = _REMOTE_CLEANUP if first else _REMOTE_CLEANUP_STATUS
    expected_code = (terminal_code if terminal_unknown else {
        "observed": "OBSERVED", "blocked": "ENDPOINT_ABSENT",
        "quit-complete": "QUIT_COMPLETED", "quit-partial": "QUIT_PARTIAL"}[observation["state"]])
    arguments = ((str(target.fixture_transfer_root), env, corr, socket, str(pid), str(ticks),
                  intent["request"]["sourceSha"], intent["commandSha256"], sid, expected_code) if first else
                 (str(target.fixture_transfer_root), env, corr, intent["request"]["sourceSha"], intent["commandSha256"]))
    raw = windows_msi_base_prepare._remote(config, program, arguments, None, 30)
    try: result = json.loads(raw) if raw is not None else {}
    except (TypeError, ValueError): result = {}
    cleanup = "complete" if isinstance(result, dict) and result.get("state") == "cleaned" and result.get("correlationId") == corr else "unknown"
    if cleanup == "complete": _record_closed(root, corr, intent["commandSha256"])
    return {**observation, "cleanupState": cleanup, "cleanupReplayAllowed": False}


def quit_status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"correlationId"}:
        raise WindowsMsiOwnerObserveError("Owner quit status requires exact correlation.")
    intent = _read_intent(Path(root).resolve(strict=True), value["correlationId"])
    if intent is None or intent.get("request", {}).get("operation") != "public-quit":
        raise WindowsMsiOwnerObserveError("Owner quit correlation is unavailable.")
    return status(root, value)


def quit_collect(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"correlationId"}:
        raise WindowsMsiOwnerObserveError("Owner quit collect requires exact correlation.")
    intent = _read_intent(Path(root).resolve(strict=True), value["correlationId"])
    if intent is None or intent.get("request", {}).get("operation") != "public-quit":
        raise WindowsMsiOwnerObserveError("Owner quit correlation is unavailable.")
    return collect(root, value)
