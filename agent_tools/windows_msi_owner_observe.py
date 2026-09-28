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


def _intent_path(root: Path, correlation: str) -> Path:
    return root / _GROUP / (correlation + ".json")


def _closed_marker(root: Path, correlation: str) -> Path:
    return root / _GROUP / (correlation + ".closed.json")


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
            if item.name.endswith((".cleanup.json", ".closed.json")):
                suffix = ".cleanup.json" if item.name.endswith(".cleanup.json") else ".closed.json"
                prior = item.name.removesuffix(suffix)
                if not _UUID.fullmatch(prior) or prior + ".json" not in entries:
                    raise WindowsMsiOwnerObserveError("CP117 owner observation journal has an orphan receipt.")
                continue
            if item.suffix != ".json" or not _UUID.fullmatch(item.stem):
                raise WindowsMsiOwnerObserveError("CP117 owner observation journal has an unknown entry.")
            previous = _read_intent(root, item.stem)
            closed = _read_private_json(_closed_marker(root, item.stem)) if _closed_marker(root, item.stem).exists() else None
            cleanup = _read_private_json(_cleanup_marker(root, item.stem)) if _cleanup_marker(root, item.stem).exists() else None
            if previous is None or closed != {"correlationId": item.stem,
                    "commandSha256": previous.get("commandSha256"), "state": "cleaned"} or cleanup != {
                    "correlationId": item.stem, "commandSha256": previous.get("commandSha256")}:
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


def _record_closed(root: Path, correlation: str, command_hash: str) -> None:
    marker = _closed_marker(root, correlation)
    expected = {"correlationId": correlation, "commandSha256": command_hash, "state": "cleaned"}
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
 $ownerRead=$false
 foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
  if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and [int]$rule.FileSystemRights -ne 0){
   if($rule.IdentityReference.Value -cne @SID@){throw 'ENDPOINT_ACL'}
   if(($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData) -ne 0){$ownerRead=$true}
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
 $stage='LOOPBACK_CONNECT'
 $client=[Net.Sockets.TcpClient]::new()
 try {
  $connect=$client.BeginConnect([Net.IPAddress]::Loopback,[int]$endpoint.port,$null,$null)
  if(-not $connect.AsyncWaitHandle.WaitOne(1000)){throw 'ENDPOINT_CONNECT'}
  $client.EndConnect($connect);$client.ReceiveTimeout=3000;$client.SendTimeout=3000
  $stream=$client.GetStream()
  function W([string]$value){$bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $value -Compress));$length=[BitConverter]::GetBytes([int]$bytes.Length);[Array]::Reverse($length);$stream.Write($length,0,4);$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}
  function R(){
   $lengthBytes=New-Object byte[] 4;$offset=0
   while($offset -lt 4){$n=$stream.Read($lengthBytes,$offset,4-$offset);if($n -le 0){throw 'FRAME_EOF'};$offset+=$n}
   if([BitConverter]::IsLittleEndian){[Array]::Reverse($lengthBytes)}
   $length=[BitConverter]::ToInt32($lengthBytes,0);if($length -lt 1 -or $length -gt 1048576){throw 'FRAME_BOUND'}
   $bytes=New-Object byte[] $length;$offset=0
   while($offset -lt $length){$n=$stream.Read($bytes,$offset,$length-$offset);if($n -le 0){throw 'FRAME_EOF'};$offset+=$n}
   return (ConvertFrom-Json -InputObject ([Text.Encoding]::UTF8.GetString($bytes)))
  }
  $stage='ENDPOINT_AUTH'
  $stage='ENDPOINT_AUTH_WRITE';W $token
  $stage='ENDPOINT_AUTH_READ';$auth=R
  $stage='ENDPOINT_AUTH_REPLY';if($auth -cne 'AUTHENTICATED'){throw 'AUTH'}
  $controllerBytes=[Text.Encoding]::UTF8.GetBytes($endpoint.controllerId)
  $controllerText=[Convert]::ToBase64String($controllerBytes).TrimEnd('=').Replace('+','-').Replace('/','_')
  $stage='SNAPSHOT_REQUEST'
  W ("cli`tcontrol-snapshot`t"+$controllerText)
  $stage='FRAMED_RESPONSE'
  $response=R
 }finally{$client.Close()}
 if($response -isnot [string]){throw 'RESPONSE_TYPE'}
 $parts=$response.Split([char]9)
 if($parts.Count -ne 4 -or $parts[0] -cne 'cli-response' -or $parts[1] -cne 'ok' -or $parts[2] -cne '0'){throw 'RESPONSE_CODE'}
 $encoded=$parts[3].Replace('-','+').Replace('_','/');$encoded=$encoded.PadRight($encoded.Length+(4-$encoded.Length%4)%4,'=')
 $body=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
 $stage='SNAPSHOT_PARSE'
 $snapshot=ConvertFrom-Json -InputObject $body
 if($snapshot.schemaVersion -ne 1 -or $snapshot.controllerId -cne @CONTROLLER@ -or $snapshot.runtimeRunning -isnot [bool]){throw 'SNAPSHOT_BINDING'}
 $limitedSnapshot=[pscustomobject]@{controllerId=$snapshot.controllerId;runtimeRunning=$snapshot.runtimeRunning;configuredMode=$snapshot.configuredMode;activeMode=$snapshot.activeMode;selectedLocationId=$snapshot.selectedLocationId;activeLocationId=$snapshot.activeLocationId}
 P 'OBSERVED' $limitedSnapshot
}catch{P ('UNKNOWN_'+$stage) $null;exit 1}
'''.replace("@ROOT@", _PS(root)).replace("@STATE@", _PS(_STATE)).replace("@CLI@", _PS(_CLI)).replace("@CORR@", _PS(correlation)).replace("@SID@", _PS(sid)).replace("@CLI_HASH@", _PS(request["installedCliSha256"])).replace("@PARENT_PID@", str(request["parentPid"])).replace("@CHILD_PID@", str(request["childPid"])).replace("@PARENT_TIME@", _PS(request["parentStartedAtUtc"])).replace("@CHILD_TIME@", _PS(request["childStartedAtUtc"])).replace("@CONTROLLER@", _PS(request["controllerId"]))


def _bootstrap(correlation: str, request: Mapping[str, Any], sid: str) -> str:
    root = _GUEST + "\\mcp-owner-observe-" + correlation
    name = "VpnControlMcpOwnerObserve-" + correlation
    packed = base64.b64encode(gzip.compress(_task(correlation, request, sid).encode("utf-16le"), mtime=0)).decode()
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
if _REMOTE_GROUP_EXCLUSIVE not in _REMOTE_START_TEMPLATE:
    raise WindowsMsiOwnerObserveError("Owner observation remote admission template changed.")
_REMOTE_START = _REMOTE_START_TEMPLATE.replace(_REMOTE_GROUP_EXCLUSIVE, _REMOTE_CLOSED_CHECK.strip())


def _close_prior(root: Path, config: Any, target: Any, descriptor: tuple[Any, ...]) -> None:
    directory = root / _GROUP
    if not directory.exists(): return
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsMsiOwnerObserveError("Owner observation journal is unsafe.")
    env, socket, pid, ticks, sid = descriptor
    for item in directory.iterdir():
        if not item.name.endswith(".json") or item.name.endswith((".cleanup.json", ".closed.json")):
            continue
        correlation = item.stem
        if not _UUID.fullmatch(correlation):
            raise WindowsMsiOwnerObserveError("Prior owner observation identity is invalid.")
        intent = _read_intent(root, correlation)
        if intent is None or any(intent.get(key) != observed for key, observed in (
                ("environment", env), ("socketPath", socket), ("pid", pid),
                ("startTicks", ticks), ("expectedSid", sid))):
            raise WindowsMsiOwnerObserveError("Prior owner observation guest identity changed.")
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


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    root = Path(root).resolve(strict=True);request = _request(value);corr = request["correlationId"]
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
    if isinstance(result,dict) and result.get('correlationId')==corr and result.get('code') in ('OBSERVED','ENDPOINT_ABSENT','UNKNOWN','UNKNOWN_IDENTITY','UNKNOWN_CLI_HASH','UNKNOWN_PROCESS','UNKNOWN_ENDPOINT_FILE','UNKNOWN_ENDPOINT_ACL','UNKNOWN_ENDPOINT_BINDING','UNKNOWN_TRANSPORT','UNKNOWN_SNAPSHOT','UNKNOWN_LOOPBACK_CONNECT','UNKNOWN_ENDPOINT_AUTH','UNKNOWN_ENDPOINT_AUTH_WRITE','UNKNOWN_ENDPOINT_AUTH_READ','UNKNOWN_ENDPOINT_AUTH_REPLY','UNKNOWN_SNAPSHOT_REQUEST','UNKNOWN_FRAMED_RESPONSE','UNKNOWN_SNAPSHOT_PARSE'):
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
    try:
        config, target, (env, socket, pid, ticks, sid) = windows_msi_base_prepare._descriptor(root)
        if any(intent.get(key) != observed for key, observed in (("environment", env), ("socketPath", socket),
                ("pid", pid), ("startTicks", ticks), ("expectedSid", sid))): raise ValueError()
        raw = windows_msi_base_prepare._remote(config, _REMOTE_STATUS,
            (str(target.fixture_transfer_root), env, corr, socket, str(pid), str(ticks),
             intent["request"]["sourceSha"], intent["commandSha256"]), None, 30)
    except (OSError, ValueError, KeyError): raw = None
    return _classify(raw, corr, intent)


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
 if not isinstance(terminal,dict) or set(terminal)!={'version','correlationId','code','originalSid','sessionId','limited','snapshot'} or type(terminal['version']) is not int or terminal['version']!=1 or terminal['correlationId']!=corr or terminal['originalSid']!=sid or type(terminal['sessionId']) is not int or terminal['sessionId']!=1 or terminal['limited'] is not True or expected_code not in ('OBSERVED','ENDPOINT_ABSENT','UNKNOWN','UNKNOWN_IDENTITY','UNKNOWN_CLI_HASH','UNKNOWN_PROCESS','UNKNOWN_ENDPOINT_FILE','UNKNOWN_ENDPOINT_ACL','UNKNOWN_ENDPOINT_BINDING','UNKNOWN_TRANSPORT','UNKNOWN_SNAPSHOT','UNKNOWN_LOOPBACK_CONNECT','UNKNOWN_ENDPOINT_AUTH','UNKNOWN_ENDPOINT_AUTH_WRITE','UNKNOWN_ENDPOINT_AUTH_READ','UNKNOWN_ENDPOINT_AUTH_REPLY','UNKNOWN_SNAPSHOT_REQUEST','UNKNOWN_FRAMED_RESPONSE','UNKNOWN_SNAPSHOT_PARSE') or terminal['code']!=expected_code:raise ValueError()
 if terminal['code']!='OBSERVED' and terminal['snapshot'] is not None:raise ValueError()
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
    diagnostic = observation.get("diagnostic", "")
    terminal_code = next((code for code in _TASK_UNKNOWN_CODES if diagnostic in
                          ("BOOTSTRAP_STATUS_TASK_" + code, "BOOTSTRAP_EXIT_TASK_" + code)
                          or (code != "UNKNOWN" and diagnostic == "TASK_" + code)), None)
    terminal_unknown = observation["state"] == "unknown" and terminal_code is not None
    if observation["state"] not in {"observed", "blocked"} and not terminal_unknown:
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
    expected_code = (terminal_code if terminal_unknown else
                     "ENDPOINT_ABSENT" if observation["state"] == "blocked" else "OBSERVED")
    arguments = ((str(target.fixture_transfer_root), env, corr, socket, str(pid), str(ticks),
                  intent["request"]["sourceSha"], intent["commandSha256"], sid, expected_code) if first else
                 (str(target.fixture_transfer_root), env, corr, intent["request"]["sourceSha"], intent["commandSha256"]))
    raw = windows_msi_base_prepare._remote(config, program, arguments, None, 30)
    try: result = json.loads(raw) if raw is not None else {}
    except (TypeError, ValueError): result = {}
    cleanup = "complete" if isinstance(result, dict) and result.get("state") == "cleaned" and result.get("correlationId") == corr else "unknown"
    if cleanup == "complete": _record_closed(root, corr, intent["commandSha256"])
    return {**observation, "cleanupState": cleanup, "cleanupReplayAllowed": False}
