"""One-shot public Windows target check/download before MSI install.

The HTTPS fixture and base installation must already exist. There is currently
no bounded MCP attestation of the live Windows owner's proxy and certificate
state, so start fails closed before any guest effect. This adapter never invokes
updates install or retries an uncertain request. Native installation remains in
windows_msi_public_scenario.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from typing import Any, Mapping

from . import windows_msi_base_prepare as base, windows_msi_public_scenario as public


class WindowsMsiTargetPrepareError(ValueError):
    pass


_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
_UTC = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z\Z")
_GROUP = ".rag_index/windows-msi-target-prepare"
_GUEST = r"C:\Users\vpncp117\AppData\Local\VpnControl"
_STATE = _GUEST + r"\cp166\state"
_CLI = r"C:\Users\vpncp117\AppData\Local\vpn-control\vpn-control-cli.exe"
_PS = public._ps_literal
_MAX_RUNNING_SECONDS = 25 * 60  # 20-minute scheduled-task limit plus bounded handoff margin.


def _request(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = {"host", "correlationId", "sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId",
              "targetMsiArtifactId", "controllerId", "ownerPid", "ownerStartedAtUtc"}
    if not isinstance(value, Mapping) or set(value) != fields or value.get("host") != "archlinux":
        raise WindowsMsiTargetPrepareError("Target preparation requires exact CP117 fields.")
    for name, pattern in (("correlationId", _UUID), ("sourceSha", _SHA),
                          ("fixtureReceiptArtifactId", _ARTIFACT), ("baseMsiArtifactId", _ARTIFACT),
                          ("targetMsiArtifactId", _ARTIFACT), ("controllerId", _UUID),
                          ("ownerStartedAtUtc", _UTC)):
        if not isinstance(value[name], str) or not pattern.fullmatch(value[name]):
            raise WindowsMsiTargetPrepareError("Invalid target preparation " + name + ".")
    if any(str(uuid.UUID(value[name])) != value[name] for name in ("correlationId", "controllerId")):
        raise WindowsMsiTargetPrepareError("Target preparation UUID is not canonical.")
    if type(value["ownerPid"]) is not int or value["ownerPid"] <= 0:
        raise WindowsMsiTargetPrepareError("Target owner PID is invalid.")
    return dict(value)


def _intent_path(root: Path, correlation: str) -> Path:
    return root / _GROUP / (correlation + ".json")


def _read_intent(root: Path, correlation: str) -> dict[str, Any] | None:
    path = _intent_path(root, correlation)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(file.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8192):
            raise WindowsMsiTargetPrepareError("Target intent is unsafe.")
        value = json.load(file)
    if not isinstance(value, dict) or value.get("request", {}).get("correlationId") != correlation:
        raise WindowsMsiTargetPrepareError("Target intent is invalid.")
    return value


def _within_running_window(intent: Mapping[str, Any]) -> bool:
    created = intent.get("createdAtUtc")
    if not isinstance(created, str) or not _UTC.fullmatch(created):
        return False
    try:
        started = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        return False
    age = (datetime.now(timezone.utc) - started).total_seconds()
    return 0 <= age <= _MAX_RUNNING_SECONDS


def _require_cross_route_lease(root: Path, record: Mapping[str, Any]) -> None:
    """Rebind target intent to both shared lease journals before reservation."""
    request = record.get("request")
    if not isinstance(request, dict) or not isinstance(record.get("leaseId"), str):
        raise WindowsMsiTargetPrepareError("CP117_CROSS_ROUTE_LEASE_UNAVAILABLE")
    config, guest, descriptor = base._descriptor(root)
    actual = base._require_verified_live_fixture(root, request, descriptor, config, guest)
    if actual != record["leaseId"]:
        raise WindowsMsiTargetPrepareError("CP117 target lease identity changed.")


def _reserve(root: Path, value: dict[str, Any]) -> None:
    _require_cross_route_lease(root, value)
    # Private, fsynced one-shot reservation after a future shared CP117 lease.
    directory = root / _GROUP
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsMsiTargetPrepareError("Target journal is unsafe.")
    import fcntl
    lock = os.open(directory / ".environment.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if any(item.suffix == ".json" for item in directory.iterdir()):
            raise WindowsMsiTargetPrepareError("CP117 has an active or unknown target preparation.")
        fd = os.open(_intent_path(root, value["request"]["correlationId"]),
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())
            file.flush(); os.fsync(file.fileno())
        parent = os.open(directory, os.O_RDONLY)
        try: os.fsync(parent)
        finally: os.close(parent)
    finally:
        os.close(lock)


def _pair(root: Path, request: dict[str, Any]) -> dict[str, Any]:
    pair = public._admit_pair(root, request["sourceSha"], request["fixtureReceiptArtifactId"],
                              request["baseMsiArtifactId"], request["targetMsiArtifactId"])
    if tuple(map(int, pair["targetVersion"].split("."))) <= tuple(map(int, pair["baseVersion"].split("."))):
        raise WindowsMsiTargetPrepareError("Target must be newer than the installed base.")
    return pair


def _require_fixture_network_admission(root: Path, request: Mapping[str, Any]) -> str:
    """Require registered pair, current QEMU generation and private live receipt."""
    _pair(root, dict(request))
    config, guest, descriptor = base._descriptor(root)
    try:
        base._require_verified_live_fixture(root, request, descriptor, config, guest)
    except ValueError as error:
        raise WindowsMsiTargetPrepareError("FIXTURE_ADMISSION_UNAVAILABLE: no live CP117 HTTPS proxy/TLS receipt") from error
    # A verified server alone cannot serialize target preparation with the
    # public installer. The exact target correlation must claim the campaign.
    raise WindowsMsiTargetPrepareError("CP117_TARGET_ROUTE_CLAIM_UNAVAILABLE")


def _readiness_script(request: Mapping[str, Any], pair: Mapping[str, Any], sid: str) -> str:
    """Inert SYSTEM observation; public commands run only in the later task."""
    return r'''$ErrorActionPreference='Stop'
try {
 $sid=@SID@;$cli=@CLI@;$state=@STATE@
 $products=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',('Registry::HKEY_USERS\'+$sid+'\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'),('Registry::HKEY_USERS\'+$sid+'\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') -ErrorAction SilentlyContinue|Where-Object {$_.DisplayName -eq 'vpn-control'})
 $owner=Get-CimInstance Win32_Process -Filter ('ProcessId='+@OWNER_PID@)
 $ownerSid=if($null -ne $owner){Invoke-CimMethod -InputObject $owner -MethodName GetOwnerSid}else{$null}
 $active=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match '^(msiexec|consent|sing-box)\.exe$'})
 $endpointPath=Join-Path $state 'activation.port'
 $endpoint=if([IO.File]::Exists($endpointPath)){Get-Content -LiteralPath $endpointPath -Raw|ConvertFrom-Json}else{$null}
 $lockRaw=if([IO.File]::Exists((Join-Path $state 'vpn-control.lock'))){(Get-Content -LiteralPath (Join-Path $state 'vpn-control.lock') -Raw).Trim()}else{$null}
 $hash=if([IO.File]::Exists($cli)){(Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant()}else{$null}
 $ready=$products.Count -eq 1 -and $products[0].DisplayVersion -ceq @BASE_VERSION@ -and
  $products[0].InstallLocation.TrimEnd('\') -ceq 'C:\Users\vpncp117\AppData\Local\vpn-control' -and
  $null -ne $owner -and $owner.Name -ceq 'vpn-control-cli.exe' -and
  $owner.CreationDate.ToUniversalTime().ToString('o') -ceq @OWNER_TIME@ -and
  $owner.SessionId -eq 1 -and $owner.ExecutablePath -ceq $cli -and
  $ownerSid.ReturnValue -eq 0 -and $ownerSid.Sid -ceq $sid -and
  $endpoint.schemaVersion -eq 1 -and $endpoint.controllerId -ceq @CONTROLLER@ -and
  $lockRaw -ceq @OWNER_PID_TEXT@ -and
  $hash -ceq @CLI_HASH@ -and $active.Count -eq 0
 $code=if($ready){'READY'}elseif($products.Count -ne 1){'PRODUCT_COUNT'}elseif($active.Count -gt 0){'ACTIVE_PROCESS'}else{'ADMISSION_CHANGED'}
 [Console]::Out.WriteLine(([pscustomobject]@{version=1;code=$code;installedVersion=$(if($products.Count -eq 1){$products[0].DisplayVersion}else{$null});
  productCount=$products.Count;ownerPid=$(if($null -ne $owner){[int]$owner.ProcessId}else{$null});
  ownerStartedAtUtc=$(if($null -ne $owner){$owner.CreationDate.ToUniversalTime().ToString('o')}else{$null});
  controllerId=$(if($null -ne $endpoint){$endpoint.controllerId}else{$null});
  cliSha256=$hash;activeCount=$active.Count}|ConvertTo-Json -Compress))
}catch{[Console]::Out.WriteLine('{"version":1,"code":"UNKNOWN"}');exit 1}
'''.replace("@SID@", _PS(sid)).replace("@CLI@", _PS(_CLI)).replace("@STATE@", _PS(_STATE)).replace("@OWNER_PID@", str(request["ownerPid"])).replace("@OWNER_PID_TEXT@", _PS(str(request["ownerPid"]))).replace("@OWNER_TIME@", _PS(request["ownerStartedAtUtc"])).replace("@BASE_VERSION@", _PS(pair["baseVersion"])).replace("@CONTROLLER@", _PS(request["controllerId"])).replace("@CLI_HASH@", _PS(pair["baseCliSha256"]))


def readiness(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    root = Path(root).resolve(strict=True)
    request = _request(value)
    pair = _pair(root, request)
    config, _, (env, sock, pid, ticks, sid) = base._descriptor(root)
    if env != "windows-cp117":
        raise WindowsMsiTargetPrepareError("Owned CP117 identity changed.")
    encoded = base64.b64encode(_readiness_script(request, pair, sid).encode("utf-16le")).decode()
    if len(encoded) >= 30000:
        raise WindowsMsiTargetPrepareError("Target readiness exceeds Windows command admission.")
    raw = base._remote(config, base._READINESS, (sock, str(pid), str(ticks), encoded), None, 30)
    unknown = {"state": "unknown", "ready": False, "productAction": False}
    try: value = json.loads(raw) if raw is not None else {}
    except (TypeError, ValueError): return unknown
    if not isinstance(value, dict) or value.get("state") != "observed" or not isinstance(value.get("inventory"), dict):
        return unknown
    item = value["inventory"]
    keys = {"version", "code", "installedVersion", "productCount", "ownerPid", "ownerStartedAtUtc",
            "controllerId", "cliSha256", "activeCount"}
    if (set(item) != keys or item["version"] != 1 or item["code"] not in
            {"READY", "PRODUCT_COUNT", "ACTIVE_PROCESS", "ADMISSION_CHANGED"}
            or type(item["productCount"]) is not int or item["productCount"] < 0
            or type(item["activeCount"]) is not int or item["activeCount"] < 0):
        return unknown
    ready = (item["code"] == "READY" and item["installedVersion"] == pair["baseVersion"]
             and item["productCount"] == 1 and item["ownerPid"] == request["ownerPid"]
             and item["ownerStartedAtUtc"] == request["ownerStartedAtUtc"]
             and item["controllerId"] == request["controllerId"]
             and item["cliSha256"] == pair["baseCliSha256"] and item["activeCount"] == 0)
    if item["code"] == "READY" and not ready: return unknown
    return {"state": "blocked", "ready": False, "code": "FIXTURE_ADMISSION_UNAVAILABLE" if ready else item["code"],
            "installedVersion": item["installedVersion"], "productCount": item["productCount"],
            "activeCount": item["activeCount"], "ownerPid": item["ownerPid"],
            "controllerId": item["controllerId"], "fixtureReady": False,
            "crossRouteLeaseReady": False, "productAction": False}


def _task(correlation: str, request: Mapping[str, Any], pair: Mapping[str, Any], sid: str) -> str:
    """Fixed PowerShell 5.1 body; public check/download only, no install."""
    guest = _GUEST + "\\mcp-target-" + correlation
    cache = _STATE + "\\updates\\vpn-control-" + pair["targetVersion"] + ".msi"
    jar = "C:\\Users\\vpncp117\\AppData\\Local\\vpn-control\\app\\" + pair["baseAppJarName"]
    helper = r"C:\Users\vpncp117\AppData\Local\vpn-control\app\native\windows-amd64\vpn-control-install-helper.exe"
    return r'''$ErrorActionPreference='Stop';$root=@ROOT@;$state=@STATE@;$cli=@CLI@;$cache=@CACHE@
$stage='IDENTITY';$checked=$null;$downloaded=$null;$ready=$null;$cacheHash=$null
function P([string]$result,[string]$code){
 ([pscustomobject]@{version=1;correlationId=@CORR@;stage=$stage;result=$result;code=$code;
  originalSid=$identity.User.Value;sessionId=(Get-Process -Id $PID).SessionId;limited=$limited;
  controllerId=@CONTROLLER@;ownerPid=@OWNER_PID@;checked=$checked;downloaded=$downloaded;
  ready=$ready;cacheSha256=$cacheHash}|ConvertTo-Json -Depth 7 -Compress)|
  Set-Content -LiteralPath (Join-Path $root 'result.json') -Encoding UTF8
}
function Owner {
 $owner=Get-CimInstance Win32_Process -Filter ('ProcessId='+@OWNER_PID@)
 if($null -eq $owner -or $owner.Name -cne 'vpn-control-cli.exe' -or
  $owner.CreationDate.ToUniversalTime().ToString('o') -cne @OWNER_TIME@ -or
  $owner.SessionId -ne 1 -or $owner.ExecutablePath -cne $cli){throw 'OWNER_GENERATION'}
 $ownerSid=Invoke-CimMethod -InputObject $owner -MethodName GetOwnerSid
 if($ownerSid.ReturnValue -ne 0 -or $ownerSid.Sid -cne @SID@){throw 'OWNER_SID'}
 $lockPath=Join-Path $state 'vpn-control.lock'
 if(-not [IO.File]::Exists($lockPath) -or (Get-Content -LiteralPath $lockPath -Raw).Trim() -cne @OWNER_PID_TEXT@){throw 'OWNER_LOCK'}
 $endpointPath=Join-Path $state 'activation.port'
 if(-not [IO.File]::Exists($endpointPath)){throw 'OWNER_ENDPOINT'}
 $endpoint=Get-Content -LiteralPath $endpointPath -Raw|ConvertFrom-Json
 if($endpoint.schemaVersion -ne 1 -or $endpoint.controllerId -cne @CONTROLLER@){throw 'OWNER_ENDPOINT'}
}
function Public([string[]]$command) {
 Owner
 $raw=& $cli --state-dir $state --json --controller-id @CONTROLLER@ --timeout-seconds 120 @command
 if($LASTEXITCODE -ne 0){throw 'PUBLIC_COMMAND'}
 $value=$raw|ConvertFrom-Json
 if($value.code -cne 'OK' -or $value.final -ne $true -or $value.controllerId -cne @CONTROLLER@){throw 'PUBLIC_RESPONSE'}
 return $value
}
try {
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 $limited=-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
 if($identity.User.Value -cne @SID@ -or (Get-Process -Id $PID).SessionId -ne 1 -or -not $limited){throw 'IDENTITY'}
 $stage='ADMISSION'
 $products=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue|Where-Object {$_.DisplayName -eq 'vpn-control'})
 if($products.Count -ne 1 -or $products[0].DisplayVersion -cne @BASE_VERSION@ -or
  $products[0].InstallLocation.TrimEnd('\') -cne 'C:\Users\vpncp117\AppData\Local\vpn-control'){throw 'BASE_PRODUCT'}
 foreach($item in @(@{path=$cli;hash=@CLI_HASH@},@{path=@JAR@;hash=@JAR_HASH@},@{path=@HELPER@;hash=@HELPER_HASH@})){
  if((Get-FileHash -LiteralPath $item.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $item.hash){throw 'BASE_BYTES'}
 }
 if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match '^(msiexec|consent|sing-box)\.exe$'}).Count -ne 0){throw 'ACTIVE_INSTALLER_OR_RUNTIME'}
 Owner
 $status=Public -command @('status')
 if($status.data.runtimeRunning -ne $false){throw 'RUNTIME_ON'}
 $stage='CHECK';P 'IN_PROGRESS' 'CHECK_STARTED'
 $check=Public -command @('updates','check')
 $checked=[pscustomobject]@{code=$check.code;availableVersion=$check.data.availableVersion;controllerId=$check.controllerId}
 if($check.data.availableVersion -cne @TARGET_VERSION@){throw 'TARGET_VERSION'}
 $stage='DOWNLOAD';P 'IN_PROGRESS' 'DOWNLOAD_STARTED'
 $download=Public -command @('updates','download')
 $downloaded=[pscustomobject]@{code=$download.code;controllerId=$download.controllerId}
 $stage='READBACK'
 $status=Public -command @('updates','status')
 $ready=[pscustomobject]@{phase=$status.data.phase;availableVersion=$status.data.availableVersion;
  downloadedBytes=$status.data.downloadedBytes;totalBytes=$status.data.totalBytes;controllerId=$status.controllerId}
 $cacheHash=(Get-FileHash -LiteralPath $cache -Algorithm SHA256).Hash.ToLowerInvariant()
 if($ready.phase -cne 'ready' -or $ready.availableVersion -cne @TARGET_VERSION@ -or
  $ready.downloadedBytes -ne @TARGET_SIZE@ -or $ready.totalBytes -ne @TARGET_SIZE@ -or
  $cacheHash -cne @TARGET_HASH@){throw 'TARGET_READBACK'}
 P 'PASSED' 'READY'
}catch{P 'FAILED' 'UNKNOWN';exit 1}
'''.replace("@ROOT@", _PS(guest)).replace("@STATE@", _PS(_STATE)).replace("@CLI@", _PS(_CLI)).replace("@CACHE@", _PS(cache)).replace("@CORR@", _PS(correlation)).replace("@CONTROLLER@", _PS(request["controllerId"])).replace("@OWNER_PID@", str(request["ownerPid"])).replace("@OWNER_PID_TEXT@", _PS(str(request["ownerPid"]))).replace("@OWNER_TIME@", _PS(request["ownerStartedAtUtc"])).replace("@SID@", _PS(sid)).replace("@BASE_VERSION@", _PS(pair["baseVersion"])).replace("@CLI_HASH@", _PS(pair["baseCliSha256"])).replace("@JAR@", _PS(jar)).replace("@JAR_HASH@", _PS(pair["baseAppJarSha256"])).replace("@HELPER@", _PS(helper)).replace("@HELPER_HASH@", _PS(pair["baseHelperSha256"])).replace("@TARGET_VERSION@", _PS(pair["targetVersion"])).replace("@TARGET_SIZE@", str(pair["targetMsiSize"])).replace("@TARGET_HASH@", _PS(pair["targetMsiSha256"]))


def _bootstrap(correlation: str, request: Mapping[str, Any], pair: Mapping[str, Any], sid: str) -> str:
    guest = _GUEST + "\\mcp-target-" + correlation
    task = "VpnControlMcpTarget-" + correlation
    packed = base64.b64encode(gzip.compress(_task(correlation, request, pair, sid).encode("utf-16le"), mtime=0)).decode()
    return r'''$ErrorActionPreference='Stop';$root=@ROOT@;$task=@TASK@
try {
 if([IO.Directory]::Exists($root) -or (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)){throw 'EXCLUSIVE'}
 [IO.Directory]::CreateDirectory($root)|Out-Null
 $compressed=[Convert]::FromBase64String(@PACKED@)
 $inputStream=[IO.MemoryStream]::new([byte[]]$compressed)
 $decompressor=[IO.Compression.GzipStream]::new($inputStream,[IO.Compression.CompressionMode]::Decompress)
 $outputStream=[IO.MemoryStream]::new();$decompressor.CopyTo($outputStream)
 $body=[Convert]::ToBase64String($outputStream.ToArray())
 $decompressor.Dispose();$inputStream.Dispose();$outputStream.Dispose()
 $action=New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$body)
 $principal=New-ScheduledTaskPrincipal -UserId 'VPNMSIX64\vpncp117' -LogonType Interactive -RunLevel Limited
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 20) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings|Out-Null
 Start-ScheduledTask -TaskName $task
 ([pscustomobject]@{version=1;correlationId=@CORR@;triggered=$true}|ConvertTo-Json -Compress)
}catch{([pscustomobject]@{version=1;correlationId=@CORR@;triggered=$false}|ConvertTo-Json -Compress);exit 1}
'''.replace("@ROOT@", _PS(guest)).replace("@TASK@", _PS(task)).replace("@PACKED@", _PS(packed)).replace("@CORR@", _PS(correlation))


def _powershell_preflight_script(body: str) -> str:
    """Ask guest PowerShell 5.1 to parse one fixed script without running it."""
    packed = base64.b64encode(gzip.compress(body.encode("utf-16le"), mtime=0)).decode()
    return r'''$ErrorActionPreference='Stop'
function Expand([string]$body) {
 $packed=[Convert]::FromBase64String($body)
 $inputStream=[IO.MemoryStream]::new([byte[]]$packed)
 $decompressor=[IO.Compression.GzipStream]::new($inputStream,[IO.Compression.CompressionMode]::Decompress)
 $outputStream=[IO.MemoryStream]::new();$decompressor.CopyTo($outputStream)
 $text=[Text.Encoding]::Unicode.GetString($outputStream.ToArray())
 $decompressor.Dispose();$inputStream.Dispose();$outputStream.Dispose()
 return $text
}
try {
 $body=Expand @PACKED@;$tokens=$null;$errors=$null
 [System.Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)|Out-Null
 if($errors.Count -ne 0){throw 'SYNTAX'}
 [Console]::Out.WriteLine('{"version":1,"code":"OK"}')
}catch{[Console]::Out.WriteLine('{"version":1,"code":"FAILED"}');exit 1}
'''.replace("@PACKED@", _PS(packed))


def powershell_preflight(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"host"} or value["host"] != "archlinux":
        raise WindowsMsiTargetPrepareError("Target PS5 preflight requires exact CP117 host.")
    root = Path(root).resolve(strict=True)
    config, _, (env, sock, pid, ticks, _) = base._descriptor(root)
    if env != "windows-cp117":
        raise WindowsMsiTargetPrepareError("Owned CP117 identity changed.")
    request = {"controllerId": "11111111-1111-4111-8111-111111111111", "ownerPid": 123,
               "ownerStartedAtUtc": "2026-09-28T10:00:00Z"}
    pair = {"baseVersion": "2.1.19", "targetVersion": "2.2.0", "baseAppJarName": "desktopApp-2.1.19.jar",
            "baseCliSha256": "a" * 64, "baseAppJarSha256": "b" * 64, "baseHelperSha256": "c" * 64,
            "targetMsiSha256": "d" * 64, "targetMsiSize": 123456}
    corr = "22222222-2222-4222-8222-222222222222"
    scripts = (_readiness_script(request, pair, "S-1-5-21-1-2-3-1002"),
               _task(corr, request, pair, "S-1-5-21-1-2-3-1002"),
               _bootstrap(corr, request, pair, "S-1-5-21-1-2-3-1002"),
               _task_probe_script(corr))
    for body in scripts:
        encoded = base64.b64encode(_powershell_preflight_script(body).encode("utf-16le")).decode()
        if len(encoded) >= 30000:
            raise WindowsMsiTargetPrepareError("Fixed target PS5 preflight exceeds Windows command admission.")
        raw = base._remote(config, base._READINESS, (sock, str(pid), str(ticks), encoded), None, 30)
        try: result = json.loads(raw) if raw is not None else {}
        except (TypeError, ValueError): result = {}
        if result.get("state") != "observed" or result.get("inventory") != {"version": 1, "code": "OK"}:
            return {"state": "unknown", "checks": []}
    return {"state": "passed", "checks": ["ps5-parse", "gzip"]}


_REMOTE_START = base._QGA + r'''import fcntl
root,env,corr,sock,pid,ticks,encoded,command_hash,source,fingerprint,receipt_id,base_id,target_id,sid=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if env!='windows-cp117' or not live(sock,pid,ticks):raise ValueError()
 if len(encoded)>=30000 or hashlib.sha256(base64.b64decode(encoded,validate=True)).hexdigest()!=command_hash:raise ValueError()
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-msi-target')
 for path in (root,parent,group):
  if not os.path.exists(path):os.mkdir(path,0o700)
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 lock=os.open(os.path.join(group,'.environment.lock'),os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
 try:
  fcntl.flock(lock,fcntl.LOCK_EX)
  if any(name!='.environment.lock' for name in os.listdir(group)):raise FileExistsError()
  stage=os.path.join(group,corr);os.mkdir(stage,0o700)
 finally:os.close(lock)
 binding={'socketPath':sock,'pid':int(pid),'startTicks':int(ticks),'sourceSha':source,'sourceFingerprint':fingerprint,'receiptArtifactId':receipt_id,'baseArtifactId':base_id,'targetArtifactId':target_id,'commandSha256':command_hash,'expectedSid':sid}
 with open(os.path.join(stage,'binding.json'),'x',encoding='utf-8') as file:json.dump(binding,file,separators=(',',':'));file.flush();os.fsync(file.fileno())
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 with open(os.path.join(stage,'dispatch.json'),'x',encoding='utf-8') as file:json.dump({'pid':child},file,separators=(',',':'));file.flush();os.fsync(file.fileno())
 out({'state':'submitted','correlationId':corr})
except FileExistsError:out({'state':'unknown','reason':'existing-intent','correlationId':corr})
except Exception:out({'state':'unknown','reason':'submission-uncertain','correlationId':corr})
'''


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    root = Path(root).resolve(strict=True)
    request = _request(value); correlation = request["correlationId"]
    existing = _read_intent(root, correlation)
    if existing is not None:
        if existing.get("request") != request:
            raise WindowsMsiTargetPrepareError("Correlation binds another target preparation.")
        return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    lease_id = _require_fixture_network_admission(root, request)
    if readiness(root, request)["state"] != "ready":
        raise WindowsMsiTargetPrepareError("Installed base or original owner is not ready.")
    pair = _pair(root, request)
    config, target, (env, sock, pid, ticks, sid) = base._descriptor(root)
    command = _bootstrap(correlation, request, pair, sid)
    encoded = base64.b64encode(command.encode("utf-16le")).decode()
    if len(encoded) >= 30000:
        raise WindowsMsiTargetPrepareError("Fixed target bootstrap exceeds Windows command admission.")
    command_hash = hashlib.sha256(command.encode("utf-16le")).hexdigest()
    record = {"request": request, "pair": pair, "environment": env, "socketPath": sock,
              "pid": pid, "startTicks": ticks, "expectedSid": sid, "commandSha256": command_hash}
    record["leaseId"] = lease_id
    record["createdAtUtc"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    _reserve(root, record)
    raw = base._remote(config, _REMOTE_START, (str(target.fixture_transfer_root), env, correlation, sock,
        str(pid), str(ticks), encoded, command_hash, request["sourceSha"], pair["sourceFingerprint"],
        request["fixtureReceiptArtifactId"], request["baseMsiArtifactId"], request["targetMsiArtifactId"], sid), None, 30)
    try: result = json.loads(raw) if raw is not None else {}
    except (TypeError, ValueError): result = {}
    state = "submitted" if result.get("state") == "submitted" and result.get("correlationId") == correlation else "unknown"
    return {"state": state, "correlationId": correlation, "replayAllowed": False}


def _task_probe_script(correlation: str) -> str:
    task_name = "VpnControlMcpTarget-" + correlation
    return r'''$ErrorActionPreference='Stop'
try {
 $task=Get-ScheduledTask -TaskName @TASK@ -ErrorAction Stop
 $name=$task.TaskName;$state=[string]$task.State
 ([pscustomobject]@{version=1;taskName=$name;state=$state}|ConvertTo-Json -Compress)
}catch{([pscustomobject]@{version=1;taskName=@TASK@;state='Unknown'}|ConvertTo-Json -Compress);exit 1}
'''.replace("@TASK@", _PS(task_name))


_REMOTE_STATUS = base._QGA + r'''import fcntl,time
root,env,corr,sock,pid,ticks,source,fingerprint,receipt_id,base_id,target_id,command_hash,sid,probe_encoded,probe_hash=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
def live_task():
 if len(probe_encoded)>=30000 or hashlib.sha256(base64.b64decode(probe_encoded,validate=True)).hexdigest()!=probe_hash:raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',probe_encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for attempt in range(24):
  state=call(sock,'guest-exec-status',{'pid':child})
  if state.get('exited') is True:break
  time.sleep(.25)
 else:raise ValueError()
 if state.get('exitcode')!=0:raise ValueError()
 output=base64.b64decode(state.get('out-data',''),validate=True)
 if len(output)>1024:raise ValueError()
 lines=[x for x in decode(output).splitlines() if x.startswith('{') and x.endswith('}')]
 if len(lines)!=1:raise ValueError()
 observed=json.loads(lines[0]);expected='VpnControlMcpTarget-'+corr
 return observed=={'version':1,'taskName':expected,'state':'Running'}
def running_or_unknown():
 if live_task():out({'state':'running','correlationId':corr,'taskState':'Running'})
 else:out({'state':'unknown','correlationId':corr,'reason':'task-not-running'})
def terminal_or_live(stage,child):
 path=os.path.join(stage,'bootstrap-terminal.json')
 lock=os.open(os.path.join(stage,'.status.lock'),os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
 try:
  fcntl.flock(lock,fcntl.LOCK_EX)
  try:
   fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
  except FileNotFoundError:fd=None
  if fd is not None:
   with os.fdopen(fd,'rb') as file:
    info=os.fstat(file.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>16384:raise ValueError()
    result=json.load(file)
   if not isinstance(result,dict) or result.get('exited') is not True or set(result) not in ({'exited','exitcode','out-data'},{'exited','invalid'}):raise ValueError()
   return result
  state=call(sock,'guest-exec-status',{'pid':child})
  if state.get('exited') is not True:return {'exited':False}
  if type(state.get('exitcode')) is int and isinstance(state.get('out-data'),str) and len(state['out-data'])<=12000:
   result={'exited':True,'exitcode':state['exitcode'],'out-data':state['out-data']}
  else:result={'exited':True,'invalid':True}
  raw=json.dumps(result,separators=(',',':')).encode()
  if len(raw)>16384:result={'exited':True,'invalid':True};raw=json.dumps(result,separators=(',',':')).encode()
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  with os.fdopen(fd,'wb') as file:file.write(raw);file.flush();os.fsync(file.fileno())
  directory=os.open(stage,os.O_RDONLY)
  try:os.fsync(directory)
  finally:os.close(directory)
  return result
 finally:os.close(lock)
try:
 stage=os.path.join(root,env,'windows-msi-target',corr);info=os.lstat(stage)
 if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 binding=json.load(open(os.path.join(stage,'binding.json'),encoding='utf-8'))
 expected={'socketPath':sock,'pid':int(pid),'startTicks':int(ticks),'sourceSha':source,'sourceFingerprint':fingerprint,'receiptArtifactId':receipt_id,'baseArtifactId':base_id,'targetArtifactId':target_id,'commandSha256':command_hash,'expectedSid':sid}
 if binding!=expected or not live(sock,pid,ticks):raise ValueError()
 dispatch=json.load(open(os.path.join(stage,'dispatch.json'),encoding='utf-8'))
 if set(dispatch)!={'pid'} or type(dispatch['pid']) is not int or dispatch['pid']<=0:raise ValueError()
 status=terminal_or_live(stage,dispatch['pid'])
 if status.get('exited') is not True:out({'state':'running','correlationId':corr,'taskState':'bootstrap-running'});raise SystemExit(0)
 if status.get('invalid') is True:raise ValueError()
 if status.get('exitcode')!=0:out({'state':'unknown','correlationId':corr});raise SystemExit(0)
 output=base64.b64decode(status.get('out-data',''),validate=True)
 if len(output)>8192:raise ValueError()
 lines=[x for x in decode(output).splitlines() if x.startswith('{') and x.endswith('}')]
 if not lines or json.loads(lines[-1])!={'version':1,'correlationId':corr,'triggered':True}:raise ValueError()
 path='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-target-'+corr+'\\result.json'
 raw=read(sock,path)
 if raw is None:running_or_unknown();raise SystemExit(0)
 result=json.loads(decode(raw))
 if isinstance(result,dict) and result.get('result')=='IN_PROGRESS':running_or_unknown();raise SystemExit(0)
 out({'state':'observed','correlationId':corr,'result':result})
except Exception:out({'state':'unknown','correlationId':corr})
'''


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"correlationId"}:
        raise WindowsMsiTargetPrepareError("Target status requires exact correlationId.")
    correlation = value["correlationId"]
    if not isinstance(correlation, str) or not _UUID.fullmatch(correlation) or str(uuid.UUID(correlation)) != correlation:
        raise WindowsMsiTargetPrepareError("Invalid target correlationId.")
    root = Path(root).resolve(strict=True)
    unknown = {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    intent = _read_intent(root, correlation)
    if intent is None: return unknown
    try:
        config, target, (env, sock, pid, ticks, sid) = base._descriptor(root)
        if any(intent.get(name) != observed for name, observed in (("environment", env), ("socketPath", sock),
                ("pid", pid), ("startTicks", ticks), ("expectedSid", sid))): return unknown
        request, pair = intent["request"], intent["pair"]
        probe = _task_probe_script(correlation)
        probe_encoded = base64.b64encode(probe.encode("utf-16le")).decode()
        if len(probe_encoded) >= 30000: return unknown
        raw = base._remote(config, _REMOTE_STATUS, (str(target.fixture_transfer_root), env, correlation, sock,
            str(pid), str(ticks), request["sourceSha"], pair["sourceFingerprint"],
            request["fixtureReceiptArtifactId"], request["baseMsiArtifactId"], request["targetMsiArtifactId"],
            intent["commandSha256"], sid, probe_encoded, hashlib.sha256(probe.encode("utf-16le")).hexdigest()), None, 30)
        result = json.loads(raw) if raw is not None else {}
    except (OSError, ValueError, TypeError, KeyError): return unknown
    if not isinstance(result, dict) or result.get("correlationId") != correlation: return unknown
    if result.get("state") == "running":
        if result.get("taskState") not in {"Running", "bootstrap-running"} or not _within_running_window(intent):
            return unknown
        return {"state": "running", "correlationId": correlation, "replayAllowed": False}
    payload = result.get("result")
    required = {"version", "correlationId", "stage", "result", "code", "originalSid", "sessionId", "limited",
                "controllerId", "ownerPid", "checked", "downloaded", "ready", "cacheSha256"}
    if result.get("state") != "observed" or not isinstance(payload, dict) or set(payload) != required:
        return unknown
    if (type(payload["version"]) is not int or payload["version"] != 1 or payload["correlationId"] != correlation
            or payload["stage"] not in {"IDENTITY", "ADMISSION", "CHECK", "DOWNLOAD", "READBACK"}
            or payload["result"] not in {"IN_PROGRESS", "PASSED", "FAILED"}
            or payload["originalSid"] != sid or type(payload["sessionId"]) is not int
            or payload["sessionId"] != 1 or payload["limited"] is not True
            or payload["controllerId"] != request["controllerId"] or type(payload["ownerPid"]) is not int
            or payload["ownerPid"] != request["ownerPid"]):
        return unknown
    # The remote observer must reconcile an in-progress file with the exact
    # scheduled task. A raw in-progress file alone is never running evidence.
    if payload["result"] == "IN_PROGRESS": return unknown
    if payload["result"] == "PASSED":
        ready = payload["ready"]
        if (payload["stage"] != "READBACK" or payload["code"] != "READY"
                or not isinstance(payload["checked"], dict)
                or set(payload["checked"]) != {"code", "availableVersion", "controllerId"}
                or payload["checked"]["code"] != "OK"
                or payload["checked"]["availableVersion"] != pair["targetVersion"]
                or payload["checked"]["controllerId"] != request["controllerId"]
                or not isinstance(payload["downloaded"], dict)
                or set(payload["downloaded"]) != {"code", "controllerId"}
                or payload["downloaded"]["code"] != "OK"
                or payload["downloaded"]["controllerId"] != request["controllerId"]
                or not isinstance(ready, dict)
                or set(ready) != {"phase", "availableVersion", "downloadedBytes", "totalBytes", "controllerId"}
                or ready.get("phase") != "ready"
                or ready.get("availableVersion") != pair["targetVersion"]
                or type(ready.get("downloadedBytes")) is not int
                or ready.get("downloadedBytes") != pair["targetMsiSize"]
                or type(ready.get("totalBytes")) is not int
                or ready.get("totalBytes") != pair["targetMsiSize"]
                or ready.get("controllerId") != request["controllerId"]
                or payload["cacheSha256"] != pair["targetMsiSha256"]):
            return unknown
    # The task readback is bound to its completion instant. A later installer
    # admission must recheck public READY and the cache, as the existing public
    # scenario does; this status never claims current cache readiness.
    return {"state": "terminal",
            "correlationId": correlation, "result": payload["result"], "stage": payload["stage"],
            "sourceSha": request["sourceSha"], "targetArtifactId": request["targetMsiArtifactId"],
            "evidenceScope": "completion-time", "currentReady": False, "replayAllowed": False}
