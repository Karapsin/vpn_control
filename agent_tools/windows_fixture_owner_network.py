"""CP117 original-owner network launch admission.

The already-running owner handles forwarded CLI update operations. A proxy and
trust store set on a forwarding CLI cannot configure that owner. This adapter
prepares a one-shot, original-user launch with explicit runtime-off admission.
Native dispatch remains closed until its exact task/status/cleanup receipts are
reviewed; no caller-supplied JVM flags or proof can unlock target/public work.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re
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


def _binding(root: Path, request: Mapping[str, Any]) -> dict[str, Any]:
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
                         and active["correlationId"] == request["ownerNetworkCorrelationId"]))):
            raise WindowsFixtureOwnerNetworkError("CP117 owner network lease changed.")
    finally:
        import os
        os.close(lock)
    return {"socketPath": socket, "qemuPid": pid, "startTicks": ticks,
            "originalSid": sid, "baseCliSha256": pair["baseCliSha256"],
            "serverPort": live["serverPort"], "liveReceiptSha256": live["liveReceiptSha256"],
            "trustStore": trusted["paths"]["trustStore"],
            "trustStoreSha256": trusted["trustStoreSha256"]}


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


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Fail closed until protected one-shot dispatch/status/cleanup is reviewed."""
    request = _request(value)
    root = Path(root).resolve(strict=True)
    binding = _binding(root, request)
    _task_script(request, binding)
    raise WindowsFixtureOwnerNetworkError("OWNER_NETWORK_DISPATCH_UNAVAILABLE")


def verified_owner_jvm_receipt(root: Path | str, lease_id: str) -> dict[str, Any]:
    """Internal probe join; no static/request receipt can attest a JVM."""
    if not _canonical(lease_id):
        raise WindowsFixtureOwnerNetworkError("Owner network lease is invalid.")
    Path(root).resolve(strict=True)
    raise WindowsFixtureOwnerNetworkError("OWNER_JVM_RECEIPT_UNAVAILABLE")
