"""One-shot CP117 HTTPS fixture server and fresh owner/process receipt.

Static ready files and fixture events never establish a live server. The route
requires a private credential descriptor, signed interpreter inventory, exact
campaign lease role, and same-generation QGA process/listener observation.
"""
from __future__ import annotations

import base64
import ast
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid
from typing import Any, Mapping

from . import windows_cp117_lease as lease
from . import windows_msi_base_prepare as base
from . import windows_msi_public_scenario as public
from . import windows_update_fixture_stage as stage


class WindowsUpdateFixtureServerError(ValueError):
    pass


_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_WINDOWS_START = re.compile(r"windows:[1-9][0-9]*\Z")
_GROUP = ".rag_index/windows-update-fixture-server"
_CLEANUP_GROUP = ".rag_index/windows-update-fixture-server-cleanup"
_PYTHON_PATH = re.compile(
    r"C:\\(?:Program Files\\Python3[0-9]{2}\\|Users\\vpncp117\\AppData\\Local\\Programs\\Python\\Python3[0-9]{2}\\)python\.exe\Z",
    re.IGNORECASE)
_FIXTURE_ENTRYPOINT = "scripts/prepare_desktop_update_fixture.py"
_FIXTURE_SOURCE_LIMIT = 512 * 1024


def _canonical(value: Any) -> bool:
    return isinstance(value, str) and bool(_UUID.fullmatch(value)) and str(uuid.UUID(value)) == value


def _request(value: Mapping[str, Any]) -> dict[str, str]:
    fields = {"host", "leaseId", "stageCorrelationId", "serverCorrelationId", "sourceSha",
              "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"}
    if not isinstance(value, Mapping) or set(value) != fields or value.get("host") != "archlinux":
        raise WindowsUpdateFixtureServerError("Server start requires exact CP117 fields.")
    if not all(_canonical(value[name]) for name in ("leaseId", "stageCorrelationId", "serverCorrelationId")):
        raise WindowsUpdateFixtureServerError("Server campaign correlations are invalid.")
    if value["stageCorrelationId"] == value["serverCorrelationId"]:
        raise WindowsUpdateFixtureServerError("Server and stage correlations must differ.")
    for name, pattern in (("sourceSha", _SHA), ("fixtureReceiptArtifactId", _ARTIFACT),
                          ("baseMsiArtifactId", _ARTIFACT), ("targetMsiArtifactId", _ARTIFACT)):
        if not isinstance(value[name], str) or not pattern.fullmatch(value[name]):
            raise WindowsUpdateFixtureServerError("Invalid server " + name + ".")
    return dict(value)


def _intent_path(root: Path, correlation: str) -> Path:
    return root / _GROUP / (correlation + ".json")


def _read_intent(root: Path, correlation: str) -> dict[str, Any] | None:
    try: fd = os.open(_intent_path(root, correlation), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError: return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384):
            raise WindowsUpdateFixtureServerError("Server intent is unsafe.")
        try: value = json.load(stream)
        except (TypeError, ValueError) as error:
            raise WindowsUpdateFixtureServerError("Server intent is invalid.") from error
    if (not isinstance(value, dict) or not isinstance(value.get("request"), dict)
            or value["request"].get("serverCorrelationId") != correlation):
        raise WindowsUpdateFixtureServerError("Server intent is invalid.")
    return value


def _closed_server_history(root: Path, current_lease_id: str, *, group: str = _GROUP) -> None:
    """Admit archived intents only after exact local and remote campaign closure."""
    directory = root / group
    if not directory.exists():
        return
    config, target, _guest = base._descriptor(root)
    remote = base._campaign_remote(config, target)
    for path in directory.iterdir():
        if path.suffix != ".json":
            continue
        if not _canonical(path.stem):
            raise WindowsUpdateFixtureServerError("Server history is unknown.")
        if group == _GROUP:
            prior = _read_intent(root, path.stem)
        else:
            prior = _read_cleanup_intent(root, path.stem)
        prior_lease = prior.get("request", {}).get("leaseId") if prior else None
        if not _canonical(prior_lease):
            raise WindowsUpdateFixtureServerError("Server history is active or unknown.")
        if prior_lease == current_lease_id:
            # One failed CP117 server can be retried in the same campaign only
            # after its fixed successor has a durable cleanup receipt and a
            # fresh guest proof that task and process are both absent.
            if group == _GROUP:
                from . import windows_fixture_server_abort_successor as successor
                if successor.allows_server_restart(root, path.stem, current_lease_id, prior):
                    continue
            raise WindowsUpdateFixtureServerError("Server history is active or unknown.")
        campaign_directory, campaign_lock = lease._locked(root)
        try:
            closed = lease._closed(campaign_directory, prior_lease)
        finally:
            os.close(campaign_lock)
        if closed is None or not lease._remote_confirm(remote, "status", closed, None):
            raise WindowsUpdateFixtureServerError("Server history is active or unknown.")


def _reserve(root: Path, record: Mapping[str, Any]) -> None:
    """Fsync a private one-shot intent before any shared claim or guest action."""
    current_lease_id = record["request"]["leaseId"]
    _closed_server_history(root, current_lease_id)
    directory = root / _GROUP
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink()
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsUpdateFixtureServerError("Server journal is unsafe.")
    lock = os.open(directory / ".environment.lock", os.O_RDWR | os.O_CREAT |
                   getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(lock)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise WindowsUpdateFixtureServerError("Server journal lock is unsafe.")
        fcntl.flock(lock, fcntl.LOCK_EX)
        # A concurrent writer cannot bypass O_EXCL; a second campaign is still
        # admitted only after each prior lease has a remote-confirmed close.
        _closed_server_history(root, current_lease_id)
        raw = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(raw) > 16384:
            raise WindowsUpdateFixtureServerError("Server intent is too large.")
        path = _intent_path(root, record["request"]["serverCorrelationId"])
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(parent)
        finally: os.close(parent)
    finally:
        os.close(lock)


def _private_tls_descriptor(root: Path, request: Mapping[str, str]) -> Mapping[str, Any]:
    """Read the fixed provision route's private native credential receipt."""
    try:
        from . import windows_fixture_credentials as credentials
        value = credentials.verified_descriptor(root, request["leaseId"],
                                                request["stageCorrelationId"])
    except (ImportError, AttributeError) as error:
        raise WindowsUpdateFixtureServerError(
            "FIXTURE_SERVER_CREDENTIAL_DESCRIPTOR_UNAVAILABLE") from error
    base_path = (r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-credentials-"
                 + request["stageCorrelationId"])
    paths = {"directory": base_path, "certificate": base_path + r"\server-cert.pem",
             "privateKey": base_path + r"\server-key.pem",
             "trustStore": base_path + r"\fixture-trust.p12"}
    if (not isinstance(value, Mapping) or set(value) != {"provisionId", "paths",
            "certificateSha256", "privateKeySha256", "trustStoreSha256",
            "peerCertificateSha256"} or not _canonical(value["provisionId"])
            or value["paths"] != paths or any(not isinstance(value[key], str)
            or not _HASH.fullmatch(value[key]) for key in
            ("certificateSha256", "privateKeySha256", "trustStoreSha256",
             "peerCertificateSha256"))):
        raise WindowsUpdateFixtureServerError("Private fixture credentials changed.")
    return dict(value)


_PYTHON_PROBE = r'''$ErrorActionPreference='Stop';$sid=@SID@
$roots=@(('Registry::HKEY_USERS\'+$sid+'\Software\Python\PythonCore'),
         'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Python\PythonCore')
$seen=@{};$found=New-Object System.Collections.ArrayList
foreach($root in $roots){
 if(-not (Test-Path -LiteralPath $root)){continue}
 $versions=@(Get-ChildItem -LiteralPath $root -ErrorAction Stop)
 if($versions.Count -gt 8){throw 'REGISTRY_COUNT'}
 foreach($version in $versions){
  $install=Join-Path $version.PSPath 'InstallPath'
  if(-not (Test-Path -LiteralPath $install)){continue}
  $directory=(Get-Item -LiteralPath $install -ErrorAction Stop).GetValue('')
  if(-not [string]::IsNullOrWhiteSpace($directory)){
   $path=[IO.Path]::GetFullPath((Join-Path $directory 'python.exe'))
   if($seen.ContainsKey($path)){continue};$seen[$path]=$true
   if(-not (($path -like 'C:\Program Files\Python3*\python.exe') -or
           ($path -like 'C:\Users\vpncp117\AppData\Local\Programs\Python\Python3*\python.exe'))){continue}
   $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
   if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'INTERPRETER_REPARSE'}
   $ancestor=$item.Directory
   while($null -ne $ancestor){
    if(($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'ANCESTOR_REPARSE'}
    $ancestor=$ancestor.Parent
   }
   $signature=Get-AuthenticodeSignature -LiteralPath $path
   if($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or
      $signature.SignerCertificate.Subject -notmatch 'Python Software Foundation'){throw 'INTERPRETER_SIGNATURE'}
   $versionText=[Diagnostics.FileVersionInfo]::GetVersionInfo($path).ProductVersion
   $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
   [void]$found.Add([pscustomobject]@{path=$path;sha256=$hash;version=$versionText;
                               signer=$signature.SignerCertificate.Subject})
  }
 }
}
([pscustomobject]@{version=1;candidates=@($found)}|ConvertTo-Json -Depth 4 -Compress)
'''


_REMOTE_PYTHON = base._QGA + r'''sock,pid,ticks,encoded=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks):raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 for _ in range(60):
  result=call(sock,'guest-exec-status',{'pid':child})
  if result.get('exited') is True:break
  __import__('time').sleep(.2)
 else:raise ValueError()
 if result.get('exitcode')!=0 or result.get('out-truncated') is not False or result.get('err-truncated') is not False:raise ValueError()
 raw=base64.b64decode(result['out-data'],validate=True)
 if not 0<len(raw)<=8192:raise ValueError()
 out({'state':'observed','inventory':json.loads(decode(raw))})
except Exception:out({'state':'unknown'})
'''


_LIVE_OBSERVER = r'''$ErrorActionPreference='Stop'
$readyPath=@READY@;$taskName=@TASK@;$expectedSid=@SID@;$python=@PYTHON@
$cert=@CERT@;$key=@KEY@;$trust=@TRUST@;$expectedArguments=@ARGUMENTS@
$ready=Get-Content -LiteralPath $readyPath -Raw -Encoding UTF8|ConvertFrom-Json
if($null -eq $ready -or $ready.serverPid -le 0 -or $ready.port -le 0){throw 'READY'}
$task=Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction Stop
$action=@($task.Actions)
if($action.Count -ne 1 -or $task.State -ne 'Running' -or
   $task.Principal.UserId -cnotin @('VPNMSIX64\vpncp117',$expectedSid) -or
   $task.Principal.LogonType.ToString() -cne 'Interactive' -or
   $task.Principal.RunLevel.ToString() -cne 'Limited' -or
   $action[0].Execute -cne $python -or $action[0].Arguments -cne $expectedArguments){throw 'TASK'}
$process=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$ready.serverPid)
if($null -eq $process -or $process.ExecutablePath -cne $python -or
   $process.CommandLine -notlike ('*'+$expectedArguments)){throw 'PROCESS'}
$owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $expectedSid -or $process.SessionId -ne 1){throw 'OWNER'}
$native=Get-Process -Id ([int]$ready.serverPid) -ErrorAction Stop
$start='windows:'+$native.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
$listeners=@(Get-NetTCPConnection -State Listen -LocalAddress '127.0.0.1' -LocalPort ([int]$ready.port) -ErrorAction Stop)
if($listeners.Count -ne 1 -or $listeners[0].OwningProcess -ne [int]$ready.serverPid){throw 'LISTENER'}
function Hash([string]$path){return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
$sha=[Security.Cryptography.SHA256]::Create()
$commandHash=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($action[0].Arguments))).Replace('-','').ToLowerInvariant()
$sha.Dispose()
$observed=[pscustomobject]@{qgaSocketPath=@SOCKET@;qemuPid=@QEMU_PID@;qemuStartTicks=@QEMU_TICKS@;
 serverPid=[int]$ready.serverPid;serverProcessStartIdentity=$start;serverInstanceId=$ready.serverInstanceId;
 originalSid=$owner.Sid;sessionId=[int]$process.SessionId;limited=$true;
 listenerAddress='127.0.0.1';listenerPort=[int]$ready.port;listenerPid=[int]$listeners[0].OwningProcess;
 taskState=$task.State.ToString();pythonExeSha256=(Hash $python);launchCommandSha256=$commandHash;
 certificateSha256=(Hash $cert);privateKeySha256=(Hash $key);trustStoreSha256=(Hash $trust);
 credentialProvisionId=@PROVISION@}
([pscustomobject]@{schemaVersion=1;ready=$ready;observed=$observed}|ConvertTo-Json -Depth 12 -Compress)
'''


def _observer_script(request: Mapping[str, str], descriptor: Mapping[str, Any],
                     python: Mapping[str, str], guest: tuple[str, int, int, str],
                     launch_arguments: str) -> str:
    stage_root = (r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-fixture-"
                  + request["stageCorrelationId"])
    paths = descriptor["paths"]
    fields = {"READY": stage_root + r"\server-state\ready.json",
              "TASK": "VpnControlMcpFixtureServer-" + request["serverCorrelationId"],
              "SID": guest[3], "PYTHON": python["path"], "CERT": paths["certificate"],
              "KEY": paths["privateKey"], "TRUST": paths["trustStore"],
              "ARGUMENTS": launch_arguments, "SOCKET": guest[0],
              "QEMU_PID": str(guest[1]), "QEMU_TICKS": str(guest[2]),
              "PROVISION": descriptor["provisionId"]}
    script = _LIVE_OBSERVER
    for key, value in fields.items():
        script = script.replace("@" + key + "@", str(value) if key in {"QEMU_PID", "QEMU_TICKS"}
                                else public._ps_literal(value))
    if len(base64.b64encode(script.encode("utf-16le"))) >= 30000:
        raise WindowsUpdateFixtureServerError("Fixed observer command exceeds QGA limit.")
    return script


def _launch_arguments(request: Mapping[str, str], descriptor: Mapping[str, Any]) -> str:
    """The sole scheduled-task argument vector; paths are fixed private inventory."""
    root = (r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-fixture-"
            + request["stageCorrelationId"])
    content = root + r"\content"
    state = root + r"\server-state"
    paths = descriptor["paths"]
    credential_root = (r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-credentials-"
                       + request["stageCorrelationId"])
    if paths != {"directory": credential_root,
                 "certificate": credential_root + r"\server-cert.pem",
                 "privateKey": credential_root + r"\server-key.pem",
                 "trustStore": credential_root + r"\fixture-trust.p12"}:
        raise WindowsUpdateFixtureServerError("Fixture launch credentials escaped fixed paths.")
    return ('"' + content + r'\server\prepare_desktop_update_fixture.py" serve --directory "'
            + content + '" --certificate "' + paths["certificate"]
            + '" --private-key "' + paths["privateKey"]
            + '" --ready-file "' + state + r'\ready.json" --confirm-owned-disposable-guest')


_REMOTE_LIVE = base._QGA + r'''sock,pid,ticks,encoded=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks):raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 for _ in range(60):
  result=call(sock,'guest-exec-status',{'pid':child})
  if result.get('exited') is True:break
  __import__('time').sleep(.2)
 else:raise ValueError()
 if result.get('exitcode')!=0 or result.get('out-truncated') is not False or result.get('err-truncated') is not False:raise ValueError()
 raw=base64.b64decode(result['out-data'],validate=True)
 if not 0<len(raw)<=16384:raise ValueError()
 out({'state':'observed','result':json.loads(decode(raw))})
except Exception:out({'state':'unknown'})
'''


_LAUNCH = r'''$ErrorActionPreference='Stop'
$stage=@STAGE@;$state=@STATE@;$script=@SCRIPT@;$python=@PYTHON@
$cert=@CERT@;$key=@KEY@;$trust=@TRUST@;$taskName=@TASK@;$arguments=@ARGUMENTS@
if(-not [IO.Directory]::Exists($stage) -or -not [IO.Directory]::Exists($state) -or
   @(Get-ChildItem -LiteralPath $state -Force).Count -ne 0 -or
   $null -ne (Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue)){throw 'EXISTING_SERVER'}
function Check([string]$path,[string]$hash){
 $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
 if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hash){throw 'FILE_HASH'}
 $ancestor=$item.Directory
 while($null -ne $ancestor){
  if(($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'ANCESTOR_REPARSE'}
  $ancestor=$ancestor.Parent
 }
}
Check $script @SCRIPT_HASH@;Check $python @PYTHON_HASH@
Check $cert @CERT_HASH@;Check $key @KEY_HASH@;Check $trust @TRUST_HASH@
Check (Join-Path $stage 'fixture-receipt.json') @RECEIPT_HASH@
Check (Join-Path $stage @TARGET_NAME@) @TARGET_HASH@
$action=New-ScheduledTaskAction -Execute $python -Argument $arguments
$principal=New-ScheduledTaskPrincipal -UserId 'VPNMSIX64\vpncp117' -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 4) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskPath '\' -TaskName $taskName -Action $action -Principal $principal -Settings $settings|Out-Null
Start-ScheduledTask -TaskPath '\' -TaskName $taskName
'''


def _launch_script(request: Mapping[str, str], pair: Mapping[str, Any],
                   descriptor: Mapping[str, Any], python: Mapping[str, str],
                   script_hash: str, arguments: str) -> str:
    root = (r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-fixture-"
            + request["stageCorrelationId"])
    stage_path = root + r"\content"
    state_path = root + r"\server-state"
    paths = descriptor["paths"]
    fields = {"STAGE": stage_path, "STATE": state_path,
              "SCRIPT": stage_path + r"\server\prepare_desktop_update_fixture.py",
              "PYTHON": python["path"], "CERT": paths["certificate"],
              "KEY": paths["privateKey"], "TRUST": paths["trustStore"],
              "TASK": "VpnControlMcpFixtureServer-" + request["serverCorrelationId"],
              "ARGUMENTS": arguments, "SCRIPT_HASH": script_hash,
              "PYTHON_HASH": python["sha256"], "CERT_HASH": descriptor["certificateSha256"],
              "KEY_HASH": descriptor["privateKeySha256"],
              "TRUST_HASH": descriptor["trustStoreSha256"],
              "RECEIPT_HASH": request["fixtureReceiptArtifactId"].removeprefix("sha256-"),
              "TARGET_NAME": r"packages\target\vpn-control-" + pair["targetVersion"] + ".msi",
              "TARGET_HASH": pair["targetMsiSha256"]}
    script = _LAUNCH
    for key, value in fields.items():
        script = script.replace("@" + key + "@", public._ps_literal(value))
    if len(base64.b64encode(script.encode("utf-16le"))) >= 30000:
        raise WindowsUpdateFixtureServerError("Fixed launch command exceeds QGA limit.")
    return script


_PRIVATE_REMOTE_JSON = r'''
def save_private_json(path,value):
 raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
 if not 0<len(raw)<=16384:raise ValueError()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'wb') as file:
  info=os.fstat(file.fileno())
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError()
  file.write(raw);file.flush();os.fsync(file.fileno())
 parent=os.open(os.path.dirname(path),os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
 try:os.fsync(parent)
 finally:os.close(parent)
'''


_REMOTE_START = base._QGA + lease.remote_role_guard() + _PRIVATE_REMOTE_JSON + r'''import fcntl,uuid
root,env,lease_id,corr,stage_corr,sock,pid,ticks,sid,source,fingerprint,receipt_id,base_id,target_id,encoded,command_hash=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 if env!='windows-cp117' or not live(sock,pid,ticks):raise ValueError()
 require_campaign_role(root,env,lease_id,'server-start',corr,source,receipt_id,base_id,target_id,sock,pid,ticks)
 if hashlib.sha256(base64.b64decode(encoded,validate=True)).hexdigest()!=command_hash:raise ValueError()
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-update-fixture-server')
 for path in (root,parent,group):
  if not os.path.exists(path):os.mkdir(path,0o700)
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 lock=os.open(os.path.join(group,'.environment.lock'),os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
 try:
  fcntl.flock(lock,fcntl.LOCK_EX)
  for name in os.listdir(group):
   if name=='.environment.lock':continue
   old_job=os.path.join(group,name);info=os.lstat(old_job)
   if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
   binding_path=os.path.join(old_job,'binding.json');info=os.lstat(binding_path)
   if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>16384:raise ValueError()
   with open(binding_path,encoding='utf-8') as file:old=json.load(file)
   old_lease=old.get('leaseId')
   if old.get('serverCorrelationId')!=name or not isinstance(old_lease,str) or str(uuid.UUID(old_lease))!=old_lease:raise ValueError()
   if old_lease==lease_id:
    # CP117's one historical retry is allowed only when this exact server was
    # retired by its fixed successor.  Re-read the remote active campaign
    # under its lock: the local claim alone cannot manufacture this history.
    if name!='2c438d90-9a77-4acd-b4d7-ab354b85a04a':raise ValueError()
    fields={'leaseId','stageCorrelationId','serverCorrelationId','socketPath','qemuPid','startTicks','originalSid','sourceSha','sourceFingerprint','fixtureReceiptArtifactId','baseMsiArtifactId','targetMsiArtifactId','commandSha256','dispatchProtocol'}
    if set(old)!=fields or old.get('stageCorrelationId')==old.get('serverCorrelationId') or old.get('socketPath')!=sock or old.get('qemuPid')!=int(pid) or old.get('startTicks')!=int(ticks) or old.get('originalSid')!=sid or old.get('sourceSha')!=source or old.get('fixtureReceiptArtifactId')!=receipt_id or old.get('baseMsiArtifactId')!=base_id or old.get('targetMsiArtifactId')!=target_id or old.get('dispatchProtocol')!=2 or not all(isinstance(old.get(k),str) and re.fullmatch(r'[0-9a-f]{64}',old[k]) for k in ('sourceFingerprint','commandSha256')):raise ValueError()
    successor=os.path.join(old_job,'successor-bbc75e43-e220-44e8-ab60-ddc3876ba5fb');info=os.lstat(successor)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
    successor_binding=os.path.join(successor,'binding.json');info=os.lstat(successor_binding)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>4096:raise ValueError()
    with open(successor_binding,encoding='utf-8') as file:successor_record=json.load(file)
    expected_successor={'serverCorrelationId':'2c438d90-9a77-4acd-b4d7-ab354b85a04a','priorCleanupCorrelationId':'710f7aaa-f92d-4fef-9f7c-57cf6e405624','successorCleanupCorrelationId':'bbc75e43-e220-44e8-ab60-ddc3876ba5fb','socketPath':sock,'qemuPid':int(pid),'startTicks':int(ticks),'originalSid':sid}
    if successor_record!=expected_successor:raise ValueError()
    terminal_path=os.path.join(successor,'terminal.json');info=os.lstat(terminal_path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>1024:raise ValueError()
    with open(terminal_path,encoding='utf-8') as file:terminal=json.load(file)
    if set(terminal)!={'exitcode'} or type(terminal.get('exitcode')) is not int or not 0<=terminal['exitcode']<=65535:raise ValueError()
    evidence=hashlib.sha256(json.dumps({'request':{'successorCleanupCorrelationId':'bbc75e43-e220-44e8-ab60-ddc3876ba5fb'},'guest':[sock,int(pid),int(ticks),sid],'exitcode':terminal['exitcode']},sort_keys=True,separators=(',',':')).encode()).hexdigest()
    campaign=os.path.join(parent,'windows-cp117-campaign');info=os.lstat(campaign)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
    campaign_lock=os.open(os.path.join(campaign,'.environment.lock'),os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    try:
     info=os.fstat(campaign_lock)
     if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError()
     fcntl.flock(campaign_lock,fcntl.LOCK_SH)
     active_path=os.path.join(campaign,'active.json');info=os.lstat(active_path)
     if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>16384:raise ValueError()
     with open(active_path,encoding='utf-8') as file:active=json.load(file)
    finally:os.close(campaign_lock)
    identity={'host':'archlinux','environment':env,'leaseId':lease_id,'operator':'windows-base','sourceSha':source,'fixtureReceiptArtifactId':receipt_id,'baseMsiArtifactId':base_id,'targetMsiArtifactId':target_id,'socketPath':sock,'qemuPid':int(pid),'startTicks':int(ticks)}
    if set(active)!={'version','identity','sequence','state','role','correlationId','server','credentials','lastEvidenceSha256','lastOutcome'} or active.get('version')!=1 or type(active.get('sequence')) is not int or active['sequence']<=0 or active.get('identity')!=identity or active.get('state')!='role-active' or active.get('role')!='server-start' or active.get('correlationId')!=corr or active.get('server')!='starting' or active.get('credentials')!='ready' or active.get('lastOutcome')!='failed-cleaned' or active.get('lastEvidenceSha256')!=evidence:raise ValueError()
    continue
   closed_path=os.path.join(parent,'windows-cp117-campaign',old_lease+'.closed.json')
   info=os.lstat(closed_path)
   if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>16384:raise ValueError()
   with open(closed_path,encoding='utf-8') as file:closed=json.load(file)
   identity=closed.get('identity',{})
   if closed.get('state')!='closed' or closed.get('server')!='stopped' or closed.get('credentials')=='ready' or identity.get('leaseId')!=old_lease or identity.get('sourceSha')!=old.get('sourceSha') or identity.get('fixtureReceiptArtifactId')!=old.get('fixtureReceiptArtifactId') or identity.get('baseMsiArtifactId')!=old.get('baseMsiArtifactId') or identity.get('targetMsiArtifactId')!=old.get('targetMsiArtifactId') or identity.get('socketPath')!=old.get('socketPath') or identity.get('qemuPid')!=old.get('qemuPid') or identity.get('startTicks')!=old.get('startTicks'):raise ValueError()
  job=os.path.join(group,corr);os.mkdir(job,0o700)
  dispatch_lock=os.open(os.path.join(job,'.dispatch.lock'),os.O_RDWR|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  fcntl.flock(dispatch_lock,fcntl.LOCK_EX)
 finally:os.close(lock)
 try:
  binding={'leaseId':lease_id,'stageCorrelationId':stage_corr,'serverCorrelationId':corr,
   'socketPath':sock,'qemuPid':int(pid),'startTicks':int(ticks),'originalSid':sid,
   'sourceSha':source,'sourceFingerprint':fingerprint,'fixtureReceiptArtifactId':receipt_id,
   'baseMsiArtifactId':base_id,'targetMsiArtifactId':target_id,'commandSha256':command_hash,'dispatchProtocol':2}
  save_private_json(os.path.join(job,'binding.json'),binding)
  save_private_json(os.path.join(job,'guest-dispatch-intent.json'),{'commandSha256':command_hash})
  child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
  save_private_json(os.path.join(job,'dispatch.json'),{'pid':child})
 finally:os.close(dispatch_lock)
 out({'state':'submitted','serverCorrelationId':corr})
except Exception:out({'state':'unknown','serverCorrelationId':corr})
'''


def _python_candidates(root: Path, request: Mapping[str, str]) -> list[dict[str, str]]:
    """Return only signed interpreters from the two fixed CP117 locations.

    This remains a read-only QGA inspection.  In particular, the diagnostic
    caller cannot turn a registry value or an arbitrary guest path into an
    accepted interpreter identity.
    """
    _admit_campaign(root, request)
    config, _target, (_env, socket, pid, ticks, sid) = base._descriptor(root)
    program = _PYTHON_PROBE.replace("@SID@", public._ps_literal(sid))
    encoded = base64.b64encode(program.encode("utf-16le")).decode("ascii")
    raw = base._remote(config, _REMOTE_PYTHON, (socket, str(pid), str(ticks), encoded), None, 30)
    try: result = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError): result = None
    if not isinstance(result, dict) or set(result) != {"state", "inventory"} or result["state"] != "observed":
        raise WindowsUpdateFixtureServerError("CP117 Python interpreter inventory is unknown.")
    inventory = result["inventory"]
    candidates = inventory.get("candidates") if isinstance(inventory, dict) else None
    # `_PYTHON_PROBE` admits at most eight registry children in each of two
    # hives.  Preserve that finite bound here before exposing diagnostics.
    if (not isinstance(inventory, dict) or set(inventory) != {"version", "candidates"}
            or inventory["version"] != 1
            or not isinstance(candidates, list) or len(candidates) > 16):
        raise WindowsUpdateFixtureServerError("CP117 Python interpreter inventory is invalid.")
    validated: list[dict[str, str]] = []
    paths: set[str] = set()
    for candidate in candidates:
        if (not isinstance(candidate, dict) or set(candidate) != {"path", "sha256", "version", "signer"}
                or not isinstance(candidate["path"], str) or not _PYTHON_PATH.fullmatch(candidate["path"])
                or not isinstance(candidate["sha256"], str) or not _HASH.fullmatch(candidate["sha256"])
                or not isinstance(candidate["version"], str) or len(candidate["version"]) > 64
                or not re.fullmatch(r"3\.1[1-4](?:\.[0-9]+)?(?:[ .].*)?", candidate["version"])
                or not isinstance(candidate["signer"], str) or len(candidate["signer"]) > 256
                or "Python Software Foundation" not in candidate["signer"]):
            raise WindowsUpdateFixtureServerError("CP117 Python interpreter identity is invalid.")
        canonical_path = candidate["path"].casefold()
        if canonical_path in paths:
            raise WindowsUpdateFixtureServerError("CP117 Python interpreter inventory is invalid.")
        paths.add(canonical_path)
        validated.append(dict(candidate))
    return validated


def _python_inventory(root: Path, request: Mapping[str, str]) -> dict[str, str]:
    """Require exactly one signed fixed interpreter for a server launch."""
    candidates = _python_candidates(root, request)
    if len(candidates) != 1:
        raise WindowsUpdateFixtureServerError("CP117 Python interpreter is not unique.")
    candidate = candidates[0]
    return {"path": candidate["path"], "sha256": candidate["sha256"],
            "version": candidate["version"]}


def _python_candidate_identity(candidate: Mapping[str, str]) -> dict[str, str]:
    """Expose a bounded identity without returning a guest filesystem path."""
    path = candidate["path"].casefold()
    if path.startswith(r"c:\program files\python"):
        location = "program-files"
    elif path.startswith("c:\\users\\vpncp117\\appdata\\local\\programs\\python\\"):
        location = "owner-local"
    else:  # `_python_candidates` already rejects this; retain the fail-closed guard.
        raise WindowsUpdateFixtureServerError("CP117 Python interpreter identity is invalid.")
    return {"location": location, "pythonExeSha256": candidate["sha256"],
            "pythonVersion": candidate["version"], "signer": "python-software-foundation"}


def python_preflight(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only route for the Windows owner; no path or private material returned."""
    root = Path(root).resolve(strict=True)
    request = _request(value)
    inventory = _python_inventory(root, request)
    return {"state": "observed", "leaseId": request["leaseId"],
            "stageCorrelationId": request["stageCorrelationId"],
            "pythonExeSha256": inventory["sha256"], "pythonVersion": inventory["version"],
            "serverReady": False}


def python_inventory_diagnostic(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Classify the admitted signed interpreter set without selecting one.

    This diagnostic is deliberately separate from `python_preflight`: it
    reports an ambiguous inventory so an operator can investigate it, while
    server admission continues to require exactly one candidate.
    """
    root = Path(root).resolve(strict=True)
    request = _request(value)
    candidates = _python_candidates(root, request)
    identities = [_python_candidate_identity(candidate) for candidate in candidates]
    identities.sort(key=lambda item: (item["location"], item["pythonExeSha256"]))
    return {"state": "observed", "leaseId": request["leaseId"],
            "stageCorrelationId": request["stageCorrelationId"],
            "serverCorrelationId": request["serverCorrelationId"],
            "candidateCount": len(identities), "candidates": identities,
            "serverReady": False}


def _admit_campaign(root: Path, request: Mapping[str, str], *,
                    require_credentials: bool = False) -> tuple[dict[str, Any], tuple[Any, ...]]:
    pair = public._admit_pair(root, request["sourceSha"], request["fixtureReceiptArtifactId"],
                              request["baseMsiArtifactId"], request["targetMsiArtifactId"])
    _, _, guest = base._descriptor(root)
    environment, socket, pid, ticks, sid = guest
    if environment != "windows-cp117":
        raise WindowsUpdateFixtureServerError("Owned guest generation changed.")
    observed = lease.inspect(root, request["leaseId"])
    if (observed.get("state") != "active" or observed.get("server") != "stopped"
            or observed.get("role") is not None):
        raise WindowsUpdateFixtureServerError("CP117 campaign is not ready for server start.")
    staged = stage.status(root, {"correlationId": request["stageCorrelationId"]})
    if (staged.get("state") != "staged-not-server-ready" or staged.get("sourceSha") != request["sourceSha"]
            or staged.get("targetMsiSha256") != pair["targetMsiSha256"]):
        raise WindowsUpdateFixtureServerError("Exact stage is not admitted.")
    directory, lock = lease._locked(root)
    try:
        current = lease._active(directory)
        identity = current.get("identity") if isinstance(current, dict) else None
        expected = {"host": "archlinux", "environment": "windows-cp117",
                    "leaseId": request["leaseId"], "operator": "windows-base",
                    "sourceSha": request["sourceSha"],
                    "fixtureReceiptArtifactId": request["fixtureReceiptArtifactId"],
                    "baseMsiArtifactId": request["baseMsiArtifactId"],
                    "targetMsiArtifactId": request["targetMsiArtifactId"],
                    "socketPath": socket, "qemuPid": pid, "startTicks": ticks}
        if identity != expected or (require_credentials and current.get("credentials") != "ready"):
            raise WindowsUpdateFixtureServerError("CP117 campaign identity changed.")
    finally:
        os.close(lock)
    return pair, (socket, pid, ticks, sid)


def _frozen_fixture_source(root: Path, source_sha: str) -> bytes | None:
    """Return one bounded immutable entrypoint blob, never the worktree copy."""
    try:
        process = subprocess.Popen(
            ["git", "show", source_sha + ":" + _FIXTURE_ENTRYPOINT],
            cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        if process.stdout is None:
            return None
        source = process.stdout.read(_FIXTURE_SOURCE_LIMIT + 1)
        if len(source) > _FIXTURE_SOURCE_LIMIT:
            process.kill()
            process.wait(timeout=5)
            return None
        returncode = process.wait(timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    finally:
        if "process" in locals() and process.stdout is not None:
            process.stdout.close()
    if returncode != 0 or not isinstance(source, bytes) or not 0 < len(source) <= _FIXTURE_SOURCE_LIMIT:
        return None
    return source


def _has_windows_safe_probe_events_mkdir(source: bytes) -> bool:
    """Accept only the source branch covered for Windows ACL-safe probe events."""
    try:
        module = ast.parse(source.decode("utf-8"), filename=_FIXTURE_ENTRYPOINT)
    except (UnicodeDecodeError, SyntaxError):
        return False
    functions = [node for node in module.body
                 if isinstance(node, ast.FunctionDef) and node.name == "probe_events_path"]
    if len(functions) != 1:
        return False

    def events_mkdir(node: ast.AST) -> ast.IfExp | None:
        if not isinstance(node, ast.Call) or node.args or len(node.keywords) != 1:
            return None
        if (not isinstance(node.func, ast.Attribute) or node.func.attr != "mkdir"
                or not isinstance(node.func.value, ast.Name) or node.func.value.id != "events"):
            return None
        keyword = node.keywords[0]
        return keyword.value if keyword.arg == "mode" and isinstance(keyword.value, ast.IfExp) else None

    function = functions[0]
    mkdir_calls = [node for node in ast.walk(function) if events_mkdir(node) is not None]
    if len(mkdir_calls) != 1:
        return False
    tries = [(index, node) for index, node in enumerate(function.body) if isinstance(node, ast.Try)]
    if len(tries) != 1:
        return False
    try_index, protected = tries[0]
    direct_mkdirs = [statement.value for statement in protected.body
                     if isinstance(statement, ast.Expr) and events_mkdir(statement.value) is not None]
    if (len(direct_mkdirs) != 1 or direct_mkdirs[0] is not mkdir_calls[0]
            or len(protected.handlers) != 1 or protected.orelse or protected.finalbody):
        return False
    handler = protected.handlers[0]
    if (not isinstance(handler.type, ast.Name) or handler.type.id != "FileExistsError"
            or len(handler.body) != 1 or not isinstance(handler.body[0], ast.Pass)):
        return False

    def windows_acl_verifier(node: ast.AST) -> bool:
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            return False
        if node.func.id != "require_windows_private_acl" or len(node.args) != 1:
            return False
        if not isinstance(node.args[0], ast.Name) or node.args[0].id != "events":
            return False
        keywords = {keyword.arg: keyword.value for keyword in node.keywords}
        return (set(keywords) == {"private", "directory"}
                and all(isinstance(keywords[key], ast.Constant) and keywords[key].value is True
                        for key in keywords))

    def windows_guard(node: ast.AST) -> bool:
        return (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                and len(node.test.ops) == len(node.test.comparators) == 1
                and isinstance(node.test.ops[0], ast.Eq) and isinstance(node.test.left, ast.Call)
                and not node.test.left.args and not node.test.left.keywords
                and isinstance(node.test.left.func, ast.Attribute) and node.test.left.func.attr == "system"
                and isinstance(node.test.left.func.value, ast.Name) and node.test.left.func.value.id == "platform"
                and isinstance(node.test.comparators[0], ast.Constant)
                and node.test.comparators[0].value == "Windows")

    if not any(windows_guard(node) and any(windows_acl_verifier(child) for child in ast.walk(node))
                   for node in function.body[try_index + 1:]):
        return False
    branch = events_mkdir(mkdir_calls[0])
    if branch is None:
        return False
    test = branch.test
    is_windows = (
        isinstance(test, ast.Compare) and len(test.ops) == len(test.comparators) == 1
        and isinstance(test.ops[0], ast.Eq) and isinstance(test.left, ast.Attribute)
        and isinstance(test.left.value, ast.Name) and test.left.value.id == "os"
        and test.left.attr == "name"
        and isinstance(test.comparators[0], ast.Constant) and test.comparators[0].value == "nt"
    )
    return (is_windows and isinstance(branch.body, ast.Constant) and branch.body.value == 0o777
            and isinstance(branch.orelse, ast.Constant) and branch.orelse.value == 0o700)


def acl_preflight(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only source/stage ACL gate for one exact server-start request."""
    root = Path(root).resolve(strict=True)
    request = _request(value)
    result = {"sourceSha": request["sourceSha"],
              "stageCorrelationId": request["stageCorrelationId"], "serverReady": False,
              "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
    try:
        staged = stage.status(root, {"correlationId": request["stageCorrelationId"]})
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return {"state": "unknown", **result}
    if not isinstance(staged, Mapping):
        return {"state": "unknown", **result}
    script_hash = staged.get("fileHashes", {}).get("server/prepare_desktop_update_fixture.py")
    if (staged.get("state") != "staged-not-server-ready"
            or staged.get("sourceSha") != request["sourceSha"]):
        return {"state": "unknown", **result}
    if not isinstance(script_hash, str) or not _HASH.fullmatch(script_hash):
        return {"state": "unknown", **result}
    source = _frozen_fixture_source(root, request["sourceSha"])
    if source is None:
        return {"state": "unknown", **result}
    if hashlib.sha256(source).hexdigest() != script_hash:
        return {"state": "blocked", **result}
    if not _has_windows_safe_probe_events_mkdir(source):
        return {"state": "blocked", **result}
    return {"state": "ready", **result}


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """One-shot limited-owner launch after credentials, stage, and lease admission."""
    root = Path(root).resolve(strict=True); request = _request(value)
    correlation = request["serverCorrelationId"]
    prior = _read_intent(root, correlation)
    if prior is not None:
        if prior.get("request") != request:
            raise WindowsUpdateFixtureServerError("Server correlation binds another request.")
        return {"state": "unknown", "serverCorrelationId": correlation,
                "cleanupRequired": True, "replayAllowed": False}
    python = _python_inventory(root, request)
    descriptor = _private_tls_descriptor(root, request)
    if acl_preflight(root, request).get("state") != "ready":
        raise WindowsUpdateFixtureServerError("Exact source ACL preflight is not ready.")
    pair, guest = _admit_campaign(root, request, require_credentials=True)
    staged = stage.status(root, {"correlationId": request["stageCorrelationId"]})
    script_hash = staged.get("fileHashes", {}).get("server/prepare_desktop_update_fixture.py")
    if not isinstance(script_hash, str) or not _HASH.fullmatch(script_hash):
        raise WindowsUpdateFixtureServerError("Exact-source staged server script is unavailable.")
    arguments = _launch_arguments(request, descriptor)
    script = _launch_script(request, pair, descriptor, python, script_hash, arguments)
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    command_hash = hashlib.sha256(script.encode("utf-16le")).hexdigest()
    config, target, (env, socket, pid, ticks, sid) = base._descriptor(root)
    if guest != (socket, pid, ticks, sid):
        raise WindowsUpdateFixtureServerError("Owned guest generation changed.")
    record = {"schemaVersion": 1, "request": request, "environment": env,
              "socketPath": socket, "qemuPid": pid, "startTicks": ticks,
              "originalSid": sid, "sourceFingerprint": pair["sourceFingerprint"],
              "targetMsiSha256": pair["targetMsiSha256"], "targetMsiSize": pair["targetMsiSize"],
              "credentialProvisionId": descriptor["provisionId"],
              "peerCertificateSha256": descriptor["peerCertificateSha256"],
              "certificateSha256": descriptor["certificateSha256"],
              "privateKeySha256": descriptor["privateKeySha256"],
              "trustStoreSha256": descriptor["trustStoreSha256"],
              "pythonPath": python["path"], "pythonExeSha256": python["sha256"],
              "pythonVersion": python["version"],
              "launchArgumentsSha256": hashlib.sha256(arguments.encode()).hexdigest(),
              "commandSha256": command_hash}
    _reserve(root, record)
    remote = base._campaign_remote(config, target)
    claimed = lease.claim_role(root, request["leaseId"], "server-start", correlation, remote)
    if claimed.get("state") != "role-active":
        return {"state": "unknown", "serverCorrelationId": correlation,
                "cleanupRequired": True, "replayAllowed": False}
    raw = base._remote(config, _REMOTE_START,
        (str(target.fixture_transfer_root), env, request["leaseId"], correlation,
         request["stageCorrelationId"], socket, str(pid), str(ticks), sid,
         request["sourceSha"], pair["sourceFingerprint"],
         request["fixtureReceiptArtifactId"], request["baseMsiArtifactId"],
         request["targetMsiArtifactId"], encoded, command_hash), None, 120)
    try: observed = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError): observed = None
    if observed != {"state": "submitted", "serverCorrelationId": correlation}:
        return {"state": "unknown", "serverCorrelationId": correlation,
                "cleanupRequired": True, "replayAllowed": False}
    return {"state": "submitted", "serverCorrelationId": correlation,
            "cleanupRequired": True, "replayAllowed": False}


def _fixture_manifest(root: Path, request: Mapping[str, str]) -> dict[str, Any]:
    path = public._verified_location(root, request["fixtureReceiptArtifactId"],
                                     "fixture-receipt", request["sourceSha"])
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 1024 * 1024:
            raise WindowsUpdateFixtureServerError("Fixture receipt is unsafe.")
        raw = stream.read(1024 * 1024 + 1)
    if hashlib.sha256(raw).hexdigest() != request["fixtureReceiptArtifactId"].removeprefix("sha256-"):
        raise WindowsUpdateFixtureServerError("Fixture receipt changed.")
    try: receipt = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise WindowsUpdateFixtureServerError("Fixture receipt is invalid.") from error
    manifest = receipt.get("manifest") if isinstance(receipt, dict) else None
    if not isinstance(manifest, dict):
        raise WindowsUpdateFixtureServerError("Fixture manifest is invalid.")
    return manifest


def _validate_live_ready(ready: Mapping[str, Any], observed: Mapping[str, Any], *,
                         request: Mapping[str, str], pair: Mapping[str, Any],
                         manifest: Mapping[str, Any], descriptor: Mapping[str, Any],
                         guest: tuple[str, int, int, str]) -> dict[str, Any]:
    """Require a fresh kernel/QGA observation; ready.json alone is never proof."""
    socket, qemu_pid, qemu_ticks, sid = guest
    ready_fields = {"port", "serverInstanceId", "serverPid", "serverProcessStartIdentity",
                    "sourceFingerprint", "fixtureReceiptSha256", "manifestSha256",
                    "peerCertificateSha256", "manifest"}
    if not isinstance(ready, Mapping) or set(ready) != ready_fields:
        raise WindowsUpdateFixtureServerError("Server ready receipt shape changed.")
    if (not _canonical(ready["serverInstanceId"]) or type(ready["port"]) is not int
            or not 1 <= ready["port"] <= 65535 or type(ready["serverPid"]) is not int
            or ready["serverPid"] <= 0 or not isinstance(ready["serverProcessStartIdentity"], str)
            or not _WINDOWS_START.fullmatch(ready["serverProcessStartIdentity"])):
        raise WindowsUpdateFixtureServerError("Server ready generation is invalid.")
    body = json.dumps(manifest, separators=(",", ":")).encode()
    if (ready["sourceFingerprint"] != pair["sourceFingerprint"]
            or ready["fixtureReceiptSha256"] != request["fixtureReceiptArtifactId"].removeprefix("sha256-")
            or ready["manifest"] != manifest
            or ready["manifestSha256"] != hashlib.sha256(body).hexdigest()
            or ready["peerCertificateSha256"] != descriptor.get("peerCertificateSha256")):
        raise WindowsUpdateFixtureServerError("Server manifest or certificate binding changed.")
    if type(manifest.get("buildNumber")) is not int or manifest["buildNumber"] <= 0:
        raise WindowsUpdateFixtureServerError("Server manifest build number is invalid.")
    target_assets = [asset for asset in manifest.get("assets", []) if isinstance(asset, dict)
                     and asset.get("platform") == "windows" and asset.get("architecture") == "x86_64"
                     and asset.get("fileName") == "vpn-control-" + pair["targetVersion"] + ".msi"]
    if (len(target_assets) != 1 or target_assets[0].get("sha256") != pair["targetMsiSha256"]
            or target_assets[0].get("sizeBytes") != pair["targetMsiSize"]
            or target_assets[0].get("displayVersion") != pair["targetVersion"]):
        raise WindowsUpdateFixtureServerError("Server manifest target changed.")
    expected_observation = {"qgaSocketPath": socket, "qemuPid": qemu_pid, "qemuStartTicks": qemu_ticks,
        "serverPid": ready["serverPid"], "serverProcessStartIdentity": ready["serverProcessStartIdentity"],
        "serverInstanceId": ready["serverInstanceId"], "originalSid": sid, "sessionId": 1,
        "limited": True, "listenerAddress": "127.0.0.1", "listenerPort": ready["port"],
        "listenerPid": ready["serverPid"], "taskState": "Running",
        "pythonExeSha256": descriptor.get("pythonExeSha256"),
        "launchCommandSha256": descriptor.get("launchCommandSha256"),
        "certificateSha256": descriptor.get("certificateSha256"),
        "privateKeySha256": descriptor.get("privateKeySha256"),
        "trustStoreSha256": descriptor.get("trustStoreSha256"),
        "credentialProvisionId": descriptor.get("provisionId")}
    if not isinstance(observed, Mapping) or dict(observed) != expected_observation:
        raise WindowsUpdateFixtureServerError("Live server process observation changed.")
    if any(not isinstance(descriptor.get(key), str) or not _HASH.fullmatch(descriptor[key])
           for key in ("pythonExeSha256", "launchCommandSha256", "certificateSha256",
                       "peerCertificateSha256", "privateKeySha256", "trustStoreSha256")):
        raise WindowsUpdateFixtureServerError("Private server descriptor is incomplete.")
    return {"state": "live", "serverInstanceId": ready["serverInstanceId"],
            "serverPid": ready["serverPid"], "serverProcessStartIdentity": ready["serverProcessStartIdentity"],
            "serverPort": ready["port"],
            "manifestSha256": ready["manifestSha256"],
            "peerCertificateSha256": ready["peerCertificateSha256"],
            "targetVersion": pair["targetVersion"], "manifestBuildNumber": manifest.get("buildNumber"),
            "targetMsiSha256": pair["targetMsiSha256"], "targetMsiSize": pair["targetMsiSize"],
            "serverReady": True, "cleanupRequired": True, "replayAllowed": False}


def _validate_probe_event(event: Mapping[str, Any], probe: Mapping[str, Any],
                          live: Mapping[str, Any], *, probe_correlation_id: str,
                          manifest_bytes: int) -> dict[str, Any]:
    if not _canonical(probe_correlation_id) or not isinstance(event, Mapping) or not isinstance(probe, Mapping):
        raise WindowsUpdateFixtureServerError("Probe correlation is invalid.")
    if (set(event) != {"schemaVersion", "correlationId", "serverInstanceId", "connectAccepted",
                       "tlsSucceeded", "exactManifestGet", "manifestSha256", "peerCertificateSha256", "servedBytes"}
            or event["schemaVersion"] != 1 or event["correlationId"] != probe_correlation_id
            or event["serverInstanceId"] != live["serverInstanceId"]
            or event["connectAccepted"] is not True or event["tlsSucceeded"] is not True
            or event["exactManifestGet"] is not True or event["manifestSha256"] != live["manifestSha256"]
            or event["peerCertificateSha256"] != live["peerCertificateSha256"]
            or type(event["servedBytes"]) is not int or event["servedBytes"] != manifest_bytes):
        raise WindowsUpdateFixtureServerError("Fixture probe event is stale or forged.")
    fields = {"correlationId", "manifestSha256", "peerCertificateSha256", "manifestBuildNumber", "availableVersion",
              "assetSha256", "assetSizeBytes"}
    if (set(probe) != fields or probe["correlationId"] != probe_correlation_id
            or probe["manifestSha256"] != live["manifestSha256"]
            or probe["peerCertificateSha256"] != live["peerCertificateSha256"]
            or probe["manifestBuildNumber"] != live["manifestBuildNumber"]
            or probe["availableVersion"] != live["targetVersion"]
            or probe["assetSha256"] != live["targetMsiSha256"]
            or probe["assetSizeBytes"] != live["targetMsiSize"]):
        raise WindowsUpdateFixtureServerError("Public probe disagrees with live fixture.")
    return {"state": "correlated", "probeCorrelationId": probe_correlation_id,
            "serverInstanceId": live["serverInstanceId"],
            "manifestSha256": live["manifestSha256"], "targetMsiSha256": live["targetMsiSha256"],
            "cleanupRequired": True, "replayAllowed": False}


def _live_receipt(request: Mapping[str, str], pair: Mapping[str, Any],
                  ready: Mapping[str, Any], observed: Mapping[str, Any],
                  manifest: Mapping[str, Any], descriptor: Mapping[str, Any],
                  guest: tuple[str, int, int, str]) -> dict[str, Any]:
    """Derive the internal target/public join receipt from fresh QGA observations."""
    live = _validate_live_ready(ready, observed, request=request, pair=pair,
                                manifest=manifest, descriptor=descriptor, guest=guest)
    socket, pid, ticks, _sid = guest
    value = {"leaseId": request["leaseId"], "sourceSha": request["sourceSha"],
             "fixtureReceiptArtifactId": request["fixtureReceiptArtifactId"],
             "baseMsiArtifactId": request["baseMsiArtifactId"],
             "targetMsiArtifactId": request["targetMsiArtifactId"],
             "stageCorrelationId": request["stageCorrelationId"],
             "serverCorrelationId": request["serverCorrelationId"],
             "socketPath": socket, "qemuPid": pid, "startTicks": ticks,
             "serverInstanceId": live["serverInstanceId"], "serverPid": live["serverPid"],
             "serverProcessStartIdentity": live["serverProcessStartIdentity"],
             "serverPort": live["serverPort"],
             "manifestSha256": live["manifestSha256"],
             "manifestBuildNumber": live["manifestBuildNumber"],
             "targetVersion": live["targetVersion"],
             "peerCertificateSha256": live["peerCertificateSha256"],
             "targetMsiSha256": live["targetMsiSha256"],
             "targetMsiSize": live["targetMsiSize"], "serverReady": True}
    value["liveReceiptSha256"] = hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return value


def _live_path(root: Path, correlation: str) -> Path:
    return root / _GROUP / (correlation + ".live")


def _read_live_snapshot(root: Path, correlation: str) -> dict[str, Any] | None:
    try: fd = os.open(_live_path(root, correlation), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError: return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384):
            raise WindowsUpdateFixtureServerError("Server live snapshot is unsafe.")
        value = json.load(stream)
    if not isinstance(value, dict):
        raise WindowsUpdateFixtureServerError("Server live snapshot is invalid.")
    digest = value.get("liveReceiptSha256")
    body = {key: item for key, item in value.items() if key != "liveReceiptSha256"}
    if (not isinstance(digest, str) or not _HASH.fullmatch(digest)
            or hashlib.sha256(json.dumps(body, sort_keys=True,
                    separators=(",", ":")).encode()).hexdigest() != digest):
        raise WindowsUpdateFixtureServerError("Server live snapshot changed.")
    return value


def _save_live_snapshot(root: Path, correlation: str, receipt: Mapping[str, Any]) -> None:
    prior = _read_live_snapshot(root, correlation)
    if prior is not None:
        if prior != receipt:
            raise WindowsUpdateFixtureServerError("Server live generation changed.")
        return
    path = _live_path(root, correlation)
    raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(raw) > 16384:
        raise WindowsUpdateFixtureServerError("Server live snapshot is too large.")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try: os.fsync(parent)
    finally: os.close(parent)


def _verified_stopped_live_snapshot(root: Path, request: Mapping[str, str]) -> dict[str, Any]:
    """Historic live identity permits cleanup only after lease and guest readback."""
    receipt = _read_live_snapshot(root, request["serverCorrelationId"])
    if receipt is None:
        raise WindowsUpdateFixtureServerError("SERVER_STOP_LIVE_SNAPSHOT_UNAVAILABLE")
    expected = {"leaseId": request["leaseId"], "sourceSha": request["sourceSha"],
                "fixtureReceiptArtifactId": request["fixtureReceiptArtifactId"],
                "baseMsiArtifactId": request["baseMsiArtifactId"],
                "targetMsiArtifactId": request["targetMsiArtifactId"],
                "stageCorrelationId": request["stageCorrelationId"],
                "serverCorrelationId": request["serverCorrelationId"], "serverReady": True}
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise WindowsUpdateFixtureServerError("Server stop live snapshot changed.")
    if (type(receipt.get("serverPid")) is not int or receipt["serverPid"] <= 0
            or not isinstance(receipt.get("serverProcessStartIdentity"), str)
            or not _WINDOWS_START.fullmatch(receipt["serverProcessStartIdentity"])
            or type(receipt.get("serverPort")) is not int or not 1 <= receipt["serverPort"] <= 65535):
        raise WindowsUpdateFixtureServerError("Server stop native generation is invalid.")
    config, target, descriptor = base._descriptor(root)
    env, socket, pid, ticks, _sid = descriptor
    if env != "windows-cp117" or any(receipt.get(key) != value for key, value in
       (("socketPath", socket), ("qemuPid", pid), ("startTicks", ticks))):
        raise WindowsUpdateFixtureServerError("Server stop guest generation changed.")
    pair = public._admit_pair(root, request["sourceSha"], request["fixtureReceiptArtifactId"],
                              request["baseMsiArtifactId"], request["targetMsiArtifactId"])
    if (receipt.get("targetMsiSha256") != pair["targetMsiSha256"]
            or receipt.get("targetMsiSize") != pair["targetMsiSize"]
            or receipt.get("targetVersion") != pair["targetVersion"]):
        raise WindowsUpdateFixtureServerError("Server stop fixture pair changed.")
    directory, lock = lease._locked(root)
    try:
        current = lease._active(directory)
        identity = base._campaign_identity({**request, "correlationId": request["leaseId"]}, descriptor)
        if (current is None or current["identity"] != identity or current["state"] != "active"
                or current["role"] is not None or current["server"] != "live"
                or current["credentials"] != "ready"
                or not lease._remote_confirm(base._campaign_remote(config, target), "status", current, None)):
            raise WindowsUpdateFixtureServerError("Server stop campaign changed.")
    finally: os.close(lock)
    return receipt


def _observe_live(root: Path, request: Mapping[str, str], pair: Mapping[str, Any],
                  descriptor: Mapping[str, Any], python: Mapping[str, str],
                  guest: tuple[str, int, int, str], launch_arguments: str) -> dict[str, Any]:
    """Read one live generation through the fixed QGA/SSH route."""
    config, _target, current = base._descriptor(root)
    if current != ("windows-cp117", *guest):
        raise WindowsUpdateFixtureServerError("Owned guest generation changed.")
    script = _observer_script(request, descriptor, python, guest, launch_arguments)
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    raw = base._remote(config, _REMOTE_LIVE, (guest[0], str(guest[1]), str(guest[2]), encoded),
                       None, 30)
    try: value = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError): value = None
    result = value.get("result") if isinstance(value, dict) and value.get("state") == "observed" else None
    if (not isinstance(result, dict) or set(result) != {"schemaVersion", "ready", "observed"}
            or result["schemaVersion"] != 1):
        raise WindowsUpdateFixtureServerError("Live fixture QGA observation is unknown.")
    manifest = _fixture_manifest(root, request)
    merged = {**descriptor, "pythonExeSha256": python["sha256"],
              "launchCommandSha256": hashlib.sha256(launch_arguments.encode()).hexdigest()}
    return _live_receipt(request, pair, result["ready"], result["observed"],
                         manifest, merged, guest)


def _live_from_intent(root: Path, intent: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any], Any, Any]:
    request = _request(intent["request"])
    config, target, guest_descriptor = base._descriptor(root)
    env, socket, pid, ticks, sid = guest_descriptor
    guest = (socket, pid, ticks, sid)
    if (env != "windows-cp117" or intent.get("environment") != env
            or any(intent.get(key) != observed for key, observed in
                   (("socketPath", socket), ("qemuPid", pid), ("startTicks", ticks),
                    ("originalSid", sid)))):
        raise WindowsUpdateFixtureServerError("Owned server guest generation changed.")
    pair = public._admit_pair(root, request["sourceSha"], request["fixtureReceiptArtifactId"],
                              request["baseMsiArtifactId"], request["targetMsiArtifactId"])
    if (intent.get("sourceFingerprint") != pair["sourceFingerprint"]
            or intent.get("targetMsiSha256") != pair["targetMsiSha256"]
            or intent.get("targetMsiSize") != pair["targetMsiSize"]):
        raise WindowsUpdateFixtureServerError("Exact server MSI fixture changed.")
    staged = stage.status(root, {"correlationId": request["stageCorrelationId"]})
    if staged.get("state") != "staged-not-server-ready":
        raise WindowsUpdateFixtureServerError("Exact server stage changed.")
    descriptor = _private_tls_descriptor(root, request)
    if (intent.get("credentialProvisionId") != descriptor["provisionId"]
            or any(intent.get(key) != descriptor[key] for key in
                   ("peerCertificateSha256", "certificateSha256", "privateKeySha256",
                    "trustStoreSha256"))):
        raise WindowsUpdateFixtureServerError("Server credentials changed.")
    python = {"path": intent.get("pythonPath"), "sha256": intent.get("pythonExeSha256"),
              "version": intent.get("pythonVersion")}
    if (not isinstance(python["path"], str) or not _PYTHON_PATH.fullmatch(python["path"])
            or not isinstance(python["sha256"], str) or not _HASH.fullmatch(python["sha256"])):
        raise WindowsUpdateFixtureServerError("Server interpreter changed.")
    arguments = _launch_arguments(request, descriptor)
    if hashlib.sha256(arguments.encode()).hexdigest() != intent.get("launchArgumentsSha256"):
        raise WindowsUpdateFixtureServerError("Server launch command changed.")
    directory, lock = lease._locked(root)
    try:
        current = lease._active(directory)
        identity = current.get("identity") if isinstance(current, dict) else None
        expected = base._campaign_identity({**request, "correlationId": request["leaseId"]},
                                           guest_descriptor)
        if (identity != expected or current.get("credentials") != "ready"
                or not ((current.get("state") == "role-active" and
                         current.get("role") == "server-start" and
                         current.get("correlationId") == request["serverCorrelationId"] and
                         current.get("server") == "starting") or
                        (current.get("server") == "live" and
                         ((current.get("state") == "active" and current.get("role") is None) or
                          (current.get("state") == "role-active" and current.get("role") in
                           {"target", "public", "network-probe", "server-stop"}))))):
            raise WindowsUpdateFixtureServerError("Server campaign phase changed.")
        if not lease._remote_confirm(base._campaign_remote(config, target), "status", current, None):
            raise WindowsUpdateFixtureServerError("Remote server campaign is unknown.")
    finally:
        os.close(lock)
    receipt = _observe_live(root, request, pair, descriptor, python, guest, arguments)
    return receipt, current, config, target


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"serverCorrelationId"} or not _canonical(value["serverCorrelationId"]):
        raise WindowsUpdateFixtureServerError("Server status requires exact correlation.")
    root = Path(root).resolve(strict=True); correlation = value["serverCorrelationId"]
    intent = _read_intent(root, correlation)
    unknown = {"state": "unknown", "serverCorrelationId": correlation,
               "cleanupRequired": intent is not None, "replayAllowed": False}
    if intent is None:
        return unknown
    try:
        receipt, current, config, target = _live_from_intent(root, intent)
        _save_live_snapshot(root, correlation, receipt)
        if current["state"] == "role-active" and current["role"] == "server-start":
            completed = lease.finish_role(root, intent["request"]["leaseId"], "server-start",
                                          correlation, receipt["liveReceiptSha256"], "succeeded",
                                          base._campaign_remote(config, target))
            if completed.get("state") != "active":
                return unknown
        return {"state": "live", "serverCorrelationId": correlation,
                "serverInstanceId": receipt["serverInstanceId"],
                "serverPid": receipt["serverPid"],
                "serverProcessStartIdentity": receipt["serverProcessStartIdentity"],
                "manifestSha256": receipt["manifestSha256"],
                "peerCertificateSha256": receipt["peerCertificateSha256"],
                "targetMsiSha256": receipt["targetMsiSha256"],
                "liveReceiptSha256": receipt["liveReceiptSha256"],
                "cleanupRequired": True, "replayAllowed": False}
    except (OSError, ValueError, KeyError, TypeError):
        return unknown


def collect(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Live process collection; public probe correlation is a separate gate."""
    return status(root, value)


_SERVER_DIAG_PS = r'''$ErrorActionPreference='Stop';$name=@TASK@;$sid=@SID@;$python=@PYTHON@;$readyPath=@READY@;$stage=@STAGE@;$state=@STATE@
$out=@{version=1;task='absent';lastResult='unknown';ready='absent';stateContent='unknown';stageAcl='unknown';stateAcl='unknown'}
function AclClass([string]$path,[string]$recipient,[bool]$private){try{$acl=Get-Acl -LiteralPath $path -ErrorAction Stop;$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;$rules=@($acl.Access);if(!$item.PSIsContainer -or !$acl.AreAccessRulesProtected -or $rules.Count -ne 3){return 'mismatch'};$expected=@{'S-1-5-18'=0x1F01FF;'S-1-5-32-544'=0x1F01FF};$expected[$recipient]=if($private){0x1F01FF}else{0x1200A9};foreach($rule in $rules){$owner=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;if(!$expected.ContainsKey($owner) -or [int]$rule.FileSystemRights -ne $expected[$owner] -or $rule.AccessControlType.ToString() -cne 'Allow' -or $rule.IsInherited -or [int]$rule.InheritanceFlags -ne 3 -or [int]$rule.PropagationFlags -ne 0){return 'mismatch'};$expected.Remove($owner)};return $(if($expected.Count -eq 0){'expected'}else{'mismatch'})}catch{return 'unknown'}}
$out.stageAcl=AclClass $stage $sid $false;$out.stateAcl=AclClass $state $sid $true
try{$t=Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction Stop;$actions=@($t.Actions);$p=$t.Principal;$principalSid=if($p.UserId -match '^S-1-'){([Security.Principal.SecurityIdentifier]::new($p.UserId)).Value}else{([Security.Principal.NTAccount]::new($p.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value};if($t.TaskPath -cne '\' -or $actions.Count -ne 1 -or $actions[0].Execute -cne $python -or $principalSid -cne $sid -or $p.LogonType.ToString() -cne 'Interactive' -or $p.RunLevel.ToString() -cne 'Limited'){$out.task='mismatch'}else{$out.task=$t.State.ToString().ToLowerInvariant();$info=Get-ScheduledTaskInfo -TaskPath '\' -TaskName $name -ErrorAction Stop;if($info.LastRunTime -ne [datetime]::MinValue){$out.lastResult=[int64]$info.LastTaskResult}}}catch{}
try{$item=Get-Item -LiteralPath $readyPath -Force -ErrorAction Stop;if(!$item.PSIsContainer -and !($item.Attributes-band [IO.FileAttributes]::ReparsePoint)){$out.ready='present'}}catch{}
try{$stateDir=Split-Path -Parent $readyPath;$names=@(Get-ChildItem -LiteralPath $stateDir -Force -ErrorAction Stop|ForEach-Object {$_.Name});$out.stateContent=if($names.Count -eq 0){'empty'}elseif($names.Count -eq 1 -and $names[0] -ceq 'probe-events'){'probe-events'}elseif($names -contains 'ready.json'){'ready-present'}else{'other'}}catch{}
$out|ConvertTo-Json -Compress'''


def diagnose_status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read only finite guest task and ready-file facts for one server intent."""
    if not isinstance(value, Mapping) or set(value) != {"serverCorrelationId"} or not _canonical(value.get("serverCorrelationId")):
        raise WindowsUpdateFixtureServerError("Server diagnostic requires exact correlation.")
    root = Path(root).resolve(strict=True); correlation = value["serverCorrelationId"]
    intent = _read_intent(root, correlation)
    if intent is None:
        return {"state": "intent-absent", "serverCorrelationId": correlation, "replayAllowed": False}
    try:
        config, target, (env, socket, pid, ticks, sid) = base._descriptor(root)
        if (env != "windows-cp117" or (socket, pid, ticks, sid) !=
                (intent.get("socketPath"), intent.get("qemuPid"), intent.get("startTicks"), intent.get("originalSid"))):
            raise WindowsUpdateFixtureServerError("Owned server generation changed.")
        ready = (r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-fixture-"
                 + intent["request"]["stageCorrelationId"] + r"\server-state\ready.json")
        state_path = ready.removesuffix(r"\ready.json")
        stage_path = state_path.removesuffix(r"\server-state") + r"\content"
        script = (_SERVER_DIAG_PS.replace("@TASK@", public._ps_literal("VpnControlMcpFixtureServer-" + correlation))
                  .replace("@SID@", public._ps_literal(sid))
                  .replace("@PYTHON@", public._ps_literal(intent["pythonPath"]))
                  .replace("@READY@", public._ps_literal(ready))
                  .replace("@STAGE@", public._ps_literal(stage_path))
                  .replace("@STATE@", public._ps_literal(state_path)))
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        raw = base._remote(config, _REMOTE_LIVE, (socket, str(pid), str(ticks), encoded), None, 30)
        outer = json.loads(raw) if raw is not None else None
        detail = outer.get("result") if isinstance(outer, dict) and outer.get("state") == "observed" else None
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        detail = None
    if (not isinstance(detail, dict) or set(detail) != {"version", "task", "lastResult", "ready", "stateContent", "stageAcl", "stateAcl"}
            or detail.get("version") != 1 or detail.get("task") not in {"absent", "running", "ready", "queued", "disabled", "mismatch"}
            or detail.get("ready") not in {"absent", "present"}
            or detail.get("stateContent") not in {"empty", "probe-events", "ready-present", "other", "unknown"}
            or detail.get("stageAcl") not in {"expected", "mismatch", "unknown"}
            or detail.get("stateAcl") not in {"expected", "mismatch", "unknown"}
            or not (detail.get("lastResult") == "unknown" or
                    (type(detail.get("lastResult")) is int and -2147483648 <= detail["lastResult"] <= 4294967295))):
        return {"state": "unknown", "serverCorrelationId": correlation, "replayAllowed": False}
    return {"state": "observed", "serverCorrelationId": correlation,
            "task": detail["task"], "lastResult": detail["lastResult"],
            "ready": detail["ready"], "stateContent": detail["stateContent"],
            "stageAcl": detail["stageAcl"], "stateAcl": detail["stateAcl"],
            "replayAllowed": False}


_STATIC_DIAG_CODE = r'''import importlib.util,json,pathlib,sys
stage=pathlib.Path(sys.argv[1]);certificate=pathlib.Path(sys.argv[2]);entry=stage/'server'/'prepare_desktop_update_fixture.py'
out={'version':1,'import':'skipped','certificate':'skipped','resources':'skipped','resourceGate':'skipped'}
try:
 sys.path.insert(0,str(entry.parent));spec=importlib.util.spec_from_file_location('fixture_diagnostic',entry);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);out['import']='ok'
except Exception:out['import']='failed'
if out['import']=='ok':
 try:module.require_fixture_certificate_current(certificate);out['certificate']='ok'
 except Exception:out['certificate']='failed'
 try:module.load_resources(stage);out['resources']='ok';out['resourceGate']='complete'
 except Exception:
  out['resources']='failed';out['resourceGate']='receipt'
  try:
   receipt=json.loads((stage/'fixture-receipt.json').read_bytes());out['resourceGate']='receipt-contract'
   if receipt['testOnly'] is not True or receipt['productionTrustChanged'] is not False:raise ValueError()
   base,target=receipt['builds'];out['resourceGate']='builds'
   if not(base['sourceFingerprint']==target['sourceFingerprint']==receipt['sourceFingerprint'] and base['codeFingerprint']==target['codeFingerprint']):raise ValueError()
   manifest=receipt['manifest'];out['resourceGate']='manifest'
   if manifest['assets']!=target['assets'] or manifest['buildNumber']!=module.version_build(target['version']):raise ValueError()
   for asset in manifest['assets']:
    file=stage/'packages'/'target'/asset['fileName'];out['resourceGate']='package-asset'
    if module.package_asset(file,asset['platform'],asset['architecture'],asset['displayVersion'])!=asset:raise ValueError()
    out['resourceGate']='package-mode'
    if file.stat().st_mode & 0o222:raise ValueError()
   out['resourceGate']='other'
  except Exception:pass
print(json.dumps(out,separators=(',',':')))'''


_REMOTE_STATIC_DIAG = base._QGA + r'''import time
sock,pid,ticks,python,stage,cert,code=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
phase='binding'
try:
 if not live(sock,pid,ticks):raise ValueError()
 phase='guest-launch'
 child=call(sock,'guest-exec',{'path':python,'arg':['-I','-B','-c',base64.b64decode(code,validate=True).decode(),stage,cert],'capture-output':True})['pid']
 phase='guest-wait'
 for _ in range(100):
  result=call(sock,'guest-exec-status',{'pid':child})
  if result.get('exited') is True:break
  time.sleep(.2)
 else:raise ValueError()
 phase='guest-exit'
 if result.get('exitcode')!=0:raise ValueError()
 phase='guest-output-truncated'
 if result.get('out-truncated',False) is not False or result.get('err-truncated',False) is not False:raise ValueError()
 phase='guest-output-bytes'
 raw=base64.b64decode(result.get('out-data',''),validate=True)
 if not 0<len(raw)<=1024:raise ValueError()
 phase='guest-parse'
 out({'state':'observed','result':json.loads(decode(raw))})
except Exception:out({'state':'diagnosed','phase':phase})'''


def diagnose_static(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Run only staged fixture import/certificate/resource reads in the guest."""
    if not isinstance(value, Mapping) or set(value) != {"serverCorrelationId"} or not _canonical(value.get("serverCorrelationId")):
        raise WindowsUpdateFixtureServerError("Server static diagnostic requires exact correlation.")
    root = Path(root).resolve(strict=True); correlation = value["serverCorrelationId"]
    intent = _read_intent(root, correlation)
    if intent is None:
        return {"state": "intent-absent", "serverCorrelationId": correlation, "replayAllowed": False}
    phase = "descriptor"
    try:
        config, _target, (env, socket, pid, ticks, sid) = base._descriptor(root)
        if (env != "windows-cp117" or (socket, pid, ticks, sid) !=
                (intent.get("socketPath"), intent.get("qemuPid"), intent.get("startTicks"), intent.get("originalSid"))):
            raise WindowsUpdateFixtureServerError("Owned server generation changed.")
        request = _request(intent["request"])
        phase = "stage"
        staged = stage.status(root, {"correlationId": request["stageCorrelationId"]})
        if staged.get("state") != "staged-not-server-ready":
            raise WindowsUpdateFixtureServerError("Exact server stage changed.")
        content = (r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-fixture-"
                   + request["stageCorrelationId"] + r"\content")
        cert = (r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-credentials-"
                + request["stageCorrelationId"] + r"\server-cert.pem")
        phase = "remote"
        raw = base._remote(config, _REMOTE_STATIC_DIAG,
                           (socket, str(pid), str(ticks), intent["pythonPath"], content, cert,
                            base64.b64encode(_STATIC_DIAG_CODE.encode()).decode()), None, 30)
        outer = json.loads(raw) if raw is not None else None
        if (isinstance(outer, dict) and set(outer) == {"state", "phase"}
                and outer.get("state") == "diagnosed"
                and outer.get("phase") in {"binding", "guest-launch", "guest-wait", "guest-exit",
                                           "guest-output-truncated",
                                           "guest-output-bytes", "guest-parse"}):
            return {"state": "diagnosed", "serverCorrelationId": correlation,
                    "phase": outer["phase"], "replayAllowed": False}
        result = outer.get("result") if isinstance(outer, dict) and outer.get("state") == "observed" else None
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return {"state": "diagnosed", "serverCorrelationId": correlation,
                "phase": phase, "replayAllowed": False}
    if (not isinstance(result, dict) or set(result) != {"version", "import", "certificate", "resources", "resourceGate"}
            or result.get("version") != 1 or result.get("import") not in {"ok", "failed", "skipped"}
            or result.get("certificate") not in {"ok", "failed", "skipped"}
            or result.get("resources") not in {"ok", "failed", "skipped"}
            or result.get("resourceGate") not in {"skipped", "receipt", "receipt-contract", "builds",
                                                   "manifest", "package-asset", "package-mode", "other", "complete"}
            or (result["resources"] == "ok") != (result["resourceGate"] == "complete")
            or (result["resources"] == "skipped") != (result["resourceGate"] == "skipped")):
        return {"state": "diagnosed", "serverCorrelationId": correlation,
                "phase": phase, "replayAllowed": False}
    return {"state": "observed", "serverCorrelationId": correlation,
            "import": result["import"], "certificate": result["certificate"],
            "resources": result["resources"], "resourceGate": result["resourceGate"],
            "replayAllowed": False}


def verified_live_receipt(root: Path | str, lease_id: str) -> dict[str, Any]:
    """Internal target/public join from one private intent and fresh QGA state."""
    if not _canonical(lease_id):
        raise WindowsUpdateFixtureServerError("Server join identity is invalid.")
    root = Path(root).resolve(strict=True)
    directory = root / _GROUP
    try: info = directory.lstat()
    except FileNotFoundError:
        raise WindowsUpdateFixtureServerError("LIVE_FIXTURE_RECEIPT_UNAVAILABLE") from None
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink()
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsUpdateFixtureServerError("LIVE_FIXTURE_RECEIPT_UNAVAILABLE")
    entries = [entry for entry in directory.iterdir() if entry.suffix == ".json"]
    if len(entries) != 1 or not _canonical(entries[0].stem):
        raise WindowsUpdateFixtureServerError("LIVE_FIXTURE_RECEIPT_UNAVAILABLE")
    intent = _read_intent(root, entries[0].stem)
    if intent is None or intent["request"].get("leaseId") != lease_id:
        raise WindowsUpdateFixtureServerError("LIVE_FIXTURE_RECEIPT_UNAVAILABLE")
    receipt, current, _config, _target = _live_from_intent(root, intent)
    if current["server"] != "live":
        raise WindowsUpdateFixtureServerError("LIVE_FIXTURE_RECEIPT_UNAVAILABLE")
    return receipt


def _cleanup_request(value: Mapping[str, Any]) -> dict[str, str]:
    fields = {"leaseId", "serverCorrelationId", "cleanupCorrelationId"}
    if (not isinstance(value, Mapping) or set(value) != fields
            or not all(_canonical(value[key]) for key in fields)
            or len(set(value.values())) != 3):
        raise WindowsUpdateFixtureServerError("Server cleanup requires exact correlations.")
    return dict(value)


def _cleanup_path(root: Path, correlation: str) -> Path:
    return root / _CLEANUP_GROUP / (correlation + ".json")


def _read_cleanup_intent(root: Path, correlation: str) -> dict[str, Any] | None:
    try: fd = os.open(_cleanup_path(root, correlation), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError: return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384):
            raise WindowsUpdateFixtureServerError("Server cleanup intent is unsafe.")
        try: value = json.load(stream)
        except (TypeError, ValueError) as error:
            raise WindowsUpdateFixtureServerError("Server cleanup intent is invalid.") from error
    if (not isinstance(value, dict) or not isinstance(value.get("request"), dict)
            or value["request"].get("cleanupCorrelationId") != correlation
            or value.get("mode") not in {"stop", "abort"}):
        raise WindowsUpdateFixtureServerError("Server cleanup intent is invalid.")
    return value


def _reserve_cleanup(root: Path, record: Mapping[str, Any]) -> None:
    _closed_server_history(root, record["request"]["leaseId"], group=_CLEANUP_GROUP)
    directory = root / _CLEANUP_GROUP
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink()
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsUpdateFixtureServerError("Server cleanup journal is unsafe.")
    fd = os.open(directory / ".environment.lock", os.O_RDWR | os.O_CREAT |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise WindowsUpdateFixtureServerError("Server cleanup lock is unsafe.")
        fcntl.flock(fd, fcntl.LOCK_EX)
        _closed_server_history(root, record["request"]["leaseId"], group=_CLEANUP_GROUP)
        raw = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(raw) > 16384:
            raise WindowsUpdateFixtureServerError("Server cleanup intent is too large.")
        path = _cleanup_path(root, record["request"]["cleanupCorrelationId"])
        item = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                       getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(item, "wb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(parent)
        finally: os.close(parent)
    finally:
        os.close(fd)


_CLEANUP_ACTION = r'''$ErrorActionPreference='Stop'
$taskName=@TASK@;$python=@PYTHON@;$arguments=@ARGUMENTS@;$expectedSid=@SID@
$expectedPid=@PID@;$expectedStart=@START@;$expectedPort=@PORT@
function MatchingProcesses {
 $items=@(Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" | Where-Object {
  $_.ExecutablePath -ceq $python -and $_.CommandLine -like ('*'+$arguments) })
 if($items.Count -gt 1){throw 'AMBIGUOUS_PROCESS'}
 return $items
}
$task=@(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop | Where-Object {$_.TaskName -ceq $taskName})
if($task.Count -gt 1){throw 'AMBIGUOUS_TASK'}
$task=if($task.Count -eq 1){$task[0]}else{$null}
$owned=@(MatchingProcesses)
if($null -ne $task){
 $actions=@($task.Actions)
 if($actions.Count -ne 1 -or $task.Principal.UserId -cnotin @('VPNMSIX64\vpncp117',$expectedSid) -or
    $task.Principal.LogonType.ToString() -cne 'Interactive' -or
    $task.Principal.RunLevel.ToString() -cne 'Limited' -or
    $actions[0].Execute -cne $python -or $actions[0].Arguments -cne $arguments){throw 'FOREIGN_TASK'}
} elseif($owned.Count -ne 0){throw 'PROCESS_WITHOUT_TASK'}
$starts=@{}
foreach($item in $owned){
 $owner=Invoke-CimMethod -InputObject $item -MethodName GetOwnerSid
 $native=Get-Process -Id ([int]$item.ProcessId) -ErrorAction Stop
 $start='windows:'+$native.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
 if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $expectedSid -or $item.SessionId -ne 1 -or
    ($expectedPid -gt 0 -and ($item.ProcessId -ne $expectedPid -or $start -cne $expectedStart))){throw 'FOREIGN_PROCESS'}
 $starts[[int]$item.ProcessId]=$start
}
if($null -ne $task){
 Stop-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue
 Unregister-ScheduledTask -TaskPath '\' -TaskName $taskName -Confirm:$false -ErrorAction Stop
}
foreach($item in $owned){
 $native=Get-Process -Id ([int]$item.ProcessId) -ErrorAction SilentlyContinue
 if($null -ne $native){
  $start='windows:'+$native.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
  if($start -cne $starts[[int]$item.ProcessId]){throw 'REUSED_PROCESS'}
  Stop-Process -Id ([int]$item.ProcessId) -Force -ErrorAction Stop
 }
}
for($i=0;$i -lt 50;$i++){
 if(@(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop | Where-Object {$_.TaskName -ceq $taskName}).Count -eq 0 -and
    @(MatchingProcesses).Count -eq 0){break}
 Start-Sleep -Milliseconds 200
}
if(@(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop | Where-Object {$_.TaskName -ceq $taskName}).Count -ne 0 -or
   @(MatchingProcesses).Count -ne 0){throw 'STOP_INCOMPLETE'}
if($expectedPort -gt 0 -and @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {
   $_.LocalAddress -eq '127.0.0.1' -and $_.LocalPort -eq $expectedPort}).Count -ne 0){throw 'LISTENER_REMAINS'}
([pscustomobject]@{taskAbsent=$true;matchingProcessAbsent=$true;listenerAbsent=$true;
 originalSid=$expectedSid;sessionId=1;serverPid=$expectedPid;
 serverProcessStartIdentity=$expectedStart;serverPort=$expectedPort}|ConvertTo-Json -Compress)
'''


def _cleanup_script(root: Path, server_request: Mapping[str, str], intent: Mapping[str, Any],
                    guest: tuple[str, int, int, str], live: Mapping[str, Any] | None) -> str:
    descriptor = _private_tls_descriptor(root, server_request)
    arguments = _launch_arguments(server_request, descriptor)
    if hashlib.sha256(arguments.encode()).hexdigest() != intent["launchArgumentsSha256"]:
        raise WindowsUpdateFixtureServerError("Server cleanup action changed.")
    fields = {"TASK": "VpnControlMcpFixtureServer-" + server_request["serverCorrelationId"],
              "PYTHON": intent["pythonPath"], "ARGUMENTS": arguments, "SID": guest[3],
              "PID": str(live["serverPid"] if live else 0),
              "START": live["serverProcessStartIdentity"] if live else "",
              "PORT": str(live["serverPort"] if live else 0)}
    script = _CLEANUP_ACTION
    for key, value in fields.items():
        script = script.replace("@" + key + "@", value if key in {"PID", "PORT"}
                                else public._ps_literal(value))
    if len(base64.b64encode(script.encode("utf-16le"))) >= 30000:
        raise WindowsUpdateFixtureServerError("Server cleanup command exceeds QGA limit.")
    return script


_CLEANUP_VERIFY = r'''$ErrorActionPreference='Stop'
$taskName=@TASK@;$python=@PYTHON@;$arguments=@ARGUMENTS@;$port=@PORT@
$tasks=@(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop | Where-Object {$_.TaskName -ceq $taskName})
$processes=@(Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" -ErrorAction Stop | Where-Object {
 $_.ExecutablePath -ceq $python -and $_.CommandLine -like ('*'+$arguments)})
$listeners=if($port -gt 0){@(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {
 $_.LocalAddress -eq '127.0.0.1' -and $_.LocalPort -eq $port})}else{@()}
([pscustomobject]@{taskAbsent=($tasks.Count -eq 0);matchingProcessAbsent=($processes.Count -eq 0);
 listenerAbsent=($listeners.Count -eq 0)}|ConvertTo-Json -Compress)
'''


def _cleanup_verify_script(server_request: Mapping[str, str], intent: Mapping[str, Any],
                           descriptor: Mapping[str, Any], port: int) -> str:
    arguments = _launch_arguments(server_request, descriptor)
    fields = {"TASK": "VpnControlMcpFixtureServer-" + server_request["serverCorrelationId"],
              "PYTHON": intent["pythonPath"], "ARGUMENTS": arguments, "PORT": str(port)}
    result = _CLEANUP_VERIFY
    for key, value in fields.items():
        result = result.replace("@" + key + "@", value if key == "PORT" else public._ps_literal(value))
    return result


_REMOTE_CLEANUP = base._QGA + lease.remote_role_guard() + _PRIVATE_REMOTE_JSON + r'''import fcntl,uuid
root,env,lease_id,role,role_corr,server_corr,cleanup_corr,sock,pid,ticks,source,receipt_id,base_id,target_id,sid,encoded,command_hash,verify_encoded,verify_hash=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks):raise ValueError()
 require_campaign_role(root,env,lease_id,role,role_corr,source,receipt_id,base_id,target_id,sock,pid,ticks)
 if any(str(uuid.UUID(value))!=value for value in (lease_id,role_corr,server_corr,cleanup_corr)):raise ValueError()
 if role not in ('server-start','server-stop') or (role=='server-start' and role_corr!=server_corr) or (role=='server-stop' and role_corr!=cleanup_corr):raise ValueError()
 if hashlib.sha256(base64.b64decode(encoded,validate=True)).hexdigest()!=command_hash:raise ValueError()
 if hashlib.sha256(base64.b64decode(verify_encoded,validate=True)).hexdigest()!=verify_hash:raise ValueError()
 group=os.path.join(root,env,'windows-update-fixture-server');job=os.path.join(group,server_corr)
 for path in (root,os.path.join(root,env),group,job):
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 binding_path=os.path.join(job,'binding.json');info=os.lstat(binding_path)
 if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>16384:raise ValueError()
 with open(binding_path,encoding='utf-8') as file:server=json.load(file)
 if server.get('leaseId')!=lease_id or server.get('serverCorrelationId')!=server_corr or server.get('socketPath')!=sock or server.get('qemuPid')!=int(pid) or server.get('startTicks')!=int(ticks) or server.get('sourceSha')!=source or server.get('fixtureReceiptArtifactId')!=receipt_id or server.get('baseMsiArtifactId')!=base_id or server.get('targetMsiArtifactId')!=target_id:raise ValueError()
 dispatch_lock=os.open(os.path.join(job,'.dispatch.lock'),os.O_RDWR|getattr(os,'O_NOFOLLOW',0))
 info=os.fstat(dispatch_lock)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError()
 fcntl.flock(dispatch_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 dispatch_path=os.path.join(job,'dispatch.json');marker_path=os.path.join(job,'guest-dispatch-intent.json')
 if os.path.exists(dispatch_path):
  info=os.lstat(dispatch_path)
  if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>16384:raise ValueError()
  info=os.lstat(marker_path)
  if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>16384:raise ValueError()
  with open(marker_path,encoding='utf-8') as file:marker=json.load(file)
  if marker!={'commandSha256':server['commandSha256']}:raise ValueError()
  with open(dispatch_path,encoding='utf-8') as file:prior=json.load(file)
  prior_state=call(sock,'guest-exec-status',{'pid':prior['pid']})
  if prior_state.get('exited') is not True:raise ValueError()
  dispatch_mode='dispatched'
 else:
  if role!='server-start' or server.get('dispatchProtocol')!=2 or os.path.lexists(marker_path):
   os.close(dispatch_lock);raise ValueError()
  dispatch_mode='no-dispatch'
 lock=os.open(os.path.join(job,'.cleanup.lock'),os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
 try:
  fcntl.flock(lock,fcntl.LOCK_EX)
  if any(name.startswith('cleanup-') for name in os.listdir(job)):raise FileExistsError()
  cleanup=os.path.join(job,'cleanup-'+cleanup_corr);os.mkdir(cleanup,0o700)
 finally:os.close(lock)
 save_private_json(os.path.join(cleanup,'binding.json'),{'leaseId':lease_id,'role':role,'roleCorrelationId':role_corr,'serverCorrelationId':server_corr,'cleanupCorrelationId':cleanup_corr,'socketPath':sock,'qemuPid':int(pid),'startTicks':int(ticks),'commandSha256':command_hash,'verifyCommandSha256':verify_hash,'dispatchMode':dispatch_mode})
 if dispatch_mode=='dispatched':
  child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
  save_private_json(os.path.join(cleanup,'dispatch.json'),{'pid':child})
 else:
  child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',verify_encoded],'capture-output':True})['pid']
  for _ in range(60):
   result=call(sock,'guest-exec-status',{'pid':child})
   if result.get('exited') is True:break
   __import__('time').sleep(.2)
  else:raise ValueError()
  if result.get('exitcode')!=0 or result.get('out-truncated',False) is not False or result.get('err-truncated',False) is not False:raise ValueError()
  raw=base64.b64decode(result['out-data'],validate=True)
  if not 0<len(raw)<=8192 or json.loads(decode(raw))!={'taskAbsent':True,'matchingProcessAbsent':True,'listenerAbsent':True}:raise ValueError()
  save_private_json(os.path.join(cleanup,'terminal.json'),{'taskAbsent':True,'matchingProcessAbsent':True,'listenerAbsent':True,'originalSid':sid,'sessionId':1,'serverPid':0,'serverProcessStartIdentity':'','serverPort':0})
 os.close(dispatch_lock)
 out({'state':'submitted','cleanupCorrelationId':cleanup_corr})
except Exception:out({'state':'unknown','cleanupCorrelationId':cleanup_corr})
'''


_REMOTE_CLEANUP_STATUS = base._QGA + lease.remote_role_guard() + _PRIVATE_REMOTE_JSON + r'''import fcntl,uuid
root,env,lease_id,role,role_corr,server_corr,cleanup_corr,sock,pid,ticks,source,receipt_id,base_id,target_id,verify_encoded,command_hash,verify_hash=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks):raise ValueError()
 require_campaign_role(root,env,lease_id,role,role_corr,source,receipt_id,base_id,target_id,sock,pid,ticks)
 if any(str(uuid.UUID(value))!=value for value in (lease_id,role_corr,server_corr,cleanup_corr)):raise ValueError()
 job=os.path.join(root,env,'windows-update-fixture-server',server_corr,'cleanup-'+cleanup_corr)
 info=os.lstat(job)
 if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 binding_path=os.path.join(job,'binding.json');info=os.lstat(binding_path)
 if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>16384:raise ValueError()
 with open(binding_path,encoding='utf-8') as file:binding=json.load(file)
 if hashlib.sha256(base64.b64decode(verify_encoded,validate=True)).hexdigest()!=verify_hash:raise ValueError()
 mode=binding.get('dispatchMode')
 if mode not in ('dispatched','no-dispatch') or binding!={'leaseId':lease_id,'role':role,'roleCorrelationId':role_corr,'serverCorrelationId':server_corr,'cleanupCorrelationId':cleanup_corr,'socketPath':sock,'qemuPid':int(pid),'startTicks':int(ticks),'commandSha256':command_hash,'verifyCommandSha256':verify_hash,'dispatchMode':mode}:raise ValueError()
 if mode=='dispatched':
  dispatch_path=os.path.join(job,'dispatch.json');info=os.lstat(dispatch_path)
  if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>16384:raise ValueError()
  with open(dispatch_path,encoding='utf-8') as file:dispatch=json.load(file)
  status_lock=os.open(os.path.join(job,'.status.lock'),os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
  try:
   lock_info=os.fstat(status_lock)
   if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid!=os.geteuid() or stat.S_IMODE(lock_info.st_mode)!=0o600:raise ValueError()
   fcntl.flock(status_lock,fcntl.LOCK_EX)
   terminal_path=os.path.join(job,'terminal.json')
   if os.path.exists(terminal_path):
    info=os.lstat(terminal_path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>4096:raise ValueError()
    with open(terminal_path,encoding='utf-8') as file:terminal=json.load(file)
   else:
    result=call(sock,'guest-exec-status',{'pid':dispatch['pid']})
    if result.get('exited') is not True:out({'state':'running','cleanupCorrelationId':cleanup_corr});raise SystemExit(0)
    if result.get('exitcode')!=0 or result.get('out-truncated',False) is not False or result.get('err-truncated',False) is not False:raise ValueError()
    raw=base64.b64decode(result['out-data'],validate=True)
    if not 0<len(raw)<=8192:raise ValueError()
    terminal=json.loads(decode(raw))
    if not isinstance(terminal,dict):raise ValueError()
    save_private_json(terminal_path,terminal)
  finally:os.close(status_lock)
 else:
  terminal_path=os.path.join(job,'terminal.json');info=os.lstat(terminal_path)
  if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>4096:raise ValueError()
  with open(terminal_path,encoding='utf-8') as file:terminal=json.load(file)
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',verify_encoded],'capture-output':True})['pid']
 for _ in range(60):
  observed=call(sock,'guest-exec-status',{'pid':child})
  if observed.get('exited') is True:break
  __import__('time').sleep(.2)
 else:raise ValueError()
 if observed.get('exitcode')!=0 or observed.get('out-truncated',False) is not False or observed.get('err-truncated',False) is not False:raise ValueError()
 fresh_raw=base64.b64decode(observed['out-data'],validate=True)
 if not 0<len(fresh_raw)<=8192:raise ValueError()
 fresh=json.loads(decode(fresh_raw))
 out({'state':'observed','cleanupCorrelationId':cleanup_corr,'terminal':terminal,'fresh':fresh})
except SystemExit:raise
except Exception:out({'state':'unknown','cleanupCorrelationId':cleanup_corr})
'''


def _cleanup_start(root: Path | str, value: Mapping[str, Any], *, mode: str) -> dict[str, Any]:
    root = Path(root).resolve(strict=True); request = _cleanup_request(value)
    correlation = request["cleanupCorrelationId"]
    prior = _read_cleanup_intent(root, correlation)
    if prior is not None:
        if prior.get("request") != request or prior.get("mode") != mode:
            raise WindowsUpdateFixtureServerError("Server cleanup correlation changed.")
        return {"state": "unknown", "cleanupCorrelationId": correlation,
                "cleanupRequired": True, "replayAllowed": False}
    server_intent = _read_intent(root, request["serverCorrelationId"])
    if server_intent is None:
        raise WindowsUpdateFixtureServerError("Exact server start intent is unavailable.")
    bound = _request(server_intent["request"])
    if bound["leaseId"] != request["leaseId"]:
        raise WindowsUpdateFixtureServerError("Server cleanup campaign changed.")
    if mode == "stop":
        try:
            live = verified_live_receipt(root, request["leaseId"])
        except (OSError, ValueError, KeyError, TypeError):
            live = _verified_stopped_live_snapshot(root, bound)
    else:
        live = None
    if live is not None and live["serverCorrelationId"] != request["serverCorrelationId"]:
        raise WindowsUpdateFixtureServerError("Live server correlation changed.")
    config, target, descriptor = base._descriptor(root)
    env, socket, pid, ticks, sid = descriptor
    guest = (socket, pid, ticks, sid)
    if (env != "windows-cp117" or any(server_intent.get(key) != observed for key, observed in
        (("environment", env), ("socketPath", socket), ("qemuPid", pid),
         ("startTicks", ticks), ("originalSid", sid)))):
        raise WindowsUpdateFixtureServerError("Server cleanup guest generation changed.")
    if mode == "abort":
        directory, lock = lease._locked(root)
        try:
            current = lease._active(directory)
            if (current is None or current.get("state") != "role-active"
                    or current.get("role") != "server-start"
                    or current.get("correlationId") != request["serverCorrelationId"]
                    or current.get("server") != "starting"
                    or current.get("identity") != base._campaign_identity(
                        {**bound, "correlationId": bound["leaseId"]}, descriptor)
                    or not lease._remote_confirm(base._campaign_remote(config, target), "status", current, None)):
                raise WindowsUpdateFixtureServerError("Unknown server start cannot be aborted.")
        finally: os.close(lock)
    action = _cleanup_script(root, bound, server_intent, guest, live)
    encoded = base64.b64encode(action.encode("utf-16le")).decode("ascii")
    digest = hashlib.sha256(action.encode("utf-16le")).hexdigest()
    tls = _private_tls_descriptor(root, bound)
    verify = _cleanup_verify_script(bound, server_intent, tls, live["serverPort"] if live else 0)
    verify_encoded = base64.b64encode(verify.encode("utf-16le")).decode("ascii")
    verify_digest = hashlib.sha256(verify.encode("utf-16le")).hexdigest()
    record = {"schemaVersion": 1, "mode": mode, "request": request,
              "serverRequest": bound, "environment": env, "socketPath": socket,
              "qemuPid": pid, "startTicks": ticks, "originalSid": sid,
              "serverPid": live["serverPid"] if live else 0,
              "serverProcessStartIdentity": live["serverProcessStartIdentity"] if live else "",
              "serverPort": live["serverPort"] if live else 0,
              "commandSha256": digest, "verifyCommandSha256": verify_digest}
    _reserve_cleanup(root, record)
    remote = base._campaign_remote(config, target)
    if mode == "stop":
        claimed = lease.claim_role(root, request["leaseId"], "server-stop", correlation, remote)
        if claimed.get("state") != "role-active":
            return {"state": "unknown", "cleanupCorrelationId": correlation,
                    "cleanupRequired": True, "replayAllowed": False}
    role = "server-stop" if mode == "stop" else "server-start"
    role_corr = correlation if mode == "stop" else request["serverCorrelationId"]
    raw = base._remote(config, _REMOTE_CLEANUP,
        (str(target.fixture_transfer_root), env, request["leaseId"], role,
         role_corr, request["serverCorrelationId"], correlation, socket, str(pid), str(ticks),
         bound["sourceSha"], bound["fixtureReceiptArtifactId"], bound["baseMsiArtifactId"],
         bound["targetMsiArtifactId"], sid, encoded, digest, verify_encoded,
         verify_digest), None, 120)
    try: result = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError): result = None
    if result != {"state": "submitted", "cleanupCorrelationId": correlation}:
        return {"state": "unknown", "cleanupCorrelationId": correlation,
                "cleanupRequired": True, "replayAllowed": False}
    return {"state": "submitted", "cleanupCorrelationId": correlation,
            "cleanupRequired": True, "replayAllowed": False}


def stop_start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    return _cleanup_start(root, value, mode="stop")


def abort_start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    return _cleanup_start(root, value, mode="abort")


def _terminal_path(root: Path, correlation: str) -> Path:
    return root / _CLEANUP_GROUP / (correlation + ".terminal")


def _terminal_receipt(root: Path, correlation: str) -> dict[str, Any] | None:
    try: fd = os.open(_terminal_path(root, correlation), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError: return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4096):
            raise WindowsUpdateFixtureServerError("Server cleanup terminal receipt is unsafe.")
        value = json.load(stream)
    if (not isinstance(value, dict) or set(value) != {"cleanupCorrelationId", "mode", "receiptSha256"}
            or value["cleanupCorrelationId"] != correlation or value["mode"] not in {"stop", "abort"}
            or not isinstance(value["receiptSha256"], str) or not _HASH.fullmatch(value["receiptSha256"])):
        raise WindowsUpdateFixtureServerError("Server cleanup terminal receipt is invalid.")
    return value


def _save_terminal(root: Path, correlation: str, mode: str, digest: str) -> None:
    prior = _terminal_receipt(root, correlation)
    expected = {"cleanupCorrelationId": correlation, "mode": mode, "receiptSha256": digest}
    if prior is not None:
        if prior != expected:
            raise WindowsUpdateFixtureServerError("Server cleanup terminal receipt changed.")
        return
    path = _terminal_path(root, correlation)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write((json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n").encode())
        stream.flush(); os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try: os.fsync(parent)
    finally: os.close(parent)


def _cleanup_status(root: Path | str, value: Mapping[str, Any], *, mode: str) -> dict[str, Any]:
    if (not isinstance(value, Mapping) or set(value) != {"cleanupCorrelationId"}
            or not _canonical(value["cleanupCorrelationId"])):
        raise WindowsUpdateFixtureServerError("Server cleanup status requires exact correlation.")
    root = Path(root).resolve(strict=True); correlation = value["cleanupCorrelationId"]
    intent = _read_cleanup_intent(root, correlation)
    unknown = {"state": "unknown", "cleanupCorrelationId": correlation,
               "cleanupRequired": intent is not None, "replayAllowed": False}
    if intent is None or intent.get("mode") != mode:
        return unknown
    request = _cleanup_request(intent["request"])
    try:
        server_intent = _read_intent(root, request["serverCorrelationId"])
        if server_intent is None or _request(server_intent["request"]) != intent["serverRequest"]:
            return unknown
        config, target, descriptor = base._descriptor(root)
        env, socket, pid, ticks, sid = descriptor
        if (env != intent["environment"] or any(intent.get(key) != observed for key, observed in
             (("socketPath", socket), ("qemuPid", pid), ("startTicks", ticks), ("originalSid", sid)))):
            return unknown
        directory, lock = lease._locked(root)
        try:
            current = lease._active(directory)
            expected_identity = base._campaign_identity(
                {**intent["serverRequest"], "correlationId": request["leaseId"]}, descriptor)
            if current is None or current["identity"] != expected_identity:
                return unknown
        finally: os.close(lock)
        terminal = _terminal_receipt(root, correlation)
        if (terminal is not None and terminal["mode"] == mode
                and current["state"] == "active" and current["role"] is None
                and current["server"] == "stopped"
                and current["lastEvidenceSha256"] == terminal["receiptSha256"]
                and lease._remote_confirm(base._campaign_remote(config, target), "status", current, None)):
            return {"state": "stopped", "cleanupCorrelationId": correlation,
                    "cleanupReceiptSha256": terminal["receiptSha256"],
                    "cleanupRequired": False, "replayAllowed": False}
        role = "server-stop" if mode == "stop" else "server-start"
        role_corr = correlation if mode == "stop" else request["serverCorrelationId"]
        expected_server = "stopping" if mode == "stop" else "starting"
        if (current["state"] != "role-active" or current["role"] != role
                or current["correlationId"] != role_corr or current["server"] != expected_server
                or current["credentials"] != "ready"
                or not lease._remote_confirm(base._campaign_remote(config, target), "status", current, None)):
            return unknown
        bound = intent["serverRequest"]
        tls = _private_tls_descriptor(root, bound)
        if (server_intent.get("credentialProvisionId") != tls["provisionId"]
                or any(server_intent.get(key) != tls[key] for key in
                       ("peerCertificateSha256", "certificateSha256", "privateKeySha256", "trustStoreSha256"))):
            return unknown
        verify = _cleanup_verify_script(bound, server_intent, tls, intent["serverPort"])
        encoded = base64.b64encode(verify.encode("utf-16le")).decode("ascii")
        raw = base._remote(config, _REMOTE_CLEANUP_STATUS,
            (str(target.fixture_transfer_root), env, request["leaseId"], role, role_corr,
             request["serverCorrelationId"], correlation, socket, str(pid), str(ticks),
             bound["sourceSha"], bound["fixtureReceiptArtifactId"], bound["baseMsiArtifactId"],
             bound["targetMsiArtifactId"], encoded, intent["commandSha256"],
             intent["verifyCommandSha256"]), None, 60)
        observed = json.loads(raw) if raw is not None else None
        if not isinstance(observed, dict) or observed.get("cleanupCorrelationId") != correlation:
            return unknown
        if observed.get("state") == "running":
            return {"state": "running", "cleanupCorrelationId": correlation,
                    "cleanupRequired": True, "replayAllowed": False}
        expected_absence = {"taskAbsent": True, "matchingProcessAbsent": True,
                            "listenerAbsent": True}
        expected_terminal = {**expected_absence, "originalSid": sid, "sessionId": 1,
            "serverPid": intent["serverPid"],
            "serverProcessStartIdentity": intent["serverProcessStartIdentity"],
            "serverPort": intent["serverPort"]}
        if (observed.get("state") != "observed" or observed.get("terminal") != expected_terminal
                or observed.get("fresh") != expected_absence):
            return unknown
        digest = hashlib.sha256(json.dumps(
            {"request": request, "mode": mode, "terminal": expected_terminal,
             "fresh": expected_absence, "guest": [socket, pid, ticks, sid]},
            sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        _save_terminal(root, correlation, mode, digest)
        completed = lease.finish_role(root, request["leaseId"], role, role_corr,
                                      digest, "succeeded" if mode == "stop" else "failed-cleaned",
                                      base._campaign_remote(config, target))
        if completed.get("state") != "active":
            return unknown
        return {"state": "stopped", "cleanupCorrelationId": correlation,
                "cleanupReceiptSha256": digest, "cleanupRequired": False,
                "replayAllowed": False}
    except (OSError, ValueError, KeyError, TypeError):
        return unknown


def stop_status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    return _cleanup_status(root, value, mode="stop")


def stop_collect(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    return stop_status(root, value)


def abort_status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    return _cleanup_status(root, value, mode="abort")


def abort_collect(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    return abort_status(root, value)


_REMOTE_CLEANUP_DIAGNOSTIC = base._QGA + r'''root,env,server_corr,cleanup_corr,sock,pid,ticks=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
phase='binding'
try:
 if not live(sock,pid,ticks):raise ValueError()
 phase='journal'
 job=os.path.join(root,env,'windows-update-fixture-server',server_corr,'cleanup-'+cleanup_corr)
 info=os.lstat(job)
 if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 for name in ('binding.json','dispatch.json'):
  path=os.path.join(job,name);info=os.lstat(path)
  if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>16384:raise ValueError()
 with open(os.path.join(job,'binding.json'),encoding='utf-8') as file:binding=json.load(file)
 if binding.get('serverCorrelationId')!=server_corr or binding.get('cleanupCorrelationId')!=cleanup_corr or binding.get('socketPath')!=sock or binding.get('qemuPid')!=int(pid) or binding.get('startTicks')!=int(ticks) or binding.get('dispatchMode')!='dispatched':raise ValueError()
 with open(os.path.join(job,'dispatch.json'),encoding='utf-8') as file:dispatch=json.load(file)
 if set(dispatch)!={'pid'} or type(dispatch['pid']) is not int or dispatch['pid']<=0:raise ValueError()
 phase='guest-task'
 result=call(sock,'guest-exec-status',{'pid':dispatch['pid']})
 if result.get('exited') is False:out({'state':'observed','task':'running','result':'unknown','stdout':'unknown','stderr':'unknown'});raise SystemExit(0)
 if result.get('exited') is not True:raise ValueError()
 code=result.get('exitcode')
 status='zero' if type(code) is int and code==0 else 'nonzero' if type(code) is int else 'unknown'
 def flag(name):
  value=result.get(name,'absent')
  return 'absent' if value=='absent' else 'false' if value is False else 'true' if value is True else 'invalid'
 out({'state':'observed','task':'terminal','result':status,'stdout':flag('out-truncated'),'stderr':flag('err-truncated')})
except SystemExit:raise
except Exception:out({'state':'diagnosed','phase':phase})'''


def diagnose_abort(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read only the exact aborted server cleanup child and finite QGA flags."""
    if (not isinstance(value, Mapping) or set(value) != {"cleanupCorrelationId"}
            or not _canonical(value.get("cleanupCorrelationId"))):
        raise WindowsUpdateFixtureServerError("Abort diagnostic requires exact correlation.")
    root = Path(root).resolve(strict=True); correlation = value["cleanupCorrelationId"]
    phase = "intent"
    try:
        intent = _read_cleanup_intent(root, correlation)
        if intent is None or intent.get("mode") != "abort":
            raise WindowsUpdateFixtureServerError("Exact abort intent is unavailable.")
        request = _cleanup_request(intent["request"])
        phase = "descriptor"
        config, target, (env, socket, pid, ticks, sid) = base._descriptor(root)
        if (env != "windows-cp117" or any(intent.get(key) != observed for key, observed in
                (("socketPath", socket), ("qemuPid", pid), ("startTicks", ticks), ("originalSid", sid)))):
            raise WindowsUpdateFixtureServerError("Abort guest generation changed.")
        phase = "remote"
        raw = base._remote(config, _REMOTE_CLEANUP_DIAGNOSTIC,
                           (str(target.fixture_transfer_root), env, request["serverCorrelationId"],
                            correlation, socket, str(pid), str(ticks)), None, 30)
        result = json.loads(raw) if raw is not None else None
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        result = None
    if (isinstance(result, dict) and set(result) == {"state", "task", "result", "stdout", "stderr"}
            and result.get("state") == "observed" and result.get("task") in {"running", "terminal"}
            and result.get("result") in {"unknown", "zero", "nonzero"}
            and result.get("stdout") in {"unknown", "absent", "false", "true", "invalid"}
            and result.get("stderr") in {"unknown", "absent", "false", "true", "invalid"}):
        return {**result, "cleanupCorrelationId": correlation, "replayAllowed": False}
    if (isinstance(result, dict) and result.get("state") == "diagnosed"
            and result.get("phase") in {"binding", "journal", "guest-task"}):
        phase = result["phase"]
    return {"state": "diagnosed", "cleanupCorrelationId": correlation,
            "phase": phase, "replayAllowed": False}
