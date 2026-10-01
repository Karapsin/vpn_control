"""One-use CP117 acquisition and transfer of the pinned Python installer.

This deliberately small adapter exists because the normal update-fixture
server cannot start until CP117 has one trusted Python interpreter.  It has no
caller-controlled URL, bytes, guest path, or command. It first records a
private intent, then an original-user limited task downloads only the fixed
public HTTPS installer with redirects disabled. It checks exact length,
SHA-256, and Authenticode signer before an atomic move into the only path
accepted by the separate Python installer action.
"""
from __future__ import annotations

import base64
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

from . import windows_msi_base_prepare as base
from . import windows_update_fixture_server as server


class WindowsFixturePythonAcquireTransferError(ValueError):
    pass


URL = "https://www.python.org/ftp/python/3.13.15/python-3.13.15-amd64.exe"
SHA256 = "edec09c4853aeae9ac36efb8c9f95b6b8e2fee65eee56d9767a8b7c69c574403"
SIZE_BYTES = 29_452_944
_GROUP = ".rag_index/windows-fixture-python-acquire-transfer"
_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
_SID = re.compile(r"S-1-5-21-(?:[0-9]+-){3}[0-9]+\Z")
_UNKNOWN = {"state": "unknown", "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}


def _canonical(value: object) -> bool:
    return isinstance(value, str) and bool(_UUID.fullmatch(value)) and str(uuid.UUID(value)) == value


def _request(value: Mapping[str, Any]) -> dict[str, str]:
    fields = {"host", "leaseId", "stageCorrelationId", "serverCorrelationId", "correlationId",
              "sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"}
    if not isinstance(value, Mapping) or set(value) != fields or value.get("host") != "archlinux":
        raise WindowsFixturePythonAcquireTransferError("CP117 Python transfer requires its exact binding.")
    if not all(_canonical(value[name]) for name in ("leaseId", "stageCorrelationId", "serverCorrelationId", "correlationId")):
        raise WindowsFixturePythonAcquireTransferError("CP117 Python transfer correlation is invalid.")
    if len({value[part] for part in ("leaseId", "stageCorrelationId", "serverCorrelationId", "correlationId")}) != 4:
        raise WindowsFixturePythonAcquireTransferError("CP117 Python transfer correlations must be distinct.")
    for name, pattern in (("sourceSha", _SHA), ("fixtureReceiptArtifactId", _ARTIFACT),
                          ("baseMsiArtifactId", _ARTIFACT), ("targetMsiArtifactId", _ARTIFACT)):
        if not isinstance(value[name], str) or not pattern.fullmatch(value[name]):
            raise WindowsFixturePythonAcquireTransferError("CP117 Python transfer binding is invalid.")
    return dict(value)


def _server_request(request: Mapping[str, str]) -> dict[str, str]:
    return {key: request[key] for key in ("host", "leaseId", "stageCorrelationId", "serverCorrelationId",
                                          "sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId",
                                          "targetMsiArtifactId")}


def _directory(root: Path, create: bool) -> Path | None:
    path = root / _GROUP
    if not path.exists() and not path.is_symlink():
        if not create:
            return None
        path.mkdir(parents=True, mode=0o700)
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise WindowsFixturePythonAcquireTransferError("CP117 Python transfer journal is unsafe.")
    return path


def _intent_path(root: Path, correlation: str) -> Path:
    return root / _GROUP / (correlation + ".json")


def _read(root: Path, correlation: str) -> dict[str, Any] | None:
    directory = _directory(root, False)
    if directory is None:
        return None
    try:
        fd = os.open(directory / (correlation + ".json"), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8192:
            raise WindowsFixturePythonAcquireTransferError("CP117 Python transfer intent is unsafe.")
        record = json.load(stream)
    if (not isinstance(record, dict) or set(record) != {"version", "request", "sha256", "size", "url"}
            or record.get("version") != 1 or record.get("sha256") != SHA256 or record.get("size") != SIZE_BYTES
            or record.get("url") != URL or record.get("request", {}).get("correlationId") != correlation):
        raise WindowsFixturePythonAcquireTransferError("CP117 Python transfer intent is invalid.")
    _request(record["request"])
    return record


def _reserve(root: Path, request: Mapping[str, str]) -> None:
    directory = _directory(root, True)
    assert directory is not None
    lock = os.open(directory / ".environment.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        raw = json.dumps({"version": 1, "request": dict(request), "sha256": SHA256, "size": SIZE_BYTES, "url": URL},
                         sort_keys=True, separators=(",", ":")).encode()
        fd = os.open(_intent_path(root, request["correlationId"]), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    finally:
        os.close(lock)


def _dispatch_path(root: Path, correlation: str) -> Path:
    return root / _GROUP / (correlation + ".dispatch.json")


def _write_dispatch(root: Path, correlation: str, command: str) -> None:
    raw = json.dumps({"version": 3, "commandSha256": hashlib.sha256(command.encode()).hexdigest()},
                     sort_keys=True, separators=(",", ":")).encode()
    fd = os.open(_dispatch_path(root, correlation), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def _dispatch(root: Path, correlation: str) -> dict[str, Any] | None:
    try: fd = os.open(_dispatch_path(root, correlation), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError: return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1024:
            raise WindowsFixturePythonAcquireTransferError("CP117 Python transfer dispatch is unsafe.")
        value = json.load(stream)
    if (not isinstance(value, dict) or set(value) != {"version", "commandSha256"}
            or value.get("version") not in {1, 2, 3}
            or not isinstance(value.get("commandSha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", value["commandSha256"])):
        raise WindowsFixturePythonAcquireTransferError("CP117 Python transfer dispatch is invalid.")
    return value



_GUEST_DOWNLOAD_PS = r'''$ErrorActionPreference='Stop';$sid=@SID@;$leaf=@LEAF@;$task=@TASK@;$command=@COMMAND@
if((Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $leaf)){throw 'EXISTS'}
$action=New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$command)
$principal=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $task -Action $action -Principal $principal|Out-Null;Start-ScheduledTask -TaskName $task
@{version=1;state='submitted'}|ConvertTo-Json -Compress'''


_REMOTE_GUEST = base._QGA + r'''import time
root,env,sock,pid,ticks,encoded=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if env!='windows-cp117' or not live(sock,pid,ticks):raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 for _ in range(160):
  result=call(sock,'guest-exec-status',{'pid':child})
  if result.get('exited') is True:break
  time.sleep(.2)
 else:raise ValueError()
 if result.get('exitcode')!=0 or result.get('out-truncated') is not False or result.get('err-truncated') is not False:raise ValueError()
 raw=base64.b64decode(result.get('out-data',''),validate=True)
 if not 0<len(raw)<=1024 or json.loads(decode(raw))!={'version':1,'state':'submitted'}:raise ValueError()
 out({'state':'submitted'})
except Exception:out({'state':'unknown'})'''

_GUEST_STATUS_PS = r'''$ErrorActionPreference='Stop';$sid=@SID@;$leaf=@LEAF@;$installer=@INSTALLER@;$task=@TASK@;$arguments=@ARGUMENTS@;$sha=@SHA@;$size=@SIZE@
$out=@{version=1;task='absent';leaf='absent';installer='absent';result='absent'}
try{$d=Get-Item -LiteralPath $leaf -Force -ErrorAction Stop;if(!$d.PSIsContainer -or ($d.Attributes-band [IO.FileAttributes]::ReparsePoint)){throw 'LEAF'};$owner=(Get-Acl -LiteralPath $leaf).GetOwner([Security.Principal.SecurityIdentifier]).Value;if($owner -cne $sid){throw 'OWNER'};$out.leaf='verified'}catch{}
try{$i=Get-Item -LiteralPath $installer -Force -ErrorAction Stop;$sig=Get-AuthenticodeSignature -LiteralPath $installer;if(!$i.PSIsContainer -and !($i.Attributes-band [IO.FileAttributes]::ReparsePoint) -and $i.Length -eq $size -and (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $sha -and $sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'Python Software Foundation'){$out.installer='verified'}}catch{}
try{$t=Get-ScheduledTask -TaskPath '\' -TaskName $task -ErrorAction Stop;$a=$t.Actions[0];$p=$t.Principal;$principalSid=if($p.UserId -match '^S-1-'){([Security.Principal.SecurityIdentifier]::new($p.UserId)).Value}else{([Security.Principal.NTAccount]::new($p.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value};if($t.TaskPath -cne '\' -or $t.Actions.Count -ne 1 -or $a.Execute -cne 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -or $a.Arguments -cne $arguments -or $principalSid -cne $sid -or $p.LogonType.ToString() -cne 'Interactive' -or $p.RunLevel.ToString() -cne 'Limited'){throw 'TASK'};$out.task=($t.State.ToString().ToLowerInvariant());$info=Get-ScheduledTaskInfo -TaskPath '\' -TaskName $task -ErrorAction Stop;if($out.task -in @('running','queued')){$out.result='running'}elseif($out.task -eq 'ready' -and $info.LastRunTime -ne [datetime]::MinValue -and $info.LastTaskResult -eq 0){$out.result='succeeded'}elseif($out.task -eq 'ready' -and $info.LastRunTime -ne [datetime]::MinValue -and $info.LastTaskResult -ne 267009){$out.result='failed'}else{$out.result='unknown'}}catch{if($out.task -ne 'absent'){$out.task='mismatch'}}
$out|ConvertTo-Json -Compress'''

_GUEST_FAILURE_PS = r'''$ErrorActionPreference='Stop';$sid=@SID@;$leaf=@LEAF@;$task=@TASK@;$sha=@SHA@;$size=@SIZE@
$out=@{version=1;task='unknown';resultCode='unknown';partial='unknown';signer='not-checked';parseErrors='unknown';phase='unknown'}
try{$t=Get-ScheduledTask -TaskPath '\' -TaskName $task -ErrorAction Stop;$p=$t.Principal;$principalSid=if($p.UserId -match '^S-1-'){([Security.Principal.SecurityIdentifier]::new($p.UserId)).Value}else{([Security.Principal.NTAccount]::new($p.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value};if($t.TaskPath -cne '\' -or $principalSid -cne $sid -or $p.LogonType.ToString() -cne 'Interactive' -or $p.RunLevel.ToString() -cne 'Limited'){throw 'TASK'};$i=Get-ScheduledTaskInfo -TaskPath '\' -TaskName $task -ErrorAction Stop;if($i.LastRunTime -eq [datetime]::MinValue){throw 'NOT_RUN'};$out.task='exact';$out.resultCode=[int64]$i.LastTaskResult;$out.parseErrors=0}catch{}
try{$d=Get-Item -LiteralPath $leaf -Force -ErrorAction Stop;if(!$d.PSIsContainer -or ($d.Attributes-band [IO.FileAttributes]::ReparsePoint) -or (Get-Acl -LiteralPath $leaf).GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $sid){throw 'LEAF'};$p=@PARTIAL@;if(-not (Test-Path -LiteralPath $p)){$out.partial='absent'}else{$f=Get-Item -LiteralPath $p -Force -ErrorAction Stop;if($f.PSIsContainer -or ($f.Attributes-band [IO.FileAttributes]::ReparsePoint)){throw 'TYPE'};if($f.Length -ne $size){$out.partial='incomplete'}elseif((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sha){$out.partial='digest-mismatch'}else{$out.partial='digest-verified';$s=Get-AuthenticodeSignature -LiteralPath $p;$out.signer=if($s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -match 'Python Software Foundation'){'valid'}else{'invalid'}}}}catch{}
try{$r=Join-Path $leaf 'download-result.json';$item=Get-Item -LiteralPath $r -Force -ErrorAction Stop;if($item.PSIsContainer -or ($item.Attributes-band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 256){throw 'RECEIPT'};$receipt=Get-Content -LiteralPath $r -Raw -ErrorAction Stop|ConvertFrom-Json;if($receipt.version -eq 2 -and $receipt.phase -in @('identity','leaf','network','headers','body','write','hash','signer','move')){$out.phase=$receipt.phase}}catch{}
$out|ConvertTo-Json -Compress'''

_REMOTE_GUEST_STATUS = _REMOTE_GUEST.replace("encoded=sys.argv[1:]", "encoded=sys.argv[1:]").replace("json.loads(decode(raw))!={'version':1,'state':'submitted'}", "not isinstance(json.loads(decode(raw)),dict)").replace("out({'state':'submitted'})", "out({'state':'observed','value':json.loads(decode(raw))})")

_GUEST_PARSE_PS = r'''$ErrorActionPreference='Stop';$encoded=@COMMAND@;$sid=@SID@
$script=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded));$tokens=$null;$errors=$null
[Management.Automation.Language.Parser]::ParseInput($script,[ref]$tokens,[ref]$errors)|Out-Null
$account=([Security.Principal.NTAccount]::new('VPNMSIX64\vpncp117')).Translate([Security.Principal.SecurityIdentifier]).Value
$scheduler=(Get-Service -Name Schedule -ErrorAction Stop).Status.ToString()
@{version=1;parseErrors=@($errors).Count;accountMatches=($account -ceq $sid);schedulerRunning=($scheduler -ceq 'Running')}|ConvertTo-Json -Compress'''


def _guest_parse(config: Any, target: Any, guest: tuple[str, int, int, str], command: str) -> bool:
    socket, pid, ticks, sid = guest
    script = _GUEST_PARSE_PS.replace("@COMMAND@", server.public._ps_literal(command)).replace("@SID@", server.public._ps_literal(sid))
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    raw = base._remote(config, _REMOTE_GUEST_STATUS,
                       (str(target.fixture_transfer_root), "windows-cp117", socket, str(pid), str(ticks), encoded),
                       None, 30)
    try:
        outer = json.loads(raw) if raw is not None else None
        value = outer.get("value") if isinstance(outer, dict) and outer.get("state") == "observed" else None
    except (TypeError, ValueError):
        value = None
    return (isinstance(value, dict) and set(value) == {"version", "parseErrors", "accountMatches", "schedulerRunning"}
            and value.get("version") == 1 and value.get("parseErrors") == 0
            and value.get("accountMatches") is True and value.get("schedulerRunning") is True)


def _download_command(correlation: str, sid: str) -> str:
    leaf = r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-python-bootstrap-" + correlation
    destination = leaf + r"\python-3.13.15-amd64.exe"
    partial = destination + ".partial"
    inner = ("$ErrorActionPreference='Stop';$sid=" + server.public._ps_literal(sid)
             + ";if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $sid){throw 'SID'}"
             + ";if((Get-Process -Id $PID).SessionId -ne 1){throw 'SESSION'}"
             + ";$leaf=" + server.public._ps_literal(leaf) + ";[IO.Directory]::CreateDirectory($leaf)|Out-Null"
             + ";$u=" + server.public._ps_literal(URL) + ";$d=" + server.public._ps_literal(destination) + ";$partial=" + server.public._ps_literal(partial)
             + ";$h=" + server.public._ps_literal(SHA256) + ";$n=" + str(SIZE_BYTES)
             + ";if((Test-Path -LiteralPath $d) -or (Test-Path -LiteralPath $partial)){throw 'EXISTS'};$handler=[Net.Http.HttpClientHandler]::new();$handler.AllowAutoRedirect=$false;$c=[Net.Http.HttpClient]::new($handler);try{$r=$c.GetAsync($u,[Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult();try{if(-not $r.IsSuccessStatusCode -or $r.Content.Headers.ContentLength -ne $n){throw 'HTTP'};$b=$r.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();if($b.Length -ne $n -or ([BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash($b))).Replace('-','').ToLowerInvariant() -cne $h){throw 'HASH'};[IO.File]::WriteAllBytes($partial,$b);$sig=Get-AuthenticodeSignature -LiteralPath $partial;if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Python Software Foundation'){throw 'SIGNER'};[IO.File]::Move($partial,$d)}finally{$r.Dispose()}}finally{$c.Dispose();$handler.Dispose()}")
    return base64.b64encode(inner.encode("utf-16le")).decode("ascii")


_download_command_v1 = _download_command


def _download_command(correlation: str, sid: str) -> str:
    """Version 2 records only the fixed stage on a terminal task failure."""
    inner = base64.b64decode(_download_command_v1(correlation, sid)).decode("utf-16le")
    stages = ((";$leaf=", ";$phase='leaf';$leaf="),
              (";$handler=", ";$phase='network';$handler="),
              ("try{if(-not $r.IsSuccessStatusCode", "try{$phase='headers';if(-not $r.IsSuccessStatusCode"),
              (";$b=$r.Content.ReadAsByteArrayAsync()", ";$phase='body';$b=$r.Content.ReadAsByteArrayAsync()"),
              (";[IO.File]::WriteAllBytes($partial,$b)", ";$phase='write';[IO.File]::WriteAllBytes($partial,$b)"),
              (";$sig=Get-AuthenticodeSignature", ";$phase='signer';$sig=Get-AuthenticodeSignature"),
              (";[IO.File]::Move($partial,$d)", ";$phase='move';[IO.File]::Move($partial,$d)"))
    for original, replacement in stages:
        if inner.count(original) != 1:
            raise WindowsFixturePythonAcquireTransferError("Pinned Python command stage changed.")
        inner = inner.replace(original, replacement)
    leaf = r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-python-bootstrap-" + correlation
    receipt = leaf + r"\download-result.json"
    catch = ("catch{$reason=@{version=2;phase=$phase}|ConvertTo-Json -Compress;"
             "try{[IO.File]::WriteAllText(" + server.public._ps_literal(receipt)
             + ",$reason,[Text.UTF8Encoding]::new($false))}catch{};throw}")
    wrapped = "$phase='identity';try{" + inner + "}" + catch
    return base64.b64encode(wrapped.encode("utf-16le")).decode("ascii")


_download_command_v2 = _download_command


_DOWNLOAD_V3_PS = r'''$ErrorActionPreference='Stop';$phase='identity'
try{
 $sid=@SID@
 if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $sid){throw 'SID'}
 if((Get-Process -Id $PID).SessionId -ne 1){throw 'SESSION'}
 $phase='leaf';$leaf=@LEAF@;[IO.Directory]::CreateDirectory($leaf)|Out-Null
 $url=@URL@;$final=@FINAL@;$partial=@PARTIAL@;$expected=@SHA@;$size=@SIZE@
 if((Test-Path -LiteralPath $final) -or (Test-Path -LiteralPath $partial)){throw 'EXISTS'}
 $phase='network';$request=[Net.HttpWebRequest]::Create($url)
 $request.Method='GET';$request.AllowAutoRedirect=$false;$request.Timeout=60000;$request.ReadWriteTimeout=60000
 $response=$request.GetResponse()
 try{
  $phase='headers'
  if([int]$response.StatusCode -ne 200 -or $response.ContentLength -ne $size){throw 'HEADERS'}
  $phase='body';$networkStream=$response.GetResponseStream()
  $output=[IO.File]::Open($partial,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{
   $buffer=New-Object byte[] 65536;$count=[int64]0
   while(($got=$networkStream.Read($buffer,0,$buffer.Length)) -gt 0){$count+=$got;if($count -gt $size){throw 'LENGTH'};$output.Write($buffer,0,$got)}
   $output.Flush($true)
  }finally{$output.Dispose();$networkStream.Dispose()}
  if($count -ne $size){throw 'LENGTH'}
 }finally{$response.Close()}
 $phase='hash';if((Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected){throw 'HASH'}
 $phase='signer';$signature=Get-AuthenticodeSignature -LiteralPath $partial
 if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Python Software Foundation'){throw 'SIGNER'}
 $phase='move';[IO.File]::Move($partial,$final)
}catch{
 try{$receipt=@{version=2;phase=$phase}|ConvertTo-Json -Compress;[IO.File]::WriteAllText(@RECEIPT@,$receipt,[Text.UTF8Encoding]::new($false))}catch{}
 throw
}'''


def _download_command(correlation: str, sid: str) -> str:
    """Version 3 uses the same Windows request stack as the successful HEAD."""
    leaf = r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-python-bootstrap-" + correlation
    final = leaf + r"\python-3.13.15-amd64.exe"
    values = {"SID": sid, "LEAF": leaf, "URL": URL, "FINAL": final,
              "PARTIAL": leaf + r"\python-3.13.15-amd64.partial.exe", "SHA": SHA256,
              "RECEIPT": leaf + r"\download-result.json"}
    script = _DOWNLOAD_V3_PS.replace("@SIZE@", str(SIZE_BYTES))
    for name, value in values.items():
        script = script.replace("@" + name + "@", server.public._ps_literal(value))
    return base64.b64encode(script.encode("utf-16le")).decode("ascii")


def _command_for(dispatch: Mapping[str, Any], correlation: str, sid: str) -> str:
    versions = {1: _download_command_v1, 2: _download_command_v2, 3: _download_command}
    return versions[dispatch["version"]](correlation, sid)


def _encoded_download(correlation: str, sid: str) -> str:
    leaf = r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-python-bootstrap-" + correlation
    command = _download_command(correlation, sid)
    script = (_GUEST_DOWNLOAD_PS.replace("@SID@", server.public._ps_literal(sid))
              .replace("@LEAF@", server.public._ps_literal(leaf)).replace("@TASK@", server.public._ps_literal("VpnControlMcpCp95Acquire-" + correlation))
              .replace("@COMMAND@", server.public._ps_literal(command)))
    return base64.b64encode(script.encode("utf-16le")).decode("ascii")


def _encoded_status(correlation: str, sid: str, dispatch: Mapping[str, Any]) -> str:
    leaf = r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-python-bootstrap-" + correlation
    command = _command_for(dispatch, correlation, sid)
    arguments = "-NoProfile -NonInteractive -EncodedCommand " + command
    script = (_GUEST_STATUS_PS.replace("@SID@", server.public._ps_literal(sid)).replace("@LEAF@", server.public._ps_literal(leaf))
              .replace("@INSTALLER@", server.public._ps_literal(leaf + r"\python-3.13.15-amd64.exe"))
              .replace("@TASK@", server.public._ps_literal("VpnControlMcpCp95Acquire-" + correlation))
              .replace("@ARGUMENTS@", server.public._ps_literal(arguments)).replace("@SHA@", server.public._ps_literal(SHA256)).replace("@SIZE@", str(SIZE_BYTES)))
    return base64.b64encode(script.encode("utf-16le")).decode("ascii")


def _encoded_failure(correlation: str, sid: str, dispatch: Mapping[str, Any]) -> str:
    leaf = r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-python-bootstrap-" + correlation
    script = (_GUEST_FAILURE_PS.replace("@SID@", server.public._ps_literal(sid))
              .replace("@LEAF@", server.public._ps_literal(leaf))
              .replace("@TASK@", server.public._ps_literal("VpnControlMcpCp95Acquire-" + correlation))
              .replace("@PARTIAL@", server.public._ps_literal(leaf + (r"\python-3.13.15-amd64.partial.exe" if dispatch["version"] == 3 else r"\python-3.13.15-amd64.exe.partial")))
              .replace("@SHA@", server.public._ps_literal(SHA256)).replace("@SIZE@", str(SIZE_BYTES)))
    return base64.b64encode(script.encode("utf-16le")).decode("ascii")


def failure_detail(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read finite task and partial-file facts for a terminal failed download."""
    root = Path(root).resolve(strict=True)
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or not _canonical(value.get("correlationId")):
        raise WindowsFixturePythonAcquireTransferError("CP117 Python failure detail requires its correlation.")
    correlation = value["correlationId"]
    if status(root, value).get("state") != "failed":
        return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    record = _read(root, correlation); dispatch = _dispatch(root, correlation)
    if record is None or dispatch is None:
        return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    try:
        config, target, guest = _admit(root, record["request"])
        socket, pid, ticks, sid = guest
        if dispatch["commandSha256"] != hashlib.sha256(_command_for(dispatch, correlation, sid).encode()).hexdigest():
            return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
        raw = base._remote(config, _REMOTE_GUEST_STATUS,
                           (str(target.fixture_transfer_root), "windows-cp117", socket, str(pid), str(ticks),
                            _encoded_failure(correlation, sid, dispatch)), None, 40)
        outer = json.loads(raw) if raw is not None else None
        detail = outer.get("value") if isinstance(outer, dict) and outer.get("state") == "observed" else None
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        detail = None
    valid = (isinstance(detail, dict) and set(detail) == {"version", "task", "resultCode", "partial", "signer", "parseErrors", "phase"}
             and detail.get("version") == 1 and detail.get("task") == "exact"
             and type(detail.get("resultCode")) is int and -2147483648 <= detail["resultCode"] <= 4294967295
             and detail.get("partial") in {"absent", "incomplete", "digest-mismatch", "digest-verified", "unknown"}
             and detail.get("signer") in {"valid", "invalid", "not-checked"}
             and type(detail.get("parseErrors")) is int and 0 <= detail["parseErrors"] <= 64
             and detail.get("phase") in {"unknown", "identity", "leaf", "network", "headers", "body", "write", "hash", "signer", "move"})
    if not valid:
        return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    return {"state": "observed", "correlationId": correlation,
            "resultCode": detail["resultCode"], "partial": detail["partial"],
            "signer": detail["signer"], "parseErrors": detail["parseErrors"],
            "phase": detail["phase"], "replayAllowed": False}


def _guest_status(config: Any, target: Any, guest: tuple[str, int, int, str], correlation: str, dispatch: Mapping[str, Any]) -> dict[str, str] | None:
    socket, pid, ticks, sid = guest
    if dispatch.get("commandSha256") != hashlib.sha256(_command_for(dispatch, correlation, sid).encode()).hexdigest():
        return None
    raw = base._remote(config, _REMOTE_GUEST_STATUS, (str(target.fixture_transfer_root), "windows-cp117", socket, str(pid), str(ticks), _encoded_status(correlation, sid, dispatch)), None, 40)
    try: outer = json.loads(raw) if raw is not None else None; value = outer.get("value") if isinstance(outer, dict) and outer.get("state") == "observed" else None
    except (TypeError, ValueError): value = None
    fields = {"version", "task", "leaf", "installer", "result"}
    if (not isinstance(value, dict) or set(value) != fields or value.get("version") != 1
            or value.get("task") not in {"absent", "ready", "running", "queued", "disabled", "mismatch"}
            or value.get("leaf") not in {"absent", "verified"} or value.get("installer") not in {"absent", "verified"}
            or value.get("result") not in {"absent", "running", "succeeded", "failed", "unknown"}): return None
    return {key: value[key] for key in ("task", "leaf", "installer", "result")}


def reconcile(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read the durable direct-download intent; no listener or retry exists."""
    root = Path(root).resolve(strict=True)
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or not _canonical(value.get("correlationId")):
        raise WindowsFixturePythonAcquireTransferError("CP117 Python reconciliation requires its correlation.")
    record = _read(root, value["correlationId"]); dispatch = _dispatch(root, value["correlationId"])
    if record is None or dispatch is None: return {**_UNKNOWN, "correlationId": value["correlationId"]}
    try:
        config, target, guest = _admit(root, record["request"])
        observed = _guest_status(config, target, guest, value["correlationId"], dispatch)
        if observed is None: return {**_UNKNOWN, "correlationId": value["correlationId"]}
        return {"state": "observed", "correlationId": value["correlationId"], "replayAllowed": False}
    except (OSError, ValueError, subprocess.SubprocessError): return {**_UNKNOWN, "correlationId": value["correlationId"]}


def _admit(root: Path, request: Mapping[str, str]) -> tuple[Any, Any, tuple[str, int, int, str]]:
    pair, guest = server._admit_campaign(root, _server_request(request), require_credentials=True)
    if server._python_candidates(root, _server_request(request)):
        raise WindowsFixturePythonAcquireTransferError("CP117 already has a Python candidate.")
    config, target, descriptor = base._descriptor(root)
    env, socket, pid, ticks, sid = descriptor
    if env != "windows-cp117" or (socket, pid, ticks, sid) != guest or not _SID.fullmatch(sid):
        raise WindowsFixturePythonAcquireTransferError("CP117 guest generation changed.")
    return config, target, guest


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    root = Path(root).resolve(strict=True); request = _request(value); correlation = request["correlationId"]
    prior = _read(root, correlation)
    if prior is not None:
        if prior["request"] != request:
            raise WindowsFixturePythonAcquireTransferError("CP117 Python correlation binds another request.")
        return {**_UNKNOWN, "correlationId": correlation}
    config, target, guest = _admit(root, request)
    command = _download_command(correlation, guest[3])
    if not _guest_parse(config, target, guest, command):
        raise WindowsFixturePythonAcquireTransferError("CP117 pinned download command is not admitted in the guest.")
    _reserve(root, request)  # Durable before any Arch or guest state change.
    try:
        socket, pid, ticks, sid = guest
        _write_dispatch(root, correlation, command)
        raw = base._remote(config, _REMOTE_GUEST, (str(target.fixture_transfer_root), "windows-cp117", socket,
                           str(pid), str(ticks), _encoded_download(correlation, sid)), None, 90)
        if raw == b'{"state":"submitted"}\n':
            return {"state": "submitted", "correlationId": correlation, "replayAllowed": False}
        return {**_UNKNOWN, "correlationId": correlation}
    except (OSError, ValueError, subprocess.SubprocessError):
        return {**_UNKNOWN, "correlationId": correlation}


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    root = Path(root).resolve(strict=True)
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or not _canonical(value.get("correlationId")):
        raise WindowsFixturePythonAcquireTransferError("CP117 Python transfer status requires its correlation.")
    record = _read(root, value["correlationId"])
    if record is None:
        return {"state": "intent-absent", "correlationId": value["correlationId"], "replayAllowed": False}
    dispatch = _dispatch(root, value["correlationId"])
    if dispatch is None:
        return {"state": "unknown", "correlationId": value["correlationId"], "replayAllowed": False}
    try:
        config, target, guest = _admit(root, record["request"])
        observed = _guest_status(config, target, guest, value["correlationId"], dispatch)
    except (OSError, ValueError, subprocess.SubprocessError):
        observed = None
    if observed is None:
        return {"state": "unknown", "correlationId": value["correlationId"], "replayAllowed": False}
    state = "downloaded" if observed == {"task": "ready", "leaf": "verified", "installer": "verified", "result": "succeeded"} else "failed" if observed["result"] == "failed" or observed["task"] == "mismatch" else "running" if observed["task"] in {"running", "queued"} and observed["result"] == "running" else "blocked"
    return {"state": state, "correlationId": value["correlationId"], "task": observed["task"], "leaf": observed["leaf"], "installer": observed["installer"], "result": observed["result"], "replayAllowed": False}


def collect(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    return status(root, value)
