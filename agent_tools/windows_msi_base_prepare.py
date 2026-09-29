"""One-shot CP117 base MSI preparation for the public update acceptance fixture.

The original-user MSI task is a fixture setup operation. It never submits the
target update. Local and remote reservations deliberately survive uncertainty.
"""
from __future__ import annotations

import base64
from datetime import datetime
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid
from typing import Any, Mapping

from . import ssh_transport, windows_credential_probe_ssh, windows_msi_public_scenario
from . import windows_cp117_lease as campaign_lease


class WindowsMsiBasePrepareError(ValueError):
    pass


_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"(?:[1-9]|1[0-9])\.(?:0|[1-9]|1[0-9])\.(?:0|[1-9]|1[0-9])\Z")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
_LOCAL = ".rag_index/windows-msi-base-prepare"
_PRE_EFFECT_REJECTED_CORRELATION = "30a6f33b-3ea2-42d0-8818-3d6711b34169"
_PRE_EFFECT_REJECTED_COMMAND_SHA256 = "f490e8582bc84145fff84b92a5bb5b05ac6e4593c429289779de8eac5aa713ca"
_PRE_EFFECT_REJECTED_REQUEST = {
    "host": "archlinux", "correlationId": _PRE_EFFECT_REJECTED_CORRELATION,
    "sourceSha": "a876f46fa4582e6218d341ac7012fd31bc919758",
    "fixtureReceiptArtifactId": "sha256-086cf41006f4340e378123220b51c21f97649193b59237c529231727b2e29782",
    "baseMsiArtifactId": "sha256-9a63e408ef6856234a2b40c121ede02a60482b5e8a6d8e624f3bd7bf70bce476",
    "targetMsiArtifactId": "sha256-dff5b596f13fb0c9469ed4b9a4f67eaea9211f2a457e99697739b034731448b7",
    "expectedCurrentVersion": "2.1.17"}
_ROOT = r"C:\Users\vpncp117\AppData\Local\VpnControl"
_ACCOUNT = r"VPNMSIX64\vpncp117"
_PRODUCT = re.compile(r"\{[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}\Z")
_INSTALL = "C:\\Users\\vpncp117\\AppData\\Local\\vpn-control\\"
_LEGACY_CORRELATION = "99126312-977f-4a61-a9ef-fb6884d2d26f"
_LEGACY_JOB = "9107428f-9c80-4284-9f4e-926350105a59"


def _request(value: Mapping[str, Any]) -> dict[str, str]:
    fields = {"host", "correlationId", "sourceSha", "fixtureReceiptArtifactId",
              "baseMsiArtifactId", "targetMsiArtifactId", "expectedCurrentVersion"}
    if not isinstance(value, Mapping) or set(value) != fields or value.get("host") != "archlinux":
        raise WindowsMsiBasePrepareError("Windows base preparation requires exact CP117 inputs.")
    for key, pattern in (("correlationId", _UUID), ("sourceSha", _SHA),
                         ("fixtureReceiptArtifactId", _ARTIFACT), ("baseMsiArtifactId", _ARTIFACT),
                         ("targetMsiArtifactId", _ARTIFACT), ("expectedCurrentVersion", _VERSION)):
        if not isinstance(value[key], str) or not pattern.fullmatch(value[key]):
            raise WindowsMsiBasePrepareError("Invalid Windows base preparation " + key + ".")
    if str(uuid.UUID(value["correlationId"])) != value["correlationId"]:
        raise WindowsMsiBasePrepareError("Correlation is not canonical.")
    return dict(value)


def _intent_path(root: Path, correlation: str) -> Path:
    return root / _LOCAL / (correlation + ".json")


def _private_intent(root: Path, correlation: str) -> dict[str, Any] | None:
    path = _intent_path(root, correlation)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8192:
            raise WindowsMsiBasePrepareError("Base preparation intent is unsafe.")
        record = json.load(stream)
    if not isinstance(record, dict) or record.get("request", {}).get("correlationId") != correlation:
        raise WindowsMsiBasePrepareError("Base preparation intent is invalid.")
    return record


def _pre_effect_marker(root: Path) -> Path:
    return root / _LOCAL / (_PRE_EFFECT_REJECTED_CORRELATION + ".pre-effect-closed.json")


def _pre_effect_closed(root: Path) -> bool:
    intent = _private_intent(root, _PRE_EFFECT_REJECTED_CORRELATION)
    if (intent is None or intent.get("request") != _PRE_EFFECT_REJECTED_REQUEST
            or intent.get("commandSha256") != _PRE_EFFECT_REJECTED_COMMAND_SHA256
            or intent.get("environment") != "windows-cp117"
            or intent.get("pid") != 589342 or intent.get("startTicks") != 520739
            or not isinstance(intent.get("socketPath"), str)
            or not isinstance(intent.get("expectedSid"), str)):
        return False
    marker = _pre_effect_marker(root)
    try: fd = os.open(marker, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError: return False
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8192):
            raise WindowsMsiBasePrepareError("Base pre-effect closure is unsafe.")
        marker_value = json.load(stream)
    if (not isinstance(marker_value, dict) or set(marker_value) != {
            "correlationId", "commandSha256", "state", "cleanupReceiptSha256"}
            or marker_value.get("correlationId") != _PRE_EFFECT_REJECTED_CORRELATION
            or marker_value.get("commandSha256") != _PRE_EFFECT_REJECTED_COMMAND_SHA256
            or marker_value.get("state") != "pre-effect-closed"
            or not isinstance(marker_value.get("cleanupReceiptSha256"), str)
            or not _HASH.fullmatch(marker_value["cleanupReceiptSha256"])):
        return False
    directory, lock = campaign_lease._locked(root)
    try:
        closed = campaign_lease._closed(directory, _PRE_EFFECT_REJECTED_CORRELATION)
    finally: os.close(lock)
    expected_identity = _campaign_identity(_PRE_EFFECT_REJECTED_REQUEST,
        (intent["environment"], intent["socketPath"], intent["pid"],
         intent["startTicks"], intent["expectedSid"]))
    return (closed is not None and closed["identity"] == expected_identity
            and closed["lastOutcome"] == "failed-cleaned"
            and closed["lastEvidenceSha256"] == marker_value["cleanupReceiptSha256"]
            and intent["pid"] == 589342 and intent["startTicks"] == 520739)


def _reserve(root: Path, record: dict[str, Any]) -> None:
    directory = root / _LOCAL
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise WindowsMsiBasePrepareError("Base preparation journal is unsafe.")
    lock_fd = os.open(directory / ".environment.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        archived = _pre_effect_closed(root)
        if any(item.suffix == ".json" and not (archived and item.name in {
                _PRE_EFFECT_REJECTED_CORRELATION + ".json",
                _PRE_EFFECT_REJECTED_CORRELATION + ".pre-effect-closed.json"})
                for item in directory.iterdir()):
            raise WindowsMsiBasePrepareError("CP117 has an active or unknown base preparation.")
        path = _intent_path(root, record["request"]["correlationId"])
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write((json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode())
            stream.flush(); os.fsync(stream.fileno())
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        os.close(lock_fd)


def _descriptor(root: Path):
    config = ssh_transport.load_config(root)
    target = config.hosts.get("archlinux")
    if target is None or target.fixture_transfer_root is None:
        raise WindowsMsiBasePrepareError("Owned Windows transfer host is unavailable.")
    env, socket, pid, ticks, account, sid, _ = windows_credential_probe_ssh._descriptor(target)
    if env != "windows-cp117" or account != "vpncp117":
        raise WindowsMsiBasePrepareError("Owned CP117 guest identity changed.")
    return config, target, (env, socket, pid, ticks, sid)


def _admit(root: Path, request: dict[str, str]) -> tuple[dict[str, Any], Path, int]:
    pair = windows_msi_public_scenario._admit_pair(root, request["sourceSha"],
        request["fixtureReceiptArtifactId"], request["baseMsiArtifactId"], request["targetMsiArtifactId"])
    if tuple(map(int, pair["baseVersion"].split("."))) <= tuple(map(int, request["expectedCurrentVersion"].split("."))):
        raise WindowsMsiBasePrepareError("Base MSI must be newer than the installed version.")
    path = windows_msi_public_scenario._verified_location(root, request["baseMsiArtifactId"],
                                                            "desktop-package", request["sourceSha"])
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or not 0 < info.st_size <= 1024 * 1024 * 1024:
        raise WindowsMsiBasePrepareError("Base MSI location is unsafe.")
    return pair, path, info.st_size


def _unique_product(value: Any, version: str) -> bool:
    """Accept one exact HKLM/HKCU registration for CP117's original user."""
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        return False
    product = value[0]
    return (set(product) == {"version", "productCode", "installLocation", "hive"}
            and product["hive"] in {"HKLM", "HKCU"}
            and product["version"] == version
            and isinstance(product["productCode"], str) and bool(_PRODUCT.fullmatch(product["productCode"]))
            and isinstance(product["installLocation"], str)
            and product["installLocation"].rstrip("\\").casefold() == _INSTALL.rstrip("\\").casefold())


_QGA = r'''import base64,hashlib,json,os,secrets,socket,stat,sys
def live(sock,pid,ticks):
 if not stat.S_ISSOCK(os.lstat(sock).st_mode):return False
 raw=open('/proc/%s/stat'%pid,'rb').read().split()
 if len(raw)<22 or raw[21].decode()!=ticks:return False
 inodes=set()
 for name in os.listdir('/proc/%s/fd'%pid):
  try:
   link=os.readlink('/proc/%s/fd/%s'%(pid,name))
   if link.startswith('socket:[') and link.endswith(']'):inodes.add(link[8:-1].encode())
  except OSError:pass
 return any(len(f)==8 and f[6] in inodes and f[7]==os.fsencode(sock) for f in (line.split() for line in open('/proc/net/unix','rb')))
def call(sock,command,args):
 c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);c.settimeout(20)
 try:
  c.connect(sock);sid=secrets.randbits(63)
  c.sendall(b'\xff'+json.dumps({'execute':'guest-sync-delimited','arguments':{'id':sid}},separators=(',',':')).encode()+b'\n')
  for i in range(8192):
   if c.recv(1)==b'\xff':break
  else:raise ValueError()
  def line():
   raw=bytearray()
   for i in range(32768):
    x=c.recv(1)
    if x==b'\n':return json.loads(raw)
    if not x:raise ValueError()
    raw.extend(x)
   raise ValueError()
  if line().get('return')!=sid:raise ValueError()
  c.sendall(json.dumps({'execute':command,'arguments':args},separators=(',',':')).encode()+b'\n')
  result=line()
  if 'return' not in result:raise ValueError()
  return result['return']
 finally:c.close()
def read(sock,path,maxsize=8192):
 try:handle=call(sock,'guest-file-open',{'path':path,'mode':'rb'})
 except ValueError:return None
 raw=bytearray()
 try:
  while len(raw)<maxsize:
   v=call(sock,'guest-file-read',{'handle':handle,'count':min(4096,maxsize-len(raw))})
   part=base64.b64decode(v['buf-b64'],validate=True)
   if v.get('count')!=len(part):raise ValueError()
   raw.extend(part)
   if v.get('eof') is True or not part:return bytes(raw)
  raise ValueError()
 finally:call(sock,'guest-file-close',{'handle':handle})
def decode(raw):
 if raw.startswith(b'\xff\xfe'):return raw.decode('utf-16')
 if raw.startswith(b'\xef\xbb\xbf'):return raw.decode('utf-8-sig')
 return raw.decode('utf-8')
'''


_STAGE = _QGA + campaign_lease.remote_role_guard() + r'''import fcntl,struct
root,env,lease,corr,sock,pid,ticks,expected,size_text,encoded,command_hash,source,fingerprint,receipt_id,base_id,target_id=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if env!='windows-cp117' or not live(sock,pid,ticks):raise ValueError()
 require_campaign_role(root,env,lease,'base',corr,source,receipt_id,base_id,target_id,sock,pid,ticks)
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-msi-base')
 for path in (root,parent,group):
  if not os.path.exists(path):os.mkdir(path,0o700)
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 lock=os.open(os.path.join(group,'.environment.lock'),os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
 try:
  fcntl.flock(lock,fcntl.LOCK_EX)
  if any(name!='.environment.lock' for name in os.listdir(group)):raise FileExistsError()
  # Earlier public receipts remain archival; fixed CP176 terminal/task cleanup
  # is checked before the shared campaign is reserved. The shared remote role
  # guard above serializes all new routes across those historical directories.
  stage=os.path.join(group,corr);os.mkdir(stage,0o700)
 finally:os.close(lock)
 binding={'socketPath':sock,'pid':int(pid),'startTicks':int(ticks),'sourceSha':source,'sourceFingerprint':fingerprint,'receiptArtifactId':receipt_id,'baseArtifactId':base_id,'targetArtifactId':target_id,'commandSha256':command_hash,'expectedSid':expected}
 with open(os.path.join(stage,'binding.json'),'x',encoding='utf-8') as file:json.dump(binding,file,separators=(',',':'));file.flush();os.fsync(file.fileno())
 size=int(size_text)
 if not 0<size<=1073741824 or len(encoded)>30000 or hashlib.sha256(base64.b64decode(encoded,validate=True)).hexdigest()!=command_hash:raise ValueError()
 # The first guest mutation creates only this correlation's staging directory.
 guest='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-base-'+corr
 ps='[IO.Directory]::CreateDirectory(\''+guest+'\')|Out-Null'
 create=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(ps.encode('utf-16le')).decode()],'capture-output':True})
 child=create['pid']
 for i in range(30):
  state=call(sock,'guest-exec-status',{'pid':child})
  if state.get('exited') is True:
   if state.get('exitcode')!=0:raise ValueError()
   break
  __import__('time').sleep(.2)
 else:raise ValueError()
 dest=guest+'\\base.msi';handle=call(sock,'guest-file-open',{'path':dest,'mode':'wb'});h=hashlib.sha256();remaining=size
 try:
  while remaining:
   part=sys.stdin.buffer.read(min(49152,remaining))
   if not part:raise ValueError()
   h.update(part);remaining-=len(part);offset=0
   while offset<len(part):
    written=call(sock,'guest-file-write',{'handle':handle,'buf-b64':base64.b64encode(part[offset:]).decode()})['count']
    if type(written) is not int or not 0<written<=len(part)-offset:raise ValueError()
    offset+=written
  if sys.stdin.buffer.read(1):raise ValueError()
  call(sock,'guest-file-flush',{'handle':handle})
 finally:call(sock,'guest-file-close',{'handle':handle})
 if h.hexdigest()!=base_id.removeprefix('sha256-'):raise ValueError()
 result=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})
 child=result['pid']
 with open(os.path.join(stage,'dispatch.json'),'x',encoding='utf-8') as file:json.dump({'pid':child},file,separators=(',',':'));file.flush();os.fsync(file.fileno())
 out({'state':'submitted','correlationId':corr})
except FileExistsError:out({'state':'unknown','reason':'existing-intent','correlationId':corr})
except Exception:out({'state':'unknown','reason':'submission-uncertain','correlationId':corr})
'''


def _task(correlation: str, pair: dict[str, Any], expected_current: str, sid: str) -> str:
    root = _ROOT + "\\mcp-base-" + correlation
    return r"""$ErrorActionPreference='Stop';$root={root};$msi=Join-Path $root 'base.msi';$stage='IDENTITY'
function P([string]$result,[int]$exitCode){{([pscustomobject]@{{version=1;correlationId={corr};stage=$stage;result=$result;exitCode=$exitCode;originalSid=$identity.User.Value;sessionId=(Get-Process -Id $PID).SessionId;limited=$limited;msiSha256=$observedMsiHash;installedVersion=$observedVersion;cliSha256=$observedCliHash;jarSha256=$observedJarHash;helperSha256=$observedHelperHash;priorProducts=$priorProducts;installedProducts=$installedProducts}}|ConvertTo-Json -Depth 5 -Compress)|Set-Content -LiteralPath (Join-Path $root 'result.json') -Encoding UTF8}}
try{{
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$limited=-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if($identity.User.Value -cne {sid} -or (Get-Process -Id $PID).SessionId -ne 1 -or -not $limited){{throw 'IDENTITY'}}
$stage='ADMISSION'
$observedMsiHash=(Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant()
if($observedMsiHash -cne {hash}){{throw 'MSI_HASH'}}
$products=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue|Where-Object {{$_.DisplayName -eq 'vpn-control'}})
if($products.Count -ne 1 -or $products[0].DisplayVersion -cne {current}){{throw 'CURRENT_PRODUCT'}}
$priorProducts=@($products|ForEach-Object {{[pscustomobject]@{{version=$_.DisplayVersion;productCode=$_.PSChildName;installLocation=$_.InstallLocation;hive=$_.PSDrive.Name}}}})
$active=@(Get-CimInstance Win32_Process|Where-Object {{$_.Name -match '^(vpn-control-cli|msiexec|consent|sing-box)\.exe$'}})
if($active.Count -ne 0){{throw 'ACTIVE_PROCESS'}}
$stage='INSTALL';P 'IN_PROGRESS' -1
$arguments='/i "'+$msi+'" /qn /norestart REBOOT=ReallySuppress MSIRESTARTMANAGERCONTROL=Disable ALLUSERS=2 MSIINSTALLPERUSER=1 /L*v "'+(Join-Path $root 'base-msi.log')+'"'
$installer=Start-Process -FilePath 'C:\Windows\System32\msiexec.exe' -ArgumentList $arguments -PassThru -Wait
$stage='READBACK'
$after=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue|Where-Object {{$_.DisplayName -eq 'vpn-control'}})
$cli='C:\Users\vpncp117\AppData\Local\vpn-control\vpn-control-cli.exe'
$jar=Join-Path 'C:\Users\vpncp117\AppData\Local\vpn-control\app' {jar}
$helper='C:\Users\vpncp117\AppData\Local\vpn-control\app\native\windows-amd64\vpn-control-install-helper.exe'
$observedVersion=if($after.Count -eq 1){{$after[0].DisplayVersion}}else{{$null}}
$installedProducts=@($after|ForEach-Object {{[pscustomobject]@{{version=$_.DisplayVersion;productCode=$_.PSChildName;installLocation=$_.InstallLocation;hive=$_.PSDrive.Name}}}})
$observedCliHash=(Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant()
$observedJarHash=(Get-FileHash -LiteralPath $jar -Algorithm SHA256).Hash.ToLowerInvariant()
$observedHelperHash=(Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash.ToLowerInvariant()
$ok=$installer.ExitCode -eq 0 -and $observedVersion -ceq {base_version} -and
 $observedCliHash -ceq {cli_hash} -and $observedJarHash -ceq {jar_hash} -and $observedHelperHash -ceq {helper_hash}
if($ok){{P 'PASSED' $installer.ExitCode}}else{{P 'FAILED' $installer.ExitCode}}
}}catch{{P 'FAILED' -1;exit 1}}
""".format(root=windows_msi_public_scenario._ps_literal(root), corr=windows_msi_public_scenario._ps_literal(correlation),
           sid=windows_msi_public_scenario._ps_literal(sid), hash=windows_msi_public_scenario._ps_literal(pair["baseArtifactId"].removeprefix("sha256-")),
           current=windows_msi_public_scenario._ps_literal(expected_current), base_version=windows_msi_public_scenario._ps_literal(pair["baseVersion"]),
           jar=windows_msi_public_scenario._ps_literal(pair["baseAppJarName"]), cli_hash=windows_msi_public_scenario._ps_literal(pair["baseCliSha256"]),
           jar_hash=windows_msi_public_scenario._ps_literal(pair["baseAppJarSha256"]), helper_hash=windows_msi_public_scenario._ps_literal(pair["baseHelperSha256"]))


def _bootstrap(correlation: str, pair: dict[str, Any], current: str, sid: str) -> str:
    root = _ROOT + "\\mcp-base-" + correlation
    task = "VpnControlMcpBase-" + correlation
    packed_task = base64.b64encode(gzip.compress(_task(correlation, pair, current, sid).encode("utf-16le"), mtime=0)).decode()
    return r"""$ErrorActionPreference='Stop';$root={root};$task={task}
try{{
if(-not [IO.Directory]::Exists($root) -or (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)){{throw 'EXCLUSIVE'}}
$msi=Join-Path $root 'base.msi'
if((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant() -cne {hash}){{throw 'MSI_HASH'}}
$compressed=[Convert]::FromBase64String({packed_task})
$inputStream=[IO.MemoryStream]::new([byte[]]$compressed)
$decompressor=[IO.Compression.GzipStream]::new($inputStream,[IO.Compression.CompressionMode]::Decompress)
$outputStream=[IO.MemoryStream]::new();$decompressor.CopyTo($outputStream)
$body=[Convert]::ToBase64String($outputStream.ToArray())
$decompressor.Dispose();$inputStream.Dispose();$outputStream.Dispose()
$action=New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$body)
$principal=New-ScheduledTaskPrincipal -UserId {account} -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings|Out-Null
Start-ScheduledTask -TaskName $task
([pscustomobject]@{{version=1;correlationId={corr};triggered=$true}}|ConvertTo-Json -Compress)
}}catch{{([pscustomobject]@{{version=1;correlationId={corr};triggered=$false}}|ConvertTo-Json -Compress);exit 1}}
""".format(root=windows_msi_public_scenario._ps_literal(root), task=windows_msi_public_scenario._ps_literal(task),
           hash=windows_msi_public_scenario._ps_literal(pair["baseArtifactId"].removeprefix("sha256-")),
           packed_task=windows_msi_public_scenario._ps_literal(packed_task),
           account=windows_msi_public_scenario._ps_literal(_ACCOUNT), corr=windows_msi_public_scenario._ps_literal(correlation))


def _powershell_preflight_script() -> str:
    """Parse both fixed CP117 programs on PowerShell 5.1 without running them."""
    pair = {"baseArtifactId": "sha256-" + "a" * 64, "baseVersion": "2.1.19",
            "baseCliSha256": "b" * 64, "baseAppJarSha256": "c" * 64,
            "baseHelperSha256": "d" * 64, "baseAppJarName": "desktopApp-fixed.jar"}
    corr = "11111111-1111-4111-8111-111111111111"
    bootstrap = _bootstrap(corr, pair, "2.1.17", "S-1-5-21-1-2-3-1002")
    task = _task(corr, pair, "2.1.17", "S-1-5-21-1-2-3-1002")
    readiness = _readiness_script("2.1.17", "S-1-5-21-1-2-3-1002")
    def packed(value: str) -> str:
        return base64.b64encode(gzip.compress(value.encode("utf-16le"), mtime=0)).decode()
    return r'''$ErrorActionPreference='Stop'
function Expand([string]$body) {
 $packed=[Convert]::FromBase64String($body)
 $inputStream=[IO.MemoryStream]::new([byte[]]$packed)
 $decompressor=[IO.Compression.GzipStream]::new($inputStream,[IO.Compression.CompressionMode]::Decompress)
 $outputStream=[IO.MemoryStream]::new();$decompressor.CopyTo($outputStream)
 $body=[Text.Encoding]::Unicode.GetString($outputStream.ToArray())
 $decompressor.Dispose();$inputStream.Dispose();$outputStream.Dispose()
 return $body
}
try {
 $bootstrap=Expand '@BOOTSTRAP@';$task=Expand '@TASK@';$readiness=Expand '@READINESS@'
 $tokens=$null;$errors=$null
 [System.Management.Automation.Language.Parser]::ParseInput($bootstrap,[ref]$tokens,[ref]$errors)|Out-Null
 if($errors.Count -ne 0){throw 'BOOTSTRAP_SYNTAX'}
 [System.Management.Automation.Language.Parser]::ParseInput($task,[ref]$tokens,[ref]$errors)|Out-Null
 if($errors.Count -ne 0){throw 'TASK_SYNTAX'}
 [System.Management.Automation.Language.Parser]::ParseInput($readiness,[ref]$tokens,[ref]$errors)|Out-Null
 if($errors.Count -ne 0){throw 'READINESS_SYNTAX'}
 [Console]::Out.WriteLine('{"version":1,"code":"OK"}')
}catch{[Console]::Out.WriteLine('{"version":1,"code":"FAILED"}');exit 1}
'''.replace("@BOOTSTRAP@", packed(bootstrap)).replace("@TASK@", packed(task)).replace("@READINESS@", packed(readiness))


def powershell_preflight(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"host"} or value["host"] != "archlinux":
        raise WindowsMsiBasePrepareError("Base PS5 preflight requires exact owned host.")
    root = Path(root).resolve(strict=True)
    config, _, (env, socket, pid, ticks, _) = _descriptor(root)
    if env != "windows-cp117":
        raise WindowsMsiBasePrepareError("Owned CP117 guest identity changed.")
    encoded = base64.b64encode(_powershell_preflight_script().encode("utf-16le")).decode()
    if len(encoded) >= 30000:
        raise WindowsMsiBasePrepareError("Fixed base PS5 preflight exceeds Windows command admission.")
    raw = windows_credential_probe_ssh._run_ssh(config, "archlinux",
        windows_credential_probe_ssh._remote_command(windows_msi_public_scenario._REMOTE_PREFLIGHT,
            socket, str(pid), str(ticks), encoded), None, 30)
    try:
        result = json.loads(raw) if raw is not None else {}
    except (TypeError, ValueError):
        result = {}
    if not isinstance(result, dict) or result.get("state") not in {"passed", "failed"}:
        return {"state": "unknown", "checks": []}
    return {"state": result["state"], "checks": ["ps5-parse", "gzip"]}


def _readiness_script(expected_version: str, expected_sid: str) -> str:
    """Read installed registration and idle original-user session without changes."""
    version = windows_msi_public_scenario._ps_literal(expected_version)
    sid = windows_msi_public_scenario._ps_literal(expected_sid)
    return r'''$ErrorActionPreference='Stop'
try {
 $sid=@SID@;$expected=@VERSION@
 $hku='Registry::HKEY_USERS\'+$sid+'\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
 $hku32='Registry::HKEY_USERS\'+$sid+'\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
 $products=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',$hku,$hku32 -ErrorAction SilentlyContinue|Where-Object {$_.DisplayName -eq 'vpn-control'})
 $active=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match '^(vpn-control-cli|msiexec|consent|sing-box)\.exe$'})
 if($active.Count -gt 16){throw 'ACTIVE_BOUND'}
 $lockPid=$null
 try{$lockRaw=(Get-Content -LiteralPath 'C:\Users\vpncp117\AppData\Local\VpnControl\cp166\state\vpn-control.lock' -Raw -ErrorAction Stop).Trim();if($lockRaw -match '^[0-9]{1,10}$'){$lockPid=[int]$lockRaw}}catch{}
 $activeProcesses=@($active|ForEach-Object {
  $process=$_;$kind=$process.Name.ToLowerInvariant().Replace('.exe','')
  $role=switch($kind){'msiexec'{'installer'}'consent'{'authorization'}'sing-box'{'runtime'}default{'unknown'}}
  if($kind -eq 'vpn-control-cli'){
   if($null -eq $process.CommandLine){$role='unknown'}
   elseif($process.CommandLine -match '(^|\s)serve(\s|$)'){$role='owner'}
   else{$role='command'}
  }
  $processOwner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
  [pscustomobject]@{kind=$kind;pid=[int]$process.ProcessId;parentPid=[int]$process.ParentProcessId;startedAtUtc=$process.CreationDate.ToUniversalTime().ToString('o');sessionId=[int]$process.SessionId;originalUser=($processOwner.ReturnValue -eq 0 -and $processOwner.Sid -ceq $sid);role=$role;currentWorkspaceOwner=($null -ne $lockPid -and $process.ProcessId -eq $lockPid)}
 })
 $activeKinds=@($active|ForEach-Object {$_.Name.ToLowerInvariant().Replace('.exe','')}|Sort-Object -Unique)
 $explorers=@(Get-CimInstance Win32_Process -Filter "name='explorer.exe'"|Where-Object {$_.SessionId -eq 1})
 $owned=0
 foreach($process in $explorers){$owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid;if($owner.ReturnValue -eq 0 -and $owner.Sid -ceq $sid){$owned++}}
 $version=if($products.Count -eq 1){$products[0].DisplayVersion}else{$null}
 $ready=$products.Count -eq 1 -and $version -ceq $expected -and $active.Count -eq 0 -and $owned -eq 1
 $code=if($ready){'READY'}elseif($products.Count -ne 1){'PRODUCT_COUNT'}elseif($version -cne $expected){'PRODUCT_VERSION'}elseif($active.Count -ne 0){'ACTIVE_PROCESS'}else{'SESSION_OWNER'}
 [Console]::Out.WriteLine(([pscustomobject]@{version=1;code=$code;installedVersion=$version;productCount=$products.Count;activeCount=$active.Count;activeKinds=$activeKinds;activeProcesses=$activeProcesses;workspaceLockPid=$lockPid;ownedExplorerCount=$owned}|ConvertTo-Json -Depth 5 -Compress))
}catch{[Console]::Out.WriteLine('{"version":1,"code":"UNKNOWN"}');exit 1}
'''.replace("@SID@", sid).replace("@VERSION@", version)


_READINESS = _QGA + r'''import time
sock,pid,ticks,encoded=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks) or len(encoded)>=30000:raise ValueError()
 start=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})
 child=start['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for attempt in range(40):
  state=call(sock,'guest-exec-status',{'pid':child})
  if state.get('exited') is True:break
  time.sleep(.25)
 else:raise ValueError()
 raw=base64.b64decode(state.get('out-data',''),validate=True)
 if len(raw)>4096:raise ValueError()
 lines=[x for x in decode(raw).splitlines() if x.startswith('{') and x.endswith('}')]
 if state.get('exitcode')!=0 or len(lines)!=1:raise ValueError()
 out({'state':'observed','inventory':json.loads(lines[0])})
except Exception:out({'state':'unknown'})
'''


def readiness(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if (not isinstance(value, Mapping) or set(value) != {"host", "expectedCurrentVersion"}
            or value["host"] != "archlinux" or not isinstance(value["expectedCurrentVersion"], str)
            or not _VERSION.fullmatch(value["expectedCurrentVersion"])):
        raise WindowsMsiBasePrepareError("Base readiness requires exact CP117 host and version.")
    root = Path(root).resolve(strict=True)
    config, _, (env, socket, pid, ticks, sid) = _descriptor(root)
    if env != "windows-cp117":
        raise WindowsMsiBasePrepareError("Owned CP117 guest identity changed.")
    encoded = base64.b64encode(_readiness_script(value["expectedCurrentVersion"], sid).encode("utf-16le")).decode()
    if len(encoded) >= 30000:
        raise WindowsMsiBasePrepareError("Fixed base readiness exceeds Windows command admission.")
    raw = _remote(config, _READINESS, (socket, str(pid), str(ticks), encoded), None, 30)
    unknown = {"state": "unknown", "ready": False, "productAction": False}
    try:
        result = json.loads(raw) if raw is not None else {}
    except (TypeError, ValueError):
        return unknown
    if not isinstance(result, dict) or result.get("state") != "observed" or not isinstance(result.get("inventory"), dict):
        return unknown
    inventory = result["inventory"]
    codes = {"READY", "PRODUCT_COUNT", "PRODUCT_VERSION", "ACTIVE_PROCESS", "SESSION_OWNER"}
    if (set(inventory) != {"version", "code", "installedVersion", "productCount", "activeCount", "activeKinds", "activeProcesses", "workspaceLockPid", "ownedExplorerCount"}
            or inventory["version"] != 1 or inventory["code"] not in codes
            or type(inventory["productCount"]) is not int or inventory["productCount"] < 0
            or type(inventory["activeCount"]) is not int or inventory["activeCount"] < 0
            or not isinstance(inventory["activeKinds"], list) or len(inventory["activeKinds"]) > 4
            or len(set(x for x in inventory["activeKinds"] if isinstance(x, str))) != len(inventory["activeKinds"])
            or any(x not in {"vpn-control-cli", "msiexec", "consent", "sing-box"} for x in inventory["activeKinds"])
            or (inventory["activeCount"] == 0) != (len(inventory["activeKinds"]) == 0)
            or not isinstance(inventory["activeProcesses"], list)
            or len(inventory["activeProcesses"]) != inventory["activeCount"]
            or len(inventory["activeProcesses"]) > 16
            or (inventory["workspaceLockPid"] is not None and
                (type(inventory["workspaceLockPid"]) is not int or inventory["workspaceLockPid"] <= 0))
            or type(inventory["ownedExplorerCount"]) is not int or inventory["ownedExplorerCount"] < 0
            or (inventory["installedVersion"] is not None and (not isinstance(inventory["installedVersion"], str)
                or not _VERSION.fullmatch(inventory["installedVersion"])))):
        return unknown
    roles = {"vpn-control-cli": {"owner", "command", "unknown"}, "msiexec": {"installer"},
             "consent": {"authorization"}, "sing-box": {"runtime"}}
    for process in inventory["activeProcesses"]:
        if (not isinstance(process, dict) or set(process) != {"kind", "pid", "parentPid", "startedAtUtc", "sessionId", "originalUser", "role", "currentWorkspaceOwner"}
                or process.get("kind") not in roles or process.get("role") not in roles[process["kind"]]
                or type(process.get("pid")) is not int or process["pid"] <= 0
                or type(process.get("parentPid")) is not int or process["parentPid"] < 0
                or not isinstance(process.get("startedAtUtc"), str)
                or type(process.get("sessionId")) is not int or process["sessionId"] < 0
                or type(process.get("originalUser")) is not bool
                or type(process.get("currentWorkspaceOwner")) is not bool):
            return unknown
        try:
            datetime.fromisoformat(process["startedAtUtc"].replace("Z", "+00:00"))
        except ValueError:
            return unknown
    if sorted({p["kind"] for p in inventory["activeProcesses"]}) != inventory["activeKinds"]:
        return unknown
    if any(p["currentWorkspaceOwner"] != (p["pid"] == inventory["workspaceLockPid"])
           for p in inventory["activeProcesses"]):
        return unknown
    ready = (inventory["code"] == "READY" and inventory["productCount"] == 1
             and inventory["installedVersion"] == value["expectedCurrentVersion"]
             and inventory["activeCount"] == 0 and inventory["ownedExplorerCount"] == 1)
    if inventory["code"] == "READY" and not ready:
        return unknown
    return {"state": "ready" if ready else "blocked", "ready": ready, "code": inventory["code"],
            "installedVersion": inventory["installedVersion"], "productCount": inventory["productCount"],
            "activeCount": inventory["activeCount"], "activeKinds": inventory["activeKinds"],
            "activeProcesses": inventory["activeProcesses"],
            "workspaceLockPid": inventory["workspaceLockPid"],
            "ownedExplorerCount": inventory["ownedExplorerCount"],
            "productAction": False}


def _remote(config: Any, program: str, args: tuple[str, ...], source: Path | None, timeout: int) -> bytes | None:
    command = windows_credential_probe_ssh._remote_command(program, *args)
    argv = ssh_transport.build_ssh_argv(config, "archlinux", min(timeout, 60), command=command)
    try:
        if source is None:
            completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, timeout=timeout, check=False)
        else:
            with source.open("rb") as stream:
                completed = subprocess.run(argv, stdin=stream, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, timeout=timeout, check=False)
        return completed.stdout if completed.returncode == 0 and len(completed.stdout) <= 16384 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


_PRE_EFFECT_STATUS = _QGA + r'''import time
root,env,corr,sock,pid,ticks=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 if env!='windows-cp117' or corr!='30a6f33b-3ea2-42d0-8818-3d6711b34169' or not live(sock,pid,ticks):raise ValueError()
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-msi-base')
 for path in (root,parent):
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 if os.path.lexists(os.path.join(group,corr)):
  out({'state':'present','correlationId':corr});raise SystemExit(0)
 if os.path.lexists(group):
  info=os.lstat(group)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 script="$ErrorActionPreference='Stop';$corr='"+corr+"';$task='VpnControlMcpBase-'+$corr;$leaf='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-base-'+$corr;try{$registered=Get-ScheduledTask -TaskPath '\\' -TaskName $task -ErrorAction SilentlyContinue;if($registered -or [IO.Directory]::Exists($leaf) -or [IO.File]::Exists($leaf)){[Console]::Out.WriteLine('{\"version\":1,\"state\":\"present\"}')}else{[Console]::Out.WriteLine('{\"version\":1,\"state\":\"absent\"}')}}catch{[Console]::Out.WriteLine('{\"version\":1,\"state\":\"unknown\"}');exit 1}"
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
 lines=[line for line in decode(raw).splitlines() if line.startswith('{') and line.endswith('}')]
 if len(lines)!=1 or json.loads(lines[0])!={'version':1,'state':'absent'}:raise ValueError()
 out({'state':'absent','correlationId':corr,'qemuPid':int(pid),'startTicks':int(ticks)})
except Exception:out({'state':'unknown','correlationId':corr})
'''


def pre_effect_status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"host"} or value["host"] != "archlinux":
        raise WindowsMsiBasePrepareError("Base pre-effect status requires exact owned host.")
    root = Path(root).resolve(strict=True)
    intent = _private_intent(root, _PRE_EFFECT_REJECTED_CORRELATION)
    if (intent is None or intent.get("commandSha256") != _PRE_EFFECT_REJECTED_COMMAND_SHA256
            or intent.get("leaseId") != _PRE_EFFECT_REJECTED_CORRELATION
            or intent.get("request", {}).get("correlationId") != _PRE_EFFECT_REJECTED_CORRELATION):
        raise WindowsMsiBasePrepareError("Base pre-effect identity changed.")
    config, target, (env, sock, pid, ticks, sid) = _descriptor(root)
    if any(intent.get(key) != observed for key, observed in (("environment", env),
            ("socketPath", sock), ("pid", pid), ("startTicks", ticks), ("expectedSid", sid))):
        return {"state": "unknown", "correlationId": _PRE_EFFECT_REJECTED_CORRELATION}
    raw = _remote(config, _PRE_EFFECT_STATUS,
        (str(target.fixture_transfer_root), env, _PRE_EFFECT_REJECTED_CORRELATION,
         sock, str(pid), str(ticks)), None, 30)
    try: observed = json.loads(raw) if raw is not None else {}
    except (TypeError, ValueError): observed = {}
    exact = {"state": "absent", "correlationId": _PRE_EFFECT_REJECTED_CORRELATION,
             "qemuPid": pid, "startTicks": ticks}
    return exact if observed == exact else {"state": "unknown", "correlationId": _PRE_EFFECT_REJECTED_CORRELATION}


def close_pre_effect(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Close only the known pre-dispatch SSH validation failure, preserving its intent."""
    if not isinstance(value, Mapping) or set(value) != {"host"} or value["host"] != "archlinux":
        raise WindowsMsiBasePrepareError("Base pre-effect closure requires exact owned host.")
    root = Path(root).resolve(strict=True)
    corr = _PRE_EFFECT_REJECTED_CORRELATION
    intent = _private_intent(root, corr)
    if (intent is None or intent.get("request") != _PRE_EFFECT_REJECTED_REQUEST
            or intent.get("commandSha256") != _PRE_EFFECT_REJECTED_COMMAND_SHA256
            or intent.get("leaseId") != corr):
        raise WindowsMsiBasePrepareError("Base pre-effect intent changed.")
    config, target, descriptor = _descriptor(root)
    env, sock, pid, ticks, sid = descriptor
    if (pid != 589342 or ticks != 520739 or
            any(intent.get(key) != observed for key, observed in (("environment", env),
                ("socketPath", sock), ("pid", pid), ("startTicks", ticks), ("expectedSid", sid)))):
        raise WindowsMsiBasePrepareError("Base pre-effect guest generation changed.")
    expected_absence = {"state": "absent", "correlationId": corr, "qemuPid": pid, "startTicks": ticks}
    if (pre_effect_status(root, {"host": "archlinux"}) != expected_absence
            or pre_effect_status(root, {"host": "archlinux"}) != expected_absence):
        return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    idle = readiness(root, {"host": "archlinux", "expectedCurrentVersion": "2.1.17"})
    if (idle.get("state") != "ready" or idle.get("ready") is not True
            or idle.get("code") != "READY" or idle.get("installedVersion") != "2.1.17"
            or idle.get("productCount") != 1 or idle.get("activeCount") != 0
            or idle.get("activeProcesses") != []):
        return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    identity = _campaign_identity(_PRE_EFFECT_REJECTED_REQUEST, descriptor)
    proof = {"correlationId": corr, "commandSha256": _PRE_EFFECT_REJECTED_COMMAND_SHA256,
             "sourceSha": _PRE_EFFECT_REJECTED_REQUEST["sourceSha"], "qemuPid": pid,
             "startTicks": ticks, "remoteStageTaskGuestLeafAbsent": True,
             "installedVersion": "2.1.17", "productCount": 1, "activeCount": 0,
             "failure": "ssh-connect-timeout-rejected-before-dispatch"}
    evidence_sha = hashlib.sha256(json.dumps(proof, sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()
    cleanup = {"guestGeneration": {"socketPath": sock, "qemuPid": pid, "startTicks": ticks},
               "serverStopped": True, "credentialsCleaned": True,
               "protectedJobsTerminalCleaned": True, "activeInstallerProcessesAbsent": True,
               "cleanupReceiptSha256": hashlib.sha256((evidence_sha + ":campaign-closed").encode()).hexdigest()}
    remote = _campaign_remote(config, target)
    directory, lock = campaign_lease._locked(root)
    try:
        record = campaign_lease._active(directory)
        closed = campaign_lease._closed(directory, corr) if record is None else None
        if record is not None and record["identity"] != identity:
            raise WindowsMsiBasePrepareError("Base campaign identity changed.")
        if closed is not None and closed["identity"] != identity:
            raise WindowsMsiBasePrepareError("Closed base campaign identity changed.")
    finally: os.close(lock)
    if record is not None and record["state"] in {"pending-finish", "pending-close"}:
        resumed = campaign_lease.reconcile(root, corr, remote)
        if resumed["state"] == "unknown":
            return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
        directory, lock = campaign_lease._locked(root)
        try:
            record = campaign_lease._active(directory)
            closed = campaign_lease._closed(directory, corr) if record is None else None
        finally: os.close(lock)
    if (record is not None and record["state"] == "role-active"
            and record["role"] == "base" and record["correlationId"] == corr
            and record["server"] == "stopped" and record["credentials"] == "absent"
            and record["lastEvidenceSha256"] is None):
        if not campaign_lease._remote_confirm(remote, "status", record, None):
            return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
        finished = campaign_lease.finish_role(root, corr, "base", corr, evidence_sha,
                                               "failed-cleaned", remote)
        if finished["state"] != "active":
            return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
        directory, lock = campaign_lease._locked(root)
        try: record = campaign_lease._active(directory)
        finally: os.close(lock)
    if record is not None:
        if (record["state"] != "active" or record["role"] is not None
                or record["correlationId"] is not None or record["server"] != "stopped"
                or record["credentials"] != "absent" or record["lastOutcome"] != "failed-cleaned"
                or record["lastEvidenceSha256"] != evidence_sha):
            raise WindowsMsiBasePrepareError("Base campaign is not verified failed-cleaned.")
        if not campaign_lease._remote_confirm(remote, "status", record, None):
            return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
        finished = campaign_lease.close(root, corr, cleanup, remote)
        if finished["state"] != "closed":
            return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    if campaign_lease.reconcile(root, corr, remote)["state"] != "closed":
        return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    marker = _pre_effect_marker(root)
    marker_value = {"correlationId": corr, "commandSha256": _PRE_EFFECT_REJECTED_COMMAND_SHA256,
                    "state": "pre-effect-closed", "cleanupReceiptSha256": cleanup["cleanupReceiptSha256"]}
    if marker.exists():
        if not _pre_effect_closed(root):
            raise WindowsMsiBasePrepareError("Base pre-effect marker changed.")
    else:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write((json.dumps(marker_value, sort_keys=True, separators=(",", ":")) + "\n").encode())
            stream.flush(); os.fsync(stream.fileno())
        parent = os.open(marker.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(parent)
        finally: os.close(parent)
    if not _pre_effect_closed(root):
        raise WindowsMsiBasePrepareError("Base pre-effect closure did not verify.")
    return {"state": "pre-effect-closed", "correlationId": corr,
            "cleanupReceiptSha256": cleanup["cleanupReceiptSha256"], "replayAllowed": False}


def _campaign_remote(config: Any, target: Any):
    """Fixed journal transport; no QGA guest-exec or product action."""
    def send(action: str, payload: Mapping[str, Any]) -> bytes | None:
        return _remote(config, campaign_lease.remote_program(),
            campaign_lease.remote_arguments(target.fixture_transfer_root, action, payload), None, 30)
    return send


def _campaign_identity(request: Mapping[str, Any], descriptor: tuple[Any, ...]) -> dict[str, Any]:
    env, socket, pid, ticks, _sid = descriptor
    return {"host": "archlinux", "environment": env, "leaseId": request["correlationId"],
            "operator": "windows-base", "sourceSha": request["sourceSha"],
            "fixtureReceiptArtifactId": request["fixtureReceiptArtifactId"],
            "baseMsiArtifactId": request["baseMsiArtifactId"],
            "targetMsiArtifactId": request["targetMsiArtifactId"],
            "socketPath": socket, "qemuPid": pid, "startTicks": ticks}


def _legacy_task_script() -> str:
    """Inert CP176 task/process inventory; no delete, stop, or replay."""
    return r'''$ErrorActionPreference='Stop'
try {
 $tasks=@(Get-ScheduledTask -TaskName 'VpnControlMcp*' -ErrorAction SilentlyContinue)
 $active=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match '^(msiexec|consent)\.exe$'})
 $legacy=@($tasks|Where-Object {$_.TaskName -ceq @TASK@})
 $other=@($tasks|Where-Object {$_.TaskName -cne @TASK@})
 $code=if($legacy.Count -eq 0 -and $other.Count -eq 0 -and $active.Count -eq 0){'CLEANED'}else{'BUSY_OR_UNKNOWN'}
 [Console]::Out.WriteLine(([pscustomobject]@{version=1;code=$code;
  legacyTaskCount=$legacy.Count;otherTaskCount=$other.Count;activeInstallerCount=$active.Count}|ConvertTo-Json -Compress))
}catch{[Console]::Out.WriteLine('{"version":1,"code":"UNKNOWN"}');exit 1}
'''.replace("@TASK@", windows_msi_public_scenario._ps_literal("VpnControlMcpMsi-" + _LEGACY_CORRELATION))


def _legacy_task_observation(root: Path, descriptor: tuple[Any, ...]) -> dict[str, Any]:
    env, socket, pid, ticks, _sid = descriptor
    if env != "windows-cp117":
        return {"state": "unknown"}
    config, _target, current = _descriptor(root)
    if current != descriptor:
        return {"state": "unknown"}
    encoded = base64.b64encode(_legacy_task_script().encode("utf-16le")).decode()
    if len(encoded) >= 30000:
        return {"state": "unknown"}
    raw = _remote(config, _READINESS, (socket, str(pid), str(ticks), encoded), None, 30)
    try: value = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError): return {"state": "unknown"}
    item = value.get("inventory") if isinstance(value, dict) and value.get("state") == "observed" else None
    if (not isinstance(item, dict) or set(item) != {"version", "code", "legacyTaskCount",
            "otherTaskCount", "activeInstallerCount"} or item["version"] != 1
            or item["code"] not in {"CLEANED", "BUSY_OR_UNKNOWN"}
            or any(type(item[key]) is not int or item[key] < 0 for key in
                   ("legacyTaskCount", "otherTaskCount", "activeInstallerCount"))):
        return {"state": "unknown"}
    clean = all(item[key] == 0 for key in ("legacyTaskCount", "otherTaskCount", "activeInstallerCount"))
    if (item["code"] == "CLEANED") != clean:
        return {"state": "unknown"}
    return {"state": "cleaned" if clean else "blocked", **item}


_LEGACY_HISTORY = _QGA + r'''root,env,sock,pid,ticks,corr=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 if env!='windows-cp117' or not live(sock,pid,ticks):raise ValueError()
 parent=os.path.join(root,env)
 for path in (root,parent):
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 groups=('windows-msi-base','windows-msi-target','windows-msi-public')
 result={}
 for group in groups:
  path=os.path.join(parent,group)
  if not os.path.lexists(path):result[group]=[];continue
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
  lock=os.path.join(path,'.environment.lock')
  if os.path.lexists(lock):
   item=os.lstat(lock)
   if not stat.S_ISREG(item.st_mode) or stat.S_ISLNK(item.st_mode) or item.st_uid!=os.geteuid() or stat.S_IMODE(item.st_mode)!=0o600:raise ValueError()
  names=sorted(name for name in os.listdir(path) if name!='.environment.lock')
  if len(names)>1 or (names and (group!='windows-msi-public' or names!=[corr])):raise ValueError()
  for name in names:
   item=os.lstat(os.path.join(path,name))
   if not stat.S_ISDIR(item.st_mode) or stat.S_ISLNK(item.st_mode) or item.st_uid!=os.geteuid() or stat.S_IMODE(item.st_mode)!=0o700:raise ValueError()
  result[group]=names
 out({'version':1,'state':'clean','groups':result})
except Exception:out({'version':1,'state':'unknown'})
'''


def _legacy_history_observation(root: Path, descriptor: tuple[Any, ...]) -> dict[str, Any]:
    config, target, current = _descriptor(root)
    if current != descriptor:
        return {"state": "unknown"}
    env, socket, pid, ticks, _sid = descriptor
    raw = _remote(config, _LEGACY_HISTORY, (str(target.fixture_transfer_root), env,
        socket, str(pid), str(ticks), _LEGACY_CORRELATION), None, 30)
    try: value = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError): return {"state": "unknown"}
    expected = {"windows-msi-base": [], "windows-msi-target": [],
                "windows-msi-public": []}
    if (not isinstance(value, dict) or set(value) != {"version", "state", "groups"}
            or value["version"] != 1 or value["state"] != "clean"
            or not isinstance(value["groups"], dict)
            or value["groups"] not in (expected,
                dict(expected, **{"windows-msi-public": [_LEGACY_CORRELATION]}))):
        return {"state": "unknown"}
    return {"state": "clean", "groups": value["groups"]}


def _require_reconciled_legacy(root: Path, descriptor: tuple[Any, ...],
                               expected_version: str) -> None:
    """Read the exact old protected job and idle guest before a new campaign.

    This is intentionally still an admission block. The old scheduled task and
    other prior route journals need a fixed cleanup observer before the terminal
    CP176 receipt can authorize a new native operation.
    """
    env, _socket, _pid, _ticks, _sid = descriptor
    if env != "windows-cp117":
        raise WindowsMsiBasePrepareError("CP117_LEGACY_RECONCILIATION_UNAVAILABLE")
    try:
        status = windows_msi_public_scenario.preinstall_status(root, "archlinux", _LEGACY_JOB)
    except ValueError as error:
        raise WindowsMsiBasePrepareError("CP117_LEGACY_RECONCILIATION_UNAVAILABLE") from error
    if (status.get("state") != "observed" or status.get("jobId") != _LEGACY_JOB
            or status.get("phase") != "Failed" or status.get("code") != "RUNTIME_FAILED"
            or type(status.get("sequence")) is not int or status["sequence"] < 3):
        raise WindowsMsiBasePrepareError("CP117_LEGACY_RECONCILIATION_UNAVAILABLE")
    inventory = readiness(root, {"host": "archlinux", "expectedCurrentVersion": expected_version})
    if inventory.get("state") != "ready" or inventory.get("activeCount") != 0:
        raise WindowsMsiBasePrepareError("CP117_LEGACY_RECONCILIATION_UNAVAILABLE")
    tasks = _legacy_task_observation(root, descriptor)
    if tasks.get("state") != "cleaned":
        raise WindowsMsiBasePrepareError("CP117_LEGACY_CLEANUP_UNVERIFIED")
    history = _legacy_history_observation(root, descriptor)
    if history.get("state") != "clean":
        raise WindowsMsiBasePrepareError("CP117_LEGACY_ROUTE_HISTORY_UNVERIFIED")
    proof = {"correlationId": _LEGACY_CORRELATION,
             "guestGeneration": {"socketPath": _socket, "qemuPid": _pid, "startTicks": _ticks},
             "terminalJobId": _LEGACY_JOB, "terminalPhase": "Failed", "cleanupCode": "OK",
             "activeInstallerProcessesAbsent": True,
             "evidenceSha256": hashlib.sha256(json.dumps({"protected": status, "tasks": tasks,
                 "history": history,
                 "generation": [_socket, _pid, _ticks]}, sort_keys=True,
                 separators=(",", ":")).encode()).hexdigest()}
    campaign_lease.attest_legacy_closed(root, proof)


def _require_base_route_free(root: Path) -> None:
    directory = root / _LOCAL
    if directory.exists():
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink()
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700
                or any(item.suffix == ".json" and not (_pre_effect_closed(root) and item.name in {
                    _PRE_EFFECT_REJECTED_CORRELATION + ".json",
                    _PRE_EFFECT_REJECTED_CORRELATION + ".pre-effect-closed.json"})
                    for item in directory.iterdir())):
            raise WindowsMsiBasePrepareError("CP117 base route has active or unknown history.")


def _open_base_campaign(root: Path, request: Mapping[str, Any], config: Any,
                        target: Any, descriptor: tuple[Any, ...]) -> str:
    """Internal: begin and claim only after an exact fsynced local intent."""
    intent = _private_intent(root, request["correlationId"])
    if (intent is None or intent.get("request") != dict(request)
            or intent.get("leaseId") != request["correlationId"]
            or any(intent.get(key) != observed for key, observed in
                   (("environment", descriptor[0]), ("socketPath", descriptor[1]),
                    ("pid", descriptor[2]), ("startTicks", descriptor[3]),
                    ("expectedSid", descriptor[4])))):
        raise WindowsMsiBasePrepareError("CP117 base intent is absent or changed.")
    _require_reconciled_legacy(root, descriptor, request["expectedCurrentVersion"])
    identity = _campaign_identity(request, descriptor)
    remote = _campaign_remote(config, target)
    opened = campaign_lease.begin(root, identity, remote)
    if opened["state"] != "active":
        raise WindowsMsiBasePrepareError("CP117 campaign reservation is unknown; inspect, do not replay.")
    claimed = campaign_lease.claim_role(root, identity["leaseId"], "base",
                                        request["correlationId"], remote)
    if claimed["state"] != "role-active":
        raise WindowsMsiBasePrepareError("CP117 base route claim is unknown; inspect, do not replay.")
    return identity["leaseId"]


def _verified_active_campaign(root: Path, request: Mapping[str, Any],
                              descriptor: tuple[Any, ...], config: Any, target: Any,
                              *, require_server: bool) -> str:
    """Internal: bind a previously verified pair and guest to both lease journals."""
    directory, lock = campaign_lease._locked(root)
    try:
        record = campaign_lease._active(directory)
        if record is None or record["state"] != "active" or record["role"] is not None:
            raise WindowsMsiBasePrepareError("CP117 campaign is absent, busy, or unknown.")
        identity = dict(record["identity"])
        expected = _campaign_identity({**request, "correlationId": identity["leaseId"]}, descriptor)
        if identity != expected or (require_server and record["server"] != "live"):
            raise WindowsMsiBasePrepareError("CP117 campaign or server identity changed.")
        if not campaign_lease._remote_confirm(_campaign_remote(config, target), "status", record, None):
            raise WindowsMsiBasePrepareError("CP117 remote campaign state is unknown.")
        return identity["leaseId"]
    finally:
        os.close(lock)


def _verified_claimed_campaign(root: Path, request: Mapping[str, Any],
                               descriptor: tuple[Any, ...], config: Any, target: Any,
                               lease_id: str, role: str) -> None:
    """Recheck the exact native route claim in both journals before its intent."""
    directory, lock = campaign_lease._locked(root)
    try:
        record = campaign_lease._active(directory)
        expected = _campaign_identity({**request, "correlationId": lease_id}, descriptor)
        if (record is None or record["identity"] != expected
                or record["state"] != "role-active" or record["role"] != role
                or record["correlationId"] != request["correlationId"]
                or record["server"] != ("live" if role in {"target", "public"} else "stopped")
                or record["credentials"] != ("ready" if role in {"target", "public"} else "absent")
                or not campaign_lease._remote_confirm(_campaign_remote(config, target),
                                                      "status", record, None)):
            raise WindowsMsiBasePrepareError("CP117 route claim is absent or unknown.")
    finally:
        os.close(lock)
    if role in {"target", "public"}:
        from . import windows_update_fixture_server
        receipt = windows_update_fixture_server.verified_live_receipt(root, lease_id)
        if not _live_receipt_matches(receipt, expected):
            raise WindowsMsiBasePrepareError("CP117 live fixture changed after route claim.")


def _live_receipt_matches(receipt: Any, expected: Mapping[str, Any]) -> bool:
    return (isinstance(receipt, dict) and
            all(receipt.get(key) == expected[key] for key in (
                "leaseId", "sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId",
                "targetMsiArtifactId", "socketPath", "qemuPid", "startTicks"))
            and receipt.get("serverReady") is True
            and isinstance(receipt.get("liveReceiptSha256"), str)
            and bool(re.fullmatch(r"[0-9a-f]{64}", receipt["liveReceiptSha256"])))


def _require_verified_live_fixture(root: Path, request: Mapping[str, Any],
                                   descriptor: tuple[Any, ...], config: Any, target: Any) -> str:
    """Join only one fixed, source-bound live server; no caller-supplied proof."""
    lease_id = _verified_active_campaign(root, request, descriptor, config, target,
                                         require_server=True)
    from . import windows_update_fixture_server
    receipt = windows_update_fixture_server.verified_live_receipt(root, lease_id)
    expected = _campaign_identity({**request, "correlationId": lease_id}, descriptor)
    if not _live_receipt_matches(receipt, expected):
        raise WindowsMsiBasePrepareError("CP117 live fixture receipt does not match campaign.")
    return lease_id


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    root = Path(root).resolve(strict=True)
    request = _request(value)
    correlation = request["correlationId"]
    existing = _private_intent(root, correlation)
    if existing is not None:
        if existing.get("request") != request:
            raise WindowsMsiBasePrepareError("Correlation binds another base preparation.")
        return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    pair, source, size = _admit(root, request)
    config, target, (env, sock, pid, ticks, sid) = _descriptor(root)
    command = _bootstrap(correlation, pair, request["expectedCurrentVersion"], sid)
    encoded = base64.b64encode(command.encode("utf-16le")).decode()
    if len(encoded) >= 30000:
        raise WindowsMsiBasePrepareError("Fixed base bootstrap exceeds Windows command admission.")
    command_hash = hashlib.sha256(command.encode("utf-16le")).hexdigest()
    record = {"request": request, "pair": pair, "environment": env, "socketPath": sock,
              "pid": pid, "startTicks": ticks, "expectedSid": sid, "commandSha256": command_hash}
    _require_reconciled_legacy(root, (env, sock, pid, ticks, sid), request["expectedCurrentVersion"])
    _require_base_route_free(root)
    stage_args = (str(target.fixture_transfer_root), env, correlation, correlation, sock,
                  str(pid), str(ticks), sid, str(size), encoded, command_hash,
                  request["sourceSha"], pair["sourceFingerprint"],
                  request["fixtureReceiptArtifactId"], request["baseMsiArtifactId"],
                  request["targetMsiArtifactId"])
    ssh_transport.build_ssh_argv(config, "archlinux", 60,
        command=windows_credential_probe_ssh._remote_command(_STAGE, *stage_args))
    record["leaseId"] = correlation
    _reserve(root, record)
    _open_base_campaign(root, request, config, target, (env, sock, pid, ticks, sid))
    raw = _remote(config, _STAGE, stage_args, source, 1800)
    try:
        result = json.loads(raw) if raw is not None else {}
    except (TypeError, ValueError):
        result = {}
    if not isinstance(result, dict) or result.get("state") != "submitted" or result.get("correlationId") != correlation:
        return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    return {"state": "submitted", "correlationId": correlation, "replayAllowed": False}


_STATUS = _QGA + r'''root,env,corr,sock,pid,ticks,source,fingerprint,receipt_id,base_id,target_id,command_hash,sid=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 stage=os.path.join(root,env,'windows-msi-base',corr);info=os.lstat(stage)
 if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 binding=json.load(open(os.path.join(stage,'binding.json'),encoding='utf-8'))
 if set(binding)!={'socketPath','pid','startTicks','sourceSha','sourceFingerprint','receiptArtifactId','baseArtifactId','targetArtifactId','commandSha256','expectedSid'}:raise ValueError()
 if binding!={'socketPath':sock,'pid':int(pid),'startTicks':int(ticks),'sourceSha':source,'sourceFingerprint':fingerprint,'receiptArtifactId':receipt_id,'baseArtifactId':base_id,'targetArtifactId':target_id,'commandSha256':command_hash,'expectedSid':sid}:raise ValueError()
 if not live(sock,pid,ticks):raise ValueError()
 dispatch=json.load(open(os.path.join(stage,'dispatch.json'),encoding='utf-8'))
 if set(dispatch)!={'pid'} or type(dispatch['pid']) is not int or dispatch['pid']<=0:raise ValueError()
 status=call(sock,'guest-exec-status',{'pid':dispatch['pid']})
 if status.get('exited') is not True:out({'state':'running','correlationId':corr});raise SystemExit(0)
 if status.get('exitcode')!=0:out({'state':'unknown','correlationId':corr});raise SystemExit(0)
 output=base64.b64decode(status.get('out-data',''),validate=True)
 if len(output)>8192:raise ValueError()
 lines=[x for x in decode(output).splitlines() if x.startswith('{') and x.endswith('}')]
 if not lines or json.loads(lines[-1])!={'version':1,'correlationId':corr,'triggered':True}:raise ValueError()
 path='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-base-'+corr+'\\result.json'
 raw=read(sock,path)
 if raw is None:out({'state':'running','correlationId':corr});raise SystemExit(0)
 result=json.loads(decode(raw))
 if set(result)!={'version','correlationId','stage','result','exitCode','originalSid','sessionId','limited','msiSha256','installedVersion','cliSha256','jarSha256','helperSha256','priorProducts','installedProducts'} or result['version']!=1 or result['correlationId']!=corr:raise ValueError()
 out({'state':'observed','correlationId':corr,'result':result})
except Exception:out({'state':'unknown','correlationId':corr})
'''


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"correlationId"}:
        raise WindowsMsiBasePrepareError("Base status requires exact correlationId.")
    correlation = value["correlationId"]
    if not isinstance(correlation, str) or not _UUID.fullmatch(correlation) or str(uuid.UUID(correlation)) != correlation:
        raise WindowsMsiBasePrepareError("Invalid base correlationId.")
    root = Path(root).resolve(strict=True)
    intent = _private_intent(root, correlation)
    unknown = {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    if intent is None:
        return unknown
    try:
        config, target, (env, sock, pid, ticks, sid) = _descriptor(root)
        if any(intent.get(key) != value for key, value in (("environment", env), ("socketPath", sock),
                ("pid", pid), ("startTicks", ticks), ("expectedSid", sid))):
            return unknown
        request = intent["request"]
        raw = _remote(config, _STATUS, (str(target.fixture_transfer_root), env, correlation, sock,
            str(pid), str(ticks), request["sourceSha"], intent["pair"]["sourceFingerprint"],
            request["fixtureReceiptArtifactId"], request["baseMsiArtifactId"], request["targetMsiArtifactId"],
            intent["commandSha256"], sid), None, 30)
        result = json.loads(raw) if raw is not None else {}
    except (OSError, ValueError, TypeError, KeyError):
        return unknown
    if not isinstance(result, dict) or result.get("correlationId") != correlation:
        return unknown
    if result.get("state") == "running":
        return {"state": "running", "correlationId": correlation, "replayAllowed": False}
    payload = result.get("result")
    if result.get("state") != "observed" or not isinstance(payload, dict):
        return unknown
    if (payload.get("version") != 1 or payload.get("correlationId") != correlation
            or payload.get("stage") not in {"IDENTITY", "ADMISSION", "INSTALL", "READBACK"}
            or payload.get("result") not in {"IN_PROGRESS", "PASSED", "FAILED"}
            or type(payload.get("exitCode")) is not int):
        return unknown
    if payload["result"] == "PASSED" and (payload["stage"] != "READBACK" or payload["exitCode"] != 0):
        return unknown
    if payload["result"] == "PASSED" and (payload.get("originalSid") != intent["expectedSid"]
            or payload.get("sessionId") != 1 or payload.get("limited") is not True
            or payload.get("msiSha256") != intent["request"]["baseMsiArtifactId"].removeprefix("sha256-")
            or payload.get("installedVersion") != intent["pair"]["baseVersion"]
            or payload.get("cliSha256") != intent["pair"]["baseCliSha256"]
            or payload.get("jarSha256") != intent["pair"]["baseAppJarSha256"]
            or payload.get("helperSha256") != intent["pair"]["baseHelperSha256"]
            or not _unique_product(payload.get("priorProducts"), intent["request"]["expectedCurrentVersion"])
            or not _unique_product(payload.get("installedProducts"), intent["pair"]["baseVersion"])):
        return unknown
    return {"state": "terminal" if payload["result"] != "IN_PROGRESS" else "running",
            "correlationId": correlation, "result": payload["result"], "stage": payload["stage"],
            "exitCode": payload["exitCode"], "sourceSha": intent["request"]["sourceSha"],
            "baseArtifactId": intent["request"]["baseMsiArtifactId"], "replayAllowed": False}


def finish_observed(root: Path | str, correlation: str) -> dict[str, Any]:
    """Internal: release base role after exact installed readback and idle guest.

    A caller cannot provide terminal or cleanup claims. Both observations are
    reread from fixed native routes before the lease transition.
    """
    root = Path(root).resolve(strict=True)
    intent = _private_intent(root, correlation)
    if intent is None or intent.get("leaseId") != correlation:
        raise WindowsMsiBasePrepareError("CP117 base intent is absent or unbound.")
    observed = status(root, {"correlationId": correlation})
    request = intent["request"]
    if (observed.get("state") != "terminal" or observed.get("result") != "PASSED"
            or observed.get("stage") != "READBACK" or observed.get("exitCode") != 0
            or observed.get("sourceSha") != request["sourceSha"]
            or observed.get("baseArtifactId") != request["baseMsiArtifactId"]):
        raise WindowsMsiBasePrepareError("CP117 base terminal readback is unavailable.")
    idle = readiness(root, {"host": "archlinux", "expectedCurrentVersion": intent["pair"]["baseVersion"]})
    if (idle.get("state") != "ready" or idle.get("activeCount") != 0
            or idle.get("installedVersion") != intent["pair"]["baseVersion"]):
        raise WindowsMsiBasePrepareError("CP117 base cleanup is not observed.")
    config, target, descriptor = _descriptor(root)
    _verified_claimed_campaign(root, request, descriptor, config, target, correlation, "base")
    evidence = hashlib.sha256(json.dumps({"terminal": observed, "idle": idle,
        "leaseId": correlation}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return campaign_lease.finish_role(root, correlation, "base", correlation,
                                      evidence, "succeeded", _campaign_remote(config, target))
