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
_VERSION = re.compile(r"(?:[1-9]|1[0-9])\.(?:0|[1-9]|1[0-9])\.(?:0|[1-9]|1[0-9])\Z")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
_LOCAL = ".rag_index/windows-msi-base-prepare"
_ROOT = r"C:\Users\vpncp117\AppData\Local\VpnControl"
_ACCOUNT = r"VPNMSIX64\vpncp117"
_PRODUCT = re.compile(r"\{[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}\Z")
_INSTALL = "C:\\Users\\vpncp117\\AppData\\Local\\vpn-control\\"


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


def _reserve(root: Path, record: dict[str, Any]) -> None:
    directory = root / _LOCAL
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise WindowsMsiBasePrepareError("Base preparation journal is unsafe.")
    lock_fd = os.open(directory / ".environment.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if any(item.suffix == ".json" for item in directory.iterdir()):
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


_STAGE = _QGA + r'''import fcntl,struct
root,env,corr,sock,pid,ticks,expected,size_text,encoded,command_hash,source,fingerprint,receipt_id,base_id,target_id=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if env!='windows-cp117' or not live(sock,pid,ticks):raise ValueError()
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-msi-base')
 for path in (root,parent,group):
  if not os.path.exists(path):os.mkdir(path,0o700)
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 lock=os.open(os.path.join(group,'.environment.lock'),os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
 try:
  fcntl.flock(lock,fcntl.LOCK_EX)
  if any(name!='.environment.lock' for name in os.listdir(group)):raise FileExistsError()
  public=os.path.join(parent,'windows-msi-public')
  if os.path.exists(public) and any(name!='.environment.lock' for name in os.listdir(public)):raise FileExistsError()
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
    argv = ssh_transport.build_ssh_argv(config, "archlinux", timeout, command=command)
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


def _require_reconciled_legacy(_root: Path, _descriptor: tuple[Any, ...]) -> None:
    """A fixed CP176/other-prior native reconciler has not been admitted yet."""
    raise WindowsMsiBasePrepareError("CP117_LEGACY_RECONCILIATION_UNAVAILABLE")


def _require_base_route_free(root: Path) -> None:
    directory = root / _LOCAL
    if directory.exists():
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink()
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700
                or any(item.suffix == ".json" for item in directory.iterdir())):
            raise WindowsMsiBasePrepareError("CP117 base route has active or unknown history.")


def _open_base_campaign(root: Path, request: Mapping[str, Any], config: Any,
                        target: Any, descriptor: tuple[Any, ...]) -> str:
    """Internal: starts only after artifact and exact legacy/guest admission."""
    _require_reconciled_legacy(root, descriptor)
    _require_base_route_free(root)
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


def _require_verified_live_fixture(root: Path, request: Mapping[str, Any],
                                   descriptor: tuple[Any, ...], config: Any, target: Any) -> str:
    """Join only one fixed, source-bound live server; no caller-supplied proof."""
    lease_id = _verified_active_campaign(root, request, descriptor, config, target,
                                         require_server=True)
    from . import windows_update_fixture_server
    receipt = windows_update_fixture_server.verified_live_receipt(root, lease_id)
    expected = _campaign_identity({**request, "correlationId": lease_id}, descriptor)
    if (not isinstance(receipt, dict) or receipt.get("leaseId") != lease_id
            or receipt.get("sourceSha") != expected["sourceSha"]
            or receipt.get("fixtureReceiptArtifactId") != expected["fixtureReceiptArtifactId"]
            or receipt.get("baseMsiArtifactId") != expected["baseMsiArtifactId"]
            or receipt.get("targetMsiArtifactId") != expected["targetMsiArtifactId"]
            or receipt.get("socketPath") != expected["socketPath"]
            or receipt.get("qemuPid") != expected["qemuPid"]
            or receipt.get("startTicks") != expected["startTicks"]
            or receipt.get("serverReady") is not True
            or not isinstance(receipt.get("liveReceiptSha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", receipt["liveReceiptSha256"])):
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
    record["leaseId"] = _open_base_campaign(root, request, config, target, (env, sock, pid, ticks, sid))
    _reserve(root, record)
    raw = _remote(config, _STAGE, (str(target.fixture_transfer_root), env, correlation, sock, str(pid), str(ticks),
        sid, str(size), encoded, command_hash, request["sourceSha"], pair["sourceFingerprint"],
        request["fixtureReceiptArtifactId"], request["baseMsiArtifactId"], request["targetMsiArtifactId"]), source, 1800)
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
