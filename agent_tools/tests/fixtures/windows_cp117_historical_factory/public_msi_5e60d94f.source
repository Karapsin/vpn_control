"""Durable Windows MSI public-install submission and bounded observation.

Start reserves one CP117 scenario before a single native submission. Status and
collect only read the exact public request, correlation journal, and protected
job. Unknown outcomes never authorize replay.
"""
from __future__ import annotations

import json
import base64
import hashlib
import gzip
import os
from pathlib import Path
import re
import stat
import subprocess
import zipfile
from typing import Any
import uuid

try:
    import fcntl
except ImportError:  # pragma: no cover - native coordinator is POSIX
    fcntl = None

try:
    from . import native_artifact_registry, ssh_transport, windows_credential_probe_ssh
    from . import windows_cp117_lease as campaign_lease
except ImportError:  # pragma: no cover - CLI fallback
    import native_artifact_registry  # type: ignore[no-redef]
    import ssh_transport  # type: ignore[no-redef]
    import windows_credential_probe_ssh  # type: ignore[no-redef]
    import windows_cp117_lease as campaign_lease  # type: ignore[no-redef]


_JOB = re.compile(r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$")
_CODE = re.compile(r"^[A-Z_]{1,40}$")
_PHASES = {"Preparing", "Authorized", "WaitingForExit", "Installing", "Succeeded", "Failed", "Cancelled"}
_STAGES = {"EXCLUSIVE_ADMISSION", "INVENTORY", "READINESS"}
_KINDS = {"OTHER", "WIN32_API", "IDENTITY"}
_TASK_STAGES = {"IDENTITY", "PACKAGE", "READY", "OWNER", "INTENT", "REQUEST", "OBSERVE", "OBSERVE_RETURNED"}
_TASK_RESULTS = {"IN_PROGRESS", "ERROR", "DONE"}
_BOOTSTRAP_STAGES = {"EXCLUSIVE", "PACKAGE", "STAGE", "TASK_REGISTER", "TASK_START"}
_ARTIFACT = re.compile(r"^sha256-[0-9a-f]{64}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SOURCE = re.compile(r"^[0-9a-f]{40}$")
_VERSION = re.compile(r"^(?:[1-9]|1[0-9])\.(?:0|[1-9]|1[0-9])\.(?:0|[1-9]|1[0-9])$")
_JAR = re.compile(r"^desktopApp-[A-Za-z0-9._-]+\.jar$")
_PUBLIC_ROOT = r"C:\Users\vpncp117\AppData\Local\VpnControl"
_INSTALLED_CLI = r"C:\Users\vpncp117\AppData\Local\vpn-control\vpn-control-cli.exe"
_STATE_DIR = _PUBLIC_ROOT + r"\cp166\state"


class WindowsMsiPreinstallStatusError(ValueError):
    pass


def _file_hash(path: Path) -> tuple[int, str]:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise WindowsMsiPreinstallStatusError("Fixture input is not an ordinary file.")
    digest = hashlib.sha256(); size = 0
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk); size += len(chunk)
    return size, digest.hexdigest()


def _verified_location(root: Path, artifact_id: str, kind: str, source_sha: str) -> Path:
    if not isinstance(artifact_id, str) or not _ARTIFACT.fullmatch(artifact_id):
        raise WindowsMsiPreinstallStatusError("Windows MSI artifact ID is invalid.")
    value = native_artifact_registry.verify_artifact(root, artifact_id)
    artifact, location = value["artifact"], value["location"]
    if (value["verification"] != "verified" or artifact.get("platform") != "windows"
            or artifact.get("artifactKind") != kind or artifact.get("sourceSha") != source_sha
            or location.get("evidenceClass") != "local-verified"):
        raise WindowsMsiPreinstallStatusError("Windows MSI artifact identity is not verified.")
    return Path(location["localPath"])


def _admit_pair(root: Path, source_sha: str, receipt_id: str, base_id: str, target_id: str) -> dict[str, Any]:
    """Bind exact local package bytes and extracted base CLI to one fixture receipt."""
    if not isinstance(source_sha, str) or not _SOURCE.fullmatch(source_sha):
        raise WindowsMsiPreinstallStatusError("Source SHA must be a full lowercase Git SHA.")
    receipt_path = _verified_location(root, receipt_id, "fixture-receipt", source_sha)
    base_path = _verified_location(root, base_id, "desktop-package", source_sha)
    target_path = _verified_location(root, target_id, "desktop-package", source_sha)
    try:
        receipt = json.loads(receipt_path.read_bytes())
        base, target = receipt["builds"]
        base_asset = next(x for x in base["assets"] if x["fileName"].endswith(".msi"))
        target_asset = next(x for x in target["assets"] if x["fileName"].endswith(".msi"))
        if (receipt["schemaVersion"] != 1 or receipt["testOnly"] is not True
                or receipt["productionTrustChanged"] is not False or receipt["architecture"] != "x86_64"
                or not str(receipt["nativeOs"]).startswith("Windows-")
                or base["label"] != "base" or target["label"] != "target"
                or base["version"] == target["version"]
                or not isinstance(base["version"], str) or not _VERSION.fullmatch(base["version"])
                or not isinstance(target["version"], str) or not _VERSION.fullmatch(target["version"])
                or tuple(map(int, target["version"].split("."))) <= tuple(map(int, base["version"].split(".")))
                or base["codeFingerprint"] != target["codeFingerprint"]
                or not _DIGEST.fullmatch(base["codeFingerprint"])
                or not _DIGEST.fullmatch(receipt["sourceFingerprint"])
                or not (base["sourceFingerprint"] == target["sourceFingerprint"] == receipt["sourceFingerprint"])):
            raise ValueError()
        if (base_asset["architecture"] != "x86_64" or target_asset["architecture"] != "x86_64"
                or base_asset["platform"] != "windows" or target_asset["platform"] != "windows"
                or base_asset["sha256"] != base_id.removeprefix("sha256-")
                or target_asset["sha256"] != target_id.removeprefix("sha256-")
                or base_asset["fileName"] != base_path.name or target_asset["fileName"] != target_path.name
                or base_asset["displayVersion"] != base["version"]
                or target_asset["displayVersion"] != target["version"]
                or base_path.name != "vpn-control-" + base["version"] + ".msi"
                or target_path.name != "vpn-control-" + target["version"] + ".msi"
                or base_asset["sizeBytes"] != base_path.stat().st_size
                or target_asset["sizeBytes"] != target_path.stat().st_size):
            raise ValueError()
        if not isinstance(base["image"], str) or base["image"].replace("\\", "/") != "packages/base/vpn-control":
            raise ValueError()
        image = receipt_path.parent / "packages" / "base" / "vpn-control"
        if any(path.is_symlink() for path in (receipt_path.parent, image.parent.parent, image.parent, image)):
            raise ValueError()
        if image.resolve(strict=True) != receipt_path.parent.resolve(strict=True) / "packages" / "base" / "vpn-control":
            raise ValueError()
        cli = image / "vpn-control-cli.exe"
        cli_size, cli_hash = _file_hash(cli)
        if cli_size < 4096:
            raise ValueError()
        app_jars = list((image / "app").glob("desktopApp-*.jar"))
        if len(app_jars) != 1:
            raise ValueError()
        if not _JAR.fullmatch(app_jars[0].name):
            raise ValueError()
        _, app_hash = _file_hash(app_jars[0])
        _, helper_hash = _file_hash(image / "app" / "native" / "windows-amd64" / "vpn-control-install-helper.exe")
        with zipfile.ZipFile(app_jars[0]) as archive:
            runtime_hash = hashlib.sha256(archive.read("bin/windows-amd64/sing-box.exe")).hexdigest()
    except (OSError, ValueError, TypeError, KeyError, IndexError, StopIteration, zipfile.BadZipFile) as error:
        raise WindowsMsiPreinstallStatusError("Same-source Windows MSI fixture is not admitted.") from error
    return {"sourceSha": source_sha, "sourceFingerprint": receipt["sourceFingerprint"],
            "receiptArtifactId": receipt_id, "baseArtifactId": base_id, "targetArtifactId": target_id,
            "baseVersion": base["version"], "targetVersion": target["version"],
            "baseCliSha256": cli_hash, "targetMsiSha256": target_asset["sha256"],
            "targetMsiSize": target_asset["sizeBytes"],
            "baseAppJarName": app_jars[0].name, "baseAppJarSha256": app_hash,
            "baseHelperSha256": helper_hash, "baseRuntimeSha256": runtime_hash}


# The remote code accepts only a configured socket, process generation, and
# validated UUID. It can issue only QGA read commands against two fixed leaves.
_REMOTE_OBSERVE = r'''import base64,json,os,secrets,socket,stat,sys,time
sock,pid,ticks,job=sys.argv[1:]
def out(v): print(json.dumps(v,separators=(",",":"),sort_keys=True))
def live():
 s=os.lstat(sock)
 if not stat.S_ISSOCK(s.st_mode): return False
 raw=open('/proc/%s/stat'%pid,'rb').read().split()
 if len(raw)<22 or raw[21].decode()!=ticks: return False
 inodes=set()
 for name in os.listdir('/proc/%s/fd'%pid):
  try:
   link=os.readlink('/proc/%s/fd/%s'%(pid,name))
   if link.startswith('socket:[') and link.endswith(']'): inodes.add(link[8:-1].encode())
  except OSError: pass
 for line in open('/proc/net/unix','rb'):
  fields=line.split()
  if len(fields)==8 and fields[6] in inodes and fields[7]==os.fsencode(sock): return True
 return False
def exchange(command,args):
 c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); c.settimeout(5)
 try:
  c.connect(sock); sid=secrets.randbits(63)
  c.sendall(b'\xff'+json.dumps({'execute':'guest-sync-delimited','arguments':{'id':sid}},separators=(',',':')).encode()+b'\n')
  seen=0
  while True:
   byte=c.recv(1); seen+=1
   if not byte or seen>8192: raise ValueError()
   if byte==b'\xff': break
  def line():
   raw=bytearray()
   while len(raw)<8192:
    x=c.recv(1)
    if not x: raise ValueError()
    if x==b'\n': return json.loads(raw)
    raw.extend(x)
   raise ValueError()
  if line().get('return')!=sid: raise ValueError()
  c.sendall(json.dumps({'execute':command,'arguments':args},separators=(',',':')).encode()+b'\n')
  return line()
 finally: c.close()
def read_leaf(leaf):
 path='C:\\ProgramData\\vpn-control-install-jobs\\'+job+'\\'+leaf
 opened=exchange('guest-file-open',{'path':path,'mode':'rb'})
 if 'return' not in opened: return None
 handle=opened['return']
 try:
  raw=bytearray()
  for attempt in range(16):
   response=exchange('guest-file-read',{'handle':handle,'count':4096-len(raw)})
   if 'return' not in response: raise ValueError()
   value=response['return']; part=base64.b64decode(value['buf-b64'],validate=True)
   if len(part)>4096-len(raw) or value.get('count')!=len(part): raise ValueError()
   raw.extend(part)
   if value.get('eof') is True or not part: return json.loads(raw)
   if len(raw)==4096: raise ValueError()
  raise ValueError()
 finally: exchange('guest-file-close',{'handle':handle})
stage='binding'
try:
 if not live(): out({'state':'unknown','reason':'guest-binding'}); raise SystemExit(0)
 stage='status'
 status=read_leaf('status.json')
 if status is None: out({'state':'unknown','reason':'status-unavailable'}); raise SystemExit(0)
 stage='diagnostic'
 diagnostic=read_leaf('preinstall-diagnostic.json')
 out({'state':'observed','status':status,'diagnostic':diagnostic})
except Exception: out({'state':'unknown','reason':stage+'-unavailable'})
'''


def _parse(raw: bytes | None, job_id: str) -> dict[str, Any]:
    if raw is None or len(raw) > 8192:
        return {"state": "unknown", "jobId": job_id}
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"state": "unknown", "jobId": job_id}
    if not isinstance(value, dict) or value.get("state") != "observed":
        return {"state": "unknown", "jobId": job_id}
    status, diagnostic = value.get("status"), value.get("diagnostic")
    if (not isinstance(status, dict) or status.get("version") != 1 or status.get("jobId") != job_id
            or type(status.get("sequence")) is not int or status["sequence"] < 0
            or status.get("phase") not in _PHASES or not isinstance(status.get("code"), str)
            or not _CODE.fullmatch(status["code"])):
        return {"state": "unknown", "jobId": job_id}
    result: dict[str, Any] = {"state": "observed", "jobId": job_id, "phase": status["phase"],
                              "code": status["code"], "sequence": status["sequence"]}
    if diagnostic is None:
        result["diagnostic"] = "absent-or-unreadable"
    elif (isinstance(diagnostic, dict) and set(diagnostic) == {"version", "stage", "kind"}
          and diagnostic["version"] == 1 and diagnostic["stage"] in _STAGES
          and diagnostic["kind"] in _KINDS):
        result["diagnostic"] = {"stage": diagnostic["stage"], "kind": diagnostic["kind"]}
    else:
        return {"state": "unknown", "jobId": job_id}
    return result


def preinstall_status(root: Path | str, host: str, job_id: str, timeout_seconds: int = 15) -> dict[str, Any]:
    """Read fixed enum diagnostic and exact protected receipt for one job."""
    if not isinstance(job_id, str) or not _JOB.fullmatch(job_id):
        raise WindowsMsiPreinstallStatusError("Protected job ID must be a canonical lowercase UUID.")
    uuid.UUID(job_id)
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 30:
        raise WindowsMsiPreinstallStatusError("Observation timeout must be 1 through 30 seconds.")
    try:
        config = ssh_transport.load_config(root)
        target = config.hosts[host]
        environment, socket, pid, ticks, _, _, _ = windows_credential_probe_ssh._descriptor(target)
        if host != "archlinux" or environment != "windows-cp117":
            raise WindowsMsiPreinstallStatusError("Windows MSI observer is bound to the owned CP117 guest.")
        command = windows_credential_probe_ssh._remote_command(_REMOTE_OBSERVE, socket, str(pid), str(ticks), job_id)
        argv = ssh_transport.build_ssh_argv(config, host, timeout_seconds, command=command)
        completed = subprocess.run(argv, capture_output=True, timeout=timeout_seconds + 1, check=False)
        raw = completed.stdout if completed.returncode == 0 else None
    except (KeyError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise WindowsMsiPreinstallStatusError("Configured Windows guest observation is unavailable.") from error
    return _parse(raw, job_id)


def _ps_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _public_task(correlation: str, pair: dict[str, Any], sid: str) -> str:
    """Fixed original-user program: assert ready/OFF, then call only public CLI."""
    root = _PUBLIC_ROOT + "\\mcp-msi-" + correlation
    cache = _STATE_DIR + "\\updates\\vpn-control-" + pair["targetVersion"] + ".msi"
    return """$ErrorActionPreference='Stop'
$root={root};$cli={cli};$state={state};$cache={cache}
$stage='IDENTITY'
function P([string]$result){{([pscustomobject]@{{version=1;correlationId={corr};stage=$stage;result=$result}}|ConvertTo-Json -Compress) |
 Set-Content -LiteralPath (Join-Path $root 'task-status.json') -Encoding UTF8}}
try{{
P 'IN_PROGRESS'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$limited=-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if($identity.User.Value -cne {sid} -or (Get-Process -Id $PID).SessionId -ne 1 -or -not $limited){{throw 'ORIGINAL_USER_REJECTED'}}
$stage='PACKAGE';P 'IN_PROGRESS'
if((Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant() -cne {cli_hash}){{throw 'BASE_CLI_CHANGED'}}
if((Get-FileHash -LiteralPath $cache -Algorithm SHA256).Hash.ToLowerInvariant() -cne {target_hash}){{throw 'TARGET_CACHE_CHANGED'}}
$stage='READY';P 'IN_PROGRESS'
$ready=& $cli --state-dir $state --json --timeout-seconds 15 updates status | ConvertFrom-Json
if($LASTEXITCODE -ne 0){{throw 'PUBLIC_READY_UNAVAILABLE'}}
if($ready.code -cne 'OK' -or $ready.final -ne $true -or $ready.data.phase -cne 'ready' -or
 $ready.data.availableVersion -cne {target_version} -or $ready.data.downloadedBytes -ne {target_size} -or
 $ready.data.totalBytes -ne {target_size}){{throw 'PUBLIC_TARGET_NOT_READY'}}
$stage='OWNER';P 'IN_PROGRESS'
$connection=& $cli --state-dir $state --json --timeout-seconds 15 status | ConvertFrom-Json
if($LASTEXITCODE -ne 0){{throw 'PUBLIC_OWNER_UNAVAILABLE'}}
if($connection.code -cne 'OK' -or $connection.controllerId -cne $ready.controllerId -or
 $connection.configurationRevision -ne $ready.configurationRevision -or $connection.data.runtimeRunning -ne $false){{throw 'PUBLIC_OWNER_CHANGED'}}
$stage='INTENT';P 'IN_PROGRESS'
([pscustomobject]@{{correlationId={corr};controllerId=$ready.controllerId;revision=$ready.configurationRevision;
 targetSha256={target_hash};targetVersion={target_version};originalSid=$identity.User.Value;sessionId=1}}|ConvertTo-Json -Compress) |
 Set-Content -LiteralPath (Join-Path $root 'intent.json') -Encoding UTF8
$stage='REQUEST';P 'IN_PROGRESS'
& $cli --state-dir $state --json --controller-id $ready.controllerId --if-revision $ready.configurationRevision --async --timeout-seconds 120 updates install | Set-Content -LiteralPath (Join-Path $root 'request.json') -Encoding UTF8
$LASTEXITCODE | Set-Content -LiteralPath (Join-Path $root 'request.exit') -Encoding Ascii
if($LASTEXITCODE -ne 0){{throw 'REQUEST_UNCERTAIN'}}
$request=Get-Content -LiteralPath (Join-Path $root 'request.json') -Raw|ConvertFrom-Json
if($request.code -cne 'ACCEPTED' -or $request.final -ne $false -or $request.operationId -notmatch '^[0-9a-f-]{{36}}$'){{throw 'REQUEST_UNCERTAIN'}}
$stage='OBSERVE';P 'IN_PROGRESS'
for($i=0;$i -lt 150;$i++){{
 $op=& $cli --state-dir $state --json --timeout-seconds 10 operations status $request.operationId | ConvertFrom-Json
 $oid=$op.operationId;if(-not $oid){{$oid=$op.data.id}};if(-not $oid){{$oid=$op.id}}
 $job=$op.data.jobId;if(-not $job){{$job=$op.jobId}}
 $ctl=$op.controllerId;if(-not $ctl){{$ctl=$op.data.controllerId}}
 $origin=$op.data.originControllerId;$originRequest=$op.data.originRequestId
 if($LASTEXITCODE -eq 0 -and $oid -ceq $request.operationId -and
   ($ctl -ceq $request.controllerId -or ($origin -ceq $request.controllerId -and $originRequest -ceq $request.requestId))){{
  ([pscustomobject]@{{operationId=$oid;controllerId=$ctl;originControllerId=$origin;originRequestId=$originRequest;jobId=$job;code=$op.code;final=$op.final}}|ConvertTo-Json -Compress)|Set-Content -LiteralPath (Join-Path $root 'operation.json') -Encoding UTF8
  if($job -match '^[0-9a-f-]{{36}}$' -or $op.final -eq $true){{break}}
 }}
 Start-Sleep -Seconds 2
}}
$stage='OBSERVE_RETURNED';P 'DONE'
}}catch{{P 'ERROR';exit 1}}
""".format(root=_ps_literal(root), cli=_ps_literal(_INSTALLED_CLI), state=_ps_literal(_STATE_DIR),
           cache=_ps_literal(cache), sid=_ps_literal(sid), cli_hash=_ps_literal(pair["baseCliSha256"]),
           target_hash=_ps_literal(pair["targetMsiSha256"]), target_version=_ps_literal(pair["targetVersion"]),
           target_size=pair["targetMsiSize"], corr=_ps_literal(correlation))


def _bootstrap(correlation: str, pair: dict[str, Any], account: str, sid: str) -> str:
    """Fixed SYSTEM setup for one Interactive, least-privilege original-user task."""
    root = _PUBLIC_ROOT + "\\mcp-msi-" + correlation
    image = r"C:\Users\vpncp117\AppData\Local\vpn-control"
    task = "VpnControlMcpMsi-" + correlation
    body = base64.b64encode(gzip.compress(_public_task(correlation, pair, sid).encode("utf-16le"), mtime=0)).decode("ascii")
    return """$ErrorActionPreference='Stop'
$root={root};$installed={image};$task={task};$body={body}
$stage='EXCLUSIVE'
try{{
if([IO.Directory]::Exists($root) -or (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)){{throw 'SCENARIO_ALREADY_EXISTS'}}
$stage='PACKAGE'
$checks=@(
 @{{path=(Join-Path $installed 'vpn-control-cli.exe');hash={cli_hash}}},
 @{{path=(Join-Path $installed 'app\\{jar}');hash={jar_hash}}},
 @{{path=(Join-Path $installed 'app\\native\\windows-amd64\\vpn-control-install-helper.exe');hash={helper_hash}}},
 @{{path=(Join-Path {state} 'updates\\vpn-control-{target_version}.msi');hash={target_hash}}}
)
foreach($item in $checks){{if(-not [IO.File]::Exists($item.path) -or
 (Get-FileHash -LiteralPath $item.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $item.hash){{throw 'PACKAGE_ADMISSION_FAILED'}}}}
$stage='STAGE'
[IO.Directory]::CreateDirectory($root)|Out-Null
([pscustomobject]@{{version=1;correlationId={corr};taskName=$task;sourceSha={source};targetSha256={target_hash}}}|ConvertTo-Json -Compress) |
 Set-Content -LiteralPath (Join-Path $root 'scenario.json') -Encoding UTF8
$stage='TASK_REGISTER'
$packed=[Convert]::FromBase64String($body)
$inputStream=[IO.MemoryStream]::new([byte[]]$packed)
$decompressor=[IO.Compression.GzipStream]::new($inputStream,[IO.Compression.CompressionMode]::Decompress)
$outputStream=[IO.MemoryStream]::new()
$decompressor.CopyTo($outputStream)
$body=[Convert]::ToBase64String($outputStream.ToArray())
$decompressor.Dispose();$inputStream.Dispose();$outputStream.Dispose()
$action=New-ScheduledTaskAction -Execute 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$body)
$principal=New-ScheduledTaskPrincipal -UserId {account} -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings|Out-Null
$stage='TASK_START'
Start-ScheduledTask -TaskName $task
([pscustomobject]@{{version=1;correlationId={corr};taskName=$task;triggered=$true}}|ConvertTo-Json -Compress)
}}catch{{([pscustomobject]@{{version=1;correlationId={corr};triggered=$false;stage=$stage}}|ConvertTo-Json -Compress);exit 1}}
""".format(root=_ps_literal(root), image=_ps_literal(image), task=_ps_literal(task), body=_ps_literal(body),
           cli_hash=_ps_literal(pair["baseCliSha256"]), jar=pair["baseAppJarName"],
           jar_hash=_ps_literal(pair["baseAppJarSha256"]), helper_hash=_ps_literal(pair["baseHelperSha256"]),
           state=_ps_literal(_STATE_DIR), target_version=pair["targetVersion"], target_hash=_ps_literal(pair["targetMsiSha256"]),
           corr=_ps_literal(correlation), source=_ps_literal(pair["sourceSha"]), account=_ps_literal(account))


_REMOTE_START = campaign_lease.remote_role_guard() + r'''import base64,fcntl,json,os,socket,stat,struct,sys,secrets
root,env,corr=sys.argv[1:]
os.umask(0o077)
def out(v): print(json.dumps(v,separators=(',',':'),sort_keys=True))
def safe_dir(path):
 i=os.lstat(path)
 return stat.S_ISDIR(i.st_mode) and not stat.S_ISLNK(i.st_mode) and i.st_uid==os.geteuid() and stat.S_IMODE(i.st_mode)==0o700
def live(sock,pid,ticks):
 try:
  if not stat.S_ISSOCK(os.lstat(sock).st_mode): return False
  raw=open('/proc/%d/stat'%pid,'rb').read().split()
  if len(raw)<22 or raw[21].decode()!=str(ticks): return False
  inodes=set()
  for name in os.listdir('/proc/%d/fd'%pid):
   try:
    link=os.readlink('/proc/%d/fd/%s'%(pid,name))
    if link.startswith('socket:[') and link.endswith(']'): inodes.add(link[8:-1].encode())
   except OSError: pass
  for line in open('/proc/net/unix','rb'):
   fields=line.split()
   if len(fields)==8 and fields[6] in inodes and fields[7]==os.fsencode(sock): return True
 except OSError: pass
 return False
def call(sock,command,args):
 c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); c.settimeout(8)
 try:
  c.connect(sock); sid=secrets.randbits(63)
  c.sendall(b'\xff'+json.dumps({'execute':'guest-sync-delimited','arguments':{'id':sid}},separators=(',',':')).encode()+b'\n')
  seen=0
  while True:
   x=c.recv(1); seen+=1
   if not x or seen>8192: raise ValueError()
   if x==b'\xff': break
  def line():
   raw=bytearray()
   while len(raw)<16384:
    x=c.recv(1)
    if not x: raise ValueError()
    if x==b'\n': return json.loads(raw)
    raw.extend(x)
   raise ValueError()
  if line().get('return')!=sid: raise ValueError()
  c.sendall(json.dumps({'execute':command,'arguments':args},separators=(',',':')).encode()+b'\n')
  return line()
 finally: c.close()
try:
 if not safe_dir(root) or env!='windows-cp117': raise ValueError()
 header=sys.stdin.buffer.read(4)
 if len(header)!=4: raise ValueError()
 length=struct.unpack('>I',header)[0]
 if length<1 or length>65536: raise ValueError()
 raw=sys.stdin.buffer.read(length)
 if len(raw)!=length or sys.stdin.buffer.read(1): raise ValueError()
 value=json.loads(raw)
 if set(value)!={'schema','leaseId','socketPath','pid','startTicks','encodedCommand','commandSha256','sourceSha','artifactIds'} or value['schema']!=1: raise ValueError()
 sock=value['socketPath']; pid=value['pid']; ticks=value['startTicks']; encoded=value['encodedCommand']
 if not isinstance(sock,str) or not sock.startswith('/') or not isinstance(pid,int) or not isinstance(ticks,int) or not live(sock,pid,ticks): raise ValueError()
 if not isinstance(encoded,str) or len(encoded)>30000 or len(encoded)<100: raise ValueError()
 if __import__('hashlib').sha256(base64.b64decode(encoded,validate=True)).hexdigest()!=value['commandSha256']: raise ValueError()
 if not isinstance(value['artifactIds'],list) or len(value['artifactIds'])!=3:raise ValueError()
 require_campaign_role(root,env,value['leaseId'],'public',corr,value['sourceSha'],*value['artifactIds'],sock,pid,ticks)
 parent=os.path.join(root,env)
 if not os.path.exists(parent): os.mkdir(parent,0o700)
 if not safe_dir(parent): raise ValueError()
 group=os.path.join(parent,'windows-msi-public')
 if not os.path.exists(group): os.mkdir(group,0o700)
 if not safe_dir(group): raise ValueError()
 lock=os.open(os.path.join(group,'.environment.lock'),os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
 try:
  fcntl.flock(lock,fcntl.LOCK_EX)
  if any(name!='.environment.lock' for name in os.listdir(group)): raise FileExistsError()
  stage=os.path.join(group,corr)
  os.mkdir(stage,0o700)
 finally: os.close(lock)
 record={k:value[k] for k in ('socketPath','pid','startTicks','sourceSha','artifactIds','commandSha256')}
 with open(os.path.join(stage,'binding.json'),'x',encoding='utf-8') as file:
  json.dump(record,file,separators=(',',':')); file.flush(); os.fsync(file.fileno())
 result=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})
 child=result.get('return',{}).get('pid')
 if not isinstance(child,int) or child<=0: raise ValueError()
 with open(os.path.join(stage,'dispatch.json'),'x',encoding='utf-8') as file:
  json.dump({'pid':child},file,separators=(',',':')); file.flush(); os.fsync(file.fileno())
 out({'state':'submitted','pid':child})
except FileExistsError: out({'state':'unknown','reason':'correlation-exists'})
except Exception: out({'state':'unknown','reason':'start-uncertain'})
'''


def _intent_file(root: Path, correlation: str) -> Path:
    return root / ".rag_index" / "windows-msi-public" / (correlation + ".json")


def _write_intent(root: Path, correlation: str, record: dict[str, Any]) -> None:
    path = _intent_file(root, correlation)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if fcntl is None:
        raise WindowsMsiPreinstallStatusError("MSI scenario requires a POSIX durable lease.")
    lock = path.parent / ".environment.lock"
    lock_fd = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if any(item.name.endswith(".json") for item in path.parent.iterdir()):
            raise WindowsMsiPreinstallStatusError("CP117 already has an active or unknown MSI scenario.")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(record, file, sort_keys=True, separators=(",", ":"))
            file.write("\n"); file.flush(); os.fsync(file.fileno())
        parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(parent)
        finally: os.close(parent)
    finally:
        os.close(lock_fd)


def _read_intent(root: Path, correlation: str) -> dict[str, Any]:
    path = _intent_file(root, correlation)
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise WindowsMsiPreinstallStatusError("MSI scenario intent is not private.")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict) or value.get("correlationId") != correlation or value.get("host") != "archlinux":
        raise WindowsMsiPreinstallStatusError("MSI scenario intent binding is invalid.")
    return value


def _require_live_fixture_campaign(root: Path, inputs: dict[str, Any],
                                   descriptor: tuple[Any, ...], config: Any, target: Any) -> tuple[str, dict[str, Any]]:
    """Internal only; fail before a public request without a live server receipt."""
    from agent_tools import windows_msi_base_prepare
    environment, socket, pid, ticks, _account, sid, _ = descriptor
    lease_id = windows_msi_base_prepare._require_verified_live_fixture(
        root, inputs, (environment, socket, pid, ticks, sid), config, target)
    from agent_tools import windows_fixture_network_probe, windows_msi_target_prepare
    probe = windows_fixture_network_probe.verified_owner_network_receipt(root, lease_id)
    if (not isinstance(probe, dict) or probe.get("originalSid") != sid
            or not isinstance(probe.get("controllerId"), str)
            or not isinstance(probe.get("ownerPid"), int)
            or not isinstance(probe.get("ownerStartedAtUtc"), str)):
        raise WindowsMsiPreinstallStatusError("CP117 original-owner network probe is unavailable.")
    request = {**inputs, "controllerId": probe["controllerId"],
               "ownerPid": probe["ownerPid"], "ownerStartedAtUtc": probe["ownerStartedAtUtc"]}
    fixture = windows_msi_target_prepare._verified_network_context(root, request, lease_id)
    return lease_id, fixture


def start(root: Path | str, inputs: dict[str, Any]) -> dict[str, Any]:
    """Submit one fixed public-update request after durable local/remote intent."""
    allowed = {"host", "correlationId", "sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId", "timeoutSeconds"}
    if not isinstance(inputs, dict) or set(inputs) - allowed or not (allowed - {"timeoutSeconds"}).issubset(inputs):
        raise WindowsMsiPreinstallStatusError("MSI public scenario inputs are invalid.")
    host, correlation = inputs["host"], inputs["correlationId"]
    if host != "archlinux" or not isinstance(correlation, str) or not _JOB.fullmatch(correlation):
        raise WindowsMsiPreinstallStatusError("MSI scenario must target the owned CP117 guest and a new UUID.")
    uuid.UUID(correlation)
    timeout = inputs.get("timeoutSeconds", 20)
    if type(timeout) is not int or not 1 <= timeout <= 30:
        raise WindowsMsiPreinstallStatusError("MSI scenario timeout must be 1 through 30 seconds.")
    root_path = Path(root).resolve()
    pair = _admit_pair(root_path, inputs["sourceSha"], inputs["fixtureReceiptArtifactId"],
                       inputs["baseMsiArtifactId"], inputs["targetMsiArtifactId"])
    config = ssh_transport.load_config(root_path)
    target = config.hosts.get(host)
    if target is None or target.fixture_transfer_root is None:
        raise WindowsMsiPreinstallStatusError("Configured CP117 transfer root is unavailable.")
    environment, socket, pid, ticks, account, sid, _ = windows_credential_probe_ssh._descriptor(target)
    if environment != "windows-cp117" or account != "vpncp117":
        raise WindowsMsiPreinstallStatusError("Configured Windows guest identity changed.")
    command = _bootstrap(correlation, pair, "VPNMSIX64\\vpncp117", sid)
    encoded = base64.b64encode(command.encode("utf-16le")).decode("ascii")
    if len(encoded) >= 30000:
        raise WindowsMsiPreinstallStatusError("Fixed MSI bootstrap exceeds Windows command-line admission.")
    command_hash = hashlib.sha256(command.encode("utf-16le")).hexdigest()
    lease_id, fixture = _require_live_fixture_campaign(root_path, inputs,
        (environment, socket, pid, ticks, account, sid, _), config, target)
    intent = {"schemaVersion": 1, "host": host, "correlationId": correlation, "environment": environment,
              "socketPath": socket, "pid": pid, "startTicks": ticks, "pair": pair, "commandSha256": command_hash}
    intent["expectedSid"] = sid
    intent["leaseId"] = lease_id
    intent["networkProbeReceiptSha256"] = fixture["probeReceiptSha256"]
    intent["expectedControllerId"] = fixture["controllerId"]
    intent["expectedOwnerPid"] = fixture["ownerPid"]
    intent["expectedOwnerStartedAtUtc"] = fixture["ownerStartedAtUtc"]
    _write_intent(root_path, correlation, intent)
    from agent_tools import windows_msi_base_prepare
    claimed = campaign_lease.claim_role(root_path, lease_id, "public", correlation,
        windows_msi_base_prepare._campaign_remote(config, target))
    if claimed["state"] != "role-active":
        raise WindowsMsiPreinstallStatusError("CP117 public claim is unknown; inspect, do not replay.")
    windows_msi_base_prepare._verified_claimed_campaign(root_path, inputs,
        (environment, socket, pid, ticks, sid), config, target, lease_id, "public")
    from agent_tools import windows_msi_target_prepare
    refreshed = windows_msi_target_prepare._verified_network_context(root_path,
        {**inputs, "controllerId": fixture["controllerId"], "ownerPid": fixture["ownerPid"],
         "ownerStartedAtUtc": fixture["ownerStartedAtUtc"]}, lease_id)
    if refreshed["probeReceiptSha256"] != fixture["probeReceiptSha256"]:
        raise WindowsMsiPreinstallStatusError("CP117 owner network probe changed after claim.")
    payload = {"schema": 1, "leaseId": lease_id, "socketPath": socket, "pid": pid, "startTicks": ticks,
               "encodedCommand": encoded, "commandSha256": command_hash, "sourceSha": pair["sourceSha"],
               "artifactIds": [pair["receiptArtifactId"], pair["baseArtifactId"], pair["targetArtifactId"]]}
    raw = windows_credential_probe_ssh._run_ssh(config, host,
        windows_credential_probe_ssh._remote_command(_REMOTE_START, str(target.fixture_transfer_root), environment, correlation),
        windows_credential_probe_ssh._remote_payload(payload), timeout)
    try:
        result = json.loads(raw) if raw is not None else {}
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
        result = {}
    if not isinstance(result, dict) or result.get("state") != "submitted" or type(result.get("pid")) is not int:
        return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    return {"state": "submitted", "correlationId": correlation, "pid": result["pid"], "replayAllowed": False}


_REMOTE_STATUS = r'''import base64,hashlib,json,os,secrets,socket,stat,sys
root,env,corr,sock_expected,pid_expected,ticks_expected,source_expected,receipt_id,base_id,target_id,command_expected=sys.argv[1:]
def out(v): print(json.dumps(v,separators=(',',':'),sort_keys=True))
def live(sock,pid,ticks):
 try:
  if not stat.S_ISSOCK(os.lstat(sock).st_mode): return False
  raw=open('/proc/%d/stat'%pid,'rb').read().split()
  if len(raw)<22 or raw[21].decode()!=str(ticks): return False
  inodes=set()
  for name in os.listdir('/proc/%d/fd'%pid):
   try:
    link=os.readlink('/proc/%d/fd/%s'%(pid,name))
    if link.startswith('socket:[') and link.endswith(']'): inodes.add(link[8:-1].encode())
   except OSError: pass
  for line in open('/proc/net/unix','rb'):
   fields=line.split()
   if len(fields)==8 and fields[6] in inodes and fields[7]==os.fsencode(sock): return True
 except OSError: pass
 return False
def call(sock,command,args):
 c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); c.settimeout(5)
 try:
  c.connect(sock); sid=secrets.randbits(63)
  c.sendall(b'\xff'+json.dumps({'execute':'guest-sync-delimited','arguments':{'id':sid}},separators=(',',':')).encode()+b'\n')
  seen=0
  while True:
   x=c.recv(1); seen+=1
   if not x or seen>8192: raise ValueError()
   if x==b'\xff': break
  def line():
   raw=bytearray()
   while len(raw)<16384:
    x=c.recv(1)
    if not x: raise ValueError()
    if x==b'\n': return json.loads(raw)
    raw.extend(x)
   raise ValueError()
  if line().get('return')!=sid: raise ValueError()
  c.sendall(json.dumps({'execute':command,'arguments':args},separators=(',',':')).encode()+b'\n')
  return line()
 finally: c.close()
def read(sock,path):
 opened=call(sock,'guest-file-open',{'path':path,'mode':'rb'})
 if 'return' not in opened: return None
 handle=opened['return']; raw=bytearray()
 try:
  for attempt in range(16):
   result=call(sock,'guest-file-read',{'handle':handle,'count':8192-len(raw)})
   if 'return' not in result: raise ValueError()
   value=result['return']; part=base64.b64decode(value['buf-b64'],validate=True)
   if len(part)>8192-len(raw) or value.get('count')!=len(part): raise ValueError()
   raw.extend(part)
   if value.get('eof') is True or not part: return bytes(raw)
   if len(raw)==8192: raise ValueError()
  raise ValueError()
 finally: call(sock,'guest-file-close',{'handle':handle})
def decode(raw):
 if raw.startswith(b'\xff\xfe'): return raw.decode('utf-16')
 if raw.startswith(b'\xef\xbb\xbf'): return raw.decode('utf-8-sig')
 return raw.decode('utf-8')
try:
 stage=os.path.join(root,env,'windows-msi-public',corr)
 info=os.lstat(stage)
 if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700: raise ValueError()
 with open(os.path.join(stage,'binding.json'),encoding='utf-8') as file: binding=json.load(file)
 if set(binding)!={'socketPath','pid','startTicks','sourceSha','artifactIds','commandSha256'}: raise ValueError()
 if (binding['socketPath']!=sock_expected or str(binding['pid'])!=pid_expected or
     str(binding['startTicks'])!=ticks_expected or binding['sourceSha']!=source_expected or
     binding['artifactIds']!=[receipt_id,base_id,target_id] or binding['commandSha256']!=command_expected): raise ValueError()
 sock=binding['socketPath']
 if not live(sock,binding['pid'],binding['startTicks']): raise ValueError()
 with open(os.path.join(stage,'dispatch.json'),encoding='utf-8') as file: dispatch=json.load(file)
 child=dispatch['pid']
 if not isinstance(child,int) or child<=0: raise ValueError()
 process=call(sock,'guest-exec-status',{'pid':child}).get('return')
 if not isinstance(process,dict): raise ValueError()
 result={'state':'observed','dispatchExited':process.get('exited') is True}
 if not result['dispatchExited']: out(result); raise SystemExit(0)
 result['dispatchExitCode']=process.get('exitcode')
 output=base64.b64decode(process.get('out-data',''),validate=True)
 if len(output)>8192: raise ValueError()
 lines=[x for x in decode(output).splitlines() if x.startswith('{') and x.endswith('}')]
 if result['dispatchExitCode']!=0 or not lines:
  if lines:
   failure=json.loads(lines[-1])
   if failure.get('version')==1 and failure.get('correlationId')==corr and failure.get('triggered') is False:
    result['bootstrapStage']=failure.get('stage')
  out(result); raise SystemExit(0)
 bootstrap=json.loads(lines[-1])
 if bootstrap.get('version')!=1 or bootstrap.get('correlationId')!=corr or bootstrap.get('triggered') is not True: raise ValueError()
 result['taskTriggered']=True
 base='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-msi-'+corr+'\\'
 task_status=read(sock,base+'task-status.json')
 if task_status is not None and task_status:
  stage=json.loads(decode(task_status))
  result['taskStage']=stage.get('stage'); result['taskResult']=stage.get('result')
  result['taskCorrelationId']=stage.get('correlationId'); result['taskVersion']=stage.get('version')
 intent=read(sock,base+'intent.json')
 if intent is None: out(result); raise SystemExit(0)
 record=json.loads(decode(intent))
 if record.get('correlationId')!=corr: raise ValueError()
 result['originalSid']=record.get('originalSid'); result['sessionId']=record.get('sessionId')
 result['controllerId']=record.get('controllerId'); result['revision']=record.get('revision')
 result['targetSha256']=record.get('targetSha256'); result['targetVersion']=record.get('targetVersion')
 request=read(sock,base+'request.json')
 if request is None or not request: out(result); raise SystemExit(0)
 public=json.loads(decode(request))
 result['requestCode']=public.get('code'); result['requestFinal']=public.get('final')
 result['operationId']=public.get('operationId'); result['requestId']=public.get('requestId')
 exit_bytes=read(sock,base+'request.exit')
 if exit_bytes is not None: result['requestExit']=decode(exit_bytes).strip()
 data=public.get('data')
 if isinstance(data,dict): result['jobId']=data.get('jobId')
 controller=result.get('controllerId'); operation_id=result.get('operationId')
 if isinstance(controller,str) and isinstance(operation_id,str) and len(controller)==36 and len(operation_id)==36:
  key=json.dumps({'controllerId':controller,'operationId':operation_id},separators=(',',':'))
  leaf='.install-correlation-'+hashlib.sha256(key.encode()).hexdigest()+'.json'
  workspace='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\cp166\\state'
  journal=read(sock,workspace+'\\'+leaf)
  if journal is not None and journal:
   binding=json.loads(decode(journal))
   if (set(binding)!={'version','controllerId','requestId','operationId','jobId','workspaceKey'}
       or type(binding['version']) is not int or binding['version']!=1
       or binding['workspaceKey']!=hashlib.sha256(workspace.encode()).hexdigest()): raise ValueError()
   result['journalControllerId']=binding.get('controllerId')
   result['journalRequestId']=binding.get('requestId')
   result['journalOperationId']=binding.get('operationId')
   result['journalJobId']=binding.get('jobId')
   result['journalVersion']=binding.get('version')
   if result.get('jobId') is None: result['jobId']=binding.get('jobId')
 operation=read(sock,base+'operation.json')
 if operation is not None and operation:
  observed=json.loads(decode(operation))
  result['observedOperationId']=observed.get('operationId')
  result['observedControllerId']=observed.get('controllerId')
  result['observedOriginControllerId']=observed.get('originControllerId')
  result['observedOriginRequestId']=observed.get('originRequestId')
  result['observedJobId']=observed.get('jobId')
  result['observedCode']=observed.get('code')
  result['observedFinal']=observed.get('final')
  if result.get('jobId') is None: result['jobId']=observed.get('jobId')
 job=result.get('jobId')
 if isinstance(job,str) and len(job)==36:
  protected=read(sock,'C:\\ProgramData\\vpn-control-install-jobs\\'+job+'\\status.json')
  if protected is not None and protected:
   result['protected']=json.loads(decode(protected))
 out(result)
except Exception: out({'state':'unknown','reason':'status-uncertain'})
'''


def _status_result(raw: bytes | None, correlation: str, intent: dict[str, Any]) -> dict[str, Any]:
    unknown = {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    if raw is None or len(raw) > 16384:
        return unknown
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return unknown
    if not isinstance(value, dict) or value.get("state") != "observed":
        return unknown
    result: dict[str, Any] = {"state": "observed", "correlationId": correlation, "replayAllowed": False,
                              "sourceSha": intent["pair"]["sourceSha"]}
    if value.get("dispatchExited") is not True:
        result["phase"] = "bootstrap-running"
        return result
    if type(value.get("dispatchExitCode")) is not int or value["dispatchExitCode"] != 0 or value.get("taskTriggered") is not True:
        stage = value.get("bootstrapStage")
        if stage in _BOOTSTRAP_STAGES:
            result["bootstrapStage"] = stage
        result["phase"] = "bootstrap-unknown"
        return result
    if "taskStage" in value:
        if (value.get("taskCorrelationId") != correlation or value.get("taskVersion") != 1
                or value.get("taskStage") not in _TASK_STAGES or value.get("taskResult") not in _TASK_RESULTS):
            return unknown
        result["taskStage"] = value["taskStage"]
        if value["taskResult"] == "ERROR":
            result["phase"] = "task-error"
            return result
    if "requestCode" not in value:
        result["phase"] = "public-request-pending-or-unreadable"
        return result
    controller = value.get("controllerId")
    if (value.get("originalSid") != intent.get("expectedSid") or value.get("sessionId") != 1
            or not isinstance(controller, str) or not _JOB.fullmatch(controller)
            or ("expectedControllerId" in intent and controller != intent["expectedControllerId"])
            or type(value.get("revision")) is not int or value["revision"] < 0
            or value.get("targetSha256") != intent["pair"]["targetMsiSha256"]
            or value.get("targetVersion") != intent["pair"]["targetVersion"]):
        return unknown
    result["controllerId"] = controller
    result["configurationRevision"] = value["revision"]
    code = value.get("requestCode")
    if not isinstance(code, str) or not _CODE.fullmatch(code):
        return unknown
    result["requestCode"] = code
    for key in ("operationId", "requestId", "jobId"):
        item = value.get(key)
        if item is not None:
            if not isinstance(item, str) or not _JOB.fullmatch(item):
                return unknown
            result[key] = item
    result["phase"] = "public-request-observed"
    if (value.get("observedJobId") is not None and value.get("journalJobId") is not None
            and value["observedJobId"] != value["journalJobId"]):
        return unknown
    if (value.get("journalJobId") is not None and value["journalJobId"] != result.get("jobId")):
        return unknown
    if (value.get("taskStage") not in {"OBSERVE", "OBSERVE_RETURNED"}
            or value.get("taskResult") not in {"IN_PROGRESS", "DONE"}
            or code != "ACCEPTED" or value.get("requestFinal") is not False
            or value.get("requestExit") != "0"
            or any(key not in result for key in ("operationId", "requestId", "jobId"))):
        return result
    operation_bound = (value.get("observedOperationId") == result.get("operationId")
        and (value.get("observedControllerId") == controller or
             (value.get("observedOriginControllerId") == controller and
              value.get("observedOriginRequestId") == result["requestId"]))
        and value.get("observedJobId") == result.get("jobId")
        and isinstance(value.get("observedCode"), str) and _CODE.fullmatch(value["observedCode"])
        and type(value.get("observedFinal")) is bool)
    journal_bound = (type(value.get("journalVersion")) is int and value["journalVersion"] == 1
        and value.get("journalControllerId") == controller
        and value.get("journalRequestId") == result["requestId"]
        and value.get("journalOperationId") == result.get("operationId")
        and value.get("journalJobId") == result.get("jobId"))
    if not operation_bound and not journal_bound:
        return result
    protected = value.get("protected")
    if isinstance(protected, dict) and protected.get("jobId") == result.get("jobId"):
        if (protected.get("version") != 1 or type(protected.get("sequence")) is not int
                or protected["sequence"] < 0 or protected.get("phase") not in _PHASES
                or not isinstance(protected.get("code"), str) or not _CODE.fullmatch(protected["code"])):
            return unknown
        result["protected"] = {"phase": protected["phase"], "code": protected["code"], "sequence": protected["sequence"]}
        result["phase"] = "protected-terminal" if protected["phase"] in {"Succeeded", "Failed", "Cancelled"} else "awaiting-uac-or-installer"
    return result


def status(root: Path | str, inputs: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(inputs, dict) or set(inputs) - {"host", "correlationId", "timeoutSeconds"} or not {"host", "correlationId"}.issubset(inputs):
        raise WindowsMsiPreinstallStatusError("MSI scenario status inputs are invalid.")
    correlation = inputs["correlationId"]
    if not isinstance(correlation, str) or not _JOB.fullmatch(correlation):
        raise WindowsMsiPreinstallStatusError("MSI scenario correlation is invalid.")
    timeout = inputs.get("timeoutSeconds", 20)
    if type(timeout) is not int or not 1 <= timeout <= 30:
        raise WindowsMsiPreinstallStatusError("MSI scenario timeout must be 1 through 30 seconds.")
    root_path = Path(root).resolve()
    intent = _read_intent(root_path, correlation)
    if inputs["host"] != intent["host"]:
        raise WindowsMsiPreinstallStatusError("MSI scenario host does not match durable intent.")
    config = ssh_transport.load_config(root_path)
    target = config.hosts.get(intent["host"])
    if target is None or target.fixture_transfer_root is None:
        raise WindowsMsiPreinstallStatusError("Configured CP117 transfer root is unavailable.")
    raw = windows_credential_probe_ssh._run_ssh(config, intent["host"],
        windows_credential_probe_ssh._remote_command(
            _REMOTE_STATUS, str(target.fixture_transfer_root), intent["environment"], correlation,
            intent["socketPath"], str(intent["pid"]), str(intent["startTicks"]),
            intent["pair"]["sourceSha"], intent["pair"]["receiptArtifactId"],
            intent["pair"]["baseArtifactId"], intent["pair"]["targetArtifactId"], intent["commandSha256"]),
        None, timeout)
    return _status_result(raw, correlation, intent)


def collect(root: Path | str, inputs: dict[str, Any]) -> dict[str, Any]:
    """Return protected terminal evidence only; installed/relaunch needs separate proof."""
    result = status(root, inputs)
    if result["state"] != "observed" or result.get("phase") != "protected-terminal":
        return {**result, "collected": False}
    return {**result, "collected": True, "installedVerified": False}


def _powershell_preflight_script() -> str:
    """Inert PS5 parser and UTF-8 pipeline probe for this exact fixed program."""
    pair = {"targetVersion": "2.2.0", "baseCliSha256": "a" * 64,
            "targetMsiSha256": "b" * 64, "targetMsiSize": 1000,
            "baseAppJarName": "desktopApp-fixed.jar", "baseAppJarSha256": "c" * 64,
            "baseHelperSha256": "d" * 64, "sourceSha": "e" * 40}
    correlation = "11111111-1111-4111-8111-111111111111"
    bootstrap = _bootstrap(correlation, pair, "VPNMSIX64\\vpncp117", "S-1-5-21-1-2-3-1002")
    task = _public_task(correlation, pair, "S-1-5-21-1-2-3-1002")
    def packed(value: str) -> str:
        return base64.b64encode(gzip.compress(value.encode("utf-16le"), mtime=0)).decode("ascii")
    return r'''$ErrorActionPreference='Stop'
function Expand([string]$body) {
 $packed=[Convert]::FromBase64String($body)
 $inputStream=[IO.MemoryStream]::new([byte[]]$packed)
 $decompressor=[IO.Compression.GzipStream]::new($inputStream,[IO.Compression.CompressionMode]::Decompress)
 $outputStream=[IO.MemoryStream]::new()
 $decompressor.CopyTo($outputStream)
 $body=[Text.Encoding]::Unicode.GetString($outputStream.ToArray())
 $decompressor.Dispose();$inputStream.Dispose();$outputStream.Dispose()
 return $body
}
try {
 $bootstrap=Expand '@BOOTSTRAP@';$task=Expand '@TASK@'
 $tokens=$null;$errors=$null
 [System.Management.Automation.Language.Parser]::ParseInput($bootstrap,[ref]$tokens,[ref]$errors)|Out-Null
 if($errors.Count -ne 0){throw 'BOOTSTRAP_SYNTAX'}
 [System.Management.Automation.Language.Parser]::ParseInput($task,[ref]$tokens,[ref]$errors)|Out-Null
 if($errors.Count -ne 0){throw 'TASK_SYNTAX'}
 $leaf=Join-Path $env:TEMP ('vpn-msi-ps-preflight-'+[Guid]::NewGuid().ToString('N')+'.json')
 try {
  '{"version":1,"code":"OK","pad":"'+('x'*240)+'"}' | Set-Content -LiteralPath $leaf -Encoding UTF8
  $value=Get-Content -LiteralPath $leaf -Raw|ConvertFrom-Json
  if($value.version -ne 1 -or $value.code -cne 'OK' -or $value.pad.Length -ne 240){throw 'UTF8_PIPELINE'}
 } finally {Remove-Item -LiteralPath $leaf -Force -ErrorAction SilentlyContinue}
 [Console]::Out.WriteLine('{"version":1,"code":"OK"}')
} catch {[Console]::Out.WriteLine('{"version":1,"code":"FAILED"}');exit 1}
'''.replace("@BOOTSTRAP@", packed(bootstrap)).replace("@TASK@", packed(task))


_REMOTE_PREFLIGHT = r'''import base64,json,os,secrets,socket,stat,sys,time
sock,pid,ticks,encoded=sys.argv[1:]
def out(v): print(json.dumps(v,separators=(',',':'),sort_keys=True))
def live():
 try:
  if not stat.S_ISSOCK(os.lstat(sock).st_mode): return False
  raw=open('/proc/%s/stat'%pid,'rb').read().split()
  if len(raw)<22 or raw[21].decode()!=ticks: return False
  inodes=set()
  for name in os.listdir('/proc/%s/fd'%pid):
   try:
    link=os.readlink('/proc/%s/fd/%s'%(pid,name))
    if link.startswith('socket:[') and link.endswith(']'): inodes.add(link[8:-1].encode())
   except OSError: pass
  for line in open('/proc/net/unix','rb'):
   fields=line.split()
   if len(fields)==8 and fields[6] in inodes and fields[7]==os.fsencode(sock): return True
 except OSError: pass
 return False
def call(command,args):
 c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);c.settimeout(8)
 try:
  c.connect(sock);sid=secrets.randbits(63)
  c.sendall(b'\xff'+json.dumps({'execute':'guest-sync-delimited','arguments':{'id':sid}},separators=(',',':')).encode()+b'\n')
  seen=0
  while True:
   x=c.recv(1);seen+=1
   if not x or seen>8192: raise ValueError()
   if x==b'\xff': break
  def line():
   raw=bytearray()
   while len(raw)<16384:
    x=c.recv(1)
    if not x: raise ValueError()
    if x==b'\n': return json.loads(raw)
    raw.extend(x)
   raise ValueError()
  if line().get('return')!=sid: raise ValueError()
  c.sendall(json.dumps({'execute':command,'arguments':args},separators=(',',':')).encode()+b'\n')
  return line()
 finally:c.close()
try:
 if not live() or len(encoded)>30000: raise ValueError()
 start=call('guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})
 child=start.get('return',{}).get('pid')
 if not isinstance(child,int) or child<=0: raise ValueError()
 for attempt in range(40):
  status=call('guest-exec-status',{'pid':child}).get('return')
  if not isinstance(status,dict): raise ValueError()
  if status.get('exited') is True: break
  time.sleep(.25)
 else: out({'state':'unknown','reason':'preflight-running'});raise SystemExit(0)
 raw=base64.b64decode(status.get('out-data',''),validate=True)
 if len(raw)>4096: raise ValueError()
 lines=[x for x in raw.decode('utf-8-sig').splitlines() if x.startswith('{') and x.endswith('}')]
 value=json.loads(lines[-1]) if lines else None
 if status.get('exitcode')==0 and value=={'version':1,'code':'OK'}: out({'state':'passed','checks':['ps5-parse','gzip','utf8-pipeline']})
 else: out({'state':'failed','checks':['ps5-parse','gzip','utf8-pipeline']})
except Exception: out({'state':'unknown','reason':'preflight-uncertain'})
'''


def powershell_preflight(root: Path | str, inputs: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(inputs, dict) or set(inputs) != {"host"} or inputs["host"] != "archlinux":
        raise WindowsMsiPreinstallStatusError("Windows MSI PS5 preflight accepts only the configured host.")
    root_path = Path(root).resolve()
    config = ssh_transport.load_config(root_path)
    target = config.hosts.get("archlinux")
    if target is None:
        raise WindowsMsiPreinstallStatusError("Configured CP117 host is unavailable.")
    environment, socket_path, pid, ticks, account, _, _ = windows_credential_probe_ssh._descriptor(target)
    if environment != "windows-cp117" or account != "vpncp117":
        raise WindowsMsiPreinstallStatusError("Owned CP117 identity changed.")
    encoded = base64.b64encode(_powershell_preflight_script().encode("utf-16le")).decode("ascii")
    if len(encoded) >= 30000:
        raise WindowsMsiPreinstallStatusError("Fixed PS5 preflight exceeds command-line admission.")
    raw = windows_credential_probe_ssh._run_ssh(config, "archlinux",
        windows_credential_probe_ssh._remote_command(_REMOTE_PREFLIGHT, socket_path, str(pid), str(ticks), encoded),
        None, 30)
    try:
        value = json.loads(raw) if raw is not None else {}
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
        value = {}
    if not isinstance(value, dict) or value.get("state") not in {"passed", "failed"}:
        return {"state": "unknown", "checks": []}
    return {"state": value["state"], "checks": ["ps5-parse", "gzip", "utf8-pipeline"]}
