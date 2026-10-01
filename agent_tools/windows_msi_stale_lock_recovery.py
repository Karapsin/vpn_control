"""One-shot removal of CP117's proven stale original-user lock.

This is deliberately not a general state-directory cleanup API.  It admits
only the recorded c32 base fixture, writes an immutable host intent, then asks
the same QEMU generation to repeat every safety check immediately before it
removes ``vpn-control.lock``.  A lost response leaves that intent unresolved;
the deletion is never replayed.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Mapping

from . import windows_msi_base_prepare as base


class WindowsMsiStaleLockRecoveryError(ValueError):
    pass


_CORRELATION = "c32cb108-4d48-407e-9153-40774559ba50"
_SOURCE = "19be9df22cbab8086c26e5ca907d9569a5a28a08"
_ARTIFACTS = {
    "fixtureReceiptArtifactId": "sha256-d437b2931db91c7b0ad97fb2809dfa0b224cb9f98d28634f4c4948e1117a705d",
    "baseMsiArtifactId": "sha256-0fada9685bb308346723e6ca74c102c699dc86ffda8fb097fc99303c5ab5aaa3",
    "targetMsiArtifactId": "sha256-5ac252557106a2bae56583253a70ea037bb300827df6b5c36b2dc502e1e01234",
}
_GROUP = ".rag_index/windows-msi-stale-lock-recovery"
_UNKNOWN = {"state": "unknown", "replayAllowed": False, "nativeActionAllowed": False}
_OPEN_ERROR_CATEGORIES = {32: 'lock-open-sharing-violation', 5: 'lock-open-access-denied',
                          87: 'lock-open-invalid-parameter', 2: 'lock-open-path-issue',
                          3: 'lock-open-path-issue', 123: 'lock-open-path-issue',
                          161: 'lock-open-path-issue'}
_DIAGNOSTIC_CATEGORIES = {'safe-proven', 'exclusive-handle-acl-blocked', 'lock-open-sharing-violation',
                          'lock-open-access-denied', 'lock-open-invalid-parameter',
                          'lock-open-path-issue', 'lock-open-other', 'lock-open-invocation',
                          'ancestors', 'cli', 'product', 'state-acl', 'lock', 'endpoint',
                          'processes', 'unexpected'}


def _open_error_category(code: int) -> str:
    """Project a Win32 open failure without exposing its numeric detail."""
    return _OPEN_ERROR_CATEGORIES.get(code, 'lock-open-other') if type(code) is int else 'lock-open-other'


# Both modes are read-only until the final, guarded Remove-Item.  The remove
# mode repeats Probe in the guest, so a host-side first census cannot race it.
_PS = r'''$ErrorActionPreference='Stop'
$sid='__SID__';$expectedHash='__CLI_HASH__';$mode='__MODE__'
$install='C:\Users\vpncp117\AppData\Local\vpn-control';$cli=Join-Path $install 'vpn-control-cli.exe'
$state='C:\Users\vpncp117\AppData\Local\VpnControl\cp166\state';$lock=Join-Path $state 'vpn-control.lock';$endpoint=Join-Path $state 'activation.port'
function Fail { throw 'UNSAFE' }
function SafeDirectory([string]$path){$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;if(-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){Fail}}
function SafeAncestors {
 foreach($path in @('C:\Users','C:\Users\vpncp117','C:\Users\vpncp117\AppData','C:\Users\vpncp117\AppData\Local',$install,'C:\Users\vpncp117\AppData\Local\VpnControl','C:\Users\vpncp117\AppData\Local\VpnControl\cp166',$state)){SafeDirectory $path}
}
function OwnerAcl([string]$path,[bool]$directory){
 $acl=Get-Acl -LiteralPath $path -ErrorAction Stop
 if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $sid){Fail}
 $ownerRead=$false;$ownerCreate=(!$directory)
 foreach($rule in @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))){
  if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and [int]$rule.FileSystemRights -ne 0){
   if($rule.IdentityReference.Value -notin @($sid,'S-1-5-18','S-1-5-32-544')){Fail}
   if($rule.IdentityReference.Value -ceq $sid){
    if(($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData) -ne 0){$ownerRead=$true}
    if($directory -and ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::CreateFiles) -ne 0){$ownerCreate=$true}
   }
  }
 }
 if(-not $ownerRead -or -not $ownerCreate){Fail}
}
if(-not ('StaleLockNative' -as [type])){Add-Type @'
using System; using System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles;
public static class StaleLockNative {
 [StructLayout(LayoutKind.Sequential)] public struct Disposition { [MarshalAs(UnmanagedType.Bool)] public bool DeleteFile; }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle file,int kind,ref Disposition value,int size);
 public static void MarkDelete(SafeFileHandle file){var value=new Disposition{DeleteFile=true};if(!SetFileInformationByHandle(file,4,ref value,Marshal.SizeOf(typeof(Disposition))))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());}
}
'@}
function Probe([bool]$holdLock) {
 SafeAncestors
 $item=Get-Item -LiteralPath $cli -Force -ErrorAction Stop
 if($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or (Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedHash){Fail}
 $products=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',('Registry::HKEY_USERS\'+$sid+'\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'),('Registry::HKEY_USERS\'+$sid+'\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') -ErrorAction SilentlyContinue|Where-Object {$_.DisplayName -eq 'vpn-control'})
 if($products.Count -ne 1 -or $products[0].DisplayVersion -cne '2.1.19' -or $products[0].InstallLocation.TrimEnd('\') -cne $install){Fail}
 OwnerAcl $state $true
 $lockItem=Get-Item -LiteralPath $lock -Force -ErrorAction Stop
 if($lockItem.PSIsContainer -or (($lockItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or $lockItem.Length -lt 1 -or $lockItem.Length -gt 4096){Fail}
 $handle=$null;$stream=$null
 if($holdLock){$handle=[StaleLockNative]::CreateFile($lock,[uint32]2147549184,[uint32]0,[IntPtr]::Zero,[uint32]3,[uint32]128,[IntPtr]::Zero);if($handle.IsInvalid){Fail};$stream=[IO.FileStream]::new($handle,[IO.FileAccess]::Read)}
 OwnerAcl $lock $false
 if($holdLock){$reader=[IO.StreamReader]::new($stream,[Text.Encoding]::UTF8,$true,4096,$true);$lockText=$reader.ReadToEnd();$stream.Position=0}else{$lockText=Get-Content -LiteralPath $lock -Raw -ErrorAction Stop}
 if($lockText.Trim() -notmatch '^[1-9][0-9]{0,9}$'){Fail}
 try{$endpointItem=Get-Item -LiteralPath $endpoint -Force -ErrorAction Stop;Fail}catch{if($_.CategoryInfo.Category -ne [System.Management.Automation.ErrorCategory]::ObjectNotFound){Fail}}
 $all=@(Get-CimInstance Win32_Process -ErrorAction Stop)
 if(@($all|Where-Object {$_.Name -in @('vpn-control.exe','vpn-control-cli.exe','msiexec.exe','consent.exe','sing-box.exe')}).Count -ne 0){Fail}
 return @($handle,$stream)
}
try { if($mode -ceq 'remove'){$held=Probe $true;$handle=$held[0];$stream=$held[1];[StaleLockNative]::MarkDelete($handle);$stream.Dispose();$handle.Dispose();if(Test-Path -LiteralPath $lock){Fail};$state='removed'}else{[void](Probe $false);$state='stale-proven'};[Console]::Out.WriteLine((@{version=1;state=$state}|ConvertTo-Json -Compress)) }
catch {[Console]::Out.WriteLine('{"version":1,"state":"unknown"}')}
'''

_REMOTE = base._QGA + r'''import time
sock,pid,ticks,sid,cli_hash,mode=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 if mode not in ('observe','remove') or not live(sock,pid,ticks):raise ValueError()
 script=STALE_LOCK_PS.replace('__SID__',sid).replace('__CLI_HASH__',cli_hash).replace('__MODE__',mode)
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(script.encode('utf-16le')).decode()],'capture-output':True}).get('pid')
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(160):
  observed=call(sock,'guest-exec-status',{'pid':child})
  if observed.get('exited') is True:break
  if observed.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if type(observed.get('exitcode')) is not int or observed['exitcode']!=0 or observed.get('out-truncated') is True or observed.get('err-truncated') is True:raise ValueError()
 raw=base64.b64decode(observed.get('out-data',''),validate=True)
 if not 0<len(raw)<=256:raise ValueError()
 lines=[line for line in decode(raw).splitlines() if line.startswith('{') and line.endswith('}')]
 if len(lines)!=1:raise ValueError()
 value=json.loads(lines[0])
 if not isinstance(value,dict) or set(value)!={'version','state'} or value.get('version')!=1 or value.get('state') not in ('stale-proven','removed'):raise ValueError()
 if (mode=='observe') != (value['state']=='stale-proven'):raise ValueError()
 out(value)
except Exception:out({'version':1,'state':'unknown'})
'''.replace('STALE_LOCK_PS', repr(_PS))

# This intentionally performs no DELETE access and has no delete disposition.
# It identifies whether the exclusive probe itself prevents Get-Acl from opening
# the pathname, which is the expected cause of the first armed-intent outcome.
_DIAGNOSTIC_PS = r'''$ErrorActionPreference='Stop'
$sid='__SID__';$expectedHash='__CLI_HASH__';$cli='C:\Users\vpncp117\AppData\Local\vpn-control\vpn-control-cli.exe';$state='C:\Users\vpncp117\AppData\Local\VpnControl\cp166\state';$lock=Join-Path $state 'vpn-control.lock';$endpoint=Join-Path $state 'activation.port'
function Unsafe { throw 'UNSAFE' }
function SafeDirectory([string]$path){$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;if(-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){Unsafe}}
function OwnerAcl([string]$path,[bool]$directory){$acl=Get-Acl -LiteralPath $path -ErrorAction Stop;if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $sid){Unsafe};$read=$false;$create=(!$directory);foreach($rule in @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))){if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and [int]$rule.FileSystemRights -ne 0){if($rule.IdentityReference.Value -notin @($sid,'S-1-5-18','S-1-5-32-544')){Unsafe};if($rule.IdentityReference.Value -ceq $sid){if(($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData) -ne 0){$read=$true};if($directory -and ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::CreateFiles) -ne 0){$create=$true}}}};if(-not $read -or -not $create){Unsafe}}
if(-not ('StaleLockDiagnosticNative' -as [type])){Add-Type @'
using System; using System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles;
public static class StaleLockDiagnosticNative { [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template); }
'@}
$category='unexpected';$openError=0;$handle=$null
try{
 $category='ancestors'
 foreach($path in @('C:\Users','C:\Users\vpncp117','C:\Users\vpncp117\AppData','C:\Users\vpncp117\AppData\Local','C:\Users\vpncp117\AppData\Local\vpn-control','C:\Users\vpncp117\AppData\Local\VpnControl','C:\Users\vpncp117\AppData\Local\VpnControl\cp166',$state)){SafeDirectory $path}
 $category='cli'
 $cliItem=Get-Item -LiteralPath $cli -Force -ErrorAction Stop;if($cliItem.PSIsContainer -or (($cliItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or (Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedHash){Unsafe}
 $category='product'
 $products=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',('Registry::HKEY_USERS\'+$sid+'\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'),('Registry::HKEY_USERS\'+$sid+'\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') -ErrorAction SilentlyContinue|Where-Object {$_.DisplayName -eq 'vpn-control'});if($products.Count -ne 1 -or $products[0].DisplayVersion -cne '2.1.19' -or $products[0].InstallLocation.TrimEnd('\') -cne 'C:\Users\vpncp117\AppData\Local\vpn-control') {Unsafe}
 $category='state-acl'
 OwnerAcl $state $true;$item=Get-Item -LiteralPath $lock -Force -ErrorAction Stop;if($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or $item.Length -lt 1 -or $item.Length -gt 4096){Unsafe};OwnerAcl $lock $false;if((Get-Content -LiteralPath $lock -Raw -ErrorAction Stop).Trim() -notmatch '^[1-9][0-9]{0,9}$'){Unsafe}
 $category='endpoint'
 try{$found=Get-Item -LiteralPath $endpoint -Force -ErrorAction Stop;Unsafe}catch{if($_.CategoryInfo.Category -ne [System.Management.Automation.ErrorCategory]::ObjectNotFound){Unsafe}}
 $category='processes'
 $all=@(Get-CimInstance Win32_Process -ErrorAction Stop);if(@($all|Where-Object {$_.Name -in @('vpn-control.exe','vpn-control-cli.exe','msiexec.exe','consent.exe','sing-box.exe')}).Count -ne 0){Unsafe}
 $category='lock-open-invocation'
 try{$handle=[StaleLockDiagnosticNative]::CreateFile($lock,[uint32]2147483648,[uint32]0,[IntPtr]::Zero,[uint32]3,[uint32]128,[IntPtr]::Zero)}catch{throw 'DONE'}
 $openError=[Runtime.InteropServices.Marshal]::GetLastWin32Error();$category='lock-open-other';if($handle.IsInvalid){if($openError -eq 32){$category='lock-open-sharing-violation'}elseif($openError -eq 5){$category='lock-open-access-denied'}elseif($openError -eq 87){$category='lock-open-invalid-parameter'}elseif($openError -in @(2,3,123,161)){$category='lock-open-path-issue'}elseif($openError -lt 0 -or $openError -gt 65535){$openError=0};throw 'DONE'}
 try{Get-Acl -LiteralPath $lock -ErrorAction Stop|Out-Null;$category='safe-proven'}catch{$category='exclusive-handle-acl-blocked'}
}catch{}finally{if($null -ne $handle){$handle.Dispose()}}
$result=@{version=1;category=$category};if($category -ceq 'lock-open-other'){$result.win32Code=[int]$openError};[Console]::Out.WriteLine(($result|ConvertTo-Json -Compress))
'''

_REMOTE_DIAGNOSE = base._QGA + r'''import time
sock,pid,ticks,sid,cli_hash=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks):raise ValueError()
 script=DIAG_PS.replace('__SID__',sid).replace('__CLI_HASH__',cli_hash)
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(script.encode('utf-16le')).decode()],'capture-output':True}).get('pid')
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(160):
  observed=call(sock,'guest-exec-status',{'pid':child})
  if observed.get('exited') is True:break
  if observed.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if type(observed.get('exitcode')) is not int or observed['exitcode']!=0 or observed.get('out-truncated') is True or observed.get('err-truncated') is True:raise ValueError()
 raw=base64.b64decode(observed.get('out-data',''),validate=True)
 lines=[line for line in decode(raw).splitlines() if line.startswith('{') and line.endswith('}')]
 if len(lines)!=1:raise ValueError()
 value=json.loads(lines[0])
 if not isinstance(value,dict) or value.get('version')!=1 or value.get('category') not in CATEGORIES:raise ValueError()
 if value['category']=='lock-open-other':
  if set(value)!={'version','category','win32Code'} or type(value.get('win32Code')) is not int or not 0<=value['win32Code']<=65535:raise ValueError()
 elif set(value)!={'version','category'}:raise ValueError()
 out(value)
except Exception:out({'version':1,'category':'unknown'})
'''.replace('DIAG_PS', repr(_DIAGNOSTIC_PS)).replace('CATEGORIES', repr(_DIAGNOSTIC_CATEGORIES))


def _admit(root: Path) -> tuple[Any, tuple[str, str, int, int, str], str] | None:
    intent = base._private_intent(root, _CORRELATION)
    if not isinstance(intent, dict) or intent.get('request') != {"host": "archlinux", "correlationId": _CORRELATION,
            "sourceSha": _SOURCE, **_ARTIFACTS, "expectedCurrentVersion": "2.1.17"}:
        return None
    config, _target, descriptor = base._descriptor(root)
    env, socket, pid, ticks, sid = descriptor
    if env != 'windows-cp117' or any(intent.get(k) != v for k, v in (("environment", env), ("socketPath", socket), ("pid", pid), ("startTicks", ticks), ("expectedSid", sid))):
        return None
    pair, _size = base._stage_artifact_readonly(root, intent)
    if (not isinstance(pair, dict) or pair.get('sourceSha') != _SOURCE or pair.get('baseVersion') != '2.1.19'
            or pair.get('baseArtifactId') != _ARTIFACTS['baseMsiArtifactId'] or pair.get('receiptArtifactId') != _ARTIFACTS['fixtureReceiptArtifactId']
            or pair.get('targetArtifactId') != _ARTIFACTS['targetMsiArtifactId'] or not isinstance(pair.get('baseCliSha256'), str)):
        return None
    return config, descriptor, pair['baseCliSha256']


def _run(config: Any, descriptor: tuple[str, str, int, int, str], cli_hash: str, mode: str) -> str | None:
    _env, socket, pid, ticks, sid = descriptor
    raw = base._remote(config, _REMOTE, (socket, str(pid), str(ticks), sid, cli_hash, mode), None, 60)
    try:
        value = json.loads(raw) if raw is not None else {}
        return value['state'] if isinstance(value, dict) and set(value) == {'version', 'state'} and value.get('version') == 1 and value.get('state') in {'stale-proven', 'removed'} else None
    except (TypeError, ValueError, KeyError):
        return None


def _diagnostic(config: Any, descriptor: tuple[str, str, int, int, str], cli_hash: str) -> dict[str, Any] | None:
    _env, socket, pid, ticks, sid = descriptor
    raw = base._remote(config, _REMOTE_DIAGNOSE, (socket, str(pid), str(ticks), sid, cli_hash), None, 60)
    try:
        value = json.loads(raw) if raw is not None else {}
        if (not isinstance(value, dict) or value.get('version') != 1
                or value.get('category') not in _DIAGNOSTIC_CATEGORIES): return None
        if value['category'] == 'lock-open-other':
            if set(value) != {'version','category','win32Code'} or type(value.get('win32Code')) is not int or not 0 <= value['win32Code'] <= 65535: return None
            return {'category':value['category'],'win32Code':value['win32Code']}
        return {'category':value['category']} if set(value) == {'version','category'} else None
    except (TypeError, ValueError, KeyError):
        return None


def _directory(root: Path, create: bool = True) -> Path:
    path = root / _GROUP
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise WindowsMsiStaleLockRecoveryError('Stale-lock journal is unsafe.')
    return path


def _intent_path(root: Path, create: bool = True) -> Path: return _directory(root, create) / (_CORRELATION + '.json')

def _read_intent(root: Path) -> dict[str, Any] | None:
    try: path = _intent_path(root, create=False)
    except FileNotFoundError: return None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    except FileNotFoundError: return None
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4096:
            raise WindowsMsiStaleLockRecoveryError('Stale-lock intent is unsafe.')
        raw = stream.read()
    try: value = json.loads(raw)
    except (TypeError, ValueError) as error: raise WindowsMsiStaleLockRecoveryError('Stale-lock intent is invalid.') from error
    if not isinstance(value, dict) or set(value) != {'version','correlationId','sourceSha','guestGeneration','evidenceSha256','state'} or value.get('version') != 1 or value.get('correlationId') != _CORRELATION or value.get('sourceSha') != _SOURCE or value.get('state') not in {'intent','recovered'}:
        raise WindowsMsiStaleLockRecoveryError('Stale-lock intent is invalid.')
    return value

def _write_intent(root: Path, value: Mapping[str, Any]) -> None:
    directory = _directory(root); path = _intent_path(root)
    lock = os.open(directory / '.environment.lock', os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if _read_intent(root) is not None: raise WindowsMsiStaleLockRecoveryError('Stale-lock intent already exists.')
        data = (json.dumps(dict(value), sort_keys=True, separators=(',',':'))+'\n').encode()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(fd, 'wb') as stream: stream.write(data); stream.flush(); os.fsync(stream.fileno())
        parent = os.open(directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0)); os.fsync(parent); os.close(parent)
    finally: os.close(lock)


def _evidence(descriptor: tuple[str, str, int, int, str]) -> tuple[dict[str, Any], str]:
    _env, socket, pid, ticks, _sid = descriptor
    generation = {'socketPath': socket, 'qemuPid': pid, 'startTicks': ticks}
    return generation, hashlib.sha256(json.dumps(generation, sort_keys=True).encode()).hexdigest()


def _matches_current(record: Mapping[str, Any], descriptor: tuple[str, str, int, int, str]) -> bool:
    generation, evidence = _evidence(descriptor)
    return record.get('guestGeneration') == generation and record.get('evidenceSha256') == evidence


def _finish_intent(root: Path, value: Mapping[str, Any]) -> None:
    """Atomically record the result; this never changes an armed intent."""
    directory = _directory(root); path = _intent_path(root)
    lock = os.open(directory / '.environment.lock', os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0))
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        current = _read_intent(root)
        if current is None or current.get('state') != 'intent':
            raise WindowsMsiStaleLockRecoveryError('Stale-lock intent changed.')
        temporary = path.with_suffix('.tmp')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write((json.dumps(dict(value), sort_keys=True, separators=(',',':'))+'\n').encode())
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent = os.open(directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0)); os.fsync(parent); os.close(parent)
    finally:
        try: temporary.unlink()
        except (FileNotFoundError, UnboundLocalError): pass
        os.close(lock)


def diagnose(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Read the armed c32 lock attempt without retrying or changing it."""
    if not isinstance(inputs, Mapping) or dict(inputs) != {'host':'archlinux'}:
        raise WindowsMsiStaleLockRecoveryError('Exact CP117 host is required.')
    try:
        root = Path(root).resolve(strict=True); admitted = _admit(root)
        if admitted is None: return dict(_UNKNOWN)
        current = _read_intent(root)
        config, descriptor, cli_hash = admitted
        if current is None or current.get('state') != 'intent' or not _matches_current(current, descriptor): return dict(_UNKNOWN)
        diagnostic = _diagnostic(config, descriptor, cli_hash)
        if diagnostic is None: return dict(_UNKNOWN)
        return {'state':'diagnosed',**diagnostic,'replayAllowed':False,'nativeActionAllowed':False}
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError, WindowsMsiStaleLockRecoveryError):
        return dict(_UNKNOWN)


def reconciliation_status(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Expose only a read-only proof boundary for a future, separate intent."""
    result = diagnose(root, inputs)
    if result.get('state') != 'diagnosed' or result.get('category') != 'safe-proven': return dict(_UNKNOWN)
    return {'state':'separate-one-shot-required','replayAllowed':False,'nativeActionAllowed':False}


def recover(root: Path | str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Remove the fixed lock once, only after a fresh exact guest proof."""
    if not isinstance(inputs, Mapping) or dict(inputs) != {'host':'archlinux'}:
        raise WindowsMsiStaleLockRecoveryError('Exact CP117 host is required.')
    try:
        root = Path(root).resolve(strict=True); admitted = _admit(root)
        if admitted is None: return dict(_UNKNOWN)
        current = _read_intent(root)
        config, descriptor, cli_hash = admitted
        if current is not None:
            if not _matches_current(current, descriptor): return dict(_UNKNOWN)
            return {'state':'recovered','replayAllowed':False,'nativeActionAllowed':False} if current['state'] == 'recovered' else dict(_UNKNOWN)
        if _run(config, descriptor, cli_hash, 'observe') != 'stale-proven': return dict(_UNKNOWN)
        generation, evidence = _evidence(descriptor)
        record = {'version':1,'correlationId':_CORRELATION,'sourceSha':_SOURCE,'guestGeneration':generation,'evidenceSha256':evidence,'state':'intent'}
        _write_intent(root, record)
        if _run(config, descriptor, cli_hash, 'remove') != 'removed': return dict(_UNKNOWN)
        record['state'] = 'recovered'
        _finish_intent(root, record)
        return {'state':'recovered','replayAllowed':False,'nativeActionAllowed':False}
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError, WindowsMsiStaleLockRecoveryError):
        return dict(_UNKNOWN)
