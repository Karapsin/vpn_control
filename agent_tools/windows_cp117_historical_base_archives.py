"""Read-only recognition of the two original CP117 unknown-cleaned base archives.

Historical closure digests retain the original 2.1.17 observation schema. Fresh
absence is a separate fact requiring current 2.1.19; neither grants cleanup or
installer authority and no replacement receipt is written.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Mapping, NamedTuple

try:
    import fcntl
except ImportError:
    fcntl = None


def _supported() -> bool:
    return fcntl is not None and callable(getattr(os, 'getuid', None)) and hasattr(os, 'O_NOFOLLOW')


if _supported():
    from . import windows_msi_base_prepare as base
else:
    base = None

_PROFILES = {
    'transfer-recovery': '45e4514a-c629-4f3b-99bc-aad599640d29',
    'unknown-closure': '2ace6a48-ba60-4705-9200-4ff857f2aba6',
}
_GENERATION = ('windows-cp117', '/home/kardinal/vpn-control-windows-msi-acceptance-cp117/cp135-launch/qga.sock',
               589342, 520739, 'S-1-5-21-2404255130-2183793310-3766671872-1002')
_PAIR_SHA256 = '4e044627c4f51c5dfde93574779b8c90fa8b567beec9d235804efd2b683c69cf'
_CLOSURE_SHA256 = {
    _PROFILES['unknown-closure']: '140fa6f521045e1710ed41e2a4652e5d9dffabdd2850e13b903e7d0e65bf7274',
    _PROFILES['transfer-recovery']: 'c6383a8ae9d5e73a5f6bf2459fd5ce901f707e972ec9985c311da915926e2cf2',
}
_PRE_MUTATION_SHA256 = 'de39fef85a6496602b74de7e7bdf0a913873cef6269afa08b07c6650536b7526'
_FLAGS = {'replayAllowed': False, 'nativeActionAllowed': False, 'productAction': False}
_REMOTE_PHASES = frozenset({'guard', 'root', 'lock', 'closed', 'active', 'stage', 'exec', 'status',
                            'output', 'identity', 'task', 'leaf', 'result', 'process', 'installer',
                            'product', 'generation', 'recheck', 'parser', 'output-envelope', 'output-truncated',
                            'output-stderr-progress', 'output-stderr-error', 'output-stderr-other',
                            'output-empty', 'output-json', 'output-shape'})


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate historical field')
        value[key] = item
    return value


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _directory(path: Path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('unsafe historical directory')
    return info


def _read(path: Path) -> dict[str, Any]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno()); current = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 8192
                or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)):
            raise ValueError('unsafe historical record')
        raw = stream.read(8193)
        if len(raw) != info.st_size:
            raise ValueError('changed historical record')
        value = json.loads(raw, object_pairs_hook=_unique)
    if not isinstance(value, dict):
        raise ValueError('invalid historical record')
    return value


def _historical_evidence(correlation: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Canonical original schema, validated against persisted native digests."""
    if correlation not in _CLOSURE_SHA256:
        raise ValueError('not an original historical profile')
    after = {'state': 'observed', 'correlationId': correlation, 'remoteStage': 'absent', 'mutation': 'none',
             'task': 'absent', 'leaf': 'absent', 'result': 'absent', 'correlationPowerShell': 'absent',
             'product': 'single', 'installedVersion': '2.1.17', 'installer': 'absent'}
    close = {'afterFirst': after, 'afterSecond': after, 'closeIntent': correlation}
    before = {key: value for key, value in after.items() if key not in {'state', 'correlationId', 'mutation'}}
    before.update(remoteStage='present', leaf='present')
    pre = {'first': before, 'second': before, 'readiness': '2.1.17'}
    return close, pre


class _ReadLockToken(NamedTuple):
    root: Path
    pid: int
    thread: int
    fd: int
    info: os.stat_result
    lockpath: Path
    parents: tuple[tuple[Path, os.stat_result], ...]


_READ_LOCK_STATE = threading.local()


def _recheck_read_lock(root: Path, token: _ReadLockToken) -> None:
    if (not isinstance(token, _ReadLockToken) or token.root != root
            or token.pid != os.getpid() or token.thread != threading.get_ident()):
        raise ValueError('foreign historical campaign lock token')
    current = os.fstat(token.fd); path = token.lockpath.lstat()
    for info in (current, path):
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or (info.st_dev, info.st_ino) != (token.info.st_dev, token.info.st_ino)):
            raise ValueError('changed historical campaign lock')
    for parent, old in token.parents:
        info = _directory(parent)
        if (old.st_dev, old.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError('changed historical campaign parent')


@contextmanager
def _history_lock(root: Path):
    """Reuse this thread's validated SH descriptor for nested read-only proofs.

    Nested scopes never acquire another flock or release the outer descriptor.
    A token binds PID/thread/root, private parents and the exact still-open inode;
    forked or changed ownership cannot inherit admission. Remote locks are
    independent and still acquired by each bounded guest proof.
    """
    if not _supported() or base is None:
        raise ValueError('historical observer requires POSIX locking')
    root = Path(root).resolve(strict=True)
    held = getattr(_READ_LOCK_STATE, 'token', None)
    if held is not None:
        _recheck_read_lock(root, held)
        try:
            yield
        finally:
            _recheck_read_lock(root, held)
        return
    directory = root / base.campaign_lease._DIR
    parents = tuple((path, _directory(path)) for path in (directory.parent, directory))
    lockpath = directory / '.environment.lock'
    fd = os.open(lockpath, os.O_RDONLY | os.O_NOFOLLOW)
    token = None
    try:
        token = _ReadLockToken(root, os.getpid(), threading.get_ident(), fd,
                               os.fstat(fd), lockpath, parents)
        _recheck_read_lock(root, token)
        fcntl.flock(fd, fcntl.LOCK_SH)
        _recheck_read_lock(root, token)
        _READ_LOCK_STATE.token = token
        try:
            yield
        finally:
            _recheck_read_lock(root, token)
    finally:
        if getattr(_READ_LOCK_STATE, 'token', None) is token:
            del _READ_LOCK_STATE.token
        os.close(fd)


def _admit(root: Path, descriptor: tuple[Any, ...], correlation: str) -> dict[str, Any]:
    with _history_lock(root):
        return _admit_locked(root, descriptor, correlation)


def _admit_locked(root: Path, descriptor: tuple[Any, ...], correlation: str) -> dict[str, Any]:
    if descriptor != _GENERATION or correlation not in _CLOSURE_SHA256 or base is None:
        raise ValueError('not the original historical generation')
    for path in (root / '.rag_index', root / base._LOCAL, root / base.campaign_lease._DIR):
        _directory(path)
    if os.path.lexists(root / base.campaign_lease._DIR / 'active.json'):
        raise ValueError('active or uncertain campaign remains')
    request, command = base._unknown_recovery_profile(correlation)
    intent = _read(root / base._LOCAL / (correlation + '.json'))
    marker = _read(root / base._LOCAL / (correlation + '.unknown-close.json'))
    closed = _read(root / base.campaign_lease._DIR / (correlation + '.closed.json'))
    if (set(intent) != {'request', 'pair', 'environment', 'socketPath', 'pid', 'startTicks', 'expectedSid', 'commandSha256', 'leaseId'}
            or intent['request'] != request or intent['commandSha256'] != command
            or intent['leaseId'] != correlation or _digest(intent['pair']) != _PAIR_SHA256
            or tuple(intent[key] for key in ('environment', 'socketPath', 'pid', 'startTicks', 'expectedSid')) != descriptor
            or type(intent['pid']) is not int or type(intent['startTicks']) is not int):
        raise ValueError('changed original historical intent')
    close, pre = _historical_evidence(correlation)
    if _digest(close) != _CLOSURE_SHA256[correlation] or _digest(pre) != _PRE_MUTATION_SHA256:
        raise ValueError('changed original historical schema')
    expected_marker = {'version': 1, 'state': 'close-intent', 'correlationId': correlation,
                       'commandSha256': command, 'sourceSha': request['sourceSha'],
                       'guestGeneration': {'environment': descriptor[0], 'socketPath': descriptor[1],
                                           'qemuPid': descriptor[2], 'startTicks': descriptor[3], 'expectedSid': descriptor[4]},
                       'preMutationEvidenceSha256': _digest(pre)}
    expected_closed = {'version': 1, 'identity': base._campaign_identity(request, descriptor),
                       'sequence': 3, 'state': 'closed', 'role': None, 'correlationId': None,
                       'server': 'stopped', 'credentials': 'absent',
                       'lastOutcome': 'unknown-cleaned', 'lastEvidenceSha256': _digest(close)}
    if (marker != expected_marker or type(marker.get('version')) is not int
            or closed != expected_closed or type(closed.get('version')) is not int
            or type(closed.get('sequence')) is not int):
        raise ValueError('changed historical closure evidence')
    if os.path.lexists(root / base.campaign_lease._DIR / 'active.json'):
        raise ValueError('campaign changed during historical admission')
    return closed


_PS = r'''$ErrorActionPreference='Stop'
$phase='identity';try{
$corr='@CORR@';$sid='@SID@';$leaf='C:\Users\vpncp117\AppData\Local\VpnControl\mcp-base-'+$corr
$actualSid=([Security.Principal.NTAccount]::new('VPNMSIX64\vpncp117')).Translate([Security.Principal.SecurityIdentifier]).Value
if($actualSid -cne $sid){throw 'IDENTITY'}
$phase='task'
$tasks=@(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq ('VpnControlMcpBase-'+$corr) -or $_.TaskName -ceq ('VpnControlMcpTransfer-'+$corr)})
$taskState=if($tasks.Count -eq 0){'absent'}else{'present'}
$phase='leaf'
$leafState=if(Test-Path -LiteralPath $leaf){'present'}else{'absent'}
$phase='result'
$resultState=if(Test-Path -LiteralPath ($leaf+'\result.json')){'present'}else{'absent'}
$phase='process'
$all=@(Get-CimInstance Win32_Process -ErrorAction Stop)
$correlated=@($all|Where-Object {$_.ProcessId -ne $PID -and $null -ne $_.CommandLine -and $_.CommandLine -match [regex]::Escape($corr)})
$opaque=@($all|Where-Object {$_.ProcessId -ne $PID -and $_.Name -in @('powershell.exe','pwsh.exe') -and $null -eq $_.CommandLine})
$processState=if($correlated.Count -gt 0){'present'}elseif($opaque.Count -gt 0){'ambiguous'}else{'absent'}
$phase='installer'
$installerState=if(@($all|Where-Object {$_.Name -in @('msiexec.exe','consent.exe')}).Count -eq 0){'absent'}else{'present'}
$phase='product'
$hku='Registry::HKEY_USERS\'+$sid+'\Software\Microsoft\Windows\CurrentVersion\Uninstall'
$hku32='Registry::HKEY_USERS\'+$sid+'\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
$records=@();foreach($path in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',$hku,$hku32)){if(Test-Path -LiteralPath $path){$records+=@(Get-ItemProperty -Path ($path+'\*') -ErrorAction Stop)}}
$products=@($records|Where-Object {$_.DisplayName -eq 'vpn-control'})
$productState=if($products.Count -eq 1){'single'}elseif($products.Count -eq 0){'absent'}else{'multiple'}
$version=if($products.Count -eq 1){$products[0].DisplayVersion}else{$null}
$phase='output'
[Console]::Out.WriteLine((@{task=$taskState;leaf=$leafState;result=$resultState;correlationProcess=$processState;installer=$installerState;product=$productState;installedVersion=$version;expectedSid=$actualSid}|ConvertTo-Json -Compress))
}catch{[Console]::Out.WriteLine((@{state='unknown';phase=$phase}|ConvertTo-Json -Compress));exit 1}
'''

_PARSER = r'''$ErrorActionPreference='Stop';try{
$bytes=[Convert]::FromBase64String('@PACKED@');$input=[IO.MemoryStream]::new([byte[]]$bytes)
$gzip=[IO.Compression.GzipStream]::new($input,[IO.Compression.CompressionMode]::Decompress)
$output=[IO.MemoryStream]::new();$gzip.CopyTo($output);$body=[Text.Encoding]::Unicode.GetString($output.ToArray())
$gzip.Dispose();$input.Dispose();$output.Dispose();$tokens=$null;$errors=$null
[Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)|Out-Null
if($errors.Count -ne 0){throw 'PARSE'}
[Console]::Out.WriteLine('{"version":1,"code":"OK"}')
}catch{[Console]::Out.WriteLine('{"version":1,"code":"FAILED"}');exit 1}
'''

_REMOTE_BODY = 'PARSER_TEMPLATE=' + repr(_PARSER) + '\n' + r'''import fcntl,time,gzip,xml.etree.ElementTree as ET
root,env,corr,sock,pid,ticks,sid,expected_text,encoded=sys.argv[1:]
lock=None
phase='guard'
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
def unique(pairs):
 value={}
 for key,item in pairs:
  if key in value:raise ValueError()
  value[key]=item
 return value
def load(raw):return json.loads(raw,object_pairs_hook=unique)
def same(a,b):return (a.st_dev,a.st_ino)==(b.st_dev,b.st_ino)
def directory(path):
 i=os.lstat(path)
 if not stat.S_ISDIR(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700:raise ValueError()
 return i
def read(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  i=os.fstat(f.fileno())
  if not stat.S_ISREG(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600 or not 0<i.st_size<=8192 or not same(i,os.lstat(path)):raise ValueError()
  raw=f.read(8193)
  if len(raw)!=i.st_size:raise ValueError()
  return load(raw)
def stderr_phase(raw):
 if not raw:return None
 if len(raw)>8192:return 'output-stderr-other'
 try:
  text=raw.decode('utf-8')
  if not text.startswith('#< CLIXML') or '<!DOCTYPE' in text or '<!ENTITY' in text:return 'output-stderr-other'
  body=text[len('#< CLIXML'):].lstrip('\r\n')
  tree=ET.fromstring(body);namespace='{http://schemas.microsoft.com/powershell/2004/04}'
  if tree.tag!=namespace+'Objs' or set(tree.attrib)!={'Version'} or tree.attrib['Version']!='1.1.0.1':return 'output-stderr-other'
  entries=list(tree)
  if not 0<len(entries)<=32:return 'output-stderr-other'
  nodes=list(tree.iter())
  if len(nodes)>256 or any(not node.tag.startswith(namespace) for node in nodes):return 'output-stderr-other'
  pending=[(tree,0)]
  while pending:
   node,depth=pending.pop()
   if depth>16:return 'output-stderr-other'
   pending.extend((child,depth+1) for child in node)
  if any(node.attrib.get('S')=='Error' for node in entries):return 'output-stderr-error'
  for node in entries:
   if node.tag!=namespace+'Obj' or set(node.attrib)!={'S','RefId'} or node.attrib['S']!='progress' or not node.attrib['RefId'].isdigit() or len(node.attrib['RefId'])>8:return 'output-stderr-other'
   if any(child.attrib.get('S') not in (None,'progress') for child in node.iter()):return 'output-stderr-other'
  return 'output-stderr-progress'
 except Exception:return 'output-stderr-other'
def query(program):
 global phase
 phase='exec'
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',program],'capture-output':True})['pid']
 if type(child)is not int or child<=0:raise ValueError()
 phase='status'
 for _ in range(40):
  item=call(sock,'guest-exec-status',{'pid':child})
  if not isinstance(item,dict):raise ValueError()
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 phase='output-envelope'
 if set(item)-{'exited','exitcode','out-data','err-data','out-truncated','err-truncated'} or type(item.get('exitcode'))is not int:raise ValueError()
 for field in ('out-truncated','err-truncated'):
  if type(item.get(field,False))is not bool:raise ValueError()
 phase='output-truncated'
 if item.get('out-truncated',False) or item.get('err-truncated',False):raise ValueError()
 phase='output-envelope'
 error=base64.b64decode(item.get('err-data',''),validate=True)
 classified=stderr_phase(error)
 # PowerShell 5.1 module loading emits CLIXML progress on stderr. Only the
 # bounded progress-only stream may coexist with a zero exit; the exact stdout
 # schema and all original archive/absence predicates are still checked below.
 if classified is not None and not (classified=='output-stderr-progress' and item['exitcode']==0):phase=classified;raise ValueError()
 raw=base64.b64decode(item.get('out-data',''),validate=True)
 phase='output-empty'
 if not raw:raise ValueError()
 phase='output-envelope'
 if len(raw)>2048:raise ValueError()
 phase='output-json'
 value=load(decode(raw))
 return item['exitcode'],value

try:
 if env!='windows-cp117' or corr not in {'45e4514a-c629-4f3b-99bc-aad599640d29','2ace6a48-ba60-4705-9200-4ff857f2aba6'} or not os.path.isabs(root) or os.path.normpath(root)!=root:raise ValueError()
 phase='generation'
 if not live(sock,pid,ticks):raise ValueError()
 phase='root'
 expected=load(expected_text)
 parent=os.path.join(root,env);campaign=os.path.join(parent,'windows-cp117-campaign');group=os.path.join(parent,'windows-msi-base');stage=os.path.join(group,corr)
 parents=[(p,directory(p)) for p in (root,parent,campaign,group)]
 phase='lock';lockpath=os.path.join(campaign,'.environment.lock');lock=os.open(lockpath,os.O_RDONLY|os.O_NOFOLLOW)
 info=os.fstat(lock)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or not same(info,os.lstat(lockpath)):raise ValueError()
 fcntl.flock(lock,fcntl.LOCK_SH)
 closedpath=os.path.join(campaign,corr+'.closed.json')
 activepath=os.path.join(campaign,'active.json')
 if not same(info,os.lstat(lockpath)):raise ValueError()
 phase='closed'
 if read(closedpath)!=expected:raise ValueError()
 phase='active'
 if os.path.lexists(activepath):raise ValueError()
 phase='stage'
 if os.path.lexists(stage):raise ValueError()
 phase='parser'
 actual=base64.b64decode(encoded,validate=True)
 packed=base64.b64encode(gzip.compress(actual,mtime=0)).decode('ascii')
 parser=PARSER_TEMPLATE.replace('@PACKED@',packed)
 parser_encoded=base64.b64encode(parser.encode('utf-16le')).decode('ascii')
 if len(parser_encoded)>=30000:raise ValueError()
 exitcode,value=query(parser_encoded)
 phase='parser'
 if exitcode!=0 or value!={'version':1,'code':'OK'} or type(value.get('version'))is not int:raise ValueError()
 exitcode,proof=query(encoded)
 phase='output-shape'
 if exitcode!=0:
  if isinstance(proof,dict) and set(proof)=={'state','phase'} and proof['state']=='unknown' and proof['phase'] in {'identity','task','leaf','result','process','installer','product','output'}:phase=proof['phase']
  raise ValueError()
 if not isinstance(proof,dict) or set(proof)!={'task','leaf','result','correlationProcess','installer','product','installedVersion','expectedSid'}:raise ValueError()
 phase='identity'
 if proof['expectedSid']!=sid:raise ValueError()
 for field,failed_phase in (('task','task'),('leaf','leaf'),('result','result'),('correlationProcess','process'),('installer','installer')):
  phase=failed_phase
  if proof[field]!='absent':raise ValueError()
 phase='product'
 if proof['product']!='single' or proof['installedVersion']!='2.1.19':raise ValueError()
 phase='closed'
 if read(closedpath)!=expected:raise ValueError()
 phase='active'
 if os.path.lexists(activepath):raise ValueError()
 phase='stage'
 if os.path.lexists(stage):raise ValueError()
 phase='generation'
 if not live(sock,pid,ticks):raise ValueError()
 phase='recheck'
 for p,i in parents:
  if not same(i,directory(p)):raise ValueError()
 out({'state':'observed','correlationId':corr,'campaignSha256':hashlib.sha256(json.dumps(expected,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'remoteStage':'absent','qemuPid':int(pid),'startTicks':int(ticks),**proof})
except Exception:out({'state':'unknown','phase':phase})
finally:
 if lock is not None:os.close(lock)
'''
_REMOTE = (base._QGA if base is not None else '') + _REMOTE_BODY


def _fresh_observe(config: Any, target: Any, descriptor: tuple[Any, ...], correlation: str, closed: dict[str, Any]) -> str:
    if descriptor != _GENERATION or correlation not in _CLOSURE_SHA256:
        return 'remote-generation'
    script = _PS.replace('@CORR@', correlation).replace('@SID@', descriptor[4])
    encoded = base64.b64encode(script.encode('utf-16le')).decode('ascii')
    if len(encoded) >= 30000:
        return 'remote-output'
    try:
        raw = base._remote(config, _REMOTE, (str(target.fixture_transfer_root), descriptor[0], correlation,
                           descriptor[1], str(descriptor[2]), str(descriptor[3]), descriptor[4],
                           json.dumps(closed, sort_keys=True, separators=(',', ':')), encoded), None, 30)
    except (OSError, ValueError, TypeError, KeyError):
        return 'remote-transport'
    if raw is None:
        return 'remote-transport'
    if not isinstance(raw, (str, bytes)) or not 0 < len(raw) <= 2048:
        return 'remote-output'
    try:
        result = json.loads(raw, object_pairs_hook=_unique)
    except (TypeError, ValueError):
        return 'remote-output'
    if (isinstance(result, dict) and set(result) == {'state', 'phase'}
            and result['state'] == 'unknown' and isinstance(result['phase'], str)
            and result['phase'] in _REMOTE_PHASES):
        return 'remote-' + result['phase']
    expected = {'state': 'observed', 'correlationId': correlation, 'campaignSha256': _digest(closed),
                'remoteStage': 'absent', 'qemuPid': descriptor[2], 'startTicks': descriptor[3],
                'task': 'absent', 'leaf': 'absent', 'result': 'absent', 'correlationProcess': 'absent',
                'installer': 'absent', 'product': 'single', 'installedVersion': '2.1.19', 'expectedSid': descriptor[4]}
    if (result == expected and type(result.get('qemuPid')) is int and type(result.get('startTicks')) is int):
        return 'archived'
    return 'remote-output'


def _fresh(config: Any, target: Any, descriptor: tuple[Any, ...], correlation: str, closed: dict[str, Any]) -> bool:
    return _fresh_observe(config, target, descriptor, correlation, closed) == 'archived'


def observe(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Fixed two-profile archive observation; no writes or mutation fallback."""
    if not isinstance(value, Mapping) or value != {}:
        raise ValueError('historical archive observation takes no inputs')
    phases = {name: 'unknown' for name in _PROFILES}
    unknown = {**_FLAGS, 'state': 'unknown', 'phases': phases}
    if not _supported() or base is None:
        return unknown
    path = Path(root).resolve(strict=True)
    try:
        config, target, descriptor = base._descriptor(path)
    except (OSError, ValueError, TypeError, KeyError):
        return unknown
    for name, correlation in _PROFILES.items():
        try:
            closed = _admit(path, descriptor, correlation)
        except (OSError, ValueError, TypeError, KeyError):
            phases[name] = 'local-history'
            continue
        try:
            first = _fresh_observe(config, target, descriptor, correlation, closed)
            if first != 'archived':
                phases[name] = first
                continue
            second = _fresh_observe(config, target, descriptor, correlation, closed)
            if second != 'archived':
                phases[name] = second
                continue
            # Revalidate original local records after the two fresh probes.
            phases[name] = 'archived' if _admit(path, descriptor, correlation) == closed else 'local-history'
        except (OSError, ValueError, TypeError, KeyError):
            phases[name] = 'local-history'

    return {**_FLAGS, 'state': 'ready' if all(v == 'archived' for v in phases.values()) else 'blocked', 'phases': phases}
