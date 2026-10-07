"""Fixed, read-only terminal observer for CP117's retained e848 HTTP task.

The port is an observed part of the task, not an independently archived original
port. Every other command byte is reconstructed from immutable local authority.
No task, receipt, campaign, product or filesystem mutation is exposed here.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping

from . import windows_cp117_historical_base_archives as history

if history._supported():
    from . import windows_update_fixture_http_stage as http
else:
    http = None
base = history.base
_CORR = 'e848bed2-5bea-47bc-a85a-6cf17b1fcc6a'
_LEASE = 'e59a7483-4e38-4e7b-b8fa-0d8b2356916a'
_GENERATION = history._GENERATION
_HASH = '634aa7a97ef77399ace35bc82fb0dae31ae6e00560a7815b2868f2793d555870'
_LENGTH = 131218059
_TEMPLATE_SHA = '5e3a449197ca105b64982d7f284354e4549e21bf75ac9087fec4dbe470d677c3'
_FLAGS = {'replayAllowed': False, 'nativeActionAllowed': False, 'productAction': False}
# Canonical digests of original private records, not new receipts or current-source labels.
_RECORD_SHA = {
    'windows-update-fixture-stage/'+_CORR+'.json': 'e29c4c2ff2d2c444ce0987181945e2f3ec7d0131d5471c05bd405cdfef3d48a8',
    'windows-update-fixture-http-stage/'+_CORR+'.json': '2adb2e61d46c702fe4d9e28d4a40bb4901e81de5147a2e61f1960d8c473b43a0',
    'windows-large-artifact-transfer/'+_CORR+'.json': '0cf54b06ad0f155ebe64efe456c75fa27a21d69ca4e37737c609ee19b5d5149d',
    'windows-cp117-campaign/'+_LEASE+'.closed.json': '433a5d1544fa44eae8ab767ed67cc1716ec8f3c8a7411fa9cde396221bf9ffbf',
    'windows-cp117-staged-fixture-retire/intent.json': '08363dc937eac08b4832101fc71e214337da93f8d651c3aebba25f2b93c186b9',
    'windows-cp117-staged-fixture-retire/receipt.json': 'da0db514ca44adcfa602b594b2cec95241950efb4da2b9ad993303b26983d57b',
    'windows-cp117-retirement-recovery/intent.json': 'edbb3efa045ea9d9223aeb19d8bad55eb51f97dc014a493a6a5c33631d23997d',
    'windows-cp117-retirement-recovery/guest-terminal.json': '992b2f7255f76ef6ac61da4ea3598dbe1767e983d13faf8218605247a1c77abc',
    'windows-cp117-retirement-recovery/host-removed.json': '992b2f7255f76ef6ac61da4ea3598dbe1767e983d13faf8218605247a1c77abc',
}
_REMOTE_PHASES = frozenset({'root','lock','closed','active','stage','parser','exec','status','output',
                           'identity','task','process','installer','generation','recheck',
                           'output-envelope','output-truncated','output-stderr-progress',
                           'output-stderr-error','output-stderr-other','output-empty','output-json','output-shape','output-bom','output-encoding'})
_PHASES = frozenset({'platform','local-history','local-active','generation','remote-transport',
                    'task-state','task-principal','task-settings','task-action','task-port',
                    'task-terminal','task-trigger','task-execution-limit','process','installer','verified'} | {'remote-'+p for p in _REMOTE_PHASES})


def _result(state: str, phase: str) -> dict[str, Any]:
    return {'state': state, 'phase': phase,
            'proof': 'terminal-success' if state == 'ready' else 'unverified', **_FLAGS}


def _admit(root: Path, descriptor: tuple[Any, ...]) -> tuple[dict[str, Any], dict[str, Any]]:
    if descriptor != _GENERATION:
        raise ValueError('generation')
    with history._history_lock(root):
        active = root / base.campaign_lease._DIR / 'active.json'
        if os.path.lexists(active):
            raise ValueError('local-active')
        values = {}
        for relative, expected in _RECORD_SHA.items():
            path = root / '.rag_index' / relative
            history._directory(path.parent)
            value = history._read(path)
            if history._digest(value) != expected:
                raise ValueError('local-history')
            values[relative] = value
        if os.path.lexists(active):
            raise ValueError('local-active')
        return (values['windows-update-fixture-http-stage/'+_CORR+'.json'],
                values['windows-cp117-campaign/'+_LEASE+'.closed.json'])


def _script(port: int, nonce: str) -> str:
    return http.guest_download_script(correlation_id=_CORR, sid=_GENERATION[4], sha256=_HASH,
                                     length=_LENGTH, port=port, path='/'+nonce)


def _validate(proof: Any, record: Mapping[str, Any]) -> str:
    keys = {'state','taskState','execute','arguments','workingDirectory','principalSid','logonType',
            'runLevel','triggerCount','executionTimeLimit','lastRunTicks','nowTicks','lastTaskResult',
            'correlationProcess','installer'}
    if not isinstance(proof, dict) or set(proof) != keys or proof['state'] != 'observed':
        return 'remote-output-shape'
    if proof['taskState'] != 'Ready': return 'task-state'
    if proof['principalSid'] != _GENERATION[4]: return 'task-principal'
    if (proof['logonType'] != 'Interactive' or proof['runLevel'] != 'Limited'
            or proof['workingDirectory'] != ''):
        return 'task-settings'
    if type(proof['triggerCount']) is not int or proof['triggerCount'] != 0: return 'task-trigger'
    if proof['executionTimeLimit'] != 'PT5M': return 'task-execution-limit'
    if proof['correlationProcess'] != 'absent': return 'process'
    if proof['installer'] != 'absent': return 'installer'
    # 2000-01-01 through 9999-12-31: a default, never-run timestamp is excluded.
    if (type(proof['lastRunTicks']) is not int or type(proof['nowTicks']) is not int
            or not 630822816000000000 <= proof['lastRunTicks'] <= proof['nowTicks'] <= 3155378975999999999
            or type(proof['lastTaskResult']) is not int or proof['lastTaskResult'] != 0):
        return 'task-terminal'
    executable = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    if proof['execute'] != executable or not isinstance(proof['arguments'], str): return 'task-action'
    prefix = '-NoProfile -NonInteractive -EncodedCommand '
    arguments = proof['arguments']
    if not arguments.startswith(prefix) or not len(prefix) < len(arguments) < 12000: return 'task-action'
    try:
        encoded = arguments[len(prefix):]
        raw = base64.b64decode(encoded, validate=True)
        if base64.b64encode(raw).decode('ascii') != encoded: return 'task-action'
        script = raw.decode('utf-16le')
        found = re.findall(r'\$port=([0-9]{1,5});', script)
        if len(found) != 1: return 'task-port'
        port = int(found[0])
        if not 1 <= port <= 65535 or str(port) != found[0]: return 'task-port'
        template = _script(1, 'A'*32)
        if hashlib.sha256(template.encode('utf-16le')).hexdigest() != _TEMPLATE_SHA: return 'task-action'
        expected = _script(port, record['routeNonce'])
        if script != expected or arguments != prefix+base64.b64encode(expected.encode('utf-16le')).decode('ascii'):
            return 'task-action'
    except (ValueError, UnicodeError, KeyError, TypeError):
        return 'task-action'
    return 'verified'


def _trigger_count_powershell() -> str:
    """Normalize only Scheduler's empty or single-null representation."""
    return ("$triggers=@($task.Triggers);"
            "if($triggers.Count -eq 0 -or ($triggers.Count -eq 1 -and $null -eq $triggers[0]))"
            "{$triggerCount=0}else{$triggerCount=$triggers.Count}")


def _process_census_powershell() -> str:
    """No other PowerShell may hide a correlated action in encoded arguments."""
    return r"""$processState='absent'
foreach($process in $all){if($process.ProcessId -eq $PID){continue};$line=[string]$process.CommandLine
 if($line -match [regex]::Escape($corr)){$processState='present';break}
 if($process.Name -in @('powershell.exe','pwsh.exe')){
  $processState='ambiguous'
  if([string]::IsNullOrWhiteSpace($line) -or $line.Length -gt 65536){continue}
  if($line -match '(?i)-(?:EncodedCommand|EncodedComman|EncodedComma|EncodedComm|EncodedCom|EncodedCo|EncodedC|Encoded|Encode|Encod|Enco|Enc|En|Ec|E)\s+"?([^\s"]+)"?'){
   try{$bytes=[Convert]::FromBase64String($Matches[1]);$utf16=[Text.UnicodeEncoding]::new($false,$false,$true);$decoded=$utf16.GetString($bytes);if($decoded -match [regex]::Escape($corr)){$processState='present';break}}catch{$processState='ambiguous'}
  }
 }
}"""


_PS = r'''$ErrorActionPreference='Stop';$phase='identity';try{
$corr='e848bed2-5bea-47bc-a85a-6cf17b1fcc6a';$sid='S-1-5-21-2404255130-2183793310-3766671872-1002'
$actualSid=([Security.Principal.NTAccount]::new('VPNMSIX64\vpncp117')).Translate([Security.Principal.SecurityIdentifier]).Value
if($actualSid -cne $sid){throw 'SID'}
$phase='stage';if(Test-Path -LiteralPath ('C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-fixture-'+$corr)){throw 'STAGE'}
$phase='task';$name='VpnControlMcpFixtureHttp-'+$corr
$tasks=@(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq $name})
if($tasks.Count -ne 1){throw 'TASK'};$task=$tasks[0];$actions=@($task.Actions)
if($actions.Count -ne 1){throw 'ACTION'};$action=$actions[0]
$principal=[string]$task.Principal.UserId
if($principal -match '^S-1-'){$principalSid=([Security.Principal.SecurityIdentifier]::new($principal)).Value}else{$principalSid=([Security.Principal.NTAccount]::new($principal)).Translate([Security.Principal.SecurityIdentifier]).Value}
$info=Get-ScheduledTaskInfo -TaskPath '\' -TaskName $name -ErrorAction Stop
if($info.LastRunTime -isnot [datetime]){throw 'TIME'}
$raw=$info.LastTaskResult;if($null -eq $raw -or [Convert]::GetTypeCode($raw) -notin @([TypeCode]::SByte,[TypeCode]::Int16,[TypeCode]::Int32,[TypeCode]::Int64,[TypeCode]::Byte,[TypeCode]::UInt16,[TypeCode]::UInt32,[TypeCode]::UInt64)){throw 'RESULT'}
$result=[int64]$raw;if($result -lt -2147483648 -or $result -gt 4294967295){throw 'RESULT'};if($result -lt 0){$result+=4294967296}
$arguments=[string]$action.Arguments;if($arguments.Length -gt 12000 -or ([string]$action.Execute).Length -gt 256 -or ([string]$action.WorkingDirectory).Length -gt 256){throw 'BOUND'}
@TRIGGER_COUNT@
$phase='process';$all=@(Get-CimInstance Win32_Process -ErrorAction Stop)
@PROCESS_CENSUS@
$phase='installer';$installerState=if(@($all|Where-Object {$_.Name -in @('msiexec.exe','consent.exe')}).Count -eq 0){'absent'}else{'present'}
$phase='output'
[Console]::Out.WriteLine((@{state='observed';taskState=[string]$task.State;execute=[string]$action.Execute;arguments=$arguments;workingDirectory=[string]$action.WorkingDirectory;principalSid=$principalSid;logonType=[string]$task.Principal.LogonType;runLevel=[string]$task.Principal.RunLevel;triggerCount=$triggerCount;executionTimeLimit=[string]$task.Settings.ExecutionTimeLimit;lastRunTicks=$info.LastRunTime.ToUniversalTime().Ticks;nowTicks=[datetime]::UtcNow.Ticks;lastTaskResult=$result;correlationProcess=$processState;installer=$installerState}|ConvertTo-Json -Compress -Depth 3))
}catch{[Console]::Out.WriteLine((@{state='unknown';phase=$phase}|ConvertTo-Json -Compress));exit 1}
'''.replace('@TRIGGER_COUNT@', _trigger_count_powershell()).replace('@PROCESS_CENSUS@', _process_census_powershell())


_REMOTE_BODY = r'''PARSER_TEMPLATE='$ErrorActionPreference=\'Stop\';try{\n$bytes=[Convert]::FromBase64String(\'@PACKED@\');$input=[IO.MemoryStream]::new([byte[]]$bytes)\n$gzip=[IO.Compression.GzipStream]::new($input,[IO.Compression.CompressionMode]::Decompress)\n$output=[IO.MemoryStream]::new();$gzip.CopyTo($output);$body=[Text.Encoding]::Unicode.GetString($output.ToArray())\n$gzip.Dispose();$input.Dispose();$output.Dispose();$tokens=$null;$errors=$null\n[Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)|Out-Null\nif($errors.Count -ne 0){throw \'PARSE\'}\n[Console]::Out.WriteLine(\'{"version":1,"code":"OK"}\')\n}catch{[Console]::Out.WriteLine(\'{"version":1,"code":"FAILED"}\');exit 1}\n'
import fcntl,time,gzip,xml.etree.ElementTree as ET
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
 if not isinstance(item.get('err-data',''),str) or len(item.get('err-data',''))>12000 or not isinstance(item.get('out-data',''),str) or len(item.get('out-data',''))>24000:raise ValueError()
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
 if len(raw)>16384:raise ValueError()
 phase='output-bom' if raw.startswith((b'\xff\xfe',b'\xfe\xff',b'\xef\xbb\xbf')) else 'output-encoding'
 text=decode(raw)
 phase='output-json'
 value=load(text)
 return item['exitcode'],value


try:
 if env!='windows-cp117' or corr!='e848bed2-5bea-47bc-a85a-6cf17b1fcc6a' or (sock,int(pid),int(ticks),sid)!=('/home/kardinal/vpn-control-windows-msi-acceptance-cp117/cp135-launch/qga.sock',589342,520739,'S-1-5-21-2404255130-2183793310-3766671872-1002') or not os.path.isabs(root) or os.path.normpath(root)!=root:raise ValueError()
 phase='generation'
 if not live(sock,pid,ticks):raise ValueError()
 phase='root';expected=load(expected_text)
 parent=os.path.join(root,env);campaign=os.path.join(parent,'windows-cp117-campaign');group=os.path.join(parent,'windows-update-fixture-http-stage');stage=os.path.join(group,corr)
 parents=[(p,directory(p)) for p in (root,parent,campaign,group)]
 phase='lock';lockpath=os.path.join(campaign,'.environment.lock');lock=os.open(lockpath,os.O_RDONLY|os.O_NOFOLLOW);info=os.fstat(lock)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or not same(info,os.lstat(lockpath)):raise ValueError()
 fcntl.flock(lock,fcntl.LOCK_SH)
 closedpath=os.path.join(campaign,'e59a7483-4e38-4e7b-b8fa-0d8b2356916a.closed.json');activepath=os.path.join(campaign,'active.json')
 def recheck():
  global phase
  phase='closed'
  if read(closedpath)!=expected:raise ValueError()
  phase='active'
  if os.path.lexists(activepath):raise ValueError()
  phase='stage'
  if os.path.lexists(stage):raise ValueError()
  phase='generation'
  if not live(sock,pid,ticks):raise ValueError()
  phase='recheck'
  if not same(info,os.lstat(lockpath)):raise ValueError()
  for path,old in parents:
   if not same(old,directory(path)):raise ValueError()
 recheck()
 phase='parser';actual=base64.b64decode(encoded,validate=True)
 packed=base64.b64encode(gzip.compress(actual,mtime=0)).decode('ascii')
 parser=PARSER_TEMPLATE.replace('@PACKED@',packed)
 parser_encoded=base64.b64encode(parser.encode('utf-16le')).decode('ascii')
 if len(parser_encoded)>=30000:raise ValueError()
 exitcode,value=query(parser_encoded);phase='parser'
 if exitcode!=0 or value!={'version':1,'code':'OK'} or type(value.get('version'))is not int:raise ValueError()
 proofs=[]
 for _ in range(2):
  recheck();exitcode,value=query(encoded);phase='output-shape'
  if exitcode!=0:
   if isinstance(value,dict) and set(value)=={'state','phase'} and value['state']=='unknown' and value['phase'] in {'identity','stage','task','process','installer','output'}:phase=value['phase']
   raise ValueError()
  if not isinstance(value,dict) or value.get('state')!='observed':raise ValueError()
  proofs.append(value);recheck()
 out({'state':'observed','proofs':proofs})
except Exception:out({'state':'unknown','phase':phase if phase!='guard' else 'root'})
finally:
 if lock is not None:os.close(lock)
'''
_REMOTE = (base._QGA if base is not None else '') + _REMOTE_BODY


def _fresh(config: Any, target: Any, descriptor: tuple[Any, ...], record: dict[str, Any], closed: dict[str, Any]) -> str:
    encoded = base64.b64encode(_PS.encode('utf-16le')).decode('ascii')
    if len(encoded) >= 30000: return 'remote-output'
    try:
        raw = base._remote(config, _REMOTE, (str(target.fixture_transfer_root), *_remote_arguments(descriptor, closed), encoded), None, 45)
        if raw is None: return 'remote-transport'
        if not isinstance(raw, (str, bytes)) or not 0 < len(raw) <= 40000: return 'remote-output'
        value = json.loads(raw, object_pairs_hook=history._unique)
        if (isinstance(value, dict) and set(value) == {'state','phase'} and value['state'] == 'unknown'
                and isinstance(value['phase'], str) and value['phase'] in _REMOTE_PHASES):
            return 'remote-'+value['phase']
        if (not isinstance(value, dict) or set(value) != {'state','proofs'} or value['state'] != 'observed'
                or not isinstance(value['proofs'], list) or len(value['proofs']) != 2):
            return 'remote-output-shape'
        first, second = value['proofs']
        for proof in (first, second):
            phase = _validate(proof, record)
            if phase != 'verified': return phase
        # Stable identity and terminal history; current time may advance.
        if {k:v for k,v in first.items() if k != 'nowTicks'} != {k:v for k,v in second.items() if k != 'nowTicks'}:
            return 'remote-recheck'
        if second['nowTicks'] < first['nowTicks']: return 'remote-recheck'
        return 'verified'
    except (OSError, ValueError, TypeError, KeyError):
        return 'remote-output'


def _remote_arguments(descriptor: tuple[Any, ...], closed: dict[str, Any]) -> tuple[str, ...]:
    return (descriptor[0], _CORR, descriptor[1], str(descriptor[2]), str(descriptor[3]), descriptor[4],
            json.dumps(closed, sort_keys=True, separators=(',', ':')))


def observe(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Observe only the fixed original HTTP downloader; never dispatch its action."""
    if not isinstance(value, Mapping) or dict(value) != {}:
        raise ValueError('Fixed HTTP task observation takes no inputs.')
    if not history._supported() or base is None or http is None:
        return _result('blocked', 'platform')
    try:
        path = Path(root).resolve(strict=True)
        config, target, descriptor = base._descriptor(path)
        if descriptor != _GENERATION: return _result('blocked', 'generation')
        # Keep the same existing shared lock throughout remote observation.
        with history._history_lock(path):
            record, closed = _admit(path, descriptor)
            phase = _fresh(config, target, descriptor, record, closed)
            if _admit(path, descriptor) != (record, closed): return _result('blocked','local-history')
        return _result('ready' if phase == 'verified' else 'unknown', phase)
    except ValueError as error:
        phase = str(error)
        return _result('blocked', phase if phase in {'local-active','generation'} else 'local-history')
    except (OSError, TypeError, KeyError):
        return _result('blocked', 'local-history')
