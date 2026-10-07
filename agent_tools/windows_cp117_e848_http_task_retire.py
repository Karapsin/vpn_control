"""One-shot retirement of only the original e848 CP117 HTTP downloader.

The original task XML and native metadata are protected and read back before
unregistration. A consumed intent permits status only; absence without a durable
terminal is unknown. Original campaign, staging and retirement journals remain.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import re
import stat
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Mapping

from . import windows_cp117_e848_http_task as observer
from . import windows_cp117_protected_journal as journal
from . import windows_cp117_retirement_guards as guards
if observer.history._supported():
    from . import windows_cp117_guest_agent_recovery as transport
else:
    transport = None
base = observer.base
_RETIREMENT = '477365c8-3c78-4d5c-83c9-2f6de2bd5997'
_DIR = '.rag_index/windows-cp117-e848-http-task-retirement'
_ROOT = r'C:\ProgramData\VpnControlCp117-retirement-'+_RETIREMENT
_TASK = 'VpnControlMcpFixtureHttp-'+observer._CORR
_LEAVES = ('binding.json','archive.json','terminal.json')
_PHASES = frozenset({'platform','intent','active-lease','descriptor','proof','snapshot','parser',
                    'dispatch','journal','terminal','absence','generation','complete'})

_PROBE_PHASES=frozenset({'transport','envelope','json','shape','descriptor','output-host-bound','gzip-envelope','gzip-bounds','gzip-hash','gzip-json'} | set(observer._REMOTE_PHASES) | {'guest-'+p for p in ('identity','stage','task','process','installer','output')})
_GUARDS=frozenset({'EXISTS','PROOF','PROOF_CHANGED','XML_SIZE','PORT','SID','STAGE','TASK','ACTION','TIME','RESULT','BOUND','UNKNOWN'})
_ARCHIVE_PHASES=frozenset({'archive-shape','archive-binding','archive-bounds','archive-compression','action-binding','xml-bounds','xml-hash','xml-encoding','xml-entity','xml-parse','xml-identity','xml-action','xml-command','xml-arguments','xml-working-directory','xml-user','xml-logon','xml-run-level'})
_PROOF_PHASES=frozenset({'task-state','task-principal','task-settings','task-trigger','task-execution-limit','task-action','task-port','task-terminal','process','installer','remote-output-shape'})
_RUN_LEVEL_PHASES=frozenset({'xml-run-level-'+form for form in ('absent','empty','limited','highest-available','other','shape')})
_ARCHIVE_PHASES=_ARCHIVE_PHASES|_RUN_LEVEL_PHASES
_PHASES=_PHASES | {'snapshot-'+p for p in _PROBE_PHASES|_ARCHIVE_PHASES|_PROOF_PHASES} | {'snapshot-guard-'+p.lower().replace('_','-') for p in _GUARDS}


def _probe_failure(phase:str)->dict[str,str]:
    return {'state':'probe-failed','phase':phase if phase in _PROBE_PHASES else 'shape'}


def _archive_phase(error:Exception)->str:
    if isinstance(error,UnicodeError):return 'xml-encoding'
    if isinstance(error,ET.ParseError):return 'xml-parse'
    names={'archive binding':'archive-binding','action binding':'action-binding','XML bounds':'xml-bounds','XML hash':'xml-hash','XML entity':'xml-entity','XML identity':'xml-identity','XML action':'xml-action'}
    if str(error).lower().replace(' ','-') in _RUN_LEVEL_PHASES:return str(error).lower().replace(' ','-')
    if str(error) in {'XML command','XML arguments','XML working-directory','XML user','XML logon','XML run-level'}:
        return str(error).lower().replace(' ','-')
    return names.get(str(error),'archive-compression')


class _Blocked(ValueError):
    def __init__(self,phase:str):
        assert phase in _PHASES
        self.phase=phase


def _result(state: str, phase: str) -> dict[str, Any]:
    assert phase in _PHASES
    return {'state':state,'phase':phase,'retirementCorrelationId':_RETIREMENT,**observer._FLAGS}


def _digest(value: Any) -> str:
    return observer.history._digest(value)


def _read(path: Path) -> dict[str, Any] | None:
    if not os.path.lexists(path): return None
    observer.history._directory(path.parent)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno());current=path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600
                or not 0<info.st_size<=16384 or (info.st_dev,info.st_ino)!=(current.st_dev,current.st_ino)):
            raise ValueError('unsafe intent')
        raw=stream.read(16385)
        if len(raw)!=info.st_size:raise ValueError('changed intent')
        value=json.loads(raw,object_pairs_hook=observer.history._unique)
    if not isinstance(value,dict):raise ValueError('invalid intent')
    return value


def _archive(value: Any, record: Mapping[str,Any], binding_sha: str | None = None) -> dict[str,Any]:
    fields={'proof','actionSha256','observedPort','xmlSha256','xmlLength','xmlGzip'}
    if binding_sha is not None:fields.add('bindingSha256')
    if (not isinstance(value,dict) or set(value)!=fields or observer._validate(value.get('proof'),record)!='verified'
            or type(value.get('observedPort')) is not int or not 1<=value['observedPort']<=65535
            or type(value.get('xmlLength')) is not int or not 1<=value['xmlLength']<=131072
            or not isinstance(value.get('xmlGzip'),str) or len(value['xmlGzip'])>15000
            or not isinstance(value.get('xmlSha256'),str) or not re.fullmatch('[0-9a-f]{64}',value['xmlSha256'])
            or (binding_sha is not None and value.get('bindingSha256')!=binding_sha)
            or len(json.dumps(value,separators=(',',':')).encode())>16384):
        raise ValueError('archive binding')
    proof=value['proof']
    action=hashlib.sha256((proof['execute']+'\0'+proof['arguments']).encode()).hexdigest()
    script=base64.b64decode(proof['arguments'].rsplit(' ',1)[1],validate=True).decode('utf-16le')
    port=int(re.findall(r'\$port=([0-9]{1,5});',script)[0])
    if value['actionSha256']!=action or value['observedPort']!=port:raise ValueError('action binding')
    packed=base64.b64decode(value['xmlGzip'],validate=True)
    with gzip.GzipFile(fileobj=io.BytesIO(packed)) as stream:
        raw=stream.read(131073)
        if len(raw)>131072 or stream.read(1):raise ValueError('XML bounds')
    if len(raw)!=value['xmlLength'] or hashlib.sha256(raw).hexdigest()!=value['xmlSha256']:raise ValueError('XML hash')
    text=raw.decode('utf-8',errors='strict')
    if '<!DOCTYPE' in text or '<!ENTITY' in text:raise ValueError('XML entity')
    tree=ET.fromstring(text);ns='{http://schemas.microsoft.com/windows/2004/02/mit/task}'
    actions=tree.find(ns+'Actions');triggers=tree.find(ns+'Triggers');principals=tree.find(ns+'Principals')
    if (tree.tag!=ns+'Task' or actions is None or len(actions)!=1 or actions[0].tag!=ns+'Exec'
            or principals is None or len(principals)!=1 or (triggers is not None and len(triggers)!=0)):
        raise ValueError('XML identity')
    checks=(
        ('command',actions[0].findtext(ns+'Command')==proof['execute']),
        ('arguments',actions[0].findtext(ns+'Arguments')==proof['arguments']),
        ('working-directory',(actions[0].findtext(ns+'WorkingDirectory') or '')==proof['workingDirectory']),
        ('user',principals[0].findtext(ns+'UserId') in {observer._GENERATION[4],r'VPNMSIX64\vpncp117'}),
        ('logon',principals[0].findtext(ns+'LogonType')=='InteractiveToken'),
    )
    for phase,valid in checks:
        if not valid:raise ValueError('XML '+phase)
    levels=principals[0].findall(ns+'RunLevel')
    # Native export omits optional RunLevel (MS Task Scheduler principalType,
    # minOccurs=0). Only the separately verified current Limited proof admits
    # this absence; XML bytes/hash remain untouched in the protected archive.
    if not levels:
        if proof['runLevel']!='Limited':raise ValueError('XML run-level-absent')
    else:
        if len(levels)!=1 or levels[0].attrib or len(levels[0]):raise ValueError('XML run-level-shape')
        level=levels[0].text
        if level!='LeastPrivilege':
            form={None:'empty','':'empty','Limited':'limited','HighestAvailable':'highest-available'}.get(level,'other')
            raise ValueError('XML run-level-'+form)
    # Current time is not historical identity; every remaining byte is retained.
    return {k:({a:b for a,b in value[k].items() if a!='nowTicks'} if k=='proof' else value[k])
            for k in fields-{'xmlGzip','bindingSha256'}}


def _binding(snapshot: dict[str,Any]) -> dict[str,Any]:
    env,sock,pid,ticks,sid=observer._GENERATION
    return {'retirementCorrelationId':_RETIREMENT,'task':_TASK,'environment':env,'socketPath':sock,
            'qemuPid':pid,'startTicks':ticks,'sid':sid,'sourceSha':'19be9df22cbab8086c26e5ca907d9569a5a28a08',
            'leaseId':observer._LEASE,'historicalRecordDigests':dict(observer._RECORD_SHA),'snapshot':snapshot}


def _task_functions() -> str:
    # Exactly the frozen read-only observer source; its output becomes private data.
    source=observer._PS.replace('[Console]::Out.WriteLine(', 'Write-Output (')
    return "function ReadTaskProof {\n"+source+"\n}\n"+r'''
$ErrorActionPreference='Stop'
function Hash([byte[]]$bytes){$h=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($h.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
function SameProof($a,$b){foreach($key in @('state','taskState','execute','arguments','workingDirectory','principalSid','logonType','runLevel','triggerCount','executionTimeLimit','lastRunTicks','lastTaskResult','correlationProcess','installer')){if($a.$key -cne $b.$key){throw 'PROOF_CHANGED'}}}
function Idle { $corr='e848bed2-5bea-47bc-a85a-6cf17b1fcc6a';$all=@(Get-CimInstance Win32_Process -ErrorAction Stop);@CENSUS@;if($processState -cne 'absent' -or @($all|Where-Object {$_.Name -in @('msiexec.exe','consent.exe')}).Count -ne 0){throw 'PROCESS'};if(Test-Path -LiteralPath ('C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-fixture-'+$corr)){throw 'STAGE'} }
function TaskSnapshot {
 $p=ReadTaskProof|ConvertFrom-Json -ErrorAction Stop
 if($p.state -cne 'observed' -or $p.taskState -cne 'Ready' -or $p.lastTaskResult -ne 0 -or $p.lastRunTicks -lt 630822816000000000 -or $p.lastRunTicks -gt $p.nowTicks -or $p.nowTicks -gt 3155378975999999999 -or $p.correlationProcess -cne 'absent' -or $p.installer -cne 'absent'){throw 'PROOF'}
 $xml=[Text.Encoding]::UTF8.GetBytes((Export-ScheduledTask -TaskPath '\' -TaskName '@TASK@' -ErrorAction Stop))
 if($xml.Length -lt 1 -or $xml.Length -gt 131072){throw 'XML_SIZE'}
 $o=[IO.MemoryStream]::new();$z=[IO.Compression.GzipStream]::new($o,[IO.Compression.CompressionMode]::Compress,$true);$z.Write($xml,0,$xml.Length);$z.Dispose();$packed=[Convert]::ToBase64String($o.ToArray());$o.Dispose()
 $fresh=ReadTaskProof|ConvertFrom-Json -ErrorAction Stop;SameProof $p $fresh
 $decoded=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(($p.arguments -split ' ')[-1]));if($decoded -notmatch '\$port=([0-9]{1,5});'){throw 'PORT'};$port=[int]$Matches[1]
 return [ordered]@{proof=$p;actionSha256=(Hash ([Text.Encoding]::UTF8.GetBytes($p.execute+[char]0+$p.arguments)));observedPort=$port;xmlSha256=(Hash $xml);xmlLength=$xml.Length;xmlGzip=$packed}
}
function VerifyArchive($a){$packed=[Convert]::FromBase64String($a.xmlGzip);$i=[IO.MemoryStream]::new([byte[]]$packed);$z=[IO.Compression.GzipStream]::new($i,[IO.Compression.CompressionMode]::Decompress);$o=[IO.MemoryStream]::new();try{$buf=New-Object byte[] 4096;while(($n=$z.Read($buf,0,$buf.Length)) -gt 0){if($o.Length+$n -gt 131072){throw 'XML_SIZE'};$o.Write($buf,0,$n)};$raw=$o.ToArray();if($raw.Length -ne $a.xmlLength -or (Hash $raw) -cne $a.xmlSha256){throw 'XML_HASH'}}finally{$z.Dispose();$i.Dispose();$o.Dispose()}}
function SameSnapshot($a,$b){SameProof $a.proof $b.proof;foreach($key in @('actionSha256','observedPort','xmlSha256','xmlLength')){if($a.$key -cne $b.$key){throw 'SNAPSHOT_CHANGED'}}}
'''.replace('@CENSUS@',observer._process_census_powershell()).replace('@TASK@',_TASK)


def _snapshot_script() -> str:
    allowed=','.join("'"+guard+"'" for guard in sorted(_GUARDS))
    return _task_functions()+";try{if(Test-Path -LiteralPath '"+_ROOT+"'){throw 'EXISTS'};$a=TaskSnapshot;[Console]::Out.WriteLine((@{archive=$a}|ConvertTo-Json -Depth 8 -Compress))}catch{$guard=$_.Exception.Message;if($guard -notin @("+allowed+")){$guard='UNKNOWN'};[Console]::Out.WriteLine((@{state='snapshot-failed';guard=$guard}|ConvertTo-Json -Compress))}"


def _plan(binding: dict[str,Any]) -> tuple[str,dict[str,Any]]:
    binding_sha=_digest(binding);text=json.dumps(binding,sort_keys=True,separators=(',',':')).replace("'","''")
    source=_task_functions()+journal.powershell(_ROOT,_LEAVES)+r'''
$b=ConvertFrom-Json '@BINDING@';$bindingSha='@SHA@';$action='@ACTION@'
if(Test-Path -LiteralPath $JournalRoot){throw 'EXISTS'}
$first=TaskSnapshot;SameSnapshot $first $b.snapshot
$second=TaskSnapshot;SameSnapshot $first $second
$first.bindingSha256=$bindingSha
if([Text.Encoding]::UTF8.GetByteCount(($first|ConvertTo-Json -Depth 8 -Compress)) -gt 16384){throw 'LEAF_SIZE'}
Idle;Initialize-SecureJournal
Write-SecureJsonCreate 'binding.json' ((@{binding=$b;bindingSha256=$bindingSha;actionSha256=$action})|ConvertTo-Json -Depth 10 -Compress)
Write-SecureJsonCreate 'archive.json' ($first|ConvertTo-Json -Depth 8 -Compress)
$savedBinding=Read-SecureJson 'binding.json';if($savedBinding.bindingSha256 -cne $bindingSha -or $savedBinding.actionSha256 -cne $action){throw 'BINDING'}
$saved=Read-SecureJson 'archive.json';VerifyArchive $saved;SameSnapshot $saved $first;if($saved.xmlGzip -cne $first.xmlGzip -or $saved.bindingSha256 -cne $bindingSha){throw 'ARCHIVE_CHANGED'}
$fresh=TaskSnapshot;SameSnapshot $fresh $saved;Idle
Unregister-ScheduledTask -TaskPath '\' -TaskName '@TASK@' -Confirm:$false -ErrorAction Stop
Idle;if(@(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq '@TASK@'}).Count -ne 0){throw 'PRESENT'}
Write-SecureJsonCreate 'terminal.json' ((@{retirementCorrelationId='@RETIREMENT@';state='retired';bindingSha256=$bindingSha;actionSha256=$action})|ConvertTo-Json -Compress)
[Console]::Out.WriteLine('{"submitted":true}')
'''.replace('@BINDING@',text).replace('@SHA@',binding_sha).replace('@TASK@',_TASK).replace('@RETIREMENT@',_RETIREMENT)
    action=hashlib.sha256(source.replace('@ACTION@','').encode('utf-16le')).hexdigest()
    return source.replace('@ACTION@',action),{'binding':binding,'bindingSha256':binding_sha,'actionSha256':action}


def _reader() -> str:
    return _task_functions()+journal.powershell(_ROOT,_LEAVES)+r'''
Idle;$b=Read-SecureJson 'binding.json';$a=Read-SecureJson 'archive.json';VerifyArchive $a;$t=Read-SecureJson 'terminal.json'
$nodes=@(Get-ChildItem -LiteralPath $JournalRoot -Force -ErrorAction Stop);if($nodes.Count -ne 3){throw 'LEAVES'}
if(@(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq '@TASK@'}).Count -ne 0){throw 'PRESENT'}
Idle;[Console]::Out.WriteLine((@{binding=$b;archive=$a;terminal=$t;absent=$true}|ConvertTo-Json -Depth 12 -Compress))
'''.replace('@TASK@',_TASK)


_REMOTE_BODY = r'''PARSER_TEMPLATE='$ErrorActionPreference=\'Stop\';try{\n$bytes=[Convert]::FromBase64String(\'@PACKED@\');$input=[IO.MemoryStream]::new([byte[]]$bytes)\n$gzip=[IO.Compression.GzipStream]::new($input,[IO.Compression.CompressionMode]::Decompress)\n$output=[IO.MemoryStream]::new();$gzip.CopyTo($output);$body=[Text.Encoding]::Unicode.GetString($output.ToArray())\n$gzip.Dispose();$input.Dispose();$output.Dispose();$tokens=$null;$errors=$null\n[Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)|Out-Null\nif($errors.Count -ne 0){throw \'PARSE\'}\n[Console]::Out.WriteLine(\'{"version":1,"code":"OK"}\')\n}catch{[Console]::Out.WriteLine(\'{"version":1,"code":"FAILED"}\');exit 1}\n'
import fcntl,time,gzip,xml.etree.ElementTree as ET
root,env,corr,sock,pid,ticks,sid,expected_text,encoded=sys.argv[1:]
lock=None
phase='guard'
def out(v):
 raw=json.dumps(v,separators=(',',':'),sort_keys=True);data=raw.encode()
 if len(data)+1>16384:
  if isinstance(v,dict) and set(v)=={'state','receipt'} and v['state']=='observed' and len(data)<=50000:
   packed=base64.b64encode(gzip.compress(data,mtime=0)).decode('ascii')
   raw=json.dumps({'state':'observed-gzip','length':len(data),'sha256':hashlib.sha256(data).hexdigest(),'gzip':packed},separators=(',',':')) if len(packed)<=16000 else raw
  if len(raw.encode())+1>16384:raw=json.dumps({'state':'unknown','phase':'output-host-bound'},separators=(',',':'))
 print(raw)
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
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-Command',program],'capture-output':True})['pid']
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
 if not isinstance(item.get('err-data',''),str) or len(item.get('err-data',''))>12000 or not isinstance(item.get('out-data',''),str) or len(item.get('out-data',''))>68000:raise ValueError()
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
 if len(raw)>50000:raise ValueError()
 phase='output-bom' if raw.startswith((b'\xff\xfe',b'\xfe\xff',b'\xef\xbb\xbf')) else 'output-encoding'
 text=decode(raw)
 phase='output-json'
 value=load(text)
 return item['exitcode'],value


try:
 phase='generation'
 if env!='windows-cp117' or corr!='e848bed2-5bea-47bc-a85a-6cf17b1fcc6a' or (sock,int(pid),int(ticks),sid)!=('/home/kardinal/vpn-control-windows-msi-acceptance-cp117/cp135-launch/qga.sock',589342,520739,'S-1-5-21-2404255130-2183793310-3766671872-1002') or not live(sock,pid,ticks):raise ValueError()
 phase='root'
 if not os.path.isabs(root) or os.path.normpath(root)!=root:raise ValueError()
 expected=load(expected_text);parent=os.path.join(root,env);campaign=os.path.join(parent,'windows-cp117-campaign');group=os.path.join(parent,'windows-update-fixture-http-stage')
 parents=[(path,directory(path)) for path in (root,parent,campaign,group)]
 phase='lock';lockpath=os.path.join(campaign,'.environment.lock');lock=os.open(lockpath,os.O_RDONLY|os.O_NOFOLLOW);info=os.fstat(lock)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or not same(info,os.lstat(lockpath)):raise ValueError()
 fcntl.flock(lock,fcntl.LOCK_SH)
 def recheck():
  global phase
  phase='closed'
  if read(os.path.join(campaign,'e59a7483-4e38-4e7b-b8fa-0d8b2356916a.closed.json'))!=expected:raise ValueError()
  phase='active'
  if os.path.lexists(os.path.join(campaign,'active.json')):raise ValueError()
  phase='stage'
  if os.path.lexists(os.path.join(group,corr)):raise ValueError()
  phase='generation'
  if not live(sock,pid,ticks):raise ValueError()
  phase='recheck'
  if not same(info,os.lstat(lockpath)):raise ValueError()
  for path,old in parents:
   if not same(old,directory(path)):raise ValueError()
 recheck();exitcode,value=query(encoded);phase='output-shape'
 if exitcode!=0:
  if isinstance(value,dict) and set(value)=={'state','phase'} and value['state']=='unknown' and value['phase'] in {'identity','stage','task','process','installer','output'}:phase='guest-'+value['phase']
  raise ValueError()
 recheck();out({'state':'observed','receipt':value})
except Exception:out({'state':'unknown','phase':phase})
finally:
 if lock is not None:os.close(lock)
'''
_REMOTE = (base._QGA if base is not None else '') + _REMOTE_BODY


def _command(source:str) -> str:
    # Fixed source is gzip-packed once; plain -Command avoids expanding the
    # already Base64-packed launcher again as UTF-16 Base64.
    command=transport._launcher(source)
    if not 0<len(command)<30000:raise ValueError('Windows command bound')
    return command


def _unpack(value:Any)->Any:
    if not isinstance(value,dict) or value.get('state')!='observed-gzip':return value
    if (set(value)!={'state','length','sha256','gzip'} or type(value['length']) is not int
            or not 1<=value['length']<=50000 or not isinstance(value['sha256'],str)
            or not re.fullmatch('[0-9a-f]{64}',value['sha256']) or not isinstance(value['gzip'],str)
            or not 0<len(value['gzip'])<=16000):return _probe_failure('gzip-envelope')
    try:
        packed=base64.b64decode(value['gzip'],validate=True)
        with gzip.GzipFile(fileobj=io.BytesIO(packed)) as stream:
            raw=stream.read(50001)
            if len(raw)>50000 or stream.read(1):return _probe_failure('gzip-bounds')
    except (OSError,ValueError,EOFError):return _probe_failure('gzip-bounds')
    if len(raw)!=value['length'] or hashlib.sha256(raw).hexdigest()!=value['sha256']:return _probe_failure('gzip-hash')
    try:return json.loads(raw,object_pairs_hook=observer.history._unique)
    except (UnicodeError,ValueError,TypeError):return _probe_failure('gzip-json')


def _run(root:Path, descriptor:tuple[Any,...], closed:dict[str,Any], source:str) -> Any:
    config,target,current=base._descriptor(root)
    if current!=descriptor or descriptor!=observer._GENERATION:return _probe_failure('descriptor')
    raw=base._remote(config,_REMOTE,(str(target.fixture_transfer_root),*observer._remote_arguments(descriptor,closed),_command(source)),None,60)
    if raw is None:return _probe_failure('transport')
    if not isinstance(raw,(bytes,str)) or not 0<len(raw)<=16384:return _probe_failure('envelope')
    try:value=json.loads(raw,object_pairs_hook=observer.history._unique)
    except (ValueError,TypeError):return _probe_failure('json')
    value=_unpack(value)
    if isinstance(value,dict) and set(value)=={'state','phase'} and value['state']=='probe-failed' and value['phase'] in _PROBE_PHASES:return value
    if (isinstance(value,dict) and set(value)=={'state','phase'} and value['state']=='unknown'
            and isinstance(value['phase'],str) and value['phase'] in _PROBE_PHASES):return _probe_failure(value['phase'])
    if isinstance(value,dict) and set(value)=={'state','receipt'} and value['state']=='observed':return value['receipt']
    return _probe_failure('shape')


def _parse(root:Path,descriptor:tuple[Any,...],closed:dict[str,Any],source:str) -> bool:
    packed=base64.b64encode(gzip.compress(source.encode('utf-16le'),mtime=0)).decode()
    parser=observer.history._PARSER.replace('@PACKED@',packed)
    # The parser receives the exact prospective source bytes and never invokes it.
    return _run(root,descriptor,closed,parser)=={'version':1,'code':'OK'}


def _admit(root:Path):
    descriptor=base._descriptor(root)[2]
    if descriptor!=observer._GENERATION:raise _Blocked('descriptor')
    record,closed=observer._admit(root,descriptor)
    if observer.observe(root,{})!={'state':'ready','phase':'verified','proof':'terminal-success',**observer._FLAGS}:raise _Blocked('proof')
    source=_snapshot_script()
    if not _parse(root,descriptor,closed,source):raise _Blocked('parser')
    snapshots=[]
    for _ in range(2):
        value=_run(root,descriptor,closed,source)
        if isinstance(value,dict) and set(value)=={'state','phase'} and value['state']=='probe-failed' and value['phase'] in _PROBE_PHASES:raise _Blocked('snapshot-'+value['phase'])
        if isinstance(value,dict) and set(value)=={'state','guard'} and value['state']=='snapshot-failed' and value['guard'] in _GUARDS:raise _Blocked('snapshot-guard-'+value['guard'].lower().replace('_','-'))
        if not isinstance(value,dict) or set(value)!={'archive'}:raise _Blocked('snapshot-archive-shape')
        a=value['archive']
        if not isinstance(a,dict):raise _Blocked('snapshot-archive-shape')
        proof_phase=observer._validate(a.get('proof'),record)
        if proof_phase in _PROOF_PHASES:raise _Blocked('snapshot-'+proof_phase)
        if (type(a.get('xmlLength')) is int and not 1<=a['xmlLength']<=131072) or (isinstance(a.get('xmlGzip'),str) and len(a['xmlGzip'])>15000) or len(json.dumps(a,separators=(',',':')).encode())>16384:raise _Blocked('snapshot-archive-bounds')
        try:snapshots.append(_archive(a,record))
        except (OSError,ValueError,KeyError,TypeError,EOFError,ET.ParseError) as error:raise _Blocked('snapshot-'+_archive_phase(error))
    if snapshots[0]!=snapshots[1]:raise _Blocked('snapshot')
    binding=_binding(snapshots[0]);plan,intent=_plan(binding)
    if not _parse(root,descriptor,closed,plan) or not _parse(root,descriptor,closed,_reader()):raise _Blocked('parser')
    if base._descriptor(root)[2]!=descriptor or observer._admit(root,descriptor)!=(record,closed):raise _Blocked('generation')
    return descriptor,record,closed,plan,intent


def _status_locked(root:Path) -> dict[str,Any]:
    local=_read(root/_DIR/'intent.json')
    if local is None:return _result('not-started','intent')
    descriptor=base._descriptor(root)[2]
    if descriptor!=observer._GENERATION:return _result('unknown','generation')
    record,closed=observer._admit(root,descriptor)
    if set(local)!={'binding','bindingSha256','actionSha256'} or not isinstance(local['binding'],dict):return _result('unknown','intent')
    binding=local['binding']
    if set(binding)!={'retirementCorrelationId','task','environment','socketPath','qemuPid','startTicks','sid','sourceSha','leaseId','historicalRecordDigests','snapshot'} or binding!=_binding(binding.get('snapshot')) or not isinstance(binding['snapshot'],dict):return _result('unknown','intent')
    _source,expected=_plan(binding)
    if local!=expected:return _result('unknown','intent')
    if not _parse(root,descriptor,closed,_reader()):return _result('unknown','parser')
    value=_run(root,descriptor,closed,_reader())
    if not isinstance(value,dict) or set(value)!={'binding','archive','terminal','absent'} or value['binding']!=local:return _result('unknown','journal')
    if value['absent'] is not True:return _result('unknown','absence')
    snapshot=_archive(value['archive'],record,local['bindingSha256'])
    terminal={'retirementCorrelationId':_RETIREMENT,'state':'retired','bindingSha256':local['bindingSha256'],'actionSha256':local['actionSha256']}
    if snapshot!=binding['snapshot'] or value['terminal']!=terminal:return _result('unknown','terminal')
    if base._descriptor(root)[2]!=descriptor or observer._admit(root,descriptor)!=(record,closed):return _result('unknown','generation')
    return _result('retired','complete')


def workflow(root:Path|str,action:str,inputs:Mapping[str,Any]) -> dict[str,Any]:
    if not isinstance(inputs,Mapping) or dict(inputs)!={} or action not in {'preflight','start','status'}:
        raise ValueError('Fixed e848 retirement takes preflight/start/status and no inputs.')
    if not observer.history._supported() or base is None or transport is None:return _result('blocked','platform')
    try:
        path=Path(root).resolve(strict=True)
        with observer.history._history_lock(path):
            if os.path.lexists(path/base.campaign_lease._DIR/'active.json'):return _result('blocked','active-lease')
            if action=='status' or os.path.lexists(path/_DIR/'intent.json'):return _status_locked(path)
            admitted=_admit(path)
            if admitted is None:return _result('blocked','proof')
            descriptor,record,closed,source,intent=admitted
            if action=='preflight':return _result('ready','proof')
            if base._descriptor(path)[2]!=descriptor or observer._admit(path,descriptor)!=(record,closed):return _result('blocked','generation')
            # Local create-only intent wins concurrent starts; loser cannot dispatch.
            directory=path/_DIR
            if not directory.exists():
                os.mkdir(directory,0o700)
                fd=os.open(directory.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(fd)
                finally:os.close(fd)
            observer.history._directory(directory)
            guards.secure_write_create(directory/'intent.json',intent)
            # Recheck after reservation; any uncertainty consumes the one-shot.
            if observer._admit(path,descriptor)!=(record,closed):return _result('unknown','generation')
            _run(path,descriptor,closed,source)
            return _status_locked(path)
    except _Blocked as error:
        return _result('blocked',error.phase)
    except (OSError,ValueError,TypeError,KeyError,IndexError,EOFError,ET.ParseError):
        return _result('unknown','journal')


def preflight(root:Path|str,inputs:Mapping[str,Any]) -> dict[str,Any]:return workflow(root,'preflight',inputs)
def start(root:Path|str,inputs:Mapping[str,Any]) -> dict[str,Any]:return workflow(root,'start',inputs)
def status(root:Path|str,inputs:Mapping[str,Any]) -> dict[str,Any]:return workflow(root,'status',inputs)
