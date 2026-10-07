"""One terminal-only metadata attempt for the consumed CP117 absence closure.

The original unknown binding-dispatch outcome stays unknown. This separately
journaled action can only complete the existing, freshly validated binding.
"""
from __future__ import annotations
import base64
from contextlib import contextmanager
from collections.abc import Mapping
from unittest import mock
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid
from . import windows_cp117_static_tasks_absence_close as closure
from .windows_diagnostic_authority_capture import AuthorityCapture

_COMPLETION='ff75a4c1-6479-41d8-9e2f-6ab58a18f8f2'
_DIR='.rag_index/windows-cp117-bound-absence-completion'
_EVIDENCE='windows-bound-absence-completion-'+_COMPLETION
_CONSUMED='4f95612760bd8b512f0fc35a61d6d4513dde5a6f7897ae31d963b046159e1739'
_CLOSURE_SOURCE='3a7870b6bbca40db99794a40509103d8a3bff802f71b64d333262c57384bc083'
_BASE_SOURCE='da3862602d906cb6146ce351fb2c3ee8697e82506f4253e39085263aecf3c9d3'
_CAPTURE_SOURCE='8101d9665a3beb8ed8771f36baa058d2f137ca68db3750ea9c9ecfdb52e9503a'


def _digest(raw):return hashlib.sha256(raw).hexdigest()


def _final_only(binding,expected,proof,intent):
    _, final, calculated=closure._scripts(binding,expected,proof)
    if calculated!=intent:raise ValueError('consumed-intent-drift')
    return final


def _admit_census(value,previous=None):
    if (not isinstance(value,dict) or set(value)!={'version','correlationId','root','unknownEntry','binding','terminal'}
            or type(value['version'])is not int or value['version']!=1 or value['correlationId']!=closure._CLOSE
            or value['root']!='present-valid' or value['unknownEntry']is not False or value['terminal']!={'state':'absent'}):
        raise ValueError('current-journal')
    binding=value['binding']
    if (not isinstance(binding,dict) or set(binding)!={'state','sha256','generation'} or binding['state']!='present-valid'
            or not isinstance(binding['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',binding['sha256'])):
        raise ValueError('current-binding')
    g=binding['generation']
    if (not isinstance(g,dict) or set(g)!={'bytes','creationTicks','writeTicks','attributes','owner','aclSha256'}
            or any(type(g[k])is not int or g[k]<0 for k in ('bytes','creationTicks','writeTicks','attributes'))
            or not 0<g['bytes']<=16384 or g['owner']not in ('S-1-5-18','S-1-5-32-544')
            or not isinstance(g['aclSha256'],str) or not re.fullmatch('[0-9a-f]{64}',g['aclSha256'])):
        raise ValueError('binding-generation')
    if previous is not None and binding!=previous:raise ValueError('binding-drift')
    return binding


def _bound_census(value,binding,nonce,source_sha):
    if binding!={'nonce':nonce,'sourceSha256':source_sha}:raise ValueError('census-execution-binding')
    return _admit_census(value)


def _consume_attempt(create,intent,dispatch,guard=lambda:None):
    # Fence BEFORE the dispatch; exceptions and observation loss never reopen it.
    guard();create('attempt.json',intent);guard()
    return dispatch()


def _read_bound_file(path,private=False,retain_bytes=False):
    path=Path(path).absolute()
    parents=[]
    for parent in path.parents:
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode):raise ValueError('source-ancestry')
        parents.append((parent,(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)))
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        fp=lambda v:[v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns]
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1
                or not 0<before.st_size<=1048576 or (private and stat.S_IMODE(before.st_mode)!=0o600)):
            raise ValueError('source-record')
        raw=bytearray()
        while len(raw)<=before.st_size:
            block=os.read(fd,min(65536,before.st_size+1-len(raw)))
            if not block:break
            raw.extend(block)
        if len(raw)!=before.st_size or fp(os.fstat(fd))!=fp(before) or fp(path.lstat())!=fp(before):raise ValueError('source-generation')
        for parent,identity in parents:
            now=parent.lstat()
            if (now.st_dev,now.st_ino,now.st_mode,now.st_uid,now.st_gid)!=identity:raise ValueError('source-ancestry')
        if fp(os.fstat(fd))!=fp(before) or fp(path.lstat())!=fp(before):raise ValueError('source-generation')
        pin={'sha256':_digest(raw),'generation':fp(before)}
        return (pin,bytes(raw)) if retain_bytes else pin
    finally:os.close(fd)


def _source_pins(root):
    pins={'completion':_read_bound_file(Path(__file__)),
          'closure':_read_bound_file(Path(closure.__file__)),
          'base':_read_bound_file(Path(closure.base.__file__)),
          'consumedIntent':_read_bound_file(root/closure._DIR/'intent.json',private=True),
          'capture':_read_bound_file(root/'agent_tools/windows_diagnostic_authority_capture.py')}
    if pins['base']['sha256']!=_BASE_SOURCE or pins['closure']['sha256']!=_CLOSURE_SOURCE or pins['consumedIntent']['sha256']!=_CONSUMED or pins['capture']['sha256']!=_CAPTURE_SOURCE:
        raise ValueError('source-authority')
    return pins


def _terminal(intent):
    return {'closureCorrelationId':closure._CLOSE,'originalRetirementCorrelationId':closure.original._RETIREMENT,
            'bindingSha256':intent['bindingSha256'],'actionSha256':intent['actionSha256'],
            'state':'closed','proof':'current-absence','originalOutcome':'unknown'}


def _readonly_journal():
    own=closure.original.journal.powershell(closure._ROOT,closure._LEAVES)
    start=own.index('function Initialize-SecureJournal ');end=own.index('function Read-SecureJson(',start)
    own=own[:start]+own[end:];own=own[:own.index('function Write-SecureJsonCreate(')]
    child="foreach($child in @(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop)){[void](Assert-LeafItem $child $child.Name)};"
    if own.count(child)!=1:raise ValueError('journal-source')
    return own.replace(child,'',1)


def _census_source(expected,proof,intent):
    wanted=json.dumps({'binding':intent,'terminal':_terminal(intent)},sort_keys=True,separators=(',',':')).replace("'","''")
    body=(closure._original_guard(expected,proof)+_readonly_journal()+
          "\n$wanted=ConvertFrom-Json '"+wanted+"'\n"+_CENSUS)
    return closure.original._guest(body,closure._PHASES)


def _effect_source(final,intent,pin):
    # Prefix admits the exact census binding generation/bytes hash. The original
    # final-only script remains verbatim, including protected CreateNew and Idle.
    literal=json.dumps(pin,sort_keys=True,separators=(',',':')).replace("'","''")
    wanted=json.dumps(intent,sort_keys=True,separators=(',',':')).replace("'","''")
    return ("$ErrorActionPreference='Stop';\n"+"function Hash([byte[]]$bytes){$h=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($h.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}\n"+closure._EQUAL+_readonly_journal()+
            "\n$wanted=ConvertFrom-Json '"+wanted+"';$required=ConvertFrom-Json '"+literal+"'\n"+
            _CENSUS_LEAF+"\n$current=CensusLeaf 'binding.json' $wanted\n"+
            "if(-not (EqualJson ($current|ConvertTo-Json -Depth 8 -Compress|ConvertFrom-Json) $required) -or (Test-Path -LiteralPath (Join-Path $JournalRoot 'terminal.json'))){throw 'binding-generation'}\n"+final)

_CENSUS_LEAF="function LeafGeneration($item) {\n $acl=Get-Acl -LiteralPath $item.FullName -ErrorAction Stop\n return [ordered]@{bytes=[long]$item.Length;creationTicks=$item.CreationTimeUtc.Ticks;writeTicks=$item.LastWriteTimeUtc.Ticks;attributes=[int]$item.Attributes;owner=([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value;aclSha256=(Hash ([Text.Encoding]::UTF8.GetBytes((@(AclRows $item.FullName)|ConvertTo-Json -Depth 6 -Compress))))}\n}\nfunction CensusLeaf([string]$name,$wantedValue) {\n $path=Join-Path $JournalRoot $name\n if(-not (Test-Path -LiteralPath $path)){return @{state='absent'}}\n $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop\n if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){return @{state='invalid-type'}}\n try {\n  $before=LeafGeneration (Assert-Leaf $name)\n  $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)\n  try {\n   if($stream.Length -ne $before.bytes -or $stream.Length -lt 1 -or $stream.Length -gt $MaxBytes){throw 'HANDLE_SIZE'}\n   $bytes=New-Object byte[] ([int]$stream.Length);$offset=0\n   while($offset -lt $bytes.Length){$count=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($count -le 0){throw 'HANDLE_READ'};$offset+=$count}\n   $after=LeafGeneration (Assert-Leaf $name)\n   if(-not (EqualJson ($before|ConvertTo-Json -Compress|ConvertFrom-Json) ($after|ConvertTo-Json -Compress|ConvertFrom-Json))){throw 'HANDLE_CHANGED'}\n  }finally{$stream.Dispose()}\n  $digest=Hash $bytes\n  try {$text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes);if($text.Length -eq 0 -or [int]$text[0] -eq 65279){throw 'JSON'};$value=$text|ConvertFrom-Json -ErrorAction Stop}\n  catch{return @{state='invalid-json';generation=$after;sha256=$digest}}\n  if(-not (EqualJson $value $wantedValue)){return @{state='invalid-schema';generation=$after;sha256=$digest}}\n  return @{state='present-valid';generation=$after;sha256=$digest}\n }catch{return @{state='invalid-protected-read'}}\n}"
_CENSUS="function LeafGeneration($item) {\n $acl=Get-Acl -LiteralPath $item.FullName -ErrorAction Stop\n return [ordered]@{bytes=[long]$item.Length;creationTicks=$item.CreationTimeUtc.Ticks;writeTicks=$item.LastWriteTimeUtc.Ticks;attributes=[int]$item.Attributes;owner=([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value;aclSha256=(Hash ([Text.Encoding]::UTF8.GetBytes((@(AclRows $item.FullName)|ConvertTo-Json -Depth 6 -Compress))))}\n}\nfunction CensusLeaf([string]$name,$wantedValue) {\n $path=Join-Path $JournalRoot $name\n if(-not (Test-Path -LiteralPath $path)){return @{state='absent'}}\n $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop\n if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){return @{state='invalid-type'}}\n try {\n  $before=LeafGeneration (Assert-Leaf $name)\n  $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)\n  try {\n   if($stream.Length -ne $before.bytes -or $stream.Length -lt 1 -or $stream.Length -gt $MaxBytes){throw 'HANDLE_SIZE'}\n   $bytes=New-Object byte[] ([int]$stream.Length);$offset=0\n   while($offset -lt $bytes.Length){$count=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($count -le 0){throw 'HANDLE_READ'};$offset+=$count}\n   $after=LeafGeneration (Assert-Leaf $name)\n   if(-not (EqualJson ($before|ConvertTo-Json -Compress|ConvertFrom-Json) ($after|ConvertTo-Json -Compress|ConvertFrom-Json))){throw 'HANDLE_CHANGED'}\n  }finally{$stream.Dispose()}\n  $digest=Hash $bytes\n  try {$text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes);if($text.Length -eq 0 -or [int]$text[0] -eq 65279){throw 'JSON'};$value=$text|ConvertFrom-Json -ErrorAction Stop}\n  catch{return @{state='invalid-json';generation=$after;sha256=$digest}}\n  if(-not (EqualJson $value $wantedValue)){return @{state='invalid-schema';generation=$after;sha256=$digest}}\n  return @{state='present-valid';generation=$after;sha256=$digest}\n }catch{return @{state='invalid-protected-read'}}\n}\nIdle\n$result=@{version=1;correlationId='8a3e6cf1-0cf8-4873-aade-bc07c42a4f30';root='unknown';unknownEntry=$false;binding=@{state='unknown'};terminal=@{state='unknown'}}\nif(-not (Test-Path -LiteralPath $JournalRoot)){\n Assert-Ancestors (Split-Path -Parent $JournalRoot);$result.root='absent';$result.binding=@{state='absent'};$result.terminal=@{state='absent'}\n}else{\n $item=Get-Item -LiteralPath $JournalRoot -Force -ErrorAction Stop\n if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){$result.root='invalid-type'}\n else{\n  try{\n   [void](Assert-Root $JournalRoot);$result.root='present-valid'\n   $names=@(Get-ChildItem -LiteralPath $JournalRoot -Force -ErrorAction Stop|ForEach-Object {$_.Name})\n   $result.unknownEntry=(@($names|Where-Object {$_ -cnotin @('binding.json','terminal.json')}).Count -ne 0)\n   $result.binding=CensusLeaf 'binding.json' $wanted.binding\n   $result.terminal=CensusLeaf 'terminal.json' $wanted.terminal\n   [void](Assert-Root $JournalRoot)\n   $afterNames=@(Get-ChildItem -LiteralPath $JournalRoot -Force -ErrorAction Stop|ForEach-Object {$_.Name}|Sort-Object)\n   $beforeNames=@($names|Sort-Object)\n   if(($afterNames -join '|') -cne ($beforeNames -join '|')){throw 'CENSUS_CHANGED'}\n  }catch{$result.root='invalid-protected-read';$result.binding=@{state='unknown'};$result.terminal=@{state='unknown'}}\n }\n}\nIdle\n[Console]::Out.WriteLine(($result|ConvertTo-Json -Depth 8 -Compress))\n"
_ANCHOR='"""Private create-only host receipt for the single fixed read-only census."""\nimport os,json,stat,hashlib\nclass Anchor:\n def __init__(self,parent,request,create=False,trusted_pins=None):\n  self.parent=parent;self.request=request;self.parent_fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)\n  self.parent_info=os.fstat(self.parent_fd);self.private_dir(self.parent_info)\n  self.name=\'windows-bound-absence-\'+request[\'role\']+\'-\'+request[\'nonce\']\n  if create:os.mkdir(self.name,0o700,dir_fd=self.parent_fd);os.fsync(self.parent_fd)\n  self.fd=os.open(self.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self.parent_fd)\n  self.info=os.fstat(self.fd);self.private_dir(self.info);self.check_dirs()\n  self.trusted=create or trusted_pins is not None\n  self.pins=json.loads(json.dumps(trusted_pins)) if trusted_pins is not None else {}\n  if trusted_pins is not None and set(self.pins)!={\'request.json\',\'child.json\',\'seal.json\',\'authority.json\'}:raise ValueError(\'external-authority-shape\')\n  if create:self.create(\'request.json\',request)\n  else:\n   value,pin=self.read(\'request.json\')\n   if value!=request:raise ValueError(\'request-binding\')\n   if trusted_pins is not None and self.pins[\'request.json\']!=pin:raise ValueError(\'external-request-generation\')\n   self.pins[\'request.json\']=pin\n def fp(self,i):return [i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid,i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns]\n def private_dir(self,i):\n  if not stat.S_ISDIR(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700:raise ValueError(\'directory-private\')\n def check_dirs(self):\n  for current,expected in ((os.fstat(self.parent_fd),self.parent_info),(os.stat(self.parent,follow_symlinks=False),self.parent_info),(os.fstat(self.fd),self.info),(os.stat(self.name,dir_fd=self.parent_fd,follow_symlinks=False),self.info)):\n   self.private_dir(current)\n   if (current.st_dev,current.st_ino)!=(expected.st_dev,expected.st_ino):raise ValueError(\'directory-generation\')\n def read(self,name):\n  if name not in {\'request.json\',\'child.json\',\'seal.json\',\'authority.json\'}:raise ValueError(\'fixed-leaf\')\n  self.check_dirs();f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.fd)\n  try:\n   before=os.fstat(f)\n   if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or not 0<before.st_size<=8192:raise ValueError(\'record-private\')\n   raw=os.read(f,8193);after=os.fstat(f);named=os.stat(name,dir_fd=self.fd,follow_symlinks=False)\n   if len(raw)!=before.st_size or self.fp(after)!=self.fp(before) or self.fp(named)!=self.fp(before):raise ValueError(\'record-generation\')\n   value=json.loads(raw);pin={\'sha256\':hashlib.sha256(raw).hexdigest(),\'generation\':self.fp(before)}\n   self.check_dirs();return value,pin\n  finally:os.close(f)\n def create(self,name,value):\n  self.check_dirs();f=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd)\n  try:\n   raw=json.dumps(value,sort_keys=True,separators=(\',\',\':\')).encode();assert 0<len(raw)<=8192\n   offset=0\n   while offset<len(raw):offset+=os.write(f,raw[offset:])\n   os.fsync(f)\n  finally:os.close(f)\n  os.fsync(self.fd);read,pin=self.read(name)\n  if read!=value:raise ValueError(\'create-binding\')\n  self.pins[name]=pin;return pin\n def bind_child(self,pid):\n  if type(pid)is not int or pid<=0:raise ValueError(\'child-shape\')\n  self.verify_request()\n  child={\'requestSha256\':self.pins[\'request.json\'][\'sha256\'],\'pid\':pid,**self.request}\n  cp=self.create(\'child.json\',child)\n  sp=self.create(\'seal.json\',{\'request\':self.pins[\'request.json\'],\'child\':cp})\n  self.create(\'authority.json\',{\'request\':self.pins[\'request.json\'],\'seal\':sp})\n  self.child=child;self.verify_child();return child\n def verify_request(self):\n  value,pin=self.read(\'request.json\')\n  if value!=self.request or pin!=self.pins[\'request.json\']:raise ValueError(\'request-generation\')\n def verify_child(self):\n  if not self.trusted:raise ValueError(\'external-original-authority-required\')\n  return self._candidate()\n def observe_unverified(self):\n  if self.trusted:raise ValueError(\'unverified-observation-only\')\n  child=self._candidate()\n  return {\'classification\':\'unverified\',\'child\':child,\'pins\':self.pins}\n def _candidate(self):\n  self.verify_request();child,cp=self.read(\'child.json\');seal,sp=self.read(\'seal.json\');authority,ap=self.read(\'authority.json\')\n  if seal!={\'request\':self.pins[\'request.json\'],\'child\':cp} or authority!={\'request\':self.pins[\'request.json\'],\'seal\':sp}:raise ValueError(\'sealed-generation\')\n  if set(child)!=set(self.request)|{\'requestSha256\',\'pid\'} or {k:child[k]for k in self.request}!=self.request or child[\'requestSha256\']!=self.pins[\'request.json\'][\'sha256\'] or type(child[\'pid\'])is not int or child[\'pid\']<=0:raise ValueError(\'child-binding\')\n  if self.pins:\n   for name,pin in [(\'child.json\',cp),(\'seal.json\',sp),(\'authority.json\',ap)]:\n    if name in self.pins and self.pins[name]!=pin:raise ValueError(\'local-generation\')\n    self.pins[name]=pin\n  self.child=child\n  for name,pin in self.pins.items():\n   if self.fp(os.stat(name,dir_fd=self.fd,follow_symlinks=False))!=pin[\'generation\']:raise ValueError(\'final-record-generation\')\n  self.check_dirs();return child\n def status(self,delegate,sock):\n  child=self.verify_child();result=delegate(sock,\'guest-exec-status\',{\'pid\':child[\'pid\']});self.verify_child();return result\n def close(self):os.close(self.fd);os.close(self.parent_fd)\n'

_METADATA_CALL=r'''
metadata_delegate=call
metadata_anchor=None
metadata_submitted=False
def metadata_call(sock,operation,args):
 global metadata_anchor,metadata_submitted
 if sock!=metadata_request['generation'][1]:raise ValueError('socket-binding')
 if operation=='guest-exec':
  if metadata_submitted or args!={'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-Command',metadata_command],'capture-output':True}:raise ValueError('fixed-execution')
  metadata_submitted=True
  metadata_anchor=Anchor(sys.argv[1],metadata_request,create=True)
  value=metadata_delegate(sock,operation,args)
  if not isinstance(value,dict) or set(value)!={'pid'}:raise ValueError('child-shape')
  child=metadata_anchor.bind_child(value['pid'])
  print('METADATA-ANCHOR '+json.dumps({'child':child,'pins':metadata_anchor.pins,'hostRoot':sys.argv[1]},sort_keys=True,separators=(',',':')),file=sys.stderr,flush=True)
  return value
 if operation!='guest-exec-status' or metadata_anchor is None:raise ValueError('status-only')
 child=metadata_anchor.verify_child()
 if args!={'pid':child['pid']}:raise ValueError('fixed-child')
 return metadata_anchor.status(metadata_delegate,sock)
call=metadata_call
'''


def _program(source,request):
    command=closure.wire._command(source)
    if not 0<len(command)<30000:raise ValueError('command-cap')
    sha=_digest(source.encode('utf-16le'))
    if request['sourceSha256']!=sha:raise ValueError('program-source')
    nonce=request['nonce']
    program=closure._fresh_program(closure.original._REMOTE,'-Command',command,sha,nonce,30000)
    submitted="[Console]::Out.WriteLine('VPNCONTROL-READ "+nonce+' '+sha+" '+$PID);\n"+command
    setup='\n'+_ANCHOR+'\nmetadata_request='+repr(request)+'\nmetadata_command='+repr(submitted)+_METADATA_CALL
    needle='call=_fresh_call(call,'
    if program.count(needle)!=1:raise ValueError('remote-source')
    return program.replace(needle,setup+'\n'+needle,1),command


def _stream(argv,receive,retain_failure=None):
    """Bounded original-frame capture; kill only the owned client on failure."""
    import selectors
    subprocess=closure.base.subprocess
    process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    selector=selectors.DefaultSelector()
    selector.register(process.stdout,selectors.EVENT_READ,'stdout')
    selector.register(process.stderr,selectors.EVENT_READ,'stderr')
    chunks={'stdout':bytearray(),'stderr':bytearray()};pending=bytearray();deadline=time.monotonic()+90
    try:
        while selector.get_map():
            remaining=deadline-time.monotonic()
            if remaining<=0:raise subprocess.TimeoutExpired(argv,90,output=bytes(chunks['stdout']),stderr=bytes(chunks['stderr']))
            for key,_ in selector.select(min(remaining,.25)):
                data=os.read(key.fileobj.fileno(),4096)
                if not data:selector.unregister(key.fileobj);continue
                chunks[key.data].extend(data)
                if len(chunks[key.data])>(1048576 if key.data=='stdout' else 65536):raise ValueError('stream-bound')
                if key.data=='stderr':
                    pending.extend(data)
                    while b'\n' in pending:
                        line,remainder=pending.split(b'\n',1);pending=bytearray(remainder)
                        if line.startswith(b'METADATA-ANCHOR '):receive(bytes(line))
        code=process.wait(timeout=max(.001,deadline-time.monotonic()))
        return subprocess.CompletedProcess(argv,code,bytes(chunks['stdout']),bytes(chunks['stderr']))
    except BaseException:
        if retain_failure is not None:
            try:retain_failure(bytes(chunks['stdout'][:1048576]),bytes(chunks['stderr'][:65536]))
            except Exception:pass
        process.kill();process.wait(timeout=3);raise
    finally:
        selector.close();process.stdout.close();process.stderr.close()


def _capture_frame(capture,role,request,target,line,anchors):
    receipt=json.loads(line.split(b' ',1)[1]);child=receipt['child']
    request_sha=_digest(json.dumps(request,sort_keys=True,separators=(',',':')).encode())
    if (set(receipt)!={'child','pins','hostRoot'} or set(child)!=set(request)|{'requestSha256','pid'}
            or {k:child[k]for k in request}!=request or child['requestSha256']!=request_sha
            or type(child['pid'])is not int or child['pid']<=0 or receipt['hostRoot']!=str(target.fixture_transfer_root)
            or set(receipt['pins'])!={'request.json','child.json','seal.json','authority.json'} or anchors):
        raise ValueError('original-live-frame')
    pin=capture.create(role+'-child.json',json.dumps(receipt,sort_keys=True).encode())
    capture.create(role+'-authority.json',json.dumps({'classification':'original-live-authority','anchor':pin,'requestSha256':request_sha},sort_keys=True).encode())
    anchors.append(receipt)


def _catalog(context,role,pin=None):
    if role=='census':return _census_source(context['expected'],context['proof'],context['intent'])
    if role=='final' and pin is not None:return _effect_source(context['final'],context['intent'],pin)
    if role=='status':return closure._reader(context['expected'],context['proof'])
    raise ValueError('fixed-role')


def _run_bound(root,context,role,capture,pin=None):
    from . import ssh_connection_session as connection
    source=_catalog(context,role,pin)
    config,target,generation=closure.base._descriptor(root)
    if generation!=context['descriptor'] or _source_pins(root)!=context['sources']:raise ValueError('generation')
    nonce=context['finalNonce'] if role=='final' else str(uuid.uuid4())
    request={'version':1,'completionCorrelationId':_COMPLETION,'closureCorrelationId':closure._CLOSE,
             'role':role,'nonce':nonce,'sourceSha256':_digest(source.encode('utf-16le')),
             'generation':list(generation),'consumedIntentSha256':_CONSUMED,'sources':context['sources'],'outerAuthority':context['outerAuthority']}
    program,command=_program(source,request)
    capture.create(role+'-request.json',json.dumps(request,sort_keys=True,separators=(',',':')).encode())
    capture.create(role+'-remote.py',program.encode())
    _verify_outer(root,context)
    argv=closure.base.ssh_transport.build_ssh_argv(config,'archlinux',60,command=closure.base.windows_credential_probe_ssh._remote_command(program,str(target.fixture_transfer_root),*closure.wire.observer._remote_arguments(generation,context['closed']),command))
    anchors=[];real_run=closure.base.subprocess.run;used=False
    def delegate(actual,**kwargs):
        nonlocal used
        expected={'stdin':closure.base.subprocess.DEVNULL,'stdout':closure.base.subprocess.PIPE,'stderr':closure.base.subprocess.PIPE,'timeout':90,'check':False}
        if kwargs!=expected:return real_run(actual,**kwargs)
        if actual!=argv or used:raise ValueError('one-fixed-dispatch')
        used=True
        if role=='final':
            if not callable(context.get('dispatchGuard')):raise ValueError('final-guard-required')
            context['dispatchGuard']()
        def retain_failure(stdout,stderr):
            capture.create(role+'-partial.stdout.private',stdout)
            capture.create(role+'-partial.stderr.private',stderr)
        return _stream(actual,lambda line:_capture_frame(capture,role,request,target,line,anchors),retain_failure)
    def observe(args,kwargs,result):
        expected={'stdin':closure.base.subprocess.DEVNULL,'stdout':closure.base.subprocess.PIPE,'stderr':closure.base.subprocess.PIPE,'timeout':90,'check':False}
        if args!=(argv,) or kwargs!=expected:return
        capture.create(role+'-stdout.private',result.stdout)
        capture.create(role+'-stderr.private',result.stderr)
    from unittest import mock
    # Only the exact guarded remote call can reach the one-submit delegate.
    with mock.patch.object(closure.base.subprocess,'run',closure._static_trace_delegate(delegate,observe)):
        raw=closure.base._remote(config,program,(str(target.fixture_transfer_root),*closure.wire.observer._remote_arguments(generation,context['closed']),command),None,90)
    capture.create(role+'-receipt.private',raw or b'null')
    _verify_outer(root,context)
    if _source_pins(root)!=context['sources']:raise ValueError('post-authority')
    if len(anchors)!=1 or raw is None:raise ValueError('unknown-observation')
    value=json.loads(raw,object_pairs_hook=closure.history._unique)
    if not isinstance(value,dict) or set(value)!={'state','receipt'} or value['state']!='observed':raise ValueError('execution-unknown')
    return value['receipt']


def _outer_authority(root):
    """Read only the current prepared session; no prepare, fallback or adoption."""
    from . import ssh_connection_session as connection
    journal=connection._journal(root,'archlinux',False)
    path=journal/'ready.json'
    pin,raw=_read_bound_file(path,private=True,retain_bytes=True)
    proof=json.loads(raw,object_pairs_hook=closure.history._unique)
    if not isinstance(proof,dict):raise ValueError('outer-authority')
    # The shared session's receipt hashes its protected ready file pin. Our
    # pin additionally retains gid; preserve its exact original fingerprint.
    generation=pin['generation']
    session_pin={'sha256':pin['sha256'],'fingerprint':generation[:4]+generation[5:]}
    receipt=connection._sha(connection._json(session_pin))
    if not connection.verify_reuse(root,'archlinux',receipt):raise ValueError('outer-authority')
    if connection._journal(root,'archlinux',False)!=journal or _read_bound_file(path,private=True,retain_bytes=True)!=(pin,raw):
        raise ValueError('outer-generation')
    return {'receiptSha256':receipt,'readyPin':pin,'proof':proof}


def _verify_outer(root,context):
    if _outer_authority(root)!=context['outerAuthority']:raise ValueError('outer-generation')


def _context(root):
    sources=_source_pins(root)
    outer=_outer_authority(root)
    descriptor,closed,expected,proof=closure._proof(root)
    intent=closure._read_private(root/closure._DIR/'intent.json')
    binding=closure._binding(descriptor,proof)
    final=_final_only(binding,expected,proof,intent)
    if _source_pins(root)!=sources:raise ValueError('source-drift')
    if _outer_authority(root)!=outer:raise ValueError('outer-generation')
    return {'sources':sources,'outerAuthority':outer,'descriptor':descriptor,'closed':closed,'expected':expected,'proof':proof,'intent':intent,'final':final}


@contextmanager
def _bounded_locks():
    """Same admission locks, with finite busy refusal before any effects.

    This scope runs only in the standalone operator process; it does not change
    shared lock implementation or permit upgrading a held history lock.
    """
    import fcntl
    original=fcntl.flock
    def finite(fd,operation):
        return original(fd,operation if operation==fcntl.LOCK_UN else operation|fcntl.LOCK_NB)
    with mock.patch.object(fcntl,'flock',finite):
        yield


def _readonly_unknown_archive(root,config,target,descriptor,correlation=None):
    """Frozen original archive predicates using the validated history SH token."""
    base=closure.base
    # Optional historical support is read-only: absent support refuses before touching root.
    if base is None:
        return False
    if correlation is None:
        correlation=base._UNKNOWN_CLOSURE_CORRELATION
    try:
        profile = base._unknown_recovery_profile(correlation)
        if profile is None:
            return False
        request, command_hash = profile
        intent = base._private_intent(root, correlation)
        if (intent is None or intent.get("request") != request
                or intent.get("commandSha256") != command_hash
                or intent.get("leaseId") != correlation
                or not isinstance(intent.get("pair"), Mapping)
                or intent["pair"].get("sourceSha") != request["sourceSha"]
                or not isinstance(intent["pair"].get("sourceFingerprint"), str)
                or base._HASH.fullmatch(intent["pair"]["sourceFingerprint"]) is None
                or not base._unknown_marker_valid(root, intent, descriptor, correlation)):
            return False
        with closure.history._history_lock(root):
            directory = root / base.campaign_lease._DIR
            active = base.campaign_lease._active(directory)
            closed = base.campaign_lease._closed(directory, correlation)
        if active is not None or closed is None:
            return False
        if (closed.get("identity") != base._campaign_identity(request, descriptor)
                or closed.get("lastOutcome") != "unknown-cleaned"):
            return False
        first = base._unknown_cleanup_census(config, target, intent, descriptor, "status", correlation)
        second = base._unknown_cleanup_census(config, target, intent, descriptor, "status", correlation)
        if not (base._unknown_both_absent(first or {}) and base._unknown_both_absent(second or {})):
            return False
        evidence = {"afterFirst": first, "afterSecond": second,
                    "closeIntent": correlation}
        evidence_sha = hashlib.sha256(json.dumps(evidence, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        return closed.get("lastEvidenceSha256") == evidence_sha
    except (OSError, ValueError, TypeError, KeyError, base.campaign_lease.Cp117LeaseError):
        return False


def _guard(root,context):
    if _source_pins(root)!=context['sources']:raise ValueError('source-drift')
    closure._recheck(root,context['descriptor'],context['closed'],context['expected'],context['proof'])
    _verify_outer(root,context)
    config,target,descriptor=closure.base._descriptor(root)
    if descriptor!=context['descriptor']:raise ValueError('generation')
    with mock.patch.object(closure.base,'_unknown_closure_archived',_readonly_unknown_archive):
        closure.base._require_base_route_free(root,config,target,descriptor)
    _verify_outer(root,context)
    if _source_pins(root)!=context['sources']:raise ValueError('source-drift')

class _Journal:
    """Fixed local fence; no existing attempt can return to dispatch."""
    def __init__(self,root):
        import fcntl
        self.root=root;self.parent=root/'.rag_index';self.path=root/_DIR
        parent=self.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=os.getuid() or stat.S_IMODE(parent.st_mode)!=0o700:raise ValueError('journal-parent')
        self.parent_identity=self.identity(parent)
        self.parent_fd=os.open(self.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        if self.identity(os.fstat(self.parent_fd))!=self.parent_identity:raise ValueError('journal-parent')
        self.fd=None;self.lock=None;self.pins={}
        try:
            try:os.mkdir(self.path.name,0o700,dir_fd=self.parent_fd);os.fsync(self.parent_fd)
            except FileExistsError:pass
            self.fd=os.open(self.path.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self.parent_fd)
            self.directory=os.fstat(self.fd)
            if not stat.S_ISDIR(self.directory.st_mode) or self.directory.st_uid!=os.getuid() or stat.S_IMODE(self.directory.st_mode)!=0o700:raise ValueError('journal-directory')
            self.lock=os.open('lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=self.fd)
            self.lock_info=os.fstat(self.lock);self.file(self.lock_info)
            fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.check()
        except BaseException:self.close();raise
    @staticmethod
    def identity(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid)
    @staticmethod
    def fp(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
    @staticmethod
    def file(s):
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1:raise ValueError('journal-record')
    def check(self):
        if self.identity(self.parent.lstat())!=self.parent_identity or self.identity(os.fstat(self.parent_fd))!=self.parent_identity:raise ValueError('journal-parent-changed')
        if self.identity(os.fstat(self.fd))!=self.identity(self.directory) or self.identity(os.stat(self.path.name,dir_fd=self.parent_fd,follow_symlinks=False))!=self.identity(self.directory):raise ValueError('journal-directory-changed')
        for s in (os.fstat(self.lock),os.stat('lock',dir_fd=self.fd,follow_symlinks=False)):
            self.file(s)
            if self.fp(s)!=self.fp(self.lock_info):raise ValueError('journal-lock-changed')
        if set(os.listdir(self.fd))-{'lock','intent.json','attempt.json'}:raise ValueError('journal-inventory')
        for name,pin in self.pins.items():
            if self.fp(os.stat(name,dir_fd=self.fd,follow_symlinks=False))!=pin['generation']:raise ValueError('journal-record-changed')
    def exists(self,name):
        self.check()
        if name not in ('intent.json','attempt.json'):raise ValueError('journal-leaf')
        try:os.stat(name,dir_fd=self.fd,follow_symlinks=False);return True
        except FileNotFoundError:return False
    def read(self,name):
        self.check()
        if name not in ('intent.json','attempt.json'):raise ValueError('journal-leaf')
        fd=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=self.fd)
        try:
            before=os.fstat(fd);self.file(before)
            if not 0<before.st_size<=16384:raise ValueError('journal-size')
            raw=os.read(fd,16385)
            if len(raw)!=before.st_size or self.fp(os.fstat(fd))!=self.fp(before) or self.fp(os.stat(name,dir_fd=self.fd,follow_symlinks=False))!=self.fp(before):raise ValueError('journal-record-changed')
            pin={'sha256':_digest(raw),'generation':self.fp(before)}
            if name in self.pins and self.pins[name]!=pin:raise ValueError('journal-record-changed')
            self.pins[name]=pin;self.check()
            return json.loads(raw,object_pairs_hook=closure.history._unique)
        finally:os.close(fd)
    def create(self,name,value):
        self.check()
        if name not in ('intent.json','attempt.json'):raise ValueError('journal-leaf')
        raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
        if not 0<len(raw)<=16384:raise ValueError('journal-size')
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
        try:
            offset=0
            while offset<len(raw):
                count=os.write(fd,raw[offset:])
                if count<=0:raise ValueError('journal-write')
                offset+=count
            os.fsync(fd);s=os.fstat(fd);self.file(s)
            self.pins[name]={'sha256':_digest(raw),'generation':self.fp(s)}
        finally:os.close(fd)
        os.fsync(self.fd);self.check()
        if self.read(name)!=value:raise ValueError('journal-binding')
    def close(self):
        for name in ('lock','fd','parent_fd'):
            value=getattr(self,name,None)
            if value is not None:os.close(value);setattr(self,name,None)


def _new_capture(root):
    leaf=_EVIDENCE+'-'+uuid.uuid4().hex[:8]
    parent=root/'.runtime/parity-evidence'
    # The shared parent already exists; never chmod repository ancestors.
    os.mkdir(parent/leaf,0o700)
    return AuthorityCapture(root,leaf)


def workflow(root,action,inputs):
    if inputs!={} or action not in ('preflight','start','status'):raise ValueError('fixed terminal completion takes no inputs')
    root=Path(root).resolve(strict=True);capture=None;journal=None;consumed=False
    try:
        _source_pins(root)
        journal=_Journal(root)
        consumed=journal.exists('attempt.json')
        if consumed and action!='status':return {'state':'unknown','phase':'attempt-consumed','completionCorrelationId':_COMPLETION}
        with _bounded_locks(),closure.original._start_admission(root),closure.history._history_lock(root),closure._fresh_read_scope(root,'diagnose'):
            context=_context(root)
            capture=_new_capture(root)
            if action=='status':
                if not consumed:return {'state':'not-started','phase':'attempt','completionCorrelationId':_COMPLETION}
                stored=journal.read('intent.json');attempt=journal.read('attempt.json')
                if (stored['outerAuthority']!=context['outerAuthority'] or stored['sources']!=context['sources'] or stored['generation']!=list(context['descriptor'])
                        or stored['consumedIntentSha256']!=_CONSUMED or attempt['intentSha256']!=closure._digest(stored)):
                    raise ValueError('attempt-authority')
                value=_run_bound(root,context,'status',capture)
                if value!={'binding':context['intent'],'terminal':_terminal(context['intent'])}:raise ValueError('terminal-proof')
                _guard(root,context);journal.check()
                return {'state':'closed','phase':'terminal-proof','completionCorrelationId':_COMPLETION,'originalOutcome':'unknown'}
            pin=_admit_census(_run_bound(root,context,'census',capture))
            _guard(root,context);journal.check()
            if action=='preflight':return {'state':'ready','phase':'valid-binding-terminal-absent','completionCorrelationId':_COMPLETION}
            nonce=str(uuid.uuid4());context['finalNonce']=nonce
            source=_catalog(context,'final',pin)
            intent={'version':1,'completionCorrelationId':_COMPLETION,'closureCorrelationId':closure._CLOSE,
                    'sources':context['sources'],'outerAuthority':context['outerAuthority'],'generation':list(context['descriptor']),'consumedIntentSha256':_CONSUMED,
                    'bindingPin':pin,'finalSourceSha256':_digest(source.encode('utf-16le')),'nonce':nonce,
                    'originalFinalSourceSha256':_digest(context['final'].encode('utf-16le'))}
            if journal.exists('intent.json'):
                # A previous intent without an attempt is still a fixed fence;
                # no newly correlated request silently replaces it.
                raise ValueError('existing-intent')
            journal.create('intent.json',intent)
            def guard():
                _guard(root,context);journal.check()
                if journal.read('intent.json')!=intent:raise ValueError('intent-drift')
            context['dispatchGuard']=guard
            attempt={'version':1,'intentSha256':closure._digest(intent),'nonce':nonce,'sourceSha256':intent['finalSourceSha256'],'generation':intent['generation']}
            consumed=True
            value=_consume_attempt(journal.create,attempt,lambda:_run_bound(root,context,'final',capture,pin),guard)
            if value!={'closed':True}:raise ValueError('terminal-dispatch-unknown')
            # A fresh finite reader verifies actual protected terminal content.
            result=_run_bound(root,context,'status',capture)
            if result!={'binding':context['intent'],'terminal':_terminal(context['intent'])}:raise ValueError('terminal-proof')
            guard()
            return {'state':'closed','phase':'terminal-proof','completionCorrelationId':_COMPLETION,'originalOutcome':'unknown'}
    except Exception as error:
        phase=str(error)if isinstance(error,ValueError)else type(error).__name__
        if capture is not None:
            try:capture.create('failure.json',json.dumps({'kind':type(error).__name__,'phase':phase[:160]},sort_keys=True).encode())
            except Exception:pass
        public_phase=error.phase if isinstance(error,closure.Blocked) else ('guard-value' if isinstance(error,ValueError) else type(error).__name__)
        return {'state':'unknown'if consumed else'blocked','phase':public_phase,'completionCorrelationId':_COMPLETION}
    finally:
        if capture is not None:capture.close()
        if journal is not None:journal.close()


def preflight(root,inputs):return workflow(root,'preflight',inputs)
def start(root,inputs):return workflow(root,'start',inputs)
def status(root,inputs):return workflow(root,'status',inputs)
