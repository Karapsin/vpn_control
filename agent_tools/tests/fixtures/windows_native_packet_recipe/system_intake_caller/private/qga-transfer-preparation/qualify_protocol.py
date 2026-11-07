"""Local whole-namespace protocol peers; never a guest/SSH/submission driver."""
import argparse
import base64
import builtins
import collections
import contextlib
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
import traceback

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'inert-caller-qualification'))
from harness import PeerSocket,PeerWorld,literals

NATIVE_SDDL_RECEIPT=HERE/'native-source-sddl-causal-fixture/native-owner-probe-gates-receipt.json'
NATIVE_SDDL_BYTES=NATIVE_SDDL_RECEIPT.read_bytes()
assert hashlib.sha256(NATIVE_SDDL_BYTES).hexdigest()=='c75d1bd910bff604c2da68e4d8eff3617bfc1cf0a5f5e65f4eb28aae1ce526db'
NATIVE_SOURCE_SDDL=json.loads(NATIVE_SDDL_BYTES)['sddl']

LOCAL_ARTIFACTS={
 'msi':HERE.parent.parent/'artifacts/baseline/extracted/vpn-control-2.2.13.msi',
 'python':HERE.parent.parent/'artifacts/python31315/acquisition-87c1e7407cb24bd58f9493d825b23408/bytes/python-3.13.15-amd64.exe'}


def file_hash(path):
 h=hashlib.sha256()
 with open(path,'rb')as f:
  while data:=f.read(262144):h.update(data)
 return h.hexdigest()


class InertParkReached(RuntimeError):pass

class ProtocolSocket(PeerSocket):
 def send(self,data):
  # Bounded partial sends exercise same-frame backpressure before any UNKNOWN.
  self.tx=getattr(self,'tx',bytearray())
  if getattr(self,'fail_send_next',False):
   self.fail_send_next=False;self.world.unknown_wire_frames=self.world.sent_frames;raise TimeoutError('inert partial original send')
  count=min(len(data),8192)
  if self.world.fault=='partial-send-timeout'and not getattr(self.world,'partial_send_used',False)and b'guest-file-write'in bytes(self.tx)+data[:100]:
   count=min(17,len(data));self.fail_send_next=True;self.world.partial_send_used=True
  self.tx.extend(data[:count])
  if self.tx.endswith(b'\n'):
   frame=bytes(self.tx);self.tx.clear();command=json.loads(frame.lstrip(b'\xff'))['execute'];self.sendall(frame)
   if self.world.defer_command==command:
    self.timeout_once=True;self.world.defer_command=None
   if self.world.fault=='sync-timeout'and command=='guest-sync-delimited'and len(self.world.executions)==0 and sum(x['command']=='guest-sync-delimited'for x in self.world.rpc)>=4 and not getattr(self.world,'sync_fault_used',False):
    self.world.sync_fault_used=True;self.timeout_once=True
   if command=='guest-file-write'and self.world.write_count==1:
    if self.world.fault=='partial-response-timeout':self.partial_reply=7;self.timeout_after_partial=True
    if self.world.fault=='eof-after-write':self.buffer.clear();self.eof_forever=True
    if self.world.fault=='response-bound':self.buffer=bytearray(b'x'*(262144+8192))
  return count
 def recv(self,count):
  self.world.socket_recv_calls+=1
  if getattr(self,'eof_forever',False):self.world.unknown_wire_frames=self.world.sent_frames;return b''
  if getattr(self,'partial_reply',0):
   count=min(count,self.partial_reply);self.partial_reply=0;result=super().recv(count);self.timeout_once=True;return result
  if getattr(self,'timeout_once',False):
   self.timeout_once=False;self.world.unknown_wire_frames=self.world.sent_frames;raise TimeoutError('inert original response delayed')
  result=super().recv(count)
  if not self.buffer and getattr(self,'last_command',None)=='guest-file-write':self.world.write_ack_consumed=True
  return result
 def sendall(self,data):
  request=json.loads(data.lstrip(b'\xff'));self.last_command=request['execute']
  assert len(data)<=60000,('actual request exceeds byte cap',len(data))
  self.world.max_request_bytes=max(self.world.max_request_bytes,len(data))
  self.world.sent_frames+=1
  return super().sendall(data)


class ProtocolWorld(PeerWorld):
 def __init__(self,declarations,case_dir,fault=None,seed_endpoint_receipt=True):
  self.declarations=declarations;self.artifact=declarations['ARTIFACT'];self.case_dir=case_dir;self.fault=fault
  self.source_generation_epoch=0;self.source_root_epoch=0;self.read_bytes=0;self.read_calls=0
  self.handle_open=False;self.handle=7001;self.remote_position=0;self.write_count=0;self.seek_count=0
  self.close_count=0;self.flush_count=0;self.write_ack_consumed=True;self.post_seek_required=False
  self.last_seek_position=0;self.max_request_bytes=0;self.native_verifies=[];self.stream_active=False
  self.sent_frames=0;self.unknown_wire_frames=None;self.defer_command=None;self.retained_namespaces=[];self.socket_recv_calls=0;self.park_sleeps=0
  self.local_source=LOCAL_ARTIFACTS.get(self.artifact['key'])
  self.physical_source=None if self.local_source is None else os.open(self.local_source,os.O_RDONLY|os.O_NOFOLLOW)
  self.physical_opening=None if self.physical_source is None else os.fstat(self.physical_source)
  self.guest_path=case_dir/'guest-file.bin';self.guest_file=open(self.guest_path,'xb+')
  super().__init__(declarations,[])
  if self.local_source is not None:
   self.node(self.artifact.get('sourceRoot'),mode=stat.S_IFDIR|0o700)
   self.node(self.artifact.get('sourcePath'),size=self.artifact['bytes'])
  if fault=='host-root-unadmitted':self.nodes[self.root]['mode']=stat.S_IFDIR|0o777
  self.endpoint=self.endpoint_receipt()
  if seed_endpoint_receipt:self.jnode(self.root+'/'+declarations['ENDPOINT_RECEIPT_NAME'],self.endpoint)
  self.os.SEEK_SET=os.SEEK_SET;self.os.lseek=self.lseek
  self.socket.socket=lambda *args,**kwargs:ProtocolSocket(self)
  normal_sleep=self.sleep
  def inert_sleep(seconds):
   if seconds==1:self.park_sleeps+=1
   return normal_sleep(seconds)
  self.time.sleep=inert_sleep

 def import_peer(self,name,globals=None,locals=None,fromlist=(),level=0):
  if name in {'types','uuid','__future__'}:
   self.imports.append(name);return builtins.__import__(name,globals,locals,fromlist,level)
  return super().import_peer(name,globals,locals,fromlist,level)

 def boot_actor(self,pid):
  return {'pid':pid,'birthFileTimeUtc':str(134368714165265650+pid),'sessionId':0,'path':self.declarations['GUEST_CONTEXT']['powerShellPath'],'principalSid':'S-1-5-18','is64BitProcess':True,'powerShellMajor':5,'powerShellEdition':'Desktop','boot':dict(self.declarations['GUEST_CONTEXT']['boot']),'tokenElevation':1,'tokenElevationType':1}

 def actor_fields(self,pid):
  actor=self.boot_actor(pid);return {'bootstrapOpening':actor,'bootstrapClosing':json.loads(json.dumps(actor)),'guestBootClosing':True,'bootstrapActorClosing':True}

 def write_fd(self,fd,data):
  path=self.fds[fd]['path']
  if self.fault=='journal-failure'and(path.endswith('.unknown.json')or'.late-'in path):raise OSError(28,'inert journal full')
  if self.fault=='raw-capture-failure'and path.endswith('.raw')and len(self.executions)>0:raise OSError(28,'inert raw capture full')
  if self.fault=='short-capture-write'and(path.endswith('.raw')or path.endswith('.wire')or path.endswith('.partial-wire')):data=data[:7]
  return super().write_fd(fd,data)

 def endpoint_receipt(self):
  sid='S-1-5-21-4099058025-2437077614-260217637-1001'
  return dict(schemaVersion=1,state='created',transferId=self.artifact['transferId'],deploymentId=self.spec['deploymentId'],
   rootPath=self.artifact['guestRoot'],filePath=self.artifact['guestPath'],rootIdentity='11223344:0000000012345600',rootIdentityClosing=True,fileIdentity='11223344:0000000012345678',
   rootAcl=dict(ownerSid='S-1-5-18',sddl='O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;'+sid+')',rules=3,protected=True),
   fileAcl=dict(ownerSid='S-1-5-18',sddl='O:SYG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;'+sid+')',rules=3,protected=False),
   originalFileOwnerSid='S-1-5-32-544',bytes=0,sha256=hashlib.sha256(b'').hexdigest(),rootCreateNew=True,fileCreateNew=True,
   parentChainNoReparse=True,creatorPid=8123,creatorBirthFileTimeUtc=self.boot_actor(8123)['birthFileTimeUtc'],creatorSessionId=0,principalSid='S-1-5-18',productOperation=False,**self.actor_fields(8123))

 def info(self,path):
  value=super().info(path)
  if str(path)==self.artifact.get('sourceRoot'):
   value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid=self.artifact['sourceRootStructure']
   value.st_mtime_ns+=self.source_root_epoch;value.st_ctime_ns+=self.source_root_epoch
  elif str(path)==self.artifact.get('sourcePath'):
   g=self.artifact.get('sourceExpectedGeneration',self.artifact.get('sourceExpectedPrefix'))
   value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,value.st_nlink,value.st_size=g[:7]
   if len(g)==9:value.st_mtime_ns,value.st_ctime_ns=g[7:]
   value.st_mtime_ns+=self.source_generation_epoch;value.st_ctime_ns+=self.source_generation_epoch
  return value

 def lseek(self,fd,offset,whence):
  assert whence==os.SEEK_SET and offset>=0
  self.fds[fd]['offset']=offset;return offset

 def read_fd(self,fd,size):
  row=self.fds[fd]
  if row['path']!=self.artifact.get('sourcePath'):return super().read_fd(fd,size)
  if self.stream_active and size<=32768 and size>1:
   assert self.write_ack_consumed and not self.post_seek_required,'source advanced before original chunk ack/postseek'
   assert row['offset']==self.remote_position,'source/guest offset mismatch before next chunk'
  raw=os.pread(self.physical_source,size,row['offset']);row['offset']+=len(raw);self.read_bytes+=len(raw);self.read_calls+=1
  if self.fault=='source-hash'and self.read_calls==1 and raw:raw=bytes([raw[0]^1])+raw[1:]
  return raw

 def record(self,command,arguments):
  safe=dict(arguments)
  if 'buf-b64'in safe:
   data=base64.b64decode(safe.pop('buf-b64'),validate=True);safe['bufferReceipt']={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
  self.rpc.append({'command':command,'arguments':safe})

 def rpc_reply(self,request):
  c=request['execute'];a=request.get('arguments',{})
  if not c.startswith('guest-file-')and c not in ('guest-exec','guest-exec-status'):return super().rpc_reply(request)
  self.record(c,a)
  if c=='guest-file-open':
   assert self.fault not in('before-open-actor-pid','saved-actor-birth-split'),'spoof actor admitted before guest-file-open'
   assert a=={'path':self.artifact['guestPath'],'mode':'r+b'} and not self.handle_open
   assert self.guest_path.stat().st_size==0
   self.handle_open=True;self.remote_position=0
   if self.fault=='open-missing-ack':self.defer_command=c
   return self.handle
  if c=='guest-file-seek':
   assert self.handle_open and a=={'handle':self.handle,'offset':0,'whence':1}
   self.seek_count+=1;self.last_seek_position=self.remote_position;self.post_seek_required=False
   position=self.remote_position
   if self.fault=='seek-before-mismatch'and self.seek_count==2:position+=1
   if self.fault=='seek-after-mismatch'and self.seek_count==3:position+=1
   return {'position':position,'eof':False}
  if c=='guest-file-write':
   assert self.handle_open and a['handle']==self.handle and type(a['count'])is int and 0<a['count']<=32768
   assert self.last_seek_position==self.remote_position and not self.post_seek_required and self.write_ack_consumed
   data=base64.b64decode(a['buf-b64'],validate=True);assert len(data)==a['count']
   assert data==os.pread(self.physical_source,len(data),self.remote_position),'chunk differs from immutable real artifact'
   self.write_count+=1;self.write_ack_consumed=False;self.post_seek_required=True
   count=len(data)-1 if self.fault=='short-write'and self.write_count==1 else len(data)
   self.guest_file.seek(self.remote_position);assert self.guest_file.write(data[:count])==count;self.guest_file.flush();self.remote_position+=count
   self.source_root_epoch+=1 # Sibling staging may change directory mtime; structure remains exact.
   if self.fault=='source-generation'and self.write_count==1:self.source_generation_epoch+=1
   if self.fault in('write-missing-ack','broken-output','journal-failure','short-capture-write')and self.write_count==1:self.defer_command=c
   return {'count':count,'eof':False}
  if c=='guest-file-flush':
   assert self.handle_open and a=={'handle':self.handle};self.flush_count+=1;self.guest_file.flush()
   if self.fault=='flush-missing-ack':self.defer_command=c
   return {}
  if c=='guest-file-close':
   assert self.handle_open and a=={'handle':self.handle};self.close_count+=1;self.handle_open=False
   if self.fault=='close-missing-ack':self.defer_command=c
   return {}
  if c=='guest-exec':
   assert a['capture-output']is True
   launch=base64.b64decode(a['arg'][-1],validate=True).decode('utf-16le')
   saved='input-data'in a
   if saved:
    payload=base64.b64decode(a['input-data'],validate=True);assert payload.startswith(b'\xef\xbb\xbf')
    script=payload.decode('utf-8-sig')
    bound=re.search(r"\$path='([^']+)';\$parent='([^']+)';\$length=([0-9]+);\$expected='([0-9a-f]{64})';\$phase='([^']+)'",launch)
    assert bound,'actual saved-source launch binding missing'
    saved_path,workspace,saved_length,saved_digest,phase=bound.groups();assert workspace==self.declarations['GUEST_CONTEXT']['sourceWorkspace']and int(saved_length)==len(payload)and saved_digest==hashlib.sha256(payload).hexdigest()
    assert saved_path==workspace+'\\infra-'+phase+'.ps1'and phase in self.declarations['NATIVE_PHASE_IDS'].values()
   else:
    opening='$protocolResult= & {\n';closing='\n};[Console]::WriteLine(($protocolResult|ConvertTo-Json -Depth 12 -Compress))\n'
    assert launch.startswith(opening)and launch.endswith(closing);script=launch[len(opening):-len(closing)];payload=script.encode('utf-8-sig')
   pid=9000+len(self.executions)
   assert script.startswith("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'"),'actual canonical first line was not used'
   assert 'Read-ProgramBootstrap' in script and 'VpnArtifactToken' in script and self.declarations['GUEST_CONTEXT']['boot']['lastBootUpTimeFileTimeUtc'] in script
   if "state='created'"in script:
    result=dict(self.endpoint,creatorPid=pid,creatorBirthFileTimeUtc=self.boot_actor(pid)['birthFileTimeUtc'],**self.actor_fields(pid))
    if self.fault=='actor-pid':result['creatorPid']=pid+1;result['bootstrapOpening']['pid']=pid+1;result['bootstrapClosing']['pid']=pid+1
   else:
    match=re.search(r"\$expectedIdentity='([^']+)';\$expectedBytes=([0-9]+);\$expectedHash='([0-9a-f]+)';\$openExpected=(\$true|\$false)",script)
    assert match,'bound native verifier source is missing exact fields'
    identity,length,digest,open_expected=match.groups();length=int(length);open_expected=open_expected=='$true'
    assert identity==self.endpoint['fileIdentity']and open_expected is self.handle_open
    self.native_verifies.append({'bytes':length,'sha256':digest,'openExpected':open_expected,'scriptSha256':hashlib.sha256(payload).hexdigest(),'launchSha256':hashlib.sha256(launch.encode('utf-8-sig')).hexdigest(),'transport':'saved-source'if saved else'inline'})
    self.guest_file.flush();actual_hash=file_hash(self.guest_path);actual_bytes=self.guest_path.stat().st_size
    result=dict(schemaVersion=1,state='verified',**{k:self.endpoint[k]for k in ('transferId','deploymentId','rootPath','filePath','rootIdentity','rootIdentityClosing','fileIdentity','rootAcl','fileAcl')},
     bytes=actual_bytes,sha256=actual_hash,heldPhysicalRead=True,identityClosing=True,aclClosing=True,namedIdentityClosing=True,
     sharingProofRequired=open_expected,writeOpenError=32 if open_expected else None,deleteOpenError=32 if open_expected else None,
     parentChainNoReparse=True,principalSid='S-1-5-18',productOperation=False,**self.actor_fields(pid))
    if len(self.native_verifies)==1:
     assert not self.handle_open and self.write_count==0,'before-open proof occurred after file effect'
     if self.fault=='before-open-boot':result['bootstrapOpening']['boot']['lastBootUpTimeFileTimeUtc']='134368653075000000';result['bootstrapClosing']['boot']['lastBootUpTimeFileTimeUtc']='134368653075000000'
     if self.fault=='before-open-actor-pid':result['bootstrapOpening']['pid']=pid+1;result['bootstrapClosing']['pid']=pid+1
     if self.fault=='before-open-root-identity':result['rootIdentity']='11223344:0000000012345601'
     if self.fault=='before-open-identity':result['fileIdentity']='11223344:0000000012345679'
     if self.fault=='before-open-acl':result['fileAcl']=dict(result['fileAcl'],sddl='O:SYG:SYD:AI')
     if self.fault=='before-open-guestexec-missing-ack':self.defer_command=c
    self.stream_active=True
    if self.fault=='initial-sharing-failure'and open_expected and length==0:result={'exited':True,'exitcode':1,'out-data':'','err-data':base64.b64encode(b'ARTIFACT_ORIGINAL_QGA_SHARING').decode()}
   if saved and 'exited'not in result:
    outer=self.actor_fields(pid)
    if self.fault=='before-open-boot':outer['bootstrapOpening']['boot']['lastBootUpTimeFileTimeUtc']='134368653075000000';outer['bootstrapClosing']['boot']['lastBootUpTimeFileTimeUtc']='134368653075000000'
    if self.fault=='saved-actor-birth-split':
     outer['bootstrapOpening']['birthFileTimeUtc']=str(int(outer['bootstrapOpening']['birthFileTimeUtc'])+1);outer['bootstrapClosing']['birthFileTimeUtc']=outer['bootstrapOpening']['birthFileTimeUtc']
    held={'phaseId':phase,'path':saved_path,'identity':'11223344:00000000abcdef01','bytes':len(payload),'sha256':saved_digest,'ownerSid':'S-1-5-18','sddl':NATIVE_SOURCE_SDDL,'createNew':True,'heldReadOnly':True,'writeOpenError':32,'deleteOpenError':32,'parserErrors':0,'bootstrapOpening':outer['bootstrapOpening'],'launch':'held-saved-file-scriptblock','originalOwnerSid':'S-1-5-32-544','explicitOwnerGreen':True,'productOperation':False,'sourceClosing':True,'finalSourceSha256':saved_digest}
    if self.fault=='saved-source-hash':held['finalSourceSha256']='0'*64
    if self.fault=='saved-source-phase':held['phaseId']='00000000-0000-4000-8000-000000000000'
    if self.fault=='saved-source-sharing':held['writeOpenError']=0
    if self.fault=='saved-source-parser':held['parserErrors']=1
    if self.fault=='saved-source-owner':held['ownerSid']='S-1-5-32-544'
    result={'state':'protocol-completed','protocolResult':result,'heldSource':held,'sourceClosing':True,'bootstrapOpening':outer['bootstrapOpening'],'bootstrapClosing':outer['bootstrapClosing']}
    if self.fault=='saved-source-closing':result['sourceClosing']=False
   self.executions.append({'pid':pid,'arguments':{'path':a['path'],'sourceSha256':hashlib.sha256(payload).hexdigest(),'launchSha256':hashlib.sha256(launch.encode('utf-8-sig')).hexdigest()},'result':result})
   if self.fault=='guestexec-missing-ack':self.defer_command=c
   return {'pid':pid}
  if c=='guest-exec-status':
   row=next(row for row in self.executions if row['pid']==a['pid']);self.status_counts[a['pid']]+=1
   if self.status_counts[a['pid']]==1:
    if self.fault in('status-missing-ack','before-open-status-missing-ack'):self.defer_command=c
    return {'exited':False}
   result=row['result']
   if 'exited'in result:return result
   return {'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps(result).encode()).decode(),'err-data':''}
  raise AssertionError('unexpected file protocol command: '+c)

 def harness_cleanup(self):
  # Only inert host descriptors/local fixture files. Never issues a guest RPC.
  for fd in list(self.fds):self.close_fd(fd)
  def gen(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  if self.physical_source is not None:
   assert gen(os.fstat(self.physical_source))==gen(self.physical_opening),'local immutable artifact changed'
   os.close(self.physical_source)
  self.guest_file.close()


def execute(path,world,label):
 source=path.read_bytes();namespace={'__name__':'__main__'}
 if world.fault!='python-c':namespace['__file__']=str(path)
 initial_globals=['__name__','__builtins__']if world.fault=='python-c'else['__name__','__file__','__builtins__']
 normal=dict(vars(builtins));normal['__import__']=world.import_peer;normal['open']=world.builtin_open;namespace['__builtins__']=normal
 class BrokenOutput(io.StringIO):
  def write(self,text):raise BrokenPipeError('inert broken original stdout')
 output=BrokenOutput()if world.fault=='broken-output'else io.StringIO();errout=io.StringIO();error=None;functions=collections.Counter();lines=set();module_functions=collections.Counter();module_lines=set();qga_functions=collections.Counter();qga_lines=set();world.park_sleeps=0;world.unknown_wire_frames=None
 source_lines=source.decode().splitlines();qga_source_lines=world.declarations.get('QGA_MODULE_SOURCE',b'').decode().splitlines();cut_after=3 if world.fault=='response-bound'else 1
 def trace(frame,event,arg):
  if frame.f_code.co_filename==world.declarations.get('QGA_MODULE_ORIGIN'):
   if event=='call':qga_functions[frame.f_code.co_name]+=1
   elif event=='line':qga_lines.add(frame.f_lineno)
   if event=='call'and frame.f_code.co_name=='park_original'and world.unknown_wire_frames is None:world.unknown_wire_frames=world.sent_frames
   if event=='line'and frame.f_code.co_name=='park_original'and world.park_sleeps>=cut_after and qga_source_lines[frame.f_lineno-1].strip()=='while True:':raise InertParkReached('local tracer cut only at original canonical park loop backedge')
  if frame.f_code.co_filename==world.declarations.get('EMITTER_ORIGIN'):
   if event=='call':module_functions[frame.f_code.co_name]+=1
   elif event=='line':module_lines.add(frame.f_lineno)
  if frame.f_code.co_filename==str(path):
   if event=='call'and frame.f_code.co_name=='park_original'and world.unknown_wire_frames is None:world.unknown_wire_frames=world.sent_frames
   if event=='call':functions[frame.f_code.co_name]+=1
   elif event=='line':lines.add(frame.f_lineno)
   if event=='line'and frame.f_code.co_name=='park_original'and world.park_sleeps>=cut_after and source_lines[frame.f_lineno-1].strip()=='while True:':raise InertParkReached('local tracer cut only at original park loop backedge')
  return trace
 prior=sys.gettrace();started=time.perf_counter()
 try:
  with contextlib.redirect_stdout(output),contextlib.redirect_stderr(errout):
   sys.settrace(trace);exec(compile(source,str(path),'exec'),namespace,namespace)
 except BaseException as caught:error={'class':type(caught).__name__,'message':str(caught),'traceback':traceback.format_exc()}
 finally:sys.settrace(prior)
 if error is None:
  assert not world.fds,'successful caller leaked host descriptors';assert all(sock.closed for sock in world.sockets)
 else:
  assert isinstance(namespace.get('original_failure'),BaseException)and error['class']=='InertParkReached',error
  assert world.fds,'UNKNOWN did not retain admitted namespace descriptors'
  if world.fault=='emitter-source-hash':assert not world.rpc and namespace['EMITTER_SOURCE'],'hash refusal sent an RPC or discarded source bytes'
  world.retained_namespaces.append(namespace)
  if world.unknown_wire_frames is not None:assert world.sent_frames==world.unknown_wire_frames,'outbound frame after UNKNOWN'
  pending=namespace.get('CURRENT_RPC')
  if pending is not None:
   assert pending.client is not None and not pending.client.closed and not pending.closed,'original socket lost'
   assert pending.request_fd in world.fds and pending.raw_fd in world.fds,'original request/raw descriptors lost'
   assert bytes(world.nodes[world.fds[pending.request_fd]['path']]['data'])==pending.request,'pending exact request bytes changed'
  if namespace.get('source_fd')is not None:assert world.fds[namespace['source_fd']]['path']==world.artifact['sourcePath'],'original source descriptor lost'
 written={e[1]for e in world.events if e[0]=='write'}
 pending=namespace.get('CURRENT_RPC');pending_request=None if pending is None else str(world.root+'/'+pending.request_name)
 captures={}
 for path,node in world.nodes.items():
  if path not in written:continue
  data=node['data'];item={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
  if not path.endswith('.request.json')or path==pending_request:item['base64']=base64.b64encode(data).decode()
  else:item['completedRequestBytesReconstructibleFromImmutableArtifactAndChunkIntent']=True
  captures[path]=item
 retained=[{'fd':fd,'path':value['path']}for fd,value in world.fds.items()]
 rpc_raw=[bytes(n['data'])for p,n in sorted(world.nodes.items())if re.search(r'\.rpc-[0-9]{6}\.raw$',p)]
 shared_raw=[bytes(n['data'])for p,n in world.nodes.items()if p.endswith('.partial-wire')]
 shared_lines=[bytes(n['data'])for p,n in world.nodes.items()if p.endswith('.wire')and not p.endswith('.partial-wire')]
 captures_complete=True
 if pending is None or getattr(pending,'capture_failure',None)is None:
  if shared_raw:assert shared_raw[-1]==b''.join(rpc_raw),'shared partial wire lost bytes on short writes'
  expected_lines=b''.join(line for raw in rpc_raw for line in raw.splitlines(keepends=True)if line.endswith(b'\n')and not line.startswith(b'\xff'))
  if shared_lines:assert shared_lines[-1]==expected_lines,'parsed wire lost bytes on short writes'
 else:captures_complete=False
 qga=namespace.get('QGA_MODULE');owner=namespace.get('QGA_OWNER')
 if qga is not None:
  assert sys.modules[qga.__name__]is qga and qga_functions['<module>']==1 and qga_lines,'complete registered QGA module was not executed'
  assert type(owner)is qga.RetainedQgaOwner and owner.current is pending,'caller did not retain canonical owner/current'
  assert qga.RetainedRpc.__module__==qga.__name__ and qga.RetainedQgaOwner.call.__globals__ is qga.__dict__
  assert hashlib.sha256(namespace['QGA_MODULE_SOURCE']).hexdigest()==namespace['QGA_MODULE_SHA']
  if error is not None and any('.canonical-qga.py'in row['path']for row in retained):
   assert any(bytes(world.nodes[row['path']]['data'])==namespace['QGA_MODULE_SOURCE']for row in retained if '.canonical-qga.py'in row['path'])
 emitter=namespace.get('EMITTER_MODULE')
 if emitter is not None:
  assert sys.modules[emitter.__name__]is emitter
  assert emitter.__dict__['render_verifier'].__globals__ is emitter.__dict__
  assert module_functions['<module>']==1 and module_lines,'canonical full module namespace was not executed'
  assert hashlib.sha256(namespace['EMITTER_SOURCE']).hexdigest()==namespace['EMITTER_SHA256']
  if error is not None and any('.canonical-emitter.py'in row['path']for row in retained):
   assert any(bytes(world.nodes[row['path']]['data'])==namespace['EMITTER_SOURCE']for row in retained if '.canonical-emitter.py'in row['path'])
 result=dict(label=label,source=str(path),sourceSha256=hashlib.sha256(source).hexdigest(),sourceUnmodified=True,partialNamespaceExecution=False,
  initialGlobals=initial_globals,pythonCWithoutFile=world.fault=='python-c',postExecFunctionReplacement=False,fullRealArtifact=None if world.local_source is None else str(world.local_source),
  physicalSourceBytes=world.artifact['bytes'],sourceReadBytes=world.read_bytes,sourceReadCalls=world.read_calls,
  wallSeconds=time.perf_counter()-started,error=error,originalFailure=None if namespace.get('original_failure')is None else {'class':type(namespace['original_failure']).__name__,'message':str(namespace['original_failure'])},stdout=output.getvalue(),stderr=errout.getvalue(),functions=dict(functions),coveredLines=sorted(lines),imports=world.imports,canonicalModuleFunctions=dict(module_functions),canonicalModuleCoveredLines=sorted(module_lines),canonicalModuleRecord=namespace.get('EMITTER_RECORD'),nativeSourceSDDLFixture={'path':str(NATIVE_SDDL_RECEIPT),'sha256':hashlib.sha256(NATIVE_SDDL_BYTES).hexdigest(),'jsonPointer':'/sddl','onlySourceSDDLAuthentic':True,'newPhaseActorEnvelopeInert':True},canonicalModuleRegistered=emitter is not None and sys.modules.get(emitter.__name__)is emitter,
  canonicalQgaFunctions=dict(qga_functions),canonicalQgaCoveredLines=sorted(qga_lines),canonicalQgaRecord=namespace.get('QGA_MODULE_RECORD'),canonicalQgaRegistered=qga is not None and sys.modules.get(qga.__name__)is qga,
  rpc=world.rpc,statusCounts=dict(world.status_counts),rawAndJournalCaptures=captures,retainedOriginalHostDescriptors=retained,
  modelRemoteHandle=world.handle,modelRemoteHandleOpen=world.handle_open,modelRemoteOffset=world.remote_position,
  writes=world.write_count,seeks=world.seek_count,flushes=world.flush_count,closes=world.close_count,maxRequestBytes=world.max_request_bytes,
  modelNativeVerifications=world.native_verifies,guestFixtureBytes=world.guest_path.stat().st_size,guestFixtureSha256=file_hash(world.guest_path),
  nativeQualified=False,realGuestOrNetworkOperations=False,keeperBindingRequired=True,
  retainedOriginalRpc=None if pending is None else pending.snapshot(),outboundFrames=world.sent_frames,outboundFramesAtUnknown=world.unknown_wire_frames,
  fullSharedWireCaptureVerified=captures_complete,
  originalStateInMemory=namespace.get('state',namespace.get('receipt')),reportingFailures=namespace.get('REPORTING_FAILURES',[]),socketRecvCalls=world.socket_recv_calls,parkIterations=world.park_sleeps,
  custodyScope='Actual park reached; local tracer cuts only at park loop backedge. Original namespace/socket/descriptors retained. No standalone runner exists; harness cleanup is inert-only.')
 (world.case_dir/(label+'-caller.py')).write_bytes(source)
 (world.case_dir/(label+'-receipt.json')).write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
 return result


def run_case(packet,case,label,fault=None):
 destination=HERE/'qualification-v1'/label;destination.mkdir(parents=True,mode=0o700,exist_ok=False)
 if fault=='emitter-source-hash':
  original=packet.read_text();declarations=literals(original);controlled=original.replace('EMITTER_SHA256='+repr(declarations['EMITTER_SHA256']), 'EMITTER_SHA256='+repr('0'*64),1);assert controlled!=original
  packet=destination/'emitter-hash-mismatch.saved-caller.py';packet.write_text(controlled)
 world=ProtocolWorld(literals(packet.read_text()),destination,fault,seed_endpoint_receipt=not case.startswith(('endpoint','probe')))
 try:
  result=execute(packet,world,label)
  is_probe=world.artifact.get('probeOnly')is True
  if case in('probe','probe-python-c'):
   assert result['error']is None,result['error'];assert result['writes']==0 and result['seeks']==0 and result['closes']==0 and result['flushes']==0
   assert len(world.executions)==2 and [x['openExpected']for x in world.native_verifies]==[False]
   assert not any(row['command'].startswith('guest-file-')for row in world.rpc)
   assert result['canonicalModuleFunctions']['render_probe_endpoint']==1 and result['canonicalModuleFunctions']['render_probe_verifier']==1 and result['canonicalModuleFunctions']['decode_guest_result']==2
  elif case=='success':
   assert result['error']is None,result['error'];assert result['guestFixtureBytes']==world.artifact['bytes']and result['guestFixtureSha256']==world.artifact['sha256']
   assert result['writes']==math.ceil(world.artifact['bytes']/32768)and result['seeks']==1+result['writes']*2
   assert result['closes']==1 and result['flushes']==1 and not world.handle_open
   assert [x['openExpected']for x in world.native_verifies]==[False,True,True,False]
  elif case=='endpoint':
   assert result['error']is None,result['error'];assert result['writes']==0 and result['closes']==0
  else:
   assert result['error']is not None,('fault did not refuse',fault)
   assert result['closes']==(1 if fault=='close-missing-ack'else 0),result['closes']
   assert result['retainedOriginalHostDescriptors']
   state=result['originalStateInMemory']if fault in('journal-failure','host-root-unadmitted')else next(json.loads(base64.b64decode(c['base64']))for p,c in result['rawAndJournalCaptures'].items()if p.endswith('.unknown.json'))
   assert state['automaticRetry']is False and state.get('automaticClose',False)is False and state['keeperBindingRequired']is True and state['programParked']is True
   assert state['hostDescriptorDisposition']=='retained-in-original-namespace'
   if fault in ('seek-before-mismatch','initial-sharing-failure','open-missing-ack','source-hash','partial-send-timeout','sync-timeout','raw-capture-failure','before-open-boot','before-open-identity','before-open-acl','before-open-guestexec-missing-ack','before-open-status-missing-ack','emitter-source-hash','before-open-actor-pid','actor-pid','before-open-root-identity','saved-actor-birth-split','saved-source-hash','saved-source-phase','saved-source-sharing','saved-source-parser','saved-source-owner','saved-source-closing','host-root-unadmitted'):assert result['writes']==0
   if fault in ('write-missing-ack','short-write','seek-after-mismatch','source-generation','partial-response-timeout','eof-after-write','response-bound','broken-output','journal-failure','short-capture-write'):assert result['writes']==1
   reasons={'before-open-boot':'transfer_actor_boot','source-hash':'transfer_source_sha256','source-generation':'instance_source_changed','seek-before-mismatch':'transfer_seek_position','seek-after-mismatch':'transfer_seek_position','short-write':'transfer_write_ack','initial-sharing-failure':'transfer_verify_output','partial-send-timeout':'inert partial original send','eof-after-write':'retained_rpc_original_wire_eof','response-bound':'retained_rpc_response_bound_latched','raw-capture-failure':'inert raw capture full','before-open-identity':'transfer_verify_identity_or_acl','before-open-acl':'transfer_verify_identity_or_acl','emitter-source-hash':'transfer_emitter_source_sha256','before-open-actor-pid':'transfer_actor_pid','actor-pid':'transfer_actor_pid','before-open-root-identity':'transfer_verify_identity_or_acl','saved-actor-birth-split':'transfer_saved_protocol_actor','saved-source-hash':'transfer_saved_proof_source','saved-source-phase':'transfer_saved_proof_source','saved-source-sharing':'transfer_saved_proof_native','saved-source-parser':'transfer_saved_proof_native','saved-source-owner':'transfer_saved_proof_acl','saved-source-closing':'transfer_saved_envelope','host-root-unadmitted':'instance_private'}
   expected_reason=reasons.get(fault,'inert original response delayed')
   if fault in('before-open-actor-pid','actor-pid'):
    if b'transfer_saved_protocol_actor'in world.declarations['EMITTER_SOURCE']:expected_reason='transfer_saved_protocol_actor'
    elif result['canonicalModuleFunctions'].get('decode_guest_result'):expected_reason='transfer_actor_pid'
    else:expected_reason='endpoint_actor_pid'if fault=='actor-pid'else'transfer_verify_actor_pid'
   if is_probe and fault=='before-open-root-identity':expected_reason='probe_verify_identity_or_acl'
   assert expected_reason in result['originalFailure']['message'],result['originalFailure']
   current=result['retainedOriginalRpc']
   if fault in('write-missing-ack','short-write','partial-send-timeout','partial-response-timeout','eof-after-write','response-bound','broken-output','journal-failure','short-capture-write'):assert current['command']=='guest-file-write'
   if fault in('seek-before-mismatch','seek-after-mismatch'):assert current['command']=='guest-file-seek'
   if fault=='source-generation':
    # Canonical owner guards before closing its current write or constructing the next seek.
    assert current['command']==('guest-file-write'if result['canonicalQgaRegistered']else'guest-file-seek')
    assert world.write_count==1 and world.remote_position==32768 and state['confirmedOffset']==0
   if fault=='open-missing-ack':assert current['command']=='guest-file-open'
   if fault in('sync-timeout','raw-capture-failure','before-open-guestexec-missing-ack'):assert current['command']=='guest-exec'
   if fault=='before-open-status-missing-ack':assert current['command']=='guest-exec-status'
   if fault.startswith('before-open-')or fault.startswith('saved-')or fault=='emitter-source-hash':assert not world.handle_open and not any(row['command']=='guest-file-open'for row in world.rpc)
   if fault=='host-root-unadmitted':assert not result['rawAndJournalCaptures']and not world.rpc,'unadmitted root received failure journals or RPC'
   if fault=='before-open-guestexec-missing-ack':assert current['response']['return']['pid']==9000 and not world.status_counts and state['pending']['label']=='before-open'and not state.get('originalGuestProcesses')
   if fault=='before-open-status-missing-ack':assert current['response']=={'return':{'exited':False}}and state['originalGuestProcesses']['before-open']=={'pid':9000}and world.status_counts[9000]==1
   if fault=='initial-sharing-failure':assert world.handle_open and [row['openExpected']for row in world.native_verifies]==[False,True]
   if fault=='partial-send-timeout':assert current['phase']=='command-sending'and current['commandSent']is False and 0<current['frameConfirmedSentBytes']<current['frameBytes']
   if fault=='sync-timeout':assert current['phase']=='late-sync-only-command-not-sent'and current['syncKnown']is True and current['commandSent']is False and not world.handle_open
   if fault=='eof-after-write':assert current['wireEof']is True and current['response']is None
   if fault=='response-bound':assert current['readRefused']is True and current['bufferBytes']==262145 and current['rawCaptureComplete']is True and result['parkIterations']==3
   if fault=='raw-capture-failure':assert current['captureFailure']is not None and current['readRefused']is True and current['rawCaptureComplete']is False
   if fault in('broken-output','journal-failure'):assert result['reportingFailures']
   if fault=='partial-response-timeout':assert state['originalRpc']['bufferBytes']==7 and current['response']['return']['count']==32768
   if fault=='guestexec-missing-ack':
    assert current['command']=='guest-exec'and current['response']['return']['pid']==9000 and not world.status_counts
    assert(not state['originalGuestProcesses']and state['pending']['label']=='create')if is_probe else state['originalGuestPid']is None
   if fault=='status-missing-ack':
    assert current['command']=='guest-exec-status'and world.status_counts[9000]==1
    assert state['originalGuestProcesses']['create']=={'pid':9000}if is_probe else state['originalGuestPid']==9000
   if fault in('flush-missing-ack','close-missing-ack'):
    command='guest-file-flush'if fault=='flush-missing-ack'else'guest-file-close'
    assert current['command']==command and state['pending']['kind']==command and state['confirmedOffset']==world.artifact['bytes']
    assert state['handleStatus']==('open-acknowledged'if fault=='flush-missing-ack'else'close-unknown')
    assert current['response']=={'return':{}}and result['guestFixtureSha256']==world.artifact['sha256']
    assert not any(p.endswith('/artifact-transfer-'+world.artifact['transferId']+'.complete.json')for p in result['rawAndJournalCaptures'])
   if fault=='write-missing-ack':
    assert state['guestHandle']==world.handle and state['confirmedOffset']==0 and state['pending']['startOffset']==0 and state['pending']['endOffset']==32768
    before=(world.write_count,world.close_count,len([r for r in world.rpc if r['command']=='guest-file-open']))
    original_unknown=next(bytes(n['data'])for p,n in world.nodes.items()if p.endswith('.unknown.json'))
    replay=execute(packet,world,label+'-replay-refusal');assert replay['originalFailure']['message']=='transfer_operation_already_started'
    assert before==(world.write_count,world.close_count,len([r for r in world.rpc if r['command']=='guest-file-open']))
    assert next(bytes(n['data'])for p,n in world.nodes.items()if p.endswith('.unknown.json'))==original_unknown
  return {'label':label,'passed':True,'fault':fault,'sourceSha256':result['sourceSha256'],'receiptSha256':hashlib.sha256((destination/(label+'-receipt.json')).read_bytes()).hexdigest(),
          'writes':result['writes'],'seeks':result['seeks'],'bytes':result['guestFixtureBytes'],'error':None if result['originalFailure']is None else result['originalFailure']['message']}
 finally:world.harness_cleanup()


if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--packet-version',default='packets-v11');p.add_argument('--case',required=True);p.add_argument('--artifact',choices=['msi','python'],default='msi');p.add_argument('--probe-label',choices=['direct','mcp'],default='direct');p.add_argument('--label',required=True);args=p.parse_args()
 kind='probe'if args.case.startswith('probe')else('endpoint'if args.case.startswith('endpoint')else'transfer')
 name='probe-'+args.probe_label+'-probe-caller.py'if kind=='probe'else args.artifact+'-'+kind+'-caller.py'
 packet=HERE/args.packet_version/name;fault=None if args.case in('success','endpoint','probe')else args.case.removeprefix('endpoint-').removeprefix('probe-')
 print(json.dumps(run_case(packet,args.case,args.label,fault),indent=2,sort_keys=True))
