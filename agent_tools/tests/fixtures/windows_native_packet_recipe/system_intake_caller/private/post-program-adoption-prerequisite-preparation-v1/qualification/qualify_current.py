"""Finite inert whole-entry qualification. No native, network or host API action.

Only test-boundary peers are adapted. Every candidate is executed once from its
complete saved bytes with Python-c globals; its embedded modules execute whole.
"""
import base64,builtins,collections,copy,hashlib,importlib.util,json,os,stat,subprocess,sys,time,traceback
from pathlib import Path

HERE=Path(__file__).resolve().parent
N=HERE.parent
B=N.parent
QGA_SHA='bf05c8f08c1e5210ba79ffb59186206e80dc13fef057748dab3596df8ab6f022'
EMITTER_SHA='297b4bad26f810b7f2433846f10a23c6abe33870f0be50315cfa45dbdcd4b479'

def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
 sys.modules[name]=module;spec.loader.exec_module(module);return module

peer=load('_bf05_whole_protocol_boundary',B/'qga-transfer-preparation/qualify_protocol.py')
models=load('_bf05_whole_producer_boundary',HERE/'producer_peers.py')
models.install_common_boundary(peer)

class PollSocket(peer.ProtocolSocket):
 def settimeout(self,value):
  super().settimeout(value);self.requested_timeout=value
 def sendall(self,data):
  command=json.loads(data.lstrip(b'\xff'))['execute']
  value=super().sendall(data)
  if command==self.world.poll_command and self.world.poll_mode and not self.world.poll_selected:
   self.world.poll_selected=True;self.poll_mode=self.world.poll_mode;self.polls=0
   self.world.poll_socket=self;self.world.poll_original_frames=self.world.sent_frames
   self.partial_first=self.poll_mode=='partial-transient'
  return value
 def recv(self,count):
  mode=getattr(self,'poll_mode',None)
  if mode:
   if getattr(self,'partial_first',False):
    self.partial_first=False;return super().recv(min(7,count))
   limit=1 if mode in ('transient','partial-transient')else 20 if mode=='late-reply'else None
   if limit is None or self.polls<limit:
    self.polls+=1;self.world.socket_recv_calls+=1
    self.world.time_now+=self.requested_timeout
    self.world.poll_events.append({'socketIndex':self.world.sockets.index(self),'command':self.last_command,'timeout':self.requested_timeout,'monotonic':self.world.time_now,'poll':self.polls,'sentFrames':self.world.sent_frames})
    raise TimeoutError('inert no-data poll on original socket')
  return super().recv(count)

class BoundaryMixin:
 def prepare(self,mode=None,command='guest-exec'):
  self.poll_mode=mode;self.poll_command=command;self.poll_selected=False
  self.poll_events=[];self.poll_socket=None;self.park_snapshots=[];self.argument_bounds=[]
  self.socket.socket=lambda *args,**kwargs:PollSocket(self)
  old_sleep=self.time.sleep
  def sleep(seconds):
   frame=sys._getframe(1);owner=None
   while frame is not None:
    if frame.f_code.co_name=='park_original'and frame.f_code.co_filename==self.declarations['QGA_MODULE_ORIGIN']:
     owner=frame.f_locals['self'];break
    frame=frame.f_back
   if owner is not None:
    self.park_snapshots.append(copy.deepcopy(owner.snapshot()))
   old_sleep(seconds)
   # The frozen helper cuts at its first counted backedge. Keep it tracing the
   # complete unchanged caller until three actual original park iterations.
   if owner is not None and len(self.park_snapshots)<3:self.park_sleeps=0
  self.time.sleep=sleep
 def rpc_reply(self,request):
  if request['execute']=='guest-exec':
   a=request['arguments'];argv=[a['path'],*a['arg']]
   assert all(type(x)is str and '\x00'not in x for x in argv)
   command=subprocess.list2cmdline(argv);units=len(command.encode('utf-16le'))//2+1
   wire=(json.dumps(request,separators=(',',':'))+'\n').encode()
   launch=base64.b64decode(a['arg'][-1],validate=True).decode('utf-16le')
   payload=base64.b64decode(a['input-data'],validate=True)if 'input-data'in a else None
   assert units<=32767 and len(wire)<=60000 and(payload is None or len(payload)<=32768)
   self.argument_bounds.append({'ordinal':len(self.argument_bounds)+1,'commandUtf16UnitsIncludingNul':units,'serializedRequestBytesIncludingLf':len(wire),'commandSha256Utf16le':sha(command.encode('utf-16le')),'launchUtf8SigBytes':len(launch.encode('utf-8-sig')),'launchUtf8SigSha256':sha(launch.encode('utf-8-sig')),'inputDataBytes':None if payload is None else len(payload),'inputDataSha256':None if payload is None else sha(payload),'transport':'inline'if payload is None else'saved-source','nativeAcceptance':'UNRUN','powerShell51ParserAcceptance':'UNRUN'})
  return super().rpc_reply(request)

class ProbeWorld(BoundaryMixin,peer.ProtocolWorld):
 def __init__(self,declarations,destination,fault=None):
  super().__init__(declarations,destination,fault='python-c',seed_endpoint_receipt=False)
  self.probe_fault=fault
 def rpc_reply(self,request):
  result=super().rpc_reply(request)
  if request['execute']=='guest-exec'and self.probe_fault=='actor-pid':
   proof=self.executions[-1]['result']
   if proof.get('state')=='protocol-completed':proof=proof['protocolResult']
   proof['bootstrapOpening']['pid']+=1;proof['bootstrapClosing']['pid']+=1
  return result

class KernelWorld(BoundaryMixin,models.KernelWorld):pass
class NativeWorld(BoundaryMixin,models.NativeWorld):pass
class PolicyWorld(BoundaryMixin,models.PolicyWorld):pass

def packets():
 result=[]
 for group,kind,name in [('canonical-probe-packets','probe','manifest.json'),('kernel-packets','kernel','manifest.private.json'),('native-causal-packets-v1','six','manifest.private.json'),('xml-packets','xml','manifest.json')]:
  raw=(N/group/name).read_bytes();manifest=json.loads(raw)
  assert manifest.get('canonicalQgaSha256',manifest.get('canonicalQga',{}).get('sha256'))==QGA_SHA
  for row in manifest.get('packets',[manifest]):
   path=Path(row['path']);pin=row.get('sourceSha256',row.get('sha256'))
   assert path.parent==N/group and sha(path.read_bytes())==pin
   route=row.get('route','mcp'if 'mcp'in path.name else'direct')
   result.append({'kind':kind,'route':route,'path':path,'sha256':pin,'manifestPath':N/group/name,'manifestSha256':sha(raw)})
 assert len(result)==7;return result

def run_case(packet,label,*,fault=None,mode=None,command='guest-exec',expected_error=None):
 destination=HERE/'cases'/label;destination.mkdir(mode=0o700,parents=True)
 declarations=peer.literals(packet['path'].read_text())
 assert declarations['QGA_MODULE_SHA']==QGA_SHA and sha(declarations['QGA_MODULE_SOURCE'])==QGA_SHA
 assert declarations['EMITTER_SHA256']==EMITTER_SHA and sha(declarations['EMITTER_SOURCE'])==EMITTER_SHA
 # These declaration defaults are used only by the in-memory peer fixture.
 declarations.setdefault('ENDPOINT_RECEIPT_NAME','unused-inert-endpoint')
 classes={'probe':ProbeWorld,'kernel':KernelWorld,'six':NativeWorld,'xml':PolicyWorld}
 before_modules=dict(sys.modules)
 for name in list(sys.modules):
  if name=='agent_tools'or name.startswith('agent_tools.'):del sys.modules[name]
 world=None;producer_calls=collections.Counter();producer_modules={}
 def profile(frame,event,arg):
  if event=='call'and(frame.f_code.co_filename==declarations.get('NATIVE_HELPER_ORIGIN')or frame.f_code.co_filename==declarations.get('CAPTURE_ORIGIN')or '/agent_tools/'in frame.f_code.co_filename and '/home/kardinal/'in frame.f_code.co_filename):
   name=frame.f_globals.get('__name__');module=sys.modules.get(name)
   assert module is not None and module.__dict__ is frame.f_globals
   producer_calls[(frame.f_code.co_filename,frame.f_code.co_name)]+=1
   producer_modules[name]={'origin':frame.f_code.co_filename,'registered':True}
 prior=sys.getprofile()
 try:
  world=classes[packet['kind']](declarations,destination,fault);world.prepare(mode,command)
  sys.setprofile(profile);receipt=peer.execute(packet['path'],world,'whole-namespace');sys.setprofile(prior)
  assert receipt['initialGlobals']==['__name__','__builtins__']and receipt['pythonCWithoutFile']
  assert receipt['canonicalQgaRegistered']and receipt['canonicalModuleRegistered']
  assert receipt['sourceSha256']==packet['sha256']and receipt['sourceUnmodified']and not receipt['partialNamespaceExecution']and not receipt['postExecFunctionReplacement']
  assert world.physical_source is None and world.read_bytes==0
  assert not any(row['command'].startswith('guest-file-')for row in world.rpc)
  assert world.write_count==world.seek_count==world.flush_count==world.close_count==0
  if expected_error:
   assert receipt['error']and expected_error in receipt['originalFailure']['message'],receipt['originalFailure']
   assert receipt['retainedOriginalHostDescriptors']and receipt['outboundFrames']==receipt['outboundFramesAtUnknown']
   assert len(world.park_snapshots)==3
  else:
   assert receipt['error']is None,receipt['error']
   result=json.loads(receipt['stdout']);assert result['state']=='qualified'and result['sourceClosing']is True
   assert len(world.executions)=={'probe':2,'kernel':1,'six':6,'xml':2}[packet['kind']]
   assert not receipt['retainedOriginalHostDescriptors']and receipt['parkIterations']==0
  if mode:
   assert world.poll_selected and world.poll_events
   if mode in('transient','partial-transient'):
    assert len(world.poll_events)==1 and not receipt['error']
    known=[json.loads(bytes(node['data']))for path,node in world.nodes.items()if path.endswith('.known.json')]
    timings=[r['timing']for r in known if r.get('timing',{}).get('readTimeoutPolls')]
    assert len(timings)==1 and timings[0]['readTimeoutPolls']==1
   else:
    pending=receipt['retainedOriginalRpc'];timing=pending['timing']
    assert timing['deadlineMonotonic']-timing['startedMonotonic']==20
    assert timing['readTimeoutPolls']==20 and len(timing['readTimeoutTrace'])==16 and timing['readTimeoutTraceOverflow']is True
    assert all(r['timing']==timing for r in world.park_snapshots)
    assert world.sent_frames==world.poll_original_frames and world.sockets.index(world.poll_socket)==len(world.sockets)-1
    assert len(world.executions)==1,'UNKNOWN resumed another native stage'
    late=[p for p in world.nodes if '.late-'in p]
    assert len(late)==1,'unchanged late observation generated new journal fingerprints'
    if mode=='late-reply':assert pending['response']is not None and pending['phase']=='reply-observed'
    else:assert pending['response']is None
  if packet['kind']=='six':assert any(fn=='<module>'and count==1 for(path,fn),count in producer_calls.items()if path==declarations['NATIVE_HELPER_ORIGIN'])
  if packet['kind']=='xml':
   for suffix in('/agent_tools/windows_ordinary_task.py','/agent_tools/tests/test_windows_ordinary_task.py'):
    assert sum(count for(path,fn),count in producer_calls.items()if path.endswith(suffix)and fn=='<module>')==1
   assert sum(count for(path,fn),count in producer_calls.items()if fn=='original_inputs')==1
  extra={'schemaVersion':1,'label':label,'passed':True,'qualifierSha256':sha(Path(__file__).read_bytes()),'producerBoundarySha256':sha((HERE/'producer_peers.py').read_bytes()),'packet':{k:str(v)if isinstance(v,Path)else v for k,v in packet.items()},'fault':fault,'pollMode':mode,'pollCommand':command,'wholeEntryReceiptSha256':sha((destination/'whole-namespace-receipt.json').read_bytes()),'canonicalQgaSha256':QGA_SHA,'canonicalEmitterSha256':EMITTER_SHA,'producerModuleCalls':[{'origin':p,'function':f,'calls':n}for(p,f),n in sorted(producer_calls.items())],'producerModules':producer_modules,'actualArgumentBounds':world.argument_bounds,'pollEvents':world.poll_events,'independentParkSnapshots':world.park_snapshots,'originalFailure':receipt['originalFailure'],'wholeSourceComplete':True,'callerNamespaceSeededOnlyWithPythonCGlobals':True,'postExecutionFunctionReplacement':False,'noGuestFileRpc':True,'largeArtifactStreamsRepeated':False,'originalCustodyClaimAppliesOnlyIfParked':bool(world.park_snapshots),'parkTraceCut':'after three actual original canonical park iterations, at the unchanged loop backedge outside retaining catch','testBoundaryChanges':'copied producer peers plus no-data timeout clock and extra park observations only','windowsPowerShell51NativeParserAcceptance':'UNRUN','nativeAcceptance':'UNRUN','realNetworkGuestOrApiOperations':False}
  raw=(json.dumps(extra,sort_keys=True,indent=2)+'\n').encode();(destination/'audit.json').write_bytes(raw)
  return {'label':label,'passed':True,'receiptSha256':sha(raw),'receiptPath':str(destination/'audit.json'),'sourceSha256':packet['sha256'],'executions':len(world.executions),'bounds':world.argument_bounds,'error':receipt['originalFailure']}
 finally:
  sys.setprofile(prior)
  if world is not None:world.harness_cleanup()
  for name in list(sys.modules):
   if name=='agent_tools'or name.startswith('agent_tools.'):del sys.modules[name]
  for name,module in before_modules.items():
   if name=='agent_tools'or name.startswith('agent_tools.'):sys.modules[name]=module

def main():
 started=time.monotonic();entries=packets();results=[]
 def run(packet,label,**kwargs):
  result=run_case(packet,label,**kwargs);results.append(result)
  print(json.dumps({'label':label,'passed':True,'receiptSha256':result['receiptSha256']}),flush=True)
 for p in entries:run(p,p['kind']+'-'+p['route']+'-success')
 direct={p['kind']:p for p in entries if p['route']=='direct'}
 run(direct['probe'],'probe-transient-sync',mode='transient',command='guest-sync-delimited')
 run(direct['kernel'],'kernel-transient-command',mode='transient')
 run(direct['six'],'six-transient-partial-status',mode='partial-transient',command='guest-exec-status')
 run(direct['probe'],'probe-command-fixed-deadline',mode='deadline',expected_error='retained_rpc_deadline')
 run(direct['six'],'six-status-fixed-deadline',mode='deadline',command='guest-exec-status',expected_error='retained_rpc_deadline')
 run(direct['xml'],'xml-original-late-reply-no-resume',mode='late-reply',expected_error='retained_rpc_deadline')
 for kind,fault,reason in [('probe','actor-pid','transfer_saved_protocol_actor'),('kernel','actor-pid','transfer_actor_pid'),('six','saved-source-hash','transfer_saved_proof_source'),('xml','saved-source-hash','transfer_saved_proof_source')]:
  run(direct[kind],kind+'-refuse-'+fault,fault=fault,expected_error=reason)
 summary={'schemaVersion':1,'allPassed':True,'caseCount':len(results),'cases':results,'elapsedSeconds':time.monotonic()-started,'canonicalQgaSha256':QGA_SHA,'canonicalEmitterSha256':EMITTER_SHA,'qualifierSha256':sha(Path(__file__).read_bytes()),'producerBoundarySha256':sha((HERE/'producer_peers.py').read_bytes()),'commonBoundarySha256':sha(Path(peer.__file__).read_bytes()),'producerBoundaryCopies':models.BOUNDARY_COPY_RECORDS,'allSevenSavedCallersWholeExecuted':True,'oldCallersOrOldTopLevelSuitesExecuted':False,'largeArtifactStreamsRepeated':False,'actualProductionRequestValidation':'parent-owned separate whole outer qualification; not asserted by this protocol fixture','powerShell51StaticScope':'actual generated source and transport form/bounds only; no PowerShell parser execution','powerShell51NativeAcceptance':'UNRUN','nativeAcceptance':'UNRUN','realNetworkGuestOrHostApiOperations':False,'receiptOwnership':str(HERE)}
 raw=(json.dumps(summary,sort_keys=True,indent=2)+'\n').encode();(HERE/'summary.json').write_bytes(raw)
 print(json.dumps({'summary':str(HERE/'summary.json'),'sha256':sha(raw),'cases':len(results),'allPassed':True}),flush=True)

if __name__=='__main__':main()
