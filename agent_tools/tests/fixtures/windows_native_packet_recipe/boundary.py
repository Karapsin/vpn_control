"""Routine boundary reused from the frozen whole-loader/operator qualification.

run_pair(route, before_bytes, fixed_bytes, repo_root, output_root) returns full
``before`` and ``after`` receipts. The original loader and complete selected
operator run without rewriting or function replacement, including the actual
saved MCP client's main. Only filesystem/time/backend and SDK/stdio I/O are
explicit inert peers. Raw framing and dual EOF are modeled, never native proof.

All logical packet and owner-ledger paths exist only in World's memory. Real
artifacts are confined to caller-owned output_root. Server source is pinned data
only and is never compiled, imported, or executed. The real current repository
SourceSession loads registered production _request -> remote.validate before
inert admission/start. Canonical emitter/QGA bytes are read from repo_root and
pinned dynamically. No fixture depends on an ignored private runtime directory.

Configuration adaptations from the frozen qualifier: injected repo/logical
roots and input-file bytes; fixture-pinned client/server instead of live reads;
fixture-pinned SDK I/O peer loaded as a registered complete source module; full
receipt return value; one selected route's manifest/request data. The virtual
root has four components below repo_root so the original operators' parents[4]
resolves unchanged. World methods and execute retain the frozen methodology;
production request functions are never copied into this fixture.
"""
import argparse,builtins,contextlib,copy,hashlib,io,json,os,stat,sys,traceback,types
from pathlib import Path,PurePosixPath

FIXTURE_ROOT=Path(__file__).resolve().parent
LOADER_SHA='312b8035fba337a6306bcd080bbec73e359b650438941ce029681dd9ffa129c0'
PROVENANCE_SHA='b74da9af7526afcf3be95e8a2b4e639e5cef3afe57ada0345ce0e8a10daa6d99'
sha=lambda raw:hashlib.sha256(raw).hexdigest()

def production_request(request, ROOT):
 from agent_tools import source_module_loader
 with source_module_loader.request_scope(ROOT/'agent_tools'):
  owner=source_module_loader.adapter(ROOT/'agent_tools','ssh_program_execution')
  module=owner._session.module
  assert module.__file__==str(ROOT/'agent_tools/ssh_program_execution.py')
  assert sys.modules[module.__name__]is module
  result=owner._request('archlinux',request)
  owner._session.guard()
  return result,{'module':module.__name__,'source':module.__file__,'requestFunction':module._request.__name__,'remoteModule':module.remote.__name__,'remoteSource':module.remote.__file__,'completeRegisteredSourceSession':True}

class World:
 def __init__(self,label,operator_raw,manifest_raw,config,fault=None):
  ROOT=config['repo_root'];N=config['logical_root'];self.config=config
  self.label=label;self.route=label.split('-')[0];self.fault=fault;self.files={};self.outputs=set();self.dirs=set();self.fds={};self.nextfd=10;self.nextino=100
  self.events=[];self.imports=[];self.api=[];self.closed=[];self.scope_active=False;self.clock=50.;self.generation_change=False;self.parser_proofs=[];self.mcp_events=[];self.starts=0;self.collects=0
  self.manifest=json.loads(manifest_raw);self.pin=next(row for row in self.manifest['requests']if row['label']==label)
  self.repo=str(ROOT);self.operator_path=str(N/(self.route+'-operator.py'));self.out=str(N/'packet'/(label+'-original-operator'))
  self.add(self.operator_path,operator_raw);self.add(str(N/'packet/manifest.private.json'),manifest_raw)
  for path,data in config['input_files'].items():
   if path not in self.files:self.add(path,data)
  self.request=json.loads(self.files[self.pin['requestPath']]['data'])
  inner={'state':'qualified','probeId':self.pin['probeId'],'canonicalEmitterSha256':self.manifest['canonicalEmitterSha256'],'canonicalQgaSha256':self.manifest['canonicalQgaSha256'],'sourceClosing':True,**self.pin.get('resultJoins',{})}
  if fault=='inner-context':inner['probeId']='00000000-0000-4000-8000-000000000000'
  stdout=(json.dumps(inner,sort_keys=True)+'\n').encode();stderr=b''
  self.terminal={'state':'terminal','operationId':self.pin['operationId'],'exitCode':0,'capture':{'complete':True,'eof':{'stdout':True,'stderr':True}},'streams':{}}
  for name,raw in [('stdout',stdout),('stderr',stderr)]:self.terminal['streams'][name]={'retainedSha256':sha(raw),'receivedSha256':sha(raw),'bytes':len(raw),'receivedBytes':len(raw)}
  if fault=='raw-sha':self.terminal['streams']['stdout']['receivedSha256']='0'*64
  ledger=self.repo+'/.rag_index/ssh-program-execution/'+self.pin['operationId']
  self.add(ledger+'/stdout.private',stdout);self.add(ledger+'/stderr.private',stderr);self.add(ledger+'/owner-closed.json',(json.dumps({'sourceClosing':fault!='owner-closing'})+'\n').encode())
  self.original={p:bytes(row['data'])for p,row in self.files.items()}
  self.owner=self.Owner(self);world=self
  class VPath(PurePosixPath):
   def resolve(self,*args,**kwargs):return self
   def read_bytes(self):return world.read_bytes(str(self))
   def mkdir(self,mode=0o777,parents=False,exist_ok=False):return world.mkdir(str(self),mode,parents,exist_ok)
   def open(self,mode='r',encoding=None,**kwargs):
    assert mode=='x'and encoding=='utf-8';return world.text_open(str(self))
  self.pathlib=types.ModuleType('pathlib');self.pathlib.Path=VPath
  self.os=types.ModuleType('os')
  for name in ('O_RDONLY','O_NOFOLLOW','O_WRONLY','O_CREAT','O_EXCL','SEEK_SET'):setattr(self.os,name,getattr(os,name))
  self.os.open=self.open;self.os.read=self.read;self.os.write=self.write;self.os.close=self.close;self.os.lseek=self.seek
  self.os.fstat=lambda fd:self.info(self.fds[fd]['path']);self.os.stat=lambda p,**kwargs:self.info(str(p));self.os.lstat=lambda p:self.info(str(p));self.os.getuid=lambda:1000;self.os.getpid=lambda:51000
  self.os.fsync=lambda fd:self.events.append(['fsync',fd]);self.os.chmod=self.chmod;self.os.environ={'PATH':'inert-no-process-search'}
  self.sys=types.ModuleType('sys');self.sys.argv=['-c',self.operator_path,sha(operator_raw),label,sha(manifest_raw)];self.sys.path=[];self.sys.modules=sys.modules
  self.time=types.ModuleType('time');self.time.monotonic=lambda:self.clock;self.time.sleep=self.sleep
  self.agent_tools=types.ModuleType('agent_tools');self.agent_tools.source_module_loader=types.SimpleNamespace(request_scope=self.request_scope,adapter=self.adapter)
  self.mcp_peer=None
 def add(self,path,data):
  assert str(path)not in self.files
  self.nextino+=1;self.files[str(path)]={'data':bytearray(data),'ino':self.nextino,'mode':stat.S_IFREG|0o600}
 def info(self,path):
  if path not in self.files:raise FileNotFoundError(path)
  row=self.files[path];changed=self.generation_change and path==self.pin['sourcePath']
  return types.SimpleNamespace(st_dev=17,st_ino=row['ino'],st_mode=row['mode'],st_uid=1000,st_gid=1000,st_nlink=1,st_size=len(row['data']),st_mtime_ns=123456+int(changed),st_ctime_ns=123456)
 def gen(self,path):
  s=self.info(path);return[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
 def mkdir(self,path,mode,parents,exist_ok):
  assert(path==self.out or path.startswith(self.out+'/'))and mode==0o700 and not parents and not exist_ok
  if path in self.dirs:raise FileExistsError(path)
  self.dirs.add(path);self.events.append(['mkdir',path])
 def open(self,path,flags,mode=0o777):
  path=str(path);writable=bool(flags&os.O_WRONLY)
  if writable:
   assert path.startswith(self.out+'/')and flags==(os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW)and mode==0o600
   if path in self.files:raise FileExistsError(path)
   self.add(path,b'');self.outputs.add(path)
  else:assert flags==(os.O_RDONLY|os.O_NOFOLLOW);self.info(path)
  self.nextfd+=1;fd=self.nextfd;self.fds[fd]={'path':path,'offset':0,'write':writable};self.events.append(['open',fd,path,'write'if writable else'read']);return fd
 def read(self,fd,count):
  row=self.fds[fd];assert not row['write'];data=self.files[row['path']]['data'];raw=bytes(data[row['offset']:row['offset']+count]);row['offset']+=len(raw);return raw
 def seek(self,fd,offset,whence):
  assert whence==os.SEEK_SET and offset==0
  self.fds[fd]['offset']=offset;return offset
 def write(self,fd,raw):
  row=self.fds[fd];assert row['write']and row['path']in self.outputs
  data=self.files[row['path']]['data'];at=row['offset'];data[at:at+len(raw)]=raw;row['offset']+=len(raw);return len(raw)
 def close(self,fd):self.closed.append({'fd':fd,**self.fds[fd]});del self.fds[fd]
 def read_bytes(self,path):self.info(path);self.events.append(['path-read-bytes',path]);return bytes(self.files[path]['data'])
 def chmod(self,path,mode):assert mode==0o600;self.files[str(path)]['mode']=stat.S_IFREG|mode
 def text_open(self,path):
  world=self;fd=self.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  class Text(io.StringIO):
   def close(self):
    if not self.closed:world.write(fd,self.getvalue().encode());world.close(fd)
    super().close()
  return Text()
 def sleep(self,seconds):self.clock+=1000 if self.fault=='pending-deadline'else seconds
 @contextlib.contextmanager
 def request_scope(self,root):
  assert str(root)==self.repo+'/agent_tools'and not self.scope_active
  self.scope_active=True;self.api.append({'method':'request_scope.enter'})
  try:yield
  finally:self.scope_active=False;self.api.append({'method':'request_scope.exit'})
 def adapter(self,root,name):assert self.scope_active and str(root)==self.repo+'/agent_tools'and name=='ssh_program_execution';return self.owner
 def parse(self,request):
  value,proof=production_request(request,Path(self.repo));assert value=={'host':'archlinux',**request};self.parser_proofs.append(proof)
 def backend_start(self,request):
  self.parse(request);assert request==self.request and self.starts==0
  if self.fault=='admission-false':return{'ok':False,'state':'refused','reason':'inert-admission-refusal','operationId':request['operationId']}
  self.starts+=1;self.api.append({'method':'start','operationId':request['operationId']});return{'state':'pending','operationId':request['operationId']}
 def backend_collect(self,identity):
  assert self.starts==1 and identity=={'operationId':self.pin['operationId']};self.collects+=1;self.api.append({'method':'collect','identity':dict(identity)})
  if self.fault=='held-generation'and self.collects==1:self.generation_change=True
  if self.fault=='unknown-collect'and self.collects==2:return{'state':'unknown','operationId':self.pin['operationId']}
  if self.fault=='pending-deadline'or self.collects==1:return{'state':'pending','operationId':self.pin['operationId']}
  return copy.deepcopy(self.terminal)
 class Owner:
  def __init__(self,world):self.world=world;self._session=object()
  def admit_start(self,root,host,request):
   assert self.world.scope_active and str(root)==self.world.repo and host=='archlinux';self.world.parse(request);self.world.api.append({'method':'admit_start','operationId':request['operationId']});return{'ok':False}if self.world.fault=='admission-false'else{'ok':True}
  def start(self,root,host,request,source_context):assert self.world.scope_active and source_context is self._session;return self.world.backend_start(request)
  def collect(self,root,host,identity):assert self.world.scope_active;return self.world.backend_collect(identity)
 def mcp_backend(self,name,payload,context):
  assert name=='ssh_workflow'and payload['host']=='archlinux'and payload['timeout_seconds']==15
  if payload['action']=='program-start':return self.backend_start(payload['transfer'])
  assert payload['action']=='program-collect';return self.backend_collect(payload['identity'])
 def mcp_terminal(self,context,raw_streams,delivery):
  directory=str(context['directory']);assert directory.startswith(self.out+'/rpc-')
  terminal={'complete':True,'returnCode':0,'eof':{'stdout':True,'stderr':self.fault!='mcp-server-eof'},'overflow':False,'readError':False,'raw':{},'delivery':copy.deepcopy(delivery)}
  for name,raw in raw_streams.items():
   path=directory+'/server.'+name;self.add(path,raw);self.outputs.add(path);terminal['raw'][name]={'bytes':len(raw),'sha256':sha(raw),'generation':self.gen(path)}
  if self.fault=='mcp-raw-pin':terminal['raw']['stdout']['sha256']='0'*64
  if self.fault=='mcp-delivery':terminal['delivery']['fullyForwardedToolCallFrameCount']=0
  path=directory+'/server-terminal.json';self.add(path,json.dumps(terminal,sort_keys=True).encode());self.outputs.add(path)
 def import_peer(self,name,globals=None,locals=None,fromlist=(),level=0):
  self.imports.append({'name':name,'fromlist':list(fromlist or()),'level':level});assert level==0
  if name in ('os','sys','time','pathlib','agent_tools'):return getattr(self,name)
  if name in('mcp','mcp.client.stdio'):
   if self.mcp_peer is None:
    self.mcp_peer=self.config['mcp_peer_class'](backend=self.mcp_backend,emit_terminal=self.mcp_terminal,observe=lambda name,details:self.mcp_events.append({'event':name,'details':details}))
   return self.mcp_peer.mcp_module if name=='mcp'else self.mcp_peer.stdio_module
  assert name in ('hashlib','json','re','stat','asyncio','types','argparse','datetime','uuid','__future__'),('unqualified import',name)
  return builtins.__import__(name,globals,locals,fromlist,level)

def execute(label,source,manifest,destination,case_name,config,fault=None,expected_error=None,expected_started=True):
 ROOT=config['repo_root'];N=config['logical_root'];LOADER=FIXTURE_ROOT/'held-loader.source'
 loader_raw=config.get('loader_bytes',LOADER.read_bytes())
 world=config.get('world_class',World)(label,source,manifest,config,fault);normal=dict(vars(builtins));normal['__import__']=world.import_peer
 normal['open']=lambda *a,**k:(_ for _ in()).throw(AssertionError('ambient open forbidden'))
 namespace={'__name__':'__main__','__builtins__':normal};stdout=io.StringIO();stderr=io.StringIO();error=None;calls={};old_modules=dict(sys.modules)
 filenames={str(LOADER),world.operator_path,str(ROOT/'agent_tools/ssh_program_mcp_client.py'),str(ROOT/'agent_tools/ssh_program_execution.py'),str(ROOT/'agent_tools/ssh_program_execution_remote.py')}
 def profile(frame,event,arg):
  if event=='call'and frame.f_code.co_filename in filenames:
   name=frame.f_code.co_filename+'::'+frame.f_code.co_name;calls[name]=calls.get(name,0)+1
 prior=sys.getprofile()
 try:
  with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):sys.setprofile(profile);exec(compile(loader_raw,str(LOADER),'exec'),namespace,namespace)
 except BaseException as caught:error={'class':type(caught).__name__,'message':str(caught),'traceback':traceback.format_exc()}
 finally:
  sys.setprofile(prior)
  for name in list(sys.modules):
   if name.startswith('_windows_fixture_actual_mcp_client_'):
    if name in old_modules:sys.modules[name]=old_modules[name]
    else:sys.modules.pop(name,None)
 assert not world.fds,'own descriptor leaked';assert all(bytes(world.files[p]['data'])==data for p,data in world.original.items()),'source/ledger input mutated'
 assert world.starts==(1 if expected_started else 0),(case_name,error,world.api)
 if expected_error is None:
  assert error is None,(case_name,error);assert json.loads(stdout.getvalue().splitlines()[-1])['state']=='qualified';assert world.collects==2
  assert world.out+'/qualified.json'in world.outputs
 else:
  assert error and expected_error in error['message'],(case_name,error)
  if config.get('physical_loader_closing'):
   assert world.out+'/qualified.json'in world.outputs,'operator did not complete before loader closing refusal'
  else:
   failure=json.loads(world.read_bytes(world.out+'/original-failure.json'));assert failure['startedOnce']is expected_started and failure['replayAllowed']is False and failure['automaticCleanup']is False;assert world.out+'/qualified.json'not in world.files
 assert world.closed[-1]['path']==world.operator_path and world.closed[-1]['fd']==11,'outer source FD did not close last'
 if expected_started:assert world.parser_proofs and calls.get(str(ROOT/'agent_tools/ssh_program_execution.py')+'::_request',0)>0 and calls.get(str(ROOT/'agent_tools/ssh_program_execution_remote.py')+'::validate',0)>0
 if label.startswith('mcp-')and world.mcp_peer is not None:assert calls.get(str(ROOT/'agent_tools/ssh_program_mcp_client.py')+'::main',0)>0
 case=destination/case_name;case.mkdir(mode=0o700,exist_ok=False);(case/'operator.py').write_bytes(source);(case/'held-loader.py').write_bytes(loader_raw);outputs={}
 for index,path in enumerate(sorted(world.outputs)):
  data=bytes(world.files[path]['data']);saved=case/('virtual-output-'+str(index).zfill(4)+'.bin');saved.write_bytes(data);outputs[path]={'sha256':sha(data),'bytes':len(data),'retainedPath':str(saved)}
 receipt={'case':case_name,'label':label,'fault':fault,'operatorSha256':sha(source),'manifestSha256':sha(manifest),'loaderSha256':sha(loader_raw),'requestSha256':world.pin['requestSha256'],'sourceSha256':world.pin['sourceSha256'],'completeHeldLoaderOperatorNamespaces':True,'completeActualMcpClientNamespace':label.startswith('mcp-')and world.mcp_peer is not None,'initialGlobals':['__name__','__builtins__'],'noFunctionReplacement':True,'noSourceRewrite':True,'sourceLogicalPath':world.operator_path,'productionRequestProofs':world.parser_proofs,'functions':calls,'stdout':stdout.getvalue(),'stderr':stderr.getvalue(),'error':error,'startCount':world.starts,'collectCount':world.collects,'apiCalls':world.api,'imports':world.imports,'mcpIoPeerEvents':world.mcp_events,'fdClosures':world.closed,'allOwnDescriptorsClosed':True,'allInputsAndSyntheticLedgerUnchanged':True,'onlyInMemoryOperatorAndLedgerWrites':True,'outputs':outputs,'realApiNetworkNativeOperations':False,'nativeQualified':False}
 if config.get('physical_loader_closing'):
  assert not world.physical_fds and world.physical_proof['replacementCount']==1
  receipt['physicalSelfReplacement']=copy.deepcopy(world.physical_proof)
 data=(json.dumps(receipt,indent=2,sort_keys=True)+'\n').encode();(case/'receipt.json').write_bytes(data)
 return receipt

def fixture_bytes(name):
 provenance_raw=(FIXTURE_ROOT/'provenance.json').read_bytes();assert sha(provenance_raw)==PROVENANCE_SHA
 provenance=json.loads(provenance_raw)
 record=provenance['fixtures'][name];raw=(FIXTURE_ROOT/name).read_bytes()
 assert len(raw)==record['bytes'] and sha(raw)==record['sha256'],name
 return raw


def load_mcp_peer():
 name='_windows_native_packet_recipe_inert_mcp_peer'
 raw=fixture_bytes('mcp_io_peer.source');module=types.ModuleType(name)
 module.__file__=str(FIXTURE_ROOT/'mcp_io_peer.source')
 prior=sys.modules.get(name);sys.modules[name]=module
 try:
  exec(compile(raw,module.__file__,'exec'),module.__dict__,module.__dict__)
  assert module.MCPIoPeer.__init__.__globals__ is module.__dict__
  return module.MCPIoPeer
 finally:
  if prior is None:sys.modules.pop(name,None)
  else:sys.modules[name]=prior


def run_pair(route,before_bytes,fixed_bytes,repo_root,output_root):
 assert route in ('direct','mcp')
 assert type(before_bytes)is bytes and type(fixed_bytes)is bytes
 assert before_bytes==fixture_bytes('operator-'+route+'.before.source')
 repo_root=Path(repo_root).resolve(strict=True);output_root=Path(output_root).resolve(strict=True)
 assert repo_root.is_dir() and output_root.is_dir()
 logical_root=repo_root/'.inert-fixture'/'windows'/'native'/'packet'
 assert (logical_root/(route+'-operator.py')).parents[4]==repo_root
 label=route+'-canonical';operation_id='c3f67b0f-9c98-41df-8545-b69524e1b150'if route=='mcp'else'b7b993d9-653b-41ac-b3ae-4f71a6ef40f7'
 probe_id='07ab780d-0434-4803-9964-d7815bafcbec'if route=='mcp'else'645dfb0b-eb3c-483c-a9a0-6e2be5f665e4'
 submitted=b'pass\n'
 request={'operationId':operation_id,'program':{'language':'python3','source':submitted.decode(),'args':[],'cwd':'/','targetContext':{'kind':'ssh','uid':1000,'principal':'inert-fixture','home':'/home/inert-fixture','bootId':'25515f23-b966-4c3a-ae63-d38452375578'}}}
 request_raw=(json.dumps(request,sort_keys=True)+'\n').encode()
 emitter=(repo_root/'agent_tools/windows_artifact_transfer.py').read_bytes()
 qga=(repo_root/'agent_tools/windows_qga_transfer.py').read_bytes()
 mcp_client=fixture_bytes('ssh_program_mcp_client.source');server=fixture_bytes('mcp_server.source')
 assert sha(fixture_bytes('held-loader.source'))==LOADER_SHA
 config={'repo_root':repo_root,'logical_root':logical_root,'mcp_peer_class':load_mcp_peer(),
         'input_files':{str(logical_root/'packet'/(label+'.request.private.json')):request_raw,
                        str(logical_root/'source.py'):submitted,
                        str(repo_root/'agent_tools/windows_artifact_transfer.py'):emitter,
                        str(repo_root/'agent_tools/windows_qga_transfer.py'):qga,
                        str(repo_root/'agent_tools/ssh_program_mcp_client.py'):mcp_client,
                        str(repo_root/'agent_tools/mcp_server.py'):server}}
 def manifest_for(operator):
  return (json.dumps({'canonicalEmitterSha256':sha(emitter),'canonicalQgaSha256':sha(qga),
   'operatorSourcePath':str(logical_root/(route+'-operator.py')),'operatorSourceSha256':sha(operator),
   'requests':[{'label':label,'operationId':operation_id,'probeId':probe_id,
    'requestPath':str(logical_root/'packet'/(label+'.request.private.json')),'requestSha256':sha(request_raw),
    'sourcePath':str(logical_root/'source.py'),'sourceSha256':sha(submitted),'sourceBytes':len(submitted),
    'sourcePins':[],'resultJoins':{}}]},sort_keys=True)+'\n').encode()
 original_sys_path=list(sys.path);sys.path.insert(0,str(repo_root))
 try:
  before=execute(label,before_bytes,manifest_for(before_bytes),output_root,route+'-before',config,
                 expected_error='retained-api-native-requests-v2/manifest.private.json',expected_started=False)
  after=execute(label,fixed_bytes,manifest_for(fixed_bytes),output_root,route+'-after',config)
  return {'before':before,'after':after}
 finally:
  sys.path[:]=original_sys_path


class PhysicalWorld(World):
 """Only the MCP self source uses real, owned temporary file descriptors."""
 def __init__(self,label,operator_raw,manifest_raw,config,fault=None):
  self.physical_path=config['physical_path'];self.physical_fds={}
  self.physical_proof={'replacementCount':0,'physicalPath':str(self.physical_path),
                       'expectedSha256':sha(operator_raw)}
  descriptor=os.open(self.physical_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:
   at=0
   while at<len(operator_raw):
    count=os.write(descriptor,operator_raw[at:]);assert count>0;at+=count
   os.fsync(descriptor)
  finally:os.close(descriptor)
  super().__init__(label,operator_raw,manifest_raw,config,fault)
  self.os.getuid=os.getuid
  self.os.fstat=self.physical_fstat
  self.physical_proof['logicalPath']=self.operator_path

 def info(self,path):
  if path==self.operator_path:return os.stat(self.physical_path,follow_symlinks=False)
  value=super().info(path);value.st_uid=os.getuid();value.st_gid=os.getgid();return value

 def physical_fstat(self,fd):
  if fd in self.physical_fds:return os.fstat(self.physical_fds[fd])
  return self.info(self.fds[fd]['path'])

 def open(self,path,flags,mode=0o777):
  logical_fd=super().open(path,flags,mode)
  if str(path)==self.operator_path:
   assert logical_fd==11 and flags==(os.O_RDONLY|os.O_NOFOLLOW)
   physical_fd=os.open(self.physical_path,flags)
   self.physical_fds[logical_fd]=physical_fd
   self.physical_proof.update(logicalFd=logical_fd,physicalFd=physical_fd,
      heldOpeningGeneration=self.native_generation(os.fstat(physical_fd)),
      namedOpeningGeneration=self.native_generation(os.lstat(self.physical_path)))
  return logical_fd

 def read(self,fd,count):
  if fd in self.physical_fds:
   raw=os.read(self.physical_fds[fd],count);self.fds[fd]['offset']+=len(raw);return raw
  return super().read(fd,count)

 def seek(self,fd,offset,whence):
  if fd in self.physical_fds:os.lseek(self.physical_fds[fd],offset,whence)
  return super().seek(fd,offset,whence)

 def close(self,fd):
  if fd in self.physical_fds:
   physical_fd=self.physical_fds.pop(fd)
   self.physical_proof['heldGenerationBeforeClose']=self.native_generation(os.fstat(physical_fd))
   os.close(physical_fd);self.physical_proof['heldSourceDescriptorClosed']=True
  return super().close(fd)

 @staticmethod
 def native_generation(value):
  return [value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,
          value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns]

 def backend_start(self,request):
  # This hook is reached only after the loader's opening guard and after the
  # actual client's initialization/inventory/call path. No source function is
  # replaced. The ordinary backend still parses the request before inert START.
  assert self.physical_proof['replacementCount']==0 and set(self.physical_fds)=={11}
  physical_fd=self.physical_fds[11];before=os.fstat(physical_fd)
  raw=os.pread(physical_fd,before.st_size+1,0)
  assert len(raw)==before.st_size and sha(raw)==self.physical_proof['expectedSha256']
  replacement=self.physical_path.with_name(self.physical_path.name+'.replacement')
  descriptor=os.open(replacement,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:
   at=0
   while at<len(raw):
    count=os.write(descriptor,raw[at:]);assert count>0;at+=count
   os.fsync(descriptor)
  finally:os.close(descriptor)
  os.replace(replacement,self.physical_path)
  held=os.fstat(physical_fd);named=os.lstat(self.physical_path)
  named_raw=self.physical_path.read_bytes();held_raw=os.pread(physical_fd,held.st_size+1,0)
  assert named.st_ino!=held.st_ino and held.st_ino==before.st_ino
  assert named_raw==held_raw==raw
  self.physical_proof.update(replacementCount=1,heldInode=held.st_ino,
    namedInode=named.st_ino,namedReplacementInode=named.st_ino,heldSha256=sha(held_raw),namedSha256=sha(named_raw),
    sameBytes=True,heldGenerationAfterReplacement=self.native_generation(held),
    namedGenerationAfterReplacement=self.native_generation(named))
  return super().backend_start(request)


def run_loader_closing_pair(before_loader_bytes,fixed_loader_bytes_or_None,
                            fixed_direct_bytes,fixed_mcp_bytes,repo_root,output_root):
 """Physical same-byte replacement RED, then optional live rendered loader GREEN.

 The unchanged MCP operator holds DIRECT as its manifest source, matching the
 production packet. Thus only the outer loader owns MCP self FD 11. Replacing
 that physical named file cannot be detected by the inner operator's holds.
 """
 assert before_loader_bytes==fixture_bytes('held-loader.source')
 assert type(fixed_direct_bytes)is bytes and type(fixed_mcp_bytes)is bytes
 assert sha(fixed_direct_bytes)=='dbbf35f31a94100d76fd3db1670d2bf3e39e825fe5dc7135644b154cd4d928ba'
 assert sha(fixed_mcp_bytes)=='0d2adf9b107f9ff59824af6edc07f5716248665b25e75b625515b8e5e1391f24'
 assert fixed_loader_bytes_or_None is None or type(fixed_loader_bytes_or_None)is bytes
 repo_root=Path(repo_root).resolve(strict=True);output_root=Path(output_root).resolve(strict=True)
 assert repo_root.is_dir() and output_root.is_dir()
 logical_root=repo_root/'.inert-fixture'/'windows'/'native'/'packet';label='mcp-canonical'
 operation_id='c3f67b0f-9c98-41df-8545-b69524e1b150';probe_id='07ab780d-0434-4803-9964-d7815bafcbec'
 submitted=b'pass\n'
 request={'operationId':operation_id,'program':{'language':'python3','source':submitted.decode(),
  'args':[],'cwd':'/','targetContext':{'kind':'ssh','uid':1000,'principal':'inert-fixture',
  'home':'/home/inert-fixture','bootId':'25515f23-b966-4c3a-ae63-d38452375578'}}}
 request_raw=(json.dumps(request,sort_keys=True)+'\n').encode()
 emitter=(repo_root/'agent_tools/windows_artifact_transfer.py').read_bytes()
 qga=(repo_root/'agent_tools/windows_qga_transfer.py').read_bytes()
 config={'repo_root':repo_root,'logical_root':logical_root,'mcp_peer_class':load_mcp_peer(),
  'world_class':PhysicalWorld,'physical_loader_closing':True,
  'input_files':{str(logical_root/'direct-operator.py'):fixed_direct_bytes,
   str(logical_root/'packet'/(label+'.request.private.json')):request_raw,
   str(logical_root/'source.py'):submitted,
   str(repo_root/'agent_tools/windows_artifact_transfer.py'):emitter,
   str(repo_root/'agent_tools/windows_qga_transfer.py'):qga,
   str(repo_root/'agent_tools/ssh_program_mcp_client.py'):fixture_bytes('ssh_program_mcp_client.source'),
   str(repo_root/'agent_tools/mcp_server.py'):fixture_bytes('mcp_server.source')}}
 manifest=(json.dumps({'canonicalEmitterSha256':sha(emitter),'canonicalQgaSha256':sha(qga),
  'operatorSourcePath':str(logical_root/'direct-operator.py'),'operatorSourceSha256':sha(fixed_direct_bytes),
  'requests':[{'label':label,'operationId':operation_id,'probeId':probe_id,
   'requestPath':str(logical_root/'packet'/(label+'.request.private.json')),'requestSha256':sha(request_raw),
   'sourcePath':str(logical_root/'source.py'),'sourceSha256':sha(submitted),'sourceBytes':len(submitted),
   'sourcePins':[],'resultJoins':{}}]},sort_keys=True)+'\n').encode()
 original_sys_path=list(sys.path);sys.path.insert(0,str(repo_root))
 try:
  config.update(loader_bytes=before_loader_bytes,physical_path=output_root/'mcp-self-before.py')
  before=execute(label,fixed_mcp_bytes,manifest,output_root,'loader-closing-before',config)
  after=None
  if fixed_loader_bytes_or_None is not None:
   config.update(loader_bytes=fixed_loader_bytes_or_None,physical_path=output_root/'mcp-self-after.py')
   after=execute(label,fixed_mcp_bytes,manifest,output_root,'loader-closing-after',config,
                 expected_error='operator_source_changed')
   assert str(FIXTURE_ROOT/'held-loader.source')in after['error']['traceback']
  return {'before':before,'after':after}
 finally:
  sys.path[:]=original_sys_path


def run_loader_systemexit_case(loader_bytes,output_root,case):
 """Execute complete saved loader + authentic harmless entry with real owned IO.

 Only sys.argv is an explicit module peer. Entry source bytes are never changed;
 filesystem calls use caller-owned temporary paths. This is a local Python
 exception/argv proof, not execution of the SDK or a native server.
 """
 assert type(loader_bytes)is bytes and case in ('replacement','three-argv')
 output_root=Path(output_root).resolve(strict=True)
 leaf=output_root/case;leaf.mkdir(mode=0o700,exist_ok=False)
 name='systemexit-'+('replacement'if case=='replacement'else'three-argv')+'.entry.source'
 source=fixture_bytes(name);path=leaf/'entry.py'
 descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  at=0
  while at<len(source):
   count=os.write(descriptor,source[at:]);assert count>0;at+=count
 finally:os.close(descriptor)
 opening=os.lstat(path);source_sha=sha(source)
 fake_sys=types.ModuleType('sys')
 extra=['connection-direct-channel-prepare','new-channel-prepare','owned-identity.json']if case=='three-argv'else[]
 fake_sys.argv=['-c',str(path),source_sha,'inert-label','0'*64,*extra]
 def import_peer(name,globals=None,locals=None,fromlist=(),level=0):
  if name=='sys'and level==0:return fake_sys
  return builtins.__import__(name,globals,locals,fromlist,level)
 normal=dict(vars(builtins));normal['__import__']=import_peer
 namespace={'__name__':'__main__','__builtins__':normal};error=None
 try:exec(compile(loader_bytes,str(leaf/'held-loader.py'),'exec'),namespace,namespace)
 except BaseException as caught:
  error={'class':type(caught).__name__,'message':str(caught),
         'code':caught.code if type(caught)is SystemExit else None,
         'contextClass':type(caught.__context__).__name__ if caught.__context__ is not None else None}
 fd=namespace['fd'];closed=False
 try:os.fstat(fd)
 except OSError as caught:
  assert caught.errno==9;closed=True
 assert closed,'whole loader leaked original held source descriptor'
 closing=os.lstat(path);unchanged=path.read_bytes()==source
 receipt={'case':case,'loaderSha256':sha(loader_bytes),'entrySha256':source_sha,
  'entryBytes':len(source),'entryPath':str(path),'completeSavedNamespaces':True,
  'initialGlobals':['__name__','__builtins__'],'declaredImportPeer':['sys.argv'],
  'sourceBytesUnmodified':True,'noFunctionReplacement':True,'sourceAdmitted':namespace.get('source_admitted'),
  'pathReplaced':opening.st_ino!=closing.st_ino,'sameByteSource':unchanged,
  'openingGeneration':PhysicalWorld.native_generation(opening),
  'closingNamedGeneration':PhysicalWorld.native_generation(closing),
  'closingHashRan':namespace.get('closing_size')==len(source),
  'error':error,'allOwnDescriptorsClosed':closed,
  'receivedEntryArguments':fake_sys.argv[1:],
  'actualSDKInvocations':0,'realApiNetworkNativeOperations':False,'nativeQualified':False}
 assert unchanged
 if case=='replacement':assert receipt['pathReplaced']
 else:assert not receipt['pathReplaced']
 (leaf/'held-loader.py').write_bytes(loader_bytes)
 (leaf/'receipt.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
 return receipt
