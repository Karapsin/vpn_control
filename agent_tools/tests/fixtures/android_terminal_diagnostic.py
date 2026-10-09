"""Actual public REMOTE/ROOT_BOOT under harmless owned pipe/process callbacks.

No external child, sudo, credential, current authority, constructor or native
programme is used. The only programme is a literal phase print plus a declared
fixture-clock suspension. SIGKILL is represented by a fixture process callback.
"""
import ast,base64,builtins,hashlib,io,json,marshal,os,resource,select,sys,threading,types,unittest
from pathlib import Path
from agent_tools import android_installer_direct_transport as direct
HERE=Path(__file__).resolve().parent
PHASE=os.environ.get('TERMINAL_CONTROL_PHASE','final')
PROGRAMME=b'import time\nprint("OWNED_HARMLESS_PHASE", flush=True)\ntime.sleep(2000)\n'

class Pipes:
 def __init__(self):self.fds=set();self.inodes=set();self.observations=[]
 def pair(self):
  values=os.pipe();self.fds.update(values);self.inodes.update(os.fstat(fd).st_ino for fd in values);return values
 def dup(self,fd):value=os.dup(fd);self.fds.add(value);return value
 def close(self,fd):
  if fd in self.fds:self.fds.remove(fd);os.close(fd)
 def all(self):
  for fd in list(self.fds):self.close(fd)
 def stat(self,fd):
  value=os.fstat(fd)
  if value.st_ino not in self.inodes:raise AssertionError('nonfixture_pipe_descriptor')
  values={name:getattr(value,name)for name in ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')};self.observations.append({'observedRealMode':value.st_mode,'observedRealUid':value.st_uid,'observedRealGid':value.st_gid,'observedRealLinks':value.st_nlink,'declaredUid':1000,'declaredGid':1000,'declaredLinks':1});values.update(st_uid=1000,st_gid=1000,st_nlink=1)
  return types.SimpleNamespace(**values)
 def os(self,uid):
  module=types.SimpleNamespace(**vars(os));module.getuid=module.geteuid=module.getgid=module.getegid=lambda:uid;module.getgroups=lambda:[uid]
  module.fstat=self.stat;module.dup=self.dup;module.close=self.close
  return module

class Stream:
 def __init__(self,pipes,fd):self.pipes=pipes;self.fd=fd;self.closed=False
 def fileno(self):return self.fd
 def close(self):
  if not self.closed:self.closed=True;self.pipes.close(self.fd)

def printer(system):
 def emit(*values,sep=' ',end='\n',file=None,flush=False):
  destination=system.stdout if file is None else file;destination.write(sep.join(map(str,values))+end)
  if flush:destination.flush()
 return emit

def imports(mapping,system):
 original=builtins.__import__
 return dict(vars(builtins),__import__=lambda name,*a,**k:mapping[name]if name in mapping else original(name,*a,**k),print=printer(system))

class HarmlessProcess:
 def __init__(self,fixture,boot):
  self.fixture=fixture;self.pid=4242;self.returncode=None;self.killCalls=0;self.killed=False;self.threadError=None
  incoming,writer=fixture.pipes.pair();out,output=fixture.pipes.pair();err,stderr_fd=fixture.pipes.pair()
  self.stdin=Stream(fixture.pipes,writer);self.stdout=Stream(fixture.pipes,out);self.stderr=Stream(fixture.pipes,err)
  self.incoming=incoming;self.output=output;self.error=stderr_fd;self.resume=threading.Event()
  class Output:
   def write(inner,value):
    if self.killed:return len(value) # simulated killed child never releases late buffered bytes
    raw=value.encode();os.write(output,raw);return len(value)
   def flush(inner):pass
  system=types.SimpleNamespace(stdin=Stream(fixture.pipes,incoming),stdout=Output())
  limits=[(1048576,1048576)];fixture.limitCalls=[]
  def set_limit(kind,value):limits[0]=value;fixture.limitCalls.append(list(value))
  resources=types.SimpleNamespace(RLIMIT_FSIZE=resource.RLIMIT_FSIZE,getrlimit=lambda kind:limits[0],setrlimit=set_limit)
  def suspend(seconds):
   fixture.phaseBuffer=system.stdout.getvalue().encode();fixture.phaseSeen.set()
   if not self.resume.wait(2):raise RuntimeError('harmless_fixture_suspend_deadline')
   raise RuntimeError('declared_harmless_process_killed')
  clock=types.SimpleNamespace(monotonic=lambda:0.,sleep=suspend)
  modules={'sys':system,'os':fixture.pipes.os(0),'resource':resources,'time':clock,'select':select}
  namespace={'__builtins__':imports(modules,system)}
  def execute():
   try:exec(compile(boot,'<actual-root-boot-owned-pipe-control>','exec',dont_inherit=True),namespace)
   except BaseException as error:
    self.threadError={'type':type(error).__name__,'message':str(error)}
    if not self.killed:self.resume.wait(2)
   finally:
    if self.returncode is None:self.returncode=1 if self.threadError else 0
    for fd in (incoming,output,stderr_fd):fixture.pipes.close(fd)
  self.thread=threading.Thread(target=execute,name='owned-harmless-root-boot-fixture',daemon=True);self.thread.start()
 def poll(self):return self.returncode
 def kill(self):
  self.killCalls+=1;self.killed=True;self.returncode=-9
  self.fixture.pipes.close(self.output);self.fixture.pipes.close(self.error);self.resume.set()
 def wait(self,timeout):
  if self.fixture.mode=='child_wait_timeout'and not self.killed and not getattr(self,'waitInjected',False):
   self.waitInjected=True;raise __import__('subprocess').TimeoutExpired(['owned-harmless-child'],timeout)
  self.thread.join(min(timeout,2))
  if self.thread.is_alive():raise AssertionError('harmless_fixture_thread_not_joined')
  return self.returncode

class ReceiverFixture:
 def __init__(self,mode='timeout'):self.mode=mode;self.injected=False;self.pipes=Pipes();self.phaseSeen=threading.Event();self.phaseBuffer=b'';self.process=None;self.limitCalls=[];self.clockAfterPhase=0. if mode=='child_wait_timeout'else 1201.
 def execute(self,remote,boot):
  reader,writer=self.pipes.pair();os.write(writer,b'harmless-frame\n'+PROGRAMME);self.pipes.close(writer)
  output=io.StringIO();system=types.SimpleNamespace(stdin=Stream(self.pipes,reader),stdout=output)
  def child(argv,**kwargs):
   if argv[:9]!=['/usr/bin/sudo','-S','-p','','--','/usr/bin/python3','-I','-B','-c']or argv[9]!=boot:raise AssertionError('fixture_process_argv_changed')
   self.process=HarmlessProcess(self,boot)
   if self.mode=='unknown_observations':del self.process.pid
   return self.process
  process=types.SimpleNamespace(Popen=child,PIPE=-1,TimeoutExpired=__import__('subprocess').TimeoutExpired)
  clock=types.SimpleNamespace(monotonic=lambda:self.clockAfterPhase if self.phaseSeen.is_set()else 0.,time=lambda:float('nan')if self.mode=='unknown_observations'else 1730000000.)
  def ready(readers,writers,exceptional,timeout):
   if self.mode=='other_value_error' and writers and self.process is not None and not self.injected:
    self.injected=True;raise ValueError('declared_distinct_owned_callback_ValueError')
   if writers or self.process is None or self.process.killed:return select.select(readers,writers,exceptional,min(timeout,.1))
   if not self.phaseSeen.wait(1):raise AssertionError('harmless_phase_not_reached:'+repr(self.process.threadError))
   if self.mode=='child_wait_timeout':
    self.pipes.close(self.process.output);self.pipes.close(self.process.error)
    return select.select(readers,writers,exceptional,min(timeout,.1))
   return [],[],[]
  modules={'sys':system,'os':self.pipes.os(1000),'subprocess':process,'time':clock,'select':types.SimpleNamespace(select=ready)}
  ns={'__builtins__':imports(modules,system)}
  try:
   exec(compile(remote,'<actual-remote-owned-pipe-timeout-control>','exec',dont_inherit=True),ns)
   if self.mode=='timeout' and not self.phaseSeen.is_set():raise AssertionError('fixture_phase_not_buffered')
   return output.getvalue().encode(),ns
  finally:
   if self.process is not None and self.process.thread.is_alive():self.process.kill();self.process.wait(2)
   self.pipes.all()

class Capture:
 def __init__(self,path,held):self.path=path;self.held=held;self.rows={};path.mkdir(mode=0o700)
 def create(self,name,raw):
  path=self.path/name;direct.bundle._write(path,raw);body,pin=direct.snapshot(path)
  self.held.append(direct._dispatch_hold(path,pin,body));self.rows[name]=body;return pin


# Frozen pre-diagnostic REMOTE; source bytes came from canonical 8b461c2c.
HISTORICAL_REMOTE="\nimport sys,os,select,time,subprocess,hashlib,base64,json\nEXPECTED_BYTES=__BYTES__;EXPECTED_SHA=__SHA__;ROOT_BOOT=__BOOT__\ndef host_identity():\n value={'uid':os.getuid(),'euid':os.geteuid(),'gid':os.getgid(),'egid':os.getegid(),'groups':sorted(os.getgroups())}\n if any(value[key]!=1000 for key in ('uid','euid','gid','egid')) or len(value['groups'])>64 or any(type(x)is not int or x<0 for x in value['groups']):raise ValueError('baseline_receiver_uid_unadmitted')\n return value\ninitial=host_identity();secret=bytearray();raw=bytearray();deadline=time.monotonic()+120\nwhile not secret.endswith(b'\\n'):\n if time.monotonic()>=deadline:raise ValueError('baseline_source_receive_timeout')\n ready,_,_=select.select([sys.stdin],[],[],1)\n if not ready:continue\n part=os.read(sys.stdin.fileno(),1)\n if not part or len(secret)>=513:raise ValueError('baseline_credential_envelope_unknown')\n secret.extend(part)\nif not 1<len(secret)<=513 or b'\\0' in secret or b'\\r' in secret:raise ValueError('baseline_credential_envelope_unknown')\nwhile True:\n remaining=deadline-time.monotonic()\n if remaining<=0:raise ValueError('baseline_source_receive_timeout')\n ready,_,_=select.select([sys.stdin],[],[],min(remaining,1))\n if not ready:continue\n part=os.read(sys.stdin.fileno(),min(65536,EXPECTED_BYTES+1-len(raw)))\n if not part:break\n raw.extend(part)\n if len(raw)>EXPECTED_BYTES:raise ValueError('baseline_source_receive_limit')\nif len(raw)!=EXPECTED_BYTES or hashlib.sha256(raw).hexdigest()!=EXPECTED_SHA or host_identity()!=initial:raise ValueError('baseline_source_changed')\nheader=('VPNCONTROL_COMPONENT_SOURCE_V1 '+str(EXPECTED_BYTES)+' '+EXPECTED_SHA+'\\n').encode('ascii')\np=None;streams={};failure=None;payload=secret+header+raw;secret=bytearray();raw=bytearray()\ntry:\n p=subprocess.Popen(['/usr/bin/sudo','-S','-p','','--','/usr/bin/python3','-I','-B','-c',ROOT_BOOT],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)\n streams={p.stdout:bytearray(),p.stderr:bytearray()};opened=list(streams);deadline=time.monotonic()+1200;offset=0;writer=p.stdin\n os.set_blocking(writer.fileno(),False)\n while opened or writer is not None:\n  remaining=deadline-time.monotonic()\n  if remaining<=0:raise ValueError('baseline_remote_collection_timeout')\n  ready,writable,_=select.select(opened,[writer] if writer is not None else [],[],min(remaining,1))\n  if writable:\n   sent=os.write(writer.fileno(),payload[offset:offset+65536])\n   if sent<=0:raise ValueError('baseline_root_stdin_write_unknown')\n   payload[offset:offset+sent]=b'\\0'*sent;offset+=sent\n   if offset==len(payload):writer.close();writer=None;payload.clear()\n  for stream in ready:\n   part=os.read(stream.fileno(),65536)\n   if not part:opened.remove(stream);continue\n   streams[stream].extend(part)\n   if sum(map(len,streams.values()))>201326592:raise ValueError('baseline_remote_collection_limit')\n p.wait(timeout=max(.01,deadline-time.monotonic()))\nexcept Exception as error:failure=type(error).__name__\nfinally:\n payload.clear();secret=bytearray()\n if p is not None:\n  if p.stdin is not None and not p.stdin.closed:p.stdin.close()\n  if p.poll()is None:p.kill();p.wait(timeout=5)\n  remaining_streams=[stream for stream in streams if not stream.closed];drain_deadline=time.monotonic()+5\n  while remaining_streams and time.monotonic()<drain_deadline:\n   ready,_,_=select.select(remaining_streams,[],[],.1)\n   for stream in ready:\n    part=os.read(stream.fileno(),65536)\n    if not part:remaining_streams.remove(stream);continue\n    streams[stream].extend(part)\n    if sum(map(len,streams.values()))>201326592:failure='baseline_remote_collection_limit';remaining_streams=[];break\n for stream in streams:stream.close()\n try:\n  if host_identity()!=initial:failure='baseline_receiver_identity_changed'\n except Exception:failure='baseline_receiver_identity_unknown'\n out=bytes(streams.get(getattr(p,'stdout',None),b''));err=bytes(streams.get(getattr(p,'stderr',None),b''))\n print(json.dumps({'schema':1,'kind':'api29-component-baseline-terminal','returncode':p.returncode if p is not None else None,'failure':failure,'hostIdentity':initial,'sourceBytes':EXPECTED_BYTES,'sourceSha256':EXPECTED_SHA,'stdoutBytes':len(out),'stdoutSha256':hashlib.sha256(out).hexdigest(),'stderrBytes':len(err),'stderrSha256':hashlib.sha256(err).hexdigest()},sort_keys=True,separators=(',',':')),flush=True)\n for name,data in [('out',out),('err',err)]:\n  for offset in range(0,len(data),524288):print(name+':'+base64.b64encode(data[offset:offset+524288]).decode(),flush=True)\n"
HISTORICAL_REMOTE_SHA256='b86307c4f1a4744b03fb35f6ff7f9c116cd69ff34a8c003b0f77b16cbcfadb5b'
ROOT_BOOT_SHA256='401b9ab1821b1022cb79f9ddc0d751186a31f0fb98aab7ac0fe412a415d93512'
HISTORICAL_COLLECT_SHA256='360e50fa0d333b3ea4b863f81e61a620b29a0ebd12b9ce5604c1ec9372507703'

# Genuine collect() beforeimage extracted by AST from canonical8b461; not current production.
HISTORICAL_COLLECT_ORIGIN_SHA256='8b461c2c2d3a24cb6d83a64c93099d4ed3328e3b396637a81e846f13ce66c4d0'
HISTORICAL_COLLECT_SOURCE="def collect(state,credential):\n    capture=state['capture'];streams={};process=None;failure=None;payload=bytearray(credential)+state['source'];credential=b''\n    durable={}\n    def retain(stream,part):\n        record=durable[stream];record['pending'].extend(part)\n        while len(record['pending'])>=CHUNK:\n            raw=bytes(record['pending'][:CHUNK]);del record['pending'][:CHUNK]\n            name=record['name']+'-'+str(len(record['chunks']))+'.private'\n            pin=capture.create(name,raw);record['chunks'].append({'name':name,'pin':pin})\n        streams[stream].extend(part)\n    def finish(name,stream):\n        if stream is None:\n            archive(capture,name,b'');return\n        record=durable[stream]\n        if record['pending']:\n            child=name+'-'+str(len(record['chunks']))+'.private';pin=capture.create(child,bytes(record['pending']))\n            record['chunks'].append({'name':child,'pin':pin});record['pending'].clear()\n        raw=bytes(streams[stream]);manifest={'bytes':len(raw),'sha256':digest(raw),'chunks':record['chunks']}\n        capture.create(name+'-manifest.json',encoded(manifest))\n    try:\n        process=subprocess.Popen(state['argv'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)\n        streams={process.stdout:bytearray(),process.stderr:bytearray()}\n        durable={stream:{'name':name,'pending':bytearray(),'chunks':[]} for name,stream in [('stdout',process.stdout),('stderr',process.stderr)]}\n        deadline=time.monotonic()+1250\n        capture.create('handle.json',encoded({'pid':process.pid,'started':time.time(),'deadlineSeconds':1250}))\n        os.set_blocking(process.stdin.fileno(),False);opened=list(streams);offset=0;writer=process.stdin\n        while opened or writer is not None:\n            remaining=deadline-time.monotonic()\n            if remaining<=0:raise ValueError('baseline_local_collection_timeout')\n            ready,writable,_=select.select(opened,[writer] if writer is not None else [],[],min(remaining,1))\n            if writable:\n                end=min(offset+65536,len(payload));sent=os.write(writer.fileno(),payload[offset:end])\n                if sent<=0:raise ValueError('baseline_stdin_transfer_unknown')\n                payload[offset:offset+sent]=b'\\0'*sent;offset+=sent\n                if offset==len(payload):writer.close();writer=None;payload.clear()\n            for stream in ready:\n                part=os.read(stream.fileno(),65536)\n                if not part:opened.remove(stream);continue\n                retain(stream,part)\n                if sum(map(len,streams.values()))>STREAM_LIMIT:raise ValueError('baseline_local_collection_limit')\n        process.wait(timeout=max(.01,deadline-time.monotonic()))\n    except Exception as error:failure=type(error).__name__\n    finally:\n        payload.clear()\n        if process is not None:\n            if process.stdin is not None and not process.stdin.closed:process.stdin.close()\n            if process.poll()is None:process.kill();process.wait(timeout=5)\n            # Retain bytes already in both pipes after a timeout or writer loss.\n            remaining_streams=[stream for stream in streams if not stream.closed]\n            drain_deadline=time.monotonic()+5\n            while remaining_streams and time.monotonic()<drain_deadline:\n                ready,_,_=select.select(remaining_streams,[],[],.1)\n                for stream in ready:\n                    part=os.read(stream.fileno(),65536)\n                    if not part:remaining_streams.remove(stream);continue\n                    retain(stream,part)\n                    if sum(map(len,streams.values()))>STREAM_LIMIT:failure='baseline_local_collection_limit';remaining_streams=[];break\n        for name,stream in [('stdout',getattr(process,'stdout',None)),('stderr',getattr(process,'stderr',None))]:\n            finish(name,stream)\n            if stream is not None:stream.close()\n        capture.create('exit.json',encoded({'returncode':process.returncode if process is not None else None,'failure':failure}))\n        os.fsync(capture.fd)\n    if process is None or failure is not None or type(process.returncode)is not int or process.returncode!=0:\n        raise ValueError('baseline_transport_unknown_raw_retained')\n    if streams[process.stderr]:raise ValueError('baseline_ssh_stderr_unknown_raw_retained')\n    return bytes(streams[process.stdout])"
