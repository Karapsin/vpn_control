"""Fixed original receipt-bound keeper entry; no ensure/renewal/replay."""
from __future__ import annotations
import base64,hashlib,json,os,re,stat,subprocess,sys,time
from contextlib import ExitStack
from pathlib import Path
from . import ssh_channel_keeper as core,ssh_fresh_nested_channel as channel,private_inventory_lock as private
from . import native_review_source_closure as closure,check_output_retention as raw_store
ROOT=Path(__file__).resolve().parents[1]
NAMES=('ssh_channel_keeper_entry.py','ssh_channel_keeper.py','ssh_channel_inventory_diagnostics.py','ssh_fresh_nested_channel.py','private_inventory_lock.py','native_review_source_closure.py','check_output_retention.py','ssh_transport.py','ssh_connection_session.py','ssh_connection_recovery.py','ssh_nested_socket_owned_home_observation.py','ssh_channel_selection.py','mcp_server.py','ssh_nested_socket_noninteractive_observation.py','ssh_nested_socket_retirement.py','ssh_nested_socket_route_diagnostic.py','ssh_recovery_adoption.py')
SOURCE_FILES={name:ROOT/'agent_tools'/name for name in NAMES}
PREFIX='native-receipt-bound-cooperative-busy-keeper-'
def _sha(value):
 if type(value)is not str or re.fullmatch('[0-9a-f]{64}',value)is None:raise ValueError('digest')
 return value
def _corr(value):channel._corr(value);return value
def source_path(root,corr):return Path(root)/'.runtime'/'ssh-channel-keeper-source'/(_corr(corr)+'.json')
def output_path(root,corr):return Path(root)/'.runtime'/'ssh-route-investigation'/(PREFIX+_corr(corr))
def save(path,value):
 body=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
 with private.Directory(path.parent) as directory:
  fd=os.open(path.name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory.fd)
  try:
   at=0
   while at<len(body):
    n=os.write(fd,body[at:])
    if n<=0:raise OSError('write')
    at+=n
   os.fsync(fd);pin=private._generation(os.fstat(fd));os.fsync(directory.fd)
   if os.pread(fd,len(body)+1,0)!=body:raise ValueError('readback')
   directory.guard()
   if private._generation(os.fstat(fd))!=pin or private._generation(os.stat(path.name,dir_fd=directory.fd,follow_symlinks=False))!=pin:raise ValueError('closing')
  finally:os.close(fd)
def source_snapshot(root,corr):
 root=Path(root).resolve(strict=True);_corr(corr);folder=source_path(root,corr).parent
 folder.parent.mkdir(mode=0o700,exist_ok=True);folder.mkdir(mode=0o700,exist_ok=True)
 held=closure._Held()
 try:
  pins={}
  for name,path in SOURCE_FILES.items():
   raw=Path(path).read_bytes();sha=hashlib.sha256(raw).hexdigest();held.read(str(path),sha);pins[str(path)]={'sha256':sha,'generation':list(held.files[str(path)][1])}
  held.finish();body={'inputs':pins};save(source_path(root,corr),body);digest=hashlib.sha256(json.dumps(body,sort_keys=True,separators=(',',':')).encode()).hexdigest()
  held.finish();return {'state':'source_recorded','correlationId':corr,'sourceManifestSha256':digest,'nativeActionAllowed':False,'replayAllowed':False}
 finally:held.close()
class SourceGuard:
 def __init__(self,root,corr,digest):
  self.held=closure._Held()
  try:
   obj=json.loads(self.held.read(str(source_path(root,corr)),_sha(digest)),object_pairs_hook=closure._pairs)
   if type(obj)is not dict or set(obj)!={'inputs'} or type(obj['inputs'])is not dict or set(obj['inputs'])!={str(p) for p in SOURCE_FILES.values()}:raise ValueError('source_roles')
   for name,pin in obj['inputs'].items():
    gen,sha=closure._pin(pin);self.held.read(name,sha,gen)
   self.guard()
  except BaseException:self.close();raise
 def guard(self):self.held.finish()
 def close(self):self.held.close()
def actor(pid=None):
 pid=os.getpid() if pid is None else pid
 if type(pid)is not int or pid<=0:raise ValueError('actor')
 env={k:v for k,v in os.environ.items() if k!='DYLD_INSERT_LIBRARIES'};env['LC_ALL']='C'
 result=subprocess.run(['/bin/ps','-p',str(pid),'-o','uid=','-o','lstart='],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3,check=False,env=env)
 if result.returncode!=0 or result.stderr or len(result.stdout)>256:raise ValueError('actor')
 fields=result.stdout.decode('ascii').strip().split()
 if len(fields)!=6 or fields[0]!=str(os.getuid()) or re.fullmatch(r'(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4}',' '.join(fields[1:])) is None:raise ValueError('actor')
 return {'pid':pid,'uid':os.getuid(),'sessionId':os.getsid(pid),'birthSha256':hashlib.sha256(' '.join(fields[1:]).encode()).hexdigest()}
def close_records(records,source_guard,receipt_guard=lambda:None,*,source_holders=()):
 # All byte reads and parent observations precede the final pure leaf pass.
 for held in records:held.guard()
 source_guard();receipt_guard()
 for public in source_holders:public.final_identity_pass()
 for held in records:held.directory.guard()
 for public in source_holders:
  for path,(fd,generation,sha,raw) in public.files.items():
   parent,name=os.path.split(path)
   if closure.generation(os.fstat(fd))!=generation or closure.generation(os.stat(name,dir_fd=public.parents[parent][0],follow_symlinks=False))!=generation:raise ValueError('joined_source_closing')
 for held in records:
  if private._generation(os.fstat(held.fd))!=held.generation or private._generation(os.stat(held.name,dir_fd=held.directory.fd,follow_symlinks=False))!=held.generation:raise ValueError('record_closing')
def run(root,corr,receipt,digest,*,clock=time.monotonic,sleep=time.sleep,emit=lambda value:print(json.dumps(value,sort_keys=True),flush=True)):
 root=Path(root).resolve(strict=True);_corr(corr);_sha(receipt);_sha(digest)
 source=SourceGuard(root,corr,digest)
 try:
  # Bind authentic current receipt before creating an original keeper effect.
  with ExitStack() as stack:
   receipt_guard=core.bind_receipt(root,corr,receipt,stack);source.guard();receipt_guard()
   journal=stack.enter_context(private.Directory(channel._journal(root,False)))
   receipt_records=[stack.enter_context(private.Snapshot(journal,corr+'.intent.json')),stack.enter_context(private.Snapshot(journal,corr+'.ready.json'))]
   if receipt_records[1].digest!=receipt:raise ValueError('receipt_binding')
   local=actor();source.guard();receipt_guard()
   parent=output_path(root,corr).parent;parent.mkdir(mode=0o700,exist_ok=True)
   with private.Directory(parent):pass
   output=output_path(root,corr);output.mkdir(mode=0o700)
   intent={'version':1,'correlationId':corr,'receiptSha256':receipt,'sourceManifestSha256':digest,'localActor':local,'sourceSha256':channel._source(),'remoteSourceSha256':hashlib.sha256(channel._REMOTE.encode()).hexdigest(),'action':'same_channel_readonly_status','durationSeconds':1800,'intervalSeconds':15,'maxIntervalSeconds':20,'newConnectionAllowed':False,'applicationReplayAllowed':False,'nativeActionAllowed':False}
   output_directory=stack.enter_context(private.Directory(output));records=list(receipt_records)
   def hold(name,sha):
    held=stack.enter_context(private.Snapshot(output_directory,name))
    if held.digest!=sha:raise ValueError('record_body')
    records.append(held);return held
   def write(name,value):
    body=json.dumps(value,sort_keys=True,separators=(',',':')).encode();save(output/name,value);hold(name,hashlib.sha256(body).hexdigest())
   def guard():close_records(records,source.guard,receipt_guard,source_holders=(source.held,))
   write('intent.json',intent);guard()
   emit({'state':'keeper_started','correlationId':corr,'localActor':local,'durationLimitSeconds':1800,'nativeActionAllowed':False,'replayAllowed':False})
   def retain_raw(index,raw):
    write('query-%04d.private.json'%index,{k:base64.b64encode(v).decode() if isinstance(v,bytes) else v for k,v in raw.items()})
    raw_store.retain_observation_capture(output,label='query-%04d'%index,capture=raw,source_fingerprint=channel._source())
   def publish(index,value):write('query-%04d.json'%index,value);guard();emit(value);guard()
   # Reuse actual static core with original raw custody callback, not duplicate provider.
   def inventory(i,e):
    retained=core.retain(output,i,e);hold('query-%04d.inventory.json'%i,retained['sha256']);guard();return retained
   result=core.bound_keep(root,corr,receipt,retain_raw,publish,guard,clock,sleep,retain_inventory=inventory)
   guard()
   if actor()!=local:raise ValueError('actor_changed')
   write('result.json',result);guard();emit(result);guard();return result
 finally:source.close()
def main(argv=None):
 argv=sys.argv[1:] if argv is None else argv
 if len(argv)!=3:raise ValueError('exact_args')
 return run(ROOT,*argv)
def validated_result(result,corr,receipt):
 keys={'correlationId','receiptSha256','queryCount','lastState','stopReason','durationLimitSeconds','intervalSeconds','maxIntervalSeconds','newConnectionAllowed','applicationReplayAllowed'}
 if type(result)is not dict or not keys<=set(result) or set(result)-keys-{'nativeActionAllowed'}:raise ValueError('result_schema')
 if result['correlationId']!=corr or result['receiptSha256']!=receipt or type(result['queryCount'])is not int or not 0<=result['queryCount']<=120 or result['lastState']not in {'unobserved','ready','unknown','ended'} or result['stopReason']not in {'duration','unknown','ended','receipt_mismatch','late_query','source_changed','capture_retention','receipt_binding'}:raise ValueError('result_fields')
 if any(type(result[k])is not int or result[k]!=v for k,v in [('durationLimitSeconds',1800),('intervalSeconds',15),('maxIntervalSeconds',20)]):raise ValueError('result_limits')
 if any(result[k] is not False for k in ('newConnectionAllowed','applicationReplayAllowed')) or result.get('nativeActionAllowed',False) is not False:raise ValueError('result_authority')
 return {**result,'nativeActionAllowed':False,'replayAllowed':False}
def observe(root,corr,receipt,digest,*,_outer_source_holder=None):
 root=Path(root).resolve(strict=True);_corr(corr);_sha(receipt);_sha(digest);source=SourceGuard(root,corr,digest)
 try:
  with private.Directory(output_path(root,corr)) as directory,ExitStack() as stack:
   receipt_guard=core.bind_receipt(root,corr,receipt,stack)
   journal=stack.enter_context(private.Directory(channel._journal(root,False)))
   receipt_records=[stack.enter_context(private.Snapshot(journal,corr+'.intent.json')),stack.enter_context(private.Snapshot(journal,corr+'.ready.json'))]
   if receipt_records[1].digest!=receipt:raise ValueError('receipt_binding')
   held=stack.enter_context(private.Snapshot(directory,'intent.json'));intent=json.loads(held.body,object_pairs_hook=closure._pairs)
   expected={'version':1,'correlationId':corr,'receiptSha256':receipt,'sourceManifestSha256':digest,'sourceSha256':channel._source(),'remoteSourceSha256':hashlib.sha256(channel._REMOTE.encode()).hexdigest(),'action':'same_channel_readonly_status','durationSeconds':1800,'intervalSeconds':15,'maxIntervalSeconds':20,'newConnectionAllowed':False,'applicationReplayAllowed':False,'nativeActionAllowed':False}
   if type(intent)is not dict or set(intent)!=set(expected)|{'localActor'}:raise ValueError('intent_binding')
   actual={k:intent[k] for k in expected}
   if json.dumps(actual,sort_keys=True,separators=(',',':'))!=json.dumps(expected,sort_keys=True,separators=(',',':')):raise ValueError('intent_binding')
   local=intent['localActor']
   if type(local)is not dict or set(local)!={'pid','uid','sessionId','birthSha256'} or any(type(local[k])is not int or local[k]<0 for k in ('pid','uid','sessionId')) or local['pid']<=0 or local['uid']!=os.getuid():raise ValueError('actor_schema')
   _sha(local['birthSha256']);source.guard();held.guard()
   try:result_held=stack.enter_context(private.Snapshot(directory,'result.json'))
   except FileNotFoundError:
    if actor(local['pid'])!=local:raise ValueError('actor_changed')
    result={'state':'observing','correlationId':corr,'localActor':local,'nativeActionAllowed':False,'replayAllowed':False}
   else:
    result={'state':'completed','correlationId':corr,'localActor':local,'result':validated_result(json.loads(result_held.body,object_pairs_hook=closure._pairs),corr,receipt),'nativeActionAllowed':False,'replayAllowed':False};result_held.guard()
   records=receipt_records+[held]+([result_held] if result['state']=='completed' else [])
   holders=(source.held,)+((_outer_source_holder,) if _outer_source_holder is not None else ())
   close_records(records,lambda: (source.guard(),_outer_source_holder.finish() if _outer_source_holder is not None else None),receipt_guard,source_holders=holders);return result
 finally:source.close()
if __name__=='__main__':main()

BOOTSTRAP='"""Fixed authenticated public-source child bootstrap, no native commands supplied."""\nimport base64,zlib,json,sys,types,importlib.abc,importlib.util,hashlib\nbundle=json.loads(zlib.decompress(base64.b64decode(sys.argv[1])))\nroot,corr,receipt,digest=sys.argv[2:]\nfiles=bundle[\'files\'];pins=bundle[\'pins\']\n# This byte payload comes directly from original parent _Held.read buffers.\n# Never import repository source from current named paths in this child.\nclosure_name=\'agent_tools.native_review_source_closure\'\npackage=types.ModuleType(\'agent_tools\');package.__path__=[];sys.modules[\'agent_tools\']=package\nname=closure_name;path,raw=files[name];raw=raw.encode()\nif hashlib.sha256(raw).hexdigest()!=pins[path][\'sha256\']:raise ValueError(\'closure_payload\')\nclosure=types.ModuleType(name);closure.__file__=path;closure.__package__=\'agent_tools\';sys.modules[name]=closure;exec(compile(raw,path,\'exec\'),closure.__dict__)\nheld=closure._Held()\ntry:\n manifest=root+\'/.runtime/ssh-channel-keeper-source/\'+corr+\'.json\';obj=json.loads(held.read(manifest,digest),object_pairs_hook=closure._pairs)\n if set(obj)!={\'inputs\'} or obj[\'inputs\']!=pins:raise ValueError(\'manifest_payload\')\n cached={}\n for path,pin in pins.items():\n  gen,sha=closure._pin(pin);held.read(path,sha,gen)\n for name,(path,data) in files.items():\n  gen,sha=closure._pin(pins[path]);actual=held.read(path,sha,gen)\n  if actual!=data.encode():raise ValueError(\'source_payload\')\n  cached[name]=(path,actual)\n held.finish()\n import inspect,ast\n fallback=inspect.getsource;fallback_lines=inspect.getsourcelines\n by_path={path:raw for path,raw in cached.values()}\n def extract(target):\n  if inspect.ismodule(target):return cached[target.__name__][1].decode(),1\n  if inspect.isclass(target):path=sys.modules[target.__module__].__file__;qualified=target.__qualname__\n  else:path=target.__code__.co_filename;qualified=target.__qualname__\n  raw=by_path[path];node=ast.parse(raw)\n  for component in qualified.split(\'.\'):\n   matches=[v for v in node.body if isinstance(v,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)) and v.name==component]\n   if len(matches)!=1:raise ValueError(\'immutable_source_target\')\n   node=matches[0]\n  start=min([node.lineno]+[d.lineno for d in node.decorator_list]);return \'\'.join(raw.decode().splitlines(True)[start-1:node.end_lineno]),start\n def getsource(target):\n  if getattr(target,\'__module__\',getattr(target,\'__name__\',\'\')).startswith(\'agent_tools\'):return extract(target)[0]\n  return fallback(target)\n def getsourcelines(target):\n  if getattr(target,\'__module__\',getattr(target,\'__name__\',\'\')).startswith(\'agent_tools\'):\n   raw,start=extract(target);return raw.splitlines(True),start\n  return fallback_lines(target)\n inspect.getsource=getsource;inspect.getsourcelines=getsourcelines\n class Loader(importlib.abc.Loader):\n  def create_module(self,spec):return None\n  def exec_module(self,module):\n   path,raw=cached[module.__name__];module.__file__=path;held.finish();exec(compile(raw,path,\'exec\'),module.__dict__);held.finish()\n class Finder(importlib.abc.MetaPathFinder):\n  def find_spec(self,name,path=None,target=None):\n   if name in cached:return importlib.util.spec_from_loader(name,Loader(),origin=cached[name][0])\n   if name.startswith(\'agent_tools.\'):raise ImportError(\'undeclared_repository_module\')\n sys.meta_path.insert(0,Finder());held.finish()\n module=__import__(\'agent_tools.ssh_channel_keeper_entry\',fromlist=[\'main\']);held.finish()\n module.run(root,corr,receipt,digest);held.finish()\nfinally:held.close()\n'
def child_argv(python,root,corr,receipt,digest,source):
 import zlib
 pins=json.loads(source.held.files[str(source_path(root,corr))][3],object_pairs_hook=closure._pairs)['inputs']
 files={}
 for name,path in SOURCE_FILES.items():
  if name=='mcp_server.py':continue
  files['agent_tools.'+Path(name).stem]=(str(path),source.held.files[str(path)][3].decode())
 payload=base64.b64encode(zlib.compress(json.dumps({'files':files,'pins':pins},sort_keys=True,separators=(',',':')).encode(),9)).decode()
 if len(payload)>131072:raise ValueError('source_bundle_cap')
 source.guard();return [python,'-I','-B','-c',BOOTSTRAP,payload,str(root),corr,receipt,digest]
