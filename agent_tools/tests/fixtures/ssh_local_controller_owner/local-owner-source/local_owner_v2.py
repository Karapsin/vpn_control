"""Private fixed-adapter LOCAL owner composition; no executable/public command API.

Adapters supply only their reviewed durable.Program (never external script input).
The original root binding and independent index are retained across parent exits.
This source contains no SSH/controller invocation. Real campaigns need separate GO.
"""
from pathlib import Path
from contextlib import ExitStack
import hashlib,json,math,os,stat,sys,time,types,uuid

REPO=Path(__file__).resolve().parents[5]
OWNER_SHA='f3b4707528c16f176b80781dd86208c324c1e10d6eb2c14451dcf4be08d0e734'
RETENTION_SHA='2c5f60321c667a9db4ae27f04103609318fbaff26c47fc140ea986c2fa9a426f'
RETENTION_PATH=Path(__file__).resolve().parent.parent/'ordinary_retention.py'
_EXECUTING_CODE=sys._getframe().f_code

class LocalOwnerBlocked(ValueError):pass

def need(ok,reason):
 if not ok:raise LocalOwnerBlocked(reason)

def generation(i):return(i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid,i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns)

class Held:
 def __init__(self,path):
  self.path=Path(path);need(self.path.is_absolute()and'..'not in self.path.parts,'local_source_path')
  self.fds=[];self.chain=[]
  try:
   fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);self.fds.append(fd);self.chain.append((None,'/',fd,generation(os.fstat(fd))[:5]))
   for name in self.path.parts[1:-1]:
    parent=fd;fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);self.fds.append(fd);self.chain.append((parent,name,fd,generation(os.fstat(fd))[:5]))
   self.parent=fd;self.name=self.path.name;self.fd=os.open(self.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd);self.fds.append(self.fd)
   i=os.fstat(self.fd);need(stat.S_ISREG(i.st_mode)and i.st_uid==os.getuid()and i.st_nlink==1 and not i.st_mode&0o022,'local_source_shape')
   self.pin=generation(i);self.raw=b''
   while len(self.raw)<i.st_size:
    part=os.read(self.fd,min(65536,i.st_size-len(self.raw)));need(bool(part),'local_source_short');self.raw+=part
   self.guard()
  except BaseException:self.close();raise
 def guard(self):
  for parent,name,fd,pin in self.chain:
   named=os.stat('/',follow_symlinks=False)if parent is None else os.stat(name,dir_fd=parent,follow_symlinks=False)
   need(generation(os.fstat(fd))[:5]==generation(named)[:5]==pin,'local_source_ancestry_changed')
  need(generation(os.fstat(self.fd))==generation(os.stat(self.name,dir_fd=self.parent,follow_symlinks=False))==self.pin and os.pread(self.fd,len(self.raw)+1,0)==self.raw,'local_source_changed')
 def close(self):
  for fd in reversed(self.fds):os.close(fd)
  self.fds=[]
 def __enter__(self):return self
 def __exit__(self,*args):
  try:self.guard()
  finally:self.close()

def _load(path,digest,name):
 held=Held(path)
 try:
  need(hashlib.sha256(held.raw).hexdigest()==digest,'local_reviewed_source_changed')
  value=types.ModuleType(name+'_'+uuid.uuid4().hex);value.__file__=str(path);value.__package__=None;sys.modules[value.__name__]=value
  exec(compile(held.raw,str(path),'exec'),value.__dict__);held.guard()
  return value,held
 except BaseException:held.close();raise

def owner_api():
 """Source-only import of exact reviewed owner; no process/kernel probe here."""
 value,held=_load(REPO/'agent_tools/durable_remote_job.py',OWNER_SHA,'_held_local_durable_owner')
 # The only substituted getter returns exact already-held reviewed bytes, never
 # rereads a mutable pathname while submit is constructing the detached owner.
 def held_owner_source():held.guard();return held.raw
 value.owner_source=held_owner_source
 return value,held

def _write(parent,name,raw):
 fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
 try:
  offset=0
  while offset<len(raw):
   n=os.write(fd,raw[offset:]);need(n>0,'local_write_short');offset+=n
  os.fsync(fd)
 finally:os.close(fd)
 os.fsync(parent)

def _json(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def _uuid(op):need(type(op)is str and str(uuid.UUID(op))==op,'local_operation_identity');return op

def _directory(path,expected=None):
 path=Path(path);need(path.is_absolute()and path.resolve()==path,'local_directory_path')
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);i=os.fstat(fd)
 try:need(stat.S_ISDIR(i.st_mode)and i.st_uid==os.getuid()and stat.S_IMODE(i.st_mode)==0o700 and generation(i)==generation(os.lstat(path))and(expected is None or generation(i)[:5]==tuple(expected)),'local_namespace_changed')
 except BaseException:os.close(fd);raise
 return fd,generation(i)[:5]

def initialize(root,binding,*,source_guard):
 """Explicit fresh private namespace only; no job submission or readiness action."""
 root=Path(root);source_guard();parent,pin=_directory(root.parent)
 try:
  os.mkdir(root.name,0o700,dir_fd=parent)
  fd,rootpin=_directory(root)
  try:
   for name in('jobs','admissions','collections'):os.mkdir(name,0o700,dir_fd=fd)
   os.fsync(fd)
   record={'schemaVersion':1,'kind':'fixed-local-controller-v1','root':str(root),'rootGeneration':rootpin,'binding':dict(binding),'ownerSourceSha256':OWNER_SHA,
           'children':{name:generation(os.lstat(root/name))[:5]for name in('jobs','admissions','collections')}}
   source_guard();_write(parent,root.name+'.namespace.json',_json(record))
  finally:os.close(fd)
 finally:os.close(parent)
 return record

class Namespace:
 def __init__(self,root):
  self.root=Path(root);self.stack=ExitStack()
  try:
   self.owner,self.owner_hold=owner_api();self.stack.callback(self.owner_hold.close)
   self.record_hold=Held(self.root.parent/(self.root.name+'.namespace.json'));self.stack.callback(self.record_hold.close)
   self.record=json.loads(self.record_hold.raw)
   need(set(self.record)=={'schemaVersion','kind','root','rootGeneration','binding','ownerSourceSha256','children'}and type(self.record['schemaVersion'])is int and self.record['schemaVersion']==1 and self.record['kind']=='fixed-local-controller-v1'and self.record['root']==str(self.root)and self.record['ownerSourceSha256']==OWNER_SHA and set(self.record['children'])=={'jobs','admissions','collections'},'local_namespace_record')
   self.binding=self.owner.MachineBinding.from_dict(self.record['binding']);self.fds={}
   fd,_=_directory(self.root,self.record['rootGeneration']);self.stack.callback(os.close,fd)
   for name in self.record['children']:
    fd,_=_directory(self.root/name,self.record['children'][name]);self.stack.callback(os.close,fd);self.fds[name]=fd
   self.job_generation=tuple(self.record['children']['jobs'][:2]);self.guard()
  except BaseException:self.stack.close();raise
 def guard(self):
  self.owner_hold.guard();self.record_hold.guard()
  fd,_=_directory(self.root,self.record['rootGeneration']);os.close(fd)
  for name,fd in self.fds.items():
   i=os.fstat(fd);need(generation(i)[:5]==tuple(self.record['children'][name])==generation(os.lstat(self.root/name))[:5],'local_namespace_changed')
 def _index(self,op):
  self.guard();_uuid(op)
  try:
   with Held(self.root/'admissions'/(op+'.json'))as held:index=json.loads(held.raw)
  except FileNotFoundError:return None
  need(set(index)=={'schemaVersion','operationId','binding','programSha256','purpose','streamLimit','campaign','admittedMonotonic','absoluteDeadline','budgetSeconds'}and index['schemaVersion']==1 and type(index['schemaVersion'])is int and index['operationId']==op and index['binding']==self.record['binding'],'local_admission_changed')
  need(type(index['admittedMonotonic'])in(int,float)and type(index['absoluteDeadline'])in(int,float)and type(index['budgetSeconds'])in(int,float)and all(math.isfinite(index[k])and index[k]>0 for k in('admittedMonotonic','absoluteDeadline','budgetSeconds'))and index['absoluteDeadline']==index['admittedMonotonic']+index['budgetSeconds'],'local_admission_deadline_changed')
  return index
 def original_admission(self,op):
  index=self._index(op);need(index is not None,'local_admission_absent');self.owner._binding_live(self.binding);self.guard();return json.loads(_json(index))
 def _unknown(self,op,reason):return{'schemaVersion':1,'operationId':op,'state':'unknown','reason':reason,'replayAllowed':False}
 def observe(self,op):
  index=self._index(op)
  if index is None:
   if(self.root/'jobs'/op).exists()or(self.root/'jobs'/op).is_symlink():return self._unknown(op,'local_orphan_admission')
   self.owner._binding_live(self.binding);return{'schemaVersion':1,'operationId':op,'state':'unsubmitted','reason':'local_admission_absent','replayAllowed':False}
  value=self.owner.observe(self.root/'jobs',op,self.binding,generation=self.job_generation)
  self.guard()
  if value['state']=='unsubmitted':return self._unknown(op,'local_consumed_index_job_missing')
  try:
   intent=self.owner._intent(self.root/'jobs'/op,op,self.binding)
   need(intent['programSha256']==index['programSha256']and intent['purpose']==index['purpose']and intent['streamLimit']==index['streamLimit'],'local_job_program_changed')
  except(FileNotFoundError,self.owner.DurableJobError):return self._unknown(op,'local_original_intent_unresolved')
  return value
 def submit_once(self,op,program,*,campaign,source_guard,budget_seconds=600):
  """Only a trusted adapter-owned fixed Program; no public payload route exists."""
  _uuid(op);need(type(campaign)is dict and all(type(k)is str and type(v)is str for k,v in campaign.items()),'local_campaign_identity')
  need(type(budget_seconds)in(int,float)and math.isfinite(budget_seconds)and 0<budget_seconds<=7200,'local_admission_budget_invalid')
  source_guard();index=self._index(op)
  expected={'schemaVersion':1,'operationId':op,'binding':self.record['binding'],'programSha256':program.digest,'purpose':program.purpose,'streamLimit':program.stream_limit,'campaign':campaign}
  if index is not None:
   need({k:v for k,v in index.items()if k not in('admittedMonotonic','absoluteDeadline','budgetSeconds')}==expected and index['budgetSeconds']==budget_seconds,'local_admission_conflict');return self.observe(op)
  need(not(self.root/'jobs'/op).exists()and not(self.root/'jobs'/op).is_symlink(),'local_orphan_admission')
  admitted=time.monotonic();expected.update(admittedMonotonic=admitted,absoluteDeadline=admitted+budget_seconds,budgetSeconds=budget_seconds)
  try:_write(self.fds['admissions'],op+'.json',_json(expected))
  except FileExistsError:return self._unknown(op,'local_concurrent_admission_observe_original')
  # Once the independent admission is consumed, no retry path calls submit.
  try:
   with Held(self.root/'admissions'/(op+'.json'))as admission:
    need(stat.S_IMODE(admission.pin[2])==0o600 and admission.raw==_json(expected),'local_admission_custody_changed')
    source_guard();admission.guard();self.guard();need(time.monotonic()<expected['absoluteDeadline'],'local_admission_deadline_exhausted')
    admission.guard()
    value=self.owner.submit(self.root/'jobs',op,self.binding,program,generation=self.job_generation)
    admission.guard();self.guard();source_guard();admission.guard()
    return value
  except Exception:return self._unknown(op,'local_submit_ack_or_source_unknown')
 def collect(self,op,*,closing_guard):
  """Retain raw complete fixed-public streams before any closing source guard."""
  status=self.observe(op);need(status['state']=='terminal','local_collect_not_terminal')
  status,stdout,stderr=self.owner.collect(self.root/'jobs',op,self.binding,generation=self.job_generation)
  helper,held=_load(RETENTION_PATH,RETENTION_SHA,'_held_local_output_custody')
  try:
   for _ in range(32):
    label='counter-%06d'%(uuid.uuid4().int%1000000)
    try:capture=helper._OutputCapture(self.root/'collections',label);break
    except FileExistsError:continue
   else:raise LocalOwnerBlocked('local_collection_name_collision')
   with capture:
    capture.write('stdout.bin',stdout);capture.write('stderr.bin',stderr)
    capture.write('terminal.json',_json(status));capture.guard_data()
    need(capture.named_custody(),'local_collection_named_custody_changed')
    retained=self.root/'collections'/label
    self.guard();held.guard();closing_guard()
   return status,retained
  finally:held.close()
 def close(self):self.stack.close()
 def __enter__(self):return self
 def __exit__(self,*args):
  try:self.guard()
  finally:self.close()
