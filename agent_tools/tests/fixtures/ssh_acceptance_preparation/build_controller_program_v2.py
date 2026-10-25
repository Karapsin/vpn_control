"""Fixed SOURCE-ONLY generator; no initialization, dispatch, readiness or network.

Only these two reviewed ordinary counter campaigns can be rendered. Actual local
namespace admission and any native execution require the coordinator's later GO.
"""
from pathlib import Path
from contextlib import ExitStack
import ast,hashlib,importlib.util,json,os,stat,sys,uuid
HERE=Path(__file__).resolve().parent
CONTROLLER_SHA='a088df1dfcd24fdc836b16d8c5011cb61e26397bcfc3265630624e2814926e51'
WRAPPER_SHA='0aaf58a4b01ef34d10d21db97ecfd6a067ae7c6b806342ef5cbd0baadf009841'
WRAPPER_ADDENDUM_SHA='5202318c4fd411012d94dec077fe50742a455054bc616ff33a8f30e26de93652'
CHECKPOINT_SHA='c26a0992933efe2d5d2e128052994a044f588448340d11910c5136f39e0de7ab'
HELPER_SHA='2c5f60321c667a9db4ae27f04103609318fbaff26c47fc140ea986c2fa9a426f'
LOCAL_OPERATIONS={'direct':'35a9c613-0985-4b0c-a1d5-3a128676c470','nested':'71d9c7af-5c7a-4cd5-9093-4b1ea32920a3'}
PURPOSE='ordinary-ssh-acceptance-controller'

class SharedSourceScope:
 """Share immutable held directory identities, retain one separate FD per file."""
 def __init__(self,held_type):self.held_type=held_type;self.directories={};self.files=[]
 def hold(self,path):
  path=Path(path)
  if not path.is_absolute()or'..'in path.parts:raise ValueError('shared_source_path')
  chain=[]
  for parent in reversed(path.parents):
   if parent not in self.directories:
    if parent==Path('/'):
     fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);entry=(None,'/',fd,module_generation(os.fstat(fd))[:5])
    else:
     base=self.directories[parent.parent][2];fd=os.open(parent.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=base);entry=(base,parent.name,fd,module_generation(os.fstat(fd))[:5])
    self.directories[parent]=entry
   chain.append(self.directories[parent])
  value=self.held_type.__new__(self.held_type);value.path=path;value.chain=chain;value.fds=[];value.parent=chain[-1][2];value.name=path.name
  try:
   value.fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=value.parent);value.fds.append(value.fd);i=os.fstat(value.fd)
   if not stat.S_ISREG(i.st_mode)or i.st_uid!=os.getuid()or i.st_nlink!=1 or i.st_mode&0o022:raise ValueError('shared_source_shape')
   value.pin=module_generation(i);value.raw=b''
   while len(value.raw)<i.st_size:
    part=os.read(value.fd,min(65536,i.st_size-len(value.raw)))
    if not part:raise ValueError('shared_source_short')
    value.raw+=part
   value.guard();self.files.append(value);return value
  except BaseException:value.close();raise
 def __enter__(self):return self
 def __exit__(self,*args):
  try:
   for source in self.files:source.guard()
  finally:
   for source in reversed(self.files):source.close()
   for _,_,fd,_ in reversed(list(self.directories.values())):os.close(fd)

def module_generation(i):return(i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid,i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns)

def build(mode):
 if mode not in LOCAL_OPERATIONS:raise ValueError('fixed_controller_mode')
 # Bootstrap the fixed wrapper using held actual bytes; no timestamp-pyc import.
 path=HERE/'local-owner-source/local_owner_v2.py';fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);i=os.fstat(fd);raw=os.read(fd,i.st_size+1)
 try:
  if hashlib.sha256(raw).hexdigest()!=WRAPPER_SHA:raise ValueError('fixed_wrapper_changed')
  if not(module_generation(os.fstat(fd))==module_generation(os.lstat(path))==module_generation(i)):raise ValueError('fixed_wrapper_generation_changed')
  module=type(sys)('_fixed_source_builder_'+uuid.uuid4().hex);module.__file__=str(path);module.__package__=None;sys.modules[module.__name__]=module
  exec(compile(raw,str(path),'exec'),module.__dict__)
  if not(module.generation(os.fstat(fd))==module.generation(os.lstat(path))==module.generation(i)):raise ValueError('fixed_wrapper_generation_changed')
  with ExitStack()as stack:
   wrapper=stack.enter_context(module.Held(path));checkpoint=stack.enter_context(module.Held(HERE/'source-checkpoint.json'));controller=stack.enter_context(module.Held(HERE/'controller.py'));helper=stack.enter_context(module.Held(HERE/'ordinary_retention.py'));manifest=stack.enter_context(module.Held(HERE/'public-source-manifest.json'))
   if(hashlib.sha256(wrapper.raw).hexdigest()!=WRAPPER_SHA or hashlib.sha256(checkpoint.raw).hexdigest()!=CHECKPOINT_SHA or hashlib.sha256(controller.raw).hexdigest()!=CONTROLLER_SHA or hashlib.sha256(helper.raw).hexdigest()!=HELPER_SHA):raise ValueError('fixed_campaign_source_changed')
   addition=stack.enter_context(module.Held(HERE/'local-owner-v2-source-addendum.json'))
   if hashlib.sha256(addition.raw).hexdigest()!=WRAPPER_ADDENDUM_SHA:raise ValueError('fixed_local_wrapper_addendum_changed')
   addendum=json.loads(addition.raw)
   if addendum['previousSourceCheckpointSha256']!=CHECKPOINT_SHA or addendum['newLocalOwnerSha256']!=WRAPPER_SHA or addendum['originalLocalOwnerSha256']!='667be765e108e62534d9ca30f4e4d9f7885087f0cbbe73d52e4c2dbb4ae67e08':raise ValueError('fixed_local_wrapper_addendum_scope')
   config=json.loads(checkpoint.raw);pins=json.loads(manifest.raw)['sources'];repo=HERE.parents[3]
   if config['controllerSha256']!=CONTROLLER_SHA or config['ordinaryLocalOwnerSourceSha256']!='667be765e108e62534d9ca30f4e4d9f7885087f0cbbe73d52e4c2dbb4ae67e08':raise ValueError('fixed_campaign_checkpoint_changed')
   scoped=stack.enter_context(SharedSourceScope(module.Held))
   artifacts=[wrapper,checkpoint,addition,controller,helper,manifest]
   for rel,digest in pins.items():
    for source in(repo/rel,HERE/mode/rel):
     held=scoped.hold(source);artifacts.append(held)
     if hashlib.sha256(held.raw).hexdigest()!=digest:raise ValueError('fixed_source_epoch_changed')
   for rel in('planned-operation.json','capsule-origin.json','route-template.private.json'):
    artifacts.append(scoped.hold(HERE/mode/rel))
   plan=json.loads(next(v.raw for v in artifacts if v.path==HERE/mode/'planned-operation.json'))
   if plan!={'operationId':{'direct':'fc338593-9f5d-45ec-9c70-2dee4685cd60','nested':'d3f264c6-641d-421d-8c26-87fb27e6ffa0'}[mode],'mode':mode,'count':1600,'intervalSeconds':.15,'budgetSeconds':600,'stage':'unsubmitted-source-only'}:raise ValueError('fixed_original_plan_changed')
   # Whitelisted private route body is never embedded or hashed. The complete
   # original named generation is sufficient to detect writes/replacement.
   bindings=[{'path':str(v.path),'generation':v.pin,**({}if v.path.name=='route-template.private.json'else{'sha256':hashlib.sha256(v.raw).hexdigest()})}for v in artifacts]
   shared=ast.parse(wrapper.raw);names={'LocalOwnerBlocked','need','generation','Held'}
   bootstrap='\n'.join(ast.unparse(n)for n in shared.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name in names)
   builder=ast.parse(Path(__file__).read_bytes());bootstrap+='\n'+'\n'.join(ast.unparse(n)for n in builder.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name in('SharedSourceScope','module_generation'))
   expected_campaign={'kind':'ordinary-ssh-acceptance','mode':mode,'remoteOperationId':plan['operationId']}
   payload='''from pathlib import Path
from contextlib import ExitStack
from types import ModuleType,SimpleNamespace
import hashlib,json,os,stat,sys,time
'''+bootstrap+'\nARTIFACTS='+repr(bindings)+'\nWRAPPER='+repr(str(path))+'\nROOT='+repr(str(HERE))+'\nMODE='+repr(mode)+'\nLOCAL_OPERATION='+repr(LOCAL_OPERATIONS[mode])+'\nCAMPAIGN='+repr(expected_campaign)+'''\nwith ExitStack()as stack:
 held={};scoped=stack.enter_context(SharedSourceScope(Held))
 for item in ARTIFACTS:
  source=scoped.hold(Path(item['path']))
  need(source.pin==tuple(item['generation']),'fixed_campaign_generation_changed')
  if 'sha256'in item:need(hashlib.sha256(source.raw).hexdigest()==item['sha256'],'fixed_campaign_bytes_changed')
  held[item['path']]=source
 wrapper=ModuleType('_fixed_local_owner_runtime');wrapper.__file__=WRAPPER;wrapper.__package__=None;sys.modules[wrapper.__name__]=wrapper
 exec(compile(held[WRAPPER].raw,WRAPPER,'exec'),wrapper.__dict__)
 with wrapper.Namespace(Path(ROOT)/('local-owner-'+MODE))as namespace:
  admission=namespace.original_admission(LOCAL_OPERATION)
  own=stack.enter_context(Held(Path(__file__)))
  need(admission['campaign']==CAMPAIGN and admission['purpose']=='ordinary-ssh-acceptance-controller'and admission['streamLimit']==4194304 and admission['budgetSeconds']==600,'fixed_local_admission_changed')
  need(admission['programSha256']==hashlib.sha256(own.raw).hexdigest(),'fixed_local_program_changed')
  need(time.monotonic()<admission['absoluteDeadline'],'fixed_local_deadline_exhausted')
  current=namespace.observe(LOCAL_OPERATION)
  need(current['state']=='running'and current['binding']==admission['binding'],'fixed_local_owner_unresolved')
  control=held[str(Path(ROOT)/'controller.py')]
  value=ModuleType('_fixed_ordinary_counter_controller');value.__file__=str(control.path);value.__package__=None;sys.modules[value.__name__]=value
  exec(compile(control.raw,str(control.path),'exec'),value.__dict__)
  try:value.main(SimpleNamespace(mode=MODE,budget=600,count=1600,interval=.15,native_go=True),absolute_deadline=admission['absoluteDeadline'])
  finally:
   for source in held.values():source.guard()
   own.guard();namespace.guard()
'''
   owner,owner_hold=module.owner_api()
   try:program=owner.Program(PURPOSE,payload.encode(),4194304);owner_hold.guard()
   finally:owner_hold.close()
   for held in artifacts:held.guard()
   return program,{'localOperationId':LOCAL_OPERATIONS[mode],'namespace':str(HERE/('local-owner-'+mode)),'campaign':expected_campaign,'admissionBudgetSeconds':600,'programSha256':program.digest,'programBytes':len(program.source),'streamLimit':program.stream_limit,'sourceArtifacts':len(bindings),'privateRouteContentHashed':False,'nativeGo':False}
 finally:os.close(fd)
