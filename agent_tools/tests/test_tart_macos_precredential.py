"""Authentic generated precredential blocks with real observer pipes/RFB sockets.

Complete before/current source fixtures are SHA-pinned. Only their exact helper
and precredential AST blocks execute through public-preflight; outer native/root
setup is compiled data. Controlled fixed observer subprocesses, RFB TCP peers,
VNC fixture FDs and metadata guards replace native endpoints. No VM, ordinary
credential, input event, retained frame or runtime inventory is reachable.
"""
from pathlib import Path
from contextlib import ExitStack,contextmanager
from types import SimpleNamespace
import ast,base64,copy,hashlib,json,os,subprocess,sys,tempfile,time,unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT));FIXTURE=Path(__file__).parent/'fixtures/tart_macos_precredential'
from agent_tools import readiness_tart_macos_unlock as U,readiness_tart_vnc as V,readiness_tart_macos as M,readiness_tart_macos_registry as R,private_inventory_lock as P,durable_remote_job as J,readiness_tart_macos_unlock_material as MAT,readiness_tart_macos_unlock_qualification as Q
from agent_tools.tests.test_readiness_tart_macos_unlock import binding,identity
from agent_tools.tests.test_readiness_tart_vnc import RfbEndpoint
from PIL import Image
OLD=FIXTURE/'public.before.source';NEW=FIXTURE/'public.current.source'
EXPECTED={'public.before.source': 'cc06ec0d0144d7fed7a64bc024daddcb2730738049cb7af0efee5a703f3a3028', 'public.current.source': '70be2d16febc49a361820cbd00050f32bb254154f1eafdf5afa829ad1958d7cb'}
for name,digest in EXPECTED.items():
 if hashlib.sha256((FIXTURE/name).read_bytes()).hexdigest()!=digest:raise AssertionError('causal source fixture changed')
def block(path,current):
 tree=ast.parse(path.read_bytes());setup=[n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='PublicGuard'or isinstance(n,ast.FunctionDef)and n.name in{'need','precredential_failure'}or isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id in{'_PUBLIC_GUARD_CODES','_PRECREDENTIAL_STAGES','_UNLOCK_DIAGNOSTIC_CODES','_VNC_DIAGNOSTIC_CODES','_INCIDENT_DIAGNOSTIC_CODES'}for t in n.targets)]
 outer=next(n for n in ast.walk(tree)if isinstance(n,ast.With)and any(isinstance(i.optional_vars,ast.Name)and i.optional_vars.id=='stack'for i in n.items))
 if current:
  inner=next(n for n in outer.body if isinstance(n,ast.Try)and any(isinstance(x,ast.Call)and isinstance(x.func,ast.Name)and x.func.id=='precredential_failure'for h in n.handlers for x in ast.walk(h)))
  inner=copy.deepcopy(inner);body=inner.body
 else:
  start=next(i for i,n in enumerate(outer.body)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='startup'for t in n.targets));body=copy.deepcopy(outer.body[start:])
 end=next(i for i,n in enumerate(body)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Attribute)and t.attr=='live'for t in n.targets))
 if current:
  inner.body=body[:end+1]
  stage=next(n for n in outer.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='precredential_stage'for t in n.targets))
  program=[copy.deepcopy(stage),inner]
 else:program=body[:end+1]
 return compile(ast.Module(body=setup+program,type_ignores=[]),str(path),'exec')
RESULTS=[]
@unittest.skipUnless(os.name=='posix','real POSIX protected FDs and process generations required')
class Checks(unittest.TestCase):
 def run_case(self,current,fault):
  selected=binding();expected=identity();children=[];opened=[];counter={'guard':0};failure=None;records={};sourcepaths=[Path(x.__file__)for x in(U,V,MAT)]
  pins={p:hashlib.sha256(p.read_bytes()).hexdigest()for p in sourcepaths};scope={}
  with tempfile.TemporaryDirectory(prefix='precredential-controlled-')as temporary,ExitStack()as held:
   root=Path(temporary).resolve();root.chmod(0o700);credential=root/'controlled-vnc-input';credential.write_bytes(b'controlled-public-fixture');credential.chmod(0o600);holder=R.HeldArtifact(credential);held.callback(holder.close)
   endpoint=RfbEndpoint(size=(3,1),rejected=fault=='auth',malformed='count'if fault=='capture'else None);held.callback(endpoint.close)
   source_file=root/'controlled-public-source.py';source_file.write_bytes(b'# controlled public source\n');source_file.chmod(0o600);source=R.PublicProof(source_file,{'generation':list(P._generation(source_file.stat())),'sha256':hashlib.sha256(source_file.read_bytes()).hexdigest()});held.callback(source.close);injected={'value':False}
   actor={'pid':os.getpid(),'birth':J._birth(os.getpid())};operation='44444444-4444-4444-8444-444444444444'
   class Custody:
    binding=selected
    @contextmanager
    def operator(self,**kw):yield
    def qualifications(self,*a):return None
    def guard(self,**kw):return {'state':'running','connection':'controlled','actor':actor,'operator':actor,'operationId':operation,'jobState':'running'}
   c=Custody();c.lifecycle_root=root;c._credentials={'vnc':holder};c.endpoint={'port':endpoint.port};backend=M.MacTartBackend(selected,c)
   directory=held.enter_context(P.Directory(root))
   def physical():
    for path,digest in pins.items():self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),digest)
    if fault=='source_guard'and scope.get('precredential_stage')=='capture_initial'and not injected['value']:
     other=root/'source-replacement.py';other.write_bytes(source_file.read_bytes());other.chmod(0o600);other.replace(source_file);injected['value']=True
    source.guard();directory.guard();counter['guard']+=1
   def save(path,value):
    raw=value if type(value)is bytes else json.dumps(value,sort_keys=True).encode();fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
    records[path.name]=value
   def native_record(name,value):
    if fault=='sink'and name=='precredential-failure.json':raise OSError('SYNTHETIC_UNEXPECTED_MESSAGE')
    save(root/name,value)
   original_fd=holder.credential_fd
   def credential_fd():
    if fault=='credential':raise PermissionError('SYNTHETIC_UNEXPECTED_MESSAGE')
    fd=original_fd();opened.append(fd);return fd
   holder.credential_fd=credential_fd
   baseline=Image.new('RGB',(3,1));baseline.putdata([(255,255,255)if fault=='recipient'else(255,0,0),(0,255,0),(255,255,255)if fault=='field'else(0,0,255)])
   profile={'profile':{'dimensions':(2,1)if fault=='image'else(3,1),'accountBox':(0,0,1,1),'fieldBox':(1,0,3,1),'caretBox':(0,0,1,1)}}
   if fault in{'incident','sink'}:(root/('macos-unlock-'+operation+'.json')).write_text('{}')
   argv,payload=U.stream.session_stream_command(selected);real_popen=subprocess.Popen
   def launch(args,**kw):
    self.assertEqual(args,[selected.tart_binary,'exec','-i',selected.vm_name,*argv]);reply={'protocol':U.stream.PROTOCOL,'state':'observer_ready','observation':expected}
    code='import sys,json\nraw=sys.stdin.buffer.read('+str(len(payload))+')\nobs='+repr(expected)+'\nprint('+repr(json.dumps(reply))+',flush=True)\nfor line in sys.stdin.buffer:\n parts=line.decode().strip().split()\n if len(parts)!=3:raise SystemExit(73)\n counter=int(parts[1]);nonce=parts[2]\n'
    if fault=='benchmark':code+=" if counter>=100:obs['console']['locked']=False\n"
    code+=' print(json.dumps({"protocol":'+repr(U.stream.PROTOCOL)+',"state":"observed","counter":counter,"nonce":nonce,"observation":obs}),flush=True)\n'
    child=real_popen([sys.executable,'-I','-B','-c',code],**kw);children.append((child,J._birth(child.pid)));return child
   scope={'U':U,'V':V,'Q':Q,'P':P,'MAT':MAT,'J':J,'backend':backend,'c':c,'expected':expected,'deadline':time.monotonic()+30,'physical':physical,'capture_out':directory,'args':SimpleNamespace(operation_id=operation),'native_record':native_record,'source_closure':lambda:{'controlled':'public sources'},'folder':root,'save':save,'baseline':baseline,'profile':profile,'time':time,'os':os,'json':json,'observations':[]}
   try:
    with mock.patch.object(U.subprocess,'Popen',launch):
     with ExitStack()as stack:
      scope['stack']=stack;stack.enter_context(backend.operation_scope(deadline=scope['deadline']))
      exec(block(NEW if current else OLD,current),scope)
   except BaseException as error:failure=type(error).__name__
   observer=scope.get('observer');leaked=observer is not None and observer.process.poll()is None
   diagnostic=records.get('precredential-failure.json')
   if observer is not None:observer.close()
   for child,birth in children:
    if child.poll()is None:child.stdin.close();child.wait(timeout=3)
    self.assertNotEqual(J._birth(child.pid),birth);self.assertTrue(child.stdin.closed and child.stdout.closed and child.stderr.closed)
   for fd in opened:
    with self.assertRaises(OSError):os.fstat(fd)
   self.assertEqual(endpoint.events,[])
   self.assertNotIn('SYNTHETIC_UNEXPECTED_MESSAGE',json.dumps(diagnostic));self.assertFalse(any('ordinary'in name for name in records))
   value={'current':current,'fault':fault,'failureClass':failure,'observerLeakedBeforeHarnessCleanup':leaked,'diagnostic':diagnostic,'allObserverPipesClosed':True,'allObserverBirthsAbsent':True,'allReturnedVncFdsClosed':True,'sourceGuards':counter['guard'],'inputEvents':0}
   RESULTS.append(value);return value
 def test_authentic_incident_fault_old_masks_and_leaks_new_retains_and_closes(self):
  old=self.run_case(False,'incident');self.assertEqual(old['failureClass'],'MacBlocked');self.assertTrue(old['observerLeakedBeforeHarnessCleanup']);self.assertIsNone(old['diagnostic'])
  new=self.run_case(True,'incident');self.assertEqual(new['failureClass'],'MacBlocked');self.assertFalse(new['observerLeakedBeforeHarnessCleanup']);self.assertEqual(new['diagnostic']['stage'],'incident_setup');self.assertEqual(new['diagnostic']['code'],'macos_unlock_original_pending')
 def test_each_credential_auth_capture_image_recipient_field_benchmark_boundary(self):
  stages={'credential':'vnc_credential_open','auth':'vnc_auth','capture':'capture_initial','image':'image_decode','recipient':'recipient_match','field':'field_empty','benchmark':'guard_benchmark'}
  for fault,stage in stages.items():
   with self.subTest(fault=fault):
    value=self.run_case(True,fault);self.assertIsNotNone(value['failureClass']);self.assertFalse(value['observerLeakedBeforeHarnessCleanup']);self.assertEqual(value['diagnostic']['stage'],stage);self.assertFalse(value['diagnostic']['rawExceptionTextRetained'])
 def test_source_generation_loss_and_diagnostic_sink_fault_always_close_observer(self):
  source=self.run_case(True,'source_guard');self.assertFalse(source['observerLeakedBeforeHarnessCleanup']);self.assertEqual(source['diagnostic']['stage'],'capture_initial');self.assertEqual(source['diagnostic']['code'],'vnc_binding_changed')
  sink=self.run_case(True,'sink');self.assertFalse(sink['observerLeakedBeforeHarnessCleanup']);self.assertIsNone(sink['diagnostic']);self.assertEqual(sink['failureClass'],'MacBlocked')
 def test_typed_unlisted_error_text_never_enters_diagnostic(self):
  tree=ast.parse(NEW.read_bytes());setup=[n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='PublicGuard'or isinstance(n,ast.FunctionDef)and n.name=='precredential_failure'or isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id in{'_PUBLIC_GUARD_CODES','_PRECREDENTIAL_STAGES','_UNLOCK_DIAGNOSTIC_CODES','_VNC_DIAGNOSTIC_CODES','_INCIDENT_DIAGNOSTIC_CODES'}for t in n.targets)]
  rows=[];scope={'U':U,'V':V,'Q':Q,'args':SimpleNamespace(operation_id='44444444-4444-4444-8444-444444444444'),'native_record':lambda name,value:rows.append(value)};exec(compile(ast.Module(body=setup,type_ignores=[]),str(NEW),'exec'),scope)
  scope['precredential_failure'](V.VncBlocked('SYNTHETIC_UNEXPECTED_MESSAGE'),'vnc_auth');self.assertEqual(rows[-1]['code'],'unclassified');self.assertNotIn('SYNTHETIC_UNEXPECTED_MESSAGE',json.dumps(rows[-1]))
  scope['precredential_failure'](U.UnlockBlocked('macos_unlock_screen_unrecognized'),'image_decode');self.assertEqual(rows[-1]['code'],'macos_unlock_screen_unrecognized')
 def test_old_recipient_guard_masked_new_has_exact_owned_code(self):
  old=self.run_case(False,'recipient');self.assertEqual(old['failureClass'],'MacBlocked');self.assertIsNone(old['diagnostic'])
  new=self.run_case(True,'recipient');self.assertEqual(new['diagnostic']['code'],'public_recipient_changed');self.assertEqual(new['diagnostic']['failureClass'],'PublicGuard')
if __name__=='__main__':unittest.main(verbosity=2)
