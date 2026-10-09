"""Own TempFS and controlled process/streams; actual production collect AST."""
import ast,hashlib,json,os,pathlib,tempfile,types,unittest
B=pathlib.Path(__file__).resolve().parent
SOURCE=pathlib.Path(os.environ.get('COLLECTOR_SOURCE_FILE','agent_tools/android_installer_asset_collection.py')).resolve()
SOURCE_SHA=hashlib.sha256(SOURCE.read_bytes()).hexdigest()
def collect_source():
 text=SOURCE.read_text();tree=ast.parse(text)
 literal=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='COLLECTOR_SOURCE'for t in n.targets))
 nodes=[n for n in ast.parse(literal).body if isinstance(n,ast.FunctionDef)and n.name in ('encoded','digest','archive','collect')or isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id in ('CHUNK','STREAM_LIMIT')for t in n.targets)]
 return ast.Module(body=nodes,type_ignores=[])
class Stream:
 def __init__(self,name,fd,fail=False):self.name=name;self.fd=fd;self.closed=False;self.close_calls=0;self.fail=fail
 def fileno(self):return self.fd
 def close(self):
  self.close_calls+=1
  if self.fail:raise RuntimeError('synthetic_close_denied')
  self.closed=True
class Process:
 def __init__(self,close_fail=False,returncode=0):self.pid=4242;self.stdin=Stream('stdin',101);self.stdout=Stream('stdout',102);self.stderr=Stream('stderr',103,close_fail);self.returncode=returncode;self.kill_calls=0;self.wait_calls=0
 def wait(self,timeout):self.wait_calls+=1;return self.returncode
 def poll(self):return self.returncode
 def kill(self):self.kill_calls+=1;raise AssertionError('no actual or new kill permitted by control')
class Capture:
 def __init__(self,path,denials):self.path=path;self.fd=os.open(path/'capture-fsync-anchor',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);self.names=[];self.denials=denials;self.errors={k:ValueError('synthetic_'+k.replace('.','_'))for k in denials}
 def create(self,name,raw):
  self.names.append(name)
  if name in self.denials:raise self.errors[name]
  p=self.path/name;p.write_bytes(raw);return {'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
 def close(self):os.close(self.fd)
def run_case(denials=(),close_fail=False,body_error=None,returncode=0):
 with tempfile.TemporaryDirectory(dir=B,prefix='owned-control-')as tmp:
  p=Process(close_fail,returncode);c=Capture(pathlib.Path(tmp),set(denials));reads=0
  def select(readers,writers,exceptional,timeout):
   nonlocal reads
   reads+=1
   if reads==1 and body_error is not None:raise body_error
   return list(readers),list(writers),[]
  calls=[]
  def popen(*args,**kwargs):calls.append((args,kwargs));return p
  ns={'hashlib':hashlib,'json':json,'time':types.SimpleNamespace(monotonic=lambda:100.0,time=lambda:200.0),'select':types.SimpleNamespace(select=select),'subprocess':types.SimpleNamespace(Popen=popen,PIPE=object()),'os':types.SimpleNamespace(set_blocking=lambda *a:None,write=lambda fd,raw:len(raw),read=lambda fd,n:b'',fsync=os.fsync)}
  exec(compile(collect_source(),'<actual-production-collect-control>','exec'),ns)
  error=None;result=None
  try:result=ns['collect']({'capture':c,'argv':['SYNTHETIC-NONDISPATCH'],'source':b'public inert source'},b'public inert prefix\n')
  except BaseException as e:error=e
  files={x.name:json.loads(x.read_bytes())for x in pathlib.Path(tmp).glob('*.json')}
  outcome={'sourceSha256':SOURCE_SHA,'names':c.names,'streams':{s.name:{'closeAttempts':s.close_calls,'closed':s.closed}for s in (p.stdin,p.stdout,p.stderr)},'waitCalls':p.wait_calls,'killCalls':p.kill_calls,'popenCalls':len(calls),'files':files,'exception':None if error is None else {'type':type(error).__name__,'message':str(error),'notes':getattr(error,'__notes__',[])},'result':None if result is None else result.decode(),'realSubprocessCalls':0,'nativeInvocations':0}
  c.close();return outcome,error,c.errors
class CloseoutRegression(unittest.TestCase):
 def test_first_stdout_publication_attempts_every_owned_closeout(self):
  o,e,errors=run_case(('stdout-manifest.json',));self.assertIs(e,errors['stdout-manifest.json'])
  self.assertTrue(o['streams']['stdout']['closed']);self.assertTrue(o['streams']['stderr']['closed'])
  self.assertIn('stderr-manifest.json',o['files']);self.assertIn('exit.json',o['files']);self.assertEqual(o['files']['exit.json'],{'failure':'ValueError','returncode':0})
  self.assertEqual(o['killCalls'],0);self.assertEqual(o['waitCalls'],1)
 def test_secondary_close_failure_retains_primary_and_is_truthful(self):
  o,e,errors=run_case(('stdout-manifest.json',),True);self.assertIs(e,errors['stdout-manifest.json'])
  self.assertTrue(o['streams']['stdout']['closed']);self.assertFalse(o['streams']['stderr']['closed']);self.assertEqual(o['streams']['stderr']['closeAttempts'],1)
  self.assertEqual(o['files']['cleanup-failures.json']['failures'],[{'stage':'stdout-publication','exceptionType':'ValueError'},{'stage':'stderr-close','exceptionType':'RuntimeError'}])
 def test_collection_unknown_dominates_closeout_denial(self):
  o,e,errors=run_case(('stdout-manifest.json',),body_error=OSError('synthetic_collection_unknown'))
  self.assertEqual(type(e),ValueError);self.assertEqual(str(e),'baseline_transport_unknown_raw_retained');self.assertEqual(o['files']['exit.json']['failure'],'OSError');self.assertTrue(o['streams']['stdout']['closed']);self.assertTrue(o['streams']['stderr']['closed'])
 def test_unhandled_primary_interrupt_is_preserved(self):
  primary=KeyboardInterrupt('synthetic_primary_interrupt');o,e,errors=run_case(('stdout-manifest.json',),body_error=primary)
  self.assertIs(e,primary);self.assertTrue(o['streams']['stdout']['closed']);self.assertTrue(o['streams']['stderr']['closed']);self.assertEqual(o['files']['exit.json']['failure'],'KeyboardInterrupt')
 def test_secondary_exit_and_diagnostic_denials_do_not_mask_first(self):
  o,e,errors=run_case(('stdout-manifest.json','exit.json','cleanup-failures.json'));self.assertIs(e,errors['stdout-manifest.json']);self.assertTrue(o['streams']['stdout']['closed']);self.assertTrue(o['streams']['stderr']['closed']);self.assertIn('exit.json',o['names']);self.assertIn('cleanup-failures.json',o['names']);self.assertTrue(any('exit-publication' in n for n in getattr(e,'__notes__',[])));self.assertTrue(any('cleanup-publication' in n for n in getattr(e,'__notes__',[])))
 def test_nonzero_child_and_publication_denial_retain_exact_facts(self):
  o,e,errors=run_case(('stdout-manifest.json',),returncode=5)
  # A first cleanup denial may surface before the nonzero postcondition. The
  # accepted child's code and every attempted cleanup fact remain truthful.
  self.assertIs(e,errors['stdout-manifest.json'])
  self.assertEqual(o['files']['exit.json'],{'failure':'ValueError','returncode':5})
  self.assertTrue(o['streams']['stdout']['closed']);self.assertTrue(o['streams']['stderr']['closed'])
  self.assertIn('stderr-manifest.json',o['files'])
  self.assertEqual(o['files']['cleanup-failures.json']['failures'],[{'stage':'stdout-publication','exceptionType':'ValueError'}])
  self.assertEqual(o['waitCalls'],1);self.assertEqual(o['killCalls'],0);self.assertIsNone(o['result'])
 def test_success_and_nonzero_unknown_remain_original(self):
  o,e,errors=run_case();self.assertIsNone(e);self.assertEqual(o['result'],'');self.assertNotIn('cleanup-failures.json',o['files']);self.assertEqual(o['files']['exit.json'],{'failure':None,'returncode':0})
  o,e,errors=run_case(returncode=5);self.assertEqual(str(e),'baseline_transport_unknown_raw_retained');self.assertEqual(o['files']['exit.json'],{'failure':None,'returncode':5});self.assertNotIn('cleanup-failures.json',o['files'])
if __name__=='__main__':unittest.main(verbosity=2)
