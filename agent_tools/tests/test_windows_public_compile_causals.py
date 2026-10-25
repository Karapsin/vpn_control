"""PUBLIC-only whole-caller regressions; no VM inventory or private inputs."""
from pathlib import Path
import ast,base64,hashlib,json,os,re,stat,subprocess,tempfile,time,types,unittest
from agent_tools.tests.windows_powershell_script import json_reply,run_program
FIX=Path(__file__).resolve().parent/'fixtures/windows_public_compile'
HASHES={'parent.before.source': '21e1bec9016cf11039caa54c51fa5158df2334ba962058e5e6ebfef8513359c6', 'parent.fixed.source': 'c9db69ccfddef08a283d010471109e760020d52a1bff8ba0a2bdc174da80fbbd', 'interpreter.source': '25caad62f5f01fd7b216c3fdb05db344bd86c482ff77c2d2fe333572f66ff23c', 'receipt.before.source': 'bcd8910f154bcfcbce03945060a0ca4448f25494c16c7503509ed9529da2cccd', 'receipt.fixed.source': '274a256d0d3c052b57cfa5f673b99c958685037a4c009efe260f5347b844b568', 'public_failure.source': '153e8d118e9e1383ddb3315c4b44654d41332f384ea5dd0d44b6513f9913b2bb', 'collector.before.source': '5b7068d5ca9356acf1b033f69806ab95e91c4d17c6dd8cb860b444c48db01839', 'collector.fixed.source': '9fe3bb812c2f4cc9d8c2c4e5a6a9664127b26ab2078ef0f3a4fd4e337aa6cce0'}
def payload(name):
 raw=(FIX/name).read_bytes()
 if hashlib.sha256(raw).hexdigest()!=HASHES[name]:raise AssertionError('historical public fixture changed: '+name)
 return raw

def require(ok,reason):
 if not ok:raise ValueError(reason)

def collector(role):
 ns={'base64':base64,'subprocess':subprocess,'time':time,'OP':'11111111-1111-4111-8111-111111111111','need':require}
 exec(compile(payload('collector.'+role+'.source'),'whole-public-collector-'+role,'exec'),ns)
 return ns['collect_public_failure']

class StreamRetention(unittest.TestCase):
 @staticmethod
 def program():
  old=payload('parent.before.source').decode();new=payload('parent.fixed.source').decode();program=payload('interpreter.source').decode()
  a=[s.strip()for s in old.splitlines()if s.strip().startswith("foreach($role in @('stdout','stderr')){$raw=if")]
  b=[s.strip()for s in new.splitlines()if s.strip().startswith("foreach($role in @('stdout','stderr')){[byte[]]$raw=")]
  require(len(a)==len(b)==1,'whole_loop_boundary')
  require(old.count('$write.GetAwaiter().GetResult();$process.StandardInput.Close()')==1 and new.count('[void]$write.GetAwaiter().GetResult();$process.StandardInput.Close()')==1,'whole_awaiter_boundary')
  for marker,value in {'__OLD_ROLE_LOOP__':a[0],'__NEW_ROLE_LOOP__':b[0],'__OLD_AWAITER__':'$write.GetAwaiter().GetResult()','__NEW_AWAITER__':'[void]$write.GetAwaiter().GetResult()'}.items():
   require(program.count(marker)==1,'template_boundary');program=program.replace(marker,value)
  return program.encode()
 def test_entire_old_and_fixed_loops_are_extracted_from_authenticated_whole_parents(self):
  program=self.program().decode()
  for name in ('stdout-empty','stderr-empty','both-empty','both-nonempty'):self.assertIn(name,program)
  for token in ('Add-Type','SendInput','Start-Process','guest-exec'):self.assertNotIn(token,program)
 @unittest.skipUnless(os.name=='nt','Windows Framework PowerShell interpreter required')
 def test_actual_windows_powershell_old_RED_fixed_GREEN(self):
  ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe';self.assertTrue(ps.is_file())
  # One complete -File script: -Command - stdin would drop everything after the first unterminated multi-line function.
  result,detail=json_reply(self,run_program(ps,self.program(),30))
  self.assertTrue(result['causalQualified'],detail);self.assertFalse(result['inputAuthority'],detail);self.assertFalse(result['nativeCompilerQualified'],detail);self.assertTrue(all(x['oldRed']and x['newGreen']for x in result['cases']),detail);self.assertEqual(result['awaiter']['oldType'],'System.Threading.Tasks.VoidTaskResult',detail);self.assertEqual(result['awaiter']['newCount'],0,detail)

class ReceiptOutputBoundary(unittest.TestCase):
 def script(self):
  path=Path(__file__).resolve().parents[1]/'readiness_windows_remote.py';tree=ast.parse(path.read_bytes());main=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='_main');node=next(n for n in main.body if isinstance(n,ast.FunctionDef)and n.name=='script')
  class Saved(Exception):pass
  writes=[]
  def save(name,value):writes.append((name,value));raise Saved()
  with tempfile.TemporaryDirectory()as td:
   env={'OPERATION':'11111111-1111-4111-8111-111111111111','MODE':'observe','root':Path(td),'re':re,'os':os,'hashlib':hashlib,'json':json,'require':require,'save':save,'CONTEXT':{'hostBootId':'public-boot'},'current_actor':{'pid':1,'startTicks':2}}
   exec(compile(ast.Module(body=[node],type_ignores=[]),str(path),'exec'),env)
   return env['script'],writes,Saved
 def test_authentic_before_fails_before_any_admission_fixed_reaches_atomic_admission(self):
  script,writes,Saved=self.script()
  with self.assertRaisesRegex(ValueError,'instance_guest_output_program'):script('session',payload('receipt.before.source').decode())
  self.assertEqual(writes,[])
  with self.assertRaises(Saved):script('session',payload('receipt.fixed.source').decode())
  self.assertEqual(len(writes),1);self.assertEqual(writes[0][1]['label'],'session')
 def test_duplicate_output_and_trailing_finally_are_not_admitted(self):
  source=payload('receipt.fixed.source').decode()
  for bad in (source+'\n[Console]::WriteLine("duplicate")\n',source+'\n}finally{}\n'):
   script,writes,_=self.script()
   with self.assertRaisesRegex(ValueError,'instance_guest_output_program'):script('session',bad)
   self.assertEqual(writes,[])

class PublicTimeoutCapture(unittest.TestCase):
 def invoke(self,role,error):
  class Guard:
   def guard(self):pass
   def revalidate(self):pass
  class Transport:
   class SubmittedResultReadinessChanged(Exception):pass
   def load_config(self,*a):return None
   def build_ssh_argv(self,*a,**k):return ['fixed-public-only-reader']
   def run_ssh(self,*a,**k):raise error
  class Capture(Guard):
   def __init__(self):self.files={}
   def save(self,name,body):self.files[name]=body if type(body)is bytes else(json.dumps(body,sort_keys=True)+'\n').encode()
  cap=Capture();guard=Guard();request=types.SimpleNamespace(guard=guard.guard,session=types.SimpleNamespace(hold_result=lambda x:x));failure={'source':b'# fixed public-only HOST reader','sourceSha256':'a'*64,'guestSourceSha256':'b'*64}
  with self.assertRaises(type(error)):collector(role)(cap,request,guard.guard,guard,Transport(),failure,None,types.SimpleNamespace(ROOT='controlled-root'),time.monotonic()+10)
  return cap.files
 def test_whole_original_discards_typed_timeout_fixed_retains_incomplete_prefixes(self):
  error=subprocess.TimeoutExpired('argv-canary',1,output=b'public-partial-out',stderr=b'public-partial-err');old=self.invoke('before',error);new=self.invoke('fixed',error)
  self.assertNotIn('public-failure-read.stdout.public',old);self.assertIsNone(json.loads(old['public-failure-read.callback.json'])['stdoutBytes'])
  self.assertEqual(new['public-failure-read.stdout.public'],error.stdout);self.assertEqual(new['public-failure-read.stderr.public'],error.stderr);meta=json.loads(new['public-failure-read.callback.json']);self.assertTrue(meta['timedOut']);self.assertFalse(meta['captureComplete']);self.assertNotIn(b'argv-canary',b''.join(new.values()))
 def test_none_nonbytes_empty_and_overflow_are_explicit(self):
  for out,err in ((None,None),('private-canary',object()),(b'',b''),(b'x'*2097153,b'y'*2097154)):
   files=self.invoke('fixed',subprocess.TimeoutExpired('argv-canary',1,output=out,stderr=err));meta=json.loads(files['public-failure-read.callback.json']);self.assertFalse(meta['captureComplete'])
   for role,value in (('stdout',out),('stderr',err)):
    name='public-failure-read.'+role+'.public'
    if type(value)is bytes:self.assertEqual(files[name],value[:2097152]);self.assertEqual(meta[role+'Bytes'],len(value))
    else:self.assertNotIn(name,files);self.assertIsNone(meta[role+'Bytes'])
   self.assertEqual(meta['overflow'],type(out)is bytes and len(out)>2097152 or type(err)is bytes and len(err)>2097152);self.assertNotIn(b'canary',b''.join(files.values()))
 def test_foreign_timeout_subclass_does_not_expose_properties(self):
  class Foreign(subprocess.TimeoutExpired):
   @property
   def stdout(self):raise AssertionError('foreign property read')
  files=self.invoke('fixed',Foreign('argv-canary',1));self.assertFalse(json.loads(files['public-failure-read.callback.json'])['timedOut']);self.assertNotIn(b'canary',b''.join(files.values()))

@unittest.skipUnless(os.name=='posix','POSIX HOST metadata contract')
class PublicHostReader(unittest.TestCase):
 @staticmethod
 def action():
  tree=ast.parse(payload('public_failure.source'));packet=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='packet');node=next(n for n in packet.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='action'for t in n.targets));literal=node.value
  while isinstance(literal,ast.Call):literal=literal.func.value
  require(isinstance(literal,ast.Constant)and type(literal.value)is str,'complete_emitted_action_boundary')
  return literal.value.replace('__OP__','11111111-1111-4111-8111-111111111111').replace('__SOURCE__','a'*64)
 def run_action(self,change=None):
  op='11111111-1111-4111-8111-111111111111';actor={'pid':7,'startTicks':9};frame={'schemaVersion':1,'operationId':op,'label':'session','sourceSha256':'a'*64}
  records={'intent':{'operationId':op,'label':'session','sourceSha256':'a'*64,'hostBoot':'public-boot','actor':actor,'replayAllowed':False,'controllerIdentity':frame},'ack':{'operationId':op,'label':'session','ack':{'pid':8},'replayAllowed':False},'observed-terminal':{'exited':True,'exitcode':1,'out-data':'','err-data':base64.b64encode(b'public-original-failure').decode()}}
  def generation(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  def private(path):
   s=os.lstat(path);require(stat.S_ISREG(s.st_mode)and s.st_uid==os.geteuid()and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1,'private_metadata');return s
  with tempfile.TemporaryDirectory()as td:
   root=Path(td).resolve();root.chmod(0o700)
   for role,value in records.items():p=root/('readiness-'+op+'-session.'+role+'.json');p.write_text(json.dumps(value));p.chmod(0o600)
   if change:change(root,records)
   held=[];pins=[];ns={'root':root,'state':'running','private':private,'generation':generation,'held':held,'pins':pins,'os':os,'hashlib':hashlib,'json':json,'base64':base64,'require':require,'CONTEXT':{'hostBootId':'public-boot'},'current_actor':actor,'result':{}}
   before=set(root.iterdir())
   try:
    exec(compile(self.action(),'complete-emitted-public-HOST-reader','exec'),ns)
    for fd,path,gen in pins:self.assertEqual(generation(os.fstat(fd)),gen);self.assertEqual(generation(os.lstat(path)),gen)
    self.assertEqual(set(root.iterdir()),before);return ns['result']
   finally:
    for fd in held:os.close(fd)
 def test_complete_emitted_reader_retains_original_raw_without_guest_or_new_wire(self):
  value=self.run_action();rows=value['originalPublicFailure']['records'];raw=base64.b64decode(rows['observed-terminal']['raw']);self.assertIn(b'public-original-failure',base64.b64decode(json.loads(raw)['err-data']));self.assertFalse(value['originalPublicFailure']['inputAuthority']);self.assertNotIn('rpc(',self.action())
 def test_source_boot_actor_and_duplicate_intent_refuse(self):
  for key,value in (('sourceSha256','f'*64),('hostBoot','foreign'),('actor',{'pid':99})):
   def change(root,records):
    records['intent'][key]=value;(root/'readiness-11111111-1111-4111-8111-111111111111-session.intent.json').write_text(json.dumps(records['intent']))
   with self.assertRaisesRegex(ValueError,'instance_public_failure_intent'):self.run_action(change)
  def duplicate(root,records):
   p=root/'readiness-11111111-1111-4111-8111-111111111111-session.intent.json';p.write_bytes(b'{"operationId":1,"operationId":2}')
  with self.assertRaisesRegex(ValueError,'duplicate'):self.run_action(duplicate)
 def test_symlink_hardlink_and_permissive_metadata_refuse(self):
  for kind in ('symlink','hardlink','mode'):
   def change(root,records):
    p=root/'readiness-11111111-1111-4111-8111-111111111111-session.intent.json'
    if kind=='mode':p.chmod(0o644)
    else:
     original=root/'original';p.rename(original)
     if kind=='symlink':p.symlink_to(original)
     else:os.link(original,p)
   with self.assertRaisesRegex(ValueError,'private_metadata'):self.run_action(change)

if __name__=='__main__':unittest.main()
