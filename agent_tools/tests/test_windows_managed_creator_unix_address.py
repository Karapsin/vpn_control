"""Whole-before RED/GREEN for the managed creator's long AF_UNIX credential socket.

The unfixed creator refused its canonical 141-byte credentials.sock pathname
before credential handoff (original 7e8b2dcd). The current creator binds and
connects through held directory descriptors. Its Linux-only cases qualify the
actual /proc/self/fd pathname, SO_PEERCRED and once fence natively; synthetic
input only, no VM effects.
"""
from pathlib import Path
import hashlib,io,json,os,socket,stat,subprocess,sys,tempfile,threading,time,types,unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_windows_managed_create as NEW
FIXTURES=Path(__file__).parent/'fixtures/windows_managed_creator_unix_address'
OP='2c370170-4b6b-4d29-b913-90fe76fa0fa0'
FRAME=json.dumps({'user':'SYNTHETIC_PUBLIC_USER_00000000000','administrator':'SYNTHETIC_PUBLIC_ADMIN_0000000000'}).encode()
def before():
 path=FIXTURES/'managed_create.before.source';raw=path.read_bytes()
 assert hashlib.sha256(raw).hexdigest()==json.loads((FIXTURES/'provenance.json').read_bytes())['files']['managed_create.before.source']['sha256']
 module=types.ModuleType('agent_tools._owned_unix_address_before');module.__package__='agent_tools';module.__file__=str(path);sys.modules[module.__name__]=module;exec(compile(raw,str(path),'exec'),module.__dict__);return module
OLD=before()
class SocketAddress(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700);self.job=self.root/('a'*70)/('b'*40);self.job.mkdir(parents=True,mode=0o700);self.other=self.root/'other';self.other.mkdir(mode=0o700);self.calls=[]
  self.module=types.SimpleNamespace(_private=jobs._private,_publish=lambda *a:self.calls.append(a),_birth=jobs._birth,_record=jobs._record)
 def tearDown(self):self.tmp.cleanup()
 def test_complete_native_before_fails_long_canonical_address_before_any_publication(self):
  self.assertGreater(len(os.fsencode(self.job/'credentials.sock')),141)
  with self.assertRaisesRegex(OSError,'AF_UNIX path too long'):OLD._receive_credentials(self.job,self.module,OP)
  self.assertEqual(self.calls,[]);self.assertFalse((self.job/'credentials.sock').exists())
 def test_current_rejects_nonprivate_job_before_bind(self):
  self.job.chmod(0o755)
  with self.assertRaises(ValueError):NEW._receive_credentials(self.job,self.module,OP)
  self.assertEqual(self.calls,[])
 def test_current_rejects_held_directory_generation_mismatch_before_bind(self):
  original=os.open
  def changed(path,flags,*args,**kwargs):return original(self.other if Path(path)==self.job else path,flags,*args,**kwargs)
  with patch.object(os,'open',side_effect=changed),self.assertRaisesRegex(ValueError,'private_input_invalid'):NEW._receive_credentials(self.job,self.module,OP)
  self.assertEqual(self.calls,[])
 def test_current_rejects_named_directory_replacement_after_open_before_bind(self):
  original=os.open;retired=self.job.with_name('retired')
  def changed(path,flags,*args,**kwargs):
   fd=original(path,flags,*args,**kwargs)
   if Path(path)==self.job:self.job.rename(retired);self.job.mkdir(mode=0o700)
   return fd
  with patch.object(os,'open',side_effect=changed),self.assertRaisesRegex(ValueError,'private_input_invalid'):NEW._receive_credentials(self.job,self.module,OP)
  self.assertEqual(self.calls,[]);self.assertFalse((self.job/'credentials.sock').exists())
 @unittest.skipUnless(sys.platform.startswith('linux'),'Linux proc-FD pathname and SO_PEERCRED native qualification')
 def test_complete_before_red_current_receive_and_handoff_same_long_socket_green(self):
  ready=threading.Event();received=[];failures=[]
  def publish(path,value):jobs._publish(path,value);ready.set()
  self.module._publish=publish
  def receive():
   try:received.append(NEW._receive_credentials(self.job,self.module,OP))
   except BaseException as e:failures.append(type(e).__name__)
  thread=threading.Thread(target=receive,daemon=True);thread.start();self.assertTrue(ready.wait(2));row=jobs._record(self.job/'creator-listener.json');self.assertEqual(row['actor'],{'pid':os.getpid(),'birth':jobs._birth(os.getpid())});self.assertEqual(stat.S_IMODE((self.job/'credentials.sock').lstat().st_mode),0o600)
  boundary=lambda *a,**k:(self.module,{}, {'pid':os.getppid()},b'EXPLICIT_CONTROLLED_SOURCE_BOUNDARY')
  output=io.StringIO()
  with patch.object(NEW,'_channel_identity',boundary),patch.object(sys,'stdin',io.TextIOWrapper(io.BytesIO(FRAME))),redirect_stdout(output):NEW._handoff(str(self.job),{'operationId':OP},'CONTROLLED_OWNER')
  thread.join(2);self.assertFalse(thread.is_alive());self.assertEqual(failures,[]);self.assertEqual(received,[json.loads(FRAME)]);self.assertEqual(json.loads(output.getvalue()),{'state':'credentials-accepted','operationId':OP,'replayAllowed':False});self.assertTrue((self.job/'credentials-handoff.intent.json').exists())
  # Original once fence prevents a second frame even after receiver exits.
  with patch.object(NEW,'_channel_identity',boundary),patch.object(sys,'stdin',io.TextIOWrapper(io.BytesIO(FRAME))),redirect_stdout(io.StringIO())as repeated:NEW._handoff(str(self.job),{'operationId':OP},'CONTROLLED_OWNER')
  self.assertEqual(json.loads(repeated.getvalue())['state'],'original-observation-required')
 @unittest.skipUnless(sys.platform.startswith('linux'),'Linux proc-FD pathname and SO_PEERCRED native qualification')
 def test_complete_handoff_rejects_foreign_actual_peer_before_frame_or_once_fence(self):
  child_source="""import os,pathlib,socket,sys
p=pathlib.Path(sys.argv[1]);fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);s=socket.socket(socket.AF_UNIX);s.bind('/proc/self/fd/'+str(fd)+'/credentials.sock');os.chmod(p/'credentials.sock',0o600);s.listen(1);print('ready',flush=True);s.settimeout(3);c,_=s.accept();c.settimeout(3);data=c.recv(4096);print(len(data),flush=True);c.close();s.close();os.close(fd)
"""
  child=subprocess.Popen([sys.executable,'-I','-B','-c',child_source,str(self.job)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  try:
   self.assertEqual(child.stdout.readline(),'ready\n');info=(self.job/'credentials.sock').lstat();exe=os.stat('/proc/self/exe');pin=lambda i:[getattr(i,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
   jobs._publish(self.job/'creator-listener.json',{'operationId':OP,'actor':{'pid':os.getpid(),'birth':jobs._birth(os.getpid())},'executableGeneration':pin(exe),'socketIdentity':[info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid]})
   boundary=lambda *a,**k:(self.module,{}, {'pid':os.getppid()},b'EXPLICIT_CONTROLLED_SOURCE_BOUNDARY')
   with patch.object(NEW,'_channel_identity',boundary),patch.object(sys,'stdin',io.TextIOWrapper(io.BytesIO(FRAME))),redirect_stdout(io.StringIO())as output:NEW._handoff(str(self.job),{'operationId':OP},'CONTROLLED_OWNER')
   self.assertEqual(json.loads(output.getvalue())['state'],'blocked');self.assertFalse((self.job/'credentials-handoff.intent.json').exists());out,err=child.communicate(timeout=3);self.assertEqual((child.returncode,out,err),(0,'0\n',''))
  finally:
   if child.poll()is None:child.kill();child.communicate()
class Provenance(unittest.TestCase):
 def test_retained_whole_before_artifact_has_exact_custody(self):
  provenance=json.loads((FIXTURES/'provenance.json').read_bytes());self.assertTrue(provenance['nativeFailureClaimed'])
  for leaf,pin in provenance['files'].items():self.assertEqual(pin['sha256'],hashlib.sha256((FIXTURES/leaf).read_bytes()).hexdigest(),leaf)
if __name__=='__main__':unittest.main()
