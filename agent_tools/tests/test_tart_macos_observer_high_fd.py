"""Actual full constructor with real high-numbered local pipes; no native VM.

The native failure's FD number was NOT retained. This proves a controlled
causal failure matching its recorded host phase and guest gate error, not a
retrospective native FD observation. No resource limit is changed.
"""
from pathlib import Path
from contextlib import contextmanager
import hashlib,json,os,subprocess,sys,tempfile,time,traceback,types,unittest
from unittest import mock
FIXTURE=Path(__file__).with_name('fixtures')/'tart_macos_startup_high_fd'
from agent_tools import readiness_tart_macos_unlock as unlock
from agent_tools import durable_remote_job as J
from agent_tools import private_inventory_lock as P
from agent_tools.tests.test_readiness_tart_macos_unlock import binding,identity

def before_module():
 path=FIXTURE/'unlock.before.source';raw=path.read_bytes()
 if hashlib.sha256(raw).hexdigest()!='03bf7bc2271576300fb5e0091e284edad1292d54db3eac6df1bfe60dbeba6340':raise AssertionError('retained whole high-FD source changed')
 m=types.ModuleType('agent_tools._startup_high_fd_before');m.__package__='agent_tools';m.__file__=str(path)
 exec(compile(raw,str(path),'exec',dont_inherit=True),m.__dict__);return m

@contextmanager
def high_fds():
 held=[]
 try:
  while not held or held[-1]<1100:held.append(os.open(os.devnull,os.O_RDONLY|os.O_CLOEXEC))
  yield len(held)
 finally:
  for fd in held:os.close(fd)
@unittest.skipUnless(os.name=='posix'and hasattr(os,'O_CLOEXEC'),'high-FD private pipes require POSIX')
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  import resource
  soft,_=resource.getrlimit(resource.RLIMIT_NOFILE)
  if soft!=resource.RLIM_INFINITY and soft<1200:raise unittest.SkipTest('requires existing RLIMIT_NOFILE>=1200; limit is never changed')
  cls.before=before_module();cls.current=unlock
 def packet(self,subject,delay=0):
  code='import json,sys,time\ne='+repr(identity())+'\n'
  if delay:code+='time.sleep('+repr(delay)+')\n'
  code+='print(json.dumps({"protocol":'+repr(subject.stream.PROTOCOL)+',"state":"observer_ready","observation":e}),flush=True)\n'
  code+='for line in sys.stdin.buffer:\n a,n,nonce=line.decode().strip().split()\n print(json.dumps({"protocol":'+repr(subject.stream.PROTOCOL)+',"state":"observed","counter":int(n),"nonce":nonce,"observation":e}),flush=True)\n'
  raw=code.encode();assert len(raw)<7482;return raw+b'\n#'+b'x'*(7482-len(raw)-2)
 def launch(self,subject,children):
  actual=subprocess.Popen
  def spawned(argv,**kwargs):
   self.assertEqual(argv[:4],[binding().tart_binary,'exec','-i',binding().vm_name]);self.assertEqual(argv[-2],'-c');gate=argv[-1]
   child=actual([sys.executable,'-I','-B','-c',gate],**kwargs);children.append((child,J._birth(child.pid),{'stdin':child.stdin.fileno(),'stdout':child.stdout.fileno(),'stderr':child.stderr.fileno()}));return child
  return spawned
 def test_full_constructor_real_held_fds_before_red_selectors_green(self):
  rows=[]
  for current in(False,True):
   subject=self.current if current else self.before;children=[];observer=None;failure=None
   with high_fds()as held_count,tempfile.TemporaryDirectory()as temporary:
    root=Path(temporary).resolve();root.chmod(0o700)
    with P.Directory(root)as directory:
     journal=subject._StartupEvidence(directory,'55555555-5555-4555-8555-555555555555')
     try:
      with mock.patch.object(subject.stream,'guest_session_stream_source',return_value=self.packet(subject)),mock.patch.object(subject.subprocess,'Popen',self.launch(subject,children)):
       try:
        observer=subject.SessionObserver(types.SimpleNamespace(binding=binding()),identity(),time.monotonic()+10,guard=lambda:None,_startup=journal)
        self.assertEqual(identity(),observer.check())
       except BaseException as error:
        failure={'class':type(error).__name__,'frames':[{'function':r.name,'line':r.lineno}for r in traceback.extract_tb(error.__traceback__)]}
     finally:
      if observer is not None:observer.close()
      journal.close()
      for child,birth,fds in children:
       self.assertIsNotNone(birth);self.assertNotEqual(J._birth(child.pid),birth);self.assertIsNotNone(child.poll());self.assertTrue(all(pipe.closed for pipe in(child.stdin,child.stdout,child.stderr)))
     self.assertTrue(all(fd>=1024 for child,birth,fds in children for fd in fds.values()))
    events=[json.loads(line)for line in(root/'startup-55555555-5555-4555-8555-555555555555.events').read_bytes().splitlines()];stdout=(root/'startup-55555555-5555-4555-8555-555555555555.stdout').read_bytes();stderr=(root/'startup-55555555-5555-4555-8555-555555555555.stderr').read_bytes()
    if not current:
     self.assertEqual('ValueError',failure['class']);self.assertEqual({'function':'_initialize','line':382},failure['frames'][-1]);self.assertEqual('write_fixed_payload',next(r['phase']for r in events if r['stage']=='startup_failed'));self.assertEqual(b'',stdout);self.assertTrue(stderr.startswith(b'Traceback (most recent call last):\n'));self.assertTrue(stderr.endswith(b'AssertionError: guest_source_changed\n'))
    else:self.assertIsNone(failure);self.assertGreater(len(stdout),0);self.assertEqual(b'',stderr);self.assertEqual('ready',events[-1]['state'])
    rows.append({'current':current,'actualHeldDevnullFds':held_count,'actualChildPipeFds':children[0][2],'failure':failure,'returncode':children[0][0].returncode,'stderrBytes':len(stderr),'stdoutBytes':len(stdout),'allLocalChildrenClosed':True,'actualNativeFdProven':False})
  self.assertEqual(2,len(rows))
 def test_high_fd_read_and_unsolicited_check_sites_are_also_covered(self):
  results=[]
  for current in(False,True):
   subject=self.current if current else self.before
   # Complete actual read() on an ordinary real pipe above FD_SETSIZE.
   with high_fds():
    r,w=os.pipe()
    try:
     os.write(w,(json.dumps({'protocol':subject.stream.PROTOCOL,'state':'observer_ready','observation':identity()})+'\n').encode());os.close(w);w=None
     with os.fdopen(r,'rb',buffering=0)as channel:
      r=None;observer=object.__new__(subject.SessionObserver);observer.buffer=bytearray();observer.deadline=time.monotonic()+3;observer.process=types.SimpleNamespace(stdout=channel)
      if current:self.assertEqual(identity(),observer.read()['observation'])
      else:
       with self.assertRaises(ValueError):observer.read()
    finally:
     if r is not None:os.close(r)
     if w is not None:os.close(w)
   # Complete ctor at ordinary descriptors, then move only its SAME original
   # read pipe to a held high descriptor. No source/guest/owner is replaced.
   children=[];observer=None
   try:
    with mock.patch.object(subject.stream,'guest_session_stream_source',return_value=self.packet(subject)),mock.patch.object(subject.subprocess,'Popen',self.launch(subject,children)):
     observer=subject.SessionObserver(types.SimpleNamespace(binding=binding()),identity(),time.monotonic()+10,guard=lambda:None)
     with high_fds():
      process=observer.process;original=process.stdout;fd=os.dup(original.fileno());self.assertGreaterEqual(fd,1024);process.stdout=os.fdopen(fd,'rb',buffering=0);original.close()
      if current:self.assertEqual(identity(),observer.check())
      else:
       with self.assertRaises(ValueError):observer.check()
   finally:
    if observer is not None:observer.close()
    for child,birth,fds in children:self.assertIsNotNone(birth);self.assertNotEqual(J._birth(child.pid),birth)
   results.append({'current':current,'readSiteCorrect':current,'checkSiteCorrect':current,'allOwnedChildrenClosed':True})
  self.assertEqual(2,len(results))
 def test_three_second_startup_deadline_is_unchanged(self):
  subject=self.current;children=[];observer=None;started=time.monotonic()
  try:
   with mock.patch.object(subject.stream,'guest_session_stream_source',return_value=self.packet(subject,3.2)),mock.patch.object(subject.subprocess,'Popen',self.launch(subject,children)):
    with self.assertRaisesRegex(subject.UnlockBlocked,'observer_deadline'):
     observer=subject.SessionObserver(types.SimpleNamespace(binding=binding()),identity(),started+10,guard=lambda:None)
  finally:
   if observer is not None:observer.close()
   for child,birth,fds in children:self.assertIsNotNone(birth);self.assertNotEqual(J._birth(child.pid),birth)
  self.assertLess(time.monotonic()-started,6)
 def test_selector_closes_after_timeout_ready_eof_and_registration_or_wait_error(self):
  subject=self.current;actual=subject.selectors.DefaultSelector;closures=[]
  class Tracked:
   def __init__(self):
    self.inner=actual();self.fd=self.inner.fileno()
   def __enter__(self):return self
   def __exit__(self,*args):
    self.inner.close()
    try:os.fstat(self.fd)
    except OSError:closures.append(True)
    else:closures.append(False)
   def register(self,*args):return self.inner.register(*args)
   def select(self,*args):return self.inner.select(*args)
  r,w=os.pipe()
  try:
   with os.fdopen(r,'rb',buffering=0)as pipe:
    r=None
    with mock.patch.object(subject.selectors,'DefaultSelector',Tracked):
     self.assertFalse(subject._poll(pipe,subject.selectors.EVENT_READ,.01))
     os.close(w);w=None
     self.assertTrue(subject._poll(pipe,subject.selectors.EVENT_READ,0))
     observer=object.__new__(subject.SessionObserver);observer.process=types.SimpleNamespace(stdout=pipe,poll=lambda:None);observer.buffer=bytearray();observer.deadline=time.monotonic()+1
     with self.assertRaisesRegex(subject.UnlockBlocked,'observer_unavailable'):observer.read()
     with self.assertRaisesRegex(subject.UnlockBlocked,'observer_unsolicited'):observer.check()
     pipe.close()
     with self.assertRaises(ValueError):subject._poll(pipe,subject.selectors.EVENT_READ,0)
   self.assertTrue(closures and all(closures))
  finally:
   if r is not None:os.close(r)
   if w is not None:os.close(w)
  class FailedWait(Tracked):
   def select(self,*args):raise OSError()
  r,w=os.pipe()
  try:
   with os.fdopen(r,'rb',buffering=0)as pipe:
    r=None
    with mock.patch.object(subject.selectors,'DefaultSelector',FailedWait):
     with self.assertRaises(OSError):subject._poll(pipe,subject.selectors.EVENT_READ,0)
   self.assertTrue(all(closures))
  finally:
   if r is not None:os.close(r)
   os.close(w)
 def test_controlled_fd_allocation_limit_stops_and_closes_every_held_fd(self):
  actual=os.open;opened=[]
  def bounded(*args,**kwargs):
   if len(opened)==3:raise OSError()
   fd=actual(*args,**kwargs);opened.append(fd);return fd
  with mock.patch.object(os,'open',bounded):
   with self.assertRaises(OSError):
    with high_fds():raise AssertionError('allocation must stop before observer creation')
  for fd in opened:
   with self.assertRaises(OSError):os.fstat(fd)

if __name__=='__main__':unittest.main(verbosity=2)
