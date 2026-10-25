"""Whole protected reader/client over owned regular files, pipes and real TCP.

Only public synthetic fixture values live in temporary files/memory. Reports
never contain value bytes, lengths, hashes, wire responses or private messages.
No native VM, account credential or resource-limit change is involved.
"""
from pathlib import Path
from contextlib import contextmanager
import hashlib,json,os,subprocess,sys,tempfile,time,traceback,types,unittest
try:
 import fcntl
except ImportError:
 fcntl=None
from unittest import mock
FIXTURE=Path(__file__).with_name('fixtures')/'tart_vnc_protected_fd_high'
from agent_tools.tests.test_readiness_tart_vnc import RfbEndpoint
from agent_tools import readiness_tart_vnc as subject

def before_module():
 path=FIXTURE/'vnc.before.source';raw=path.read_bytes()
 if hashlib.sha256(raw).hexdigest()!='a5b5196c62cdfb2270d3f54faf3f8c318022d16a174447722a94f9d18d2b0a1d':raise AssertionError('retained protected FD source changed')
 value=types.ModuleType('_protected_fd_before');value.__file__=str(path)
 exec(compile(raw,str(path),'exec',dont_inherit=True),value.__dict__);return value

@contextmanager
def high_fds():
 holders=[]
 try:
  while not holders or holders[-1]<1100:holders.append(os.open(os.devnull,os.O_RDONLY|os.O_CLOEXEC))
  yield
 finally:
  for fd in holders:os.close(fd)
@contextmanager
def handed(kind,value,*,blocking=True,writer_open=False):
 if kind=='regular':
  with tempfile.TemporaryDirectory()as temporary:
   root=Path(temporary).resolve();root.chmod(0o700);path=root/'private-synthetic-value';path.write_bytes(value);path.chmod(0o600);fd=os.open(path,os.O_RDONLY)
   try:
    os.set_blocking(fd,blocking);yield fd
   finally:os.close(fd)
 else:
  fd,writer=os.pipe()
  try:
   if value:os.write(writer,value)
   if not writer_open:os.close(writer);writer=None
   os.set_blocking(fd,blocking);yield fd
  finally:
   os.close(fd)
   if writer is not None:os.close(writer)
@unittest.skipUnless(os.name=='posix'and fcntl is not None and hasattr(os,'O_CLOEXEC'),'private high-FD readiness requires POSIX')
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  import resource
  soft,_=resource.getrlimit(resource.RLIMIT_NOFILE)
  if soft!=resource.RLIM_INFINITY and soft<1200:raise unittest.SkipTest('requires existing RLIMIT_NOFILE>=1200; limit is never changed')
  cls.before=before_module();cls.current=subject
 def protected(self,subject,fd,limit=256,seconds=1):
  old=fcntl.fcntl(fd,fcntl.F_GETFL);duplicates=[];real=os.dup
  def dup(original):
   copied=real(original);duplicates.append(copied);return copied
  try:
   with mock.patch.object(subject.os,'dup',dup):return subject._protected_bytes(fd,limit,time.monotonic()+seconds)
  finally:
   self.assertEqual(old,fcntl.fcntl(fd,fcntl.F_GETFL))
   for duplicate in duplicates:
    with self.assertRaises(OSError):os.fstat(duplicate)
 def test_whole_reader_high_fd_regular_and_pipe_before_red_current_green(self):
  rows=[]
  for current in(False,True):
   subject=self.current if current else self.before
   for kind in('regular','pipe'):
    for blocking in(False,True):
     with high_fds(),handed(kind,b'public-only-fixture',blocking=blocking)as fd:
      self.assertGreaterEqual(fd,1024)
      if current:self.assertTrue(self.protected(subject,fd)==b'public-only-fixture')
      else:
       with self.assertRaisesRegex(subject.VncBlocked,'^vnc_credential_unavailable$'):self.protected(subject,fd)
      rows.append({'current':current,'kind':kind,'initialBlocking':blocking,'expectedOutcome':True,'flagsRestored':True,'duplicateClosed':True})
  self.assertEqual(8,len(rows))
 def test_regular_files_never_enter_epoll_or_other_selector(self):
  subject=self.current
  with handed('regular',b'public-fixture')as fd,mock.patch.object(subject.selectors,'DefaultSelector',side_effect=AssertionError('regular files must not use epoll')):
   self.assertTrue(self.protected(subject,fd)==b'public-fixture')
 def test_flags_restore_and_non_echo_for_timeout_empty_overflow_and_private_io_error(self):
  subject=self.current
  for kind in('regular','pipe'):
   for raw,limit,reason in((b'',8,'vnc_credential_empty'),(b'NON_ECHO_MARKER_FIXTURE',8,'vnc_credential_overflow')):
    with handed(kind,raw)as fd:
     with self.assertRaises(subject.VncBlocked)as caught:self.protected(subject,fd,limit)
     self.assertEqual(reason,str(caught.exception));rendered=''.join(traceback.format_exception(caught.exception));self.assertNotIn('NON_ECHO_MARKER_FIXTURE',rendered);self.assertNotIn('private-synthetic-value',rendered)
  with handed('pipe',b'',writer_open=True)as fd:
   with self.assertRaisesRegex(subject.VncBlocked,'^vnc_credential_deadline$'):self.protected(subject,fd,seconds=.03)
  with handed('regular',b'public')as fd:
   with self.assertRaisesRegex(subject.VncBlocked,'^vnc_deadline$'):self.protected(subject,fd,seconds=-1)
  with handed('regular',b'public')as fd,mock.patch.object(subject.os,'read',side_effect=OSError('NON_ECHO_MARKER_FIXTURE')):
   with self.assertRaisesRegex(subject.VncBlocked,'^vnc_credential_unavailable$')as caught:self.protected(subject,fd)
   self.assertNotIn('NON_ECHO_MARKER_FIXTURE',''.join(traceback.format_exception(caught.exception)))
 def test_invalid_file_modes_and_types_never_reach_network(self):
  subject=self.current
  with tempfile.TemporaryDirectory()as temporary:
   path=Path(temporary)/'private-synthetic-value';path.write_bytes(b'public');path.chmod(0o644);fd=os.open(path,os.O_RDONLY)
   try:
    with mock.patch.object(subject.socket,'create_connection',side_effect=AssertionError('no network')):
     with self.assertRaisesRegex(subject.VncBlocked,'^vnc_credential_fd_invalid$')as caught:
      with subject.ProtectedVncSession(port=5901,credential_fd=fd,guard=lambda:None):pass
    self.assertNotIn(str(path),''.join(traceback.format_exception(caught.exception)))
   finally:os.close(fd)
  for descriptor in(0,1,2,True,-1):
   with self.assertRaisesRegex(subject.VncBlocked,'^vnc_credential_fd_invalid$'):subject._protected_bytes(descriptor,8,time.monotonic()+1)
 def test_pipe_selector_closes_after_ready_timeout_register_and_wait_errors(self):
  subject=self.current;actual=subject.selectors.DefaultSelector;closed=[]
  class Tracked:
   def __init__(self):self.actual=actual();self.fd=self.actual.fileno()
   def __enter__(self):return self
   def __exit__(self,*args):
    self.actual.close()
    try:os.fstat(self.fd)
    except OSError:closed.append(True)
    else:closed.append(False)
   def register(self,*args):return self.actual.register(*args)
   def select(self,*args):return self.actual.select(*args)
  with handed('pipe',b'public')as fd,mock.patch.object(subject.selectors,'DefaultSelector',Tracked):self.assertTrue(self.protected(subject,fd)==b'public')
  with handed('pipe',b'',writer_open=True)as fd,mock.patch.object(subject.selectors,'DefaultSelector',Tracked):
   with self.assertRaisesRegex(subject.VncBlocked,'^vnc_credential_deadline$'):self.protected(subject,fd,seconds=.02)
  for method in('register','select'):
   class Failed(Tracked):pass
   setattr(Failed,method,lambda *args:(_ for _ in()).throw(OSError('NON_ECHO_MARKER_FIXTURE')))
   with handed('pipe',b'public')as fd,mock.patch.object(subject.selectors,'DefaultSelector',Failed):
    with self.assertRaisesRegex(subject.VncBlocked,'^vnc_credential_unavailable$')as caught:self.protected(subject,fd)
    self.assertNotIn('NON_ECHO_MARKER_FIXTURE',''.join(traceback.format_exception(caught.exception)))
  self.assertTrue(closed and all(closed))
 def test_fcntl_setup_failure_restores_original_flags_and_closes_duplicate(self):
  subject=self.current;actual=subject.fcntl.fcntl;set_calls=0
  def failed(fd,action,*args):
   nonlocal set_calls
   if action==subject.fcntl.F_SETFL:
    set_calls+=1
    if set_calls==1:raise OSError('NON_ECHO_MARKER_FIXTURE')
   return actual(fd,action,*args)
  with handed('pipe',b'public')as fd,mock.patch.object(subject.fcntl,'fcntl',failed):
   with self.assertRaisesRegex(subject.VncBlocked,'^vnc_credential_unavailable$')as caught:self.protected(subject,fd)
   self.assertNotIn('NON_ECHO_MARKER_FIXTURE',''.join(traceback.format_exception(caught.exception)))
  self.assertEqual(2,set_calls)
 def test_whole_client_high_fd_before_no_network_current_auth_only_and_no_input(self):
  for current in(False,True):
   subject=self.current if current else self.before
   for kind in('regular','pipe'):
    endpoint=RfbEndpoint()
    try:
     with high_fds(),handed(kind,b'public-only-fixture')as fd:
      if current:
       with subject.ProtectedVncSession(port=endpoint.port,credential_fd=fd,guard=lambda:None,timeout=1):pass
       self.assertTrue(bool(endpoint.responses));self.assertEqual([],endpoint.events)
      else:
       with self.assertRaisesRegex(subject.VncBlocked,'^vnc_credential_unavailable$'):
        with subject.ProtectedVncSession(port=endpoint.port,credential_fd=fd,guard=lambda:None,timeout=1):pass
       self.assertEqual([],endpoint.requests);self.assertEqual([],endpoint.events)
    finally:endpoint.close()
if __name__=='__main__':unittest.main(verbosity=2)
