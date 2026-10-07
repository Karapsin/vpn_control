from pathlib import Path
import unittest,tempfile,io,sys,os,json,hashlib,contextlib
from unittest import mock
from agent_tools import windows_secondary_fixture_stage as stage
r=Path(tempfile.gettempdir()).resolve()
LEGACY = r'''from pathlib import Path
import os,stat,sys,hashlib,json
ROOT='/home/kardinal/vpn-control-secondary-base-input-1502d4fc-afd4-4322-bc98-75880be02d78'
SIZE=131101044
SHA='539504d691d396745d8426551e12107475281f3b189f75f3f802c5476920d1cd'
p=Path(ROOT);home=p.parent;st=home.lstat()
if os.geteuid()!=1000 or str(home)!='/home/kardinal' or not stat.S_ISDIR(st.st_mode) or st.st_uid!=1000 or st.st_mode&0o022 or os.path.realpath(home)!=str(home):raise ValueError('host-input-parent')
p.mkdir(mode=0o700);directory=os.open(p,os.O_DIRECTORY|os.O_NOFOLLOW);fd=None;count=0;h=hashlib.sha256();state='UNKNOWN'
try:
 fd=os.open('base.msi',os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_WRONLY,0o600,dir_fd=directory)
 while count<SIZE:
  block=sys.stdin.buffer.read(min(1048576,SIZE-count))
  if not block:raise ValueError('host-input-short')
  offset=0
  while offset<len(block):
   n=os.write(fd,block[offset:])
   if n<=0:raise ValueError('host-input-write')
   offset+=n
  h.update(block);count+=len(block)
 if sys.stdin.buffer.read(1):raise ValueError('host-input-extra')
 os.fsync(fd);original=os.fstat(fd);named=os.stat('base.msi',dir_fd=directory,follow_symlinks=False)
 if original!=named or count!=SIZE or h.hexdigest()!=SHA:raise ValueError('host-input-fullsha')
 state='HOST_INPUT_STAGED'
finally:
 if fd is not None:os.close(fd)
 os.close(directory)
 print(json.dumps({'state':state,'path':str(p/'base.msi'),'length':count,'sha256':h.hexdigest(),'guestEffect':False,'installerStarted':False,'replayAllowed':False},sort_keys=True),flush=True)
'''
PROVEN=stage.secondary_base_host_input_program('1502d4fc-afd4-4322-bc98-75880be02d78','539504d691d396745d8426551e12107475281f3b189f75f3f802c5476920d1cd',131101044)
OLD=LEGACY
NEW=PROVEN
class Receiver(unittest.TestCase):
 def run_receiver(self,source,mutation=None):
  td=tempfile.TemporaryDirectory(dir=r);self.addCleanup(td.cleanup);home=Path(td.name);target=home/'owned';data=b'public MSI bytes';text=source;line=next(x for x in text.splitlines() if x.startswith('ROOT='));text=text.replace(line,'ROOT='+repr(str(target))).replace('SIZE=131101044','SIZE='+str(len(data))).replace("SHA='539504d691d396745d8426551e12107475281f3b189f75f3f802c5476920d1cd'","SHA="+repr(hashlib.sha256(data).hexdigest())).replace("str(home)!='/home/kardinal'",'str(home)!='+repr(str(home))).replace('!=1000','!='+str(os.geteuid())).replace('[home,*home.parents]','[home]')
  original=os.fsync;acted=False
  def fsync(fd):
   nonlocal acted
   original(fd)
   if not acted and mutation is not None and os.fstat(fd).st_size==len(data):
    acted=True
    if mutation=='root':target.rename(home/'held-original');target.mkdir(mode=0o700)
    elif mutation=='file':os.pwrite(fd,b'foreign overwrite',0)
  out=io.StringIO();error=None
  with mock.patch.object(sys,'stdin',io.TextIOWrapper(io.BytesIO(data))),mock.patch.object(os,'fsync',fsync),contextlib.redirect_stdout(out):
   try:exec(compile(text,'actual scoped receiver','exec'),{})
   except Exception as e:error=e
  if not out.getvalue():raise AssertionError(str(error))
  return json.loads(out.getvalue()),error,target
 @unittest.skipUnless(os.name == 'posix', 'Arch host receiver native descriptor boundary')
 def test_actual_old_directory_exchange_false_success_red(self):
  v,e,p=self.run_receiver(OLD,'root');self.assertEqual(v['state'],'HOST_INPUT_STAGED');self.assertFalse((p/'base.msi').exists());self.assertIsNone(e)
 @unittest.skipUnless(os.name == 'posix', 'Arch host receiver native descriptor boundary')
 def test_actual_new_directory_exchange_refuses_green(self):
  v,e,p=self.run_receiver(NEW,'root');self.assertEqual(v['state'],'UNKNOWN');self.assertEqual(v['reason'],'host-input-root-name');self.assertIsNotNone(e);self.assertFalse((p/'base.msi').exists())
 @unittest.skipUnless(os.name == 'posix', 'Arch host receiver native descriptor boundary')
 def test_actual_new_full_input_green(self):
  v,e,p=self.run_receiver(NEW);self.assertEqual(v['state'],'HOST_INPUT_STAGED');self.assertIsNone(e);self.assertEqual(hashlib.sha256((p/'base.msi').read_bytes()).hexdigest(),v['sha256']);self.assertEqual(v['fileGeneration'][6],len(b'public MSI bytes'))
 @unittest.skipUnless(os.name == 'posix', 'Arch host receiver native descriptor boundary')
 def test_actual_new_same_inode_overwrite_refuses_green(self):
  v,e,p=self.run_receiver(NEW,'file');self.assertEqual(v['state'],'UNKNOWN');self.assertIsNotNone(e);self.assertNotEqual(hashlib.sha256((p/'base.msi').read_bytes()).hexdigest(),v['sha256'])
 def test_factory_exact_native_proven_source(self):
  self.assertEqual(hashlib.sha256(PROVEN.encode()).hexdigest(),'9e42edffe1f88250d1e9b7cc24376285fa4504ea0ed58ba8eb0aeb1de1d16ae2')
 def test_invalid_correlation_hash_size_refused(self):
  for corr,sha,size in [('foreign','a'*64,1),('1502d4fc-afd4-4322-bc98-75880be02d78','A'*64,1),('1502d4fc-afd4-4322-bc98-75880be02d78','a'*64,True)]:
   with self.assertRaises(ValueError):stage.secondary_base_host_input_program(corr,sha,size)
class InputDescriptor(unittest.TestCase):
 @unittest.skipUnless(os.name == 'posix', 'Arch SSH fixture input descriptor boundary')
 def test_original_descriptor_and_separate_stderr_eof(self):
  import subprocess,uuid
  from agent_tools.windows_diagnostic_authority_capture import AuthorityCapture
  with tempfile.TemporaryDirectory() as td:
   root=Path(td).resolve();path=root/'input';original=b'public original MSI bytes\0'*10000;path.write_bytes(original);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
   path.rename(root/'original');path.write_bytes(b'foreign named replacement')
   folder=root/'.runtime/parity-evidence';folder.mkdir(parents=True,mode=0o700);(root/'.runtime').chmod(0o700);leaf='secondary-fixture-'+uuid.uuid4().hex;(folder/leaf).mkdir(mode=0o700);capture=AuthorityCapture(root,leaf)
   code="import sys,json,hashlib;v=sys.stdin.buffer.read();sys.stderr.buffer.write(b'PUBLIC_STDERR');print(json.dumps({'size':len(v),'sha256':hashlib.sha256(v).hexdigest()}))"
   client=stage.SecondaryFixtureInputClient([sys.executable,'-c',code],fd,capture)
   try:
    client.observe(2);self.assertTrue(client.eof and client.stderr_eof);self.assertEqual(client.child.returncode,0);self.assertEqual(json.loads(client.raw),{'size':len(original),'sha256':hashlib.sha256(original).hexdigest()});self.assertEqual(bytes(client.stderr_raw),b'PUBLIC_STDERR');self.assertEqual(client.stderr_observation()['originalPid'],client.child.pid);client.close_terminal()
   finally:os.close(fd)

# Exact original directly used client methods retained for causal RED coverage.
_LEGACY_CLIENT = "class SecondaryFixtureInputClient(transport.RetainedClient):\n\n    def __init__(self, argv, input_fd, capture):\n        self.stderr_fd = os.open('transport.stderr.private', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384, dir_fd=capture.fd)\n        self.stderr_raw = bytearray()\n        self.stderr_bytes = 0\n        self.stderr_eof = False\n        self.capture = capture\n        self.raw_fd = os.open('transport.stdout.private', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384, dir_fd=capture.fd)\n        self.raw = bytearray()\n        self.eof = False\n        self.child = None\n        self.selector = None\n        self.initialization_unknown = False\n        self.fallback_readiness = False\n        self.child = subprocess.Popen(argv, stdin=input_fd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)\n        try:\n            self.selector = selectors.DefaultSelector()\n            self.selector.register(self.child.stdout, selectors.EVENT_READ)\n            self.selector.register(self.child.stderr, selectors.EVENT_READ)\n        except BaseException as error:\n            self.initialization_unknown = True\n            self.fallback_readiness = True\n            raise transport.ClientUnknown('client-initialization-unknown', self) from error\n\n    def _stderr_block(self):\n        block = os.read(self.child.stderr.fileno(), 4096)\n        if not block:\n            self.stderr_eof = True\n            if self.selector is not None:\n                try:\n                    self.selector.unregister(self.child.stderr)\n                except KeyError:\n                    pass\n            return\n        self.stderr_bytes += len(block)\n        retain = block[:max(0, STDERR_LIMIT + 1 - len(self.stderr_raw))]\n        self.stderr_raw.extend(retain)\n        offset = 0\n        while offset < len(retain):\n            n = os.write(self.stderr_fd, retain[offset:])\n            transport.need(n > 0, 'diagnostic-stderr-write')\n            offset += n\n        os.fsync(self.stderr_fd)\n\n    def ready(self, remaining):\n        if self.fallback_readiness:\n            import select\n            pipes = [self.child.stdout] + ([] if self.stderr_eof else [self.child.stderr])\n            ready, _, _ = select.select(pipes, [], [], remaining)\n        else:\n            ready = [key.fileobj for key, _ in self.selector.select(remaining)]\n        result = []\n        for pipe in ready:\n            if pipe is self.child.stderr:\n                self._stderr_block()\n            else:\n                result.append(pipe)\n        return result\n\n    def observe(self, seconds):\n        import time\n        deadline = time.monotonic() + seconds\n        error = None\n        try:\n            super().observe(seconds)\n        except transport.ClientUnknown as e:\n            error = e\n        if self.eof and self.child.poll() is not None:\n            while not self.stderr_eof and time.monotonic() < deadline:\n                self.ready(min(0.1, max(0, deadline - time.monotonic())))\n        self.capture.create('stderr-observation-' + __import__('uuid').uuid4().hex + '.json', json.dumps(self.stderr_observation(), sort_keys=True).encode())\n        if error is not None:\n            raise error\n        if not self.stderr_eof:\n            raise transport.ClientUnknown('diagnostic-stderr-eof-unknown', self)\n\n    def stderr_observation(self):\n        return {'originalPid': None if self.child is None else self.child.pid, 'stdoutEof': self.eof, 'stderrEof': self.stderr_eof, 'exitCode': None if self.child is None else self.child.poll(), 'outputBytes': self.stderr_bytes, 'retainedBytes': len(self.stderr_raw), 'overflow': self.stderr_bytes > STDERR_LIMIT, 'rawSha256': hashlib.sha256(self.stderr_raw).hexdigest(), 'productAcceptance': False, 'replayAllowed': False}\n\n    def close_terminal(self):\n        transport.need(self.eof and self.stderr_eof and (self.child.poll() is not None), 'diagnostic-original-not-terminal')\n        super().close_terminal()\n        self.child.stderr.close()\n        os.close(self.stderr_fd)"
class StderrCustody(unittest.TestCase):
 def child(self,cls):
  from agent_tools.windows_diagnostic_authority_capture import AuthorityCapture
  import uuid
  td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve();folder=root/'.runtime/parity-evidence';folder.mkdir(parents=True,mode=0o700);(root/'.runtime').chmod(0o700);leaf='stderr-custody-'+uuid.uuid4().hex;(folder/leaf).mkdir(mode=0o700);capture=AuthorityCapture(root,leaf);source=root/'input';source.write_bytes(b'');fd=os.open(source,os.O_RDONLY);self.addCleanup(os.close,fd)
  client=cls([sys.executable,'-c',"import sys;sys.stderr.buffer.write(b'PUBLIC_STDERR');sys.stderr.flush();print('{}')"],fd,capture)
  return client,folder/leaf
 @unittest.skipUnless(os.name == 'posix', 'Arch retained stderr boundary')
 def test_actual_original_named_swap_false_success_red(self):
  import types,selectors,subprocess,time,uuid
  from agent_tools import windows_parallel_vm_prepare_transport as transport
  ns={'transport':transport,'os':os,'json':json,'hashlib':hashlib,'selectors':selectors,'subprocess':subprocess,'time':time,'uuid':uuid,'STDERR_LIMIT':8192};exec(compile(_LEGACY_CLIENT,'exact original client','exec'),ns);client,folder=self.child(ns['SecondaryFixtureInputClient']);path=folder/'transport.stderr.private';path.rename(folder/'retained-original');path.write_bytes(b'foreign named stderr');path.chmod(0o600);client.observe(2);self.assertTrue(client.stderr_eof);client.close_terminal();self.assertEqual(path.read_bytes(),b'foreign named stderr')
 @unittest.skipUnless(os.name == 'posix', 'Arch retained stderr boundary')
 def test_actual_named_swap_refuses_observation_green(self):
  from agent_tools import windows_parallel_vm_prepare_transport as transport
  client,folder=self.child(stage.SecondaryFixtureInputClient);path=folder/'transport.stderr.private';path.rename(folder/'retained-original');path.write_bytes(b'foreign named stderr');path.chmod(0o600)
  with self.assertRaisesRegex(transport.ClientUnknown,'stderr-custody'):client.observe(2)
  self.assertTrue(client.eof and client.stderr_eof);self.assertEqual(client.child.returncode,0)
  with self.assertRaisesRegex(transport.ClientUnknown,'stderr-custody'):client.close_terminal()
  self.assertFalse(any(folder.glob('stderr-observation-*.json')))
  # Return original namespace after refusal solely to close this harmless
  # terminal fixture. Production callers keep uncertain originals untouched.
  path.unlink();(folder/'retained-original').rename(path);client.close_terminal()
 @unittest.skipUnless(os.name == 'posix', 'Arch retained stderr boundary')
 def test_actual_same_inode_overwrite_refuses_close_green(self):
  from agent_tools import windows_parallel_vm_prepare_transport as transport
  client,folder=self.child(stage.SecondaryFixtureInputClient);client.observe(2);path=folder/'transport.stderr.private';original=path.read_bytes();inode=path.stat().st_ino;path.write_bytes(b'x'*len(original));self.assertEqual(path.stat().st_ino,inode)
  with self.assertRaisesRegex(transport.ClientUnknown,'stderr-custody'):client.close_terminal()
  path.write_bytes(original);client.close_terminal()

if __name__=='__main__':unittest.main()


