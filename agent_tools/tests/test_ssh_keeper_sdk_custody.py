"""Real SDK launcher and controlled owned descendants; no protocol/SSH/native app."""
import importlib.util,json,os,subprocess,sys,tempfile,time,unittest,uuid
from pathlib import Path
from unittest import mock

P=Path(__file__).resolve().parent
from agent_tools import ssh_keeper_sdk_custody as m
import agent_tools
try:
 import anyio
 from mcp.client.stdio import _create_platform_compatible_process
except ImportError:
 anyio=None
PACKAGE_ROOTS=os.pathsep.join(dict.fromkeys(str(Path(p).parent)for p in agent_tools.__path__))
@unittest.skipIf(anyio is None,'MCP SDK unavailable; install agent_tools/requirements-mcp.txt')
@unittest.skipUnless(os.name=='posix' and Path('/bin/ps').exists(),'requires POSIX process topology')
class _TopologyCase(unittest.TestCase):
 def setUp(self):
  from agent_tools.tests.test_ssh_channel_keeper_entry import KeeperEntryTests
  self.f=KeeperEntryTests('runTest');self.f.setUp();self.addCleanup(self.f.doCleanups);self.f.invoke()
  self.root=self.f.root;self.corr=str(uuid.UUID(self.f.f.corr));self.receipt=self.f.receipt;self.digest=self.f.source
  self.session=self.root/'controlled-sdk';self.session.mkdir(mode=0o700)
  request={'action':'connection-channel-keep','host':'archlinux','timeout_seconds':1800,'identity':{'correlationId':self.corr,'receiptSha256':self.receipt,'sourceManifestSha256':self.digest}}
  m.save(self.session/'request.json',{'request':request,'serverSHA':m.SERVER_SHA})
  self.child=subprocess.Popen([sys.executable,'-B',str(P/'fixtures/ssh_keeper_causal/sdk_harmless_topology.py'),'sdk',str(self.session)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={**m.clean_environment(m.ROOT),'PYTHONPATH':PACKAGE_ROOTS})
  self.addCleanup(self.release)
  end=time.monotonic()+8
  while not (self.session/'keeper.json').exists():
   if self.child.poll()is not None:raise AssertionError(self.child.stderr.read().decode())
   if time.monotonic()>end:raise AssertionError('harmless startup deadline')
   time.sleep(.02)
  self.sdk=m.entry.actor(self.child.pid);self.local=json.loads((self.session/'keeper.json').read_bytes())
  self.assertNotEqual(self.sdk['sessionId'],self.local['sessionId'])
  # Declared remote/placement seam: real canonical TempFS keeper output, with
  # localActor placed at controlled actual SDK descendant rather than test PID.
  intent=m.entry.output_path(self.root,uuid.UUID(self.corr).hex)/'intent.json';value=json.loads(intent.read_bytes());value['localActor']=self.local;intent.write_text(json.dumps(value));intent.chmod(0o600)
  self.holder=m.closure._Held();self.addCleanup(self.holder.close);public=self.root/'PUBLIC_SOURCE';public.write_bytes(b'owned');self.holder.read(str(public),m.hashlib.sha256(b'owned').hexdigest())
  class Guard:
   holder=self.holder
   def __call__(s):s.holder.finish()
  self.guard=Guard()
 def release(self):
  if self.child.stdin and not self.child.stdin.closed:self.child.stdin.close()
  self.child.wait(timeout=8)
  for stream in (self.child.stdout,self.child.stderr):
   if stream and not stream.closed:stream.close()
 def ready(self):
  kwargs={'clock':lambda:11.,'emit':lambda _:None}
  if hasattr(m,'SDKCustody'):
   with m.SDKCustody(self.session,self.corr,self.receipt,self.digest,self.sdk,m.entry.actor(),m.entry.actor(os.getppid())) as custody:
    kwargs['custody']=custody
    return m.first_ready(self.root,self.corr,self.receipt,self.digest,self.child,10.,self.sdk,self.guard,**kwargs)
  return m.first_ready(self.root,self.corr,self.receipt,self.digest,self.child,10.,self.sdk,self.guard,**kwargs)
 def test_actual_sdk_distinct_session_original_first_ready(self):
  server=json.loads((self.session/'server-intent.json').read_bytes());actors=[self.local,server['serverActor'],server['relayActor'],self.sdk,m.entry.actor(),m.entry.actor(os.getppid())];print('CONTROLLED_GRAPH',[(a['pid'],a['sessionId'],int(subprocess.check_output(['/bin/ps','-p',str(a['pid']),'-o','ppid='],env={**m.clean_environment(m.ROOT),'PYTHONPATH':PACKAGE_ROOTS}))) for a in actors],flush=True)
  self.assertEqual('FIRST_READY',self.ready()['stage'])
 def test_finite_refusal_is_retained_before_original_sdk_wait(self):
  values=[]
  m.retain_first_ready_refusal(self.root,self.corr,self.receipt,self.sdk,ValueError('sdk_keeper_lineage'),self.guard,values.append)
  self.assertIsNone(self.child.poll());self.assertEqual('FIRST_READY_REFUSED',values[0]['stage']);self.assertEqual('unknown',values[0]['state']);self.assertFalse(values[0]['nativeActionAllowed']);self.assertFalse(values[0]['replayAllowed']);self.assertEqual('sdk_keeper_lineage',values[0]['reason'])
  self.assertEqual(values[0],json.loads((self.root/'first-ready-refusal.json').read_bytes()))
 def test_foreign_original_sdk_owner_refuses(self):
  self.sdk=m.entry.actor()
  with self.assertRaises(ValueError):self.ready()
 def test_relay_producer_birth_replacement_refuses(self):
  path=self.session/'server-intent.json';v=json.loads(path.read_bytes());v['relayActor']['birthSha256']='0'*64;path.write_text(json.dumps(v));path.chmod(0o600)
  with self.assertRaises(ValueError):self.ready()
 def test_client_request_foreign_receipt_refuses(self):
  path=self.session/'client-intent.json';v=json.loads(path.read_bytes());v['request']['identity']['receiptSha256']='0'*64;path.write_text(json.dumps(v));path.chmod(0o600)
  with self.assertRaises(ValueError):self.ready()

@unittest.skipIf(anyio is None,'MCP SDK unavailable; install agent_tools/requirements-mcp.txt')
@unittest.skipUnless(os.name=='posix' and Path('/bin/ps').exists(),'requires POSIX process topology')
class SDKTopologyTests(unittest.TestCase):
 def control(self,selector):
  env={**m.clean_environment(m.ROOT),'PYTHONPATH':PACKAGE_ROOTS}
  child=subprocess.Popen([sys.executable,'-W','error::ResourceWarning','-m','unittest',__name__+'._TopologyCase.'+selector],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
  out,err=child.communicate(timeout=20)
  self.assertEqual(0,child.returncode,(out+err).decode())
 def test_actual_sdk_distinct_session_original_first_ready(self):self.control('test_actual_sdk_distinct_session_original_first_ready')
 def test_finite_refusal_is_retained_before_original_sdk_wait(self):self.control('test_finite_refusal_is_retained_before_original_sdk_wait')
 def test_foreign_original_sdk_owner_refuses(self):self.control('test_foreign_original_sdk_owner_refuses')
 def test_relay_producer_birth_replacement_refuses(self):self.control('test_relay_producer_birth_replacement_refuses')
 def test_client_request_foreign_receipt_refuses(self):self.control('test_client_request_foreign_receipt_refuses')
def load_tests(loader,tests,pattern):return loader.loadTestsFromTestCase(SDKTopologyTests)
