"""Real-child collection and real-FD once-marker causal coverage.

OS principal/boot and synthetic APK/material seams come from ReceiverTests.
No runtime archives/configuration/private inputs/SSH or native environment.
"""
import copy,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest import mock
from agent_tools import android_installer_asset_collection as operator
from agent_tools import android_installer_asset_staging as assets,ssh_transfer,android_installer_component_bundle as bundle
from agent_tools import windows_diagnostic_authority_capture as authority
from agent_tools.tests import test_android_installer_asset_staging as staging_tests
CORR=staging_tests.CORR
BOOT=staging_tests.BOOT

class OperatorLocal(unittest.TestCase):
 def setUp(self):
  self.fixture=staging_tests.ReceiverTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.repo=Path(self.temp.name).resolve()
  self.leaf=self.repo/'.runtime/parity-evidence/asset-operator-local';self.leaf.mkdir(parents=True,mode=0o700);self.leaf.chmod(0o700)
  self.capture=authority.AuthorityCapture(self.repo,'asset-operator-local');self.addCleanup(self.capture.close)
  self.payload=self.repo/'payload.bin';self.payload.write_bytes(b''.join(self.fixture.data[n]for n in assets.NAMES));self.payload.chmod(0o600)
  self.prepared=copy.deepcopy(self.fixture.prepared);self.prepared['payloadPin']=assets.snapshot(self.payload,assets.MAX_TOTAL)
  self.stream=ssh_transfer.StreamPayload(assets.canonical(self.fixture.manifest),self.payload)
  self.source_path=self.repo/'android_installer_asset_collection.py'
  source=Path(operator.__file__).read_bytes();self.source_path.write_bytes(source)
  _,pin=bundle._read(self.source_path);self.source_pin={'path':str(self.source_path),**pin}
 def execute(self,source=None):
  argv=[sys.executable,'-I','-B','-c',self.fixture.prefix+(self.fixture.source if source is None else source),str(self.fixture.root),CORR,self.prepared['manifestSha256'],BOOT]
  with assets.held_custody([(self.source_pin,8388608)])as source_closing:
   return operator.collect_asset(self.prepared,argv,self.stream,self.capture,source_custody=source_closing)
 def test_actual_collector_stream_receiver_complete_and_dual_eof(self):
  value=self.execute();self.assertEqual(value['state'],'complete');self.assertFalse(value['leaseIssued'])
  self.assertEqual(assets.decode((self.leaf/'exit.json').read_bytes()),{'failure':None,'returncode':0})
  self.assertTrue((self.leaf/'handle.json').is_file())
  self.assertEqual(assets.decode((self.leaf/'stderr-manifest.json').read_bytes())['bytes'],0)
  for name in assets.NAMES:self.assertEqual((self.fixture.root/('android-complete-update-inputs-'+CORR)/name).read_bytes(),self.fixture.data[name])
 def test_stream_submission_once_precedes_popen(self):
  self.assertEqual(self.execute()['state'],'complete')
  from unittest import mock
  with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('replay submission forbidden')):
   with self.assertRaisesRegex(ValueError,'asset_operator_collection_consumed'):self.execute()
  self.assertTrue((self.repo/'asset-collection-intent.json').is_file())
 def test_actual_collector_retains_unknown_reply_and_no_custody(self):
  # Consumed remote create-only leaf is UNKNOWN, never adopted or reissued.
  (self.fixture.root/('android-complete-update-inputs-'+CORR)).mkdir(mode=0o700)
  value=self.execute();self.assertEqual(value['state'],'unknown');self.assertNotIn('authority',value);self.assertFalse(value['replayAllowed'])
  manifest=assets.decode((self.leaf/'stdout-manifest.json').read_bytes());self.assertGreater(manifest['bytes'],0)
 def test_actual_collector_stderr_and_nonzero_raw_before_refusal(self):
  source="import sys;sys.stdin.buffer.read();sys.stderr.write('FINITE-FIXTURE-STDERR');sys.stdout.write('FINITE-FIXTURE-OUT');sys.exit(7)"
  with self.assertRaisesRegex(ValueError,'baseline_transport_unknown_raw_retained'):self.execute(source)
  self.assertEqual(assets.decode((self.leaf/'exit.json').read_bytes())['returncode'],7)
  self.assertEqual(assets.decode((self.leaf/'stdout-manifest.json').read_bytes())['bytes'],18)
  self.assertEqual(assets.decode((self.leaf/'stderr-manifest.json').read_bytes())['bytes'],21)
  self.assertFalse((self.leaf/'asset-custody-projection.json').exists())
 def test_payload_pin_drift_refuses_before_popen(self):
  self.payload.write_bytes(b'changed')
  from unittest import mock
  with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('submission forbidden')):
   with self.assertRaisesRegex(ValueError,'asset_custody_changed'):self.execute()
  self.assertFalse((self.leaf/'handle.json').exists())
 def test_genuine_collector_source_and_source_closing_templates(self):
  base=operator.collector()
  self.assertEqual(set(['collect','parse_terminal','ROOT_BOOT','REMOTE','archive'])-set(base),set())
  self.assertEqual(assets.sha(operator.COLLECTOR_SOURCE.encode()),operator.COLLECTOR_SOURCE_SHA256)
  self.assertIn('time.monotonic()+1250',base['_original_collect_source'])
 def test_actual_collection_has_no_config_or_runtime_source_dependency(self):
  from agent_tools import ssh_transport
  original_open=Path.open
  def guarded_open(path,*args,**kwargs):
   if path.is_relative_to(Path.cwd()/'.runtime'):
    raise AssertionError('routine collection must not load ignored sources')
   return original_open(path,*args,**kwargs)
  with mock.patch.object(Path,'open',guarded_open),mock.patch.object(ssh_transport,'load_config',side_effect=AssertionError('routine collection must not read configuration')):
   self.assertEqual(self.execute()['state'],'complete')

OLD_COLLECTION_ORIGIN_SHA256='8798e6004cc1a674b5fb23342c3f8603644673957fa5384acf700f8d686c09f8'
OLD_COLLECTION_FUNCTION='def collect_asset(prepared,argv,stream,capture):\n    """Native-capable only after independent stream review+root explicit GO.\n\n    Keep exact original select/timeout/raw-first/dualEOF collector. Only its\n    stdin producer changes from one in-memory source to StreamPayload\'s fixed\n    prefix and held nofollow file chunks. No input/key bytes are archived here.\n    """\n    base=collector();source=base[\'_original_collect_source\']\n    changes={\n        \'def collect(state,credential):\':\'def collect_stream(state,credential):\',\n        "payload=bytearray(credential)+state[\'source\'];credential=b\'\'":"payload=bytearray(state[\'stream\'].prefix);credential=b\'\'",\n        \'if offset==len(payload):writer.close();writer=None;payload.clear()\':"""if offset==len(payload):\n                    payload.clear();offset=0\n                    part=os.read(state[\'assetFd\'],65536)\n                    if part:\n                        state[\'assetHash\'].update(part);state[\'assetBytes\']+=len(part)\n                        if state[\'assetBytes\']>state[\'payloadPin\'][\'generation\'][6]:raise ValueError(\'asset_operator_stream_changed\')\n                        payload.extend(part)\n                    else:\n                        if state[\'assetBytes\']!=state[\'payloadPin\'][\'generation\'][6] or state[\'assetHash\'].hexdigest()!=state[\'payloadPin\'][\'sha256\'] or assets.generation(os.fstat(state[\'assetFd\']))!=state[\'payloadPin\'][\'generation\']:raise ValueError(\'asset_operator_stream_changed\')\n                        writer.close();writer=None""",\n    }\n    for old,new in changes.items():\n        if source.count(old)!=1:raise ValueError(\'asset_operator_stream_boundary_changed\')\n        source=source.replace(old,new)\n    base[\'assets\']=assets\n    exec(compile(source,\'<actual-collector-fixed-StreamPayload>\',\'exec\',dont_inherit=True),base)\n    pin=prepared[\'payloadPin\']\n    if stream.path!=Path(pin[\'path\']) or type(stream.prefix)is not bytes or not stream.prefix or len(stream.prefix)>69632:raise ValueError(\'asset_operator_stream_binding_changed\')\n    with assets.held_custody([(pin,assets.MAX_TOTAL)])as closing:\n        fd=os.open(stream.path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)\n        try:\n            if assets.generation(os.fstat(fd))!=pin[\'generation\']:raise ValueError(\'asset_operator_stream_changed\')\n            state={\'argv\':argv,\'capture\':capture,\'stream\':stream,\'assetFd\':fd,\'payloadPin\':pin,\'assetHash\':hashlib.sha256(),\'assetBytes\':0}\n            # transport_request already produced durable submission intent. The\n            # collector records original process PID/start before first write.\n            # Fixed create-only attempt receipt survives loss of the launch\n            # marker; neither a missing marker nor a new capture permits retry.\n            attempt=Path(pin[\'path\']).parent/\'asset-collection-attempt.json\'\n            try:attempt_fd=os.open(attempt,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n            except FileExistsError:raise ValueError(\'asset_operator_collection_consumed\')from None\n            attempt_data=assets.canonical({\'schema\':1,\'correlationId\':prepared[\'correlationId\'],\'payloadSha256\':pin[\'sha256\'],\'manifestSha256\':prepared[\'manifestSha256\'],\'replayAllowed\':False})\n            try:\n                at=0\n                while at<len(attempt_data):\n                    count=os.write(attempt_fd,attempt_data[at:])\n                    if count<=0:raise ValueError(\'asset_operator_intent_write_unknown\')\n                    at+=count\n                os.fsync(attempt_fd)\n            finally:os.close(attempt_fd)\n            attempt_pin=assets.snapshot(attempt,65536)\n            if attempt_pin[\'sha256\']!=assets.sha(attempt_data):raise ValueError(\'asset_operator_intent_changed\')\n            marker=Path(pin[\'path\']).parent/\'asset-collection-intent.json\'\n            try:once=os.open(marker,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n            except FileExistsError:raise ValueError(\'asset_operator_collection_consumed\')from None\n            try:\n                data=assets.canonical({\'schema\':1,\'correlationId\':prepared[\'correlationId\'],\'payloadSha256\':pin[\'sha256\'],\'manifestSha256\':prepared[\'manifestSha256\'],\'replayAllowed\':False});at=0\n                while at<len(data):\n                    count=os.write(once,data[at:])\n                    if count<=0:raise ValueError(\'asset_operator_intent_write_unknown\')\n                    at+=count\n                os.fsync(once)\n                directory=os.open(marker.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)\n                try:os.fsync(directory)\n                finally:os.close(directory)\n                original=assets.generation(os.fstat(once));marker_pin=assets.snapshot(marker,65536)\n                if marker_pin[\'generation\']!=original or marker_pin[\'sha256\']!=assets.sha(data):raise ValueError(\'asset_operator_intent_changed\')\n                with assets.held_custody([(marker_pin,65536),(attempt_pin,65536)])as once_closing:\n                    def intent_closing():\n                        try:\n                            if assets.generation(os.fstat(once))!=original:raise ValueError(\'asset_operator_intent_changed\')\n                            once_closing()\n                        except (ValueError,OSError):raise ValueError(\'asset_operator_intent_changed\')from None\n                    capture.create(\'asset-collection-intent.json\',data)\n                    closing();intent_closing()\n                    raw=base[\'collect_stream\'](state,b\'\')\n                    intent_closing()\n            finally:os.close(once)\n            closing()\n        finally:os.close(fd)\n    result=assets.project(prepared,raw,b\'\',0,{\'stdout\':True,\'stderr\':True})\n    capture.create(\'asset-custody-projection.json\',assets.canonical(result))\n    return result'

class SourceCustodyBoundary(unittest.TestCase):
 def test_archived_real_collection_reproduces_source_publication_gap(self):
  case=OperatorLocal();case.setUp();self.addCleanup(case.doCleanups)
  namespace=dict(operator.__dict__)
  exec(compile(OLD_COLLECTION_FUNCTION,'<authenticated-old-8798-collection>','exec',dont_inherit=True),namespace)
  create=case.capture.create
  def drift(name,body):
   result=create(name,body)
   if name=='asset-collection-intent.json':case.source_path.chmod(0o664)
   return result
  case.capture.create=drift
  argv=[sys.executable,'-I','-B','-c',case.fixture.prefix+case.fixture.source,str(case.fixture.root),CORR,case.prepared['manifestSha256'],BOOT]
  with assets.held_custody([(case.source_pin,8388608)])as source_closing:
   source_closing()
   result=namespace['collect_asset'](case.prepared,argv,case.stream,case.capture)
   self.assertEqual(result['state'],'complete')
   self.assertTrue((case.leaf/'handle.json').exists())
   with self.assertRaisesRegex(ValueError,'asset_custody_changed'):source_closing()
  self.assertTrue((case.fixture.root/('android-complete-update-inputs-'+CORR)/'base.apk').exists())

 def test_source_drift_at_intent_publication_blocks_before_child(self):
  for mutation in ('mode','samebytes-replacement','bytes'):
   with self.subTest(mutation=mutation):
    case=OperatorLocal();case.setUp()
    try:
     create=case.capture.create
     def drift(name,body):
      result=create(name,body)
      if name=='asset-collection-intent.json':
       if mutation=='mode':case.source_path.chmod(0o664)
       elif mutation=='bytes':case.source_path.write_bytes(b'changed source')
       else:
        raw=case.source_path.read_bytes();case.source_path.unlink();case.source_path.write_bytes(raw)
      return result
     case.capture.create=drift
     with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('source drift must refuse before submission')):
      with self.assertRaisesRegex(ValueError,'asset_custody_changed'):case.execute()
     self.assertFalse((case.leaf/'handle.json').exists())
    finally:case.doCleanups()
 def test_source_custody_is_mandatory_and_additive(self):
  case=OperatorLocal();case.setUp();self.addCleanup(case.doCleanups)
  with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('missing guard must refuse')):
   with self.assertRaisesRegex(ValueError,'asset_operator_source_custody_required'):
    operator.collect_asset(case.prepared,[],case.stream,case.capture)
  self.assertFalse((case.repo/'asset-collection-attempt.json').exists())
 def test_postcollection_source_drift_retains_raw_unknown(self):
  case=OperatorLocal();case.setUp();self.addCleanup(case.doCleanups)
  create=case.capture.create
  def drift(name,body):
   result=create(name,body)
   if name=='exit.json':case.source_path.chmod(0o664)
   return result
  case.capture.create=drift
  with self.assertRaisesRegex(ValueError,'asset_custody_changed'):case.execute()
  self.assertTrue((case.leaf/'stdout-manifest.json').exists())
  self.assertFalse((case.leaf/'asset-custody-projection.json').exists())

class IntentBoundary(unittest.TestCase):
 def test_original_marker_deleted_during_receipt_blocks_before_child(self):
  case=OperatorLocal();case.setUp();self.addCleanup(case.doCleanups)
  create=case.capture.create
  def exchanged(name,body):
   result=create(name,body)
   if name=='asset-collection-intent.json':(case.repo/name).unlink()
   return result
  case.capture.create=exchanged
  with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('child must not launch after deleted intent')):
   with self.assertRaisesRegex(ValueError,'asset_operator_intent_changed'):case.execute()
  self.assertFalse((case.leaf/'handle.json').exists())
  # Removing a marker after an uncertain attempt is never a new submission.
  with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('retry forbidden')):
   with self.assertRaisesRegex(ValueError,'asset_operator_collection_consumed'):case.execute()
 def test_original_marker_replacement_and_mode_drift_block_before_child(self):
  for mutation in ('samebytes-replacement','mode'):
   with self.subTest(mutation=mutation):
    case=OperatorLocal();case.setUp()
    try:
     create=case.capture.create
     def exchanged(name,body):
      result=create(name,body)
      if name=='asset-collection-intent.json':
       marker=case.repo/name
       if mutation=='mode':marker.chmod(0o644)
       else:
        raw=marker.read_bytes();marker.unlink();marker.write_bytes(raw);marker.chmod(0o600)
      return result
     case.capture.create=exchanged
     with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('child must not launch after intent drift')):
      with self.assertRaisesRegex(ValueError,'asset_operator_intent_changed'):case.execute()
     self.assertFalse((case.leaf/'handle.json').exists())
    finally:case.doCleanups()
 def test_postcollection_marker_drift_retains_raw_unknown(self):
  case=OperatorLocal();case.setUp();self.addCleanup(case.doCleanups)
  create=case.capture.create
  def drift(name,body):
   result=create(name,body)
   if name=='exit.json':(case.repo/'asset-collection-intent.json').unlink()
   return result
  case.capture.create=drift
  with self.assertRaisesRegex(ValueError,'asset_operator_intent_changed'):case.execute()
  self.assertTrue((case.leaf/'handle.json').is_file());self.assertTrue((case.leaf/'stdout-manifest.json').is_file())
  self.assertFalse((case.leaf/'asset-custody-projection.json').exists())




# Routine readiness regressions: immutable original collector control reconstructed
# from its authenticated source, independent of current production collector().
import ast,base64,hashlib,math,select,stat,time
try:
 import resource
except ImportError:
 resource=None
def historical_collector():
    if hashlib.sha256(operator.COLLECTOR_SOURCE.encode()).hexdigest()!=operator.COLLECTOR_SOURCE_SHA256:
        raise ValueError('asset_operator_collector_source_changed')
    tree=ast.parse(operator.COLLECTOR_SOURCE)
    namespace=dict(ast=ast,base64=base64,hashlib=hashlib,json=json,math=math,os=os,select=select,stat=stat,subprocess=subprocess,time=time,Path=Path)
    exec(compile(tree,'<authenticated-historical-asset-collector>','exec',dont_inherit=True),namespace)
    namespace['_original_collect_source']=ast.get_source_segment(operator.COLLECTOR_SOURCE,next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='collect'))
    return namespace

class Readiness(unittest.TestCase):
 def high(self):
  if os.name!='posix' or resource is None or not hasattr(os,'O_NOFOLLOW') or not os.path.exists(os.devnull):
   self.skipTest('POSIX high-FD resource/descriptor capability unavailable')
  if resource.getrlimit(resource.RLIMIT_NOFILE)[0]<1200:self.skipTest('owned FD>=1100 capability unavailable')
  fds=[]
  try:
   while not fds or fds[-1]<1100:fds.append(os.open(os.devnull,os.O_RDONLY))
  except BaseException:
   for fd in fds:os.close(fd)
   raise
  self.addCleanup(lambda:[os.close(fd)for fd in reversed(fds)])
 def case(self):
  c=OperatorLocal();c.setUp();self.addCleanup(c.doCleanups);return c
 def test_historical_actual_high_fd_collector_red(self):
  self.high();c=self.case()
  children=[];original=subprocess.Popen
  def popen(*args,**kwargs):
   child=original(*args,**kwargs);children.append(child);return child
  try:
   with mock.patch.object(operator,'collector',historical_collector),mock.patch.object(subprocess,'Popen',popen),self.assertRaisesRegex(ValueError,'filedescriptor out of range in select'):c.execute()
  finally:
   for child in children:
    for stream in [child.stdin,child.stdout,child.stderr]:
     if stream is not None:stream.close()
  self.assertTrue((c.leaf/'handle.json').is_file());self.assertFalse((c.leaf/'exit.json').exists())
 def test_fixed_actual_high_fd_receiver_dual_eof_and_once(self):
  self.high();c=self.case()
  value=c.execute();self.assertEqual(value['state'],'complete')
  self.assertEqual(operator.assets.decode((c.leaf/'exit.json').read_bytes()),{'failure':None,'returncode':0})
  self.assertEqual(operator.assets.decode((c.leaf/'stderr-manifest.json').read_bytes())['bytes'],0)
  with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('once must forbid child')):
   with self.assertRaisesRegex(ValueError,'asset_operator_collection_consumed'):c.execute()
 def test_high_fd_stderr_nonzero_retained_before_refusal(self):
  self.high();c=self.case()
  body="import sys;sys.stdin.buffer.read();sys.stdout.write('PUBLIC_OUT');sys.stderr.write('PUBLIC_ERR');sys.exit(7)"
  with self.assertRaisesRegex(ValueError,'baseline_transport_unknown_raw_retained'):c.execute(body)
  for name in ['stdout','stderr']:self.assertEqual(operator.assets.decode((c.leaf/(name+'-manifest.json')).read_bytes())['bytes'],10)
  self.assertEqual(operator.assets.decode((c.leaf/'exit.json').read_bytes())['returncode'],7)
 def test_selector_closes_on_invalid_and_success(self):
  self.high();r,w=os.pipe();self.addCleanup(os.close,r);self.addCleanup(os.close,w);os.write(w,b'X');instances=[];original=operator.selectors.DefaultSelector
  def factory():
   x=original();instances.append(x);return x
  with mock.patch.object(operator.selectors,'DefaultSelector',factory):
   self.assertEqual(operator._select_ready([r],[w],[],0),([r],[w],[]))
   bad=os.open(os.devnull,os.O_RDONLY);os.close(bad)
   with self.assertRaises(OSError):operator._select_ready([bad],[],[],0)
  self.assertTrue(all(x.get_map()is None for x in instances))
  with self.assertRaisesRegex(ValueError,'exceptional_not_supported'):operator._select_ready([],[],[r],0)
 def test_only_readiness_callees_change_budgets_and_caps_exact(self):
  base=operator.collector();old=historical_collector()
  self.assertEqual(operator.assets.sha(operator.COLLECTOR_SOURCE.encode()),operator.COLLECTOR_SOURCE_SHA256)
  self.assertEqual(base['_historical_collect_source'],old['_original_collect_source'])
  self.assertEqual(base['_original_collect_source'].replace('_select_ready(','select.select('),old['_original_collect_source'])
  self.assertIn('time.monotonic()+1250',base['_original_collect_source'])
  for name in ['REMOTE','ROOT_BOOT','STREAM_LIMIT','CHUNK']:self.assertEqual(base[name],old[name])

if __name__=='__main__':unittest.main(verbosity=2)
