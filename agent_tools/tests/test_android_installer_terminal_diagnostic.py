"""Routine causal controls for paired, nonauthorizing terminal diagnostics.

Actual canonical REMOTE/ROOT_BOOT run only under reviewed own-pipe/thread
callbacks. No external child, sudo, SSH, device or private authority is used.
All captures and once-marker controls live in each test's TemporaryDirectory.
"""
import copy,hashlib,json,os,tempfile,types,unittest
from pathlib import Path
from agent_tools import android_installer_asset_collection as operator
from agent_tools import android_installer_direct_transport as direct
if os.name == 'posix':
 from agent_tools.tests.fixtures import android_terminal_diagnostic as fixtures
else:
 fixtures = None
PROGRAMME = fixtures.PROGRAMME if fixtures is not None else b''

@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'), 'POSIX owned pipe and nofollow controls required')
class DiagnosticControls(unittest.TestCase):
 def setUp(self):
  self.held=[];self.sequence=0
  self.temporary=tempfile.TemporaryDirectory(prefix='android-terminal-diagnostic-')
  self.addCleanup(self.temporary.cleanup);self.work=Path(self.temporary.name).resolve()
  self.module=operator;self.ns=operator.collector()
  self.modules={'before':types.SimpleNamespace(collector=lambda:{'REMOTE':fixtures.HISTORICAL_REMOTE,'ROOT_BOOT':self.ns['ROOT_BOOT']})}
  for path in (Path(operator.__file__).absolute(),Path(fixtures.__file__).absolute(),Path(__file__).absolute()):
   raw,pin=direct.snapshot(path);self.held.append(direct._dispatch_hold(path,pin,raw))
  direct._dispatch_guard(self.held)
 def tearDown(self):
  original=None
  try:direct._dispatch_guard(self.held)
  except BaseException as error:original=error
  for _,_,parents,fd in reversed(self.held):
   try:os.close(fd)
   except BaseException as error:
    if original is None:original=error
   try:direct.bundle._close(parents)
   except BaseException as error:
    if original is None:original=error
  if original is not None:raise original
 def raw_fixture(self,mode='timeout',module=None):
  namespace=(self.module if module is None else module).collector();digest=hashlib.sha256(PROGRAMME).hexdigest()
  boot=namespace['ROOT_BOOT'].replace('__BYTES__',str(len(PROGRAMME))).replace('__SHA__',repr(digest))
  remote=namespace['REMOTE'].replace('__BYTES__',str(len(PROGRAMME))).replace('__SHA__',repr(digest)).replace('__BOOT__',repr(boot))
  fixture=fixtures.ReceiverFixture(mode);wire,_=fixture.execute(remote,boot);header=json.loads(wire.splitlines()[0])
  self.assertFalse(fixture.process.thread.is_alive());self.assertEqual(fixture.process.killCalls,1);self.assertFalse(fixture.pipes.fds)
  direct._dispatch_guard(self.held)
  return wire,header,fixture
 def save(self,name,value):
  with (self.work/(''+name+'.json')).open('x')as f:json.dump(value,f,indent=2);f.write('\n')
 def retained_unknown(self,wire,label):
  capture=fixtures.Capture(self.work/(''+label+'-capture'),self.held)
  with self.assertRaisesRegex(ValueError,'^baseline_component_terminal_unknown_raw_retained$'):self.ns['parse_terminal'](wire,{'source':PROGRAMME,'capture':capture})
  self.assertEqual(set(capture.rows),{'remote-stdout-manifest.json','remote-stderr-manifest.json','remote-terminal.json'})
  self.assertEqual(json.loads(capture.rows['remote-terminal.json']),json.loads(wire.splitlines()[0]))
  self.assertEqual(json.loads(capture.rows['remote-stdout-manifest.json'])['bytes'],0)
  self.assertEqual(json.loads(capture.rows['remote-stderr-manifest.json'])['bytes'],0)
  direct._dispatch_guard(self.held)
  return capture
 def test_actual_timeout_preserves_reason_and_observed_facts(self):
  wire,header,fixture=self.raw_fixture()
  self.save('actual-timeout',{'header':header,'phaseBuffered':fixture.phaseBuffer.decode(),'killCallbackCalls':fixture.process.killCalls,'threadJoined':True,'externalProcess':False,'sourceHoldersClosing':True})
  self.assertEqual(header.get('diagnostic',{}).get('collectionReason'),'baseline_remote_collection_timeout','actual before REMOTE loses its precise guarded timeout reason')
  diagnostic=header['diagnostic'];self.assertEqual(header['schema'],2)
  self.assertEqual(diagnostic['timeoutBranch'],'collection_loop');self.assertEqual(diagnostic['elapsedSeconds'],1201)
  self.assertEqual(diagnostic['child'],{'pid':4242,'startTicks':None,'launchObservedEpochSeconds':1730000000.,'launchObservedMonotonicSeconds':0.})
  self.assertEqual(diagnostic['kill'],{'attempted':True,'call':'returned','submitted':None,'wait':'returned','returncode':-9})
  self.assertIsNone(diagnostic['authority']);self.assertIs(diagnostic['replayAllowed'],False)
  self.assertEqual(header['returncode'],-9);self.assertEqual(header['failure'],'ValueError');self.assertEqual(header['stdoutBytes'],0);self.assertEqual(header['stderrBytes'],0)
  self.assertIn(b'OWNED_HARMLESS_PHASE',fixture.phaseBuffer)
  self.retained_unknown(wire,'timeout')
 def test_distinct_value_error_is_unclassified_without_exception_text(self):
  timeout_wire,timeout,_=self.raw_fixture();other_wire,other,fixture=self.raw_fixture('other_value_error')
  self.assertTrue(fixture.injected);self.assertFalse(fixture.phaseSeen.is_set())
  self.assertEqual(other['diagnostic']['collectionReason'],'unclassified_collection_exception');self.assertIsNone(other['diagnostic']['timeoutBranch'])
  self.assertNotIn(b'declared_distinct_owned_callback_ValueError',other_wire)
  self.assertNotEqual(timeout_wire,other_wire)
  legacy=lambda header:{k:v for k,v in header.items()if k not in ('schema','diagnostic')}
  self.assertEqual(legacy(timeout),legacy(other));self.assertIsNone(other['diagnostic']['kill']['submitted'])
  self.retained_unknown(other_wire,'distinct')
  self.save('distinct-cause',{'timeoutReason':timeout['diagnostic']['collectionReason'],'distinctReason':other['diagnostic']['collectionReason'],'legacyFieldsIdentical':True,'arbitraryExceptionTextRetained':False,'bothUnknown':True})
 def test_legacy_schema1_remains_exact_unknown_raw_retained(self):
  wire,header,_=self.raw_fixture(module=self.modules['before'])
  self.assertEqual(header['schema'],1);self.assertNotIn('diagnostic',header)
  self.retained_unknown(wire,'legacy')
  self.save('legacy',{'schema':1,'diagnosticAbsent':True,'rawRetained':True,'result':'baseline_component_terminal_unknown_raw_retained'})
 def test_missing_process_observations_remain_unknown(self):
  wire,header,_=self.raw_fixture('unknown_observations');diagnostic=header['diagnostic']
  self.assertIsNone(diagnostic['child']['pid']);self.assertIsNone(diagnostic['child']['startTicks']);self.assertIsNone(diagnostic['child']['launchObservedEpochSeconds'])
  self.assertIsNone(diagnostic['kill']['submitted']);self.retained_unknown(wire,'unknown-observations')
  self.save('unknown-observations',diagnostic)
 def test_strict_version_shape_enums_and_no_authority_promotion(self):
  wire,original,_=self.raw_fixture();mutations=[]
  def add(name,edit):
   header=copy.deepcopy(original);edit(header);mutations.append((name,header))
  add('extra-header',lambda h:h.update(extra=True))
  add('unsupported-schema',lambda h:h.update(schema=3))
  add('legacy-extra-diagnostic',lambda h:h.update(schema=1))
  add('boolean-version',lambda h:h['diagnostic'].update(version=True))
  add('extra-diagnostic',lambda h:h['diagnostic'].update(extra=True))
  add('arbitrary-reason',lambda h:h['diagnostic'].update(collectionReason='declared_distinct_owned_callback_ValueError'))
  add('bad-timeout-branch',lambda h:h['diagnostic'].update(timeoutBranch=None))
  add('boolean-pid',lambda h:h['diagnostic']['child'].update(pid=True))
  add('negative-start',lambda h:h['diagnostic']['child'].update(startTicks=-1))
  add('unobserved-positive-start',lambda h:h['diagnostic']['child'].update(startTicks=123))
  add('start-without-pid',lambda h:h['diagnostic']['child'].update(pid=None,startTicks=123))
  add('nan-elapsed',lambda h:h['diagnostic'].update(elapsedSeconds=float('nan')))
  add('negative-elapsed',lambda h:h['diagnostic'].update(elapsedSeconds=-1))
  add('boolean-elapsed',lambda h:h['diagnostic'].update(elapsedSeconds=True))
  add('false-kill-submission',lambda h:h['diagnostic']['kill'].update(submitted=True))
  add('contradictory-kill-attempt',lambda h:h['diagnostic']['kill'].update(attempted=False))
  add('boolean-kill-return',lambda h:h['diagnostic']['kill'].update(returncode=True))
  add('duplicate-cleanup',lambda h:h['diagnostic'].update(cleanupReasons=['baseline_remote_collection_limit']*2))
  add('arbitrary-cleanup',lambda h:h['diagnostic'].update(cleanupReasons=['arbitrary']))
  add('impossible-identity-cleanup',lambda h:h['diagnostic'].update(cleanupReasons=['baseline_receiver_identity_changed','baseline_receiver_identity_unknown']))
  add('reversed-cleanup',lambda h:h['diagnostic'].update(cleanupReasons=['baseline_receiver_identity_changed','baseline_remote_collection_limit']))
  add('authority-promotion',lambda h:h['diagnostic'].update(authority='release'))
  add('replay-promotion',lambda h:h['diagnostic'].update(replayAllowed=True))
  for index,(name,header)in enumerate(mutations):
   with self.subTest(case=name):
    capture=fixtures.Capture(self.work/('invalid-'+str(index)+'-capture'),self.held)
    with self.assertRaisesRegex(ValueError,'unknown_raw_retained$'):self.ns['parse_terminal']((json.dumps(header,sort_keys=True,separators=(',',':'))+'\n').encode(),{'source':PROGRAMME,'capture':capture})
    self.assertFalse(capture.rows)
  self.save('strict-shape',{'cases':len(mutations),'allRefused':True,'authorityPromotionRefused':True,'replayPromotionRefused':True})
 def test_contradictory_diagnostics_never_permit_success(self):
  wire,original,_=self.raw_fixture();cases=[]
  timeout=copy.deepcopy(original);timeout.update(returncode=0,failure=None);cases.append(('timeout',timeout))
  cleanup=copy.deepcopy(original);cleanup.update(returncode=0,failure=None);cleanup['diagnostic'].update(collectionReason=None,timeoutBranch=None,cleanupReasons=['baseline_receiver_identity_changed']);cases.append(('cleanup',cleanup))
  killed=copy.deepcopy(original);killed.update(returncode=0,failure=None);killed['diagnostic'].update(collectionReason=None,timeoutBranch=None);cases.append(('kill-wait-code',killed))
  unknown_kill=copy.deepcopy(original);unknown_kill.update(returncode=0,failure=None);unknown_kill['diagnostic'].update(collectionReason=None,timeoutBranch=None);unknown_kill['diagnostic']['kill'].update(call='unknown',wait='not_called',returncode=None);cases.append(('attempted-unknown-kill',unknown_kill))
  for name,header in cases:
   with self.subTest(case=name):
    capture=fixtures.Capture(self.work/('contradictory-'+name+'-capture'),self.held)
    with self.assertRaisesRegex(ValueError,'^baseline_remote_diagnostic_unknown_raw_retained$'):self.ns['parse_terminal']((json.dumps(header,sort_keys=True,separators=(',',':'))+'\n').encode(),{'source':PROGRAMME,'capture':capture})
    self.assertEqual(json.loads(capture.rows['remote-terminal.json']),header)
  self.save('contradiction',{'cases':len(cases),'allUnknownRawRetained':True,'successNotPromoted':True})
 def test_actual_child_wait_timeout_preserves_reason_and_branch(self):
  wire,header,fixture=self.raw_fixture('child_wait_timeout')
  self.save('child-wait-timeout',{'header':header,'actualTimeoutExpiredCallback':fixture.process.waitInjected,'killCallbackCalls':fixture.process.killCalls,'externalProcess':False})
  self.assertTrue(fixture.process.waitInjected);self.assertEqual(header['failure'],'TimeoutExpired')
  self.assertEqual(header['diagnostic']['collectionReason'],'baseline_remote_child_wait_timeout')
  self.assertEqual(header['diagnostic']['timeoutBranch'],'child_wait');self.assertEqual(header['diagnostic']['elapsedSeconds'],0)
  self.retained_unknown(wire,'child-wait-timeout')
 def test_actual_create_only_attempt_guard_still_refuses_without_dispatch(self):
  assets=self.module.assets
  with tempfile.TemporaryDirectory(prefix='owned-consumed-attempt-',dir=self.work)as name:
   directory=Path(name);path=directory/'owned-harmless-source';raw=b'owned harmless consumed-attempt fixture\n'
   direct.bundle._write(path,raw);pin=assets.snapshot(path,assets.MAX_TOTAL)
   marker=directory/'asset-collection-attempt.json';marker_raw=b'{"replayAllowed":false}\n';direct.bundle._write(marker,marker_raw)
   stream=types.SimpleNamespace(path=path,prefix=b'owned-harmless-frame\n')
   prepared={'payloadPin':pin};capture=types.SimpleNamespace(create=lambda *a:self.fail('capture_or_dispatch_reached'))
   for _ in range(2):
    with self.assertRaisesRegex(ValueError,'^asset_operator_collection_consumed$'):self.module.collect_asset(prepared,[],stream,capture,source_custody=lambda:direct._dispatch_guard(self.held))
   self.assertEqual(marker.read_bytes(),marker_raw);self.assertFalse((directory/'asset-collection-intent.json').exists())
  self.save('no-replay',{'actualCreateOnlyAttemptGuardInvoked':True,'attempts':2,'bothRefusedBeforeDispatch':True,'replayAllowed':False,'markerUnchanged':True,'nativeInvocation':False})

 def test_authenticated_before_timeout_control_reproduces_missing_reason(self):
  wire,before,fixture=self.raw_fixture(module=self.modules['before'])
  self.assertEqual(before['schema'],1);self.assertNotIn('diagnostic',before)
  self.assertEqual(before['failure'],'ValueError');self.assertEqual(before['returncode'],-9)
  self.assertIn(b'OWNED_HARMLESS_PHASE',fixture.phaseBuffer)
  self.assertEqual(hashlib.sha256(fixtures.HISTORICAL_REMOTE.encode()).hexdigest(),fixtures.HISTORICAL_REMOTE_SHA256)
  self.retained_unknown(wire,'historical-cause')

 def test_root_boot_caps_and_reviewed_embedded_collect_frame_preserved(self):
  self.assertEqual(hashlib.sha256(self.ns['ROOT_BOOT'].encode()).hexdigest(),fixtures.ROOT_BOOT_SHA256)
  self.assertEqual(hashlib.sha256(self.ns['_embedded_collect_source'].encode()).hexdigest(),'c2d9ba304459bc1d101b9586d2c81776682973bbea009deef18c2007cb682655')
  self.assertEqual(self.ns['CHUNK'],524288);self.assertEqual(self.ns['STREAM_LIMIT'],201326592)
  self.assertIn('time.monotonic()+1250',self.ns['_original_collect_source'])
  # Execute the reviewed production receiver at its exact controlled deadline.
  # Inspect its computed state and timeout envelope, not its source spelling.
  digest=hashlib.sha256(PROGRAMME).hexdigest()
  boot=self.ns['ROOT_BOOT'].replace('__BYTES__',str(len(PROGRAMME))).replace('__SHA__',repr(digest))
  remote=self.ns['REMOTE'].replace('__BYTES__',str(len(PROGRAMME))).replace('__SHA__',repr(digest)).replace('__BOOT__',repr(boot))
  fixture=fixtures.ReceiverFixture();fixture.clockAfterPhase=1200.
  wire,actual=fixture.execute(remote,boot);header=json.loads(wire.splitlines()[0])
  self.assertEqual(actual['collection_started'],0.);self.assertEqual(actual['deadline'],1200.)
  self.assertEqual(actual['remaining'],0.)
  self.assertEqual(header['diagnostic']['collectionReason'],'baseline_remote_collection_timeout')
  self.assertEqual(header['diagnostic']['timeoutBranch'],'collection_loop')
  self.assertEqual(header['diagnostic']['elapsedSeconds'],1200.)
  self.assertIn(b'OWNED_HARMLESS_PHASE',fixture.phaseBuffer)
  self.assertFalse(fixture.process.thread.is_alive());self.assertFalse(fixture.pipes.fds)
  self.assertEqual(fixture.process.killCalls,1)
  self.retained_unknown(wire,'exact-1200-deadline')
  self.assertIn('FILE_LIMIT=8388608',self.ns['ROOT_BOOT'])
