"""Native-derived public foreground with synthetic backdrop recognition controls.

No native access/newframe/privatefield/ordinarycredentials. No profile authority
is minted. Only before/candidate module definitions and extracted recipient run.
"""
from pathlib import Path
import ast,io,json,types,sys,unittest,hashlib,os,tempfile,time
from contextlib import ExitStack
from unittest import mock
from PIL import Image
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT));O=ROOT/'agent_tools';F=Path(__file__).with_name('fixtures')/'tart_macos_label_profile'
def module(path,name):
 m=types.ModuleType(name);m.__package__='agent_tools';m.__file__=str(path);exec(compile(path.read_bytes(),str(path),'exec'),m.__dict__);return m
OLD=module(F/'readiness_tart_macos_unlock.before.source','_label_old');NEW=module(O/'readiness_tart_macos_unlock.py','_label_candidate');Q=module(O/'readiness_tart_macos_unlock_qualification.py','_label_qualification');profile=dict(Q.PROFILE)
def images():
 data=json.loads((F/'public-label-mask.json').read_bytes());result=[]
 assert data['width']==180 and data['height']==41
 for backdrop in((110,18,0),(180,68,12)):
  image=Image.new('RGB',profile['dimensions']);a=profile['accountBox']
  image.paste(Image.new('RGB',(180,41),backdrop),a[:2])
  for i in data['foreground']:image.putpixel((a[0]+i%180,a[1]+i//180),(255,255,255))
  result.append(image)
 return result

_provenance=json.loads((F/'provenance.json').read_bytes());assert _provenance['nativeCallsInRoutine']==0 and _provenance['credentialBytes'] is False
rows=[]
class Checks(unittest.TestCase):
 def test_authentic_before_native_foreground_synthetic_backdrop_rejection(self):
  current,baseline=images();tree=ast.parse((F/'readiness_tart_macos_unlock.before.source').read_bytes());recipient=next(n for n in ast.walk(tree)if isinstance(n,ast.FunctionDef)and n.name=='recipient')
  data=io.BytesIO();current.save(data,format='PNG');calls=[];ns={**OLD.__dict__,'guard':lambda:calls.append('guard'),'_image':OLD._image,'view':types.SimpleNamespace(capture_png=lambda:data.getvalue()),'material':types.SimpleNamespace(profile=profile),'baseline':baseline};exec(compile(ast.Module(body=[recipient],type_ignores=[]),'authentic-before-recipient','exec'),ns)
  with self.assertRaises(OLD.UnlockBlocked)as err:ns['recipient']()
  self.assertEqual(err.exception.args,('macos_unlock_recipient_changed',));self.assertEqual(calls,['guard'])
  actual,expected=NEW._white_label_mask(current,profile),NEW._white_label_mask(baseline,profile);self.assertEqual(actual,expected);self.assertEqual(sum(actual),576);self.assertFalse(NEW._account_matches(current,baseline,profile))
  rows.append({'case':'native_foreground_synthetic_backdrops','oldFullRgbRefuses':True,'whiteMaskPixels':576,'whiteMaskDiff':0,'newEpochDispatchAuthority':False})
 def test_altered_name_layout_blank_bright_unrecognized_and_threshold_nearwhite_refused(self):
  current,baseline=images();expected=NEW._white_label_mask(baseline,profile);a=profile['accountBox'];white=next(i for i,v in enumerate(expected)if v);x,y=a[0]+white%180,a[1]+white//180
  mutants={}
  im=current.copy();im.putpixel((x,y),(0,0,0));mutants['removed_glyph_stroke']=im
  im=current.copy();im.putpixel((a[0],a[1]),(255,255,255));mutants['extra_unrecognized_white']=im
  im=current.copy();crop=im.crop(a);im.paste(Image.new('RGB',(180,41)),a[:2]);im.paste(crop,(a[0]+1,a[1]));mutants['layout_shift_one_pixel']=im
  im=current.copy();im.paste(Image.new('RGB',(180,41)),a[:2]);mutants['blank']=im
  im=current.copy();im.paste(Image.new('RGB',(180,41),(255,255,255)),a[:2]);mutants['bright_white']=im
  im=current.copy();im.paste(Image.new('RGB',(180,41),(254,254,254)),a[:2]);mutants['bright_nearwhite']=im
  im=current.copy();im.putpixel((x,y),(245,245,245));mutants['threshold245_not_exactwhite']=im
  for name,im in mutants.items():
   with self.subTest(name=name):self.assertNotEqual(NEW._white_label_mask(im,profile),expected)
  rows.append({'case':'meaningful_negatives','variants':list(mutants),'allRefused':True})
 def test_nonwhite_backdrop_ignored_only_in_pure_foreground_algorithm_not_default_mode(self):
  current,baseline=images();mask=NEW._white_label_mask(baseline,profile);a=profile['accountBox'];changed=current.copy()
  for i,pixel in enumerate(mask):
   if not pixel:changed.putpixel((a[0]+i%180,a[1]+i//180),(4,221,19))
  self.assertEqual(NEW._white_label_mask(changed,profile),mask);self.assertFalse(NEW._account_matches(changed,baseline,profile))
  rows.append({'case':'no_implicit_mode_switch','defaultStillFullRgb':True,'foregroundIsLabelOnlyNotWholeScreenRecognition':True})
 def test_caller_dto_epoch_constructor_or_missing_native_driver_cannot_enable(self):
  with self.assertRaises(Q.QualificationBlocked):Q.LabelProfile()
  for value in(None,{'labelForegroundEpoch':Q._LABEL_MODE},types.SimpleNamespace(_token=object()),object.__new__(Q.LabelProfile)):
   with self.assertRaises(Q.QualificationBlocked):Q._label_epoch_guard(value,object(),profile)
  with self.assertRaises(Q.QualificationBlocked):Q.label_profile_program(types.SimpleNamespace(), '11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222')
  rows.append({'case':'opaque_source_epoch_gate','callerDtosRefused':True,'requiresCanonicalOwnedNativeProgram':True})
 def test_opaque_samecustody_epoch_binds_exact_held_baseline_mask(self):
  import agent_tools as package
  current,baseline=images();custody=types.SimpleNamespace(_operator=types.SimpleNamespace(guard=lambda:None))
  epoch=object.__new__(Q.LabelProfile);epoch._token=Q._LABEL_TOKEN;epoch._custody=custody;epoch._held=[];epoch._owner=types.SimpleNamespace(observe=lambda:{'state':'terminal'});epoch._owner_state={'state':'terminal'};epoch._mask=NEW._white_label_mask(baseline,profile);epoch._closed=False
  with mock.patch.object(package,'readiness_tart_macos_unlock_qualification',Q,create=True),mock.patch.dict(sys.modules,{'agent_tools.readiness_tart_macos_unlock_qualification':Q}):
   self.assertTrue(NEW._account_matches(current,baseline,profile,epoch=epoch,custody=custody))
   with self.assertRaises(Q.QualificationBlocked):NEW._account_matches(current,baseline,profile,epoch=epoch,custody=object())
   epoch._mask=bytes(len(epoch._mask))
   with self.assertRaises(Q.QualificationBlocked):NEW._account_matches(current,baseline,profile,epoch=epoch,custody=custody)
   epoch._mask=NEW._white_label_mask(baseline,profile);epoch._owner_state={'state':'terminal','exitCode':0}
   with self.assertRaises(Q.QualificationBlocked):NEW._account_matches(current,baseline,profile,epoch=epoch,custody=custody)
  rows.append({'case':'actual_opaque_mask_gate','sameCustodyRequired':True,'differentBaselineMaskRefused':True,'controlledPrivateTokenNotNativeAuthority':True})
 def test_empty_field_same_original_function_unchanged_caret_only_exception(self):
  old=next(ast.get_source_segment((F/'readiness_tart_macos_unlock.before.source').read_text(),n)for n in ast.parse((F/'readiness_tart_macos_unlock.before.source').read_bytes()).body if isinstance(n,ast.FunctionDef)and n.name=='_empty');new=next(ast.get_source_segment((O/'readiness_tart_macos_unlock.py').read_text(),n)for n in ast.parse((O/'readiness_tart_macos_unlock.py').read_bytes()).body if isinstance(n,ast.FunctionDef)and n.name=='_empty');self.assertEqual(old,new)
  a=Image.new('RGB',profile['dimensions']);b=a.copy();box=profile['fieldBox'];b.putpixel((box[0]+profile['caretBox'][0],box[1]+profile['caretBox'][1]),(255,255,255));self.assertTrue(NEW._empty(a,b,profile));b.putpixel((box[0]+30,box[1]+5),(1,0,0));self.assertFalse(NEW._empty(a,b,profile));rows.append({'case':'empty_guard_not_weakened','functionByteIdentical':True,'nonCaretBackdropChangeRefused':True,'nativeFieldEvidence':'not captured; actual historical field RGB stability remains unproven'})

Q.unlock=NEW;U=NEW
from agent_tools import durable_remote_job as J,private_inventory_lock as P
from agent_tools.tests.test_readiness_tart_macos_unlock import binding,identity
DEPENDENCY_ROOT=Path(J.__file__).resolve().parents[1]
class Integration(unittest.TestCase):
 def test_native_renderer_fixed_no_field_pixels_or_input_and_wrapper_original_intent_first(self):
  body=Q._render_profile_driver('/controlled','controlled-epoch','tart:explicit',{'fixed.py':'a'*64});tree=ast.parse(body);compile(body,'fixed-readonly-profile','exec');calls=[n for n in ast.walk(tree)if isinstance(n,ast.Call)]
  self.assertEqual(sum(isinstance(n.func,ast.Attribute)and n.func.attr=='capture_png'for n in calls),1)
  for n in calls:
   if isinstance(n.func,ast.Attribute):self.assertNotIn(n.func.attr,{'save','key','mouse','type_public','type_secret_from_fd','unlock_once','SessionObserver'})
  self.assertIn(b'U._foreground_label_matches',body);self.assertIn(b'U._empty',body);self.assertIn(b'nonCaretFieldDifferingPixels',body);self.assertNotIn(b'576',body)
  self.assertLess(Q._PROFILE_WRAPPER.index('J._intent('),Q._PROFILE_WRAPPER.index('J._create('));self.assertLess(Q._PROFILE_WRAPPER.index('J._publish('),Q._PROFILE_WRAPPER.index('exec(compile(original'))
  self.assertEqual(hashlib.sha256(Q._PROFILE_CAPTURE_SOURCE).hexdigest(),'387919a86e815bfb879be04c280db870a64ca09fd65931dace82b51d6d113b36')
 def test_actual_durable_wrapper_publishes_fixed_files_after_intent_before_driver(self):
  with tempfile.TemporaryDirectory(prefix='label-profile-wrapper-')as tmp:
   life=Path(tmp).resolve();life.chmod(0o700);jobs=life/'jobs';jobs.mkdir(mode=0o700);generation=J.root_generation(jobs);host=J.current_binding('controlled-explicit','controlled');op='55555555-5555-4555-8555-555555555555';lease='66666666-6666-4666-8666-666666666666'
   c=types.SimpleNamespace(root=DEPENDENCY_ROOT,lifecycle_root=life,binding=binding(),fixture_id='controlled',run_intent={'operationId':'77777777-7777-4777-8777-777777777777'})
   driver=b"print('public readonly wrapper reached',flush=True)\n"
   with mock.patch.object(Q,'_profile_context',return_value=(jobs,generation,host)),mock.patch.object(Q,'_profile_roles',return_value={}),mock.patch.object(Q,'_render_profile_driver',return_value=driver):
    program=Q._label_program(c,op,lease,'controlled')
   J.submit(jobs,op,host,program,generation=generation);stop=time.monotonic()+8
   while (state:=J.observe(jobs,op,host,generation=generation))['state']!='terminal':
    self.assertLess(time.monotonic(),stop);time.sleep(.02)
   status,stdout,stderr=J.collect(jobs,op,host,generation=generation)
   self.assertEqual(status['terminal']['exitCode'],0,stderr);self.assertEqual(stdout,b'public readonly wrapper reached\n');self.assertEqual(stderr,b'')
   self.assertEqual((jobs/op/'label-driver.py').read_bytes(),driver);self.assertEqual((jobs/op/'label-profile-capture.py').read_bytes(),Q._PROFILE_CAPTURE_SOURCE)
   self.assertEqual((jobs/op/'label-driver.py').stat().st_mode&0o777,0o600)
   self.assertEqual(json.loads((life/('native-unlock-controller-'+op+'.json')).read_text())['programSha256'],program.digest)
 def test_runtime_mask_not_fixture_count_and_empty_fullwhite_baseline_refuses(self):
  profile=dict(Q.PROFILE)
  for pixel in((0,0,0),(255,255,255)):
   im=Image.new('RGB',profile['dimensions'],pixel)
   with self.assertRaises(U.UnlockBlocked):U._foreground_label_matches(im,im,profile)
  im=Image.new('RGB',profile['dimensions']);im.putpixel((430,415),(255,255,255));self.assertTrue(U._foreground_label_matches(im,im,profile))
 def test_material_epoch_load_failure_always_closes_full_unlock_admission(self):
  source=(O/'readiness_tart_macos_unlock_material.py').read_text();tree=ast.parse(source);f=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='material');outer=next(n for n in f.body if isinstance(n,ast.With));body=outer.body
  # Execute actual load/try/finally slice; inject failure at profile loading,
  # before unrelated native/private material code. No credential reader reachable.
  fn=ast.FunctionDef(name='probe',args=ast.arguments(posonlyargs=[],args=[],kwonlyargs=[],kw_defaults=[],defaults=[]),body=body,decorator_list=[]);code=compile(ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[])),'actual-material-load-cleanup','exec');closed=[]
  admitted=types.SimpleNamespace(close=lambda:closed.append('closed'))
  fake=types.SimpleNamespace(load=lambda c:admitted,load_label_epoch=lambda c:(_ for _ in()).throw(ValueError('controlled')))
  namespace={'qualification':fake,'custody':object()};exec(code,namespace)
  with self.assertRaises(ValueError):next(namespace['probe']())
  self.assertEqual(closed,['closed'])
 def test_whole_prior_profile_mint_adopts_second_terminal_current_refuses(self):
  before=globals()['module'](F/'qualification-owner-admission.before.source','_profile_mint_before');before.unlock=U
  with tempfile.TemporaryDirectory(prefix='label-profile-mint-')as tmp:
   project=Path(tmp).resolve();project.chmod(0o700);root=project/'.runtime';root.mkdir(mode=0o700);op='88888888-8888-4888-8888-888888888888'
   baseline=root/'public-held-source-native-wake-empty-Tool-Recovery-lockscreen-1792522029846637000.png';image=Image.new('RGB',Q.PROFILE['dimensions']);image.putpixel((430,415),(255,255,255));buf=io.BytesIO();image.save(buf,format='PNG');baseline.write_bytes(buf.getvalue());baseline.chmod(0o600)
   ref={'path':str(baseline),'pin':{'generation':list(P._generation(baseline.stat())),'sha256':hashlib.sha256(baseline.read_bytes()).hexdigest()}}
   authorized={'state':'terminal','terminal':{'exitCode':0,'streamsClosed':True,'stdout':{'sha256':'a'*64}}};changed={'state':'terminal','terminal':{'exitCode':0,'streamsClosed':True,'stdout':{'sha256':'b'*64}}}
   case={'operationId':op,'baseline':ref,'before':identity()};receipt={'schemaVersion':1,'mode':Q._LABEL_MODE,'case':case};path=root/('label-profile-epoch-'+op+'.json');path.write_text(json.dumps(receipt));path.chmod(0o600);pin={'generation':list(P._generation(path.stat())),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
   c=types.SimpleNamespace(root=project,lifecycle_root=root,descriptor={'qualifications':{'labelProfile':{'path':str(path),'pin':pin}}},_operator=types.SimpleNamespace(guard=lambda:None))
   for module,old in((before,True),(Q,False)):
    with self.subTest(old=old),mock.patch.object(module,'_profile_context',return_value=None),mock.patch.object(module,'_LABEL_BASELINE_SHA',ref['pin']['sha256']):
     owner=types.SimpleNamespace(observe=lambda:changed);result=(case,owner)if old else(case,owner,authorized)
     with mock.patch.object(module,'_read_profile_case',return_value=result):
      if old:
       value=module.load_label_epoch(c);self.assertEqual(value._owner_state,changed);value.close()
      else:
       with self.assertRaises(module.QualificationBlocked)as error:module.load_label_epoch(c)
       self.assertEqual(error.exception.args,('macos_label_profile_original_changed',))
 def test_actual_durable_owner_complete_parser_and_source_tamper_refusal(self):
  with tempfile.TemporaryDirectory(prefix='label-profile-owner-')as tmp:
   root=Path(tmp).resolve();root.chmod(0o700);life=root/'.runtime';life.mkdir(mode=0o700);jobs=life/'jobs';jobs.mkdir(mode=0o700);generation=J.root_generation(jobs);host=J.current_binding('controlled-explicit','controlled');op='11111111-1111-4111-8111-111111111111';lease='33333333-3333-4333-8333-333333333333';folder=life/('native-label-profile-'+op);folder.mkdir(mode=0o700)
   selected=binding();ident=identity();packet={'facts':{'machine':ident['machine'],'boot':ident['boot'],'uid':ident['uid'],'account':ident['principal'],'home':ident['home'],'console':ident['console'],'display':ident['display']},'agent':{'actor':{'pid':17,'birth':'darwin:123:4'},'uid':ident['uid'],'principal':ident['principal'],'home':ident['home'],'python':selected.guest_python,'rawBoot':ident['rawBoot']}}
   img=Image.new('RGB',Q.PROFILE['dimensions']);img.putpixel((430,415),(255,255,255));buf=io.BytesIO();img.save(buf,format='PNG');baseline=life/'public-held-source-native-wake-empty-Tool-Recovery-lockscreen-1792522029846637000.png';baseline.write_bytes(buf.getvalue());baseline.chmod(0o600);ref={'path':str(baseline),'pin':{'generation':list(P._generation(baseline.stat())),'sha256':hashlib.sha256(baseline.read_bytes()).hexdigest()}}
   metrics={'labelMatch':True,'baselineForegroundPixels':1,'emptyFieldMatch':False,'nonCaretFieldDifferingPixels':1,'nativeProfileMode':Q._LABEL_MODE};done={'operationId':op,'captures':1,'sameIdentityBeforeAfter':True,'profileMode':Q._LABEL_MODE,'state':'readonly_label_profile_qualified','ordinaryCredentialAccess':False,'guiInput':False,'fullFramePersisted':False,'newBaselineAuthority':False};pins={'fixed.py':'a'*64};fixed=b'# fixed public readonly probe\n';actor={'pid':99999999,'birth':'darwin:123:4','parent':os.getpid()};closure={'allClosed':True,'attempts':[{'actor':actor,'callback':{'actor':actor,'stdoutEof':True,'stderrEof':True,'partial':False,'actorAbsent':True}}]}
   records={'complete.json':json.dumps(done),'profile-match-result.json':json.dumps(metrics),'root-before.source.py':fixed.decode(),'root-after.source.py':fixed.decode(),'root-before.stdout.json':json.dumps(packet),'root-after.stdout.json':json.dumps(packet),'root-before.result.json':'{"returncode":0}','root-after.result.json':'{"returncode":0}','source-capsule-before.json':json.dumps(pins),'source-capsule-closed.json':json.dumps(pins),'rpc-closure.json':json.dumps(closure),'lease-original-status.json':'{}','baseline-reference.json':json.dumps(ref)}
   response={'operationId':op,'state':'readonly_label_profile_qualified',**metrics}
   body='CONFIG='+repr({'leaseOperationId':lease,'fixtureId':'controlled'})+'\nimport os,pathlib,json\nfolder=pathlib.Path('+repr(str(folder))+')\nrecords='+repr(records)+'\nfor name,text in records.items():\n fd=os.open(folder/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\n with os.fdopen(fd,"w")as f:f.write(text)\nprint('+repr(json.dumps(response))+',flush=True)\n';program=J.Program(Q._PROFILE_PURPOSE,body.encode(),262144);c=types.SimpleNamespace(root=root,lifecycle_root=life,host_binding=host,binding=selected,fixture_id='controlled',guest_proof={'prefix':'controlled','publicFiles':{}},_operator=types.SimpleNamespace(guard=lambda:None))
   patches=[mock.patch.object(Q,'_LABEL_BASELINE_SHA',ref['pin']['sha256']),mock.patch.object(Q,'_profile_context',return_value=(jobs,generation,host)),mock.patch.object(Q,'_label_program',return_value=program),mock.patch.object(Q,'_profile_roles',return_value=pins),mock.patch.object(Q,'_original_profile_fixture',side_effect=lambda c,f,h:f),mock.patch.object(Q.registry,'guest_probe_source',return_value=fixed)]
   with ExitStack()as stack:
    for patch in patches:stack.enter_context(patch)
    # A success DTO without an actual canonical original owner cannot qualify.
    held=[]
    with self.assertRaises((OSError,J.DurableJobError)):Q._read_profile_case(c,op,held)
    J.submit(jobs,op,host,program,generation=generation)
    stop=time.monotonic()+8
    while (state:=J.observe(jobs,op,host,generation=generation))['state']!='terminal' or J._birth(state['owner']['pid'])==state['owner']['birth']:
     self.assertLess(time.monotonic(),stop);time.sleep(.02)
    held=[]
    try:case,owner,validated=Q._read_profile_case(c,op,held);self.assertEqual(case['metrics'],metrics);self.assertEqual(owner.observe()['state'],'terminal')
    finally:
     for proof in reversed(held):proof.close()
    path=folder/'source-capsule-closed.json';path.write_text('{}')
    held=[]
    try:
     with self.assertRaises(Q.QualificationBlocked):Q._read_profile_case(c,op,held)
    finally:
     for proof in reversed(held):proof.close()

M=types.ModuleType('_public_guard_cost');exec(compile((F/'readonly-recipient-procedure.source').read_bytes(),'fixed-public-cost-procedure','exec'),M.__dict__)
class TimingChecks(unittest.TestCase):
 def test_exact_recipient_guard_path_128_events_no_input_and_counter_headroom(self):
  state=types.SimpleNamespace(counter=0);calls={'recipient':0,'guard':0,'checks':0}
  def guard():state.counter+=1;calls['guard']+=1
  def recipient(*a,guard,**k):
   calls['recipient']+=1;guard();view.capture_png();return object()
  class View:
   timeout=30
   def _check(self,extra=None):
    calls['checks']+=1;guard()
    if extra:extra()
   def _active(self):self._check();return M.time.monotonic()+30
   def capture_png(self):
    # Current complete raw-frame path: active, pre-request and completed frame.
    for _ in range(3):self._check()
    return b'fixed public pixels discarded'
  view=View();U=types.SimpleNamespace(_recipient_image=recipient,_empty=lambda *a:True,_need=lambda x,r:None)
  V=types.SimpleNamespace(_remaining=lambda d:1)
  result=M.measure(U,V,view,None,{},object(),object(),guard,state,deadline=M.time.monotonic()+180)
  self.assertEqual(calls['recipient'],131);self.assertEqual(result['secretEventGuardChecks'],128)
  self.assertEqual(result['observerCounterAfter'],state.counter);self.assertLess(state.counter,1024)
  self.assertEqual(result['recipientCaptures'],131);self.assertFalse(result['inputSent'])
 def test_slow_callback_hits_no_late_input_fence_without_claiming_strict_return_bound(self):
  state=types.SimpleNamespace(counter=0);calls=[]
  class View:
   def _active(self):return M.time.monotonic()+30
   def _check(self,extra=None):
    if extra:extra()
  def late(deadline):calls.append('late');raise TimeoutError()
  U=types.SimpleNamespace(_recipient_image=lambda *a,**k:object(),_empty=lambda *a:True,_need=lambda *a:None)
  with self.assertRaises(TimeoutError):M.measure(U,types.SimpleNamespace(_remaining=late),View(),None,{},object(),object(),lambda:None,state,deadline=M.time.monotonic()+180)
  self.assertEqual(calls,['late'])

if __name__=='__main__':unittest.main(verbosity=2)
