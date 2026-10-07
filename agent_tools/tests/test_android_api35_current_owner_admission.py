"""Real TempFS product/ADB responses and immutable fresh owner certificates."""
import ast,base64,copy,hashlib,json,os,stat,types,unittest
from pathlib import Path
from agent_tools import android_api35_current_owner_admission as admission
from agent_tools.tests import test_android_installer_component_bundle as fixture
NEW_OWNER='db5d7417-dd02-4e18-83f2-988caeec21a1'
CORR='4dd2d807-7968-4a43-842f-46a947304b2e'
def terminal_row():
 return {'controllerId':NEW_OWNER,'id':CORR,'requestId':'public request: non-UUID','operation':'diagnostics.export','phase':'succeeded','final':True,'cancellable':False,'completedUnits':None,'totalUnits':None,'code':'OK','configurationRevision':0,'restartRequired':False}
def measured_package_block(uid=10123,identity='appId'):
 # Self-contained exact structural fields measured in native031d's package block.
 return 'Packages:\n  Package [com.kardinal.vpncontrol] (2bb629f):\n    '+identity+'='+str(uid)+'\n    versionCode=16840 minSdk=29 targetSdk=35\n    versionName=2.2.2\n    flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]\n    User 0: ceDataInode=352921 deDataInode=57933 installed=true hidden=false\n\nQueries:\n'

@unittest.skipUnless(os.name=='posix','real descriptor/pipe component admission fixtures')
class AdmissionTests(unittest.TestCase):
 def setUp(self):
  self.helper=fixture.BundleTests();self.helper.setUp();self.addCleanup(self.helper.tearDown)
  self.selected,self.backend,self.args,self.state,self.log,_,_=self.helper.api35_fixture()
  context=self.selected['adapter'].production_imports('api35')
  transport=self.selected['transport'];reader=transport.readonly
  fragments=[transport.REMOTE+'\n'+transport._bounded_source(),reader.getter_source._GETTER.replace('__GETTER__','{}'),reader.getter_source.coldboot._BOOT.replace('__LAUNCH__','{}'),reader.proven._REMOTE.replace('__EXTERNAL__','{}')]
  names={'component_command','command_binary','command_request','command_host_identity','command_host_guard','command_bounded','getter_stage','child_identity','session_guest','qemu_fact','external_file','external_jdk','external_jdk_guard'}
  code=compile(context+'\n'+ast.unparse(ast.Module(body=[n for fragment in fragments for n in ast.parse(fragment).body if isinstance(n,ast.FunctionDef) and n.name in names],type_ignores=[])),'<actual-api35-fixed-readers>','exec',dont_inherit=True)
  for value in code.co_consts:
   if isinstance(value,types.CodeType) and value.co_name in names:
    previous=self.backend[value.co_name];self.backend[value.co_name]=types.FunctionType(value,self.backend,argdefs=previous.__defaults__)
  java=Path(self.backend['EXTERNAL']['selectedJdk']['root'])/'bin/java';adb=Path(self.backend['LAUNCH']['adbPath'])
  for path in (java,adb):
   raw=path.read_text().replace(" owner=args[args.index('--controller-id')+1]", " owner=args[args.index('--controller-id')+1] if '--controller-id'in args else None")
   raw=raw.replace("if 'shell' in args or 'exec-out' in args:","if '--version'in args:print('2.2.2');sys.exit(0)\nif 'shell' in args or 'exec-out' in args:")
   raw=raw.replace(" elif words[:1]==['cat']:print(state['boot'])", " elif words==['pidof','com.kardinal.vpncontrol']:print(state.get('appPid',31))\n elif words==['ps','-A','-o','PID,UID,NAME']:print('PID UID NAME\\n'+str(state.get('appPid',31))+' '+str(state.get('appUid',10123))+' com.kardinal.vpncontrol')\n elif words[:1]==['cat'] and words[1].endswith('/stat'):print(str(state.get('appPid',31))+' (vpncontrol) '+' '.join(['S']+['0']*18+[str(state.get('appTick',991))]))\n elif words[:1]==['cat']:print(state['boot'])")
   raw=raw.replace(" if args[-2:]==['operations','list']:"," if args[-2:]==['settings','show']:data={'configuredMode':'vpn','language':'en'}\n if args[-2:]==['operations','list']:")
   raw=raw.replace("data={'operations':state['operations']}","data={'scope':'android-provider-operations','operations':state['operations']}")
   raw=raw.replace("print('versionName=2.2.2 versionCode=16840')",'print('+repr(measured_package_block())+')')
   path.write_text(raw)
  self.backend['LAUNCH']['adbFacts']['generation']=self.backend['fp'](adb.stat());self.backend['EXTERNAL']['selectedJdk']=self.backend['external_jdk']('jdk17')
  state=json.loads(self.state.read_bytes());state['owner']=NEW_OWNER;state['operations']=[terminal_row()];self.state.write_text(json.dumps(state))
  self.backend['GETTER']['generation']['device']={'sdk':state['sdk'],'abi':state['abi'],'kernelAvd':state['avd'],'bootAvd':state['avd'],'bootCompleted':'1','shellUid':state['uid'],'guestBootId':state['boot'],'matched':True}
  self.request={'host':'archlinux','device':'android-api35','correlationId':CORR,'sourceSha':admission.bundle._PRODUCT_SHA,'expectedAvd':'owned-fixture','expectedApi':35,'packageSha256':self.backend['GETTER']['packageSha256'],'reservation':copy.deepcopy(self.backend['LAUNCH']['intent']['reservation'])}
  self.scope={'COMPONENT_BUNDLE':admission.bundle,'OWNER_ADMISSION_KEYS':admission._KEYS,'OWNER_ADMISSION_SOURCE_SHA':hashlib.sha256(Path(admission.__file__).read_bytes()).hexdigest(),'copy':copy,'types':types,'re':__import__('re'),'Path':Path,'base64':base64,'hashlib':hashlib}
  exec(admission._REMOTE,self.scope)
 def create(self):return self.scope['OwnerAdmissionGuard'](self.helper.receipt,self.selected,self.backend,self.request)
 def test_current_owner_recipe_never_enables_physical_batch(self):
  guard=self.create();before=self.log.read_bytes()
  with self.assertRaisesRegex(ValueError,'owner_admission_batch_disabled'):guard.enable_physical_batch()
  for value in (None,{}):
   guard.batch_admission=value
   with self.subTest(value=value),self.assertRaisesRegex(ValueError,'owner_admission_batch_disabled'):guard._physical()
  del guard.batch_admission
  self.assertEqual(before,self.log.read_bytes())
  self.assertEqual(guard.expected,guard._physical())
 def test_wrong_bundle_source_refuses_before_factory_or_native_reader(self):
  from unittest.mock import patch
  before=self.log.read_bytes() if self.log.exists() else b''
  with patch.object(admission,'BUNDLE_SHA','0'*64):
   with self.assertRaisesRegex(ValueError,'owner_admission_source_changed'):admission.prepare_source(self.helper.receipt,{},self.request)
  self.assertEqual(before,self.log.read_bytes() if self.log.exists() else b'')
 def test_actual_constructor_root_worker_under_user_owned_receiver(self):
  from unittest import mock
  receiver=self.helper.root;parent_inode=receiver.stat().st_ino;real_uid=os.getuid()
  proxy=types.SimpleNamespace(**vars(os));proxy.getuid=proxy.geteuid=proxy.getgid=proxy.getegid=lambda:0
  def info(value):
   owner=1000 if value.st_ino==parent_inode else (0 if value.st_uid==real_uid else value.st_uid)
   return types.SimpleNamespace(**{name:(owner if name in ('st_uid','st_gid') else getattr(value,name)) for name in dir(value) if name.startswith('st_')})
  proxy.stat=lambda *args,**kwargs:info(os.stat(*args,**kwargs));proxy.fstat=lambda *args,**kwargs:info(os.fstat(*args,**kwargs))
  with mock.patch.object(admission.bundle,'os',proxy):
   constructor=next(n for n in ast.parse(admission._REMOTE).body if isinstance(n,ast.ClassDef)).body[0]
   statements=constructor.body
   start=next(i for i,n in enumerate(statements) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='output' for t in n.targets))
   stop=next(i for i,n in enumerate(statements[start:],start) if isinstance(n,ast.Assign) and ast.unparse(n.targets[0])=='self.args')
   scope={'b':admission.bundle,'Path':Path,'backend':self.backend,'request':self.request}
   exec(compile(ast.Module(body=statements[start:stop],type_ignores=[]),'<actual-constructor-directory>','exec'),scope)
   self.assertEqual(0,admission.bundle._directory(scope['output'])['generation'][3])
 def test_actual_stale_constructor_red_then_fresh_positive_certificate_green(self):
  stale={**self.request,'expectedOwner':admission.OLD_OWNER,'expectedRevision':0,'correlationId':'2f05bf99-19d1-41a3-ad95-b6653bba83c6'}
  with self.assertRaisesRegex(ValueError,'component_guard_owner_changed'):admission.bundle.BaselineGuard(self.helper.receipt,self.selected,self.backend,stale)
  guard=self.create();self.assertEqual(NEW_OWNER,guard.owner);self.assertEqual(31,guard.app['pid']);self.assertEqual(991,guard.app['startTicks']);self.assertEqual(10123,guard.app['uid']);self.assertEqual('2.2.2',guard.version)
  certificate=self.helper.root/('android-installer-component-baseline-'+CORR)/'current-owner-admission'/'admission.json';value=json.loads(certificate.read_bytes());self.assertEqual(NEW_OWNER,value['controllerId']);self.assertEqual(value,json.loads(json.dumps(guard.certificate)));self.assertFalse(value['guestMutationPerformed']);self.assertFalse(value['installerLeaseGranted'])
  self.assertFalse(any('updates' in row or 'off' in row for row in [json.loads(line) for line in self.log.read_text().splitlines()]))
  with self.assertRaises(FileExistsError):self.create()
 def test_runtime_running_refuses_certificate(self):
  state=json.loads(self.state.read_bytes());state['runtime']=True;self.state.write_text(json.dumps(state))
  with self.assertRaisesRegex(ValueError,'fresh_stopped_owner_unknown'):self.create()
  self.assertFalse((self.helper.root/('android-installer-component-baseline-'+CORR)/'current-owner-admission'/'admission.json').exists())
 def test_real_foreign_malformed_ledger_causal_refusal(self):
  state=json.loads(self.state.read_bytes());state['operations']=[{'final':True,'controllerId':'foreign','id':'not-an-id'}];self.state.write_text(json.dumps(state))
  with self.assertRaisesRegex(ValueError,'owner_admission_ledger'):self.create()
  self.assertFalse((self.helper.root/('android-installer-component-baseline-'+CORR)/'current-owner-admission'/'admission.json').exists())
 def test_real_complete_foreign_dto_refuses_certificate(self):
  row=terminal_row();row['controllerId']='8cafc586-56e8-4a82-ad1e-94af6159c993'
  state=json.loads(self.state.read_bytes());state['operations']=[row];self.state.write_text(json.dumps(state))
  with self.assertRaisesRegex(ValueError,'owner_admission_ledger_row_unknown'):self.create()
  self.assertFalse((self.helper.root/('android-installer-component-baseline-'+CORR)/'current-owner-admission'/'admission.json').exists())
 def test_shell_root_uid_refuses_certificate_before_app_reads(self):
  state=json.loads(self.state.read_bytes());state['uid']='0';self.state.write_text(json.dumps(state))
  with self.assertRaisesRegex(ValueError,'component_guard_device_unadmitted'):self.create()
  self.assertFalse((self.helper.root/('android-installer-component-baseline-'+CORR)/'current-owner-admission'/'admission.json').exists())
  self.assertFalse(any('pidof' in json.loads(line) for line in self.log.read_text().splitlines()))
 def test_same_owned_qemu_changed_guest_boot_causal_refusal(self):
  state=json.loads(self.state.read_bytes());state['boot']='77f8c47a-97c0-4d04-a621-51fa4b175d86';self.state.write_text(json.dumps(state))
  with self.assertRaisesRegex(ValueError,'owner_admission_original_guest_changed'):self.create()
  self.assertFalse((self.helper.root/('android-installer-component-baseline-'+CORR)/'current-owner-admission'/'admission.json').exists())
 def test_public_api35_appid_sample_causal_positive_admission(self):
  # Public structural package sample, not a native raw receipt/admission claim.
  package=measured_package_block(uid=10209)
  adb=Path(self.backend['LAUNCH']['adbPath']);lines=adb.read_text().splitlines();lines=[" elif words[:2]==['dumpsys','package']:print("+repr(package)+")" if "elif words[:2]==['dumpsys','package']" in line else line for line in lines];adb.write_text('\n'.join(lines)+'\n');self.backend['LAUNCH']['adbFacts']['generation']=self.backend['fp'](adb.stat())
  state=json.loads(self.state.read_bytes());state['appUid']=10209;state['appPid']=5447;self.state.write_text(json.dumps(state))
  guard=self.create();self.assertEqual(10209,guard.app['uid']);self.assertEqual(5447,guard.app['pid']);self.assertEqual(NEW_OWNER,guard.owner)
 def test_app_uid_and_pid_start_tick_parser_reject(self):
  state=json.loads(self.state.read_bytes());state['appUid']=2000;self.state.write_text(json.dumps(state))
  with self.assertRaisesRegex(ValueError,'app_process_unknown'):self.create()
 def test_owner_or_app_drift_during_measured_reads_refuses(self):
  cls=self.scope['OwnerAdmissionGuard'];original=cls._fresh_reply;count=[0]
  def reply(self,*args):
   value=original(self,*args);count[0]+=1
   if count[0]==1:
    state=json.loads(Path(self.backend['ROOT']).joinpath('device.json').read_bytes());state['owner']='b0a17e46-a2e8-45cc-836b-fc8a63707d13';Path(self.backend['ROOT']).joinpath('device.json').write_text(json.dumps(state))
   return value
  cls._fresh_reply=reply
  with self.assertRaisesRegex(ValueError,'fresh_owner_unknown'):self.create()
 def test_crossed_reservation_and_api_refuse_before_children(self):
  self.request['reservation']={'foreign':True}
  with self.assertRaisesRegex(ValueError,'reservation_changed'):self.create()
  self.assertFalse(self.log.exists())
 def test_real_app_start_tick_drift_after_settings_no_certificate(self):
  cls=self.scope['OwnerAdmissionGuard'];original=cls._settings;count=[0]
  def settings(guard):
   value=original(guard);count[0]+=1
   if count[0]==1:
    state=json.loads(self.state.read_bytes());state['appTick']=992;self.state.write_text(json.dumps(state))
   return value
  cls._settings=settings
  with self.assertRaisesRegex(ValueError,'owner_admission_process_changed'):self.create()
  self.assertFalse((self.helper.root/('android-installer-component-baseline-'+CORR)/'current-owner-admission'/'admission.json').exists())
 def test_lost_status_read_same_correlation_consumed_without_admission(self):
  java=Path(self.backend['EXTERNAL']['selectedJdk']['root'])/'bin/java';raw=java.read_text().replace(" owner=args[args.index('--controller-id')+1] if '--controller-id'in args else None", " if '--controller-id'not in args:print('partial unknown response');sys.exit(0)\n owner=args[args.index('--controller-id')+1] if '--controller-id'in args else None")
  java.write_text(raw);self.backend['EXTERNAL']['selectedJdk']=self.backend['external_jdk']('jdk17')
  with self.assertRaises((ValueError,json.JSONDecodeError)):self.create()
  with self.assertRaises(FileExistsError):self.create()
  self.assertFalse((self.helper.root/('android-installer-component-baseline-'+CORR)/'current-owner-admission'/'admission.json').exists())
 def test_failed_run_preserves_closing_evidence_and_never_owner_adoption(self):
  java=Path(self.backend['EXTERNAL']['selectedJdk']['root'])/'bin/java';raw=java.read_text().replace(" owner=args[args.index('--controller-id')+1] if '--controller-id'in args else None", " if '--controller-id'not in args:print('partial unknown response');sys.exit(0)\n owner=args[args.index('--controller-id')+1] if '--controller-id'in args else None")
  java.write_text(raw);self.backend['EXTERNAL']['selectedJdk']=self.backend['external_jdk']('jdk17')
  with self.assertRaises((ValueError,json.JSONDecodeError)):self.scope['owner_admission_run'](self.helper.receipt,self.backend,self.request)
  folder=self.helper.root/('android-installer-component-baseline-'+CORR)/'current-owner-admission';closing=json.loads((folder/'read-failed-closing.json').read_bytes())['record'];self.assertTrue(closing['physicalVerified']);self.assertTrue(closing['appProcessVerified']);self.assertFalse(closing['admissionGranted']);self.assertFalse((folder/'admission.json').exists())

class PublicSchemaTests(unittest.TestCase):
 def package_uid(self,value,uid=10123):
  node=next(n for n in ast.parse(admission._REMOTE).body if isinstance(n,ast.FunctionDef) and n.name=='owner_admission_package_uid');scope={'re':__import__('re')};exec(compile(ast.Module(body=[node],type_ignores=[]),'<actual-package-uid>','exec'),scope)
  return scope['owner_admission_package_uid'](value,uid)
 def test_measured_appid_and_legacy_userid_primary_user_mapping(self):
  self.assertEqual(10123,self.package_uid(measured_package_block()))
  self.assertEqual(10123,self.package_uid(measured_package_block(identity='userId')))
  self.assertEqual(10209,self.package_uid(measured_package_block(10209),10209))
 def test_package_identity_foreign_duplicate_conflict_user_and_version_refuse(self):
  raw=measured_package_block()
  variants=[raw.replace('appId=10123','appId=10209'),raw.replace('appId=10123','appId=10123\n    userId=10124'),raw.replace('appId=10123','appId=10123\n    appId=10123'),raw.replace('appId=10123','appId=bad'),raw.replace('com.kardinal.vpncontrol','foreign.package'),raw.replace('User 0:','User 1:'),raw.replace('installed=true','installed=false'),raw.replace('installed=true','installed=true installed=false'),raw.replace('2.2.2','2.2.3'),raw.replace('16840','16841'),raw.replace('HAS_CODE','DEBUGGABLE'),raw.replace('Packages:','Foreign:'),raw+raw]
  for value in variants:
   with self.subTest(dump=value),self.assertRaisesRegex(ValueError,'owner_admission_'):self.package_uid(value)
  with self.assertRaisesRegex(ValueError,'app_uid_changed'):self.package_uid(measured_package_block(110123),110123)
 def ledger(self,rows,revision=3):
  tree=ast.parse(admission._REMOTE);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='owner_admission_ledger');scope={'re':__import__('re')}
  exec(compile(ast.Module(body=[node],type_ignores=[]),'<actual-admission-ledger>','exec'),scope)
  return scope['owner_admission_ledger']({'scope':'android-provider-operations','operations':rows},NEW_OWNER,revision)
 def test_exact_terminal_dto_nullable_progress_arbitrary_request_and_prior_revision(self):
  row=terminal_row();self.ledger([row]);row.update(phase='failed',code='UNAVAILABLE',configurationRevision=1,completedUnits=0,totalUnits=None,restartRequired=True);self.ledger([row])
  row.update(phase='cancelled',code='CANCELLED',completedUnits=None,totalUnits=0);self.ledger([row])
 def test_malformed_terminal_schema_identity_types_progress_and_phase_refuse(self):
  row=terminal_row()
  variants=[{**row,key:value} for key,values in {'controllerId':['foreign'],'id':['not-an-id',CORR.upper()],'requestId':[' ',None],'operation':['arbitrary',None],'phase':['running','unknown',None],'final':[1,False],'cancellable':[0,True],'configurationRevision':[True,-1,4,None],'restartRequired':[0,None],'code':['ACCEPTED','UNKNOWN',None],'completedUnits':[True,-1,2**63],'totalUnits':[False,-1,2**63]}.items() for value in values]
  variants += [{key:value for key,value in row.items() if key!='requestId'},{**row,'secret':'private'},{**row,'completedUnits':2,'totalUnits':1},{**row,'phase':'failed','code':'OK'},{**row,'phase':'cancelled','code':'OK'}]
  for value in variants:
   with self.subTest(row=value),self.assertRaisesRegex(ValueError,'owner_admission_ledger'):self.ledger([value])
 def test_duplicate_ids_requests_and_capacity_refuse(self):
  row=terminal_row();second={**row,'id':'8cafc586-56e8-4a82-ad1e-94af6159c993'}
  for values in ([row,row],[row,second],[row]*257):
   with self.assertRaisesRegex(ValueError,'owner_admission_ledger'):self.ledger(values)
 def test_ledger_catalogue_matches_canonical_kotlin_wire_enums(self):
  node=next(n for n in ast.parse(admission._REMOTE).body if isinstance(n,ast.FunctionDef) and n.name=='owner_admission_ledger')
  values={n.targets[0].id:ast.literal_eval(n.value) for n in node.body if isinstance(n,ast.Assign) and isinstance(n.value,ast.Set)}
  model=Path(admission.__file__).parent.parent/'shared/model/src/commonMain/kotlin/com/kardinal/vpncontrol/model'
  self.assertEqual(set(__import__('re').findall(r'\("([a-z.-]+)"\)',(model/'ControlOperationId.kt').read_text())),values['operations'])
  codes=set(__import__('re').findall(r'^    [A-Z_]+\("([A-Z_]+)",', (model/'ControlModels.kt').read_text(),__import__('re').M))
  self.assertEqual(codes-{'OK','ACCEPTED'},values['failures'])
 def test_invalid_device_rejects_before_source_or_native(self):
  from unittest import mock
  with mock.patch.object(admission.availability,'_snapshot',side_effect=AssertionError('no private reads')):
   for value in ({},{'device':'android-api29'},{'expectedApi':True}):
    with self.assertRaisesRegex(ValueError,'owner_admission_request_unknown'):admission.prepare_source({}, {}, value)
 def test_recipe_uses_no_installer_or_runtime_mutation_command(self):
  tree=ast.parse(admission._REMOTE);calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call)]
  forbidden={'off','on','install','force-stop','root','unroot','set'}
  for call in calls:
   if ast.unparse(call.func).endswith(('._text','._fresh_reply','component_command')):
    for argument in call.args:
     if isinstance(argument,ast.List):self.assertFalse(forbidden.intersection(n.value for n in argument.elts if isinstance(n,ast.Constant) and type(n.value)is str))

@unittest.skipUnless(os.name=='posix','POSIX source-closed factory composition')
class FactoryTests(unittest.TestCase):
 def test_actual_complete_api35_factory_carrier_contains_exact_read_recipe(self):
  from agent_tools import android_api35_coldboot_product_observation as observer
  from agent_tools.tests.fixtures.android_api35_historical_context import install
  history=install(self,globals(),'admission')
  from agent_tools.tests.fixtures.android_remaining_hermetic import component_command
  admission.command=component_command(history,admission.command)
  helper=fixture.BundleTests();helper.setUp()
  try:
   prepared=history.prepare();prepared,_=admission.command.prepare(history.root,prepared,'android-api35')
   tree=ast.parse(prepared['program']);getter=admission.command.readonly._assignment(tree,'GETTER');launch=admission.command.readonly._assignment(tree,'LAUNCH')
   request={'host':'archlinux','device':'android-api35','correlationId':CORR,'sourceSha':admission.bundle._PRODUCT_SHA,'expectedAvd':launch['avd'],'expectedApi':35,'packageSha256':getter['packageSha256'],'reservation':launch['intent']['reservation']}
   # Current changed bundle stays incompatible with the frozen consumer.
   with self.assertRaisesRegex(ValueError,'owner_admission_source_changed'):
    admission.prepare_source(helper.receipt,prepared,request)
   from agent_tools.tests.fixtures import historical_source
   archive=Path(__file__).parent/'fixtures/android_installer_hermetic/component-bundle.source'
   raw=archive.read_bytes();destination=history.root/'agent_tools/android_installer_component_bundle.py';destination.write_bytes(raw)
   compatible=historical_source.load(destination,admission.BUNDLE_SHA)
   source_file=helper.source_root/'agent_tools/android_installer_component_bundle.py'
   source_file.write_bytes(raw)
   receipt=compatible.prepare(helper.source_root,helper.root/'compatible-stage',compatible.reviewed_tree(helper.source_root)['treeSha256'])
   admission.bundle=compatible
   source=admission.prepare_source(receipt,prepared,request);code=compile(source,'<complete-api35-owner-carrier>','exec',dont_inherit=True)
   case=AdmissionTests();case.setUp()
   try:
    names={'component_command','command_binary','command_request','command_host_identity','command_host_guard','command_bounded','getter_stage','child_identity','session_guest','qemu_fact','external_file','external_jdk','external_jdk_guard'}
    for value in code.co_consts:
     if isinstance(value,types.CodeType) and value.co_name in names:
      previous=case.backend[value.co_name];case.backend[value.co_name]=types.FunctionType(value,case.backend,argdefs=previous.__defaults__)
    pins=admission.bundle._guard_backend(case.selected,case.backend,'api35');self.assertTrue(names.issubset(pins))
   finally:case.doCleanups()
   self.assertIn('OWNER_ADMISSION_RESULT=owner_admission_run',source);self.assertIn('COMPONENT_RECEIPT=COMPONENT_BUNDLE.stage_payload',source);self.assertIn('appProcess',source)
   self.assertIn(Path(admission.__file__).absolute(),prepared['snapshots']);self.assertEqual('owner_admission_run',next(value.co_name for value in code.co_consts if isinstance(value,types.CodeType) and value.co_name=='owner_admission_run'))
   self.assertEqual(1,sum(isinstance(n,ast.ClassDef) and n.name=='OwnerAdmissionGuard' for n in ast.parse(source).body))
  finally:helper.tearDown()
