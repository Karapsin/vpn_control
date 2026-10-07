"""Complete generated restore transaction on inert process/filesystem fixtures."""
import ast, base64, hashlib, json, os, shlex, stat, tempfile, types, unittest
from pathlib import Path
from unittest import mock
from agent_tools import android_api35_owned_proxy_restore as restore
from agent_tools import android_avd_coldboot as coldboot
from agent_tools.tests import test_android_api35_current_proxy_probe as probes
from agent_tools.tests import test_android_api35_coldboot_product_observation as products
ROOT=Path(__file__).resolve().parents[2]
CORRELATION='65d8a14b-f3a8-4ae4-a74a-b6be55e2408f'

class Device:
 def __init__(self):
  self.rows={'global_http_proxy_host':'127.0.0.1','global_http_proxy_port':'45635','global_http_proxy_exclusion_list':''}
  self.kind='owned';self.effects=[];self.trigger=True;self.lose=None;self.foreign=None
 def read(self,ns,case):
  command=case['command']
  if case['mode'].startswith('restore-effect-'):
   index=int(case['mode'].rsplit('-',1)[1]);self.effects.append(command)
   words=shlex.split(command.split('/system/bin/settings ',1)[1]);op,_,key,*value=words
   if op=='put':self.rows[key]=value[0]
   else:self.rows.pop(key,None)
   # Primary-source-derived observer model: ONLY http_proxy is observed.
   if key=='http_proxy' and op=='put' and value==[':0'] and self.trigger:
    self.rows.update(global_http_proxy_host='',global_http_proxy_port='0',global_http_proxy_pac='',global_http_proxy_exclusion_list='');self.kind='clear'
   if self.lose==index:
    ns['GETTER_RECORDS']['lostEffect']={'command':command,'stdoutBase64':'','stderrBase64':'','unknown':True}
    raise ValueError('probe_transport_unknown')
   return probes.reply(b'')
  if case['mode'].startswith('restore-settings'):
   if self.foreign is not None:self.rows['global_http_proxy_host']=self.foreign
   return probes.reply((''.join(key+'='+value+'\n' for key,value in self.rows.items())).encode())
  if case['mode']=='restore-binder':
   value=probes.getter_value();value['correlationId']=restore.PROBE_CORRELATION
   proxy={'host':'127.0.0.1','port':45635,'exclusionList':[''],'pacUrl':''}
   if self.kind=='owned':value['reads']=[{'global':proxy,'defaultForShell':proxy}]*2
   return probes.reply(json.dumps(value).encode())
  if case['mode']=='restore-dex-generation':
   generation=ns['RESTORE']['deviceStageGeneration'];parent=generation['directory'];file=generation['file']
   return probes.reply(('\n'.join([parent,file,file,restore.DEX_SHA+'  /proc/self/fd/3',parent,file,file])+'\n').encode())
  raise AssertionError(case['mode'])

class RestoreTests(unittest.TestCase):
 def setUp(self):
  from agent_tools.tests.fixtures.android_api35_historical_context import install
  install(self,globals(),'restore')
  self.history.restore_metadata(restore)
  for target,name,value in ((probes,'probe',restore.current),(globals(),'coldboot',self.history.modules['coldboot'])):
   patch=mock.patch.dict(target,{name:value}) if isinstance(target,dict) else mock.patch.object(target,name,value)
   patch.start();self.addCleanup(patch.stop)

 def test_synthetic_receipt_binding_keeps_production_constant_and_hash_refusal(self):
  from agent_tools import android_api35_owned_proxy_restore as production
  from agent_tools.tests.fixtures.android_api35_historical_context import digest
  old=restore._syntheticRetirementDigestBinding['original']
  self.assertEqual(1,production._authority.__code__.co_consts.count(old))
  source=Path(production.__file__).read_bytes()
  self.assertEqual(source,(ROOT/'agent_tools'/Path(production.__file__).name).read_bytes())
  path=ROOT/'.runtime/parity-evidence/android-current/api35-retirement-d0fb-native-receipt.json'
  before=path.read_bytes();restore._authority(ROOT,{})
  path.write_bytes(before+b' ')
  with self.assertRaisesRegex(ValueError,'historical_proof_changed'):restore._authority(ROOT,{})
  path.write_bytes(before)
  current=ROOT/'.runtime/parity-evidence'/restore.CAPSULE/'result-0.private'
  value=json.loads(current.read_bytes());value['closingGuardsVerified']=False
  current.write_bytes(json.dumps(value).encode());restore.CURRENT_RECEIPT=digest(current.read_bytes())
  with self.assertRaisesRegex(ValueError,'current_proof_changed'):restore._authority(ROOT,{})
  self.assertEqual(1,production._authority.__code__.co_consts.count(old))
  self.assertFalse(restore._syntheticRetirementDigestBinding['nativeAuthority'])

 def test_legacy_observer_trigger_precedes_companion_deletes(self):
  self.assertEqual(('put','http_proxy',':0'),restore._FIXED_RESTORE[0])
  self.assertEqual([('delete',key,None) for key in ('global_http_proxy_host','global_http_proxy_port','global_http_proxy_pac','http_proxy')],list(restore._FIXED_RESTORE[1:]))
 def scope(self):
  env,_=probes.scope();binding={'correlationId':CORRELATION,'action':'probe','sourceSha256':'a'*64,'authority':{'historical':'inert','componentBackend':{'backendSourceSha256':restore.COMPONENT_SOURCE}},'deviceStageGeneration':{'directory':probes.PARENT,'file':probes.FILE,'sha256':restore.DEX_SHA},'stageFence':{}}
  env['PROBE']['correlationId']=restore.PROBE_CORRELATION;env['RESTORE_CLOSING']=False;env['RESTORE_DEADLINE']=float('inf')
  exec(restore._REMOTE.replace('__RESTORE__',repr(binding)).replace('__STEPS__',repr(restore._FIXED_RESTORE)),env);return env
 def test_direct_companion_writes_leave_cache_owned_causal_red(self):
  model=Device()
  model.rows.update(global_http_proxy_host='',global_http_proxy_port='0',global_http_proxy_pac='',global_http_proxy_exclusion_list='')
  self.assertEqual('owned',model.kind)
  env=self.scope();model.read(env,{'mode':'restore-effect-0','command':env['restore_fixed_step'](0)})
  self.assertEqual('clear',model.kind)
 def test_all_five_row_presence_and_strict_binder_schema(self):
  env=self.scope();census={'settings':{'values':dict(env['RESTORE_OWNED']),'rows':{'http_proxy':'null'}},'kind':'owned'}
  with self.assertRaisesRegex(ValueError,'restore_proxy_changed'):env['restore_expected'](census,dict(env['RESTORE_OWNED']),'owned',['http_proxy'])
  for field,value in (('schema',True),('uid',True)):
   data=probes.getter_value();data['correlationId']=restore.PROBE_CORRELATION;data[field]=value
   with self.assertRaises(ValueError):env['parse_probe_current'](probes.reply(json.dumps(data).encode()))
  with self.assertRaisesRegex(ValueError,'restore_settings_schema_changed'):env['restore_settings'](probes.reply(b'http_proxy=null\nhttp_proxy=null\n'))
 def full(self,device=None,failure=None,actual_reader=False,actual_component=False,arm_shape=False,prepared_override=None):
  self.assertTrue((ROOT/'.runtime/parity-evidence'/restore.CAPSULE/'result-0.private').exists(),'owned synthetic historical fixture is incomplete')
  if prepared_override is not None:prepared=prepared_override
  elif arm_shape:
   # ROOT is this test's owned TempFS. Keep the actual O_EXCL ledger
   # and every downstream source/FD guard in that same namespace.
   if not hasattr(self,'_unit_arm_prepared'):
    self._unit_arm_prepared=restore.prepare(ROOT,products.CompositionTests().reservation(),CORRELATION,'arm')
   prepared=self._unit_arm_prepared
   restore.guard_prepared(prepared)
  else:prepared=restore.prepare(ROOT,products.CompositionTests().reservation(),CORRELATION)
  tree=ast.parse(prepared['program'])
  for index in range(len(tree.body)-1,-1,-1):
   text=ast.unparse(tree.body[index])
   if text.startswith('_failed = read_fixed('):tree.body.insert(index,ast.parse('HOST_HISTORY(globals())').body[0])
   elif text=='alias_history_guard()':tree.body.insert(index,ast.parse('alias_history_guard=HOST_ALIAS').body[0])
  tree.body.insert(-1,ast.parse('HOST_INSTALL(globals())').body[0]);self.assertEqual('coldboot_dispatch()',ast.unparse(tree.body[-1]))
  model=device or Device();tmp=tempfile.TemporaryDirectory();shared=Path(tmp.name)/'shared';shared.mkdir(mode=0o700)
  adb=shared/'adb';adb.write_bytes(b'harmless fixed reader fixture');adb.chmod(0o700);reader_launches=[]
  directory=shared/('android-avd-coldboot-'+restore.current.admission.original.CORRELATION);probes.journal(directory)
  lock=shared/'android-avd-coldboot-api35.lock';lock.write_bytes(b'');lock.chmod(0o600)
  proxy,Directory,fp=probes.fake_root_os();Directory(shared);original=Directory(directory)
  old_fstat=proxy.fstat;old_stat=proxy.stat;shared_ino=shared.stat().st_ino
  def principal(info):
   if info.st_ino==shared_ino:info.st_uid=1000;info.st_gid=1000
   return info
  proxy.fstat=lambda fd:principal(old_fstat(fd));proxy.stat=lambda *a,**k:principal(old_stat(*a,**k))
  def parents(path):
   parent=path.parent;fd=os.open(parent,os.O_RDONLY);return ([{'fd':fd,'pin':fp(proxy.fstat(fd)),'path':parent}],path.name)
  def guards(chain):
   for item in chain:
    self.assertEqual(item['pin'],fp(proxy.fstat(item['fd'])));self.assertEqual(item['pin'],fp(proxy.stat(item['path'])))
  old=self.scope();old.update(os=proxy,fp=fp,parent_fds=parents,guard_parents=guards,close_parents=lambda c:[os.close(i['fd']) for i in c]);fence=old['probe_fence'](original);self.original_stage_fence=fence
  class Shared:
   def __truediv__(self,name):return original if name==directory.name else shared/name
  emitted=[];action=['arm'];public_calls=[0];arm_pin=[None];readmission_pin=[None]
  def install(ns):
   self.generated_namespace=ns
   env=self.scope();ns.update({key:env[key] for key in ('getter_stage','getter_generation','getter_apk','getter_cli','getter_envelope') if key!='getter_cli' or not actual_component})
   ns['RESTORE']['stageFence']=fence;ns['RESTORE']['action']=action[0]
   if arm_pin[0] is not None:ns['RESTORE']['armPin']=arm_pin[0]
   if action[0].startswith('readmission-'):
    ns['RESTORE']['readmission']={'correlationId':'836d2aa6-1d27-4554-a70a-32c4bf49e39d','sourceSha256':ns['RESTORE']['sourceSha256'],'originalCorrelationId':CORRELATION,'originalArmPin':arm_pin[0],'originalOutcome':'unknown','replayAllowed':False}
    if readmission_pin[0] is not None:ns['RESTORE']['readmissionPin']=readmission_pin[0]

   if actual_reader:
    # Keep the ACTUAL inherited reader. Only its external launch is inert;
    # FD/source guards and initial record append are executed unchanged.
    ns['LAUNCH']['adbPath']=str(adb);ns['LAUNCH']['adbFacts']['generation']=fp(proxy.stat(adb))
    frozen_reader=ns['probe_read'];transport=types.SimpleNamespace(**vars(ns['subprocess']))
    def popen(*args,**kwargs):reader_launches.append('attempt');raise ValueError('fixture_transport_stop')
    transport.Popen=popen;ns['subprocess']=transport
   else:frozen_reader=lambda case:model.read(ns,case)
   if actual_component:
    ns['LAUNCH']['adbPath']=str(adb);ns['LAUNCH']['adbFacts']['generation']=fp(proxy.stat(adb))
    # Execute the installed component_cli AND its actual frozen PIPE capture
    # body. Only device/JDK filesystem readers and the executable boundary
    # are inert; receipts are produced by real subprocess streams/EOF/wait.
    import subprocess,sys
    generated_cli_original=ns['getter_cli']
    def generated_cli(*args):
     try:return generated_cli_original(*args)
     except Exception as error:ns['GETTER_RECORDS']['inertBackendFailure']=str(error);raise
    transport=types.SimpleNamespace(**vars(ns['subprocess']))
    envelope=env['getter_cli'](['status'],ns['FD_OWNER'])['stdout']
    def popen(argv,**kwargs):
     self.assertIn(argv[-1],('status','list'));payload=json.dumps(envelope)
     code='import sys;sys.stdout.write('+repr(payload)+'+"\\n")'
     if failure=='actual-stderr':code+=';sys.stderr.write('+repr('pure virtual method called\nterminate called without an active exception\n')+')'
     kwargs.pop('preexec_fn',None);kwargs['executable']=sys.executable;kwargs['env']={k:v for k,v in os.environ.items() if k!='DYLD_INSERT_LIBRARIES'}
     return subprocess.Popen([sys.executable,'-I','-c',code],**kwargs)
    transport.Popen=popen;ns['subprocess']=transport;ns['external_jdk_guard']=lambda:None
    def binary(path,expected,args,environment,limit=1048576):
     fd=os.open(adb,os.O_RDONLY)
     try:return ns['getter_bounded']([str(path),*args],fd,environment,limit=limit)
     finally:os.close(fd)
    ns['getter_binary']=binary
   original_cli=ns['getter_cli']
   def cli(*args):
    value=original_cli(*args);value.setdefault('stderrRaw','');value.update(captureComplete=True,componentRuntime='EXTERNAL_JDK',backendSourceSha256=restore.COMPONENT_SOURCE,installedLauncherAccepted=False,bundledRuntimeAccepted=False);public_calls[0]+=1
    if failure=='stderr':value['stderrRaw']='pure virtual method called\nterminate called without an active exception\n'
    if failure=='returncode-bool':value['returncode']=False
    if failure=='incomplete':value['captureComplete']=False
    if failure=='owner' and public_calls[0]>8:value['stdout']['controllerId']='foreign'
    return value
   ns.update(ROOT=Shared(),os=proxy,fp=fp,parent_fds=parents,guard_parents=guards,close_parents=lambda c:[os.close(i['fd']) for i in c],journal_read=lambda *args:ns['LAUNCH']['intent'],probe_read=frozen_reader,getter_cli=generated_cli if actual_component else cli,print=lambda line:emitted.append(json.loads(line)))
  bindings={'HOST_INSTALL':install,'HOST_HISTORY':lambda ns:ns.update(read_fixed=lambda *args:{**ns['CFG']['failedCensus']['pin'],'raw':b''}),'HOST_ALIAS':lambda:None}
  def execute(selected):
   action[0]=selected;emitted.clear();exec(compile(ast.fix_missing_locations(tree),'<actual-restore-prefix-and-tail>','exec'),dict(bindings));self.assertEqual(1,len(emitted))
   if selected=='arm' and emitted[0]['state']=='restore-armed':arm_pin[0]={key:emitted[0]['result']['record'][key] for key in ('generation','sha256')}
   if selected=='readmission-admit' and emitted[0]['state']=='restore-readmission-admitted':readmission_pin[0]={key:emitted[0]['result']['record'][key] for key in ('generation','sha256')}
   return emitted[0]
  return tmp,model,directory,execute
 def test_actual_prepare_arm_generation_survives_json_record_roundtrip(self):
  tmp,device,directory,execute=self.full(arm_shape=True)
  try:
   result=execute('arm')
   self.assertEqual('restore-armed',result['state'],result['reason'])
   record=result['result']['record']
   self.assertIs(type(record['value']['binding']['localIntentPin']['generation']),list)
   self.assertEqual([],device.effects)
   self.assertFalse((directory/('proxy-restore-'+CORRELATION)/'effect-fence.json').exists())
  finally:tmp.cleanup()
 def test_complete_generated_arm_effect_final_status_and_no_replay(self):
  tmp,device,directory,execute=self.full()
  try:
   arm=execute('arm');self.assertEqual('restore-armed',arm['state']);self.assertEqual([],device.effects)
   result=execute('restore');self.assertEqual('owned-proxy-restored',result['state'],result['reason']);self.assertEqual(5,len(device.effects));self.assertTrue(result['closingGuardsVerified']);self.assertFalse(result['acceptanceComplete'])
   self.assertEqual({'global_http_proxy_exclusion_list':''},device.rows);self.assertEqual('clear',device.kind)
   repeated=execute('restore');self.assertEqual('unknown',repeated['state']);self.assertEqual(5,len(device.effects))
   self.assertEqual('owned-proxy-restored',execute('status')['state'])
   (directory/('proxy-restore-'+CORRELATION)/'foreign').write_bytes(b'foreign')
   self.assertEqual('unknown',execute('status')['state'])
  finally:tmp.cleanup()
 def test_interrupted_arm_metadata_read_only_and_effect_absence(self):
  tmp,device,directory,execute=self.full(arm_shape=True)
  try:
   self.assertEqual('restore-armed',execute('arm')['state'])
   journal=directory/('proxy-restore-'+CORRELATION);before=restore.availability._snapshot(journal/'arm.json')
   result=execute('metadata')
   self.assertEqual('arm-metadata-observed',result['state'],result['reason'])
   self.assertTrue(result['result']['effectFenceAbsent']);self.assertTrue(result['result']['terminalAbsent'])
   self.assertFalse(result['result']['readmissionGranted']);self.assertEqual('unknown',result['result']['originalOutcome'])
   self.assertEqual(before,restore.availability._snapshot(journal/'arm.json'));self.assertEqual([],device.effects)
   (journal/'effect-fence.json').write_bytes(b'unknown effect');(journal/'effect-fence.json').chmod(0o600)
   self.assertEqual('unknown',execute('metadata')['state']);self.assertEqual([],device.effects)
  finally:tmp.cleanup()
 def test_fixed_interrupted_metadata_factory_source_and_local_binding(self):
  reservation=products.CompositionTests().reservation();prepared=restore.arm_metadata(ROOT,reservation)
  self.assertEqual('metadata',prepared['restoreAction'])
  self.assertEqual(restore._INTERRUPTED,prepared['restoreBinding']['correlationId'])
  self.assertEqual(restore._INTERRUPTED_SOURCE,prepared['restoreBinding']['sourceSha256'])
  self.assertIs(type(prepared['restoreBinding']['authority']['localIntentPin']['generation']),list)
  self.assertNotIn('armPin',prepared['restoreBinding'])
  original=restore.availability._snapshot
  def drift(path):
   pin,raw=original(path)
   if str(path).endswith(restore._INTERRUPTED_CAPSULE+'/arm-program.py'):raw+=b'\n'
   return pin,raw
  with mock.patch.object(restore.availability,'_snapshot',side_effect=drift),self.assertRaisesRegex(ValueError,'restore_interrupted_source_changed'):
   restore.arm_metadata(ROOT,reservation)
 def test_generated_readmission_existing_arm_one_effect_fence_no_old_adoption(self):
  tmp,device,directory,execute=self.full(arm_shape=True)
  try:
   self.assertEqual('restore-armed',execute('arm')['state'])
   journal=directory/('proxy-restore-'+CORRELATION);original=restore.availability._snapshot(journal/'arm.json')
   admission=execute('readmission-admit');self.assertEqual('restore-readmission-admitted',admission['state'],admission['reason']);self.assertEqual([],device.effects)
   self.assertEqual('unknown',execute('restore')['state']);self.assertEqual([],device.effects)
   result=execute('readmission-restore');self.assertEqual('owned-proxy-restored',result['state'],result['reason']);self.assertEqual(5,len(device.effects))
   self.assertEqual('owned-proxy-restored',execute('readmission-status')['state'])
   self.assertEqual('unknown',execute('readmission-restore')['state']);self.assertEqual(5,len(device.effects))
   self.assertEqual(original,restore.availability._snapshot(journal/'arm.json'))
  finally:tmp.cleanup()
 def test_generated_readmission_lost_effect_retains_unknown_no_replay(self):
  device=Device();device.lose=0;tmp,device,directory,execute=self.full(device,arm_shape=True)
  try:
   self.assertEqual('restore-armed',execute('arm')['state']);self.assertEqual('restore-readmission-admitted',execute('readmission-admit')['state'])
   self.assertEqual('unknown',execute('readmission-restore')['state']);self.assertEqual(1,len(device.effects))
   self.assertEqual('unknown',execute('readmission-restore')['state']);self.assertEqual(1,len(device.effects))
   self.assertEqual('unknown',execute('readmission-status')['state'])
  finally:tmp.cleanup()
 def test_readmission_arm_drift_and_second_admission_never_effect(self):
  for mutate in (False,True):
   tmp,device,directory,execute=self.full(arm_shape=True)
   try:
    self.assertEqual('restore-armed',execute('arm')['state']);self.assertEqual('restore-readmission-admitted',execute('readmission-admit')['state'])
    self.assertEqual('unknown',execute('readmission-admit')['state'])
    if mutate:
     path=directory/('proxy-restore-'+CORRELATION)/'arm.json';value=json.loads(path.read_bytes());value['sourceSha256']='b'*64;path.write_text(json.dumps(value));path.chmod(0o600)
     self.assertEqual('unknown',execute('readmission-restore')['state']);self.assertEqual([],device.effects)
   finally:tmp.cleanup()
 def test_actual_readmission_factories_local_fd_admit_retain_and_single_fence(self):
  reservation=products.CompositionTests().reservation();operation='786b7ea9-31ee-4921-95f7-ae065ecfaad1';writer=restore._write_local;snapshot=restore.availability._snapshot
  with tempfile.TemporaryDirectory() as local_tmp:
   scope=ROOT/'.rag_index'/('android-api35-proxy-readmission-'+restore._INTERRUPTED)/operation
   def mapped(path):
    return scope/Path(path).name if ('android-api35-proxy-readmission-'+restore._INTERRUPTED) in str(path) else Path(path)
   def write(path,value,prepared):return writer(mapped(path),value,prepared)
   def snap(path):return snapshot(mapped(path))
   with mock.patch.object(restore,'_write_local',side_effect=write),mock.patch.object(restore.availability,'_snapshot',side_effect=snap):
    admitted=restore.readmission_admit(ROOT,reservation,operation);binding=admitted['restoreBinding'];intent=snapshot(scope/'intent.json')
    self.assertIs(type(binding['readmission']['localIntentPin']['generation']),list)
    self.assertEqual('readmission-admit',binding['action']);self.assertFalse((scope/'effect-fence.json').exists())
    # Actual generated remote journal writer, real held/named FDs and JSON
    # roundtrip; only root principal and private device directory are inert.
    env=self.scope();proxy,Directory,fp=probes.fake_root_os();journal=Path(local_tmp)/'remote';journal.mkdir(mode=0o700);Directory(journal)
    def parents(path):
     fd=os.open(path.parent,os.O_RDONLY);return ([{'fd':fd,'pin':fp(proxy.fstat(fd)),'path':path.parent}],path.name)
    def guards(chain):
     for item in chain:self.assertEqual(item['pin'],fp(proxy.fstat(item['fd'])));self.assertEqual(item['pin'],fp(proxy.stat(item['path'])))
    env.update(os=proxy,fp=fp,parent_fds=parents,guard_parents=guards,close_parents=lambda c:[os.close(x['fd']) for x in c],restore_journal=lambda directory:journal)
    body={'schema':1,'operation':binding['readmission'],'originalArmPin':binding['readmission']['originalArmPin'],'originalOutcome':'unknown','replayAllowed':False}
    record=env['restore_record'](journal,'readmission.json',body)
    raw=json.dumps({'state':'restore-readmission-admitted','closingGuardsVerified':True,'correlationId':restore._INTERRUPTED,'historicalUnknownsPreserved':True,'replayAllowed':False,'result':{'record':record}}).encode()
    restore.retain_readmission(ROOT,admitted,raw)
    restored=restore.readmission_restore_once(ROOT,reservation,operation);self.assertEqual('readmission-restore',restored['restoreAction'])
    self.assertTrue((scope/'effect-fence.json').is_file());self.assertEqual(intent,snapshot(scope/'intent.json'))
    with self.assertRaises(FileExistsError):restore.readmission_restore_once(ROOT,reservation,operation)
    status=restore.readmission_status(ROOT,reservation,operation);self.assertEqual('readmission-status',status['restoreAction'])
    with self.assertRaises(FileExistsError):restore.readmission_admit(ROOT,reservation,operation)
 def test_lost_response_keeps_fence_partial_raw_and_does_not_resume(self):
  device=Device();device.lose=0;tmp,device,directory,execute=self.full(device)
  try:
   self.assertEqual('restore-armed',execute('arm')['state']);first=execute('restore');self.assertEqual('unknown',first['state']);self.assertIn('lostEffect',first['records']);self.assertTrue(first['closingGuardsVerified'])
   self.assertTrue((directory/('proxy-restore-'+CORRELATION)/'effect-fence.json').exists());self.assertFalse((directory/('proxy-restore-'+CORRELATION)/'terminal.json').exists())
   self.assertEqual('unknown',execute('restore')['state']);self.assertEqual(1,len(device.effects));self.assertEqual('unknown',execute('status')['state'])
  finally:tmp.cleanup()
 def test_trigger_not_observed_and_foreign_drift_never_delete(self):
  for mode in ('no-trigger','foreign','owner'):
   device=Device();device.trigger=mode!='no-trigger';tmp,device,directory,execute=self.full(device,'owner' if mode=='owner' else None)
   try:
    arm=execute('arm')
    if mode=='foreign':device.foreign='foreign.example'
    result=execute('restore');self.assertEqual('unknown',result['state']);self.assertLessEqual(len(device.effects),1)
   finally:tmp.cleanup()
 def test_local_fd_fence_real_create_partial_and_symlink_scope(self):
  source=restore.availability._snapshot(Path(coldboot.__file__).absolute());prepared={'snapshots':{Path(coldboot.__file__).absolute():source}}
  with tempfile.TemporaryDirectory() as tmp:
   path=Path(tmp).resolve()/'.rag_index/android-api35-owned-proxy-restore'/CORRELATION/'intent.json'
   restore._write_local(path,{'authority':'fixed'},prepared);self.assertEqual({'authority':'fixed'},json.loads(path.read_bytes()));self.assertEqual(0o600,stat.S_IMODE(path.stat().st_mode));self.assertEqual(0o700,stat.S_IMODE(path.parent.stat().st_mode))
   with self.assertRaises(FileExistsError):restore._write_local(path,{'authority':'fixed'},prepared)
   effect=path.with_name('effect-fence.json')
   with mock.patch.object(restore.os,'write',side_effect=OSError('lost write')),self.assertRaises(OSError):restore._write_local(effect,{},prepared)
   with self.assertRaises(FileExistsError):restore._write_local(effect,{},prepared)
  with tempfile.TemporaryDirectory() as tmp:
   parent=Path(tmp).resolve()/'.rag_index';parent.symlink_to(Path(tmp))
   with self.assertRaises(OSError):restore._write_local(parent/'android-api35-owned-proxy-restore'/CORRELATION/'intent.json',{},prepared)
 def test_consistent_source_drift_before_dependency_factory(self):
  original=restore.availability._snapshot
  def drift(path):
   pin,raw=original(path)
   if Path(path)==Path(restore.current.__file__).absolute():raw+=b'\n'
   return pin,raw
  with mock.patch.object(restore.availability,'_snapshot',side_effect=drift),mock.patch.object(restore.current,'prepare') as factory:
   with self.assertRaisesRegex(ValueError,'current_source_changed'):restore.prepare(ROOT,{},CORRELATION)
   factory.assert_not_called()
  with self.assertRaisesRegex(ValueError,'restore_prepared_required'):restore.restore_carrier({'preEffectGuard':'/system/bin/app_process injected'})

 def test_actual_settings_filter_shell_read_only_and_fixed_mutations(self):
  import subprocess
  env=self.scope()
  with tempfile.TemporaryDirectory() as tmp:
   settings=Path(tmp)/'settings';settings.write_text('#!/bin/sh\nprintf "%s\\n" "unrelated=x" "http_proxy=null" "global_http_proxy_host=127.0.0.1" "global_http_proxy_port=45635" "global_http_proxy_pac=null" "global_http_proxy_exclusion_list="\n');settings.chmod(0o700)
   command=env['restore_settings_command']().replace('/system/bin/id','/usr/bin/id').replace('= 2000','= '+str(os.getuid())).replace('/system/bin/settings',shlex.quote(str(settings)))
   result=subprocess.run(['sh','-c',command],capture_output=True,timeout=5);self.assertEqual(0,result.returncode,result.stderr)
   parsed=env['restore_settings'](probes.reply(result.stdout));self.assertEqual(env['RESTORE_OWNED'],parsed['values']);self.assertEqual(5,len(parsed['rows']))
  for index,(op,key,value) in enumerate(restore._FIXED_RESTORE):
   words=shlex.split(env['restore_fixed_step'](index).split('/system/bin/settings ',1)[1]);self.assertEqual([op,'global',key]+([] if value is None else [value]),words)
  for bad in (True,-1,5,'0'):
   with self.assertRaises(ValueError):env['restore_fixed_step'](bad)
 def test_terminal_corruption_and_original_history_drift_never_promote(self):
  tmp,model,directory,execute=self.full()
  try:
   self.assertEqual('restore-armed',execute('arm')['state']);self.assertEqual('owned-proxy-restored',execute('restore')['state'])
   path=directory/('proxy-restore-'+CORRELATION)/'terminal.json';value=json.loads(path.read_bytes());value['schema']=True;path.write_text(json.dumps(value));self.assertEqual('unknown',execute('status')['state']);self.assertEqual(5,len(model.effects))
   (directory/'ready.json').write_bytes(b'foreign')
   self.assertEqual('unknown',execute('status')['state'])
  finally:tmp.cleanup()
 def test_native_arm_retention_strict_schema_hash_and_create_only(self):
  source=restore.availability._snapshot(Path(coldboot.__file__).absolute());authority={'fixed':'authority'};content={'binding':authority,'correlationId':CORRELATION,'sourceSha256':'a'*64,'schema':1};raw=(json.dumps(content,sort_keys=True,separators=(',',':'))+'\n').encode();pin=[1,2,len(raw),3,4,stat.S_IFREG|0o600,0,0,1]
  reply={'state':'restore-armed','closingGuardsVerified':True,'correlationId':CORRELATION,'historicalUnknownsPreserved':True,'replayAllowed':False,'result':{'record':{'value':content,'generation':pin,'sha256':hashlib.sha256(raw).hexdigest()}}}
  prepared={'restoreAction':'arm','restoreBinding':{'authority':authority,'correlationId':CORRELATION,'sourceSha256':'a'*64},'snapshots':{Path(coldboot.__file__).absolute():source}}
  with tempfile.TemporaryDirectory() as tmp,mock.patch.object(restore,'guard_prepared'):
   root=Path(tmp).resolve();restore._write_local(root/'.rag_index/android-api35-owned-proxy-restore'/CORRELATION/'intent.json',authority,prepared)
   for kind in ('schema','pin','hash','closing'):
    bad=json.loads(json.dumps(reply))
    if kind=='schema':bad['result']['record']['value']['schema']=True
    elif kind=='pin':bad['result']['record']['generation'][0]=True
    elif kind=='hash':bad['result']['record']['sha256']='b'*64
    else:bad['closingGuardsVerified']=1
    with self.assertRaises(ValueError):restore.retain_arm(root,prepared,json.dumps(bad).encode())
   snapshot=restore.retain_arm(root,prepared,json.dumps(reply).encode());self.assertEqual(hashlib.sha256(json.dumps(reply).encode()).hexdigest(),json.loads(snapshot[1])['responseSha256'])
   with self.assertRaises(FileExistsError):restore.retain_arm(root,prepared,json.dumps(reply).encode())

 def test_actual_composed_frozen_reader_has_initialized_capture_before_launch(self):
  tmp,model,directory,execute=self.full(actual_reader=True)
  try:
   result=execute('probe')
   # One primary read + its closing guard. Both execute the actual reader's
   # capture append BEFORE the deliberately stopped external subprocess.
   self.assertIn('shellFdReads',result['records'])
   self.assertEqual(2,len(result['records']['shellFdReads']))
   self.assertEqual([],model.effects)
   for record in result['records']['shellFdReads']:
    self.assertEqual('restore-dex-generation',record['mode']);self.assertIsNone(record['exitCode']);self.assertFalse(record['captureComplete'])
  finally:tmp.cleanup()

 def test_actual_composition_rejects_measured_launcher_stderr_and_bool_exit_before_reader(self):
  for failure in ('stderr','returncode-bool','incomplete'):
   tmp,model,directory,execute=self.full(failure=failure,actual_reader=True)
   try:
    result=execute('probe');self.assertEqual('unknown',result['state']);self.assertFalse(result['closingGuardsVerified']);self.assertEqual([],model.effects)
    self.assertEqual([],result['records']['shellFdReads'])
   finally:tmp.cleanup()

 def test_complete_composed_flow_uses_actual_component_pipe_capture_body(self):
  tmp,model,directory,execute=self.full(actual_component=True)
  try:
   arm=execute('arm');self.assertEqual('restore-armed',arm['state'],arm['reason']);self.assertTrue(arm['records']['captures'])
   result=execute('restore');self.assertEqual('owned-proxy-restored',result['state'],result['reason']);self.assertEqual(5,len(model.effects))
   status=execute('status');self.assertEqual('owned-proxy-restored',status['state'],status['reason'])
   for response in (arm,result,status):
    for capture in response['records']['captures']:
     self.assertEqual(0,capture['returncode']);self.assertIsNone(capture['failure']);self.assertEqual('',capture['stderrBase64']);self.assertGreater(capture['stdoutBytes'],0)
    for record in response['records']['restorePublic']:
     self.assertIs(True,record['captureComplete']);self.assertEqual('EXTERNAL_JDK',record['componentRuntime']);self.assertFalse(record['installedLauncherAccepted']);self.assertEqual(restore.COMPONENT_SOURCE,record['backendSourceSha256'])
  finally:tmp.cleanup()
 def test_actual_component_stderr_capture_is_retained_and_cannot_arm(self):
  tmp,model,directory,execute=self.full(failure='actual-stderr',actual_component=True)
  try:
   result=execute('arm');self.assertEqual('unknown',result['state']);self.assertFalse(result['closingGuardsVerified']);self.assertEqual([],model.effects)
   self.assertTrue(result['records']['captures']);self.assertTrue(all(item['stderrBytes']==72 for item in result['records']['captures']))
   self.assertFalse((directory/('proxy-restore-'+CORRELATION)).exists())
  finally:tmp.cleanup()
 def test_shared_backend_drift_is_rejected_before_its_factory(self):
  source=restore.availability._snapshot
  def drift(path):
   pin,raw=source(path)
   if Path(path)==Path(restore.component.__file__).absolute():raw+=b'\n'
   return pin,raw
  with mock.patch.object(restore.availability,'_snapshot',side_effect=drift),mock.patch.object(restore.component,'prepare_binding') as factory:
   with self.assertRaisesRegex(ValueError,'restore_backend_source_changed'):restore.prepare(ROOT,products.CompositionTests().reservation(),CORRELATION)
   factory.assert_not_called()
