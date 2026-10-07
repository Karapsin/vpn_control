"""Current epoch admission rejects old uncertain effects and retains its own ledger."""
import ast,copy,hashlib,json,os,stat,tempfile,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import android_api29_current_epoch_diagnostics as epoch
from agent_tools.tests import test_android_api29_current_permission_diagnostics as prior
ROOT=Path(__file__).resolve().parents[2]
from agent_tools.tests.fixtures.android_api29_epoch.context import Context, SOURCE_SHA, BASE, PROVENANCE_SHA
from agent_tools.tests.fixtures import historical_source
CORR='4c98a7f0-2e86-41de-bc1b-41a2e8e292e8'

def binding():
 value=prior.binding();value['correlationId']=CORR;value['requestId']=str(uuid.uuid5(uuid.UUID(CORR),'api29-owned-diagnostics-export'));value['controllerId']=epoch.OWNER
 request=json.loads(value['requestBytes']);request.update(controllerId=epoch.OWNER,requestId=value['requestId']);value['requestBytes']=json.dumps(request,sort_keys=True,separators=(',',':'));return value

def scope():
 env=prior.prior.scope();program='PERMISSION_OWNER='+repr(epoch.OWNER)+'\n'+epoch.old._REMOTE.replace('__DIAGNOSTIC__',repr(binding()))+'\ndef coldboot_dispatch():pass\ncoldboot_dispatch()\n'
 exec(epoch.compose(program,binding()),env);ledger=[];calls=[]
 terminal={'ok':True,'final':True,'code':'OK','requestId':binding()['requestId'],'controllerId':epoch.OWNER,'configurationRevision':0,'operationId':prior.OP,'restartRequired':False,'warnings':[],'data':{'content':'[runtime]\nmode=VPN\nvpn_permission_granted=false\nis_vpn_running=false\n'}}
 def cli(words,owner=None):
  calls.append(('public',words));value={'runtimeRunning':False,'runtimeObservation':'stopped','configuredMode':'vpn','operations':copy.deepcopy(ledger) if words==['operations','list'] else []}
  if words[:2]==['operations','status']:return {'returncode':0,'stdout':{**copy.deepcopy(terminal),'requestId':'new-status-request','data':{}}}
  return {'returncode':0,'stdout':{'ok':True,'final':True,'code':'OK','controllerId':epoch.OWNER,'configurationRevision':0,'data':value}}
 def adb(words,payload=None):
  calls.append((words,payload));uri=env['URI']
  if words==['call','--uri',uri,'--method','create']:return 'Result: Bundle[{id='+prior.TRANSFER+', controllerId='+epoch.OWNER+', requestUri='+uri+'/requests/'+prior.TRANSFER+', resultUri='+uri+'/results/'+prior.TRANSFER+'}]\n'
  if words==['write','--uri',uri+'/requests/'+prior.TRANSFER]:
   assert json.loads(payload)==json.loads(binding()['requestBytes']);ledger.append({'controllerId':epoch.OWNER,'id':prior.OP,'requestId':binding()['requestId'],'operation':'diagnostics.export','phase':'succeeded','final':True,'cancellable':False,'completedUnits':None,'totalUnits':None,'code':'OK','configurationRevision':0,'restartRequired':False});return ''
  if words==['call','--uri',uri,'--method','status','--arg',prior.TRANSFER]:return 'Result: Bundle[{state=complete}]\n'
  if words==['read','--uri',uri+'/results/'+prior.TRANSFER]:return json.dumps(terminal)
  raise AssertionError('unexpected transport')
 env.update(epoch_old_effect_absent=lambda _:calls.append(('old-absence',None)),getter_cli=cli,diagnostic_adb=adb,diagnostic_intent_guard=lambda:None,diagnostic_fence=lambda _:([{'fd':7,'pin':[1]*9}],{'full':'intent-pin'}),diagnostic_write=lambda chain,name,value:calls.append(('durable-'+name,copy.deepcopy(value))),close_parents=lambda _:None)
 return env,ledger,calls,terminal

def old_result():
 return {'correlationId':epoch.OLD_CORRELATION,'reason':'diagnostic_public_unknown','permissionObserved':False,'intentPin':None,'ownedTerminal':None,'ownedOperation':None,'records':{'captures':[],'statusBefore':{'returncode':1,'stdout':{'ok':False,'code':'CONFLICT','controllerId':epoch.OWNER,'configurationRevision':0}}}}

class EpochTests(unittest.TestCase):
 def test_old_might_have_submitted_rejects_before_new_admission(self):
  self.assertTrue(epoch.validate_old(old_result()))
  for field,value in [('intentPin',{}),('ownedTerminal',{}),('ownedOperation',{})]:
   result=old_result();result[field]=value
   with self.assertRaisesRegex(ValueError,'epoch_old_submission_unknown'):epoch.validate_old(result)
  result=old_result();result['records']['transfer']={}
  with self.assertRaisesRegex(ValueError,'epoch_old_submission_unknown'):epoch.validate_old(result)
 def test_actual_transformed_export_one_exact_owned_ledger(self):
  env,ledger,calls,terminal=scope();result=env['observed_getter'](Path('/inert'),[])
  self.assertTrue(result['permissionObserved']);self.assertTrue(result['closingGuardsVerified']);self.assertEqual(epoch.OWNER,result['controllerId']);self.assertEqual(1,len(ledger));self.assertEqual(2,sum(c[0]=='old-absence' for c in calls));self.assertEqual(1,sum(isinstance(c[0],list) and c[0][0]=='write' for c in calls))
  self.assertFalse(result['replayAllowed']);self.assertFalse(result['runtimeMutationPerformed'])
 def test_owner_drift_before_effect_and_extra_operation_reject(self):
  env,ledger,calls,_=scope();original=env['getter_cli']
  def changed(words,owner=None):
   result=original(words,owner)
   if len([c for c in calls if c[0]=='public'])==3:result['stdout']['controllerId']='foreign'
   return result
  env['getter_cli']=changed;result=env['observed_getter'](Path('/inert'),[])
  self.assertFalse(result['permissionObserved']);self.assertTrue(result['closingGuardsVerified']);self.assertEqual([],ledger);self.assertFalse(any(isinstance(c[0],list) and c[0][0]=='call' for c in calls))
  env,ledger,calls,_=scope();export=env['diagnostic_export']
  def extra():
   value=export();ledger.append(dict(ledger[0],id=CORR));return value
  env['diagnostic_export']=extra;self.assertFalse(env['observed_getter'](Path('/inert'),[])['permissionObserved'])
 def test_consumed_remote_epoch_and_foreign_owned_terminal_never_replay(self):
  env,ledger,calls,_=scope();env['diagnostic_fence']=lambda _:(_ for _ in ()).throw(FileExistsError('consumed'))
  result=env['observed_getter'](Path('/inert'),[]);self.assertFalse(result['permissionObserved']);self.assertTrue(result['closingGuardsVerified']);self.assertEqual([],ledger);self.assertFalse(any(isinstance(c[0],list) for c in calls))
  for field,value in [('controllerId','foreign'),('requestId',CORR),('configurationRevision',False),('final',1)]:
   env,ledger,calls,terminal=scope();terminal[field]=value;result=env['observed_getter'](Path('/inert'),[]);self.assertFalse(result['permissionObserved']);self.assertFalse(result['replayAllowed'])
 def test_source_admission_before_factory(self):
  # Establish an untouched compatible factory first: mutation is causal, rather
  # than an always-failing current dependency disguised as a drift regression.
  with tempfile.TemporaryDirectory() as tmp:
   context=Context(Path(tmp),old_result());prepared=context.prepare(CORR)
   self.assertEqual(SOURCE_SHA,prepared['ownedDiagnostic']['componentBinding']['backendSourceSha256'])
   actual=epoch.availability._snapshot
   def changed(path):
    pin,raw=actual(path);return (pin,raw+b'\n') if Path(path)==Path(context.component.__file__).absolute() else (pin,raw)
   with mock.patch.object(epoch.availability,'_snapshot',side_effect=changed),mock.patch.object(context.old,'prepare') as factory:
    with self.assertRaisesRegex(ValueError,'epoch_dependency_changed'):context.prepare(CORR)
    factory.assert_not_called()
 def test_current_incompatible_source_refuses_before_upstream_history(self):
  # Production constants and current source are untouched; no private read.
  with tempfile.TemporaryDirectory() as tmp,mock.patch.object(epoch.old,'prepare') as factory:
   with self.assertRaisesRegex(ValueError,'epoch_dependency_changed'):epoch.prepare(Path(tmp),{},CORR)
   factory.assert_not_called()
 def test_exact_public_history_provenance_and_synthetic_protocol_label(self):
  self.assertEqual(PROVENANCE_SHA,hashlib.sha256((BASE/'provenance.json').read_bytes()).hexdigest())
  provenance=json.loads((BASE/'provenance.json').read_bytes())
  self.assertFalse(provenance['executionAuthority']);self.assertFalse(provenance['nativePayloadIncluded'])
  module=historical_source.load(BASE/'component.source',SOURCE_SHA)
  historical_source.verify(module,BASE/'component.source',SOURCE_SHA)
  with tempfile.TemporaryDirectory() as tmp:
   changed=Path(tmp)/'component.source';changed.write_bytes((BASE/'component.source').read_bytes()+b'\n')
   with self.assertRaisesRegex(ValueError,'historical_source_binding_changed'):historical_source.load(changed,SOURCE_SHA)
  with tempfile.TemporaryDirectory() as tmp:
   context=Context(Path(tmp),old_result());p=context.prepare(CORR)
   self.assertNotEqual(epoch.RESULT_SHA,context.epoch.RESULT_SHA)
   self.assertEqual(context.epoch.RESULT_SHA,p['ownedDiagnostic']['oldEffectProof']['resultSha256'])
   context.write(context.epoch.RESULT,dict(old_result(),permissionObserved=True))
   with self.assertRaisesRegex(ValueError,'component_source_changed'):context.component.guard(p)
 def test_unknown_submit_retains_terminal_and_all_closing_guards(self):
  env,_,calls,_=scope();env['diagnostic_export']=lambda:(_ for _ in ()).throw(ValueError('diagnostic_command_timeout'))
  result=env['observed_getter'](Path('/inert'),[]);self.assertTrue(result['closingGuardsVerified']);self.assertFalse(result['permissionObserved']);self.assertFalse(result['replayAllowed']);self.assertEqual('durable-terminal.json',calls[-1][0])

@unittest.skipUnless(os.name=='posix','descriptor-relative POSIX epoch fences')
class EpochFenceTests(unittest.TestCase):
 def test_old_remote_directory_or_symlink_rejects_positive_absence_gate(self):
  env,_,_,_=scope();exec(epoch._EPOCH_REMOTE,env)
  with tempfile.TemporaryDirectory() as tmp:
   fd=os.open(tmp,os.O_RDONLY|os.O_DIRECTORY);env.update(os=os,guard_parents=lambda _:None)
   try:
    env['epoch_old_effect_absent']([{'fd':fd}]);path=Path(tmp)/('android-api29-owned-diagnostics-'+epoch.BOOT);path.mkdir()
    with self.assertRaisesRegex(ValueError,'diagnostic_old_remote_effect_unknown'):env['epoch_old_effect_absent']([{'fd':fd}])
    path.rmdir();path.symlink_to('/missing')
    with self.assertRaisesRegex(ValueError,'diagnostic_old_remote_effect_unknown'):env['epoch_old_effect_absent']([{'fd':fd}])
   finally:os.close(fd)
 def test_new_uuid_never_bypasses_same_owner_once_fence_raw_retained(self):
  def prepared(root):return {'diagnosticRoot':root,'ownedDiagnostic':binding(),'program':'fixed','diagnosticProgramSha256':hashlib.sha256(b'fixed').hexdigest(),'snapshots':{},'armed':False}
  with tempfile.TemporaryDirectory() as tmp,mock.patch.object(epoch.historical,'guard_prepared'):
   root=Path(tmp).resolve();p=prepared(root);epoch.arm(p);self.assertEqual('consumed-unknown',epoch.status(root)['state']);other=prepared(root);other['ownedDiagnostic']['correlationId']=str(uuid.uuid4())
   with self.assertRaises(FileExistsError):epoch.arm(other)
   epoch.retain(p,b'partial-submit',b'unknown',None);self.assertEqual('consumed-recorded',epoch.status(root)['state'])
   with self.assertRaisesRegex(ValueError,'diagnostic_local_consumed'):epoch.guard_prepared(p)
   self.assertFalse((root/'.rag_index/android-api29-owned-permission-diagnostics').exists())

class HermeticFactoryCase(unittest.TestCase):
 def setUp(self):
  self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
  self.context=Context(Path(self.temporary.name),old_result())
 def prepared(self):return self.context.prepare(CORR)

class ActualFactoryTests(HermeticFactoryCase):
 def test_exact_old_history_source_binding_and_request(self):
  p=self.prepared();tree=ast.parse(p['program']);diagnostic=epoch.component._assignment(tree,'DIAGNOSTIC');request=json.loads(diagnostic['requestBytes'])
  self.assertEqual(epoch.OWNER,request['controllerId']);self.assertEqual(self.context.epoch.RESULT_SHA,diagnostic['oldEffectProof']['resultSha256']);self.assertEqual(epoch.COMPONENT_SHA,diagnostic['componentBinding']['backendSourceSha256']);self.assertEqual(15,len(p['snapshots']));self.assertIn(BASE/'component.source',p['snapshots']);self.assertIn("'android-api29-current-epoch-diagnostics-'",p['program']);self.assertIn('component_cli',p['program'])
 def test_full_prefix_dispatch_tail_source_and_own_ledger(self):
  p=self.prepared();tree=ast.parse(p['program']);emitted=[];pin=[1]*9
  for index in range(len(tree.body)-1,-1,-1):
   text=ast.unparse(tree.body[index])
   if text.startswith('_failed = read_fixed('):tree.body.insert(index,ast.parse('HOST_HISTORY(globals())').body[0])
   elif text=='alias_history_guard()':tree.body.insert(index,ast.parse('alias_history_guard=HOST_ALIAS').body[0])
  tree.body.insert(-1,ast.parse('HOST_INSTALL(globals())').body[0])
  class Directory:
   name='inert-original-journal'
   def lstat(self):return types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o700)
  class Root:
   def __truediv__(self,_):return Directory()
  def install(ns):
   env,ledger,calls,terminal=scope();proxy=types.SimpleNamespace(**vars(os));proxy.getuid=lambda:0;proxy.geteuid=lambda:0;proxy.open=lambda *a,**k:8;proxy.close=lambda _:None
   info=types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o600,st_nlink=1);rootinfo=types.SimpleNamespace(st_uid=1000,st_mode=stat.S_IFDIR|0o700);proxy.fstat=lambda fd:rootinfo if fd==7 else info;proxy.stat=lambda *a,**k:info
   ns.update({k:env[k] for k in ('getter_generation','getter_stage','getter_cli','getter_envelope','diagnostic_adb','diagnostic_fence','diagnostic_write','diagnostic_intent_guard','epoch_old_effect_absent')});ns.update(getter_apk=lambda:ns['GETTER']['packageSha256'],ROOT=Root(),os=proxy,parent_fds=lambda _:([{'fd':7,'pin':pin}],None),guard_parents=lambda _:None,close_parents=lambda _:None,fp=lambda _:pin,journal_read=lambda *a:ns['LAUNCH']['intent'],fcntl=types.SimpleNamespace(LOCK_EX=1,LOCK_NB=2,flock=lambda *a:None),print=lambda line:emitted.append(json.loads(line)))
  host={'HOST_INSTALL':install,'HOST_HISTORY':lambda ns:ns.update(read_fixed=lambda *a:{**ns['CFG']['failedCensus']['pin'],'raw':b''}),'HOST_ALIAS':lambda:None};exec(compile(ast.fix_missing_locations(tree),'<whole-owned-current-epoch>','exec'),host)
  self.assertEqual(1,len(emitted));self.assertTrue(emitted[0]['permissionObserved']);self.assertFalse(emitted[0]['acceptanceComplete'])

@unittest.skipUnless(os.name=='posix','descriptor-relative POSIX receipt custody')
class PersistedAuthorityTests(HermeticFactoryCase):
 def test_actual_prepare_arm_guard_carrier_json_roundtrip(self):
  p=self.prepared()
  with tempfile.TemporaryDirectory() as tmp:
   p['diagnosticRoot']=Path(tmp).resolve()
   self.context.epoch.arm(p)
   self.context.epoch.guard_prepared(p)
   carrier=self.context.epoch.ssh_carrier(p)
   self.assertIsNotNone(carrier)
   self.assertEqual(p['ownedDiagnostic'],json.loads(json.dumps(p['ownedDiagnostic'])))
   # Decode the real carrier without executing its receiver/device boundary.
   import base64,zlib
   packed=ast.literal_eval(ast.parse(carrier).body[0].value.args[0].args[0].args[0])
   self.assertEqual(p['program'].encode(),zlib.decompress(base64.b64decode(packed)))
   other=self.prepared();other['diagnosticRoot']=Path(tmp).resolve()
   with self.assertRaises(FileExistsError):self.context.epoch.arm(other)
   self.context.epoch.retain(p,b'partial-unknown',b'raw-error',None)
   self.assertEqual('consumed-recorded',self.context.epoch.status(Path(tmp).resolve())['state'])
   with self.assertRaisesRegex(ValueError,'diagnostic_local_consumed'):self.context.epoch.guard_prepared(p)
