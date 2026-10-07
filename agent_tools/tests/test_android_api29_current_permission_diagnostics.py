"""Actual fixed request/program and faithful production ledger tests; no guest."""
import ast,base64,copy,hashlib,json,os,stat,subprocess,tempfile,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import android_api29_current_permission_diagnostics as diagnostic
from agent_tools.tests import test_android_api29_current_permission_observation as prior
ROOT=Path(__file__).resolve().parents[2]
from agent_tools.tests.fixtures.android_api29_epoch.adjacent import AdjacentContext
CORR='39c1c234-22c9-45aa-82e0-a156acbcde23'
OP='02c2c5b3-73fb-4abd-acf5-2784889e4c2e'
TRANSFER='1c2dde23-4b12-4c67-bdd3-256ae95c23c9'

def binding():
 request={'schemaVersion':1,'requestId':str(uuid.uuid5(uuid.UUID(CORR),'api29-owned-diagnostics-export')),'controllerId':diagnostic.OWNER,'ifRevision':0,'interactive':False,'asynchronous':False,'command':{'operation':'diagnostics.export','arguments':{}}}
 return {'correlationId':CORR,'currentBootCorrelation':diagnostic.historical.original.CORRELATION,'requestId':request['requestId'],'requestBytes':json.dumps(request,sort_keys=True,separators=(',',':'))}

def runtime_scope():
 env=prior.scope();exec(diagnostic._REMOTE.replace('__DIAGNOSTIC__',repr(binding())),env)
 env['GETTER_RECORDS']={};env['DIAGNOSTIC_STATE']={};ledger=[];calls=[];terminal={'ok':True,'final':True,'code':'OK','requestId':binding()['requestId'],'controllerId':diagnostic.OWNER,'configurationRevision':0,'operationId':OP,'restartRequired':False,'warnings':['METADATA_OBSERVED_AFTER_REPORT'],'data':{'content':'[runtime]\nmode=VPN\nvpn_permission_granted=false\nis_vpn_running=false\n'}}
 env['getter_cli']=lambda words,owner=None:{'returncode':0,'stdout':{'ok':True,'final':True,'code':'OK','controllerId':diagnostic.OWNER,'configurationRevision':0,'data':{'runtimeRunning':False,'runtimeObservation':'stopped','configuredMode':'vpn','operations':copy.deepcopy(ledger) if words==['operations','list'] else []}}}
 def transport(words,payload=None):
  calls.append((words,payload));uri=env['URI']
  if words==['call','--uri',uri,'--method','create']:return 'Result: Bundle[{id='+TRANSFER+', controllerId='+diagnostic.OWNER+', requestUri='+uri+'/requests/'+TRANSFER+', resultUri='+uri+'/results/'+TRANSFER+'}]\n'
  if words==['write','--uri',uri+'/requests/'+TRANSFER]:
   request=json.loads(payload);assert request==json.loads(binding()['requestBytes'])
   ledger.append({'controllerId':diagnostic.OWNER,'id':OP,'requestId':request['requestId'],'operation':'diagnostics.export','phase':'succeeded','final':True,'cancellable':False,'completedUnits':None,'totalUnits':None,'code':'OK','configurationRevision':0,'restartRequired':False});return ''
  if words==['call','--uri',uri,'--method','status','--arg',TRANSFER]:return 'Result: Bundle[{state=complete}]\n'
  if words==['read','--uri',uri+'/results/'+TRANSFER]:return json.dumps(terminal)
  raise AssertionError('unexpected public command')
 env.update(diagnostic_intent_guard=lambda:None,diagnostic_adb=transport,diagnostic_fence=lambda _:([{'fd':7,'pin':[1]*9}],{'full':'intent-pin'}),diagnostic_write=lambda chain,name,value:calls.append(('durable-'+name,copy.deepcopy(value))),close_parents=lambda _:None,diagnostic_operation_status=lambda operation:{'returncode':0,'stdout':{**copy.deepcopy(terminal),'requestId':'new-status-request','data':{}}})
 return env,ledger,calls,terminal

class ShapeTests(unittest.TestCase):
 def test_fixed_schema_no_interaction_and_bad_identity_rejected(self):
  for value in (None,1,'../bad',CORR.upper()):
   with self.assertRaises(ValueError):diagnostic._identifier(value)
  request=json.loads(binding()['requestBytes']);self.assertEqual('diagnostics.export',request['command']['operation']);self.assertIs(request['interactive'],False);self.assertIs(request['asynchronous'],False);self.assertEqual(0,request['ifRevision'])
 def test_production_ledger_causal_old_red_new_green(self):
  env,ledger,calls,terminal=runtime_scope();result=env['observed_getter'](Path('/inert'),[])
  self.assertTrue(result['permissionObserved']);self.assertTrue(result['closingGuardsVerified']);self.assertEqual(OP,result['ownedOperation']['id']);self.assertEqual(1,len(ledger));self.assertEqual(1,sum(isinstance(c[0],list) and c[0][0]=='write' for c in calls))
  # The exact old guard fails on this same production-retained summary.
  old=prior.scope();record=env['getter_cli'](['operations','list'],diagnostic.OWNER)
  with self.assertRaisesRegex(ValueError,'permission_operations_not_empty'):old['permission_public'](record,'operations')
  for key in ('endpointAdmitted','productAdmitted','acceptanceComplete','permissionGrantPerformed','runtimeMutationPerformed','replayAllowed'):self.assertIs(result[key],False)
 def test_foreign_request_operation_owner_rev_boolean_and_extra_op_reject(self):
  for field,value in (('requestId',CORR),('operation','on'),('controllerId','foreign'),('configurationRevision',False),('phase','running'),('cancellable',0),('final',1)):
   env,ledger,calls,terminal=runtime_scope();export=env['diagnostic_export']
   def changed():
    reply=export();ledger[0][field]=value;return reply
   env['diagnostic_export']=changed;result=env['observed_getter'](Path('/inert'),[]);self.assertFalse(result['permissionObserved']);self.assertTrue(result['closingGuardsVerified'])
  env,ledger,calls,terminal=runtime_scope();export=env['diagnostic_export']
  def extra():
   value=export();ledger.append(dict(ledger[0],id=CORR));return value
  env['diagnostic_export']=extra;self.assertFalse(env['observed_getter'](Path('/inert'),[])['permissionObserved'])
 def test_failed_submit_retains_unknown_and_runs_all_closing_guards(self):
  env,ledger,calls,terminal=runtime_scope();env['diagnostic_export']=lambda:(_ for _ in ()).throw(ValueError('diagnostic_command_timeout'));result=env['observed_getter'](Path('/inert'),[])
  self.assertTrue(result['closingGuardsVerified']);self.assertFalse(result['permissionObserved']);self.assertIn('operationsAfter',result['records']);self.assertIn('statusAfter',result['records']);self.assertEqual('durable-terminal.json',calls[-1][0]);self.assertIs(result['replayAllowed'],False)
 def test_forged_terminal_and_changed_inspection_fail(self):
  for field,value in (('requestId',CORR),('controllerId','foreign'),('configurationRevision',False),('operationId','bad'),('final',1)):
   env,ledger,calls,terminal=runtime_scope();terminal[field]=value;self.assertFalse(env['observed_getter'](Path('/inert'),[])['permissionObserved'])
  env,ledger,calls,terminal=runtime_scope();env['diagnostic_operation_status']=lambda _: {'stdout':{**terminal,'data':{'content':'forged'}}};self.assertEqual('diagnostic_inspection_changed',env['observed_getter'](Path('/inert'),[])['reason'])
 def test_source_before_factory_and_full_generation_pin(self):
  temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);context=AdjacentContext(Path(temporary.name));context.old.historical=context.permission
  context.old.prepare(context.root,{'syntheticProtocol':True},CORR)
  real=diagnostic.availability._snapshot
  def changed(path):
   pin,raw=real(path);return (pin,raw+b'\n') if Path(path)==Path(context.permission.__file__).absolute() else (pin,raw)
  with mock.patch.object(diagnostic.availability,'_snapshot',side_effect=changed),mock.patch.object(context.permission,'prepare') as factory:
   with self.assertRaisesRegex(ValueError,'diagnostic_historical_source_changed'):context.old.prepare(context.root,{'syntheticProtocol':True},CORR)
   factory.assert_not_called()

@unittest.skipUnless(os.name=='posix','descriptor-bound durable POSIX fences')
class FenceTests(unittest.TestCase):
 def local(self,root):return {'diagnosticRoot':root,'ownedDiagnostic':binding(),'program':'fixed-program','diagnosticProgramSha256':hashlib.sha256(b'fixed-program').hexdigest(),'snapshots':{},'armed':False}
 def test_createonly_consumed_unknown_raw_retention_and_different_corr_no_bypass(self):
  with tempfile.TemporaryDirectory() as tmp,mock.patch.object(diagnostic.historical,'guard_prepared'):
   root=Path(tmp).resolve();p=self.local(root);diagnostic.arm(p);self.assertEqual('consumed-unknown',diagnostic.status(root)['state']);diagnostic.guard_prepared(p)
   other=self.local(root);other['ownedDiagnostic']=dict(binding(),correlationId=str(uuid.uuid4()))
   with self.assertRaises(FileExistsError):diagnostic.arm(other)
   diagnostic.retain(p,b'private raw failure',b'private stderr',None);self.assertEqual('consumed-recorded',diagnostic.status(root)['state'])
   with self.assertRaisesRegex(ValueError,'diagnostic_local_consumed'):diagnostic.guard_prepared(p)
   with self.assertRaises(FileExistsError):diagnostic.retain(p,b'',b'',0)
 def test_shortwrites_fsync_failure_and_parent_exchange_reject(self):
  with tempfile.TemporaryDirectory() as tmp,mock.patch.object(diagnostic.historical,'guard_prepared'):
   root=Path(tmp).resolve();p=self.local(root);real=os.write
   with mock.patch.object(diagnostic.os,'write',side_effect=lambda fd,data:real(fd,data[:7])):diagnostic.arm(p)
   intent=root/'.rag_index/android-api29-owned-permission-diagnostics'/diagnostic.historical.original.CORRELATION/'intent.json';self.assertEqual(binding(),json.loads(intent.read_bytes())['binding'])
   original=intent.read_bytes();intent.unlink();intent.write_bytes(original);intent.chmod(0o600)
   with self.assertRaisesRegex(ValueError,'diagnostic_local_fence_changed'):diagnostic.guard_prepared(p)
  with tempfile.TemporaryDirectory() as tmp,mock.patch.object(diagnostic.historical,'guard_prepared'):
   root=Path(tmp).resolve();p=self.local(root)
   with mock.patch.object(diagnostic.os,'fsync',side_effect=OSError('durability failed')):
    with self.assertRaises(OSError):diagnostic.arm(p)
   self.assertIs(p['armed'],False)
 def test_large_retained_capture_verified_and_corruption_rejected(self):
  with tempfile.TemporaryDirectory() as tmp,mock.patch.object(diagnostic.historical,'guard_prepared'):
   root=Path(tmp).resolve();p=self.local(root);diagnostic.arm(p);diagnostic.retain(p,b'x'*1100000,b'',None);self.assertEqual('consumed-recorded',diagnostic.status(root)['state'])
   path=root/'.rag_index/android-api29-owned-permission-diagnostics'/diagnostic.historical.original.CORRELATION/'capture.json';path.write_bytes(b'changed');path.chmod(0o600)
   with self.assertRaisesRegex(ValueError,'diagnostic_local_capture_changed'):diagnostic.status(root)
 def test_actual_remote_intent_guard_samebytes_generation_drift(self):
  env,_,_,_=runtime_scope()
  node=next(n for n in ast.parse(diagnostic._REMOTE.replace('__DIAGNOSTIC__',repr(binding()))).body if isinstance(n,ast.FunctionDef) and n.name=='diagnostic_intent_guard')
  exec(compile(ast.Module(body=[node],type_ignores=[]),'<actual-intent-guard>','exec'),env)
  with tempfile.TemporaryDirectory() as tmp:
   path=Path(tmp)/'intent.json';raw=json.dumps(binding()).encode();path.write_bytes(raw);path.chmod(0o600);fd=os.open(tmp,os.O_RDONLY|os.O_DIRECTORY)
   try:
    fingerprint=lambda x:[x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns,x.st_mode,x.st_uid,x.st_gid,x.st_nlink]
    pin={'generation':fingerprint(path.stat()),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
    env.update(os=os,hashlib=hashlib,fp=fingerprint,guard_parents=lambda _:None,DIAGNOSTIC_STATE={'chain':[{'fd':fd}],'intentPin':pin})
    env['diagnostic_intent_guard']();path.unlink();path.write_bytes(raw);path.chmod(0o600)
    with self.assertRaisesRegex(ValueError,'diagnostic_intent_changed'):env['diagnostic_intent_guard']()
   finally:os.close(fd)
 def test_actual_phase_transport_rejects_crossed_method_or_payload_before_spawn(self):
  env,_,_,_=runtime_scope();node=next(n for n in ast.parse(diagnostic._REMOTE.replace('__DIAGNOSTIC__',repr(binding()))).body if isinstance(n,ast.FunctionDef) and n.name=='diagnostic_adb');exec(compile(ast.Module(body=[node],type_ignores=[]),'<actual-fixed-transport>','exec'),env)
  env['parent_fds']=lambda _:(_ for _ in ()).throw(AssertionError('unexpected binary open'))
  env['DIAGNOSTIC_STATE']={'phase':'created','transfer':TRANSFER}
  for words,payload in ((['call','--uri',env['URI'],'--method','create'],None),(['write','--uri',env['URI']+'/requests/'+TRANSFER],b'forged'),(['write','--uri',env['URI']+'/requests/'+CORR],binding()['requestBytes'].encode())):
   with self.assertRaisesRegex(ValueError,'diagnostic_fixed_transport_required'):env['diagnostic_adb'](words,payload)
 def test_actual_capture_bounded_input_raw_before_parse_timeout_and_overflow(self):
  env,_,_,_=runtime_scope();real=subprocess.Popen
  for script,payload,timeout,limit,reason in (("import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b'\\xff')",binding()['requestBytes'].encode(),1,1024,None),("print('x'*100)",None,1,16,'diagnostic_command_output_limit'),('import time;time.sleep(10)',None,.01,16,'diagnostic_command_timeout')):
   env['GETTER_RECORDS']={}
   def launch(argv,**kwargs):return real([__import__('sys').executable,'-c',script],stdin=subprocess.PIPE if payload else subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   env['subprocess']=types.SimpleNamespace(Popen=launch,PIPE=subprocess.PIPE,DEVNULL=subprocess.DEVNULL,TimeoutExpired=subprocess.TimeoutExpired)
   if reason:
    with self.assertRaisesRegex(ValueError,reason):env['diagnostics_capture']([],3,{},payload,timeout,limit)
   else:
    with self.assertRaises(UnicodeError):env['diagnostics_capture']([],3,{},payload,timeout,limit)
   record=env['GETTER_RECORDS']['captures'][0];self.assertLessEqual(record['stdoutBytes']+record['stderrBytes'],limit)
   if reason is None:self.assertEqual(b'\xff',base64.b64decode(record['stdoutBase64']))

class CompositionTests(unittest.TestCase):
 def test_full_generated_original_prefix_dispatch_tail_and_production_ledger(self):
  temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);context=AdjacentContext(Path(temporary.name))
  context.old.historical=context.permission
  prepared=context.old.prepare(context.root,{'syntheticProtocol':True},CORR);tree=ast.parse(prepared['program']);emitted=[]
  for index in range(len(tree.body)-1,-1,-1):
   text=ast.unparse(tree.body[index])
   if text.startswith('_failed = read_fixed('):tree.body.insert(index,ast.parse('HOST_HISTORY(globals())').body[0])
   elif text=='alias_history_guard()':tree.body.insert(index,ast.parse('alias_history_guard=HOST_ALIAS').body[0])
  tree.body.insert(-1,ast.parse('HOST_INSTALL(globals())').body[0]);pin=[1]*9
  class Directory:
   name='inert-original-journal'
   def lstat(self):return types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o700)
  class Root:
   def __truediv__(self,_):return Directory()
  for fail in (None,'tail','intent','foreign'):
   emitted.clear()
   def install(ns):
    env,ledger,calls,terminal=runtime_scope();proxy=types.SimpleNamespace(**vars(os));proxy.getuid=lambda:0;proxy.geteuid=lambda:0;proxy.open=lambda *a,**k:8;proxy.close=lambda _:None
    info=types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o600,st_nlink=1);rootinfo=types.SimpleNamespace(st_uid=1000,st_mode=stat.S_IFDIR|0o700);proxy.fstat=lambda fd:rootinfo if fd==7 else info;proxy.stat=lambda *a,**k:info;checks=[0]
    def guard(_):
     checks[0]+=1
     if fail=='tail' and checks[0]==4:raise ValueError('tail_changed')
    if fail=='foreign':terminal['controllerId']='foreign'
    ns.update({k:env[k] for k in ('getter_generation','getter_stage','getter_cli','getter_envelope','diagnostic_adb','diagnostic_fence','diagnostic_write','diagnostic_operation_status','diagnostic_intent_guard')})
    # Preserve the actual generated export/parser/owned-summary logic, not a
    # handwritten dispatch. Provider external boundary emulates production.
    ns.update(getter_apk=lambda:ns['GETTER']['packageSha256'],ROOT=Root(),os=proxy,parent_fds=lambda _:([{'fd':7,'pin':pin}],None),guard_parents=guard,close_parents=lambda _:None,fp=lambda _:pin,journal_read=lambda *a:{} if fail=='intent' else ns['LAUNCH']['intent'],fcntl=types.SimpleNamespace(LOCK_EX=1,LOCK_NB=2,flock=lambda *a:None),print=lambda line:emitted.append(json.loads(line)))
   host={'HOST_INSTALL':install,'HOST_HISTORY':lambda ns:ns.update(read_fixed=lambda *a:{**ns['CFG']['failedCensus']['pin'],'raw':b''}),'HOST_ALIAS':lambda:None}
   if fail in ('tail','intent'):
    with self.assertRaises(ValueError):exec(compile(ast.fix_missing_locations(tree),'<actual-owned-diagnostics>','exec'),host)
    self.assertEqual([],emitted)
   else:
    exec(compile(ast.fix_missing_locations(tree),'<actual-owned-diagnostics>','exec'),host);self.assertEqual(1,len(emitted));self.assertEqual(fail is None,emitted[0]['permissionObserved']);self.assertFalse(emitted[0]['replayAllowed'])
