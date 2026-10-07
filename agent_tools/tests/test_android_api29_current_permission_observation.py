"""Current API29 permission reads through actual frozen composition, no guest."""
import ast,base64,copy,hashlib,json,os,re,stat,subprocess,tempfile,time,types,unittest
from pathlib import Path
from unittest import mock
from agent_tools import android_api29_current_permission_observation as observer
from agent_tools.tests import test_android_coldboot_product_observation as inherited_tests
ROOT=Path(__file__).resolve().parents[2]
from agent_tools.tests.fixtures.android_api29_epoch.adjacent import AdjacentContext

def scope():
 env=inherited_tests.GetterTests().scope();env.update(json=json,pathlib=Path.__module__ and __import__('pathlib'),subprocess=subprocess,os=os,time=time)
 exec(observer._OBSERVER.replace('__OWNER__',repr(observer.OWNER)),env)
 env['getter_stage']=lambda:{'full155':'unchanged'}
 env['getter_cli']=lambda words,owner=None:{'returncode':0,'stdout':{'ok':True,'final':True,'code':'OK','controllerId':observer.OWNER,'configurationRevision':0,'data':{'runtimeRunning':False,'runtimeObservation':'stopped','operations':[]}}}
 env['permission_diagnostics']=lambda:{'returncode':0,'stdoutRaw':'[runtime]\nmode=VPN\nvpn_permission_granted=false\nis_vpn_running=false\n','stderrRaw':''}
 return env

def reservation():
 rows=json.loads((ROOT/'.rag_index/native-environments/reservations.json').read_bytes())['reservations']
 row=next(r for r in rows if r['id']=='env-11f1a10b21cfea11b504bd9db53dd9a0')
 return {k:row[{'reservationId':'id'}.get(k,k)] for k in ('reservationId','token','hostAlias','environment','operator')}

class PermissionTests(unittest.TestCase):
 def test_boolean_mode_duplicate_and_noninteger_exit_reject(self):
  env=scope();record=env['permission_diagnostics']();self.assertIs(env['permission_parse'](record)['permissionGranted'],False)
  granted={**record,'stdoutRaw':record['stdoutRaw'].replace('granted=false','granted=true')};self.assertIs(env['permission_parse'](granted)['permissionGranted'],True)
  for changed in ({**record,'returncode':False},{**record,'stderrRaw':'private'},{**record,'stdoutRaw':record['stdoutRaw'].replace('granted=false','granted=0')},{**record,'stdoutRaw':record['stdoutRaw']+'[runtime]\n'},{**record,'stdoutRaw':record['stdoutRaw']+'vpn_permission_granted=true\n'}):
   with self.assertRaises(ValueError):env['permission_parse'](changed)
 def test_no_permission_is_proof_only_not_grant_endpoint_or_acceptance(self):
  result=scope()['observed_getter'](Path('/inert'));self.assertTrue(result['permissionObserved']);self.assertTrue(result['closingGuardsVerified'])
  for key in ('endpointAdmitted','productAdmitted','acceptanceComplete','permissionGrantPerformed'):self.assertIs(result[key],False)
 def test_owner_revision_running_operations_and_stage_drift(self):
  for mutate in (lambda r:r['stdout'].update(controllerId='foreign'),lambda r:r['stdout'].update(configurationRevision=False),lambda r:r['stdout']['data'].update(runtimeRunning=True),lambda r:r['stdout']['data'].update(operations=[{}])):
   env=scope();original=env['getter_cli']
   def cli(*args):
    r=original(*args);mutate(r);return r
   env['getter_cli']=cli;self.assertFalse(env['observed_getter'](Path('/inert'))['permissionObserved'])
  env=scope();pins=iter([{'gen':1},{'gen':2}]);env['getter_stage']=lambda:next(pins);self.assertEqual('getter_stage_generation_changed',env['observed_getter'](Path('/inert'))['reason'])
 def test_guest_drift_blocks_diagnostics_and_failure_still_closes(self):
  env=scope();env['original_status']=lambda _:{};env['permission_diagnostics']=lambda:(_ for _ in ()).throw(AssertionError('unadmitted read'));self.assertFalse(env['observed_getter'](Path('/inert'))['permissionObserved'])
  env=scope();env['permission_diagnostics']=lambda:(_ for _ in ()).throw(ValueError('permission_command_timeout'));result=env['observed_getter'](Path('/inert'));self.assertTrue(result['closingGuardsVerified']);self.assertFalse(result['permissionObserved'])
 def test_source_drift_rejected_before_factory_and_guard_keeps_generation(self):
  temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);context=AdjacentContext(Path(temporary.name))
  prepared=context.permission_prepared();context.permission.guard_prepared(prepared)
  original=observer.availability._snapshot
  def changed(path):
   pin,raw=original(path);return (pin,raw+b'\n') if Path(path)==Path(context.product.__file__).absolute() else (pin,raw)
  with mock.patch.object(observer.availability,'_snapshot',side_effect=changed),mock.patch.object(context.product,'prepare') as factory:
   with self.assertRaisesRegex(ValueError,'permission_original_source_changed'):context.permission_prepared()
   factory.assert_not_called()
  # Untouched current d90 is genuinely incompatible with historical ec56.
  with mock.patch.object(observer.original,'prepare') as factory:
   with self.assertRaisesRegex(ValueError,'permission_original_source_changed'):observer.prepare(Path(temporary.name),{})
   factory.assert_not_called()
 @unittest.skipUnless(os.name=='posix','bounded POSIX descriptor consumer')
 def test_actual_old_reader_utf8_failure_loses_raw_new_retains_before_decode(self):
  env=scope();env['GETTER_RECORDS']={};real=subprocess.Popen
  class Process:
   def __new__(cls,argv,**kwargs):return real([__import__('sys').executable,'-c',"import sys;sys.stdout.buffer.write(b'\\xff')"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  env['subprocess']=types.SimpleNamespace(Popen=Process,PIPE=subprocess.PIPE,DEVNULL=subprocess.DEVNULL,TimeoutExpired=subprocess.TimeoutExpired)
  old=next(n for n in ast.parse(observer.original._GETTER).body if isinstance(n,ast.FunctionDef) and n.name=='getter_bounded');old.name='old_bounded';exec(compile(ast.fix_missing_locations(ast.Module(body=[old],type_ignores=[])),'<frozen-old-reader>','exec'),env)
  with self.assertRaises(UnicodeError):env['old_bounded']([],3,{})
  self.assertEqual({},env['GETTER_RECORDS']) # causal RED: actual old bounded reader discards output
  with self.assertRaises(UnicodeError):env['getter_bounded']([],3,{})
  self.assertEqual(b'\xff',base64.b64decode(env['GETTER_RECORDS']['captures'][0]['stdoutBase64']))
 @unittest.skipUnless(os.name=='posix','bounded POSIX descriptor consumer')
 def test_actual_output_cap_timeout_and_fixed_diagnostic_argv(self):
  env=scope();real=subprocess.Popen
  for script,timeout,limit,reason in (("print('x'*100)",1,16,'permission_command_output_limit'),('import time;time.sleep(10)',.01,16,'permission_command_timeout')):
   env['GETTER_RECORDS']={}
   def launch(argv,**kwargs):return real([__import__('sys').executable,'-c',script],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   env['subprocess']=types.SimpleNamespace(Popen=launch,PIPE=subprocess.PIPE,DEVNULL=subprocess.DEVNULL,TimeoutExpired=subprocess.TimeoutExpired)
   with self.assertRaisesRegex(ValueError,reason):env['getter_bounded']([],3,{},timeout=timeout,limit=limit)
   capture=env['GETTER_RECORDS']['captures'][0];self.assertEqual(reason,capture['failure']);self.assertLessEqual(capture['stdoutBytes']+capture['stderrBytes'],limit)
  env=scope();env['GETTER'].update(cli='/fixed/cli',manifest={'launcherSha256':'fixed'});env['LAUNCH']={'adbPath':'/fixed/adb','environment':{}};env['read_fixed']=lambda *a:{'raw':b'cli','hashScope':'full','sha256':'fixed','generation':[1]};env['public_cli_environment']=lambda *a:{};calls=[]
  env['getter_binary']=lambda *a,**k:calls.append(a[2]) or {};env['permission_diagnostics']=None
  node=next(n for n in ast.parse(observer._OBSERVER.replace('__OWNER__',repr(observer.OWNER))).body if isinstance(n,ast.FunctionDef) and n.name=='permission_diagnostics');exec(compile(ast.Module(body=[node],type_ignores=[]),'<fixed-diagnostics>','exec'),env)
  env['permission_diagnostics']();self.assertEqual(['diagnostics','export','--output','-'],calls[0][-4:]);self.assertIn('emulator-5684',calls[0]);self.assertIn(observer.OWNER,calls[0]);self.assertNotIn('--json',calls[0])
 def test_actual_factory_full_prefix_dispatch_tail(self):
  temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);context=AdjacentContext(Path(temporary.name))
  prepared=context.permission_prepared();tree=ast.parse(prepared['program']);emitted=[]
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
  for failure in (None,'tail','intent','production-ledger'):
   emitted.clear()
   def install(ns):
    env=scope();proxy=types.SimpleNamespace(**vars(os));proxy.getuid=lambda:0;proxy.geteuid=lambda:0;proxy.open=lambda *a,**k:8;proxy.close=lambda _:None
    info=types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o600,st_nlink=1);rootinfo=types.SimpleNamespace(st_uid=1000,st_mode=stat.S_IFDIR|0o700)
    proxy.fstat=lambda fd:rootinfo if fd==7 else info;proxy.stat=lambda *a,**k:info;checks=[0]
    def guard(_):
     checks[0]+=1
     if failure=='tail' and checks[0]==4:raise ValueError('tail_changed')
    if failure=='production-ledger':
     # Faithful production behavior: settingsWrite admits and retains the
     # diagnostics operation. The legacy neutral-reader branch is not used.
     ledger=[];public=env['getter_cli'];diagnostics=env['permission_diagnostics']
     def production_cli(words,owner=None):
      record=public(words,owner)
      if words==['operations','list']:record['stdout']['data']['operations']=copy.deepcopy(ledger)
      return record
     def production_export():
      ledger.append({'id':'owned-diagnostic','requestId':'fresh-request','operation':'diagnostics.export','phase':'complete','final':True})
      return diagnostics()
     env.update(getter_cli=production_cli,permission_diagnostics=production_export)
    ns.update({k:env[k] for k in ('getter_generation','getter_stage','getter_apk','getter_cli','getter_envelope','permission_diagnostics')})
    ns.update(getter_apk=lambda:ns['GETTER']['packageSha256'],ROOT=Root(),os=proxy,parent_fds=lambda _:([{'fd':7,'pin':pin}],None),guard_parents=guard,close_parents=lambda _:None,fp=lambda _:pin,journal_read=lambda *a:{} if failure=='intent' else ns['LAUNCH']['intent'],fcntl=types.SimpleNamespace(LOCK_EX=1,LOCK_NB=2,flock=lambda *a:None),print=lambda line:emitted.append(json.loads(line)))
   bindings={'HOST_INSTALL':install,'HOST_HISTORY':lambda ns:ns.update(read_fixed=lambda *a:{**ns['CFG']['failedCensus']['pin'],'raw':b''}),'HOST_ALIAS':lambda:None}
   if failure=='production-ledger':
    exec(compile(ast.fix_missing_locations(tree),'<actual-production-ledger>','exec'),bindings)
    self.assertEqual(1,len(emitted));self.assertFalse(emitted[0]['permissionObserved']);self.assertEqual('permission_operations_not_empty',emitted[0]['reason']);self.assertFalse(emitted[0]['closingGuardsVerified'])
   elif failure:
    with self.assertRaises(ValueError):exec(compile(ast.fix_missing_locations(tree),'<actual-full-permission>','exec'),bindings)
    self.assertEqual([],emitted)
   else:
    exec(compile(ast.fix_missing_locations(tree),'<actual-full-permission>','exec'),bindings);self.assertEqual(1,len(emitted));self.assertTrue(emitted[0]['permissionObserved']);self.assertFalse(emitted[0]['endpointAdmitted'])
