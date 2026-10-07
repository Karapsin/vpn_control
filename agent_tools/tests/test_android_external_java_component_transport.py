"""Exact shared backend composition and real bounded-child capture regressions."""
import atexit,ast,base64,copy,hashlib,json,os,pathlib,re,select,subprocess,sys,time,tempfile,types,unittest
from unittest import mock
from agent_tools import android_external_java_component_transport as transport
from agent_tools import android_api29_current_owner_observation as owner
from agent_tools import android_api35_coldboot_product_observation as api35
OWNER='6373d143-1372-4835-a89b-baafb0959b9f'

LEGACY_PROVENANCE_SHA='c4c4afe5b101f099f23bc80cc8dfb7e1d3febff7299ee53672128a0440806742'
LEGACY_SOURCES={
 'reader':('android_avd_launch_recovery.source','eb89ef4cccdb5417becd02b4116eccd10b2e4da4d9fe81f3a8c54d8f97b13fa0'),
 'diagnostic':('android_avd_census_diagnostic.source','ac5c810179a0f3a2efaef3ed18dbe45787cb1b3409c8ac98895d21cea62f6fc8'),
 'alias':('android_avd_sdk_alias_observation.source','ab2f1d0249a68a47d7a11ba74400615f0fc9aa27a067a1e0839ee188e63976c9'),
 'census':('android_avd_sdk_alias_census.source','caac560d9183469ef1bc8fa4a267c69ca23db3960c43baec1edb02e83fab2ccf'),
 'producer':('../android_existing_readonly/coldboot_producer.source','7d90c06070ffad1439e613c9ad5d63f979d43b738944f0630b2b15187f09fec6'),
 'product':('product_observer.source','ec56e238b0bac95d67ae1942b7218bb844db1e48b29cff1ad7b390b1721d8ae7'),
}

from agent_tools.tests.fixtures.android_component_hermetic import ComponentContext,backend
PUBLIC_ROOT=pathlib.Path(__file__).resolve().parents[2]
ROOT=PUBLIC_ROOT
_CONTEXT=None

def historical_prepared(device='android-api29'):
 return _CONTEXT.prepared(device)
prepared=historical_prepared

def installed(device='android-api29'):
 return _CONTEXT.installed(device)

class FixtureCase(unittest.TestCase):
 def setUp(self):
  temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
  context=ComponentContext(pathlib.Path(temporary.name))
  for name,value in (('_CONTEXT',context),('ROOT',context.root),('transport',context.transport)):
   patch=mock.patch(__name__+'.'+name,value);patch.start();self.addCleanup(patch.stop)

class ImportPrivacyTests(unittest.TestCase):
 def test_fresh_import_does_not_probe_checkout_private_history(self):
     """Real fresh import; forbidden paths are blocked before any OS access."""
     import subprocess,sys,textwrap
     root=pathlib.Path(__file__).resolve().parents[2]
     script=textwrap.dedent("""
         import os,sys,builtins,json,io
         root=sys.argv[1]
         forbidden=[os.path.join(root,name) for name in ('.runtime','.rag_index')]
         attempted=[]
         def wrap(function):
             def guarded(path,*args,**kwargs):
                 if isinstance(path,(str,bytes,os.PathLike)):
                     name=os.path.abspath(os.fsdecode(path))
                     if any(name==prefix or name.startswith(prefix+os.sep) for prefix in forbidden):
                         attempted.append('checkout-private-access')
                         raise PermissionError('blocked before OS access')
                 return function(path,*args,**kwargs)
             return guarded
         os.stat=wrap(os.stat);os.lstat=wrap(os.lstat);os.open=wrap(os.open)
         builtins.open=wrap(builtins.open);io.open=wrap(io.open)
         sys.path.insert(0,root)
         import agent_tools.tests.test_android_external_java_component_transport
         import agent_tools.tests.test_android_component_command_transport
         import agent_tools.tests.fixtures.android_component_hermetic
         print(json.dumps({'attempts':len(attempted)}))
     """)
     result=subprocess.run([sys.executable,'-I','-B','-c',script,str(root)],capture_output=True,timeout=15)
     self.assertEqual(0,result.returncode,result.stderr)
     self.assertEqual({'attempts':0},json.loads(result.stdout))

class HistoricalFixtureTests(FixtureCase):
 def test_archives_are_exact_executable_sources_with_original_filenames(self):
  from agent_tools.tests.fixtures import historical_source
  base=PUBLIC_ROOT/'agent_tools/tests/fixtures/android_component_legacy'
  raw=(base/'provenance.json').read_bytes();self.assertEqual(LEGACY_PROVENANCE_SHA,hashlib.sha256(raw).hexdigest())
  provenance=json.loads(raw)
  self.assertFalse(provenance['credentialsEmbedded']);self.assertFalse(provenance['executionAuthority'])
  for name,sha in LEGACY_SOURCES.values():
   path=(base/name).resolve();module=historical_source.load(path,sha)
   self.assertEqual(str(path),module.__file__)
   historical_source.verify(module,path,sha)
   with tempfile.TemporaryDirectory() as temporary:
    changed=pathlib.Path(temporary)/'changed.source';changed.write_bytes(path.read_bytes()+b'\n')
    with self.assertRaisesRegex(ValueError,'historical_source_binding_changed'):historical_source.load(changed,sha)
 def test_actual_modeled_launch_snapshot_mutation_rejected_by_original_guard(self):
  value=historical_prepared();guard=value['_historicalGuard'];guard(value)
  path=value['_modeledLaunchPath'];path.write_bytes(path.read_bytes()+b'\n')
  with self.assertRaisesRegex(ValueError,'fixture_upstream_source_changed'):guard(value)
  with self.assertRaisesRegex(ValueError,'component_source_changed'):transport.guard(value)

class ComponentTests(FixtureCase):
 def test_actual_launcher_red_retained_clean_component_proof_green(self):
  baseline=json.loads((ROOT/transport.proven.BASELINE).read_bytes());self.assertTrue(baseline['syntheticProtocol']);self.assertNotEqual('',baseline['records']['statusDiscovery']['stderrRaw'])
  proof=json.loads((ROOT/transport.PROOF).read_bytes());self.assertTrue(proof['componentFlowObserved']);self.assertEqual(transport.PROOF_SHA,hashlib.sha256((ROOT/transport.PROOF).read_bytes()).hexdigest())
  for name in ('statusDiscovery','operationsBefore','statusPinned','operationsAfter','statusFinal'):self.assertEqual('',proof['records'][name]['stderrRaw'])
  env,calls,_,_=backend();record=env['getter_cli'](['status'],OWNER);self.assertTrue(record['captureComplete']);self.assertFalse(record['installedLauncherAccepted']);self.assertFalse(record['bundledRuntimeAccepted'])
  def dirty(*a,**k):return dict(record,stderrRaw=baseline['records']['statusDiscovery']['stderrRaw'])
  env['getter_binary']=dirty
  with self.assertRaisesRegex(ValueError,'component_public_failed'):env['getter_cli'](['status'],OWNER)
 def test_actual_installed_api35_replaces_old_capture_schema(self):
  old=prepared('android-api35');tree=ast.parse(old['program']);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='getter_bounded');self.assertIn('lastBoundedCommand',ast.unparse(node));self.assertNotIn('captures',ast.unparse(node))
  actual,b=installed('android-api35');env,calls,p,_=backend('android-api35');self.assertIn('captures',ast.unparse(next(n for n in ast.parse(actual['program']).body if isinstance(n,ast.FunctionDef) and n.name=='getter_bounded')))
  self.assertTrue(env['getter_cli'](['operations','list'],OWNER)['captureComplete']);self.assertIn('emulator-5682',calls[0]);self.assertNotIn('emulator-5684',calls[0])
 def test_crossed_device_and_binding_jvm_source_drift_rejected(self):
  p=prepared()
  with self.assertRaisesRegex(ValueError,'component_crossed_device'):transport.prepare_binding(ROOT,p,'android-api35')
  p,b=installed();b['javaOptions'].append('-javaagent:private')
  with self.assertRaisesRegex(ValueError,'component_binding_changed'):transport.install(p,b)
  p=prepared();b=transport.prepare_binding(ROOT,p,'android-api29');p['program']=p['program'].replace("limit=8388608","limit=123")
  with self.assertRaisesRegex(ValueError,'component_hook_changed'):transport.install(p,b)
 def test_source_snapshot_guard_before_factory(self):
  p=prepared();actual=transport.availability._snapshot
  def changed(path):
   pin,raw=actual(path);return (pin,raw+b'\n') if pathlib.Path(path)==pathlib.Path(transport.proven.__file__).absolute() else (pin,raw)
  with mock.patch.object(transport.availability,'_snapshot',side_effect=changed):
   with self.assertRaises(ValueError):transport.prepare_binding(ROOT,p,'android-api29')
 def test_exact_fixed_catalogue_environment_owner_and_stage_guards(self):
  env,calls,_,_=backend()
  for words in (['status'],['operations','list'],['operations','status',OWNER],['operations','wait',OWNER],['diagnostics','export','--output','-']):env['getter_cli'](words,OWNER)
  self.assertEqual(5,len(calls));self.assertEqual(57,len(calls[0][calls[0].index('-cp')+1].split(':')))
  for words in (['on'],['diagnostics','export','--output','/private'],['updates','install'],['operations','cancel',OWNER],['operations','status','forged']):
   with self.assertRaises(ValueError):env['getter_cli'](words,OWNER)
  env['LAUNCH']['environment']['JAVA_TOOL_OPTIONS']='private'
  with self.assertRaisesRegex(ValueError,'component_fixed_environment_required'):env['getter_cli'](['status'],OWNER)
  del env['LAUNCH']['environment']['JAVA_TOOL_OPTIONS'];env['GETTER']['stageId']='other'
  with self.assertRaisesRegex(ValueError,'component_stage_identity_changed'):env['getter_cli'](['status'],OWNER)
 def test_jdk_and_stage_closing_drift_even_public_failure(self):
  env,calls,_,_=backend();counter=[0]
  def guard():
   counter[0]+=1
   if counter[0]==2:raise ValueError('external_jdk_generation_changed')
  env['external_jdk_guard']=guard
  with self.assertRaisesRegex(ValueError,'external_jdk_generation_changed'):env['getter_cli'](['status'],OWNER)
  self.assertEqual(1,len(calls))
  env,_,_,_=backend();counter=[0]
  def stage():counter[0]+=1;return counter[0]
  env['getter_stage']=stage
  with self.assertRaisesRegex(ValueError,'component_stage_generation_changed'):env['getter_cli'](['status'],OWNER)
 def test_bool_exit_and_forged_capture_rejected(self):
  for code in (True,1,None):
   env,_,_,_=backend();original=env['getter_binary']
   def call(*a,**k):return dict(original(*a,**k),returncode=code)
   env['getter_binary']=call
   with self.assertRaisesRegex(ValueError,'component_public_failed'):env['getter_cli'](['status'],OWNER)

@unittest.skipUnless(os.name=='posix','POSIX real pipe capture')
class RealCaptureTests(unittest.TestCase):
 def test_actual_api35_installed_bounded_reader_real_child_retains_before_parse(self):
  env,_,_,_=backend('android-api35');real=subprocess.Popen
  def launch(argv,**kwargs):
   for key in ('executable','pass_fds','preexec_fn'):kwargs.pop(key,None)
   return real([sys.executable,'-c',"import sys;sys.stdout.write('{\\\"ok\\\":true}');sys.stderr.write('')"],**kwargs)
  with mock.patch.object(subprocess,'Popen',side_effect=launch):
   result=env['getter_bounded'](['fixed'],0,{},timeout=3)
  self.assertEqual(0,result['returncode']);capture=env['GETTER_RECORDS']['captures'][-1];self.assertIsNone(capture['failure']);self.assertEqual(base64.b64encode(result['stdoutRaw'].encode()).decode(),capture['stdoutBase64']);self.assertEqual('',capture['stderrBase64'])

@unittest.skipUnless(os.name=='posix','POSIX real bounded child failure captures')
class RawFailureTests(FixtureCase):
 def test_utf8_timeout_overflow_keep_actual_raw_capture(self):
  for script,timeout,limit,reason in [("import os;os.write(1,b'\\xff')",3,1024,None),("import os,time;os.write(1,b'partial');time.sleep(2)",.08,1024,'permission_command_timeout'),("import os;os.write(1,b'x'*4096)",3,32,'permission_command_output_limit')]:
   env,_,_,_=backend('android-api35');real=subprocess.Popen
   def launch(argv,**kwargs):
    for key in ('executable','pass_fds','preexec_fn'):kwargs.pop(key,None)
    return real([sys.executable,'-c',script],**kwargs)
   with mock.patch.object(subprocess,'Popen',side_effect=launch):
    with self.assertRaises((ValueError,UnicodeError)):env['getter_bounded'](['fixed'],0,{},timeout=timeout,limit=limit)
   capture=env['GETTER_RECORDS']['captures'][-1];self.assertGreater(capture['stdoutBytes'],0);self.assertEqual(capture['stdoutBytes'],len(base64.b64decode(capture['stdoutBase64'])))
   self.assertEqual(reason,capture['failure']);self.assertLessEqual(capture['stdoutBytes'],limit)
 def test_original_api29_uncaptured_reader_upgraded_by_exact_hook(self):
  p=prepared();tree=ast.parse(p['program']);original=ast.parse(transport.getter_source._GETTER.replace('__GETTER__','{}'))
  replacement=next(n for n in original.body if isinstance(n,ast.FunctionDef) and n.name=='getter_bounded');index=next(i for i,n in enumerate(tree.body) if isinstance(n,ast.FunctionDef) and n.name=='getter_bounded');tree.body[index]=replacement;p['program']=ast.unparse(tree)
  b=transport.prepare_binding(ROOT,p,'android-api29');transport.install(p,b)
  self.assertIn("setdefault('captures'",ast.unparse(next(n for n in ast.parse(p['program']).body if isinstance(n,ast.FunctionDef) and n.name=='getter_bounded')))

@unittest.skipUnless(os.name=='posix','POSIX actual source-closed caller composition')
class WholeCompositionTests(FixtureCase):
 def test_actual_full_prefix_backend_dispatch_tail_and_closing_refusal(self):
  import stat,types
  from agent_tools.tests import test_android_api29_current_owner_observation as owner_tests
  p,b=installed();tree=ast.parse(p['program']);emitted=[]
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
  for failure in (False,True):
   emitted.clear()
   def install(ns):
    env,_,_=owner_tests.scope();ns['LAUNCH'].update(adbPath='/fixed/adb',environment={k:'fixed'for k in ('ANDROID_AVD_HOME','ANDROID_HOME','ANDROID_SDK_ROOT','HOME','LOGNAME','PATH','USER')});proxy=types.SimpleNamespace(**vars(os));proxy.getuid=lambda:0;proxy.geteuid=lambda:0;proxy.open=lambda *a,**k:8;proxy.close=lambda _:None
    info=types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o600,st_nlink=1);rootinfo=types.SimpleNamespace(st_uid=1000,st_mode=stat.S_IFDIR|0o700);proxy.fstat=lambda fd:rootinfo if fd==7 else info;proxy.stat=lambda *a,**k:info;checks=[0]
    def guard(_):
     checks[0]+=1
     if failure and checks[0]==4:raise ValueError('tail_changed')
    def binary(path,pin,args,environment,limit):
     words=['operations','list'] if args[-2:]==['operations','list'] else ['status'];record=env['getter_cli'](words,OWNER);raw=json.dumps(record['stdout']);record.update(stdoutRaw=raw,stderrRaw='')
     ns['GETTER_RECORDS'].setdefault('captures',[]).append({'returncode':0,'failure':None,'stdoutBase64':base64.b64encode(raw.encode()).decode(),'stderrBase64':'','stdoutBytes':len(raw.encode()),'stderrBytes':0});return record
    ns.update(getter_generation=env['getter_generation'],getter_stage=env['getter_stage'],getter_apk=lambda:ns['GETTER']['packageSha256'],external_jdk_guard=lambda:None,getter_binary=binary,public_cli_environment=lambda *a:{},ROOT=Root(),os=proxy,parent_fds=lambda _:([{'fd':7,'pin':pin}],None),guard_parents=guard,close_parents=lambda _:None,fp=lambda _:pin,journal_read=lambda *a:ns['LAUNCH']['intent'],fcntl=types.SimpleNamespace(LOCK_EX=1,LOCK_NB=2,flock=lambda *a:None),print=lambda line:emitted.append(json.loads(line)))
   host={'HOST_INSTALL':install,'HOST_HISTORY':lambda ns:ns.update(read_fixed=lambda *a:{**ns['CFG']['failedCensus']['pin'],'raw':b''}),'HOST_ALIAS':lambda:None}
   if failure:
    with self.assertRaises(ValueError):exec(compile(ast.fix_missing_locations(tree),'<actual-whole-component>','exec'),host)
    self.assertEqual([],emitted)
   else:
    exec(compile(ast.fix_missing_locations(tree),'<actual-whole-component>','exec'),host);self.assertEqual(1,len(emitted));self.assertTrue(emitted[0]['ownerObserved'],emitted[0]);self.assertFalse(emitted[0]['acceptanceComplete'])

class PublicSchemaTests(unittest.TestCase):
 def test_invalid_device_or_hook_rejects_before_any_fixture_read(self):
  with mock.patch.object(transport.availability,'_snapshot',side_effect=AssertionError('unexpected private read')):
   for device in (None,True,'api29','android-api34','emulator-5682'):
    with self.assertRaisesRegex(ValueError,'component_device_required'):transport.prepare_binding(ROOT,{},device)
   for hook in ('public','invoke',None):
    with self.assertRaisesRegex(ValueError,'component_fixed_hook_required'):transport.install({}, {}, hook)
 def test_fixed_backend_has_no_subprocess_or_caller_java_environment_hook(self):
  tree=ast.parse(transport._BACKEND)
  self.assertEqual(['component_cli'],[n.name for n in tree.body if isinstance(n,ast.FunctionDef)])
  self.assertNotIn('subprocess',transport._BACKEND);self.assertNotIn('JAVA_HOME',transport._BACKEND)
  self.assertEqual({'android-api29':'emulator-5684','android-api35':'emulator-5682'},transport.DEVICES)
