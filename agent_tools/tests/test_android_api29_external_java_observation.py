"""Fixed external JDK census/CLI composition, retaining actual launcher RED."""
import ast,copy,hashlib,json,os,stat,tempfile,types,unittest
from pathlib import Path
from unittest import mock
from agent_tools import android_api29_external_java_observation as external
from agent_tools.tests import test_android_api29_current_owner_observation as owner_tests
from agent_tools.tests import test_android_api29_current_permission_observation as original_tests
ROOT=Path(__file__).resolve().parents[2]
from agent_tools.tests.fixtures.android_api29_epoch.adjacent import AdjacentContext

def jdk(alias='jdk17'):
 return {'state':'observed','alias':alias,'root':external.CANDIDATES[alias],'declaredJavaVersion':'17.0.20.1' if alias=='jdk17' else '21.0.8','files':{name:{'generation':[1,2,10,4,5,stat.S_IFREG|0o755,0,0,1],'bytesRead':10,'sha256':'a'*64,'hashScope':'full'} for name in external.JDK_FILES}}

def binding(action='compare'):
 return {'action':action,'candidates':external.CANDIDATES,'jdkFiles':list(external.JDK_FILES),'selectedJdk':jdk() if action=='compare' else None,'classpath':['fixed.jar']*57,'javaOptions':['-Djpackage.app-version=2.2.2','-Dcompose.application.resources.dir=$APPDIR/resources','-Dcompose.application.configure.swing.globals=true','-Dskiko.library.path=$APPDIR'],'sourceSha256':'b'*64,'originalSourceSha256':external.ORIGINAL_SHA,'baselineSha256':external.BASELINE_SHA}

def scope(action='compare'):
 env,calls,ledger=owner_tests.scope();exec(external._REMOTE.replace('__EXTERNAL__',repr(binding(action))),env)
 env['GETTER'].update(cli='/fixed/tree/opt/vpn-control/bin/vpn-control',stageId='fixed-stage');env['external_jdk_guard']=lambda:None
 def invoke(words,owner=None):
  if words==['--version']:return {'returncode':0,'stdoutRaw':'2.2.2\n','stderrRaw':''}
  return env['getter_cli'](words,owner)
 env['external_cli']=invoke;env['external_census']=lambda:{'jdk17':jdk(),'jdk21':{'state':'unknown','reason':'external_jdk_unavailable'}}
 return env,calls,ledger

class ExternalTests(unittest.TestCase):
 def test_actual_retained_launcher_stderr_red_clean_component_green(self):
  temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);context=AdjacentContext(Path(temporary.name))
  raw=(context.root/context.external.BASELINE).read_bytes();self.assertEqual(context.external.BASELINE_SHA,hashlib.sha256(raw).hexdigest());self.assertNotEqual(external.BASELINE_SHA,context.external.BASELINE_SHA);value=json.loads(raw);env,_,_=scope()
  with self.assertRaisesRegex(ValueError,'owner_public_unavailable'):env['owner_status'](value['records']['statusDiscovery'])
  result=env['observed_getter'](Path('/inert'));self.assertTrue(result['componentFlowObserved']);self.assertEqual('EXTERNAL_JDK',result['componentRuntime']);self.assertTrue(result['jdkClosingGuardsVerified']);self.assertTrue(result['ledgerEmpty'])
  for key in ('installedLauncherAccepted','bundledRuntimeAccepted','permissionObserved','exportSubmitted','productAdmitted','acceptanceComplete'):self.assertIs(result[key],False)
 def test_census_executes_no_cli_or_java(self):
  env,calls,_=scope('census');env['external_cli']=lambda *a:(_ for _ in ()).throw(AssertionError('unexpected execution'));result=env['observed_getter'](Path('/inert'));self.assertTrue(result['censusComplete']);self.assertFalse(result['componentFlowObserved']);self.assertEqual([],calls)
 def test_version_failure_jdk_drift_and_public_epoch_failure_still_close(self):
  env,_,_=scope();env['external_cli']=lambda *a:(_ for _ in ()).throw(ValueError('external_product_version_failed'));result=env['observed_getter'](Path('/inert'));self.assertTrue(result['closingGuardsVerified']);self.assertFalse(result['componentFlowObserved'])
  env,_,_=scope();checks=[0]
  def guard():
   checks[0]+=1
   if checks[0]>1:raise ValueError('external_jdk_generation_changed')
  env['external_jdk_guard']=guard;result=env['observed_getter'](Path('/inert'));self.assertFalse(result['componentFlowObserved']);self.assertTrue(result['closingGuardsVerified']);self.assertFalse(result['jdkClosingGuardsVerified'])
  env,calls,_=scope();original=env['getter_cli']
  def cli(*args):
   record=original(*args)
   if len(calls)==3:record['stdout']['controllerId']='foreign'
   return record
  env['getter_cli']=cli;self.assertFalse(env['observed_getter'](Path('/inert'))['componentFlowObserved'])
 def test_actual_fixed_java_argv_exact_cfg_and_no_arbitrary_operation(self):
  env,_,_=scope();node=next(n for n in ast.parse(external._REMOTE.replace('__EXTERNAL__',repr(binding()))).body if isinstance(n,ast.FunctionDef) and n.name=='external_cli');exec(compile(ast.Module(body=[node],type_ignores=[]),'<fixed-java-argv>','exec'),env)
  env['LAUNCH']={'adbPath':'/fixed/adb','environment':{k:'fixed' for k in ('ANDROID_AVD_HOME','ANDROID_HOME','ANDROID_SDK_ROOT','HOME','LOGNAME','PATH','USER')}};env['public_cli_environment']=lambda *a:{};calls=[]
  env['getter_binary']=lambda path,pin,args,environment,limit:calls.append((path,pin,args)) or {'returncode':0,'stdoutRaw':'2.2.2\n' if args[-1]=='--version' else '{}','stderrRaw':''}
  env['external_cli'](['--version']);env['external_cli'](['status'],owner_tests.CURRENT)
  self.assertEqual(Path(external.CANDIDATES['jdk17'])/'bin/java',calls[0][0]);self.assertEqual('com.kardinal.vpncontrol.desktop.MainKt',calls[0][2][-2]);self.assertEqual(57,len(calls[0][2][calls[0][2].index('-cp')+1].split(':')));self.assertIn('-Dskiko.library.path=/fixed/tree/opt/vpn-control/lib/app',calls[0][2]);self.assertIn(owner_tests.CURRENT,calls[1][2])
  for words in (['diagnostics','export'],['on'],['routing','show'],['settings','set']):
   with self.assertRaisesRegex(ValueError,'external_fixed_command_required'):env['external_cli'](words)
  self.assertEqual(2,len(calls))
  env['LAUNCH']['environment']['JAVA_TOOL_OPTIONS']='forged'
  with self.assertRaisesRegex(ValueError,'external_fixed_environment_required'):env['external_cli'](['status'])
  self.assertEqual(2,len(calls))
 def test_version_stderr_is_not_suppressed(self):
  env,_,_=scope();node=next(n for n in ast.parse(external._REMOTE.replace('__EXTERNAL__',repr(binding()))).body if isinstance(n,ast.FunctionDef) and n.name=='external_cli');exec(compile(ast.Module(body=[node],type_ignores=[]),'<version-cleanliness>','exec'),env)
  env['LAUNCH']={'adbPath':'/fixed/adb','environment':{k:'fixed' for k in ('ANDROID_AVD_HOME','ANDROID_HOME','ANDROID_SDK_ROOT','HOME','LOGNAME','PATH','USER')}};env['public_cli_environment']=lambda *a:{};env['getter_binary']=lambda *a,**k:{'returncode':0,'stdoutRaw':'2.2.2\n','stderrRaw':'pure virtual method called\n'}
  with self.assertRaisesRegex(ValueError,'external_product_version_failed'):env['external_cli'](['--version'])
 def test_source_drift_before_factory_and_malformed_action(self):
  temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);context=AdjacentContext(Path(temporary.name));context.external_prepared('census')
  actual=external.availability._snapshot
  def changed(path):
   pin,raw=actual(path);return (pin,raw+b'\n') if Path(path)==Path(context.owner.__file__).absolute() else (pin,raw)
  with mock.patch.object(external.availability,'_snapshot',side_effect=changed),mock.patch.object(context.owner,'prepare') as factory:
   with self.assertRaisesRegex(ValueError,'external_original_source_changed'):context.external_prepared('census')
   factory.assert_not_called()
  for action in ('on',None,1):
   with self.assertRaises(ValueError):external.prepare(ROOT,{},action)
 def test_exact_57_classpath_and_release_version_binding(self):
  temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);context=AdjacentContext(Path(temporary.name))
  stage=context.root/'.rag_index/android-cli-stages'/context.getter['stageId'];manifest=context.getter['manifest'];raw=(stage/'tree/opt/vpn-control/lib/app/vpn-control.cfg').read_bytes();classpath,options=context.external._configuration(raw,manifest);self.assertEqual(57,len(classpath));self.assertEqual(4,len(options))
  with self.assertRaisesRegex(ValueError,'external_config_changed'):context.external._configuration(raw+b'\n',manifest)
  env,_,_=scope();actual=next(n for n in ast.parse(external._REMOTE.replace('__EXTERNAL__',repr(binding()))).body if isinstance(n,ast.FunctionDef) and n.name=='external_jdk');exec(compile(ast.Module(body=[actual],type_ignores=[]),'<actual-jdk-version>','exec'),env)
  def file(path,limit):return jdk()['files'][external.JDK_FILES[0]],b'JAVA_VERSION="17.0.20.1"\n' if path.endswith('/release') else b''
  env['external_file']=file;self.assertEqual('17.0.20.1',env['external_jdk']('jdk17')['declaredJavaVersion'])
  with self.assertRaisesRegex(ValueError,'external_jdk_version_unknown'):env['external_jdk']('jdk21')

@unittest.skipUnless(os.name=='posix','POSIX descriptor-bound runtime census')
class StreamingTests(unittest.TestCase):
 def test_actual_streaming_hash_no_library_body_retained_and_symlink_shortread_drift(self):
  env,_,_=scope();node=next(n for n in ast.parse(external._REMOTE.replace('__EXTERNAL__',repr(binding()))).body if isinstance(n,ast.FunctionDef) and n.name=='external_file');exec(compile(ast.Module(body=[node],type_ignores=[]),'<actual-streaming-jdk>','exec'),env)
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);path=root/'modules';raw=b'm'*1048576;path.write_bytes(raw);path.chmod(0o644)
   def parent(p):return [{'fd':os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)}],p.name
   def fp(info):return [info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_mode,0,0,info.st_nlink]
   env.update(parent_fds=parent,guard_parents=lambda _:None,close_parents=lambda c:os.close(c[-1]['fd']),fp=fp,os=os,stat=stat,hashlib=hashlib)
   fact,retained=env['external_file'](str(path),2097152);self.assertEqual(b'',retained);self.assertEqual(hashlib.sha256(raw).hexdigest(),fact['sha256'])
   alias=root/'alias';alias.symlink_to(path)
   with self.assertRaises(OSError):env['external_file'](str(alias),2097152)
   with mock.patch.object(os,'read',return_value=b''):
    with self.assertRaisesRegex(ValueError,'external_jdk_short_read'):env['external_file'](str(path),2097152)
   original=os.read;changed=[False]
   def read(fd,size):
    part=original(fd,size)
    if not changed[0]:changed[0]=True;os.utime(path,None)
    return part
   with mock.patch.object(os,'read',side_effect=read):
    with self.assertRaisesRegex(ValueError,'external_jdk_generation_changed'):env['external_file'](str(path),2097152)

class FactoryTests(unittest.TestCase):
 def prepared(self,action):
  temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);context=AdjacentContext(Path(temporary.name))
  return context.external_prepared(action)
 def test_forged_census_path_schema_source_and_crossed_generation_reject(self):
  _,b,proof=self.prepared('census');self.assertEqual(jdk(),external._selected(proof,b))
  for key,value in (('sourceSha256','f'*64),('generation',{}),('censusComplete',1)):
   changed=copy.deepcopy(proof);changed[key]=value
   with self.assertRaises(ValueError):external._selected(changed,b)
  for mutate in (lambda r:r.update(root='/arbitrary/java'),lambda r:r['files']['bin/java']['generation'].__setitem__(5,stat.S_IFREG|0o644),lambda r:r['files']['release'].update(privateKey='forged')):
   changed=copy.deepcopy(proof);mutate(changed['candidates']['jdk17'])
   with self.assertRaises(ValueError):external._selected(changed,b)
 def test_actual_complete_census_and_compare_prefix_tail(self):
  for action in ('census','compare'):
   p,_,_=self.prepared(action);tree=ast.parse(p['program']);emitted=[]
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
   for fail in (None,'tail'):
    emitted.clear()
    def install(ns):
     env,_,_=scope(action);proxy=types.SimpleNamespace(**vars(os));proxy.getuid=lambda:0;proxy.geteuid=lambda:0;proxy.open=lambda *a,**k:8;proxy.close=lambda _:None
     info=types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o600,st_nlink=1);rootinfo=types.SimpleNamespace(st_uid=1000,st_mode=stat.S_IFDIR|0o700);proxy.fstat=lambda fd:rootinfo if fd==7 else info;proxy.stat=lambda *a,**k:info;checks=[0]
     def guard(_):
      checks[0]+=1
      if fail=='tail' and checks[0]==4:raise ValueError('tail_changed')
     ns.update({k:env[k] for k in ('getter_generation','getter_stage','external_cli','external_census','external_jdk_guard')});ns.update(getter_apk=lambda:ns['GETTER']['packageSha256'],ROOT=Root(),os=proxy,parent_fds=lambda _:([{'fd':7,'pin':pin}],None),guard_parents=guard,close_parents=lambda _:None,fp=lambda _:pin,journal_read=lambda *a:ns['LAUNCH']['intent'],fcntl=types.SimpleNamespace(LOCK_EX=1,LOCK_NB=2,flock=lambda *a:None),print=lambda line:emitted.append(json.loads(line)))
    host={'HOST_INSTALL':install,'HOST_HISTORY':lambda ns:ns.update(read_fixed=lambda *a:{**ns['CFG']['failedCensus']['pin'],'raw':b''}),'HOST_ALIAS':lambda:None}
    if fail:
     with self.assertRaises(ValueError):exec(compile(ast.fix_missing_locations(tree),'<actual-external-component>','exec'),host)
     self.assertEqual([],emitted)
    else:
     exec(compile(ast.fix_missing_locations(tree),'<actual-external-component>','exec'),host);self.assertEqual(1,len(emitted));self.assertEqual(action=='compare',emitted[0]['componentFlowObserved']);self.assertEqual(action=='census',emitted[0]['censusComplete']);self.assertFalse(emitted[0]['installedLauncherAccepted'])
