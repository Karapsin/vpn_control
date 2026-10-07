"""Read-only full dispatcher, real journal FDs, measured absent-PAC/owner fixture."""
import ast,base64,hashlib,json,os,stat,tempfile,unittest,sys,types,subprocess,re,pathlib
from pathlib import Path
from unittest import mock
from agent_tools import android_api35_partial_proxy_diagnostic as diagnostic
from agent_tools.tests import test_android_api35_owned_proxy_restore as restored
from agent_tools.tests import test_android_api35_current_proxy_probe as probes
from agent_tools.tests import test_android_api35_coldboot_product_observation as products
ROOT=Path(__file__).resolve().parents[2]
OWNER='34a12ada-31a6-4653-9f2e-cedfab3b583a'

class PartialTests(unittest.TestCase):
 def setUp(self):
  from agent_tools.tests.fixtures.android_api35_historical_context import install
  install(self,globals(),'diagnostic')
  self.history.partial_context(diagnostic)
  for target,name,value in ((restored,'restore',diagnostic.original),(restored,'coldboot',self.history.modules['coldboot']),(probes,'probe',diagnostic.original.current)):
   patch=mock.patch.object(target,name,value);patch.start();self.addCleanup(patch.stop)
 def full(self,drift=False,record_drift=False,schema_bool=False,actual_apk=False):
  self.assertTrue((ROOT/'.runtime/parity-evidence'/diagnostic.CAPSULE/'admit-remote-stdout-0.private').exists(),'owned synthetic historical fixture is incomplete')
  prepared=diagnostic.prepare(ROOT,products.CompositionTests().reservation());tree=ast.parse(prepared['program'])
  for index in range(len(tree.body)-1,-1,-1):
   text=ast.unparse(tree.body[index])
   if text.startswith('_failed = read_fixed('):tree.body.insert(index,ast.parse('HOST_HISTORY(globals())').body[0])
   elif text=='alias_history_guard()':tree.body.insert(index,ast.parse('alias_history_guard=HOST_ALIAS').body[0])
  tree.body.insert(-1,ast.parse('HOST_INSTALL(globals())').body[0])
  self.assertEqual('coldboot_dispatch()',ast.unparse(tree.body[-1]))
  tmp=tempfile.TemporaryDirectory();shared=Path(tmp.name)/'shared';shared.mkdir(mode=0o700)
  directory=shared/('android-avd-coldboot-'+diagnostic.original.current.admission.original.CORRELATION);probes.journal(directory)
  lock=shared/'android-avd-coldboot-api35.lock';lock.write_bytes(b'');lock.chmod(0o600)
  journal=directory/('proxy-restore-'+diagnostic.original._INTERRUPTED);journal.mkdir(mode=0o700)
  metadata=json.loads((ROOT/'.runtime/parity-evidence'/diagnostic.original._METADATA_CAPSULE/'metadata-remote-stdout-0.private').read_bytes())['result']['record']
  admitted=json.loads((ROOT/'.runtime/parity-evidence'/diagnostic.CAPSULE/'admit-remote-stdout-0.private').read_bytes())['result']['record']
  arm=metadata['value'];admission=admitted['value'];binding=prepared['restoreBinding'];operation=binding['readmission']
  effect={'schema':1,'correlationId':operation['correlationId'],'sourceSha256':operation['sourceSha256'],'readmissionPin':binding['readmissionPin'],'armPin':operation['originalArmPin'],'initial':arm['census'],'effect':'owned-global-proxy-restore','replayAllowed':False}
  for name,value in (('arm.json',arm),('readmission.json',admission),('effect-fence.json',effect)):
   path=journal/name;path.write_bytes((json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode());path.chmod(0o600)
  proxy,Directory,fp=probes.fake_root_os();Directory(shared);original_directory=Directory(directory);Directory(journal)
  original_stat=proxy.stat;original_fstat=proxy.fstat;special={}
  for name,record in (('arm.json',metadata),('readmission.json',admitted)):special[(journal/name).stat().st_ino]=record['generation']
  journal_ino=journal.stat().st_ino;shared_ino=shared.stat().st_ino
  def info(item):
   pin=special.get(item.st_ino)
   if pin is not None:
    for key,value in zip(('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_uid','st_gid','st_nlink'),pin):setattr(item,key,value)
   elif item.st_ino==journal_ino:
    for index,key in ((0,'st_dev'),(1,'st_ino'),(5,'st_mode'),(6,'st_uid'),(7,'st_gid'),(8,'st_nlink')):setattr(item,key,arm['journalIdentity'][str(index)])
   elif item.st_ino==shared_ino:item.st_uid=item.st_gid=1000
   return item
  proxy.stat=lambda *a,**kw:info(original_stat(*a,**kw));proxy.fstat=lambda fd:info(original_fstat(fd))
  def parents(path):
   parent=path.parent;fd=os.open(parent,os.O_RDONLY);return ([{'fd':fd,'pin':fp(proxy.fstat(fd)),'path':parent}],path.name)
  def guards(chain):
   for item in chain:self.assertEqual(item['pin'],fp(proxy.fstat(item['fd'])));self.assertEqual(item['pin'],fp(proxy.stat(item['path'])))
  class Shared:
   def __truediv__(self,name):return original_directory if name==directory.name else shared/name
  env=restored.RestoreTests().scope();emitted=[];calls=[]
  def install(ns):
   ns.update(ROOT=Shared(),os=proxy,fp=fp,parent_fds=parents,guard_parents=guards,close_parents=lambda c:[os.close(x['fd']) for x in c],journal_read=lambda *a:ns['LAUNCH']['intent'],print=lambda line:emitted.append(json.loads(line)))
   # Only device/source filesystem boundaries are inert. New diagnostic and
   # inherited real root dispatcher/lock/journal reader all execute unchanged.
   ns.update(getter_generation=lambda d:None,getter_stage=lambda:{'fixed':'stage'},getter_apk=lambda:ns['GETTER']['packageSha256'],probe_fence_guard=lambda d,p:None)
   def cli(words,owner=None):
    calls.append((words,owner));reply=env['getter_cli'](words,ns['FD_OWNER']);current=OWNER if not drift or len(calls)<4 else '6a4636bc-cb3d-4918-b3ec-5ecb72fbc57c'
    reply['stdout'].update(controllerId=current,schemaVersion=True if schema_bool else 1);reply.update(captureComplete=True,stderrRaw='',componentRuntime='EXTERNAL_JDK',backendSourceSha256=diagnostic.original.COMPONENT_SOURCE)
    return reply
   def read(case):
    mode=case['mode']
    if mode=='partial-dex-generation':
     g=ns['RESTORE']['deviceStageGeneration'];return probes.reply(('\n'.join([g['directory'],g['file'],g['file'],diagnostic.original.DEX_SHA+'  /proc/self/fd/3',g['directory'],g['file'],g['file']])+'\n').encode())
    if mode.startswith('partial-settings'):return probes.reply(b'global_http_proxy_exclusion_list=\nglobal_http_proxy_host=\nglobal_http_proxy_port=0\nhttp_proxy=:0\n')
    if mode=='partial-binder':
     value=probes.getter_value();value['correlationId']=diagnostic.original.PROBE_CORRELATION;return probes.reply(json.dumps(value).encode())
    raise AssertionError(mode)
   ns.update(getter_cli=cli,probe_read=read)
   if actual_apk:
    # Preserve ACTUAL getter_apk/getter_adb/getter_binary and installed bounded
    # capture. Only the native executable ABI and UID transition are inert.
    adb=shared/'adb';adb.write_bytes(b'fixed harmless adb executable fixture');adb.chmod(0o700)
    ns['LAUNCH']['adbPath']=str(adb);ns['LAUNCH']['adbFacts']['generation']=fp(proxy.stat(adb))
    # Device executable boundary only: actual inherited APK reader and
    # bounded PIPE capture still consume a real harmless child's bytes.
    apk_path='/data/app/synthetic/com.kardinal.vpncontrol/base.apk';pm='package:'+apk_path+'\n'
    transport=types.SimpleNamespace(**vars(ns['subprocess']))
    def popen(argv,**kwargs):
     self.assertEqual(argv[1:3],['-s','emulator-5682'])
     if argv[3:]==['shell','-T','pm','path','com.kardinal.vpncontrol']:raw=pm
     else:
      self.assertEqual(argv[3:],['shell','-T','sha256sum',apk_path]);raw=ns['GETTER']['packageSha256']+'  '+apk_path+'\n'
     kwargs.pop('preexec_fn',None);kwargs['executable']=sys.executable;kwargs['env']={k:v for k,v in os.environ.items() if k!='DYLD_INSERT_LIBRARIES'}
     return subprocess.Popen([sys.executable,'-I','-c','import sys;sys.stdout.write('+repr(raw)+')'],**kwargs)
    transport.Popen=popen;ns['subprocess']=transport
    # Undo ONLY the earlier generic fixture shortcut for this ABI regression.
    actual=next(n for n in ast.parse(prepared['program']).body if isinstance(n,ast.FunctionDef) and n.name=='getter_apk')
    exec(compile(ast.Module(body=[actual],type_ignores=[]),'<actual-generated-getter-apk>','exec'),ns)

   if record_drift:
    path=journal/'effect-fence.json';value=json.loads(path.read_bytes());value['correlationId']='foreign';path.write_text(json.dumps(value));path.chmod(0o600)
  bindings={'HOST_INSTALL':install,'HOST_HISTORY':lambda ns:ns.update(read_fixed=lambda *a:{**ns['CFG']['failedCensus']['pin'],'raw':b''}),'HOST_ALIAS':lambda:None}
  before={p.name:p.read_bytes() for p in journal.iterdir()}
  exec(compile(ast.fix_missing_locations(tree),'<complete-partial-prefix-tail>','exec'),bindings)
  self.assertEqual(1,len(emitted));after={p.name:p.read_bytes() for p in journal.iterdir()}
  return tmp,emitted[0],calls,before,after
 def test_measured_pac_absence_classified_without_restore_or_owner_adoption(self):
  old=restored.RestoreTests().scope();census={'settings':{'values':{'http_proxy':':0','global_http_proxy_host':'','global_http_proxy_port':'0','global_http_proxy_pac':'null','global_http_proxy_exclusion_list':''}},'kind':'clear'}
  with self.assertRaisesRegex(ValueError,'restore_proxy_changed'):old['restore_expected'](census,old['RESTORE_NORMAL'],'clear')
  tmp,value,calls,before,after=self.full()
  try:
   self.assertTrue(value['observationComplete'],value['reason']);self.assertTrue(value['pacAbsent']);self.assertTrue(value['effectiveProxyClear'])
   self.assertFalse(value['historicalOwnerMatchesCurrent']);self.assertEqual(OWNER,value['currentControllerId'])
   self.assertFalse(value['readmissionGranted']);self.assertFalse(value['settingsEffectsSubmitted']);self.assertEqual(before,after)
   self.assertFalse(value['result']['journalAfter']['terminal.json']['present'])
  finally:tmp.cleanup()
 def test_changed_owner_rejection_preserves_primary_and_closing_separately(self):
  tmp,value,calls,before,after=self.full(drift=True)
  try:
   self.assertFalse(value['observationComplete']);self.assertEqual('partial_public_owner_changed',value['primaryReason']);self.assertEqual('partial_public_owner_changed',value['closingReason']);self.assertEqual(before,after)
  finally:tmp.cleanup()
 def test_effect_lineage_drift_stays_diagnostic_and_no_effects(self):
  tmp,value,calls,before,after=self.full(record_drift=True)
  try:self.assertFalse(value['observationComplete']);self.assertEqual('partial_effect_changed',value['primaryReason']);self.assertFalse(value['settingsEffectsSubmitted'])
  finally:tmp.cleanup()
 def test_measured_historical_owner_guard_rejects_new_owner_without_ordering_claim(self):
  env=restored.RestoreTests().scope();record=env['getter_cli'](['status'],env['FD_OWNER']);record['stdout']['controllerId']=OWNER
  with self.assertRaisesRegex(ValueError,'fd_probe_public_owner_unavailable'):env['fd_guard_reply'](record,'status')
 def test_boolean_schema_is_unknown_not_positive(self):
  tmp,value,calls,before,after=self.full(schema_bool=True)
  try:self.assertFalse(value['observationComplete']);self.assertEqual('partial_public_schema_unknown',value['primaryReason']);self.assertEqual(before,after)
  finally:tmp.cleanup()
 def test_actual_apk_suffix_abi_full_prefix_and_capture(self):
  tmp,value,calls,before,after=self.full(actual_apk=True)
  try:
   self.assertTrue(value['observationComplete'],value['reason']);self.assertEqual(before,after)
   self.assertIn('packagePathCurrent',value['records']);self.assertIn('packageHashCurrent',value['records'])
   self.assertTrue(value['records']['captures']);self.assertFalse(value['settingsEffectsSubmitted'])
  finally:tmp.cleanup()
 def test_apk_suffix_abi_routine_without_private_native_evidence(self):
  from agent_tools import android_api35_coldboot_product_observation as tracked
  functions=[n for n in ast.parse(tracked._GETTER.replace('__GETTER__','{}')).body if isinstance(n,ast.FunctionDef) and n.name in ('getter_adb','getter_apk')]
  hardware=next(n for n in ast.parse(diagnostic._REMOTE.replace('__PARTIAL__','{}')).body if isinstance(n,ast.FunctionDef) and n.name=='partial_hardware')
  pattern=next(n.value for n in ast.walk(functions[1]) if isinstance(n,ast.Constant) and isinstance(n.value,str) and n.value.startswith('/data/app/'))
  apk=next(path for path in ('/data/app/fixture/base.apk','/data/app/fixture/base\\.apk') if re.fullmatch(pattern,path))
  expected='a'*64;calls=[]
  def binary(path,generation,args,environment):
   calls.append(args)
   if args[2:]==['shell','-T','pm','path','com.kardinal.vpncontrol']:raw='package:'+apk+'\n'
   else:self.assertEqual(args[2:],['shell','-T','sha256sum',apk]);raw=expected+'  '+apk+'\n'
   child=subprocess.run([sys.executable,'-I','-c','import sys;sys.stdout.write('+repr(raw)+')'],capture_output=True,timeout=10,env={k:v for k,v in os.environ.items() if k!='DYLD_INSERT_LIBRARIES'})
   return {'returncode':child.returncode,'stdoutRaw':child.stdout.decode(),'stderrRaw':child.stderr.decode()}
  namespace={'pathlib':pathlib,'re':re,'GETTER_APK_PASS':True,'GETTER_RECORDS':{},'GETTER':{'packageSha256':expected},'LAUNCH':{'adbPath':'/fixed/source-admitted/adb','adbFacts':{'generation':[]},'environment':{}},'getter_binary':binary,'getter_generation':lambda d:None,'getter_stage':lambda:{},'restore_read':lambda *a:{},'probe_generation_command':lambda:'fixed-read-only','probe_generation':lambda r:{},'RESTORE':{'deviceStageGeneration':{}}}
  exec(compile(ast.Module(body=functions+[hardware],type_ignores=[]),'<tracked-current-apk-abi-routine>','exec'),namespace)
  namespace['partial_hardware'](None,{})
  self.assertEqual('Current',namespace['GETTER_APK_PASS']);self.assertIn('packagePathCurrent',namespace['GETTER_RECORDS']);self.assertIn('packageHashCurrent',namespace['GETTER_RECORDS']);self.assertEqual(2,len(calls))
 def test_malformed_real_fd_record_retains_bytes_before_json_parse(self):
  env=restored.RestoreTests().scope();exec(diagnostic._REMOTE.replace('__PARTIAL__',repr({'correlationId':'inert'})),env)
  with tempfile.TemporaryDirectory() as tmp:
   directory=Path(tmp);raw=b'{malformed measured effect record';path=directory/'effect-fence.json';path.write_bytes(raw);path.chmod(0o600)
   proxy,Directory,fp=probes.fake_root_os();Directory(directory)
   def parents(path):
    fd=os.open(path.parent,os.O_RDONLY);return ([{'fd':fd,'pin':fp(proxy.fstat(fd)),'path':path.parent}],path.name)
   def guards(chain):
    for item in chain:self.assertEqual(item['pin'],fp(proxy.fstat(item['fd'])));self.assertEqual(item['pin'],fp(proxy.stat(item['path'])))
   env.update(os=proxy,fp=fp,parent_fds=parents,guard_parents=guards,close_parents=lambda c:[os.close(i['fd']) for i in c],restore_journal=lambda d:directory,GETTER_RECORDS={})
   with self.assertRaises(json.JSONDecodeError):env['partial_record'](directory,'effect-fence.json')
   captures=env['GETTER_RECORDS'].get('partialRecordCaptures',[])
   self.assertEqual(1,len(captures));capture=captures[0]
   self.assertEqual(raw,base64.b64decode(capture['rawBase64']));self.assertEqual(hashlib.sha256(raw).hexdigest(),capture['sha256']);self.assertEqual(fp(proxy.stat(path)),capture['generation']);self.assertTrue(capture['captureComplete']);self.assertTrue(capture['identityGuardVerified'])
 def test_source_admitted_before_original_factory(self):
  snapshot=diagnostic.availability._snapshot
  def drift(path):
   pin,raw=snapshot(path)
   if Path(path)==Path(diagnostic.original.__file__).absolute():raw+=b'\n'
   return pin,raw
  with mock.patch.object(diagnostic.availability,'_snapshot',side_effect=drift),mock.patch.object(diagnostic.original,'readmission_status') as factory:
   with self.assertRaisesRegex(ValueError,'partial_original_source_changed'):diagnostic.prepare(ROOT,{})
   factory.assert_not_called()
 def test_actual_composition_has_no_setting_effect_call_or_unbound_global(self):
  self.assertTrue((ROOT/'.runtime/parity-evidence'/diagnostic.CAPSULE/'admit-remote-stdout-0.private').exists(),'owned synthetic historical fixture is incomplete')
  prepared=diagnostic.prepare(ROOT,products.CompositionTests().reservation());tree=ast.parse(prepared['program']);names={n.name for n in tree.body if isinstance(n,ast.FunctionDef)}
  self.assertTrue({'partial_record','partial_journal','partial_census','observed_getter'}<=names)
  self.assertFalse({'restore_transaction','restore_fixed_step','restore_arm','restore_readmission_admit','restore_record'}&names)
  self.assertEqual('coldboot_dispatch()',ast.unparse(tree.body[-1]))

if __name__=='__main__':unittest.main()
