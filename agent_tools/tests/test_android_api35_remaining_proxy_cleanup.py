"""Generated remaining cleanup: real journal FDs, exact fixed effect sequence."""
import ast,base64,hashlib,json,os,stat,tempfile,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import android_api35_remaining_proxy_cleanup as cleanup
from agent_tools.tests import test_android_api35_partial_proxy_diagnostic as partial
from agent_tools.tests import test_android_api35_current_proxy_probe as probes
from agent_tools.tests import test_android_api35_coldboot_product_observation as products
ROOT=Path(__file__).resolve().parents[2]

class RemainingTests(unittest.TestCase):
 def setUp(self):
  from agent_tools.tests.fixtures.android_api35_historical_context import install
  from agent_tools.tests import test_android_api35_owned_proxy_restore as restored
  install(self,globals(),'cleanup')
  self.history.remaining_context(cleanup)
  for target,name,value in ((partial,'ROOT',ROOT),(partial,'diagnostic',cleanup.diagnostic),(partial,'OWNER',cleanup.OWNER),(restored,'restore',cleanup.diagnostic.original),(restored,'coldboot',self.history.modules['coldboot']),(probes,'probe',cleanup.diagnostic.original.current)):
   patch=mock.patch.object(target,name,value);patch.start();self.addCleanup(patch.stop)
 def prepared(self,action='admit',correlation=None):
  self.assertTrue((ROOT/'.runtime/parity-evidence'/cleanup.PROOF_CAPSULE/'diagnostic-remote-stdout-0.private').exists(),'owned synthetic historical fixture is incomplete')
  temporary=tempfile.TemporaryDirectory();root=ROOT;correlation=correlation or str(uuid.uuid4());writer=cleanup._local_write;snapshot=cleanup.availability._snapshot
  def local(path,value,prepared):return writer(root/'.rag_index'/cleanup.SCOPE/correlation/Path(path).name,value,prepared)
  def read(path):
   path=Path(path)
   if cleanup.SCOPE in path.parts:path=root/'.rag_index'/cleanup.SCOPE/correlation/path.name
   return snapshot(path)
  with mock.patch.object(cleanup,'_local_write',side_effect=local),mock.patch.object(cleanup.availability,'_snapshot',side_effect=read):
   prepared=cleanup.admit(ROOT,products.CompositionTests().reservation(),correlation)
  return temporary,root,prepared,local,read
 def flow(self,fail_step=None,owner_drift=None,replay=False):
  temporary,localroot,prepared,local,read=self.prepared();tree=ast.parse(prepared['program'])
  observed=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='observed_getter');observed.name='remaining_observed_actual';observed.body.insert(0,ast.parse('os.fixture_hook(globals())').body[0])
  wrapper=ast.parse("""
def observed_getter(directory):
 admission=remaining_observed_actual(directory)
 if admission['state']!='remaining-admitted':return admission
 REMAINING['controllerId']=admission['currentControllerId'];REMAINING['admissionPin']={k:admission['result']['record'][k] for k in ('generation','sha256')};REMAINING['action']='restore'
 restored=remaining_observed_actual(directory)
 if restored['state']!='remaining-proxy-restored':return restored
 if os.fixture_replay:
  replayed=remaining_observed_actual(directory)
  return {'state':restored['state'],'replay':replayed,'records':restored['records']}
 REMAINING['action']='status';return remaining_observed_actual(directory)
""").body
  tree.body[-1:-1]=wrapper;prepared['program']=ast.unparse(ast.fix_missing_locations(tree))+'\n'
  fake=probes.fake_root_os;effects=[];rows=dict(cleanup.ROWS);hooked=set();proof=prepared['remainingBinding']['originalJournal']
  def root_os():
   proxy,Directory,fp=fake();proxy.fixture_replay=replay
   oldstat=proxy.stat;oldfstat=proxy.fstat
   def pin(info):
    # Native immutable original effect pin; only the OS fixture principal/inode ABI differs.
    try:known=json.loads((ROOT/'.runtime/parity-evidence'/cleanup.PROOF_CAPSULE/'diagnostic-remote-stdout-0.private').read_bytes())['result']['journalAfter']['effect-fence.json']
    except Exception:return info
    if info.st_size==known['generation'][2] and stat.S_ISREG(info.st_mode):
     for k,v in zip(('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_uid','st_gid','st_nlink'),known['generation']):setattr(info,k,v)
    return info
   proxy.stat=lambda *a,**kw:pin(oldstat(*a,**kw));proxy.fstat=lambda fd:pin(oldfstat(fd))
   def hook(ns):
    if id(ns) in hooked:return
    hooked.add(id(ns));reader=ns['probe_read'];cli=ns['getter_cli']
    def current_cli(words,owner=None):
     result=cli(words,owner)
     if owner_drift is not None and len(effects)>=owner_drift:result['stdout']['controllerId']='7bc37753-dc54-44c2-bc3a-899b9067a83b'
     return result
    def device(case):
     mode=case['mode']
     if mode.startswith('partial-settings'):return probes.reply((''.join(k+'='+v+'\n' for k,v in sorted(rows.items()))).encode())
     if mode.startswith('remaining-effect-'):
      index=int(mode.rsplit('-',1)[1]);self.assertEqual(ns['remaining_delete'](index),case['command']);effects.append(cleanup.KEYS[index])
      if fail_step==index:return probes.reply(b'',code=1)
      del rows[cleanup.KEYS[index]];return probes.reply(b'')
     return reader(case)
    ns.update(probe_read=device,getter_cli=current_cli)
   proxy.fixture_hook=hook;return proxy,Directory,fp
  try:
   with mock.patch.object(partial.diagnostic,'prepare',return_value=prepared),mock.patch.object(probes,'fake_root_os',side_effect=root_os):
    tmp,value,calls,before,after=partial.PartialTests().full()
   return tmp,value,effects,before,after
  finally:temporary.cleanup()
 def test_actual_generated_admit_three_deletes_terminal_status(self):
  tmp,value,effects,before,after=self.flow()
  try:
   self.assertEqual('remaining-proxy-restored',value['state'],(value.get('primaryReason'),value.get('closingReason')))
   self.assertEqual(list(cleanup.KEYS),effects);self.assertTrue(value['closingGuardsVerified']);self.assertFalse(value['pacEffectSubmitted'])
   self.assertNotIn('terminal.json',after);self.assertTrue({'remaining-admission.json','remaining-effect-fence.json','remaining-terminal.json'}<=set(after))
   for name,raw in before.items():self.assertEqual(raw,after[name])
  finally:tmp.cleanup()

 def test_partial_effect_failure_stops_and_preserves_original_unknown(self):
  tmp,value,effects,before,after=self.flow(fail_step=1)
  try:
   self.assertEqual('unknown',value['state']);self.assertEqual(list(cleanup.KEYS[:2]),effects)
   self.assertIn('remaining-effect-fence.json',after);self.assertNotIn('remaining-terminal.json',after);self.assertNotIn('terminal.json',after)
   for name,raw in before.items():self.assertEqual(raw,after[name])
  finally:tmp.cleanup()
 def test_owner_drift_after_one_effect_prevents_remaining_effects(self):
  tmp,value,effects,before,after=self.flow(owner_drift=1)
  try:
   self.assertEqual('unknown',value['state']);self.assertEqual('partial_public_owner_changed',value['primaryReason']);self.assertEqual(list(cleanup.KEYS[:1]),effects);self.assertNotIn('remaining-terminal.json',after)
  finally:tmp.cleanup()
 def test_completed_effect_fence_cannot_replay(self):
  tmp,value,effects,before,after=self.flow(replay=True)
  try:self.assertEqual('unknown',value['replay']['state']);self.assertEqual(list(cleanup.KEYS),effects)
  finally:tmp.cleanup()
 def test_actual_local_prepare_retain_restore_status_and_duplicate_fence(self):
  temporary,root,prepared,local,read=self.prepared();authority=prepared['remainingBinding']['authority'];owner=partial.OWNER
  expected={'schema':1,'binding':authority,'currentControllerId':owner,'originalOperationOutcome':'unknown','replayAllowed':False};raw=(json.dumps(expected,sort_keys=True,separators=(',',':'))+'\n').encode()
  record={'value':expected,'generation':[66307,109000001,len(raw),1791073500000000000,1791073500000000000,33152,0,0,1],'sha256':hashlib.sha256(raw).hexdigest()}
  response=json.dumps({'state':'remaining-admitted','correlationId':authority['correlationId'],'closingGuardsVerified':True,'historicalUnknownsPreserved':True,'replayAllowed':False,'originalOperationOutcome':'unknown','currentControllerId':owner,'result':{'record':record}}).encode()
  try:
   with mock.patch.object(cleanup,'_local_write',side_effect=local),mock.patch.object(cleanup.availability,'_snapshot',side_effect=read):
    cleanup.retain_admission(ROOT,prepared,response)
    effect=cleanup.restore_once(ROOT,products.CompositionTests().reservation(),authority['correlationId'])
    self.assertEqual(owner,effect['remainingBinding']['controllerId']);self.assertEqual(record['generation'],effect['remainingBinding']['admissionPin']['generation'])
    self.assertTrue((root/'.rag_index'/cleanup.SCOPE/authority['correlationId']/'effect-fence.json').is_file())
    observed=cleanup.status(ROOT,products.CompositionTests().reservation(),authority['correlationId']);self.assertEqual('status',observed['remainingAction'])
    with self.assertRaises(FileExistsError):cleanup.restore_once(ROOT,products.CompositionTests().reservation(),authority['correlationId'])
    with self.assertRaises(FileExistsError):cleanup.retain_admission(ROOT,prepared,response)
  finally:temporary.cleanup()
 def test_narrow_proof_fd_reader_large_receipt_and_symlink_refusal_routine(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t).resolve();parent=root/'.runtime/parity-evidence'/cleanup.PROOF_CAPSULE;parent.mkdir(parents=True,mode=0o700)
   path=parent/'diagnostic-remote-stdout-0.private';raw=b'x'*286940;path.write_bytes(raw);path.chmod(0o600)
   pin,data=cleanup._proof_snapshot(root);self.assertEqual(raw,data);self.assertEqual(len(raw),pin[2])
   outside=parent/'saved';path.rename(outside);path.symlink_to(outside)
   with self.assertRaises(OSError):cleanup._proof_snapshot(root)
 def test_local_fd_writer_create_only_and_unsafe_parent_routine(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t).resolve();path=root/'.rag_index'/cleanup.SCOPE/str(uuid.uuid4())/'intent.json';prepared={'snapshots':{}}
   cleanup._local_write(path,{'originalOutcome':'unknown'},prepared)
   self.assertEqual({'originalOutcome':'unknown'},json.loads(path.read_bytes()));self.assertEqual(0o600,stat.S_IMODE(path.stat().st_mode))
   with self.assertRaises(FileExistsError):cleanup._local_write(path,{},prepared)
   other=root/'other';other.mkdir();link=root/'link';link.symlink_to(other,target_is_directory=True)
   unsafe=link/'.rag_index'/cleanup.SCOPE/str(uuid.uuid4())/'intent.json'
   with self.assertRaises(OSError):cleanup._local_write(unsafe,{},prepared)
 def test_original_source_change_rejected_before_factory_routine(self):
  snapshot=cleanup.availability._snapshot
  def drift(path):
   pin,raw=snapshot(path)
   if Path(path)==Path(cleanup.diagnostic.__file__).absolute():raw+=b'\n'
   return pin,raw
  with mock.patch.object(cleanup.availability,'_snapshot',side_effect=drift),mock.patch.object(cleanup.diagnostic,'prepare') as factory:
   with self.assertRaisesRegex(ValueError,'remaining_diagnostic_source_changed'):cleanup.admit(ROOT,{},str(uuid.uuid4()))
   factory.assert_not_called()

 def test_fixed_proof_receipt_exchange_after_prepare_rejects_before_carrier(self):
  temporary,root,prepared,local,read=self.prepared()
  try:
   pin,raw=prepared['remainingProofSnapshot']
   with mock.patch.object(cleanup,'_proof_snapshot',return_value=(pin,raw+b' ')),mock.patch.object(cleanup.availability,'_snapshot',side_effect=read):
    with self.assertRaisesRegex(ValueError,'remaining_proof_changed'):cleanup.carrier(prepared)
  finally:temporary.cleanup()
 def test_source_exchange_after_prepare_rejects_before_carrier(self):
  temporary,root,prepared,local,read=self.prepared()
  try:
   # Mutate the owned source object itself; every actual reader namespace
   # must refuse it, regardless of which availability module owns the call.
   path=Path(cleanup.__file__).absolute();self.assertTrue(path.is_relative_to(ROOT))
   path.write_bytes(path.read_bytes()+b'\n')
   with self.assertRaisesRegex(ValueError,'census_local_source_changed'):cleanup.carrier(prepared)
  finally:temporary.cleanup()
 def test_unsafe_proof_capsule_rejected_routine(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t).resolve();parent=root/'.runtime/parity-evidence'/cleanup.PROOF_CAPSULE;parent.mkdir(parents=True,mode=0o700)
   path=parent/'diagnostic-remote-stdout-0.private';path.write_bytes(b'{}');path.chmod(0o600);parent.chmod(0o777)
   with self.assertRaisesRegex(ValueError,'remaining_proof_capsule_unsafe'):cleanup._proof_snapshot(root)

class RoutineRemainingTests(unittest.TestCase):
 """Tracked remote functions, real metadata FDs; only Android readers inert."""
 def fixture(self):
  from agent_tools.tests import test_android_api35_owned_proxy_restore as restored
  temporary=tempfile.TemporaryDirectory();root=Path(temporary.name).resolve();directory=root/'original-journal';directory.mkdir(mode=0o700)
  proxy,Directory,fp=probes.fake_root_os();Directory(root);Directory(directory)
  env=restored.RestoreTests().scope()
  def parents(path):
   fd=os.open(path.parent,os.O_RDONLY);return ([{'fd':fd,'pin':fp(proxy.fstat(fd)),'path':path.parent}],path.name)
  def guards(chain):
   for item in chain:
    self.assertEqual(item['pin'],fp(proxy.fstat(item['fd'])));self.assertEqual(item['pin'],fp(proxy.stat(item['path'])))
  env.update(os=proxy,fp=fp,parent_fds=parents,guard_parents=guards,close_parents=lambda c:[os.close(i['fd']) for i in c],restore_journal=lambda d:directory,GETTER_RECORDS={},PROBE_CASES=[],probe_fence_guard=lambda d,p:None)
  diagnostic=cleanup.diagnostic
  exec(diagnostic._REMOTE.replace('__PARTIAL__',repr({'correlationId':'inert-only'})),env)
  # Make authenticated original history with actual real-file generations.
  original=env['RESTORE'];before=fp(proxy.stat(root));before[8]-=1;after=list(before);after[8]+=1
  original['stageFence']={'parentGeneration':before,'parentInventory':[]}
  arm={'schema':1,'binding':original['authority'],'sourceSha256':original['sourceSha256'],'correlationId':original['correlationId'],'replayAllowed':False,'stageFence':{'parentGeneration':after,'parentInventory':[directory.name]},'journalIdentity':{str(n):fp(proxy.stat(directory))[n] for n in (0,1,5,6,7,8)}}
  def write(name,value):
   path=directory/name;path.write_bytes((json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode());path.chmod(0o600)
   return {'generation':fp(proxy.stat(path)),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
  arm_pin=write('arm.json',arm)
  operation={'correlationId':'66f5e1d4-114c-4e05-8b53-cc64e92563bf','sourceSha256':original['sourceSha256'],'originalArmPin':arm_pin}
  original['readmission']=operation
  original['readmissionPin']=write('readmission.json',{'schema':1,'operation':operation,'originalArmPin':arm_pin,'originalOutcome':'unknown','replayAllowed':False})
  initial={'settings':{'rows':dict(env['RESTORE_OWNED']),'values':dict(env['RESTORE_OWNED'])},'kind':'owned'}
  write('effect-fence.json',{'schema':1,'correlationId':operation['correlationId'],'sourceSha256':operation['sourceSha256'],'armPin':arm_pin,'readmissionPin':original['readmissionPin'],'effect':'owned-global-proxy-restore','replayAllowed':False,'initial':initial})
  journal=env['partial_journal'](None);binding={'action':'admit','authority':{'correlationId':str(uuid.uuid4()),'initialRows':dict(cleanup.ROWS)},'controllerId':None,'originalJournal':journal}
  # Same closed factory edits as prepare; no fabricated read/write receipt.
  tree=ast.parse(diagnostic._REMOTE.replace('__PARTIAL__','{}'))
  functions=[]
  for node in tree.body:
   if isinstance(node,ast.FunctionDef) and node.name=='partial_record':
    for child in ast.walk(node):
     if isinstance(child,ast.Tuple) and all(isinstance(x,ast.Constant) for x in child.elts) and ast.literal_eval(child)==('arm.json','readmission.json','effect-fence.json','terminal.json'):
      child.elts += [ast.Constant(x) for x in ('remaining-admission.json','remaining-effect-fence.json','remaining-terminal.json')]
    functions.append(node)
   elif isinstance(node,ast.FunctionDef) and node.name=='partial_journal':
    for i,statement in enumerate(node.body):
     if isinstance(statement,ast.If) and ast.unparse(statement.test)=='names != expected_names':node.body[i]=ast.parse('remaining_inventory(directory,names,expected_names)').body[0]
    functions.append(node)
  exec(compile(ast.fix_missing_locations(ast.Module(body=functions,type_ignores=[])),'<actual-record-and-inventory-composition>','exec'),env)
  exec(cleanup._REMOTE.replace('__REMAINING__',repr(binding)),env)
  rows=dict(cleanup.ROWS);effects=[];public=env['getter_cli'];stage={'current-native-boundary':'inert'}
  def cli(words,owner=None):
   reply=public(words,env['FD_OWNER']);reply['stdout'].update(controllerId=partial.OWNER,schemaVersion=1)
   reply.update(captureComplete=True,stderrRaw='',componentRuntime='EXTERNAL_JDK',backendSourceSha256=original['authority']['componentBackend']['backendSourceSha256']);return reply
  def device(case):
   mode=case['mode']
   if mode.startswith('partial-settings'):return probes.reply((''.join(k+'='+v+'\n' for k,v in sorted(rows.items()))).encode())
   if mode=='partial-binder':
    value=probes.getter_value();value['correlationId']=cleanup.diagnostic.original.PROBE_CORRELATION
    return probes.reply(json.dumps(value).encode())
   if mode.startswith('remaining-effect-'):
    index=int(mode.rsplit('-',1)[1]);self.assertEqual(env['remaining_delete'](index),case['command']);effects.append(cleanup.KEYS[index]);del rows[cleanup.KEYS[index]];return probes.reply(b'')
   raise AssertionError(mode)
  # Hardware/source authority is exercised by the separate full native-proof
  # composition tests; here only that external boundary is inert.
  env.update(getter_stage=lambda:stage,partial_hardware=lambda d,s:self.assertEqual(stage,s),getter_cli=cli,probe_read=device)
  return temporary,directory,env,effects
 def test_actual_admission_inventory_closing_red_then_green_routine(self):
  temporary,directory,env,effects=self.fixture()
  try:
   admitted=env['observed_getter'](None)
   self.assertEqual('remaining-admitted',admitted['state'],(admitted['primaryReason'],admitted['closingReason']));self.assertTrue(admitted['closingGuardsVerified']);self.assertEqual([],effects)
   # Measured old behavior: after own new admission, old inventory predicate
   # refuses the extra filename during closing. Exercise actual guard closure.
   current=env['remaining_inventory'];tree=ast.parse(cleanup._REMOTE.replace('__REMAINING__','{}'));old=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='remaining_inventory')
   old.body=[n for n in old.body if not isinstance(n,ast.If) or 'REMAINING_ADMISSION_WRITTEN' not in ast.unparse(n.test)]
   exec(compile(ast.Module(body=[old],type_ignores=[]),'<actual-old-inventory-predicate>','exec'),env)
   with self.assertRaisesRegex(ValueError,'remaining_inventory_changed'):env['remaining_original'](None)
   env['remaining_inventory']=current;env['remaining_original'](None)
   self.assertNotIn('terminal.json',os.listdir(directory))
  finally:temporary.cleanup()
 def test_actual_once_fence_and_alternate_admission_refusal_routine(self):
  temporary,directory,env,effects=self.fixture()
  try:
   admitted=env['observed_getter'](None);record=admitted['result']['record']
   env['REMAINING'].update(action='restore',controllerId=admitted['currentControllerId'],admissionPin={k:record[k] for k in ('generation','sha256')})
   result=env['observed_getter'](None);self.assertEqual('remaining-proxy-restored',result['state'],(result['primaryReason'],result['closingReason']));self.assertEqual(list(cleanup.KEYS),effects)
   before={p.name:p.read_bytes() for p in directory.iterdir()};again=env['observed_getter'](None)
   self.assertEqual('unknown',again['state']);self.assertEqual(list(cleanup.KEYS),effects)
   env['REMAINING']['action']='admit';env['REMAINING']['authority']['correlationId']=str(uuid.uuid4());alternate=env['observed_getter'](None)
   self.assertEqual('unknown',alternate['state']);self.assertEqual(before,{p.name:p.read_bytes() for p in directory.iterdir()});self.assertNotIn('terminal.json',before)
  finally:temporary.cleanup()
 def test_malformed_new_fence_raw_retained_before_decode_routine(self):
  temporary,directory,env,effects=self.fixture()
  try:
   env['observed_getter'](None);path=directory/'remaining-effect-fence.json';raw=b'{broken fixed effect-fence';path.write_bytes(raw);path.chmod(0o600);env['GETTER_RECORDS']={}
   with self.assertRaises(json.JSONDecodeError):env['partial_record'](None,path.name)
   capture=env['GETTER_RECORDS']['partialRecordCaptures'][0]
   self.assertEqual(raw,base64.b64decode(capture['rawBase64']));self.assertEqual(hashlib.sha256(raw).hexdigest(),capture['sha256']);self.assertEqual(len(raw),capture['bytes']);self.assertTrue(capture['identityGuardVerified']);self.assertEqual([],effects)
  finally:temporary.cleanup()

if __name__=='__main__':unittest.main()
