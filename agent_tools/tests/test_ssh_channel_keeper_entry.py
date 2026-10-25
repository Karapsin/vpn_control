"""Source/local controls only, real TempFS/OS child, synthetic channel reply."""
import base64,builtins,contextlib,hashlib,io,json,os,subprocess,sys,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools.tests import test_ssh_fresh_nested_channel as channel_fixtures
from agent_tools import (private_inventory_lock as private, ssh_fresh_nested_channel as channel,
                        ssh_channel_keeper as core, ssh_channel_keeper_entry as entry,
                        mcp_server as server)
REPO=Path(entry.__file__).resolve().parents[1]
ORIGINAL_PRODUCER_SHA='a306827faef4dcdc28c49fc757056dfc8f61c1729b55857594187f6ad18a791f'
@unittest.skipUnless(os.name=='posix' and hasattr(os,'O_NOFOLLOW') and hasattr(os,'getsid'),
                     'POSIX held custody, exact local process identity and OS flock')
class KeeperEntryTests(unittest.TestCase):
 def setUp(self):
  self.f=channel_fixtures.FreshChannelTests('runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
  self.root=self.f.root;self.now=0.;self.emitted=[]
  self.server=server
  folder=self.root/'agent_tools';folder.mkdir();(folder/'__init__.py').write_text('')
  # The keeper is original-only: its immutable fixed UID/boot and global journal
  # belong to the complete captured pre-namespace producer, not today's generic
  # new-channel producer. Execute genuine old bytes and compute their real hash.
  fixture=Path(__file__).parent/'fixtures/keeper_legacy_original'
  raw=(fixture/'provider.before.source').read_bytes()
  provenance=json.loads((fixture/'provenance.json').read_bytes())
  self.assertEqual(ORIGINAL_PRODUCER_SHA,provenance['sourceSha256'])
  self.assertEqual(ORIGINAL_PRODUCER_SHA,hashlib.sha256(raw).hexdigest())
  for name in entry.NAMES:
   body=raw if name=='ssh_fresh_nested_channel.py' else (REPO/'agent_tools'/name).read_bytes()
   if name=='ssh_channel_keeper_entry.py' and getattr(self,'before_entry',None) is not None:body=self.before_entry
   (folder/name).write_bytes(body)
  replacements={}
  def load(stem):
   source=folder/(stem+'.py');name='agent_tools._keeper_fixture_'+uuid.uuid4().hex
   module=types.ModuleType(name);module.__package__='agent_tools';module.__file__=str(source)
   def importing(name,globals=None,locals=None,fromlist=(),level=0):
    if name=='' and level==1:
     package=builtins.__import__(name,globals,locals,fromlist,level)
     return types.SimpleNamespace(**{item:replacements.get(item,getattr(package,item)) for item in fromlist})
    return builtins.__import__(name,globals,locals,fromlist,level)
   module.__builtins__={**vars(builtins),'__import__':importing};sys.modules[name]=module
   self.addCleanup(sys.modules.pop,name,None)
   exec(compile(source.read_bytes(),str(source),'exec'),module.__dict__)
   replacements[stem]=module;return module
  self.provider=load('ssh_fresh_nested_channel');self.core=load('ssh_channel_keeper');self.entry=load('ssh_channel_keeper_entry')
  self.assertEqual(provenance['sourceSha256'],self.provider._source())
  self.assertIs(self.provider,self.core.original);self.assertIs(self.provider,self.entry.channel)
  self.assertIs(self.core,self.entry.core);self.assertEqual(self.provider._source(),self.core.SOURCE_SHA)
  # Only existing fixture IO points at the original provider. Product source,
  # receipt authority, generated remote programme and manifest pins stay real.
  for obj,name,value in [(channel_fixtures,'channel',self.provider),
                         (server,'REPO_ROOT',self.root),(server,'AGENT_TEST_PYTHON',sys.executable)]:
   patch=mock.patch.object(obj,name,value);patch.start();self.addCleanup(patch.stop)
  self.f.stdout=json.dumps(self.f.ready_fixture()).encode();self.f.rc=0
  with mock.patch.object(self.provider.subprocess,'Popen',side_effect=self.consumer):self.ready=self.provider.prepare(self.root,'archlinux',self.f.corr)
  self.assertEqual('ready',self.ready['state']);self.receipt=self.ready['receiptSha256']
  self.source=self.entry.source_snapshot(self.root,self.f.corr)['sourceManifestSha256']
 def test_original_fixture_manifest_uses_executed_captured_producer(self):
  fixture=Path(__file__).parent/'fixtures/keeper_legacy_original'
  digest=ORIGINAL_PRODUCER_SHA
  self.assertEqual(digest,hashlib.sha256((fixture/'provider.before.source').read_bytes()).hexdigest())
  self.assertEqual(digest,self.provider._source());self.assertEqual(digest,self.core.SOURCE_SHA)
  self.assertIs(self.provider,self.entry.channel);self.assertIs(self.provider,self.core.original)
  manifest=json.loads(self.entry.source_path(self.root,self.f.corr).read_bytes())
  path=self.root/'agent_tools/ssh_fresh_nested_channel.py'
  self.assertEqual(digest,manifest['inputs'][str(path)]['sha256'])
  self.assertEqual(digest,hashlib.sha256(path.read_bytes()).hexdigest())
  self.assertEqual(self.root/'.rag_index/ssh-fresh-nested-channel',self.provider._journal(self.root,False))
  with contextlib.ExitStack() as stack:
   guard=self.core.bind_receipt(self.root,self.f.corr,self.receipt,stack);guard()
 def test_original_keeper_rejects_changed_arch_identity_with_valid_receipt_hash(self):
  path=self.provider._journal(self.root,False)/(self.f.corr+'.ready.json')
  original=path.read_bytes()
  for key,value in [('uid',self.provider.EXPECTED_UID+1),('boot',str(uuid.uuid4()))]:
   changed=json.loads(original);changed['result']['arch'][key]=value
   raw=json.dumps(changed,sort_keys=True,separators=(',',':')).encode();path.write_bytes(raw)
   receipt=hashlib.sha256(raw).hexdigest()
   with self.subTest(field=key),contextlib.ExitStack() as stack,self.assertRaisesRegex(ValueError,'receipt_binding'):
    self.core.bind_receipt(self.root,self.f.corr,receipt,stack)
  path.write_bytes(original)
 def consumer(self,argv,**kwargs):
  if argv[0]=='/bin/ps':return self.f.real_popen(argv,**kwargs)
  return self.f.consumer(argv,**kwargs)
 def invoke(self,emit=None):
  def output(value):
   self.emitted.append(value)
   if emit:emit(value)
   if 'queryCount' not in value and value.get('state')=='ready':self.now=1800.
  with mock.patch.object(self.provider.subprocess,'Popen',side_effect=self.consumer):return self.entry.run(self.root,self.f.corr,self.receipt,self.source,clock=lambda:self.now,sleep=lambda seconds:setattr(self,'now',self.now+seconds),emit=output)
 def identity(self):return {'correlationId':str(uuid.UUID(self.f.corr)),'receiptSha256':self.receipt,'sourceManifestSha256':self.source}
 def test_actual_main_retains_pid_birth_query_raw_and_result(self):
  result=self.invoke();output=self.entry.output_path(self.root,self.f.corr);intent=json.loads((output/'intent.json').read_bytes())
  self.assertEqual(self.entry.actor(),intent['localActor']);self.assertEqual('duration',result['stopReason']);self.assertEqual(1,result['queryCount'])
  raw=json.loads((output/'query-0000.private.json').read_bytes());self.assertEqual(self.f.stdout,base64.b64decode(raw['stdout']));self.assertTrue(raw['complete']);self.assertTrue(raw['eof']['stdout'])
  observed=self.entry.observe(self.root,self.f.corr,self.receipt,self.source);self.assertEqual('completed',observed['state']);self.assertFalse(observed['nativeActionAllowed']);self.assertFalse(observed['replayAllowed']);self.assertEqual(result['queryCount'],observed['result']['queryCount'])
 def test_real_lock_busy_release_retained_then_fresh_ready(self):
  child=[]
  def emit(value):
   if value.get('state')=='keeper_started':
    path=self.root/'.rag_index/ssh-recovery-adoption/config.lock'
    code="import os,fcntl,sys;fd=os.open(sys.argv[1],os.O_RDONLY);fcntl.flock(fd,fcntl.LOCK_EX);print('locked',flush=True);sys.stdin.buffer.read(1);os.close(fd)"
    c=self.f.real_popen([sys.executable,'-I','-B','-c',code,str(path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={k:v for k,v in os.environ.items() if k!='DYLD_INSERT_LIBRARIES'});child.append(c);self.assertEqual(b'locked\n',c.stdout.readline())
   elif value.get('state')=='unknown':
    c=child[0];c.stdin.write(b'x');c.stdin.flush();self.assertEqual(0,c.wait(timeout=3))
    for stream in (c.stdin,c.stdout,c.stderr):stream.close()
  try:result=self.invoke(emit)
  finally:
   for c in child:
    if c.poll() is None:c.kill();c.wait()
    for stream in (c.stdin,c.stdout,c.stderr):stream.close()
  self.assertEqual(2,result['queryCount']);self.assertEqual(['unknown','ready'],[v['state'] for v in self.emitted if 'transport' in v]);output=self.entry.output_path(self.root,self.f.corr)
  self.assertTrue((output/'query-0000.inventory.json').exists());self.assertFalse((output/'query-0000.private.json').exists());self.assertTrue((output/'query-0001.private.json').exists())
 def test_original_intent_observe_before_result_never_relaunches(self):
  seen=[]
  def emit(value):
   if value.get('state')=='keeper_started':seen.append(self.entry.observe(self.root,self.f.corr,self.receipt,self.source))
  self.invoke(emit);self.assertEqual('observing',seen[0]['state']);self.assertFalse(seen[0]['nativeActionAllowed']);self.assertFalse(seen[0]['replayAllowed'])
 def test_actual_current_child_refuses_foreign_handle_without_observation(self):
  source=self.entry.SourceGuard(self.root,self.f.corr,self.source)
  try:argv=self.entry.child_argv(sys.executable,self.root,self.f.corr,self.receipt,self.source,source)
  finally:source.close()
  argv[-3]='c'*32
  child=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8,check=False,env={k:v for k,v in os.environ.items() if k!='DYLD_INSERT_LIBRARIES'})
  self.assertNotEqual(0,child.returncode);self.assertNotIn(b'keeper_started',child.stdout)
  self.assertFalse(self.entry.output_path(self.root,'c'*32).exists());self.assertEqual(['prepare'],[v[6] for v in self.f.calls])
 def test_intent_remote_and_authority_corruption_refused(self):
  self.invoke();path=self.entry.output_path(self.root,self.f.corr)/'intent.json';original=json.loads(path.read_bytes())
  for key,value in [('remoteSourceSha256','0'*64),('newConnectionAllowed',True),('durationSeconds',1800.0)]:
   path.write_text(json.dumps({**original,key:value}));path.chmod(0o600)
   with self.assertRaises(ValueError):self.entry.observe(self.root,self.f.corr,self.receipt,self.source)
 def test_final_publication_mutation_of_original_result_refuses(self):
  def emit(value):
   if 'queryCount' in value:
    path=self.entry.output_path(self.root,self.f.corr)/'result.json';body=json.loads(path.read_bytes());body['queryCount']+=1;path.write_text(json.dumps(body))
  with self.assertRaises(ValueError):self.invoke(emit)
 def test_parent_lazy_import_actual_changed_source_has_no_effect(self):
  import agent_tools
  marker=self.root/'PARENT_PUBLIC_MARKER';name='agent_tools.ssh_channel_keeper_entry';saved=sys.modules.get(name)
  path=self.root/'agent_tools/ssh_channel_keeper_entry.py';path.write_text('from pathlib import Path\nPath('+repr(str(marker))+').write_text("executed")\nraise ValueError("PUBLIC_MARKER")\n');sys.modules.pop(name,None)
  try:
   with mock.patch.object(agent_tools,'__path__',[str(self.root/'agent_tools')]),mock.patch.object(self.server,'_run',side_effect=AssertionError('no child expected')):value=self.server._ssh_channel_keeper_workflow('connection-channel-keep','archlinux',1800,self.identity(),None,None)
   self.assertFalse(marker.exists());self.assertEqual('blocked',value['state'])
  finally:
   sys.modules.pop(name,None)
   if saved is not None:sys.modules[name]=saved
 def test_actual_observe_late_intent_guard_mutates_result_then_refuses(self):
  self.invoke();path=self.entry.output_path(self.root,self.f.corr)/'result.json';seen=[False];mutated=[False];original=private.Snapshot.guard
  def guard(holder):
   original(holder)
   if holder.name=='result.json':seen[0]=True
   if holder.name=='intent.json' and seen[0] and not mutated[0]:
    value=json.loads(path.read_bytes());value['queryCount']+=1;path.write_text(json.dumps(value));mutated[0]=True
  with mock.patch.object(private.Snapshot,'guard',guard),self.assertRaises(ValueError):self.entry.observe(self.root,self.f.corr,self.receipt,self.source)
  self.assertTrue(mutated[0])
 def test_source_mutation_after_sourceguard_in_late_private_parent_refuses(self):
  self.invoke();path=self.root/'agent_tools/ssh_channel_keeper_entry.py';original_source=self.entry.SourceGuard.guard;original_parent=private.Directory.guard;calls=[0];changed=[False]
  def source_guard(holder):original_source(holder);calls[0]+=1
  def parent_guard(holder):
   original_parent(holder)
   if calls[0]>=3 and holder.path==self.entry.output_path(self.root,self.f.corr) and not changed[0]:path.write_bytes(path.read_bytes()+b'\n# OWN_PUBLIC_LATE_PARENT_DRIFT\n');changed[0]=True
  with mock.patch.object(self.entry.SourceGuard,'guard',source_guard),mock.patch.object(private.Directory,'guard',parent_guard),self.assertRaises(ValueError):self.entry.observe(self.root,self.f.corr,self.receipt,self.source)
  self.assertTrue(changed[0])
 def test_journal_receipt_mutation_at_final_output_parent_refuses(self):
  self.invoke();path=self.provider._journal(self.root,False)/(self.f.corr+'.ready.json');changed=[False];original=private.Directory.guard
  def parent(holder):
   original(holder)
   if holder.path==self.entry.output_path(self.root,self.f.corr) and not changed[0]:path.write_bytes(path.read_bytes()+b' ');changed[0]=True
  with mock.patch.object(private.Directory,'guard',parent),self.assertRaises(ValueError):self.entry.observe(self.root,self.f.corr,self.receipt,self.source)
  self.assertTrue(changed[0])
 def test_whole_core_final_internal_receiptguard_source_drift_refuses(self):
  self.now=0.;guard_calls=[0];endguards=[0];armed=[False];changed=[False];path=self.root/'agent_tools/ssh_channel_keeper_entry.py';source=self.entry.SourceGuard(self.root,self.f.corr,self.source);original=private.Snapshot.guard
  def guard():
   source.guard();guard_calls[0]+=1
   if self.now>=1800:endguards[0]+=1
   armed[0]=endguards[0]>=2
  def private_guard(holder):
   original(holder)
   if holder.name==self.f.corr+'.ready.json' and armed[0] and not changed[0]:path.write_bytes(path.read_bytes()+b'\n# OWN_FINAL_INTERNAL_RECEIPT_DRIFT\n');changed[0]=True
  def publish(index,value):self.now=1800.
  try:
   with mock.patch.object(private.Snapshot,'guard',private_guard),mock.patch.object(self.provider.subprocess,'Popen',side_effect=self.consumer):result=self.core.bound_keep(self.root,self.f.corr,self.receipt,lambda i,r:None,publish,guard,lambda:self.now,lambda seconds:None,retain_inventory=lambda i,e:self.core.retain(self.root,i,e))
   self.assertTrue(changed[0]);self.assertEqual('unknown',result['lastState']);self.assertEqual('source_changed',result['stopReason'])
  finally:source.close()
 def test_source_parent_drift_during_later_receipt_body_refuses(self):
  self.invoke();parent=self.root/'agent_tools';mode=parent.stat().st_mode & 0o777;original_source=self.entry.SourceGuard.guard;original_snapshot=private.Snapshot.guard;calls=[0];changed=[False]
  def source_guard(holder):original_source(holder);calls[0]+=1
  def snapshot_guard(holder):
   original_snapshot(holder)
   if calls[0]>=3 and holder.name==self.f.corr+'.ready.json' and not changed[0]:parent.chmod(0o777);changed[0]=True
  try:
   with mock.patch.object(self.entry.SourceGuard,'guard',source_guard),mock.patch.object(private.Snapshot,'guard',snapshot_guard),self.assertRaises(ValueError):self.entry.observe(self.root,self.f.corr,self.receipt,self.source)
   self.assertTrue(changed[0])
  finally:parent.chmod(mode)
 def test_actual_create_only_output_refuses_replay(self):
  self.invoke();count=len(self.f.calls)
  with self.assertRaises(FileExistsError):self.invoke()
  self.assertEqual(count,len(self.f.calls))
 def test_wrong_receipt_and_source_refuse_before_output_or_observation(self):
  for receipt,digest in [('0'*64,self.source),(self.receipt,'0'*64)]:
   with self.assertRaises(ValueError):self.entry.run(self.root,self.f.corr,receipt,digest,emit=self.emitted.append)
  self.assertFalse(self.entry.output_path(self.root,self.f.corr).exists());self.assertEqual([],self.emitted)
 def test_unknown_same_original_stops_with_durable_result_no_replay(self):
  self.f.stdout=json.dumps({'state':'unknown','correlationId':self.f.corr}).encode();self.f.rc=3
  result=self.invoke();self.assertEqual('unknown',result['lastState']);self.assertEqual('unknown',result['stopReason']);self.assertEqual(['prepare','status'],[v[6] for v in self.f.calls]);self.assertTrue((self.entry.output_path(self.root,self.f.corr)/'result.json').exists())
 def test_actual_canonical_dispatch_and_cli_have_fixed_envelope(self):
  seen=[]
  def runner(argv,timeout,output_limit,output_capture):
   self.assertEqual(1845,timeout);self.assertEqual(0,output_limit);self.assertEqual(['-I','-B','-c'],argv[1:4]);seen.append(argv)
   out=io.StringIO()
   with contextlib.redirect_stdout(out):self.invoke(emit=lambda v:print(json.dumps(v),flush=True))
   raw=out.getvalue().encode();retained=output_capture(0,raw,b'');return {'ok':True,'returncode':0,'completionOutput':retained}
  identity=self.identity();file=self.root/'identity.json';file.write_text(json.dumps(identity))
  original=self.server._agent_module
  # This is the dispatch unit seam: the authentic entry and its complete held
  # manifest live in this owned TempFS, where the synthetic child writes results.
  route=lambda name:self.entry if name=='ssh_channel_keeper_entry' else original(name)
  # Original internal dispatch keeps its exact child envelope/custody checks.
  authenticated=self.entry.SourceGuard(self.root,self.f.corr,self.source)
  try:
   with mock.patch.object(self.server,'_run',side_effect=runner):
    value=self.server._keeper_dispatch_authenticated(self.entry,authenticated.held,
                                                     'connection-channel-keep',self.f.corr,identity)
  finally:authenticated.close()
  self.assertEqual('completed',value['state']);self.assertEqual(1,len(seen))
  # Public new work is retired; the exact original status reader stays available.
  with mock.patch.object(self.server,'_keeper_authenticated_entry',side_effect=AssertionError('retired new work must not load sources')),contextlib.redirect_stdout(io.StringIO()) as stdout:
   status=self.server.main(['ssh-workflow','connection-channel-keep','--host','archlinux','--timeout-seconds','1800','--identity-file',str(file)])
  value=json.loads(stdout.getvalue());self.assertEqual(1,status);self.assertEqual('blocked',value['state'])
  with mock.patch.object(self.server,'_agent_module',side_effect=route):
   value=self.server.ssh_workflow('connection-channel-keep-status','archlinux',15,identity)
  self.assertEqual('completed',value['state'])
 def test_valid_new_keeper_actions_retire_before_source_loading_or_child(self):
  for action,timeout,identity in [('connection-channel-keeper-source',15,{'correlationId':self.identity()['correlationId']}),
                                  ('connection-channel-keep',1800,self.identity())]:
   with self.subTest(action=action),mock.patch.object(self.server,'_keeper_authenticated_entry',side_effect=AssertionError('retired new work must not load sources')),mock.patch.object(self.server,'_run',side_effect=AssertionError('retired new work must not launch')):
    value=self.server._ssh_channel_keeper_workflow(action,'archlinux',timeout,identity,None,None)
    self.assertEqual('blocked',value['state']);self.assertEqual('historical_channel_keeper_new_work_retired',value['reason'])
    self.assertFalse(value['nativeActionAllowed']);self.assertFalse(value['replayAllowed'])
 def test_retired_source_and_original_reader_invalid_envelopes_stay_unknown(self):
  source={'correlationId':self.identity()['correlationId']}
  cases=[('connection-channel-keeper-source','archlinux',0,source,None,None),
         ('connection-channel-keeper-source','archlinux',61,source,None,None),
         ('connection-channel-keeper-source','archlinux',True,source,None,None),
         ('connection-channel-keeper-source','archlinux',15,{**source,'path':'forbidden'},None,None),
         ('connection-channel-keeper-source','other',15,source,None,None),
         ('connection-channel-keeper-source','archlinux',15,source,{},None),
         ('connection-channel-keeper-source','archlinux',15,source,None,'device'),
         ('connection-channel-keep-status','archlinux',15,{**self.identity(),'receiptSha256':'bad'},None,None)]
  for arguments in cases:
   with self.subTest(arguments=arguments),mock.patch.object(self.server,'_keeper_authenticated_entry',side_effect=AssertionError('must not load sources')),mock.patch.object(self.server,'_run',side_effect=AssertionError('must not launch')):
    value=self.server._ssh_channel_keeper_workflow(*arguments)
    self.assertEqual('unknown',value['state']);self.assertFalse(value['nativeActionAllowed']);self.assertFalse(value['replayAllowed'])
 def test_dispatch_invalid_limits_private_fields_never_launch(self):
  for timeout,identity,transfer in [(60,self.identity(),None),(True,self.identity(),None),
                                    (1800,{**self.identity(),'command':'forbidden'},None),(1800,self.identity(),{}),
                                    (1800,{**self.identity(),'receiptSha256':'bad'},None),
                                    (1800,{**self.identity(),'sourceManifestSha256':'bad'},None)]:
   with mock.patch.object(self.server,'_keeper_authenticated_entry',side_effect=AssertionError('must not load sources')),mock.patch.object(self.server,'_run',side_effect=AssertionError('must not launch')):result=self.server.ssh_workflow('connection-channel-keep','archlinux',timeout,identity,transfer)
   self.assertEqual('unknown',result['state']);self.assertFalse(result['nativeActionAllowed']);self.assertFalse(result['replayAllowed'])
 def test_actual_child_cached_import_refuses_late_named_marker(self):
  marker=self.root/'marker';path=self.root/'agent_tools/ssh_channel_keeper_entry.py';source=self.entry.SourceGuard(self.root,self.f.corr,self.source)
  try:
   argv=self.entry.child_argv(sys.executable,self.root,self.f.corr,self.receipt,self.source,source)
   path.write_text('from pathlib import Path\nPath('+repr(str(marker))+').write_text("executed")\n')
   child=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8,check=False,env={k:v for k,v in os.environ.items() if k!='DYLD_INSERT_LIBRARIES'})
   self.assertNotEqual(0,child.returncode);self.assertFalse(marker.exists());self.assertNotIn(b'keeper_started',child.stdout)
  finally:source.close()
 def test_actual_bootstrap_valid_guard_stops_bad_receipt_without_ssh(self):
  source=self.entry.SourceGuard(self.root,self.f.corr,self.source)
  try:argv=self.entry.child_argv(sys.executable,self.root,self.f.corr,'0'*64,self.source,source)
  finally:source.close()
  child=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8,check=False,env={k:v for k,v in os.environ.items() if k!='DYLD_INSERT_LIBRARIES'})
  self.assertNotEqual(0,child.returncode);self.assertIn(b'receipt_binding',child.stderr);self.assertNotIn(b'keeper_started',child.stdout)
 def test_whole_before_bundle_readiness_red_current_receipt_guard_green(self):
  path=REPO/'agent_tools/tests/fixtures/ssh_generated_dependency_closure_before/keeper_entry.before.source'
  raw=path.read_bytes();self.assertEqual('83c30a87daf6afeefe074d58b53ab380946d99d457469c077e75296e3ca5e48a',hashlib.sha256(raw).hexdigest())
  name='test_actual_bootstrap_valid_guard_stops_bad_receipt_without_ssh'
  original=KeeperEntryTests(name);original.before_entry=raw;result=unittest.TestResult();original.run(result)
  self.assertEqual(1,len(result.failures));self.assertFalse(result.errors)
  self.assertIn('undeclared_repository_module',result.failures[0][1])
  self.assertIn('readiness',result.failures[0][1])
  current=unittest.TestResult();KeeperEntryTests(name).run(current)
  self.assertTrue(current.wasSuccessful(),current.failures+current.errors)
 def test_added_readiness_role_replacement_refuses_before_keeper_or_ssh(self):
  source=self.entry.SourceGuard(self.root,self.f.corr,self.source)
  try:argv=self.entry.child_argv(sys.executable,self.root,self.f.corr,self.receipt,self.source,source)
  finally:source.close()
  path=self.root/'agent_tools/readiness.py';replacement=path.with_suffix('.replacement');replacement.write_bytes(path.read_bytes());replacement.replace(path)
  child=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8,check=False,env={k:v for k,v in os.environ.items() if k!='DYLD_INSERT_LIBRARIES'})
  self.assertNotEqual(0,child.returncode);self.assertNotIn(b'keeper_started',child.stdout)
  self.assertFalse(self.entry.output_path(self.root,self.f.corr).exists())
  self.assertEqual(['prepare'],[v[6] for v in self.f.calls])
 def authenticated_entry(self,entry=None):
  entry=self.entry if entry is None else entry
  original=self.server._agent_module
  route=lambda name:entry if name=='ssh_channel_keeper_entry' else original(name)
  return mock.patch.object(self.server,'_agent_module',side_effect=route)
 def test_complete_original_reader_catalog_red_current_exact18_guard_green(self):
  path=REPO/'agent_tools/tests/fixtures/ssh_generated_dependency_closure_before/keeper_reader.before.source'
  raw=path.read_bytes();provenance=json.loads(path.with_name('provenance.json').read_bytes())
  digest='caccd482155dc4e9dddd8cbc547cb906ea22c9007602071122f07758d16e1aec'
  self.assertEqual(digest,provenance['cases'][path.name]['sha256']);self.assertEqual(digest,hashlib.sha256(raw).hexdigest())
  with self.authenticated_entry():
   namespace=dict(vars(self.server));exec(compile(raw,str(path),'exec'),namespace)
   with self.assertRaisesRegex(ValueError,'source_roles'):
    with namespace['_keeper_authenticated_entry'](self.f.corr,self.source):self.fail('old catalog accepted18 roles')
   with mock.patch.object(self.entry,'SourceGuard',wraps=self.entry.SourceGuard) as guard:
    with self.server._keeper_authenticated_entry(self.f.corr,self.source) as (actual,held):
     self.assertIs(self.entry,actual);self.assertEqual(18,len(actual.NAMES));held.finish()
    self.assertEqual(1,guard.call_count)
 def test_reader_exact_legacy17_requires_original_entry_and_sourceguard(self):
  path=REPO/'agent_tools/tests/fixtures/ssh_generated_dependency_closure_before/keeper_entry.before.source'
  raw=path.read_bytes();self.assertEqual('83c30a87daf6afeefe074d58b53ab380946d99d457469c077e75296e3ca5e48a',hashlib.sha256(raw).hexdigest())
  legacy=KeeperEntryTests('runTest');legacy.before_entry=raw
  try:
   legacy.setUp()
   with legacy.authenticated_entry(),mock.patch.object(legacy.entry,'SourceGuard',wraps=legacy.entry.SourceGuard) as guard:
    with legacy.server._keeper_authenticated_entry(legacy.f.corr,legacy.source) as (actual,held):
     self.assertIs(legacy.entry,actual);self.assertEqual(17,len(actual.NAMES));held.finish()
    self.assertEqual(1,guard.call_count)
   # Its incomplete historical transport bundle keeps the original finite
   # declared-import refusal; accepting17 roles never upgrades its executor.
   source=legacy.entry.SourceGuard(legacy.root,legacy.f.corr,legacy.source)
   try:argv=legacy.entry.child_argv(sys.executable,legacy.root,legacy.f.corr,'0'*64,legacy.source,source)
   finally:source.close()
   child=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8,check=False)
   self.assertNotEqual(0,child.returncode);self.assertIn(b'undeclared_repository_module',child.stderr)
   self.assertNotIn(b'keeper_started',child.stdout)
  finally:legacy.doCleanups()
 def test_reader_rejects_foreign19_missing_required_and_legacy_current_mismatch(self):
  path=self.entry.source_path(self.root,self.f.corr);original=json.loads(path.read_bytes())
  for removed,added in [(None,'foreign.py'),('ssh_transport.py',None),('readiness.py',None)]:
   changed=json.loads(json.dumps(original));inputs=changed['inputs']
   if removed:inputs.pop(str(self.root/'agent_tools'/removed))
   if added:inputs[str(self.root/'agent_tools'/added)]={'sha256':'0'*64,'generation':[]}
   raw=json.dumps(changed,sort_keys=True,separators=(',',':')).encode();path.write_bytes(raw);path.chmod(0o600)
   digest=hashlib.sha256(raw).hexdigest()
   with self.subTest(removed=removed,added=added),self.authenticated_entry(),mock.patch.object(self.entry,'SourceGuard',side_effect=AssertionError('role mismatch must precede entry guard')):
    with self.assertRaisesRegex(ValueError,'source_roles'):
     with self.server._keeper_authenticated_entry(self.f.corr,digest):self.fail('invalidrole accepted')
if __name__=='__main__':unittest.main()
