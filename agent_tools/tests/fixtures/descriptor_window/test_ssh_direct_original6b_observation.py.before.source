"""Exact original-only observation through complete provider and owned TempFS.

Original authority constants are explicitly modeled to inert fixture digests.
Remote facts use a real bounded byte-consuming Python child; no actual SSH/config.
"""
import ast,copy,hashlib,json,os,shlex,sys,tempfile,threading,types,unittest
import agent_tools
from pathlib import Path
from unittest import mock
from agent_tools import ssh_direct_nested_channel as direct
if direct.coordinator_capable():
 from agent_tools import ssh_fresh_nested_channel as channel,ssh_transport as transport,ssh_connection_session as session
from agent_tools.tests import test_ssh_direct_ended_source_transition as history
from agent_tools.tests.test_ssh_direct_ended_inventory_successor import historical_sources
CHECKPOINT74_PROVIDER_BEFORE=history.CHECKPOINT74_PROVIDER_BEFORE
MCP_REVIEWED_AFTER=history.MCP_REVIEWED_AFTER
TRANSPORT_BEFORE74=history.TRANSPORT_BEFORE74
MCP_CHECKPOINT74=history.MCP_CHECKPOINT74
TRANSPORT_CHECKPOINT74=history.TRANSPORT_CHECKPOINT74
CURRENT_CLOSURE=history.CURRENT_CLOSURE
SOURCE=Path(channel.__file__) if direct.coordinator_capable() else None
DEPENDENCIES=Path(direct.__file__).parent
CORR='6b8c312131ab47ca812252e2c3f10021'
_PIN_SOURCE_GROWTH_BEFORE="def _pin_source(name):\n f=os.open(_STAGE+'/'+name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);s=os.fstat(f)\n if not stat.S_ISREG(s.st_mode)or s.st_uid!=1000 or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1 or not 0<s.st_size<=65536:os.close(f);raise ValueError('original_remote_source_shape')\n raw=b''\n while v:=os.read(f,65536):raw+=v\n if len(raw)!=s.st_size or _generation(os.fstat(f))!=_generation(s) or _generation(os.stat(_STAGE+'/'+name,follow_symlinks=False))!=_generation(s):os.close(f);raise ValueError('original_remote_source_changed')\n _holders.append((name,f,s,raw));return json.loads(raw,object_pairs_hook=_fixed_pairs)"

@unittest.skipUnless(direct.coordinator_capable(),'POSIX complete private provider fixture required')
class Original6bObservationTests(unittest.TestCase):
 def setUp(self):
  self.f=history.ProviderEndedHistoryTests('runTest');self.f.setUp();self.addCleanup(self.f.doCleanups);f=self.f
  # This is the immutable original v1 authority/observation graph. Current v3
  # private-generation authority is independently covered by current fixtures.
  sources=historical_sources()
  for name,body in sources.items():(f.source/name).write_bytes(body)
  self.historical_direct=types.ModuleType('agent_tools._original6b_direct_epoch')
  self.historical_direct.__file__=str(f.source/'ssh_direct_nested_channel.py');self.historical_direct.__package__='agent_tools'
  exec(compile(sources['ssh_direct_nested_channel.py'],self.historical_direct.__file__,'exec'),vars(self.historical_direct))
  for owner in (agent_tools,history.fixture_owner):
   patch=mock.patch.object(owner,'ssh_direct_nested_channel'if owner is agent_tools else'direct',self.historical_direct);patch.start();self.addCleanup(patch.stop)
  patch=mock.patch.object(self.historical_direct,'_dependencies',side_effect=lambda:(session,f.module,history._Held));patch.start();self.addCleanup(patch.stop)
  f.corr=CORR;f.owner.corr=CORR;f.result={**f.result,'correlationId':CORR,'controlPath':'/tmp/vpn-channel-'+CORR+'/m'}
  for name,body in [('ssh_fresh_nested_channel.py',CHECKPOINT74_PROVIDER_BEFORE),('mcp_server.py',MCP_REVIEWED_AFTER),('ssh_transport.py',TRANSPORT_BEFORE74),('native_review_source_closure.py',CURRENT_CLOSURE)]:
   (f.source/name).write_bytes(body)
  f.module=f.load();f.seed();(f.journal/(CORR+'.terminal.json')).unlink();self.original={k:(f.journal/(CORR+'.'+k+'.json')).read_bytes()for k in ('intent','ready')}
  self.before=f.root/'before.private.json';self.before.write_bytes(f.owner.config_path.read_bytes());os.chmod(self.before,0o600)
  cfg=f.owner.f.f.config;cfg['hosts']['ubuntu2341-owned-current']=dict(host='127.0.0.1',port=2341,user='vpnfixture',identityFile=str(transport.load_config(f.root).hosts['archlinux'].identity_file),knownHostsFile='/home/kardinal/vpn-control-linux-current-gui-1a477863-3a55736da205494eb903a2ecd716d64a/known-hosts',transport='nested',gateway='archlinux',remoteHostAlias='linux2341-current',remoteConfigFile='/home/kardinal/vpn-control-linux-current-gui-1a477863-3a55736da205494eb903a2ecd716d64a/ssh-current-gui.config',fixtureTransferRoot='/home/vpnfixture/.vpn-control-linux-current7f-gui-context-2b32263e6971451eb5eb52e9ed5a9293/mcp-native');f.owner.f.f.write_config()
  self.proof=f.root/'proof.public.json';self.proof.write_bytes(b'{"modeledLocalMapping":true}');os.chmod(self.proof,0o600)
  for name,body in [('ssh_fresh_nested_channel.py',history.CURRENT_PROVIDER_SOURCE.read_bytes()),('mcp_server.py',MCP_CHECKPOINT74),('ssh_transport.py',TRANSPORT_CHECKPOINT74)]:
   (f.source/name).write_bytes(body)
  f.module=f.load();m=f.module
  modeled={'_ORIGINAL6B_INTENT_SHA':hashlib.sha256(self.original['intent']).hexdigest(),'_ORIGINAL6B_READY_SHA':hashlib.sha256(self.original['ready']).hexdigest(),'_ORIGINAL6B_INVENTORY_SHA':hashlib.sha256(self.before.read_bytes()).hexdigest(),'_ORIGINAL6B_CURRENT_INVENTORY_SHA':hashlib.sha256(f.owner.config_path.read_bytes()).hexdigest(),'_ORIGINAL6B_PROOF_SHA':hashlib.sha256(self.proof.read_bytes()).hexdigest(),'_ORIGINAL6B_BEFORE':'before.private.json','_ORIGINAL6B_PROOF':'proof.public.json'}
  for name,value in modeled.items():setattr(m,name,value)
  self.saved=json.loads(self.original['ready'])['result'];self.response={'state':'ended','correlationId':CORR,'prior':self.saved,'gatewayBoot':self.saved['master']['gatewayBoot']};self.emitted=[];self.closing=None
  def consume(argv,**kwargs):
   remote=shlex.split(argv[-1]);self.assertEqual('status',remote[6]);self.assertEqual('a78e779e21716a9ccf2ab96330f47a0342308d215749f7b90a13f1a8c80b52ed',remote[9]);self.assertEqual(CORR,remote[5])
   call=ast.parse(remote[4],mode='eval').body;program=ast.literal_eval(call.args[0]);tree=ast.parse(program);effective=next(ast.literal_eval(x.value)for x in tree.body if isinstance(x,ast.Assign)and any(isinstance(y,ast.Name)and y.id=='_STATUS'for y in x.targets));self.assertEqual(hashlib.sha256(effective.encode()).hexdigest(),'a0d5a30bbb83bea3ba4dd7fb3c5b1664e5be2dd90e1ade1e82c3fb6123d032fd');self.assertIn('sys.addaudithook',program);self.assertIn('_generation',program);self.emitted.append(remote)
   code='import json,sys;assert json.loads(sys.stdin.buffer.read())=={};sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))'
   child=f.owner.real_popen([sys.executable,'-I','-B','-c',code,json.dumps(self.response).encode().hex()],**kwargs)
   if self.closing:self.closing()
   return child
  self.consumer=consume
 def invoke(self,method='status',corr=CORR):
  with mock.patch('subprocess.Popen',side_effect=self.consumer):return getattr(self.historical_direct,method)(self.f.root,'archlinux',corr)
 def assert_originals(self):
  self.assertEqual(self.original,{k:(self.f.journal/(CORR+'.'+k+'.json')).read_bytes()for k in self.original})
 def refuse(self):
  fd=len(os.listdir('/dev/fd'));value=self.invoke();self.assertEqual('unknown',value['state']);self.assertFalse((self.f.journal/(CORR+'.terminal.json')).exists());self.assert_originals();self.assertEqual(fd,len(os.listdir('/dev/fd')))
 def test_actual_original_ended_status_appends_terminal_only(self):
  fd=len(os.listdir('/dev/fd'));value=self.invoke();self.assertEqual('ended',value['state']);self.assertEqual(1,len(self.emitted));self.assert_originals();terminal=json.loads((self.f.journal/(CORR+'.terminal.json')).read_bytes());self.assertEqual(terminal['intentSha256'],hashlib.sha256(self.original['intent']).hexdigest());self.assertEqual(terminal['receiptSha256'],hashlib.sha256(self.original['ready']).hexdigest());self.assertEqual(fd,len(os.listdir('/dev/fd')));self.f.assert_legacy_unchanged()
 def test_prepare_never_migrates_or_dispatches(self):
  self.assertEqual('unknown',self.invoke('prepare')['state']);self.assertEqual([],self.emitted);self.assert_originals()
 def test_ready_reply_never_promotes_usable_selection(self):
  self.response=self.saved;self.refuse();self.assertEqual(1,len(self.emitted))
 def test_future_mcp_role_refuses(self):
  (self.f.source/'mcp_server.py').write_bytes(MCP_CHECKPOINT74+b'\n# unknown future role\n');self.refuse();self.assertEqual([],self.emitted)
 def test_future_transport_role_refuses(self):
  (self.f.source/'ssh_transport.py').write_bytes(TRANSPORT_CHECKPOINT74+b'\n# unknown future role\n');self.refuse();self.assertEqual([],self.emitted)
 def test_changed_beforeimage_bytes_refuse(self):
  self.before.write_bytes(self.before.read_bytes()+b' ');self.refuse();self.assertEqual([],self.emitted)
 def test_changed_current_inventory_refuses(self):
  self.f.owner.config_path.write_bytes(self.f.owner.config_path.read_bytes()+b' ');self.refuse();self.assertEqual([],self.emitted)
 def test_missing_ready_refuses(self):
  (self.f.journal/(CORR+'.ready.json')).unlink();fd=len(os.listdir('/dev/fd'));self.assertEqual('unknown',self.invoke()['state']);self.assertEqual([],self.emitted);self.assertEqual(fd,len(os.listdir('/dev/fd')))
 def test_changed_proof_during_capture_blocks_terminal(self):
  self.closing=lambda:self.proof.write_bytes(b'{"drift":true}');self.refuse();self.assertEqual(1,len(self.emitted))
 def test_changed_local_key_during_capture_blocks_terminal(self):
  self.closing=lambda:self.f.owner.f.f.key.write_bytes(b'changed');self.refuse();self.assertEqual(1,len(self.emitted))
 def test_wrong_original_ready_hash_refuses(self):
  self.f.module._ORIGINAL6B_READY_SHA='0'*64;self.refuse();self.assertEqual([],self.emitted)
 def test_changed_remote_render_refuses(self):
  self.f.module._REMOTE+='\n# unreviewed effective source\n';self.refuse();self.assertEqual([],self.emitted)



@unittest.skipUnless(direct.coordinator_capable(),'POSIX readonly original scope')
class Original6bGuardCausalTests(unittest.TestCase):
 def test_actual_read_atime_before_refuses_fixed_gen9_and_named_drift_refuses(self):
  fixture=Path(__file__).with_name('fixtures')/'ssh_direct_ended_v1/original6b-fullstat-guard.before.py'
  old=fixture.read_bytes();template=next(ast.literal_eval(x.value)for x in ast.parse(SOURCE.read_bytes()).body if isinstance(x,ast.Assign)and any(isinstance(y,ast.Name)and y.id=='_ORIGINAL6B_READONLY'for y in x.targets));tree=ast.parse(template);nodes=[x for x in tree.body if isinstance(x,ast.FunctionDef)and x.name in ('_generation','_pin_source')];pairs=next(x for x in tree.body if isinstance(x,ast.FunctionDef)and x.name=='_fixed_pairs')
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);q=root/'intent.json';q.write_bytes(b'{"inert":true}');os.chmod(q,0o600);os.utime(q,ns=(1,q.stat().st_mtime_ns))
   # Only gateway UID is modeled. Every other stat field, file, read and inode
   # comes from the actual owned OS object; no actual private body is read.
   def view(st):
    fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns','st_atime_ns')
    return types.SimpleNamespace(**{name:(1000 if name=='st_uid'else getattr(st,name))for name in fields})
   facade=types.SimpleNamespace(**{name:getattr(os,name)for name in ('O_RDONLY','O_NOFOLLOW','O_NONBLOCK','open','close','read')},fstat=lambda fd:view(os.fstat(fd)),stat=lambda path,**kw:view(os.stat(path,**kw)))
   def run(body):
    ns={'os':facade,'stat':__import__('stat'),'json':json,'_STAGE':str(root),'_holders':[]}
    exec(compile(ast.Module(body=[pairs],type_ignores=[]),'actual-duplicate-key-hook','exec'),ns)
    exec(compile(body,'actual-owned-source-pin','exec'),ns)
    try:return ns['_pin_source']('intent.json'),ns
    except Exception:
     for name,fd,st,raw in ns['_holders']:os.close(fd)
     raise
   with self.assertRaisesRegex(ValueError,'original_remote_source_changed'):run(old)
   result,ns=run(ast.Module(body=nodes,type_ignores=[]));self.assertEqual({'inert':True},result)
   try:
    name,fd,st,raw=ns['_holders'][0];other=root/'replacement';other.write_bytes(q.read_bytes());os.replace(other,q)
    self.assertNotEqual(ns['_generation'](facade.stat(q,follow_symlinks=False)),ns['_generation'](st))
   finally:
    for name,fd,st,raw in ns['_holders']:os.close(fd)
 def test_actual_same_bytes_beforeimage_copy_has_distinct_generation(self):
  # Complete provider positive already admits the exact original byte/size
  # witness through a separately held generation. This retains the bad actual
  # copied-file identity predicate independently as causal beforeimage.
  before=(Path(__file__).with_name('fixtures')/'ssh_direct_ended_v1/original6b-copy-generation-guard.before.py').read_text()
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);a=root/'a';b=root/'b';a.write_bytes(b'{"inert":true}');b.write_bytes(a.read_bytes())
   def pin(q):
    st=q.stat();raw=q.read_bytes();return {'generation':[st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns],'sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw)}
   ap,bp=pin(a),pin(b);self.assertNotEqual(ap['generation'],bp['generation']);identity={'sha256':'f'*64};original={'inventory':ap,'sourceSha256':'old','remoteSourceSha256':'render'}
   ns={'intent':types.SimpleNamespace(body=json.dumps(original).encode(),pin=lambda:identity),'ready':types.SimpleNamespace(body=json.dumps({'intent':identity}).encode()),'proof':types.SimpleNamespace(body=json.dumps({'beforeimagePin':bp}).encode()),'data':json.loads,'OLD_SOURCE':'old','REMOTE':'render'}
   with self.assertRaises(AssertionError):exec(compile(before,'actual-original-copy-guard','exec'),ns)
   self.assertEqual(ap['sha256'],bp['sha256']);self.assertEqual(ap['size'],bp['size'])

 def test_actual_concurrent_growth_closes_and_refuses_at_opening_size_plus_one(self):
  template=next(ast.literal_eval(x.value)for x in ast.parse(SOURCE.read_bytes()).body if isinstance(x,ast.Assign)and any(isinstance(y,ast.Name)and y.id=='_ORIGINAL6B_READONLY'for y in x.targets));tree=ast.parse(template)
  common=[x for x in tree.body if isinstance(x,ast.FunctionDef)and x.name in ('_generation','_fixed_pairs')];fixed=next(x for x in tree.body if isinstance(x,ast.FunctionDef)and x.name=='_pin_source')
  def exercise(body):
   with tempfile.TemporaryDirectory()as tmp:
    root=Path(tmp);q=root/'intent.json';q.write_bytes(b'{"inert":true}');os.chmod(q,0o600);opening=q.stat().st_size
    go=threading.Event();done=threading.Event();writer_errors=[];reads=[];opened=[];closed=[]
    def writer():
     try:
      if not go.wait(2):raise RuntimeError('growth_control_not_reached')
      with q.open('ab')as stream:stream.write(b'x'*4096)
     except BaseException as exc:writer_errors.append(exc)
     finally:done.set()
    thread=threading.Thread(target=writer);thread.start()
    def view(st):
     fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
     return types.SimpleNamespace(**{name:(1000 if name=='st_uid'else getattr(st,name))for name in fields})
    def opened_file(*args):
     fd=os.open(*args);opened.append(fd);return fd
    def close(fd):closed.append(fd);os.close(fd)
    def read(fd,amount):
     go.set()
     if not done.wait(2):raise RuntimeError('growth_control_writer_pending')
     value=os.read(fd,amount);reads.append((amount,len(value)));return value
    facade=types.SimpleNamespace(**{name:getattr(os,name)for name in ('O_RDONLY','O_NOFOLLOW','O_NONBLOCK')},open=opened_file,close=close,read=read,fstat=lambda fd:view(os.fstat(fd)),stat=lambda path,**kw:view(os.stat(path,**kw)))
    ns={'os':facade,'stat':__import__('stat'),'json':json,'_STAGE':str(root),'_holders':[]}
    exec(compile(ast.Module(body=common,type_ignores=[]),'actual-pin-common','exec'),ns);exec(compile(body,'actual-pin-growth','exec'),ns)
    try:
     with self.assertRaisesRegex(ValueError,'original_remote_source_changed'):ns['_pin_source']('intent.json')
    finally:
     go.set();thread.join(2)
     for fd in opened:
      if fd not in closed:os.close(fd)
    self.assertFalse(thread.is_alive());self.assertEqual([],writer_errors);self.assertEqual(opened,closed);self.assertEqual([],ns['_holders'])
    return opening,reads
  opening,before_reads=exercise(_PIN_SOURCE_GROWTH_BEFORE);self.assertGreater(sum(n for _,n in before_reads),opening+1)
  opening,fixed_reads=exercise(ast.Module(body=[fixed],type_ignores=[]));self.assertEqual([(opening+1,opening+1)],fixed_reads)

if __name__=='__main__':unittest.main()
