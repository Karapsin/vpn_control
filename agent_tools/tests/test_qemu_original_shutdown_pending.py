"""Ignored full-source causal controls. Synthetic local endpoints only.
Control records are retained only under VPN_CONTROL_QEMU_SHUTDOWN_EVIDENCE_ROOT."""
import ast,base64,contextlib,ctypes,hashlib,io,json,os,shlex,shutil,socket,stat,struct,subprocess,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).with_name('fixtures')/'qemu_original_shutdown_pending'
from agent_tools import readiness,readiness_qemu_remote as AFTER,readiness_qemu as NEW_LOCAL
from agent_tools.tests import test_readiness_qemu_remote as existing
REAL_RUN=subprocess.run;REAL_SOCKET=socket.socket;REAL_TEMP=tempfile.TemporaryDirectory
EVIDENCE=None;CHILDREN=[];CASES=[]
def save(path,value):
 raw=value if isinstance(value,bytes)else(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
def archived(name,filename,expected):
 path=HERE/filename;raw=path.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('qemu_shutdown_fixture_source_changed')
 m=types.ModuleType('agent_tools.'+name);m.__package__='agent_tools';m.__file__=str(path);sys.modules[m.__name__]=m;exec(compile(raw,str(path),'exec'),m.__dict__);return m
BEFORE=archived('_pending_shutdown_remote_before','readiness_qemu_remote.py.before.source','7353aedc72fe1873605897cc219d94aeb95793cb946e11156ca596238e8565a5')
DUP_BEFORE=archived('_pending_shutdown_remote_without_duplicate_guard','readiness_qemu_remote.before-duplicate-guard.source','628f40e7ea79e79e434283a3a79e5542ff65ebba1120fd1d16c25b5590e13552')
OLD_LOCAL=archived('_pending_shutdown_local_before','readiness_qemu.py.before.source','33d930197e4d03ca5bbc68afe980fae90b56aa515af366b2486b4a589a588303')
OLD_LOCAL.packets=BEFORE
class PeerSocket(REAL_SOCKET):
 def getsockopt(self,level,name,*args):
  if sys.platform=='darwin' and level==socket.SOL_SOCKET and name==0x7ffffffe:
   pid=super().getsockopt(0,2);uid=ctypes.c_uint();gid=ctypes.c_uint();lib=ctypes.CDLL(None,use_errno=True);fn=lib.getpeereid;fn.argtypes=[ctypes.c_int,ctypes.POINTER(ctypes.c_uint),ctypes.POINTER(ctypes.c_uint)];fn.restype=ctypes.c_int
   if fn(self.fileno(),ctypes.byref(uid),ctypes.byref(gid))!=0:raise OSError(ctypes.get_errno(),'peer_credentials_unavailable')
   return struct.pack('3i',pid,uid.value,gid.value)
  return super().getsockopt(level,name,*args)
@contextlib.contextmanager
def peer_compat():
 if sys.platform!='darwin':yield;return
 with mock.patch.object(socket,'SO_PEERCRED',0x7ffffffe,create=True),mock.patch.object(socket,'socket',PeerSocket):yield
SSH_STUB="""import json,pathlib,sys
root=pathlib.Path(sys.argv[1]);state=json.loads((root/'controlled-ssh-state.json').read_text());sys.stdin.buffer.read()
if state['mode']=='unreachable':sys.stderr.write('controlled_fixture_unreachable\\n');sys.exit(255)
print(json.dumps(state['guest'],sort_keys=True))
"""
class Fixture:
 def __init__(self,*args):self.case=existing.QemuRemotePacketTests('runTest')
 def __getattr__(self,name):return getattr(self.case,name)
 def write(self,*args):return existing.QemuRemotePacketTests.write(self,*args)
 def stop_child(self):return existing.QemuRemotePacketTests.stop_child(self)
 def setUp(self):
  with mock.patch.object(tempfile,'TemporaryDirectory',side_effect=lambda *a,**kw:REAL_TEMP(dir='/private/tmp'if sys.platform=='darwin'else'/tmp',prefix='qp-')):
   existing.QemuRemotePacketTests.setUp(self)
  self.captures=[];self.ssh_children=[];self.producer=AFTER
  self.write('controlled-ssh.py',SSH_STUB.encode());self.mode('reachable')
  CHILDREN.append({'pid':self.child.pid,'kind':'qmp','handle':self.child})
 def mode(self,mode):
  self.write('controlled-ssh-state.json',json.dumps({'mode':mode,'guest':{'bootId':self.guest_boot,'account':'recovery','originalUid':'1000','protectedOrInstallerProcesses':[], 'machineId':'a'*32,'jobVisibilityComplete':True,'systemdJobs':[],'cloudInit':'status: done','foreignSessions':[],'unknownOrRunningJobs':[]}}).encode())
 def run_packet(self,action='observe',pins=None,rid=None,expected=None,producer=None,read_hook=None):
  producer=producer or self.producer;concrete=type(self.root)
  def path(*parts):
   result=concrete(*parts)
   return self.proc/str(result).removeprefix('/proc').lstrip('/')if str(result)=='/proc'or str(result).startswith('/proc/')else result
  def run(argv,**kwargs):
   self.ssh.append(argv);self.assertEqual('/usr/bin/ssh',argv[0]);self.assertIn('StrictHostKeyChecking=yes',argv);self.assertIn('BatchMode=yes',argv)
   self.assertNotEqual(shlex.split(argv[-1])[:3],['sudo','-n','systemctl'],'No power command may reach even the synthetic SSH child')
   child=subprocess.Popen([sys.executable,'-B',str(self.root/'controlled-ssh.py'),str(self.root)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   item={'pid':child.pid,'kind':'synthetic-ssh','handle':child};CHILDREN.append(item);self.ssh_children.append(item)
   out,err=child.communicate(kwargs.get('input',b''),timeout=5);item.update(returnCode=child.returncode,stdout=out.decode(),stderr=err.decode(),reaped=child.poll()is not None)
   return subprocess.CompletedProcess(argv,child.returncode,out,err)
  stream=io.StringIO();source=producer.program(self.binding,pins,action,rid,expected)
  with contextlib.ExitStack()as stack:
   stack.enter_context(peer_compat());stack.enter_context(mock.patch('pathlib.Path',side_effect=path));stack.enter_context(mock.patch.object(subprocess,'run',side_effect=run));stack.enter_context(contextlib.redirect_stdout(stream))
   if read_hook is not None:stack.enter_context(mock.patch.object(os,'read',side_effect=read_hook))
   exec(compile(source,'complete original/candidate generated QEMU packet','exec'),{'__name__':'__main__'})
  value=json.loads(stream.getvalue());self.captures.append((source,stream.getvalue()));return value
 def seed(self,ack={'acknowledged':True,'returnCode':0},order=None):
  first=self.run_packet('enroll');self.pins=first['pins'];manager=self.root/'readiness-qemu';manager.mkdir(mode=0o700)
  self.rid='12'*32;self.intent={'action':'poweroff','recoveryId':self.rid,'boot':self.guest_boot,'owner':self.owner,'idleVisibility':order or ['reservations','running_jobs','unknown_jobs','installers','lifecycle_phases','operators','protected_processes'],'idleBlockers':[]}
  self.write('readiness-qemu/'+self.rid+'.intent.json',json.dumps(self.intent).encode())
  if ack is not None:self.write('readiness-qemu/'+self.rid+'.ack.json',json.dumps(ack).encode())
  self.ssh.clear();return first
 def retain(self,label):
  d=EVIDENCE/(str(len(CASES))+'-'+label);d.mkdir(mode=0o700);CASES.append(str(d))
  for i,(source,reply)in enumerate(self.captures):save(d/(str(i)+'.packet.py'),source.encode());save(d/(str(i)+'.reply.json'),reply.encode())
  for p in(self.root/'readiness-qemu').glob('*.json')if(self.root/'readiness-qemu').exists()else[]:save(d/p.name,p.read_bytes())
  save(d/'children.json',[{k:v for k,v in x.items()if k!='handle'}for x in self.ssh_children]);save(d/'qmp-identity.json',self.owner)
@contextlib.contextmanager
def fixture(producer=AFTER):
 f=Fixture('runTest');f.producer=producer
 try:
  f.setUp();f.producer=producer;yield f
 finally:
  try:
   if hasattr(f,'captures'):f.retain('after'if producer is AFTER else'before')
  finally:f.doCleanups()
def desired(value):
 assert value['facts']['guest']=='unknown'
 assert value['facts']['idleBlockers']==['original_shutdown_pending']
 assert value['pendingShutdown']['completionProven']is False
 assert value['pendingShutdown']['replayAllowed']is False
 assert value['pendingShutdown']['reservationReleaseAllowed']is False
 assert value['cleanStop']is None
@contextlib.contextmanager
def local_call(m,value,case):
 with REAL_TEMP(dir='/private/tmp'if sys.platform=='darwin'else'/tmp',prefix='ql-')as tmp:
  root=Path(tmp).resolve();root.chmod(0o700);reply=root/'reply';reply.write_bytes(value if type(value)is bytes else json.dumps(value).encode());reply.chmod(0o600)
  binding={'root':'/home/owner/vc-r-0f559886','machine':'0f559886-4ff5-4075-ad25-beb805173364','host':'fixture','target':'qemu-linux:0f559886-4ff5-4075-ad25-beb805173364'}
  ready=types.SimpleNamespace(connection='controlled-transport');admission=types.SimpleNamespace(ready=ready,revalidate=lambda:None)
  backend=m.QemuLinuxBackend(root,binding,value.get('pins',{})if type(value)is dict else{})
  child_argv=[sys.executable,'-B','-c','import pathlib,sys;sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())',str(reply)]
  with mock.patch.object(m.transport,'admitted_transport',return_value=contextlib.nullcontext(admission)),mock.patch.object(m.transport,'load_config',return_value=object()),mock.patch.object(m.transport,'build_ssh_argv',return_value=child_argv):
   yield backend,root
  target=EVIDENCE/('local-'+str(len(CASES)));target.mkdir(mode=0o700);CASES.append(str(target))
  for p in(root/'.runtime/readiness-qemu').glob('*/*')if(root/'.runtime/readiness-qemu').exists()else[]:
   if p.is_file():save(target/p.name,p.read_bytes())
  save(target/'expected-reply',reply.read_bytes())
class Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  global EVIDENCE
  import uuid
  retained=os.environ.get('VPN_CONTROL_QEMU_SHUTDOWN_EVIDENCE_ROOT')
  if not retained:cls.temp=REAL_TEMP(prefix='qemu-shutdown-controls-');cls.addClassCleanup(cls.temp.cleanup)
  EVIDENCE=Path(retained or cls.temp.name)/str(uuid.uuid4());EVIDENCE.mkdir(mode=0o700,parents=True)
  CHILDREN.clear();CASES.clear()
  metadata=json.loads((HERE/'provenance.json').read_bytes())
  for name,sha in metadata['files'].items():
   if hashlib.sha256((HERE/name).read_bytes()).hexdigest()!=sha:raise ValueError('qemu_shutdown_fixture_source_changed')
 @classmethod
 def tearDownClass(cls):
  closure={'children':[{k:v for k,v in x.items()if k!='handle'}|{'returnCode':x['handle'].poll(),'reaped':x['handle'].poll()is not None}for x in CHILDREN],'platformPeerSeam':'Darwin kernel LOCAL_PEERPID/getpeereid to Linux tuple'if sys.platform=='darwin'else'Linux SO_PEERCRED','allOwnedChildrenReaped':all(x['handle'].poll()is not None for x in CHILDREN),'cases':CASES,'nativeProviderEffects':False,'powerActions':False}
  save(EVIDENCE/'closure.json',closure)
  if not closure['allOwnedChildrenReaped']:raise AssertionError('owned_fixture_child_not_reaped')
 def test_1_whole_original_unreachable_queued_ack_red_candidate_unknown_green(self):
  for producer in(BEFORE,AFTER):
   with self.subTest(before=producer is BEFORE),fixture(producer)as f:
    self.assertIs(producer,f.producer);f.seed();f.mode('unreachable');v=f.run_packet(pins=f.pins)
    if producer is BEFORE:
     self.assertEqual('booting',v['facts']['guest']);self.assertEqual(1,len(f.ssh))
     with self.assertRaises(AssertionError):desired(v)
    else:
     desired(v);self.assertEqual([],f.ssh);self.assertEqual(f.rid,v['pendingShutdown']['recoveryId']);self.assertEqual(f.guest_boot,v['pendingShutdown']['originalBoot'])
     obs=readiness.Observation(f.binding['target'],f.machine,connection='local',guest='unknown',transport='ready',trusted=True,owned=True,integrity=True,idle_blockers=frozenset({'original_shutdown_pending'}))
     with self.assertRaises(readiness.ReadinessBlocked)as e:readiness._next(obs,readiness.Requirements({'guest_agent'}),'controlled')
     self.assertEqual('guest_state_unknown',e.exception.reason)
 def test_2_reachable_and_authentic_reordered_categories_still_fenced(self):
  authentic=json.loads((HERE/'original8042-public-projection.json').read_bytes())
  self.assertEqual('5b0bb04ce9b49342537421c107dc24e7fa911274c88fb9b5a6a6a37876ba5886',authentic['recoveryId'])
  self.assertEqual({'acknowledged':True,'returnCode':0},authentic['ack']);categories=authentic['idleVisibility']
  self.assertEqual(7,len(categories));self.assertEqual(7,len(set(categories)))
  for order in(categories,list(reversed(categories))):
   with self.subTest(order=order),fixture()as f:
    f.seed(order=order);v=f.run_packet(pins=f.pins);desired(v);self.assertEqual([],f.ssh)
    self.assertEqual({'present':True,'acknowledged':True,'returnCode':0},v['pendingShutdown']['ack'])
    expected={k:v['facts'][k]for k in('owner','boot','guest')};refused=f.run_packet('guest_jobs',f.pins,expected=expected)
    self.assertEqual('blocked',refused['state']);self.assertFalse(refused['vmSubmitted']);self.assertEqual([],f.ssh)
 def test_3_absent_negative_and_malformed_ack_never_grants_replay(self):
  for ack in(None,{'acknowledged':False,'returnCode':255},{'acknowledged':True,'returnCode':True},{'acknowledged':False,'returnCode':0},{'acknowledged':True,'returnCode':0,'extra':1}):
   with self.subTest(ack=ack),fixture()as f:
    f.seed(ack);v=f.run_packet(pins=f.pins)
    if ack is None or ack=={'acknowledged':False,'returnCode':255}:desired(v)
    else:self.assertEqual('blocked',v['state']);self.assertEqual('pending_shutdown_ack',v['reason']);self.assertFalse(v['vmSubmitted'])
    self.assertEqual([],f.ssh)
 def test_4_record_identity_metadata_and_generation_negatives(self):
  for mode in('foreign-owner','foreign-rid','invalid-boot','duplicate-category','multiple','mode','symlink','hardlink','replace-during-read','duplicate-key'):
   with self.subTest(mode=mode),fixture()as f:
    f.seed();p=f.root/'readiness-qemu'/(f.rid+'.intent.json');value=dict(f.intent)
    if mode=='foreign-owner':value['owner']={**f.owner,'startTicks':778}
    elif mode=='foreign-rid':value['recoveryId']='34'*32
    elif mode=='invalid-boot':value['boot']='foreign'
    elif mode=='duplicate-category':value['idleVisibility']=['reservations']*7
    if mode in('foreign-owner','foreign-rid','invalid-boot','duplicate-category'):f.write(str(p.relative_to(f.root)),json.dumps(value).encode())
    if mode=='multiple':f.write('readiness-qemu/'+('34'*32)+'.intent.json',json.dumps({**f.intent,'recoveryId':'34'*32}).encode())
    if mode=='mode':p.chmod(0o644)
    if mode=='symlink':p.rename(p.with_suffix('.held'));p.symlink_to(p.with_suffix('.held'))
    if mode=='hardlink':os.link(p,f.root/'nonowned-public-hardlink')
    if mode=='duplicate-key':
     body=p.read_text();p.write_text(body.replace('{','{\"action\":\"poweroff\",',1))
     old=f.run_packet(pins=f.pins,producer=DUP_BEFORE);desired(old)
     with self.assertRaises(AssertionError):self.assertEqual('blocked',old['state'])
    real_read=os.read;changed=[False]
    def read(fd,count):
     raw=real_read(fd,count)
     if mode=='replace-during-read' and not changed[0]and b'"action": "poweroff"'in raw:
      changed[0]=True;q=p.with_suffix('.replacement');q.write_bytes(p.read_bytes());q.chmod(0o600);os.replace(q,p)
     return raw
    v=f.run_packet(pins=f.pins,read_hook=read if mode=='replace-during-read'else None)
    if mode=='foreign-owner':self.assertEqual('running',v['facts']['guest']);self.assertNotIn('pendingShutdown',v);self.assertEqual(1,len(f.ssh))
    else:self.assertEqual('blocked',v['state']);self.assertFalse(v['vmSubmitted']);self.assertEqual([],f.ssh)
 def test_5_local_full_reply_validation_unknown_and_no_untrusted_selector(self):
  with fixture()as f:
   f.seed();valid=f.run_packet(pins=f.pins);desired(valid)
   with local_call(NEW_LOCAL,valid,self)as(backend,root):
    observed=backend.observe(readiness.Requirements({'guest_agent'}),time.monotonic()+15)
    self.assertEqual('unknown',observed.guest);self.assertEqual(frozenset({'original_shutdown_pending'}),observed.idle_blockers);self.assertEqual(valid,backend.last_response)
    trusted=backend._last_actual;bad=json.loads(json.dumps(valid));bad['pendingShutdown']['actor']['startTicks']+=1;(root/'reply').write_text(json.dumps(bad))
    with self.assertRaises(ValueError):backend.observe(readiness.Requirements({'guest_agent'}),time.monotonic()+15)
    self.assertEqual(valid,backend.last_response);self.assertEqual(valid['facts'],backend.last_facts);self.assertIs(trusted,backend._last_actual);self.assertEqual(bad,backend.retained_response)
   for mode in('foreign-actor','invalid-rid','extra','invalid-boot','ack-type','completion','missing-envelope','wrong-pins','alien-state','malformed-json'):
    value=json.loads(json.dumps(valid))
    if mode=='foreign-actor':value['pendingShutdown']['actor']['pid']+=1
    elif mode=='invalid-rid':value['pendingShutdown']['recoveryId']='bad'
    elif mode=='extra':value['pendingShutdown']['extra']=True
    elif mode=='invalid-boot':value['pendingShutdown']['originalBoot']='bad'
    elif mode=='ack-type':value['pendingShutdown']['ack']['returnCode']=True
    elif mode=='completion':value['pendingShutdown']['completionProven']=True
    elif mode=='missing-envelope':del value['pendingShutdown']
    elif mode=='wrong-pins':value['pins']={'foreign':True}
    elif mode=='alien-state':value['state']='alien'
    elif mode=='malformed-json':value=b'{"state":"observed","facts":'
    with self.subTest(mode=mode),local_call(NEW_LOCAL,value,self)as(backend,root):
     if mode=='wrong-pins':backend.pins=valid['pins']
     with self.assertRaises((ValueError,TypeError,KeyError)):backend.observe(readiness.Requirements({'guest_agent'}),time.monotonic()+15)
     self.assertIsNone(backend.last_response);self.assertIsNone(backend.last_facts);self.assertIsNone(backend._last_actual)
     if mode!='malformed-json':self.assertEqual(value,backend.retained_response)
     caps=list((root/'.runtime/readiness-qemu').glob('*/*.capture.json'));self.assertEqual(1,len(caps));captured=json.loads(caps[0].read_bytes());self.assertTrue(captured['executionComplete']);self.assertEqual(value if type(value)is bytes else json.dumps(value).encode(),captured['stdout'].encode())
 def test_7_existing_whole_expectation_before_red_current_green(self):
  old=archived('_pending_shutdown_existing_test_before','test_readiness_qemu_remote.py.before.source','54b38fa4b8b3c29d7a41eafd73fc742be6690665987daa09d4f648a2c7c839e6')
  for producer in(old,existing):
   case=producer.QemuRemotePacketTests('test_acknowledged_poweroff_blocks_new_guest_admission_causal_red_green')
   original_set_up=producer.QemuRemotePacketTests.setUp
   def setup(target):
    with mock.patch.object(tempfile,'TemporaryDirectory',side_effect=lambda *a,**kw:REAL_TEMP(dir='/private/tmp'if sys.platform=='darwin'else'/tmp',prefix='qe-')):original_set_up(target)
   with peer_compat(),mock.patch.object(producer.QemuRemotePacketTests,'setUp',setup):
    if producer is old:
     with self.assertRaises(AssertionError)as failed:case.test_acknowledged_poweroff_blocks_new_guest_admission_causal_red_green()
     self.assertIn("'booting' != 'unknown'",str(failed.exception))
     save(EVIDENCE/'whole-existing-expectation-red.json',{'errorClass':'AssertionError','reason':'preserved_expectation_booting_actual_unknown','exactExpectedFailureMatched':True})
    else:case.test_acknowledged_poweroff_blocks_new_guest_admission_causal_red_green()
 def test_6_whole_before_parsed_public_evidence_retention_red_green(self):
  reply={'state':'alien','pins':{},'facts':{'untrustedPublicFact':True}}
  for m in(OLD_LOCAL,NEW_LOCAL):
   with self.subTest(before=m is OLD_LOCAL),local_call(m,reply,self)as(backend,root):
    with self.assertRaises(ValueError):backend._run('observe','2835df1e-fc0c-4483-b2c3-66e4893af5f3',time.monotonic()+15)
    self.assertIsNone(backend.last_response);self.assertIsNone(backend.last_facts)
    if m is OLD_LOCAL:
     with self.assertRaises(AssertionError):self.assertEqual(reply,getattr(backend,'retained_response',None))
    else:self.assertEqual(reply,backend.retained_response);self.assertEqual(reply['facts'],backend.retained_facts)
    caps=list((root/'.runtime/readiness-qemu').glob('*/*.capture.json'));self.assertEqual(reply,json.loads(json.loads(caps[0].read_bytes())['stdout']))
if __name__=='__main__':unittest.main(verbosity=2)
