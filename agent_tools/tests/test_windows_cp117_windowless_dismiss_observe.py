import ast,base64,copy,hashlib,inspect,json,time,textwrap,types,unittest
from unittest.mock import patch
from agent_tools import windows_cp117_windowless_dismiss_observe as m
from agent_tools.tests import test_windows_cp117_secure_input_geometry_observe as geo
from agent_tools.tests import test_windows_cp117_secure_layout_observe as layout
from agent_tools.tests import test_windows_cp117_windowless_edit_observe as windowlessfixture

class DismissTests(unittest.TestCase):
 def value(self):return {'state':'observed','facts':geo.CensusTests().answer()}
 def record(self):
  fixture=layout.CompleteGeneratedFlowTests();src=inspect.getsource(layout.CompleteGeneratedFlowTests.execute_flow);prefix=textwrap.dedent(src).split('source,sha=')[0];prefix=prefix.replace('def execute_flow(self,stale=False,foreign=False):','def record(self):');prefix+='return record\n';ns={'secure':m.geometry.secure};exec(prefix,ns);return ns['record'](fixture)
 def test_fixed_catalog_sources_parent_child_and_unknown_slot_refusal(self):
  record=self.record()
  for slot,(corr,nonce)in m.SLOTS.items():
   source,sha=m.slot_program(record,slot);self.assertEqual(sha,m.SLOT_HASHES[slot][0]);tree=ast.parse(source)
   ns={}
   with patch('signal.signal'),patch('signal.setitimer'):exec(compile(ast.Module(body=tree.body[:-1],type_ignores=[]),'slot-definitions','exec'),ns)
   self.assertEqual(ns['NONCE'],nonce);self.assertEqual(ns['D'],corr);self.assertEqual(ns['CHILD_SHA'],m.SLOT_HASHES[slot][1]);self.assertNotIn('send-key',source)
  with self.assertRaises(ValueError):m.slot_program(record,'arbitrary')
 def flow(self,slot,stale=False):
  fixture=windowlessfixture.CensusTests()if slot=='after'else geo.CensusTests();a=fixture.answer();corr,nonce=m.SLOTS[slot];a['reader']['nonce']=a['birth']['nonce']=nonce;a['reader']['sourceSha256']=a['birth']['sourceSha256']=m.SLOT_HASHES[slot][1]
  class Adapter(unittest.TestCase):
   answer=lambda self:a
   def terminal(self,nonce=None):
    raw=('CP117-READ '+(nonce or m.SLOTS[slot][1])+' '+m.SLOT_HASHES[slot][0]+' 456\n'+json.dumps(a)).encode();return {'exited':True,'exitcode':0,'out-data':base64.b64encode(raw).decode()}
  source=textwrap.dedent(inspect.getsource(layout.CompleteGeneratedFlowTests.execute_flow)).replace('secure.program(record,secure.NONCE)','reader.program(record)')
  reader=types.SimpleNamespace(program=lambda r:m.slot_program(r,slot));secure=types.SimpleNamespace(login=m.login,CORRELATION=corr,NONCE=nonce)
  ns={'ast':ast,'base64':base64,'json':json,'patch':patch,'secure':secure,'reader':reader};exec(source,ns);return ns['execute_flow'](Adapter(),stale,False)
 def test_each_actual_generated_slot_one_submit_same_pid_and_stale_exhaustion(self):
  for slot in m.SLOTS:
   r,calls,_=self.flow(slot);self.assertEqual(r['state'],'observed',r);self.assertEqual([c[0]for c in calls],['guest-exec','guest-exec-status']);self.assertEqual(calls[1][1],{'pid':456})
  r,calls,_=self.flow('before1',stale=True);self.assertEqual(r['state'],'unknown');self.assertEqual(len(calls),81)
 def test_two_positive_no_edit_same_tree_within_fixed_age(self):
  a={'value':self.value(),'observedAtNs':1};b=copy.deepcopy(a);b['observedAtNs']=2;m._admit_pair(a,b,3)
  b['value']['facts']['facts']['secureInput']['nodes'][0]['controlId']=50004
  with self.assertRaises(ValueError):m._admit_pair(a,b,3)
  b=copy.deepcopy(a)
  with self.assertRaises(ValueError):m._admit_pair(a,b,30_000_000_002)
  b['value']['facts']['facts']['secureInput']['nodes'][0]['width']['value']=1023
  with self.assertRaises(ValueError):m._admit_pair(a,b,3)
 def test_sequence_two_before_then_one_wake_immediate_after_no_auth(self):
  calls=[];saved=[]
  def read(slot):calls.append(slot);return {'value':{'state':'observed','facts':windowlessfixture.CensusTests().answer()}if slot=='after'else self.value(),'observedAtNs':time.time_ns()}
  def wake(second):calls.append('wake');return {'state':'observed'}
  r=m._sequence(read,lambda a,b:m._admit_pair(a,b,time.time_ns()),wake,lambda n,v:saved.append(n));self.assertEqual(calls,['before1','before2','wake','after']);self.assertEqual(saved,calls);self.assertFalse(r['keyboardAdmission']);self.assertFalse(r['passwordTyped']);self.assertFalse(r['loginSubmitted'])
 def test_unknown_before_zero_key_and_lost_wake_no_after_or_replay(self):
  for failed in('before1','before2','wake','after'):
   calls=[]
   def read(slot):calls.append(slot);return {'value':{'state':'unknown'}if slot==failed else self.value(),'observedAtNs':time.time_ns()}
   def wake(second):calls.append('wake');return {'state':'unknown'if failed=='wake'else'observed'}
   with self.assertRaises(ValueError):m._sequence(read,lambda a,b:m._admit_pair(a,b,time.time_ns()),wake,lambda n,v:None)
   expected={'before1':['before1'],'before2':['before1','before2'],'wake':['before1','before2','wake'],'after':['before1','before2','wake','after']}[failed];self.assertEqual(calls,expected)
 def test_actual_generated_wake_only_one_fixed_released_key_fence_first_raw_retained(self):
  source=m.wake_program(self.record(),{'observedAtNs':123});self.assertEqual(source.count("'execute':'send-key'"),1);self.assertIn("'data':'ret'",source);self.assertIn("'hold-time':100",source);self.assertNotIn('guest-exec',source)
  self.assertIn('beforeFrameAuthority',source);self.assertIn('os.fsync(fd);os.fsync(jobfd)',source);self.assertIn("'dismiss-session-expired'",source)
  self.assertLess(source.index('def wake_fence'),source.index('def key()'));self.assertIn('verify();fence();verify();key();value=capture_post();verify();return value',inspect.getsource(m.login._guarded_wake))
 def test_existing_strict_clock_page_guard_no_key_on_foreign_or_expired_frame(self):
  calls=[]
  for age in (0,6):
   with patch.object(m.login,'_validate_lockscreen',side_effect=ValueError('foreign-clock')):
    with self.assertRaises(ValueError):m.login._guarded_wake(b'foreign',age,lambda:calls.append('verify'),lambda:calls.append('fence'),lambda:calls.append('key'),lambda:None)
  self.assertEqual(calls,[])
  with patch.object(m.login,'_validate_lockscreen'):
   with self.assertRaises(ValueError):m.login._guarded_wake(b'fixture',6,lambda:calls.append('verify'),lambda:calls.append('fence'),lambda:calls.append('key'),lambda:None)
  self.assertEqual(calls,[])

class ActualStartWrapperTests(unittest.TestCase):
 def run_start(self,failed_before=False,poisoned=False):
  import tempfile,os,gzip
  from pathlib import Path
  from contextlib import ExitStack
  r=m.login.guest.recovery;authority=r.authority;records={};native=[];streams=[];frame=b'P6\n1 1\n255\nabc'
  def bound(path):return {'sha256':hashlib.sha256(Path(path).read_bytes()).hexdigest(),'generation':[1]}
  recovery_pin=bound(r.__file__);original=json.dumps({'request':{'sources':{'recovery':recovery_pin}},'authority':[],'result':{'qemu':{'pid':1}}}).encode()
  class Capture:
   def __init__(self,root,leaf):self.path=Path(root)/'.runtime/parity-evidence'/leaf;self.fd=os.open(root,os.O_RDONLY);self.leaf=leaf
   def close(self):os.close(self.fd)
   def create(self,name,raw):records[(self.leaf,name)]=raw;return {'sha256':hashlib.sha256(raw).hexdigest()}
  def stream(argv,c,diagnostic,nonce,sha,qemu):
   streams.append(diagnostic);return ({'state':'unknown'}if failed_before else {'state':'observed','facts':windowlessfixture.CensusTests().answer()}if diagnostic==m.SLOTS['after'][0]else DismissTests().value()),[]
  def run(*args,**kwargs):
   self.assertIn(('windows-cp117-windowless-dismiss-'+m.CORRELATION,'wake-attempt.json'),records);native.append('wake')
   v={'state':'observed','frameGzip':base64.b64encode(gzip.compress(frame)).decode(),'frameSha256':hashlib.sha256(frame).hexdigest(),'qemu':{'pid':1},'bootId':r.BOOT_ID,'beforeFrameAuthority':{'diagnosticOnly':True}}
   if not poisoned:v.update(valid_authorities({'pid':1}))
   return types.SimpleNamespace(returncode=0,stdout=json.dumps(v).encode(),stderr=b'')
  with tempfile.TemporaryDirectory()as directory,ExitStack()as stack:
   root=Path(directory);(root/'.runtime/parity-evidence').mkdir(parents=True)
   mocks=[(m,'_check_factories',lambda:None),(m,'AuthorityCapture',Capture),(r,'_local_read',lambda *a:original),(authority,'_read_bound_file',bound),(authority,'_source_pins',lambda *a:{}),(authority,'_outer_authority',lambda *a:{}),(authority,'_verify_outer',lambda *a:None),(authority.closure.base,'_descriptor',lambda *a:(object(),types.SimpleNamespace(fixture_transfer_root=m.login.TRANSFER),None)),(authority.closure.base.ssh_transport,'build_ssh_argv',lambda *a,**k:['inert']),(m.login.guest,'_stream',stream),(m,'slot_program',lambda record,slot:('print("fixed-read")','a'*64)),(m,'wake_program',lambda record,admission:'print("fixed-one-wake")'),(m.subprocess,'run',run),(m.login,'_frame_create',lambda capture,raw:{'sha256':hashlib.sha256(raw).hexdigest()})]
   for target,name,value in mocks:stack.enter_context(patch.object(target,name,value))
   result=m.start(root)
  return result,native,streams,records
 def test_actual_start_retains_before_results_then_consumes_before_one_wake_then_after(self):
  result,native,streams,records=self.run_start();self.assertEqual(result['state'],'observed',result);self.assertEqual(native,['wake']);self.assertEqual(streams,[x[0]for x in m.SLOTS.values()]);self.assertFalse(result['passwordTyped']);self.assertFalse(result['loginSubmitted'])
 def test_actual_start_unknown_before_has_no_effect_fence_or_wake(self):
  result,native,streams,records=self.run_start(failed_before=True);self.assertEqual(result['state'],'unknown');self.assertEqual(native,[]);self.assertEqual(len(streams),1);self.assertFalse(any(name=='wake-attempt.json'for leaf,name in records))

class MissingPreFrameCausalTests(ActualStartWrapperTests):
 def test_actual_observed_wake_missing_unbound_preframe_is_not_accepted(self):
  result,native,streams,records=self.run_start(poisoned=True);self.assertEqual(result['state'],'unknown');self.assertEqual(native,['wake']);self.assertEqual(len(streams),2)

def valid_authorities(qemu):
 g={'st_dev':66307,'st_ino':1234,'st_mode':33152,'st_uid':1000,'st_gid':1000,'st_nlink':1,'st_size':3072016,'st_mtime_ns':1,'st_ctime_ns':1};sha='a'*64
 before={'path':m.login.TRANSFER+'/cp117-login-screen-'+m.CORRELATION+'/frame.ppm','generation':g,'sha256':sha};record={'state':'consumed','diagnosticId':m.CORRELATION,'qemu':qemu,'frameSha256':sha};raw=json.dumps(record,sort_keys=True).encode();ag=dict(g,st_ino=5678,st_size=len(raw))
 return {'beforeFrameAuthority':before,'wakeAuthority':{'generation':ag,'sha256':hashlib.sha256(raw).hexdigest(),'record':record}}

class AuthoritySchemaTests(unittest.TestCase):
 def test_missing_poisoned_preframe_or_attempt_never_accepts(self):
  qemu={'pid':1};value=valid_authorities(qemu);self.assertEqual(m._frame_authority(value,qemu),value['beforeFrameAuthority'])
  for edit in(lambda v:v.pop('beforeFrameAuthority'),lambda v:v['beforeFrameAuthority'].update(path='/foreign/frame.ppm'),lambda v:v['beforeFrameAuthority']['generation'].update(st_mode=33188),lambda v:v['beforeFrameAuthority']['generation'].update(st_nlink=2),lambda v:v['beforeFrameAuthority']['generation'].update(st_size=1),lambda v:v['beforeFrameAuthority'].update(sha256='z'*64),lambda v:v.pop('wakeAuthority'),lambda v:v['wakeAuthority']['record'].update(frameSha256='b'*64),lambda v:v['wakeAuthority']['record'].update(qemu={'pid':99}),lambda v:v['wakeAuthority']['record'].update(diagnosticId='old'),lambda v:v['wakeAuthority'].update(sha256='b'*64),lambda v:v['wakeAuthority']['generation'].update(st_size=1)):
   v=copy.deepcopy(value);edit(v)
   with self.assertRaises(ValueError):m._frame_authority(v,qemu)
 def test_generated_actual_pre_key_guard_pins_preframe_attempt_after_read(self):
  source=m.wake_program(DismissTests().record(),{'observedAtNs':123})
  self.assertIn("wake_authority.update({'generation':fp(os.fstat(f))",source);self.assertIn("'dismiss-preframe-drift'",source);self.assertIn("hashlib.sha256(ab).hexdigest()==wake_authority['sha256']",source);self.assertIn("'wakeAuthority':wake_authority",source)

class WindowlessAdmissionTests(unittest.TestCase):
 def test_actual_after_parser_required_and_diagnostic_flags_never_input_admission(self):
  calls=[]
  def read(slot):
   calls.append(slot);return {'value':DismissTests().value(),'observedAtNs':time.time_ns()}
  with self.assertRaises(ValueError):m._sequence(read,lambda a,b:m._admit_pair(a,b,time.time_ns()),lambda b:{'state':'observed'},lambda n,v:None)
  self.assertEqual(calls,['before1','before2','after'])
 def test_actual_foreign_before_no_key_and_future_timestamp_refused(self):
  a={'value':DismissTests().value(),'observedAtNs':time.time_ns()+1_000_000_000}
  with self.assertRaises(ValueError):m._admit_pair(a,a,time.time_ns())
  a['value']['facts']['facts']['secureInput']['nodes'][0]['pid']=1
  with self.assertRaises(ValueError):m._no_edit(a['value'])
