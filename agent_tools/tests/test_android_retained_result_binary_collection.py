"""Actual fake children and fixed retained828 framing; no native capability."""
import base64,hashlib,importlib.util,json,os,re,sys,tempfile,time,types,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=next(path for path in HERE.parents if (path/'agent_tools').is_dir())
if str(ROOT)not in sys.path:sys.path.insert(0,str(ROOT))
FIX=HERE/'fixtures'/'android_retained_record_binary'
from agent_tools import android_original_host_wire as owner
decoder=types.SimpleNamespace(decode=owner.decode_retained_record_frames,CORR='828431f1-5588-4b99-b85c-1bf1dece9da9')
try:
 import fcntl
 POSIX=os.name=='posix'and all(hasattr(os,x)for x in ('O_NOFOLLOW','O_DIRECTORY','pread'))
except ImportError:POSIX=False
# This ignored candidate exercises the proposed actual pure owner module.
SIZE=3534648
DATA=b'{"fake":"'+b'x'*(SIZE-11)+b'"}'
DIGEST=hashlib.sha256(DATA).hexdigest()
PIN={'generation':[66307,123456789,SIZE,1791900000000000000,1791900000000000000,384,1000,1],'sha256':DIGEST,'bytes':SIZE,'ancestry':[[66307,120001+i,16832,1000]for i in range(5)],'hostBootId':'25515f23-b966-4c3a-ae63-d38452375578'}
def frame(offset,body,eof):
 return json.dumps({'state':'record-authenticated','correlationId':decoder.CORR,'receiptPin':PIN,'pin':PIN,'replayAllowed':False,'sourceClosingAuthenticated':True,'kind':'receipt','offset':offset,'chunk':base64.b64encode(body).decode(),'eof':eof},separators=(',',':')).encode()+b'\n'
WIRE=b''.join(frame(i,DATA[i:i+1536],i+1536>=SIZE)for i in range(0,SIZE,1536))
class PureFraming(unittest.TestCase):
 def test_full_wire_preserves_all_record_bytes(self):self.assertEqual(DATA,decoder.decode(WIRE,PIN))
 def test_duplicate_frame(self):self.refuses(WIRE.splitlines(keepends=True)[:1]+WIRE.splitlines(keepends=True))
 def test_missing_frame(self):self.refuses(WIRE.splitlines(keepends=True)[1:])
 def test_reordered_frames(self):
  rows=WIRE.splitlines(keepends=True);self.refuses(rows[1:2]+rows[:1]+rows[2:])
 def test_truncated_final_frame(self):self.refuses([WIRE[:-1]])
 def test_oversized_frame(self):self.refuses([b'x'*4097+b'\n']+WIRE.splitlines(keepends=True)[1:])
 def changed(self,key,value):
  rows=WIRE.splitlines(keepends=True);first=json.loads(rows[0]);first[key]=value;self.refuses([json.dumps(first,separators=(',',':')).encode()+b'\n']+rows[1:])
 def refuses(self,rows):
  with self.assertRaises((ValueError,TypeError)):decoder.decode(b''.join(rows),PIN)
 def test_bool_offset(self):self.changed('offset',False)
 def test_changed_generation(self):self.changed('pin',dict(PIN,generation=[0]*8))
 def test_early_eof(self):self.changed('eof',True)
 def test_changed_hash(self):self.changed('chunk',base64.b64encode(b'z'*1536).decode())
 def test_false_closing(self):self.changed('sourceClosingAuthenticated',False)
 def test_wrong_correlation(self):self.changed('correlationId','00000000-0000-0000-0000-000000000000')
 def test_expected_bytes_bool_refused(self):
  with self.assertRaises(ValueError):decoder.decode(WIRE,dict(PIN,bytes=True))
 def test_expected_missing_bytes_refused(self):
  pin=dict(PIN);del pin['bytes']
  with self.assertRaises(ValueError):decoder.decode(WIRE,pin)
 def test_expected_hash_shape_refused(self):
  with self.assertRaises(ValueError):decoder.decode(WIRE,dict(PIN,sha256='g'*64))
 def test_duplicate_json_key_refused(self):
  rows=WIRE.splitlines(keepends=True);rows[0]=rows[0].replace(b'{',b'{"offset":0,',1)
  self.refuses(rows)
 def typed_row_pin(self,field,mutate):
  rows=WIRE.splitlines(keepends=True);first=json.loads(rows[0]);mutate(first[field]);rows[0]=json.dumps(first,separators=(',',':')).encode()+b'\n'
  self.refuses(rows)
 def test_row_pin_bool_nlink_is_refused(self):
  self.typed_row_pin('pin',lambda pin:pin['generation'].__setitem__(7,True))
 def test_row_receipt_pin_bool_nlink_is_refused(self):
  self.typed_row_pin('receiptPin',lambda pin:pin['generation'].__setitem__(7,True))
 def test_row_pin_other_scalar_types_are_refused(self):
  mutations=[('bytes_float',lambda pin:pin.__setitem__('bytes',float(pin['bytes']))),('device_float',lambda pin:pin['generation'].__setitem__(0,float(pin['generation'][0]))),('size_float',lambda pin:pin['generation'].__setitem__(2,float(pin['generation'][2]))),('mode_float',lambda pin:pin['generation'].__setitem__(5,384.0)),('uid_float',lambda pin:pin['generation'].__setitem__(6,1000.0)),('ancestry_mode_float',lambda pin:pin['ancestry'][0].__setitem__(2,float(pin['ancestry'][0][2])))]
  for field in ('pin','receiptPin'):
   for name,mutate in mutations:
    with self.subTest(field=field,mutation=name):self.typed_row_pin(field,mutate)
@unittest.skipUnless(POSIX,'Actual POSIX FD capture requires fcntl/O_NOFOLLOW/pread')
class ActualChildCapture(unittest.TestCase):
 def setUp(self):
  from agent_tools import android_installer_direct_transport
  self.direct=android_installer_direct_transport;self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700);self.count=0
  self.data=self.root/'data';self.data.mkdir(mode=0o700);self.private(self.data/'result.private.json',DATA);self.private(self.data/'boot.private',PIN['hostBootId'].encode())
 def private(self,path,raw):
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 def sender(self,fixture='sender-green.source'):
  source=(FIX/fixture).read_text()
  source=re.sub(r'root=Path\([^\n;]+\);uid=\d+;',lambda _: 'root=Path('+repr(str(self.data))+');uid='+str(os.getuid())+';',source,count=1)
  return source
 def capture(self,source,*,timeout=False,change=False):
  import subprocess
  self.count+=1;capsule=self.root/('capture-'+str(self.count));capsule.mkdir(mode=0o700)
  self.private(capsule/'source.py',source.encode());relative=str((capsule/'source.py').relative_to(self.root));pins={relative:self.direct.snapshot(capsule/'source.py',private=False)[1]}
  namespace=dict(self.direct._transport_capture.__globals__)
  if timeout:
   start=time.monotonic();namespace['time']=types.SimpleNamespace(monotonic=lambda:(time.monotonic()-start)*1000+start,monotonic_ns=time.monotonic_ns)
  collect=types.FunctionType(self.direct._transport_capture.__code__,namespace)
  child,out,err,eof,reason=collect(capsule,[sys.executable,'-I','-B','-c',source],b'\n','readonly',self.root,pins,hashlib.sha256(source.encode()).hexdigest())
  if child.poll()is None:child.kill();child.wait(timeout=2)
  for pipe in (child.stdin,child.stdout,child.stderr):
   if pipe is not None and not pipe.closed:pipe.close()
  terminal=json.loads((capsule/'readonly-raw-terminal.json').read_bytes())
  retained=b''.join((capsule/Path(x['path']).name).read_bytes()for x in terminal['raw']['stdout']['chunks']);self.assertEqual(out,retained)
  if change:(capsule/'source.py').write_text('source-changed\n')
  closed=True
  try:self.direct._source_guard(self.root,pins)
  except ValueError:closed=False
  return child,out,eof,reason,closed,capsule
 def projected(self,result):
  child,out,eof,reason,closed,_=result
  if child.returncode!=0 or not all(eof.values())or reason is not None or not closed:raise ValueError('capture_not_closed')
  return decoder.decode(out,PIN)
 def test_one_child_all2302frames_full_retention_before_source_close_and_decode(self):
  result=self.capture(self.sender());self.assertEqual(DATA,self.projected(result));self.assertEqual(1,self.count);self.assertEqual(2302,len(result[1].splitlines()));self.assertLessEqual(len(result[1]),8388608);self.assertLessEqual(max(map(len,result[1].splitlines(keepends=True))),4096)
 def test_partial_nonzero_retained_and_refused(self):
  result=self.capture("import sys;sys.stdin.buffer.read(1);sys.stdout.buffer.write(b'partial');sys.exit(3)");self.assertEqual(b'partial',result[1])
  with self.assertRaises(ValueError):self.projected(result)
 def test_record4mib_plus_one_refused(self):
  changed=dict(PIN,bytes=4194305)
  with self.assertRaises(ValueError):decoder.decode(WIRE,changed)
  result=self.capture(self.sender().replace('expected_size=3534648','expected_size=4194305'));self.assertEqual(b'',result[1])
  with self.assertRaises(ValueError):self.projected(result)
 def test_timeout_keeps_partial_and_forbids_projection(self):
  result=self.capture("import sys,time;sys.stdin.buffer.read(1);sys.stdout.buffer.write(b'prefix');sys.stdout.buffer.flush();time.sleep(10)",timeout=True);self.assertEqual(b'prefix',result[1]);self.assertEqual('direct_transport_timeout',result[3])
  with self.assertRaises(ValueError):self.projected(result)
 def test_source_closure_failure_refuses_complete_wire(self):
  result=self.capture(self.sender(),change=True);self.assertEqual(WIRE,result[1]);self.assertFalse(result[4])
  with self.assertRaises(ValueError):self.projected(result)
 def test_generation_changed_after_opening_refuses(self):
  result=self.capture(self.sender().replace('guard();digest();guard()','guard();digest();guard();os.utime(root/leaf,None)'))
  with self.assertRaises(ValueError):self.projected(result)
 def test_original_once_fence_forbids_replay(self):
  result=self.capture(self.sender());capsule=result[-1]
  with self.assertRaises(FileExistsError):self.direct._transport_capture(capsule,[sys.executable,'-c','raise AssertionError("replay")'],b'\n','readonly',self.root,{},'a'*64)
 def test_original_local_missing_json_before_is_red(self):
  with self.assertRaises(ValueError):self.projected(self.capture(self.sender('sender-missing-json-before.source')))
 def test_original_local_pin_shadow_before_is_red(self):
  with self.assertRaises(ValueError):self.projected(self.capture(self.sender('sender-shadow-before.source')))
 def test_preserved8135_one_frame_is_refused_as_incomplete(self):
  old=(FIX/'collector-8135-before.source').read_text()
  # Explicit fixture seams only: local owner, fake boot path, fixed local args,
  # initial pin generated by the same original8135 private_snapshot function.
  old=old.replace('root_raw,kind,offset_raw,pin_raw=sys.argv[1:]','root_raw,kind,offset_raw,pin_raw='+repr((str(self.data),'receipt','0','null')))
  old=old.replace('os.getuid()!=1000','os.getuid()!='+str(os.getuid()))
  old=old.replace("Path('/proc/sys/kernel/random/boot_id')","Path("+repr(str(self.data/'boot.private'))+")")
  old=old.replace("if requested!=pin or offset>len(raw)","requested=pin\n  if requested!=pin or offset>len(raw)")
  directory=self.data/'android-current-readonly-retirement-facts-828431f1-5588-4b99-b85c-1bf1dece9da9';directory.mkdir(mode=0o700)
  obj={'scope':'fixed_readonly_retirement_facts_only','correlationId':decoder.CORR,'originalOutcome':'UNKNOWN','leaseReleased':False,'replayAllowed':False,'guestMutationPerformed':False,'componentCertificateCreated':False,'retirementAdmission':False,'fake':''}
  prefix=json.dumps(obj,separators=(',',':')).encode();obj['fake']='x'*(SIZE-len(prefix));payload=json.dumps(obj,separators=(',',':')).encode();self.assertEqual(SIZE,len(payload));self.private(directory/'result.private.json',payload)
  result=self.capture(old);child,out,eof,reason,closed,capsule=result
  row=json.loads(out);self.assertEqual('record-authenticated',row['state']);self.assertTrue(row['sourceClosingAuthenticated']);self.assertEqual(0,child.returncode);self.assertTrue(closed);self.assertTrue(all(eof.values()));self.assertIsNone(reason)
  pin=json.loads(json.dumps(row['pin']));pin['generation'][6]=1000 # explicit local UID fixture seam
  with self.assertRaisesRegex(ValueError,'frame_count'):decoder.decode(out,pin)
 def test_unchanged8mib_transport_refuses_overflow(self):
  self.assertEqual(8388608,self.direct.MAX_RAW)
  result=self.capture("import sys;sys.stdin.buffer.read(1);sys.stdout.buffer.write(b'x'*8388609)")
  self.assertEqual('direct_transport_raw_limit',result[3]);self.assertLessEqual(len(result[1]),8388608)
  with self.assertRaises(ValueError):self.projected(result)
if __name__=='__main__':unittest.main()
