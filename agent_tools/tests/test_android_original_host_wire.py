from pathlib import Path
import ast,base64,hashlib,json,os,random,subprocess,sys,tempfile,unittest,zlib
D=Path(__file__).resolve().parent
from agent_tools.android_qualified_cli_observation import OuterCustody
from agent_tools import android_original_host_wire as wire_module
codec=vars(wire_module)
MODE=os.environ.get('VC_CODEC_MODE','green')

def original_emit():
 return (D/'fixtures/android_host11_before_emit.py').read_text()

def payload(large):
 roles={}
 for name,limit in codec['ROLE_LIMITS'].items():
  data=bytes(range(256))*min(2,limit//256)
  roles[name]={'state':'present','bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'generation':[1,2,len(data),3,4,384,1000,1],'base64':base64.b64encode(data).decode()}
 value={'state':'observed','correlationId':'0dd55704-1e80-4d62-8d9d-2f0a123e0c3b','replayAllowed':False,'leaseReleased':False,'records':roles,'actorPasses':[{'worker':{'state':'absent','pid':1169929,'expectedStartTicks':72285068},'fixture':{'state':'absent','pid':1172004,'expectedStartTicks':72288190}}]*2,'fixturePadding':''}
 if large:
  name='output/phase-check.json'
  baseline=len(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
  amount=((128567-baseline)//4)*3+roles[name]['bytes']
  data=(bytes(range(256))*((amount+255)//256))[:amount]
  roles[name].update(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),base64=base64.b64encode(data).decode())
  missing=128567-len(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
  if missing<0:
   data=data[:len(data)-3];roles[name].update(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),base64=base64.b64encode(data).decode());missing=128567-len(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
  value['fixturePadding']='x'*missing
  assert len(json.dumps(value,sort_keys=True,separators=(',',':')).encode())==128567
 return value

@unittest.skipUnless(os.name == 'posix', 'POSIX subprocess pipe custody required')
class CausalCapacityTests(unittest.TestCase):
 def roundtrip(self,large):
  value=payload(large)
  with tempfile.TemporaryDirectory(prefix='vcz-',dir=Path('/tmp').resolve())as temporary:
   p=Path(temporary)/'payload.json';p.write_text(json.dumps(value));p.chmod(0o600)
   if MODE=='red':producer='import json,sys; result=json.loads(open(sys.argv[1]).read()); CORRELATION=result["correlationId"];\n'+original_emit()
   else:producer=Path(wire_module.__file__).read_text()+'\nimport sys;result=json.loads(open(sys.argv[1]).read());print(encode_payload(result).decode("ascii"),flush=True)'
   custody=OuterCustody([sys.executable,'-I','-B','-c',producer,str(p)]);custody.send(b'{}');initial=custody.observe(5);custody.finish_naturally();final=custody.snapshot()
   self.assertTrue(initial['complete']);self.assertTrue(final['complete']);self.assertEqual(0,final['returnCode']);self.assertTrue(all(final['eof'].values()));self.assertFalse(final['overflow']);self.assertFalse(final['timeout']);self.assertEqual(b'',bytes(custody.raw['stderr']))
   if os.environ.get('VC_TEST_CAPTURE'):
    evidence=Path(os.environ['VC_TEST_CAPTURE']);evidence.mkdir(mode=0o700,parents=True,exist_ok=True)
    stem='large'if large else'small'
    for role in ('stdout','stderr'):
     target=evidence/(stem+'.'+role);target.write_bytes(bytes(custody.raw[role]));target.chmod(0o600)
    receipt={'initial':initial,'final':final,'streams':{role:{'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}for role,raw in custody.raw.items()}}
    target=evidence/(stem+'.receipt.json');target.write_text(json.dumps(receipt,sort_keys=True)+'\n');target.chmod(0o600)
   raw=bytes(custody.raw['stdout']);self.assertEqual(len(raw),final['counts']['stdout']);self.assertLessEqual(len(raw),65536)
   envelope=json.loads(raw)
   if envelope.get('codec')==codec['CODEC']:
    decoded=codec['decode_payload_bytes'](raw)
    expected=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
    self.assertEqual(expected,decoded)
    self.assertEqual(hashlib.sha256(expected).hexdigest(),envelope['decodedSha256'])
    self.assertEqual(len(expected),envelope['decodedBytes'])
    actual=codec['decode_payload'](raw)
   else:actual=envelope
   self.assertEqual(value,actual)
   for role,row in actual['records'].items():
    binary=base64.b64decode(row['base64'],validate=True);self.assertEqual(row['bytes'],len(binary));self.assertEqual(row['sha256'],hashlib.sha256(binary).hexdigest())
 def test_small_whole_envelope_preserves_all_binary_records(self):self.roundtrip(False)
 def test_actual128567_byte_envelope_preserves_all_records_inside_unchanged_wire_cap(self):self.roundtrip(True)

class StrictCodecTests(unittest.TestCase):
 def test_status_collection_without_fcntl_keeps_pure_codec_controls_available(self):
  source=Path(__file__).with_name('test_android_original_host_status.py')
  programme='''import importlib.abc,runpy,sys
class MissingFcntl(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname=='fcntl':raise ModuleNotFoundError("no fcntl on Windows",name='fcntl')
sys.path.insert(0,sys.argv[2]);sys.meta_path.insert(0,MissingFcntl());sys.modules.pop('fcntl',None)
runpy.run_path(sys.argv[1],run_name='portable_collection')
'''
  completed=subprocess.run([sys.executable,'-I','-B','-c',programme,str(source),str(Path(sys.modules[OuterCustody.__module__].__file__).resolve().parents[1])],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=False)
  self.assertEqual(0,completed.returncode,completed.stderr.decode('utf-8','replace'))
 def frame(self,decoded,compressed=None,**changes):
  envelope={'codec':codec['CODEC'],'decodedBytes':len(decoded),'decodedSha256':hashlib.sha256(decoded).hexdigest(),'payload':base64.b64encode(zlib.compress(decoded)if compressed is None else compressed).decode()};envelope.update(changes);return json.dumps(envelope,separators=(',',':')).encode()+b'\n'
 def refuse(self,wire):
  with self.assertRaises((ValueError,zlib.error)):codec['decode_payload'](wire)
 def test_strict_closed_json_types_lengths_hashes_and_binary_framing(self):
  decoded=b'{"ok":true}';good=self.frame(decoded);self.assertEqual({'ok':True},codec['decode_payload'](good))
  cases=[good+b'\n',good+b'x',good[:-1]+b' ',b'{"codec":1,"codec":2}',self.frame(decoded,decodedBytes=True),self.frame(decoded,decodedBytes=-1),self.frame(decoded,decodedBytes=len(decoded)+1),self.frame(decoded,decodedSha256='0'*64),self.frame(decoded,payload='non-base64!'),self.frame(decoded,payload=base64.b64encode(zlib.compress(decoded)).decode()+'='),self.frame(b'{"a":1,"a":2}'),self.frame(b'{"a":1} '),self.frame(b'{"a":NaN}'),self.frame(b'{"a":1e9999}'),self.frame(b'{"a":-1e9999}'),self.frame(b'[]'),b'x'*65537]
  for wire in cases:
   with self.subTest(length=len(wire)):self.refuse(wire)
 def test_actual_compressed_eof_trailing_stream_and_bomb_refuse(self):
  decoded=b'{"ok":true}';compressed=zlib.compress(decoded)
  for bad in (compressed[:-1],compressed+b'\x00',compressed+zlib.compress(decoded)):
   with self.subTest(bytes=len(bad)):self.refuse(self.frame(decoded,bad))
  bomb=b'x'*(codec['DECODED_LIMIT']+1);self.refuse(self.frame(bomb,decodedBytes=codec['DECODED_LIMIT']))
 def test_encoder_preserves_original_frame_and_decoded_bounds(self):
  with self.assertRaises(ValueError):codec['encode_payload']({'large':'x'*codec['DECODED_LIMIT']})
  entropy=random.Random(17).randbytes(60000)
  with self.assertRaises(ValueError):codec['encode_payload']({'binary':base64.b64encode(entropy).decode()})

if __name__=='__main__':unittest.main()
