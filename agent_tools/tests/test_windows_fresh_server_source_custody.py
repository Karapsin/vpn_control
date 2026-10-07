"""Actual public population, retained FD and publication boundary controls.

Synthetic source files/authority only; collector stops before native calls.
PublicInputs and phase factory are authenticated source fixtures, unchanged.
"""
import ast,hashlib,json,os,tempfile,unittest,types,importlib.util
from pathlib import Path
P=Path(__file__).resolve().parent
ROOT=next(parent for parent in P.parents if (parent/'agent_tools/native_review_source_closure.py').is_file())
FIXTURES=P/'fixtures/windows_fresh_server_source_custody'
TEMP_ROOT=os.environ.get('TEST_OUTPUT_ROOT')
def load(path):
 ns={'__name__':'public_synthetic_fixture','__file__':str(path)}
 exec(compile(path.read_bytes(),str(path),'exec'),ns);return ns
support=types.SimpleNamespace(load=load,holder=lambda:load(FIXTURES/'public_inputs.source'),factory=lambda:load(FIXTURES/'phase_factory.source'))
helper=load(P.parent/'windows_fresh_server_source_custody.py')
wrapper=types.SimpleNamespace(expand_public_inputs=helper['expand_public_inputs'],load_holder=lambda:load(ROOT/'agent_tools/native_review_source_closure.py')['_Held'])
class NoNative(RuntimeError):pass
class Custody(unittest.TestCase):
 def run_boundary(self,expanded,mutation,publication=False):
  ns=support.load(FIXTURES/'direct_executor.source');authority=support.load(ROOT/'agent_tools/windows_diagnostic_authority_capture.py')['AuthorityCapture'];holder=support.holder();Held=wrapper.load_holder();plan={'phaseCorrelation':'50213a23-d04c-4d4a-9f58-e4df48a504bb','phaseNonce':'b0c027ab-fa12-4a0f-be6b-9e4976ffe076'};calls=[];publications=[]
  with tempfile.TemporaryDirectory(dir=TEMP_ROOT)as temp:
   root=Path(temp).resolve();(root/'.runtime/parity-evidence').mkdir(parents=True);base=root/'base.py';new=root/'new.py';base.write_bytes(b'PUBLIC_BASE=True\n');new.write_bytes(b'PUBLIC_AUTHORED=True\n');os.chmod(base,0o600);os.chmod(new,0o600)
   manifest=root/'base-inputs.json';manifest.write_text(json.dumps({'version':1,'scope':'complete-direct-public-update-source','inputs':{str(base):{'generation':holder['generation'](base.stat()),'sha256':hashlib.sha256(base.read_bytes()).hexdigest()}}}));os.chmod(manifest,0o600)
   inputs=holder['PublicInputs'](root,manifest,hashlib.sha256(manifest.read_bytes()).hexdigest());held=Held();held.read(str(new),hashlib.sha256(new.read_bytes()).hexdigest())
   try:
    if expanded:wrapper.expand_public_inputs(inputs,held)
    def argv(command):
     if mutation:new.write_bytes(b'FOREIGN_AUTHORED=True\n')
     return ['NO_NATIVE']
    class Capture(authority):
     def create(self,name,raw):
      pin=super().create(name,raw)
      if publication and name=='result.json':publications.append(True);new.write_bytes(b'FOREIGN_PUBLICATION=True\n')
      return pin
    def collect(argv,capture,verify,frame,c,n,digest,q,**kw):
     calls.append(True)
     if not publication:raise NoNative('synthetic-fence')
     events=[]
     for kind in ('submitted','terminal'):
      event={'diagnosticId':c,'nonce':n,'sourceSha256':digest,'qemu':q,'kind':kind,'pid':23}
      if kind=='terminal':event.update(poll=1,payload={'facts':{'state':'synthetic-public'}})
      pin=capture.create(c+'-event-'+str(len(events))+'.json',json.dumps(event).encode());events.append({'event':event,'pin':pin})
     return {'state':'observed','facts':{'state':'synthetic-public'},'qemu':q,'guestChildPid':23,'appAdmission':False,'installerAction':False},events,{'returncode':0,'pipesClosed':True,'sourceFrameWritten':True,'ackWritten':True,'birth':'synthetic-public-birth'}
    context={'root':root,'consumed':set(),'verify':inputs.verify,'stdin_command':lambda s:('synthetic',b'public-source'),'ssh_argv':argv,'capture_class':Capture,'guest_collect':collect,'factory':support.factory(),'qemu':{'pid':17}}
    source='D='+repr(plan['phaseCorrelation'])+'\nNONCE='+repr(plan['phaseNonce'])+"\nBODY_SHA='"+'1'*64+"'\n"
    source+="import re,types\ndef validate(v):\n if type(v)is not dict or v!={'state':'synthetic-public'}:raise ValueError('synthetic-facts')\n return v\ndef parse_terminal(p,n,s,c):return validate(p['facts'])\n"
    result=ns['run_direct_server'](context,source,'1'*64,b'\x00\x00\x00\x02{}',(b'SYNTHETIC_PRIVATE_MARKER',))
    if publication:self.assertEqual(publications,[True])
    return len(calls),result
   finally:inputs.close();held.close()
 def test_actual_original_population_red(self):
  count,result=self.run_boundary(False,True);self.assertEqual(count,1);self.assertEqual(result['state'],'unknown')
 def test_actual_unified_population_green_refuses_before_collector(self):
  count,result=self.run_boundary(True,True);self.assertEqual(count,0);self.assertEqual(result['state'],'unknown');self.assertIs(result['replayAllowed'],False)
 def test_actual_unified_unchanged_population_reaches_fence(self):
  count,result=self.run_boundary(True,False);self.assertEqual(count,1);self.assertEqual(result['state'],'unknown')
 def test_actual_final_result_publication_source_drift_refuses_observed(self):
  count,result=self.run_boundary(True,False,True);self.assertEqual(count,1);self.assertEqual(result['state'],'unknown');self.assertEqual(result['exceptionType'],'ValueError');self.assertIs(result['replayAllowed'],False)
 def test_genuine_foreign_root_population_refuses(self):
  with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as tmp:
   root=Path(tmp).resolve();inside=root/'inside';inside.mkdir();foreign=root/'outside.py';foreign.write_bytes(b'PUBLIC=True\n');foreign.chmod(0o600)
   ns=support.holder();base=inside/'base.py';base.write_bytes(b'PUBLIC_BASE=True\n');base.chmod(0o600)
   manifest=inside/'inputs.json';manifest.write_text(json.dumps({'version':1,'scope':'complete-direct-public-update-source','inputs':{str(base):{'generation':ns['generation'](base.stat()),'sha256':hashlib.sha256(base.read_bytes()).hexdigest()}}}));manifest.chmod(0o600)
   inputs=ns['PublicInputs'](inside,manifest,hashlib.sha256(manifest.read_bytes()).hexdigest());held=wrapper.load_holder()()
   try:
    held.read(str(foreign),hashlib.sha256(foreign.read_bytes()).hexdigest())
    with self.assertRaisesRegex(ValueError,'sibling-expanded-source-root'):wrapper.expand_public_inputs(inputs,held)
    self.assertNotIn(str(foreign),inputs.fds)
   finally:inputs.close();held.close()
 def test_matching_overlap_and_duplicate_fd_survive_original_holder_close(self):
  with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as tmp:
   root=Path(tmp).resolve();ns=support.holder();base=root/'base.py';new=root/'new.py';base.write_bytes(b'PUBLIC_BASE=True\n');new.write_bytes(b'PUBLIC_NEW=True\n')
   base.chmod(0o600);new.chmod(0o600);manifest=root/'inputs.json';manifest.write_text(json.dumps({'version':1,'scope':'complete-direct-public-update-source','inputs':{str(base):{'generation':ns['generation'](base.stat()),'sha256':hashlib.sha256(base.read_bytes()).hexdigest()}}}));manifest.chmod(0o600)
   inputs=ns['PublicInputs'](root,manifest,hashlib.sha256(manifest.read_bytes()).hexdigest());held=wrapper.load_holder()()
   try:
    for path in (base,new):held.read(str(path),hashlib.sha256(path.read_bytes()).hexdigest())
    wrapper.expand_public_inputs(inputs,held);self.assertNotEqual(inputs.fds[str(new)],held.files[str(new)][0]);held.close();held=None;inputs.verify();self.assertEqual(inputs.body(new),b'PUBLIC_NEW=True\n')
   finally:
    inputs.close()
    if held is not None:held.close()
if __name__=='__main__':unittest.main()
