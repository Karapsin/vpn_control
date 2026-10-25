"""Real fresh-interpreter dependency preflight before any bootstrap owner."""
from pathlib import Path
import hashlib,json,os,subprocess,sys,unittest
from agent_tools.tests import test_windows_bootstrap_durable as subject

FIXTURE=Path(__file__).with_name('fixtures')/'windows_bootstrap_nested_closure'


class NestedClosureTests(unittest.TestCase):
    def test_whole_before_and_original_native_failure_authenticated(self):
        expected={'before.source':'e224c0b638351ee2e5c800ee13773ec2973910327d778eaf65e1d6c048911a08',
            'carrier.before.source':'034cb070bab7057796732f434e8d9da5b6d65273cb77e9465313e76cdab365f8',
            'native-failure.json':'11fa1b456f750c57b28d0ab705cc97574d8d42f3f7ebfc202d3dcef8f2b14ebb',
            'provenance.json':'de76947d3db3fc2666cfdacb7e958813865fba903a83c1a1116bb5f97be1108f',
            'host-test.before.source':'94d8297a4df62260edc89df220093dc94d8d06a20d51cdf027ce4a27ab89bde8','controlled_host_test_role.source':'914017642a6263c64fc49e40b7cc6a37f8bf9487e811b536805c8f0a66e6b96b',
            'run-owned-input.before.source':'43465154530518881f8ba47a1f32177ebb24a7ecbf670d768e7ca7284b26bc84','run-owned-input-failure.json':'5640e3153902a0dee6bee7faf7ff34b4e1eb14398b3673caa32d5ebba4f35af7'}
        self.assertEqual({p.name for p in FIXTURE.iterdir()},set(expected))
        for name,sha in expected.items():self.assertEqual(hashlib.sha256((FIXTURE/name).read_bytes()).hexdigest(),sha)
        failure=json.loads((FIXTURE/'native-failure.json').read_bytes());self.assertEqual((failure['testsRun'],failure['failures'],failure['errors'],failure['skips']),(28,2,0,0))

    def test_actual_nested_graph_before_missing_dependency_current_guard_before_owner(self):
        code=r'''
import ast,importlib.util,json,pathlib,subprocess,sys,unittest
from unittest import mock
sys.path.insert(0,ROOT)
from agent_tools import readiness_windows
if BEFORE:
 path=pathlib.Path(BEFORE_PATH);name='agent_tools.tests._bootstrap_nested_before'
 spec=importlib.util.spec_from_loader(name,loader=None,origin=str(path));module=importlib.util.module_from_spec(spec)
 # Preserve the original repository-location metadata used by the whole old
 # test. Its executed code remains exactly the authenticated e224 source.
 module.__file__=str(pathlib.Path(ROOT)/'agent_tools/tests/test_windows_bootstrap_durable.py');sys.modules[name]=module;exec(compile(path.read_bytes(),str(path),'exec'),module.__dict__)
 real_run=subprocess.run
 def real_guard_on_old_emitted_graph(command,**kwargs):
  if type(command)is list and type(command[-1])is str and command[-1].startswith('import sys,unittest,json;'):
   tree=ast.parse(command[-1]);roots=[node.args[1].value for node in ast.walk(tree)if isinstance(node,ast.Call)and isinstance(node.func,ast.Attribute)and node.func.attr=='insert'and len(node.args)==2 and isinstance(node.args[1],ast.Constant)]
   assert len(roots)==1
   # Run the SAME actual backend dependency guard on the old emitted clone;
   # never execute the old endpoint scenario or create its durable owner.
   source='import sys;sys.path.insert(0,'+repr(roots[0])+');from agent_tools import readiness_windows as windows;windows._source_pins()'
   return real_run([sys.executable,'-I','-B','-c',source],capture_output=True,timeout=10)
  return real_run(command,**kwargs)
 with mock.patch.object(module.subprocess,'run',side_effect=real_guard_on_old_emitted_graph):
  module.DurableEndpointTests('test_fresh_original_observation_after_signin_does_not_require_zero_interactive')._isolated_source_graph()
else:
 from agent_tools.tests import test_windows_bootstrap_durable as module
 module.DurableEndpointTests('test_fresh_original_observation_after_signin_does_not_require_zero_interactive')._isolated_source_graph(preflight_only=True)
 assert module.OWNED_CLOSURES and all(row['reaped']and not row['sameOriginalBirthPresent']and row['terminalStreamsClosed']for row in module.OWNED_CLOSURES)
 print(json.dumps({'preflight':'actual_dependency_guard_green','owned':module.OWNED_CLOSURES}))
'''
        outputs=[]
        for before in (True,False):
            source='ROOT='+repr(str(Path(__file__).resolve().parents[2]))+'\nBEFORE='+repr(before)+'\nBEFORE_PATH='+repr(str(FIXTURE/'before.source'))+'\n'+code
            result=subject.run_owned([sys.executable,'-I','-B','-c',source],capture_output=True,timeout=25);outputs.append(result)
        old,current=outputs
        self.assertNotEqual(old.returncode,0);self.assertIn(b'readiness_reservation_observation',old.stderr)
        selected=old if os.environ.get('VPN_CONTROL_BOOTSTRAP_NESTED_BEFORE')=='1'else current
        self.assertEqual(selected.returncode,0,(selected.stdout+selected.stderr).decode())
        self.assertIn(b'actual_dependency_guard_green',current.stdout)

    def test_failed_helper_and_endpoint_cleanup_recorded_before_exception(self):
        start=len(subject.OWNED_CLOSURES);captures=len(subject.NESTED_CAPTURES)
        with self.assertRaises(subprocess.TimeoutExpired):
            subject.run_owned([sys.executable,'-I','-B','-c','import time;print("owned public partial",flush=True);time.sleep(2)'],capture_output=True,timeout=.15)
        row=subject.OWNED_CLOSURES[start];self.assertTrue(row['reaped']);self.assertFalse(row['sameOriginalBirthPresent']);self.assertTrue(row['terminalStreamsClosed'])
        saved=subject.NESTED_CAPTURES[captures];self.assertTrue(saved['stdoutAvailable']);self.assertTrue(saved['stdoutComplete']);self.assertGreater(saved['stdoutBytes'],0)
        def action(original,witness,packet,repo):
            vm=Path(original.as_dict()['binding']['spec']['root']);start=len(subject.OWNED_CLOSURES)
            with self.assertRaisesRegex(RuntimeError,'controlled assertion'):
                with subject.native_endpoint(vm,original):raise RuntimeError('controlled assertion')
            self.assertTrue(subject.OWNED_CLOSURES[start]['endpointSocketAbsent']);self.assertTrue(subject.OWNED_CLOSURES[start]['endpointThreadJoined'])
        subject.with_original(self,action)

    def test_failed_controlled_carrier_records_original_child_on_timeout(self):
        from contextlib import contextmanager
        import sys as runtime_sys
        namespace={'contextmanager':contextmanager,'subprocess':subprocess,'os':os,'sys':runtime_sys}
        raw=(Path(subject.FIXTURE)/'controlled_carrier_roles.source').read_bytes()
        exec(compile(raw,'exact controlled carrier fixture','exec'),namespace)
        payload='import time;print("owned public partial",flush=True);time.sleep(2)'
        with self.assertRaises(subprocess.TimeoutExpired):
            namespace['run_ssh'](('python3','-I','-B','-c','exec('+repr(payload)+')'),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=.15)
        row=namespace['_BOOTSTRAP_CONTROLLED_CHILDREN'][0];self.assertTrue(row['reaped']);self.assertFalse(row['sameOriginalBirthPresent']);self.assertTrue(row['terminalStreamsClosed'])
        subject.OWNED_CLOSURES.append(row)

    def test_source_owned_host_role_stdin_before_rejected_current_real_child(self):
        import importlib.util
        path=FIXTURE/'run-owned-input.before.source';name='agent_tools.tests._bootstrap_input_before'
        spec=importlib.util.spec_from_loader(name,loader=None,origin=str(path));before=importlib.util.module_from_spec(spec);before.__file__=str(path);sys.modules[name]=before
        exec(compile(path.read_bytes(),str(path),'exec'),before.__dict__)
        command=[sys.executable,'-I','-B','-c','import sys;exec(compile(sys.stdin.buffer.read(),"controlled-input-fixture","exec"))']
        payload=b'print("source-owned stdin marker")\n'
        with self.assertRaisesRegex(TypeError,'unexpected keyword argument'):before.run_owned(command,input=payload,capture_output=True,timeout=5)
        result=subject.run_owned(command,input=payload,capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0);self.assertEqual(result.stdout,b'source-owned stdin marker\n');self.assertTrue(subject.OWNED_CLOSURES[-1]['terminalStreamsClosed'])


if __name__=='__main__':unittest.main()
