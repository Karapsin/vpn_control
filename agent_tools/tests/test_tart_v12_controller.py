"""Whole captured controller wrapper with an actual detached durable owner.

All programs are harmless local test sentinels; no registry/VM/input call runs.
"""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from uuid import uuid4

from agent_tools import durable_remote_job as jobs
from agent_tools import private_inventory_lock as private


@unittest.skipUnless(os.name == 'posix', 'actual detached durable owner')
class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name).resolve();self.folder.chmod(0o700)
        self.root=self.folder/'jobs';self.root.mkdir(mode=0o700)
        self.generation=jobs.root_generation(self.root)
        self.binding=jobs.current_binding('controlled-tart-explicit-target','controlled-host-machine')
        self.operation=str(uuid4());self.marker=self.folder/'one-execution'
        self.fixture=Path(__file__).parent/'fixtures/tart_v12_durable_controller.source'
        tree=ast.parse(self.fixture.read_bytes())
        self.wrapper=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name)and t.id=='WRAPPER'for t in n.targets)))

    def program(self, *, fail=False, hold=False):
        self.driver=self.folder/'controlled-driver.py';self.release=self.folder/'release-original'
        wait=(f"end=time.monotonic()+5\nwhile not pathlib.Path({str(self.release)!r}).exists():\n if time.monotonic()>end:raise RuntimeError('controlled release missing')\n time.sleep(.02)\n"if hold else "time.sleep(.3)\n")
        source=("import os,sys,time,pathlib\n"+f"p=pathlib.Path({str(self.marker)!r});fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,b'once');os.close(fd)\n"+"print('original begin',flush=True);sys.stderr.write('retained public stderr\\n');sys.stderr.flush()\n"+wait+("raise RuntimeError('controlled finite postguard failure')\n" if fail else "print('original end',flush=True)\n")).encode()
        self.driver.write_bytes(source);self.driver.chmod(0o600)
        config={'project':str(Path(__file__).resolve().parents[2]),'jobRoot':str(self.root),'jobRootGeneration':list(self.generation),
            'hostBinding':self.binding.__dict__,'operationId':self.operation,'leaseOperationId':str(uuid4()),'originalRunOperationId':str(uuid4()),
            'fixtureId':'controlled-v12','target':'tart:explicit-controlled-vm','phase':'public','purpose':'native_macos_public136_v12',
            'source':base64.b64encode(source).decode(),'sourceSha256':hashlib.sha256(source).hexdigest(),
            'sourceGeneration':list(private._generation(self.driver.lstat())),'driverPath':str(self.driver),'indexPath':str(self.folder/('native-unlock-controller-'+self.operation+'.json'))}
        return jobs.Program(config['purpose'],('CONFIG='+repr(config)+'\n'+self.wrapper).encode(),262144)

    def terminal(self):
        end=time.monotonic()+10
        while time.monotonic()<end:
            status=jobs.observe(self.root,self.operation,self.binding,generation=self.generation)
            if status['state']=='terminal'and jobs._birth(status['owner']['pid'])!=status['owner']['birth']:return jobs.collect(self.root,self.operation,self.binding,generation=self.generation)
            time.sleep(.025)
        self.fail('original controller did not become terminal: '+repr(status))

    def test_source_captured_program_survives_original_submitting_client_death_once_and_full_streams(self):
        program=self.program(hold=True)
        bootstrap=('import base64,json,pathlib,sys;sys.path.insert(0,'+repr(str(Path(__file__).resolve().parents[2]))+');from agent_tools import durable_remote_job as J;'
            +'b=J.MachineBinding.from_dict('+repr(self.binding.__dict__)+');p=J.Program('+repr(program.purpose)+',base64.b64decode('+repr(base64.b64encode(program.source).decode())+'),262144);'
            +'r=J.submit(pathlib.Path('+repr(str(self.root))+'),'+repr(self.operation)+',b,p,generation='+repr(self.generation)+');print(json.dumps(r),flush=True)')
        client=subprocess.run([sys.executable,'-B','-c',bootstrap],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,
                              env={k:v for k,v in os.environ.items()if not k.startswith('DYLD_')})
        self.assertEqual(client.returncode,0,client.stderr)
        self.assertTrue((self.root/self.operation/'intent.json').is_file())
        end=time.monotonic()+5
        while not self.marker.exists()and time.monotonic()<end:time.sleep(.02)
        live=jobs.observe(self.root,self.operation,self.binding,generation=self.generation)
        self.assertEqual(live['state'],'running')
        self.assertEqual(jobs._birth(live['owner']['pid']),live['owner']['birth'])
        self.release.write_bytes(b'original client already absent; finish same owner')
        status,stdout,stderr=self.terminal()
        self.assertEqual(status['terminal']['exitCode'],0,stderr)
        self.assertEqual(stdout,b'original begin\noriginal end\n');self.assertEqual(stderr,b'retained public stderr\n')
        self.assertEqual(self.marker.read_bytes(),b'once')
        index=json.loads((self.folder/('native-unlock-controller-'+self.operation+'.json')).read_bytes())
        self.assertEqual(index['programSha256'],program.digest)
        self.assertEqual(index['operationId'],self.operation)
        duplicate=jobs.submit(self.root,self.operation,self.binding,program,generation=self.generation)
        self.assertEqual(duplicate,status);self.assertEqual(self.marker.read_bytes(),b'once')
        self.assertNotEqual(jobs._birth(status['owner']['pid']),status['owner']['birth'])

    def test_terminal_failing_guard_retains_original_stdout_stderr_without_replacement(self):
        program=self.program(fail=True)
        jobs.submit(self.root,self.operation,self.binding,program,generation=self.generation)
        status,stdout,stderr=self.terminal()
        self.assertNotEqual(status['terminal']['exitCode'],0)
        self.assertEqual(stdout,b'original begin\n');self.assertIn(b'controlled finite postguard failure',stderr)
        before=(self.root/self.operation/'intent.json').read_bytes()
        self.assertEqual(jobs.submit(self.root,self.operation,self.binding,program,generation=self.generation),status)
        self.assertEqual((self.root/self.operation/'intent.json').read_bytes(),before)

    def test_changed_named_driver_refuses_before_any_sentinel_or_input(self):
        program=self.program();self.driver.write_bytes(b"raise SystemExit(0)\n")
        jobs.submit(self.root,self.operation,self.binding,program,generation=self.generation)
        status,stdout,stderr=self.terminal()
        self.assertNotEqual(status['terminal']['exitCode'],0);self.assertFalse(self.marker.exists())
        self.assertIn(b'controller_named_source_changed',stderr);self.assertFalse((self.folder/('native-unlock-controller-'+self.operation+'.json')).exists())

    def test_actual_original_only_selector_gate_refuses_other_target_before_collect(self):
        from types import SimpleNamespace as NS
        program=self.program()
        jobs.submit(self.root,self.operation,self.binding,program,generation=self.generation)
        status,_,_=self.terminal()
        config=ast.literal_eval(program.source.decode().splitlines()[0].removeprefix('CONFIG='))
        tree=ast.parse(self.fixture.read_bytes())
        gate=next(n for n in ast.walk(tree)if isinstance(n,ast.If)and ast.unparse(n.test)=="status['state'] != 'unsubmitted'")
        def need(value,reason):
            if not value:raise RuntimeError(reason)
        args=NS(phase='public',operation_id=self.operation,lease_operation_id=config['leaseOperationId'],fixture_id='controlled-v12',target='tart:explicit-controlled-vm')
        scope={'status':status,'J':jobs,'root':self.root,'binding':self.binding,'ast':ast,'hashlib':hashlib,'base64':base64,
            'WRAPPER':self.wrapper,'args':args,'purpose':program.purpose,'generation':self.generation,'digest':hashlib.sha256(self.driver.read_bytes()).hexdigest(),
            'run':{'operationId':config['originalRunOperationId']},'run_path':self.folder/'original-run.json',
            '__file__':str(self.folder/'controller.inert.py'),'Path':Path,'filename':self.driver.name,'need':need}
        code=compile(ast.Module(body=[gate],type_ignores=[]),str(self.fixture),'exec')
        exec(code,scope)  # Exact original selector is accepted.
        args.target='tart:another-vm'
        with self.assertRaisesRegex(RuntimeError,'original_selector_changed'):exec(code,scope)
        self.assertEqual(self.marker.read_bytes(),b'once')
