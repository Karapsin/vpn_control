"""Finite capsule and actual wrong-account child; no Mac native API calls."""
from dataclasses import replace
import ast
import types
import tempfile
from unittest.mock import patch
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from uuid import uuid4

from agent_tools import readiness_tart_macos_lease_bridge as bridge
from agent_tools import readiness_tart_macos_leases as leases


class LeaseBridgeTests(unittest.TestCase):
    def setUp(self):
        self.binding=leases.MacLeaseBinding('explicit-tart-mac',str(uuid4()),str(uuid4()).upper(),
            '502'if os.geteuid()!=502 else '503','ordinary','/Users/ordinary','42')
        root=Path(bridge.__file__).parent
        self.packet={'schemaVersion':1,'root':bridge.ROOT,'target':self.binding.target,
            'machine':self.binding.machine,'account':self.binding.account,
            'rootGeneration':[1,2],'jobGeneration':[1,3],'admissionGeneration':[1,4],
            'sources':{name:hashlib.sha256((root/name).read_bytes()).hexdigest()for name in bridge._FILES}}
    def test_selected_machine_and_raw_boot_are_captured_without_host_root_resolution(self):
        value=bridge.source('probe',self.binding)
        self.assertIn(self.binding.boot.encode(),value)
        self.assertIn(self.binding.machine.encode(),value)
        self.assertIn(b'/private/var/tmp/vc-recovery-macos-leases',value)
        self.assertNotIn(b"'root': '/var/tmp/",value)
        compile(value,'fixed-mac-bridge','exec')
        self.assertLess(len(value),262144)
    def test_full_captured_helper_refuses_wrong_account_before_any_native_or_namespace_action(self):
        for action in ('probe','enroll','namespace-status'):
            value=bridge.source(action,self.binding)
            result=subprocess.run([sys.executable,'-c','exec(compile(__import__("sys").stdin.buffer.read(),"<fixed>","exec"))'],
                input=value,capture_output=True,timeout=10)
            self.assertEqual(3,result.returncode,result.stderr.decode())
            self.assertEqual(b'',result.stderr)
            self.assertEqual({'reason':'macos_lease_original_unavailable','state':'blocked'},json.loads(result.stdout))
    def test_namespace_retarget_source_or_generation_drift_refuses_before_source_dispatch(self):
        for key,value in (('root','/var/tmp/vc-recovery-macos-leases'),('target','other-target'),
                          ('machine',str(uuid4())),('account','0'),('sources',{}),('jobGeneration',[True,4])):
            changed={**self.packet,key:value}
            with self.subTest(key=key),self.assertRaises(leases.MacLeaseError):
                bridge.source('status',self.binding,namespace=changed,operation=str(uuid4()))
        with self.assertRaises(leases.MacLeaseError):
            bridge.source('status',self.binding,namespace={**self.packet,'credential':'PRIVATE'},operation=str(uuid4()))
    def test_only_finite_original_uuid_actions_have_capsules(self):
        op=str(uuid4())
        for action in ('acquire','status','cancel','reconcile'):
            value=bridge.source(action,self.binding,namespace=self.packet,operation=op,ttl=2 if action=='acquire'else None)
            self.assertIn(op.encode(),value);compile(value,'fixed-mac-bridge','exec')
        value=bridge.source('inventory',self.binding,namespace=self.packet)
        compile(value,'fixed-mac-inventory','exec')
        for action in ('stop','wake','unlock','exec',None):
            with self.assertRaises(leases.MacLeaseError):bridge.source(action,self.binding)
        with self.assertRaises(leases.MacLeaseError):
            bridge.source('cancel',self.binding,namespace=self.packet,operation=op,ttl=2)
    def test_original_capsule_observer_uses_no_live_source_and_forbids_submission(self):
        raw=bridge.capsule(self.binding,self.packet);digest=hashlib.sha256(raw).hexdigest()
        self.assertLess(len(raw),262144)
        with patch.object(bridge.Path,'read_bytes',side_effect=AssertionError('live source is forbidden')):
            for action in ('status','cancel','reconcile'):
                value=bridge.observer_source(raw,action,expected_sha256=digest,operation=str(uuid4()))
                compile(value,'original-observer','exec')
                self.assertIn(self.binding.boot.encode(),value)
            value=bridge.observer_source(raw,'inventory',expected_sha256=digest)
            compile(value,'original-inventory','exec')
        for action in ('probe','enroll','acquire'):
            with self.assertRaises(leases.MacLeaseError):
                bridge.observer_source(raw,action,expected_sha256=digest,operation=str(uuid4()))
        with self.assertRaises(leases.MacLeaseError):
            bridge.observer_source(raw+b' ', 'status',expected_sha256=digest,operation=str(uuid4()))
        initial=bridge.capsule(self.binding)
        value=bridge.observer_source(initial,'namespace-status',expected_sha256=hashlib.sha256(initial).hexdigest())
        compile(value,'original-enroll-observer','exec')

    def test_full_original_observer_child_keeps_wrong_account_refusal_after_current_source_updates(self):
        raw=bridge.capsule(self.binding,self.packet)
        with patch.object(bridge.Path,'read_bytes',side_effect=AssertionError('current source drift')):
            value=bridge.observer_source(raw,'status',expected_sha256=hashlib.sha256(raw).hexdigest(),operation=str(uuid4()))
        result=subprocess.run([sys.executable,'-c','exec(compile(__import__("sys").stdin.buffer.read(),"<original>","exec"))'],
            input=value,capture_output=True,timeout=10)
        self.assertEqual(3,result.returncode);self.assertEqual(b'',result.stderr)
        self.assertEqual('blocked',json.loads(result.stdout)['state'])

    def test_original_boot_guard_before_red_current_status_green_mutations_still_refuse(self):
        before=Path(__file__).parent/'fixtures/macos_lease_bridge_before.py'
        tree=ast.parse(before.read_bytes())
        old=next(node.value.value for node in tree.body if isinstance(node,ast.Assign)
                 and any(isinstance(t,ast.Name)and t.id=='_GUEST'for t in node.targets))
        newboot=str(uuid4())
        # Execute the original complete binding predicate, with controlled
        # read-only native getter replies. No process/root/session is mutated.
        for label,body in (('before',old),('current',bridge._GUEST)):
            tree=ast.parse(body)
            function=next(node for node in tree.body if isinstance(node,ast.FunctionDef)and node.name=='binding')
            code=compile(ast.Module(body=[function],type_ignores=[]),'<fixed-binding>','exec')
            fake_j=types.SimpleNamespace(_binding_live=lambda value:(_ for _ in ()).throw(AssertionError('old boot live check')))
            native=types.SimpleNamespace(machine=lambda:self.binding.machine,boot=lambda:(newboot,{}))
            scope={'CONFIG':{'binding':self.binding.__dict__,'action':'status'},'L':leases,'J':fake_j,
                   'P':types.SimpleNamespace(Native=lambda:native),'need':lambda value,reason:None if value else (_ for _ in ()).throw(ValueError(reason)),
                   'os':types.SimpleNamespace(geteuid=lambda:int(self.binding.account)),
                   'pwd':types.SimpleNamespace(getpwuid=lambda uid:types.SimpleNamespace(pw_name=self.binding.principal,pw_dir=self.binding.home))}
            exec(code,scope)
            if label=='before':
                with self.assertRaisesRegex(ValueError,'macos_lease_boot_changed'):scope['binding']()
            else:
                self.assertEqual(self.binding,scope['binding']())
                for action in ('acquire','cancel','reconcile','enroll'):
                    scope['CONFIG']['action']=action
                    with self.assertRaisesRegex(ValueError,'macos_lease_boot_changed'):scope['binding']()

    def test_actual_unknown_namespace_entry_before_red_current_refuses_before_assertion(self):
        from agent_tools import durable_remote_job as jobs
        archive=Path(__file__).parent/'fixtures/macos_lease_namespace_before.py'
        body=next(node.value.value for node in ast.parse(archive.read_bytes()).body if isinstance(node,ast.Assign)
                  and any(isinstance(target,ast.Name)and target.id=='_GUEST'for target in node.targets))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();root.chmod(0o700)
            (root/'jobs').mkdir(mode=0o700);(root/'admissions').mkdir(mode=0o700)
            packet={**self.packet,'rootGeneration':list(jobs.root_generation(root)),
                'jobGeneration':list(jobs.root_generation(root/'jobs')),
                'admissionGeneration':list(jobs.root_generation(root/'admissions'))}
            jobs._publish(root/'namespace.json',packet)
            (root/'unexpected-PRIVATE').write_bytes(b'PRIVATE-UNCLASSIFIED-WORK')
            class Alias:
                def __str__(self):return case_root
                def __fspath__(self):return str(root)
                def __truediv__(self,key):return root/key
                def iterdir(self):return root.iterdir()
            for label,text in (('before',body),('current',bridge._GUEST)):
                fn=next(node for node in ast.parse(text).body if isinstance(node,ast.FunctionDef)and node.name=='namespace')
                case_root=next(node.comparators[0].value for node in ast.walk(fn)if isinstance(node,ast.Compare)
                    and isinstance(node.left,ast.Call)and isinstance(node.left.func,ast.Name)and node.left.func.id=='str'
                    and isinstance(node.comparators[0],ast.Constant))
                packet['root']=case_root;(root/'namespace.json').write_text(json.dumps(packet))
                scope={'Path':lambda path:Alias(),'J':jobs,'CONFIG':{'root':case_root,'action':'namespace-status',
                    'sources':packet['sources'],'namespace':packet},'need':lambda condition,reason='invalid':
                    None if condition else (_ for _ in ()).throw(ValueError(reason))}
                exec(compile(ast.Module(body=[fn],type_ignores=[]),'<original-namespace>','exec'),scope)
                if label=='before':self.assertEqual(packet,scope['namespace'](self.binding)[1])
                else:
                    with self.assertRaisesRegex(ValueError,'^macos_lease_namespace_changed$') as error:
                        scope['namespace'](self.binding)
                    self.assertNotIn('PRIVATE',str(error.exception))

    def test_original_v1_root_and_source_binding_survive_v2_without_live_source_reads(self):
        import base64
        raw=json.loads(bridge.capsule(self.binding))
        original=Path(__file__).parent/'fixtures/macos_lease_bridge_namespace_v1_before.source'
        raw['bridge']=base64.b64encode(original.read_bytes()).decode()
        encoded=json.dumps(raw,sort_keys=True,separators=(',',':')).encode();digest=hashlib.sha256(encoded).hexdigest()
        packet={**self.packet,'root':'/private/var/tmp/vc-recovery-macos-leases'}
        with patch.object(bridge.Path,'read_bytes',side_effect=AssertionError('live source forbidden')):
            self.assertEqual(packet['root'],bridge.capsule_root(encoded,expected_sha256=digest))
            bound=bridge.bind_namespace(encoded,packet,expected_sha256=digest)
            value=bridge.observer_source(bound,'inventory',expected_sha256=hashlib.sha256(bound).hexdigest())
            compile(value,'old-original-inventory','exec')
        self.assertEqual(raw['bridge'],json.loads(bound)['bridge'])
        self.assertEqual(raw['files'],json.loads(bound)['files'])
        self.assertEqual(self.binding.__dict__,json.loads(bound)['binding'])
        for key,value in (('root',bridge.ROOT),('jobGeneration',[True,2]),('machine',str(uuid4())),('sources',{})):
            with self.subTest(key=key),self.assertRaises(leases.MacLeaseError):
                bridge.bind_namespace(encoded,{**packet,key:value},expected_sha256=digest)

    def test_qualified_original_producer_does_not_adopt_live_guest_source_updates(self):
        raw=bridge.capsule(self.binding,self.packet);digest=hashlib.sha256(raw).hexdigest();op=str(uuid4())
        with patch.object(bridge.Path,'read_bytes',side_effect=AssertionError('live guest source forbidden')):
            value=bridge.qualified_acquire_source(raw,expected_sha256=digest,operation=op,ttl=5)
        self.assertIn(op.encode(),value);self.assertIn(self.binding.boot.encode(),value);compile(value,'qualified-producer','exec')
        for changed in (digest[:-1]+('0'if digest[-1]!='0'else'1'),None):
            with self.assertRaises(leases.MacLeaseError):
                bridge.qualified_acquire_source(raw,expected_sha256=changed,operation=op,ttl=5)
        with self.assertRaises(leases.MacLeaseError):
            bridge.qualified_acquire_source(raw,expected_sha256=digest,operation=op,ttl=True)

    def test_original_absence_complete_before_red_current_green_real_private_namespace(self):
        import contextlib,io
        from agent_tools import durable_remote_job as jobs
        archive=Path(__file__).parent/'fixtures/macos_lease_original_absence_before.source'
        raw=archive.read_bytes()
        self.assertEqual('f456cd5b4448fbe9f94b3b32c4802f2e8822d71213cab5ba7d47d0ff07c0ead6',hashlib.sha256(raw).hexdigest())
        old=next(node.value.value for node in ast.parse(raw).body if isinstance(node,ast.Assign)
                 and any(isinstance(t,ast.Name)and t.id=='_GUEST'for t in node.targets))
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory).resolve();root.chmod(0o700)
            (root/'jobs').mkdir(mode=0o700);(root/'admissions').mkdir(mode=0o700)
            packet={**self.packet,'rootGeneration':list(jobs.root_generation(root)),
                'jobGeneration':list(jobs.root_generation(root/'jobs')),
                'admissionGeneration':list(jobs.root_generation(root/'admissions'))}
            jobs._publish(root/'namespace.json',packet);op=str(uuid4())
            class Alias:
                def __str__(self):return bridge.ROOT
                def __fspath__(self):return str(root)
                def __truediv__(self,key):return root/key
                def iterdir(self):return root.iterdir()
            live=[]
            def binding_live(value):live.append(value)
            j=types.SimpleNamespace(**vars(jobs));j._binding_live=binding_live
            def run(body):
                scope={'CONFIG':{'action':'status','operation':op,'root':bridge.ROOT,'namespace':packet,
                                'sources':packet['sources']},'J':j,'L':leases,'Path':lambda path:Alias(),'json':json}
                funcs=[n for n in ast.parse(body).body if isinstance(n,ast.FunctionDef)or (isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='_original_invoke'for t in n.targets))]
                exec(compile(ast.Module(body=funcs,type_ignores=[]),'<complete-original-status>','exec'),scope)
                scope['binding']=lambda:self.binding
                output=io.StringIO()
                with contextlib.redirect_stdout(output):code=scope['main']()
                return code,json.loads(output.getvalue())
            self.assertEqual((3,{'state':'blocked','reason':'macos_lease_original_unavailable'}),run(old))
            fixed=bridge._GUEST+bridge._ORIGINAL_STATUS
            code,result=run(fixed);self.assertEqual(0,code);self.assertEqual('unsubmitted',result['state'])
            self.assertEqual('original_admission_absent',result['reason']);self.assertEqual(op,result['operationId'])
            self.assertIs(False,result['replayAllowed']);self.assertEqual(1,len(live))
            self.assertEqual(set(),set((root/'admissions').iterdir()));self.assertEqual(set(),set((root/'jobs').iterdir()))
            for variant in ('admission_present','job_present','symlink','boot_changed','generation_changed','source_changed'):
                with self.subTest(variant=variant):
                    admission=root/'admissions'/(op+'.json');job=root/'jobs'/op
                    if variant=='admission_present':admission.write_text('{}')
                    if variant=='job_present':job.mkdir(mode=0o700)
                    if variant=='symlink':admission.symlink_to(root/'absent')
                    if variant=='boot_changed':j._binding_live=lambda value:(_ for _ in ()).throw(jobs.DurableJobError('boot_changed'))
                    if variant=='generation_changed':packet['jobGeneration'][1]+=1
                    if variant=='source_changed':packet['sources']={}
                    self.assertEqual('blocked',run(fixed)[1]['state'])
                    if admission.exists()or admission.is_symlink():admission.unlink()
                    if job.exists():job.rmdir()
                    j._binding_live=binding_live
                    packet['jobGeneration']=list(jobs.root_generation(root/'jobs'));packet['sources']=self.packet['sources']

    def test_missing_or_wrong_typed_inputs_have_no_default_target(self):
        with self.assertRaises(leases.MacLeaseError):bridge.source('probe',None)
        with self.assertRaises(leases.MacLeaseError):
            bridge.source('acquire',self.binding,namespace=self.packet,operation=str(uuid4()),ttl=True)
        with self.assertRaises(leases.MacLeaseError):
            bridge.source('probe',self.binding,namespace=self.packet)
        with self.assertRaises(leases.MacLeaseError):
            bridge.source('status',replace(self.binding,target='other-target'),namespace=self.packet,operation=str(uuid4()))


if __name__=='__main__':unittest.main()
