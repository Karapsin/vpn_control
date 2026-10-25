"""Source/stream/identity proof gates and restart-only metadata reconciliation."""
import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import types
import unittest
from unittest import mock
from uuid import UUID, uuid5

from agent_tools import readiness, readiness_qemu as backend_module, readiness_qemu_refusal as subject
from agent_tools import readiness_fixture_registry as registry


class RemoteRefusalTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700)
        self.machine='0f559886-4ff5-4075-ad25-beb805173364';self.rid='a'*64;self.digest='b'*64;self.operation=str(uuid5(UUID(self.machine),self.rid))
        self.binding={'host':'fixture','root':'/home/owner/vc-r-0f559886','machine':self.machine,'target':'qemu-linux:'+self.machine}
        self.hostboot='25515f23-b966-4c3a-ae63-d38452375578';self.oldboot='766684cb-a628-4c05-98f7-6fd364d351cc'
        self.owner={'operationId':self.machine,'preparationId':self.machine,'hostBootId':self.hostboot,'pid':17,'startTicks':777,
                    'argvSha256':'c'*64,'qmpSocketInode':22,'state':'running','guestSubmitted':True}
        self.pins={'root':[1,2,stat.S_IFDIR|0o700,1000,1000],'hostBoot':self.hostboot,'disk':[1,4,stat.S_IFREG|0o600,1000,1000]}
        for index,name in enumerate(('prepared','initialOwner','reservation','key','knownHosts','seed','base','imageReceipt')):
            self.pins[name]={'generation':[1,50+index,stat.S_IFREG|0o600,1000,1000,1,100,0,0]}
            if name not in {'key','seed'}:self.pins[name]['sha256']='d'*64
        self.expected={'owner':self.owner,'boot':self.oldboot,'guest':'paused'}
        self.actual={'owner':self.owner,'boot':None,'guest':'paused'}
        self.remote={'schemaVersion':1,'provider':'raw-qemu-linux','reason':'prepared_context_stale','action':'resume','recoveryId':self.rid,
            'attempt':1,'dispatchDigest':self.digest,'controllerSourceSha256':hashlib.sha256(inspect.getsource(subject.packets._main).encode()).hexdigest(),
            'controller':{'pid':111,'startTicks':999,'uid':1000,'hostBootId':self.hostboot},'fixture':self.binding,'assets':self.pins,
            'expected':self.expected,'actual':self.actual,'rootGeneration':[1,2,stat.S_IFDIR|0o700,1000,1000,2,4096,0,0],
            'operatorGeneration':[1,3,stat.S_IFREG|0o600,1000,1000,1,4,0,0],'managerGeneration':[1,5,stat.S_IFDIR|0o700,1000,1000,2,4096,0,0],
            'originalActor':'alive','cleanStop':None,'powerIntentAbsent':True,'noVmEffectAdmitted':True,'resourceSnapshotSha256':None,'phase':'qmp'}
        self.response={'state':'blocked','reason':'prepared_context_stale','phase':'qmp','errorClass':'ValueError','vmSubmitted':False,'completedRefusal':self.remote}
        source=subject.packets.program(self.binding,self.pins,'resume',self.rid,self.expected,
            dispatch_identity={'recoveryId':self.rid,'attempt':1,'dispatchDigest':self.digest})
        self.packet=self.root/'.runtime/readiness-qemu'/self.operation/'1792500000000000000-resume.py'
        self.write(self.packet,source.encode());self.capture=self.packet.with_suffix('.capture.json')
        self.capture_body={'returnCode':0,'stdout':json.dumps(self.response,sort_keys=True)+'\n','stderrBytes':0,'sourceSha256':hashlib.sha256(source.encode()).hexdigest(),
            'executionComplete':True,'stdoutEof':True,'stderrEof':True}
        self.write(self.capture,json.dumps(self.capture_body,sort_keys=True).encode())
        self.sources={name:hashlib.sha256(Path(subject.__file__).with_name(name).read_bytes()).hexdigest() for name in subject.SOURCE_NAMES}
        self.path=self.root/'.runtime/readiness-qemu/unsubmitted-remote'/self.rid/'1.json'
        self.envelope={'schemaVersion':1,'provider':'raw-qemu-linux','action':'resume','machineUuid':self.machine,'operationId':self.operation,
            'recoveryId':self.rid,'attempt':1,'dispatchDigest':self.digest,'resourceSnapshotSha256':None,'sourceClosure':self.sources,
            'packet':{'path':str(self.packet),'pin':registry._body(self.packet)[1]},'capture':{'path':str(self.capture),'pin':registry._body(self.capture)[1]},'remote':self.remote}
        self.rewrite()
    def write(self,path,raw):
        path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o600)
    def rewrite(self):
        self.write(self.path,json.dumps(self.envelope,sort_keys=True).encode())
    def update_response(self):
        self.capture_body['stdout']=json.dumps(self.response,sort_keys=True)+'\n';self.write(self.capture,json.dumps(self.capture_body,sort_keys=True).encode())
        self.envelope['capture']['pin']=registry._body(self.capture)[1];self.rewrite()
    def validate(self):
        return subject.validated_remote_refusal(self.root,attestation_path=self.path,attestation_sha256=registry._body(self.path)[1]['sha256'],
            machine_uuid=self.machine,operation_id=self.operation,recovery_id=self.rid,attempt=1,dispatch_digest=self.digest,
            packet_sha256=self.envelope['packet']['pin']['sha256'],resource_snapshot=None,fixture_host=self.binding['host'],fixture_root=self.binding['root'])
    def backend(self):
        return backend_module.QemuLinuxBackend(self.root,self.binding,self.pins,capabilities={'resume'})
    def test_full_source_terminal_and_original_barrier_are_held(self):
        with self.validate() as verified:
            self.assertEqual(self.rid,verified.data['recoveryId']);verified.guard()
    def test_rewritten_packet_with_same_flags_never_authorizes_retry(self):
        self.write(self.packet,b'print("injected before controller")\n'+self.packet.read_bytes())
        self.envelope['packet']['pin']=registry._body(self.packet)[1];self.capture_body['sourceSha256']=self.envelope['packet']['pin']['sha256'];self.update_response()
        with self.assertRaisesRegex(ValueError,'packet_source'):
            with self.validate():pass
    def test_capture_requires_real_terminal_types_and_both_eofs(self):
        original=copy.deepcopy(self.capture_body)
        for field,value in [('returnCode',False),('returnCode',1),('stdoutEof',False),('stderrEof',False),('executionComplete',False),('stderrBytes',1)]:
            with self.subTest(field=field,value=value):
                self.capture_body={**original,field:value};self.update_response()
                with self.assertRaisesRegex(ValueError,'terminal_capture'):
                    with self.validate():pass
    def test_remote_actor_lock_and_dispatch_cannot_be_replaced(self):
        original=copy.deepcopy(self.remote)
        changes=[('recoveryId','e'*64),('powerIntentAbsent',False),('originalActor','absent'),('controllerSourceSha256','0'*64)]
        for field,value in changes:
            with self.subTest(field=field):
                self.remote.clear();self.remote.update(copy.deepcopy(original));self.remote[field]=value;self.update_response()
                with self.assertRaises(ValueError):
                    with self.validate():pass
    def test_held_capture_cannot_be_deleted_or_modified_during_publication(self):
        with self.assertRaisesRegex(ValueError,'file_changed'):
            with self.validate() as verified:
                self.capture.unlink()
                verified.guard()
    def test_identical_capture_replacement_during_publication_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'file_changed'):
            with self.validate() as verified:
                raw=self.capture.read_bytes();self.capture.unlink();self.write(self.capture,raw)
                verified.guard()
    def test_restart_finishes_only_missing_local_proof_without_network(self):
        backend=self.backend();observed=readiness.Observation(self.binding['target'],self.machine,guest='paused')
        self.assertIsNone(backend.observe_recovery('resume',self.rid,observed,time.monotonic()+30,1,self.digest))
        self.assertFalse((self.root/'.runtime/readiness-qemu/unsubmitted').exists())
        with mock.patch.object(backend,'_run',side_effect=AssertionError('must not contact a VM')):
            self.assertTrue(backend.reconcile_recovery('resume',self.rid,observed,time.monotonic()+30,1,self.digest))
            self.assertFalse(backend.reconcile_recovery('resume',self.rid,observed,time.monotonic()+30,1,self.digest))
            proof=backend.observe_recovery('resume',self.rid,observed,time.monotonic()+30,1,self.digest)
        native=self.root/'.runtime/readiness-qemu/unsubmitted'/self.rid/'1.json'
        self.assertEqual(hashlib.sha256(native.read_bytes()).hexdigest(),proof.proof_sha256)
        body=json.loads(native.read_bytes());self.assertEqual(2,body['schemaVersion']);self.assertTrue(body['popenCalled']);self.assertFalse(body['mutationExecutableStarted'])
    def test_whole_old_backend_retains_unknown_current_proves_unsubmitted(self):
        folder=Path(__file__).parent/'fixtures/qemu_remote_refusal_before';raw=(folder/'readiness_qemu.py.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_text())['sourceSha256']['readiness_qemu.py'],hashlib.sha256(raw).hexdigest())
        old=types.ModuleType('agent_tools._qemu_completed_refusal_before');old.__package__='agent_tools';old.__file__=str(folder/'readiness_qemu.py.source')
        sys.modules[old.__name__]=old;self.addCleanup(sys.modules.pop,old.__name__,None);exec(compile(raw,old.__file__,'exec'),old.__dict__)
        observed=readiness.Observation(self.binding['target'],self.machine,connection='original',guest='paused',boot=self.oldboot)
        def dispatch(*args,**kwargs):
            trace=kwargs['dispatch_trace'];trace.update(popenCalled=True,packetSha256=self.envelope['packet']['pin']['sha256'],
                packetPath=str(self.packet),packetPin=self.envelope['packet']['pin'],capturePath=str(self.capture),capturePin=self.envelope['capture']['pin'])
            return self.response,None
        for module,before in [(old,True),(backend_module,False)]:
            with self.subTest(before=before),mock.patch.object(module,'_sources',return_value=self.sources):
                backend=module.QemuLinuxBackend(self.root,self.binding,self.pins,capabilities={'resume'});backend.last_facts=self.expected
                with mock.patch.object(backend,'observe',return_value=observed),mock.patch.object(backend,'_run',side_effect=dispatch) as called:
                    if before:
                        with self.assertRaises(module.QemuError):backend.recover_attempt('resume',self.rid,observed,time.monotonic()+30,1,self.digest)
                    else:
                        with self.assertRaises(readiness.RecoveryUnsubmitted):backend.recover_attempt('resume',self.rid,observed,time.monotonic()+30,1,self.digest)
                    called.assert_called_once()

    def before_module(self,name):
        folder=Path(__file__).parent/'fixtures/qemu_refusal_action_binding_before';raw=(folder/(name+'.source')).read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256'][name],hashlib.sha256(raw).hexdigest())
        module=types.ModuleType('agent_tools._'+name.removesuffix('.py')+'_action_binding_before');module.__package__='agent_tools';module.__file__=str(folder/(name+'.source'))
        sys.modules[module.__name__]=module;self.addCleanup(sys.modules.pop,module.__name__,None);exec(compile(raw,module.__file__,'exec'),module.__dict__)
        return module
    def test_whole_recovery_hook_rejects_a_different_core_action_causal_red_green(self):
        before=self.before_module('readiness_qemu.py')
        for module,old in ((before,True),(backend_module,False)):
            fixture=RemoteRefusalTests('runTest');fixture.setUp()
            try:
                with mock.patch.object(module,'_sources',return_value=fixture.sources):
                    backend=module.QemuLinuxBackend(fixture.root,fixture.binding,fixture.pins,capabilities={'resume','reboot'})
                    observed=readiness.Observation(fixture.binding['target'],fixture.machine,guest='paused')
                    if old:
                        with self.assertRaises(AssertionError):
                            self.assertFalse(backend.reconcile_recovery('reboot',fixture.rid,observed,time.monotonic()+30,1,fixture.digest))
                    else:
                        with self.assertRaisesRegex(ValueError,'requested_action'):
                            backend.reconcile_recovery('reboot',fixture.rid,observed,time.monotonic()+30,1,fixture.digest)
            finally:fixture.doCleanups()
    def test_whole_validator_start_requires_original_resource_snapshot_causal_red_green(self):
        before=self.before_module('readiness_qemu_refusal.py')
        self.remote['action']='start';self.envelope['action']='start'
        self.packet=self.packet.with_name(self.packet.name.replace('-resume.py','-start.py'));self.capture=self.packet.with_suffix('.capture.json')
        raw=subject.packets.program(self.binding,self.pins,'start',self.rid,self.expected,
            dispatch_identity={'recoveryId':self.rid,'attempt':1,'dispatchDigest':self.digest}).encode()
        self.write(self.packet,raw);self.envelope['packet']={'path':str(self.packet),'pin':registry._body(self.packet)[1]}
        self.capture_body['sourceSha256']=hashlib.sha256(raw).hexdigest();self.envelope['capture']['path']=str(self.capture);self.update_response()
        arguments=dict(attestation_path=self.path,attestation_sha256=registry._body(self.path)[1]['sha256'],machine_uuid=self.machine,
            operation_id=self.operation,recovery_id=self.rid,attempt=1,dispatch_digest=self.digest,packet_sha256=hashlib.sha256(raw).hexdigest(),
            resource_snapshot=None,fixture_host=self.binding['host'],fixture_root=self.binding['root'])
        # Keep the deployed dependency directory identical while executing the
        # complete preserved validator, rather than copying its nine inputs.
        with mock.patch.object(before,'__file__',subject.__file__),self.assertRaises(AssertionError):
            with before.validated_remote_refusal(self.root,**arguments):self.fail('start without original resource snapshot was accepted')
        with self.assertRaisesRegex(ValueError,'start_snapshot'):
            with subject.validated_remote_refusal(self.root,**arguments):pass


if __name__=='__main__':unittest.main()
