"""Real consumed resource journals and ordinary generated owner capacity gates."""
import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from types import ModuleType
import unittest
from unittest import mock
from uuid import UUID,uuid5

from agent_tools import readiness_windows_lifecycle as current
from agent_tools import readiness_resources as resources
from agent_tools import windows_vm_resources as facts
from agent_tools.tests import test_readiness_resources as resource_tests
BOOT=resource_tests.BOOT
from agent_tools.tests.test_readiness_windows_lifecycle import binding,sample

FIXTURE=Path(__file__).parent/'fixtures/windows_start_capacity'


def old_module():
    raw=(FIXTURE/'before.source').read_bytes();assert hashlib.sha256(raw).hexdigest()==json.loads((FIXTURE/'provenance.json').read_text())['sourceSha256']
    module=ModuleType('agent_tools._windows_capacity_before');module.__package__='agent_tools';module.__file__=str(FIXTURE/'before.source')
    sys.modules[module.__name__]=module;exec(compile(raw,module.__file__,'exec'),module.__dict__);return module


class WindowsCapacityTests(unittest.TestCase):
    def setUp(self):
        self.fixture=resource_tests.ResourceTests('runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.binding=binding();self.binding['context']['hostBootId']=BOOT;self.body=sample(self.binding)
        self.rid='1'*64;self.op=str(uuid5(UUID(self.binding['spec']['deploymentId']),self.rid))
        self.admission=resources.prepare_start(self.fixture.root,host=self.binding['spec']['host'],machine_uuid=self.binding['spec']['deploymentId'],
            operation_id=self.op,fixture_root=self.binding['spec']['root'],credential_file='/CONTROLLED_PRIVATE_HANDLE',
            requested_memory_bytes=self.binding['spec']['memoryMiB']*1024**2,headroom_bytes=self.binding['spec']['headroomMiB']*1024**2)

    def snapshot(self):
        self.assertTrue(self.admission.mark_submitting(recovery_id=self.rid,dispatch_digest='2'*64))
        return self.admission.submission_snapshot()

    def validate(self,snapshot):
        fresh=snapshot['census'];return current._start_capacity(self.binding['spec'],self.binding['context'],snapshot,fresh,facts.measurement(fresh),self.op)

    def test_real_consumed_snapshot_exact_original_and_unknown_claims_counted(self):
        with self.assertRaisesRegex(ValueError,'dispatch_unavailable'):self.admission.submission_snapshot()
        snapshot=self.snapshot();self.validate(snapshot)
        self.assertFalse(self.admission.mark_submitting(recovery_id=self.rid,dispatch_digest='2'*64))
        self.assertEqual(self.admission.submission_snapshot(),snapshot)
        unknown=copy.deepcopy(snapshot);unknown['pending']=[{'id':'unresolved-original','memoryBytes':1024**4}]
        with self.assertRaisesRegex(ValueError,'capacity_unavailable'):self.validate(unknown)
        for key,value in (('deploymentId',str(uuid5(UUID(self.op),'foreign'))),('hostBootId',str(uuid5(UUID(self.op),'foreignboot'))),
                          ('mode','observe'),('inventoryComplete',False),('nativeActionAllowed',True),('replayAllowed',True)):
            invalid=copy.deepcopy(snapshot);invalid['census'][key]=value
            with self.assertRaises(ValueError):self.validate(invalid)
        expired=copy.deepcopy(snapshot)
        for row in expired['census']['samples']:row['observedAtUnixMs']-=61000
        with self.assertRaises(ValueError):self.validate(expired)
        with self.admission._journal().locked()as journal:journal.record('released',{'controlledNegative':True})
        with self.assertRaisesRegex(ValueError,'dispatch_unavailable'):self.admission.submission_snapshot()

    def test_actual_other_consumed_unknown_reservation_remains_in_snapshot(self):
        other_machine=str(uuid5(UUID(self.op),'other-machine'));other_operation=str(uuid5(UUID(other_machine),'3'*64))
        other=resources.prepare_start(self.fixture.root,host=self.binding['spec']['host'],machine_uuid=other_machine,
            operation_id=other_operation,fixture_root='/home/owner/separate-owned-fixture',credential_file='/CONTROLLED_PRIVATE_HANDLE',
            requested_memory_bytes=2*1024**3,headroom_bytes=8*1024**3)
        self.assertTrue(other.mark_submitting(recovery_id='3'*64,dispatch_digest='4'*64))
        # No running/terminal/released record follows: the genuinely consumed
        # private original remains UNKNOWN and its capacity must not disappear.
        snapshot=self.snapshot();self.validate(snapshot)
        self.assertTrue(any(row['memoryBytes']==2*1024**3 for row in snapshot['pending']))
        with other._journal().locked()as journal:
            self.assertIsNotNone(journal.lookup('submitting'))
            self.assertIsNone(journal.lookup('running'));self.assertIsNone(journal.lookup('released'))
        self.assertEqual(other.submission_snapshot()['requestedMemoryBytes'],2*1024**3)

    @unittest.skipIf(os.geteuid()==0,'ordinary owner privilege boundary required')
    def test_whole_before_ordinary_root_producer_red_verified_snapshot_reaches_actual_endpoint_green(self):
        subject=old_module()if os.environ.get('VPN_CONTROL_WINDOWS_CAPACITY_BEFORE')=='1'else current
        snapshot=self.snapshot()
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp);root.chmod(0o700);wire=root/'metadata.sock';marker=root/'admitted';ready=root/'ready'
            server=subprocess.Popen([sys.executable,'-I','-B','-c',
                "import socket,sys;from pathlib import Path;s=socket.socket(socket.AF_UNIX);s.bind(sys.argv[1]);s.listen(1);s.settimeout(.3);Path(sys.argv[2]).touch();\ntry:\n c,_=s.accept();assert c.recv(32)==b'validated';Path(sys.argv[3]).touch();c.close()\nexcept TimeoutError:pass\ns.close()",str(wire),str(ready),str(marker)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                end=time.monotonic()+3
                while not ready.exists():self.assertIsNone(server.poll());self.assertLess(time.monotonic(),end);time.sleep(.005)
                def pin(*args,**kwargs):
                    with socket.socket(socket.AF_UNIX)as client:client.connect(str(wire));client.sendall(b'validated')
                    raise ValueError('controlled_stop_before_writer')
                # Old actual root-only generated callee, not a fake successful
                # census. The ordinary process fails its original euid check.
                source=inspect.getsource(facts._main).replace('def _main(', 'def _lifecycle_resource_main(',1)
                ns={'os':os,'json':json,'SPEC':self.binding['spec'],'MODE':'observe'};exec(source,ns)
                fake_spec={**self.binding['spec'],'root':str(root)}
                function=subject._existing_raw_start
                with mock.patch.dict(function.__globals__,{'_actor_absent':lambda *a:True,'_stopped_artifacts':lambda *a:{},
                    '_lifecycle_resource_main':ns['_lifecycle_resource_main'],'_lifecycle_measurement':facts.measurement}):
                    with self.assertRaises(ValueError):function(fake_spec,self.binding['context'],self.op,self.rid,self.body,
                        {'artifacts':{}},{},snapshot,lambda *a:None,lambda *a:None,lambda *a:None,lambda *a:None,
                        lambda:None,pin,lambda *a:None,lambda *a:None,lambda *a:None,[])
                server.communicate(timeout=3);self.assertTrue(marker.exists(),'valid consumed ROOT snapshot was not usable by ordinary owner')
            finally:
                if server.poll()is None:server.terminate();server.communicate(timeout=3)
                self.assertEqual(server.returncode,0)

    def test_missing_actual_writable_vm_storage_coverage_is_never_ignored(self):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp);disk=root/'disk.qcow2';disk.write_bytes(b'controlled owned disk');disk.chmod(0o600)
            # A real live child owns the inode. An unclaimed current VM cannot
            # be treated as zero disk growth even if the selected fixture fits.
            child=subprocess.Popen([sys.executable,'-I','-B','-c','import sys,time;f=open(sys.argv[1],"r+b");print("ready",flush=True);time.sleep(30)',str(disk)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                self.assertEqual(child.stdout.readline(),b'ready\n')
                birth=lambda pid:1
                census={'vms':[{'pid':child.pid,'startTicks':1}]}
                if sys.platform=='linux':
                    with self.assertRaisesRegex(ValueError,'storage_coverage'):current._storage_vm_coverage({'plans':{}},census,birth)
                else:
                    with self.assertRaises(ValueError):current._storage_vm_coverage({'plans':{}},census,birth)
            finally:child.terminate();child.communicate(timeout=3)


if __name__=='__main__':unittest.main()
