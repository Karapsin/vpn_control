"""Original Windows lease admission survives fresh clients without GUI recovery."""
import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock
from uuid import UUID,uuid4,uuid5

from agent_tools import readiness_windows as windows
from agent_tools import readiness_windows_remote as packets
from agent_tools import readiness_windows_leases as leases
from agent_tools.tests.test_native_vm_spec import request
from agent_tools.tests.test_readiness_windows_guest import facts

MACHINE='7fb3fd62-699e-4478-9bd0-498a61efb91c'
BOOT='2026-10-20T09:04:39.5000000Z'
SID='S-1-5-21-1-2-3-1000'
HOSTBOOT='25515f23-b966-4c3a-ae63-d38452375578'


def snapshot():
    return {'schemaVersion':1,'provider':'raw-qemu-windows',
            'binding':{'provider':'raw-qemu-windows','spec':request(),
                       'setup':{'user':'recovery','administrator':'recoveryadmin','locale':'en-US','imageName':'Windows 11 Pro'},
                       'context':{'hostBootId':HOSTBOOT,'pending':[]},'uri':None,'domain':None,'xmlSha256':None},
            'expectedSid':SID,'host':{'actor':{'pid':123,'startTicks':456},'hostBoot':HOSTBOOT,'controlConnection':'qmp:42'},
            'guest':{'machine':MACHINE,'boot':BOOT,'account':SID,'session':'2:1234',
                     'root_generation':'12345678:0000000000000042:0000000000000001'},'sources':windows._source_pins()}


def unsubmitted(operation):
    return {'schemaVersion':1,'operationId':operation,'machine':MACHINE,'boot':BOOT,
            'rootGeneration':'12345678:0000000000000042:0000000000000001','state':'unsubmitted',
            'reason':'original_admission_absent','replayAllowed':False}


class WindowsLeaseExecutorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.saved=snapshot();self.op=str(uuid4())

    def executor(self):return windows.lease_executor_from_snapshot(self.root,self.saved)

    def run_result(self,mode,hostop,deadline,**options):
        return {'state':'observed','lease':unsubmitted(options['lease_operation'])},None

    def test_fresh_snapshot_reconciliation_never_loads_registry_or_gui(self):
        with mock.patch.object(windows.registry,'registered_fixture',side_effect=AssertionError('registry')),\
             mock.patch.object(windows.WindowsBackend,'observe',side_effect=AssertionError('readiness')),\
             mock.patch.object(windows.WindowsBackend,'recover',side_effect=AssertionError('recovery')),\
             mock.patch.object(windows.WindowsBackend,'_run',side_effect=self.run_result)as dispatch:
            first=self.executor();self.assertEqual('unsubmitted',first.observe(self.op)['state'])
            second=self.executor();self.assertEqual('unsubmitted',second.observe(self.op)['state'])
        one,two=dispatch.call_args_list
        self.assertEqual('lease-status',one.args[0]);self.assertNotEqual(one.args[1],two.args[1])
        for call in (one,two):
            self.assertEqual(self.op,call.kwargs['lease_operation']);self.assertIs(True,call.kwargs['reconcile'])
            self.assertEqual(self.saved['host'],call.kwargs['expected'])

    def test_same_original_admission_reuses_host_uuid_and_refuses_ttl_replacement(self):
        with mock.patch.object(windows.WindowsBackend,'_run',side_effect=self.run_result)as dispatch:
            self.executor().submit(self.op,20)
            self.executor().submit(self.op,20)
            self.assertEqual(dispatch.call_args_list[0].args[1],dispatch.call_args_list[1].args[1])
            with self.assertRaisesRegex(Exception,'windows_lease_original_inputs_changed'):
                self.executor().submit(self.op,21)
            self.assertEqual(2,dispatch.call_count)

    def test_lost_original_ack_returns_unknown_and_never_uses_new_guest_uuid(self):
        with mock.patch.object(windows.WindowsBackend,'_run',return_value=({'state':'blocked','reason':'instance_original_guest_ack_unknown'},None))as dispatch:
            result=self.executor().submit(self.op,20)
            self.assertEqual('unknown',result['state']);self.assertFalse(result['replayAllowed'])
            self.assertEqual('resolve_blocker',result['nextAction']);self.assertEqual(1,dispatch.call_count)
            self.assertEqual(self.op,dispatch.call_args.kwargs['lease_operation'])

    def test_foreign_guest_operation_is_rejected_before_original_identity_retention(self):
        value=unsubmitted(str(uuid4()))
        with mock.patch.object(windows.WindowsBackend,'_run',return_value=({'state':'observed','lease':value},None)):
            with self.assertRaisesRegex(ValueError,'windows_lease_observation_identity_changed'):
                self.executor().observe(self.op)
        self.assertEqual([],list((self.root/'.runtime/readiness-windows-leases'/self.op).glob('*identity.json')))

    def test_snapshot_copy_and_qualification_custody(self):
        executor=self.executor();returned=executor.snapshot();returned['guest']['session']='0:1'
        self.assertEqual('2:1234',executor.snapshot()['guest']['session'])
        broken=copy.deepcopy(self.saved);broken['sources'][str(Path(windows.__file__))]['sha256']='0'*64
        with self.assertRaisesRegex(Exception,'windows_lease_original_source_changed'):
            windows.lease_executor_from_snapshot(self.root,broken)
        for capability in ['login','reboot','start']:
            with self.assertRaisesRegex(Exception,'windows_recovery_unqualified'):
                windows.WindowsBackend(self.root,self.saved['binding'],SID,capabilities={capability})

    def test_invalid_ttl_publishes_no_operation(self):
        with mock.patch.object(windows.WindowsBackend,'_run',side_effect=AssertionError('dispatch')):
            for ttl in [True,None,0,18001,float('nan')]:
                with self.subTest(ttl=ttl),self.assertRaises(ValueError):self.executor().submit(self.op,ttl)
        self.assertFalse((self.root/'.runtime/readiness-windows-leases').exists())

    def test_complete_packet_keeps_guest_identity_separate_and_bound_to_original_host(self):
        binding=leases.WindowsLeaseBinding(**self.saved['guest']);hostop=str(uuid4())
        emitted=packets.program(self.saved['binding'],'lease-status',hostop,
                expected=self.saved['host'],lease_binding=binding,lease_operation=self.op)
        compile(emitted,'complete generated Windows caller','exec')
        self.assertIn(('OPERATION='+repr(hostop)).encode(),emitted)
        self.assertIn(b'instance_original_lease_host_changed',emitted)
        for bad in ['password','EncodedCommand','AutoAdminLogon']:
            self.assertNotIn(bad.encode(),emitted)
        with self.assertRaisesRegex(ValueError,'windows_lease_host_binding'):
            packets.program(self.saved['binding'],'lease-status',hostop,lease_binding=binding)

    def test_only_proven_unsubmitted_metadata_packet_can_be_regenerated(self):
        session=facts();session['machine']=MACHINE;session['boot']=BOOT
        value={'state':'observed','guest':'running','guestAgent':True,'sessionFacts':session,
               'actor':self.saved['host']['actor'],'hostBoot':HOSTBOOT,'controlConnection':'qmp:42',
               'displayFacts':{'schemaVersion':1,'machine':MACHINE,'boot':BOOT,'displayState':1}}
        backend=windows.WindowsBackend(self.root,self.saved['binding'],SID);backend.last_facts=value
        original=str(uuid5(UUID(MACHINE),'lease-enrollment:'+BOOT));directory=windows._directory(self.root/'.runtime/readiness-windows'/original)
        path=directory/('lease-enroll-'+'a'*32+'.py');windows._save(path,b'RETAINED_ORIGINAL_SOURCE')
        result={'state':'observed','lease':{'schemaVersion':1,'machine':MACHINE,'boot':BOOT,'rootGeneration':self.saved['guest']['root_generation']}}
        for state in ['unknown','proven_unsubmitted']:
            with self.subTest(state=state),mock.patch.object(windows,'reconcile_enrollment',return_value={'state':state})as resolve,\
                 mock.patch.object(backend,'_run',return_value=(result,None))as submit:
                if state=='unknown':
                    with self.assertRaisesRegex(Exception,'windows_lease_enrollment_unknown'):backend.lease_executor()
                    self.assertEqual(0,submit.call_count)
                else:
                    executor=backend.lease_executor()
                    self.assertEqual(original,submit.call_args.args[1])
                    self.assertEqual(MACHINE,executor.binding.machine)
                self.assertEqual(1,resolve.call_count)
                self.assertEqual(b'RETAINED_ORIGINAL_SOURCE',path.read_bytes())


if __name__=='__main__':unittest.main()
