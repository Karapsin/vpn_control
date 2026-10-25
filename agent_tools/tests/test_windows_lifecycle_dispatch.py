"""Finite lifecycle producer admission and actual child/socket shutdown fences.

No VM is created or powered. The controlled endpoint is a harmless Python
process. Windows guest and Linux pidfd native acceptance remain independent.
"""
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
from uuid import uuid4
from uuid import uuid5,UUID
from urllib.parse import quote

from agent_tools import readiness_windows_lifecycle as subject
from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_resources as resources
from agent_tools.tests.test_readiness_windows_lifecycle import binding,sample
from agent_tools.tests.test_readiness_windows_guest import SID

FIXTURE=Path(__file__).parent/'fixtures/windows_lifecycle_pure_validation'


def causal_subject():
    if not os.environ.get('VPN_CONTROL_WINDOWS_LIFECYCLE_BEFORE'):return subject
    assert os.environ['VPN_CONTROL_WINDOWS_LIFECYCLE_BEFORE']=='1'
    path=FIXTURE/'before.source';raw=path.read_bytes()
    assert hashlib.sha256(raw).hexdigest()==json.loads((FIXTURE/'provenance.json').read_text())['sourceSha256']
    module=ModuleType('agent_tools._windows_lifecycle_contract_before');module.__package__='agent_tools';module.__file__=str(path)
    sys.modules[module.__name__]=module;exec(compile(raw,str(path),'exec'),module.__dict__)
    return module


def managed_binding():
    bound=binding();body=sample(bound);bound['provider']='libvirt-windows'
    root=Path(bound['spec']['root'])
    bound.update(uri='qemu+unix:///session?socket='+quote(str(root.parent/'.cache/libvirt/virtqemud-sock'),safe='/'),
                 domain='vc-recovery-libvirt-'+bound['spec']['deploymentId'][:8],xmlSha256='a'*64)
    manager=copy.deepcopy(body['qemu']);manager.update(pid=40,startTicks=440,argv=['/usr/bin/virtqemud'])
    manager['commandSha256']=hashlib.sha256(b'/usr/bin/virtqemud\0').hexdigest()
    body['provider']='libvirt-windows';body['firmware']['ownership']='manager-path-held'
    body['executables']['manager']={'path':'/usr/bin/virtqemud','generation':manager['executableGeneration'],'sha256':'b'*64}
    body['libvirt']={k:bound[k]for k in ('uri','domain','xmlSha256')}
    body['libvirt'].update(manager=manager,socketPath=str(root.parent/'.cache/libvirt/virtqemud-sock'),
                          socketIdentity=[1,70,0o140600,1000,1000])
    return bound,body


class LifecycleAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.binding=binding();self.lineage=subject.validate_lineage(self.binding,sample(self.binding))
        body=self.lineage.as_dict();self.operation=str(uuid4());self.rid='1'*64
        self.expected={'actor':body['qemu'],'hostBoot':body['hostBoot'],'controlConnection':'qmp:42'}

    def test_shape_validation_contract_whole_before_red_current_green(self):
        module=causal_subject()
        with mock.patch.object(module.packets,'program',side_effect=AssertionError('generated command before readiness')):
            module.validate_lineage(self.binding,sample(self.binding))

    def test_whole_before_renders_command_during_shape_validation_current_is_pure(self):
        path=FIXTURE/'before.source';raw=path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),json.loads((FIXTURE/'provenance.json').read_text())['sourceSha256'])
        before=ModuleType('agent_tools._windows_lifecycle_pure_before');before.__package__='agent_tools';before.__file__=str(path)
        sys.modules[before.__name__]=before;exec(compile(raw,str(path),'exec'),before.__dict__)
        for module,expected in ((before,True),(subject,False)):
            with mock.patch.object(module.packets,'program',side_effect=AssertionError('command before readiness')) as builder:
                if expected:
                    with self.assertRaisesRegex(AssertionError,'command before readiness'):
                        module.validate_lineage(self.binding,sample(self.binding))
                else:module.validate_lineage(self.binding,sample(self.binding))
                self.assertEqual(expected,bool(builder.call_count))

    def test_durable_fixed_powerdown_preserves_full_native_idle_fence_and_once_intent(self):
        program=subject.powerdown_program(self.binding,self.lineage,self.operation,self.rid,
                    expected=self.expected,expected_sid=SID,reservation={})
        self.assertIs(type(program),jobs.Program)
        text=program.source.decode();compile(text,'controlled fixed powerdown','exec')
        self.assertIn("rpc('guest-shutdown',{'mode':'powerdown'})",text)
        self.assertNotIn("rpc('guest-shutdown',{'mode':'reboot'})",text)
        self.assertIn("'instance_positive_idle_required'",text)
        self.assertIn("'instance_reservation_visibility_missing'",text)
        self.assertIn("'instance_reboot_session_changed'",text)
        self.assertIn('process(LIFECYCLE_QEMU);process(LIFECYCLE_TPM)',text)
        # O_EXCL intent is the no-replay fence before guest shutdown. QEMU is
        # never sent a quit/reset/signal; only exact stopped TPM gets SIGTERM.
        self.assertLess(text.index("'action':'powerdown'"),text.index("rpc('guest-shutdown'"))
        self.assertNotIn("qmp('quit'",text);self.assertNotIn("qmp('system_reset'",text)
        self.assertIn('os.O_EXCL',text)

    def test_wrong_actor_and_unqualified_libvirt_stop_before_command_generation(self):
        with mock.patch.object(subject.packets,'program',side_effect=AssertionError('generated')):
            with self.assertRaisesRegex(ValueError,'windows_lifecycle_actor_changed'):
                subject.powerdown_program(self.binding,self.lineage,self.operation,self.rid,
                        expected={**self.expected,'actor':{}},expected_sid=SID,reservation={})
            foreign=copy.deepcopy(self.binding);foreign['provider']='libvirt-windows'
            with self.assertRaisesRegex(ValueError,'windows_lifecycle_libvirt_lineage_unqualified'):
                subject.validate_lineage(foreign,sample(self.binding))

    def test_clean_terminal_is_exact_original_lineage_and_immutable_projection(self):
        body=self.lineage.as_dict()
        terminal={'schemaVersion':1,'kind':'windows-clean-poweroff-v1','operationId':self.operation,
            'recoveryId':self.rid,'machine':body['machine'],'hostBoot':body['hostBoot'],
            'actor':{k:body['qemu'][k]for k in ('pid','startTicks')},'tpm':{k:body['tpm'][k]for k in ('pid','startTicks')},
            'bootBefore':'2026-10-20T00:00:00.000Z','account':SID,
            'lineageSha256':subject.existing_start_plan(self.binding,self.lineage).lineage_sha256,
            'artifacts':{'rootIdentity':body['rootIdentity'],'mutable':body['mutable'],
                'tpmState':{**body['tpmState'],'files':{'state':[1,50,0o100600,1000,1000]}}},
            'cleanPoweroff':True,'guestJobsAbsent':True,'cleanCause':{'kind':'qmp-shutdown-event','guest':True,'reason':'guest-shutdown'},'replayAllowed':False}
        proof=subject.validate_clean_stopped(self.binding,self.lineage,terminal)
        self.assertEqual(self.operation,proof.resource_release_proof()['cleanPoweroffOperationId'])
        terminal['actor']['pid']+=1
        self.assertNotEqual(terminal,proof.as_dict())
        with self.assertRaisesRegex(ValueError,'windows_lifecycle_clean_stop_identity'):
            subject.validate_clean_stopped(self.binding,self.lineage,terminal)

    def test_existing_start_requires_consumed_exact_resource_authority_and_has_no_create_path(self):
        body=self.lineage.as_dict();operation=str(uuid5(UUID(body['machine']),self.rid))
        terminal={'schemaVersion':1,'kind':'windows-clean-poweroff-v1','operationId':self.operation,
            'recoveryId':'2'*64,'machine':body['machine'],'hostBoot':body['hostBoot'],
            'actor':{k:body['qemu'][k]for k in ('pid','startTicks')},'tpm':{k:body['tpm'][k]for k in ('pid','startTicks')},
            'bootBefore':'2026-10-20T00:00:00.000Z','account':SID,
            'lineageSha256':subject.existing_start_plan(self.binding,self.lineage).lineage_sha256,
            'artifacts':{'rootIdentity':body['rootIdentity'],'mutable':body['mutable'],
                'tpmState':{**body['tpmState'],'files':{'state':[1,50,0o100600,1000,1000]}}},
            'cleanPoweroff':True,'guestJobsAbsent':True,'cleanCause':{'kind':'qmp-shutdown-event','guest':True,'reason':'guest-shutdown'},'replayAllowed':False}
        clean=subject.validate_clean_stopped(self.binding,self.lineage,terminal)
        target=resources.ResourceTarget(operation,self.binding['spec']['host'],self.binding['spec']['root'])
        authority=resources.ResourceAdmission(Path('/tmp'),target,body['machine'],operation,Path('/tmp'),'/not-opened',time.monotonic()+30)
        snapshot={'hostBootId':body['hostBoot'],'census':{},'inventorySha256':'3'*64,'resourceAliases':[target.host],
                  'pending':[],'requestedMemoryBytes':self.binding['spec']['memoryMiB']*1024**2,
                  'headroomBytes':self.binding['spec']['headroomMiB']*1024**2}
        with mock.patch.object(resources.ResourceAdmission,'submission_snapshot',return_value=snapshot):
            program=subject.existing_start_program(self.binding,self.lineage,clean,operation,self.rid,authority)
        text=program.source.decode();compile(text,'controlled persisted start','exec')
        self.assertIn('os.execve(executables[\'qemu\']',text)
        self.assertIn("executable='/proc/self/fd/'",text)
        self.assertIn("'windows-'+spec['deploymentId']",text)
        self.assertIn('_storage_vm_coverage(state,fresh,birth)',text)
        self.assertIn('instance_lifecycle_old_actor_present',text)
        self.assertNotIn("qemu-img','create",text)
        self.assertNotIn('Autounattend.xml',text)
        self.assertNotIn('/not-opened',text)
        with self.assertRaisesRegex(ValueError,'windows_lifecycle_resource_authority'):
            subject.existing_start_program(self.binding,self.lineage,clean,operation,self.rid,object())

    def test_managed_lineage_uses_exact_manager_and_distinct_lifecycle_boundary(self):
        bound,body=managed_binding();lineage=subject.validate_lineage(bound,body)
        source=subject.libvirt_lineage_program(bound,str(uuid4()),request_only=True)
        compile(source,'controlled libvirt lineage','exec')
        self.assertIn(b'instance_lifecycle_managed_tpm_unqualified',source)
        self.assertIn(b"backend.get('persistent_state')=='yes'",source)
        program=subject.powerdown_program(bound,lineage,self.operation,self.rid,
                  expected={'actor':body['qemu'],'hostBoot':body['hostBoot'],'controlConnection':'libvirt:40:440:70'},expected_sid=SID,reservation={})
        self.assertIn(b"managed=PROVIDER=='libvirt-windows'",program.source)
        self.assertIn(b"not domain.isActive()",program.source)
        self.assertIn(b"manager['executableGeneration']==LIFECYCLE_MANAGED",program.source)
        with self.assertRaisesRegex(ValueError,'windows_lifecycle_libvirt_plan_required'):
            subject.existing_start_plan(bound,lineage)
        broken=copy.deepcopy(body);broken['libvirt']['uri']='qemu:///session'
        with self.assertRaises(ValueError):subject.validate_lineage(bound,broken)

    def test_managed_existing_start_uses_existing_domain_only_and_retains_once_ack(self):
        bound,body=managed_binding();lineage=subject.validate_lineage(bound,body)
        terminal={'schemaVersion':1,'kind':'windows-clean-poweroff-v1','operationId':self.operation,
            'recoveryId':'2'*64,'machine':body['machine'],'hostBoot':body['hostBoot'],
            'actor':{k:body['qemu'][k]for k in ('pid','startTicks')},'tpm':{k:body['tpm'][k]for k in ('pid','startTicks')},
            'bootBefore':'2026-10-20T00:00:00.000Z','account':SID,'lineageSha256':subject._lineage_sha(lineage),
            'artifacts':{'rootIdentity':body['rootIdentity'],'mutable':body['mutable'],
                'tpmState':{**body['tpmState'],'files':{'state':[1,50,0o100600,1000,1000]}}},
            'cleanPoweroff':True,'guestJobsAbsent':True,'cleanCause':{'kind':'libvirt-shutoff','reason':'shutdown'},'replayAllowed':False}
        clean=subject.validate_clean_stopped(bound,lineage,terminal);operation=str(uuid5(UUID(body['machine']),self.rid))
        target=resources.ResourceTarget(operation,bound['spec']['host'],bound['spec']['root'])
        authority=resources.ResourceAdmission(Path('/tmp'),target,body['machine'],operation,Path('/tmp'),'/not-opened',time.monotonic()+30)
        snapshot={'hostBootId':body['hostBoot'],'census':{},'inventorySha256':'3'*64,'resourceAliases':[target.host],
                  'pending':[],'requestedMemoryBytes':bound['spec']['memoryMiB']*1024**2,
                  'headroomBytes':bound['spec']['headroomMiB']*1024**2}
        with mock.patch.object(resources.ResourceAdmission,'submission_snapshot',side_effect=AssertionError('resource consumed')), \
             mock.patch.object(subject.packets,'program',side_effect=AssertionError('packet generated')):
            with self.assertRaisesRegex(ValueError,'windows_lifecycle_managed_start_witness_unqualified'):
                subject.existing_start_program(bound,lineage,clean,operation,self.rid,authority)



class ActualChildPowerdownTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700);self.rows={};self.saved={}
        (self.root/'tpm').mkdir(mode=0o700)
        for name in ('disk.qcow2','uefi-vars.fd','tpm/state'):
            path=self.root/name;path.write_bytes(b'private fixture');path.chmod(0o600)
        self.script=self.root/'endpoint.py'
        self.script.write_text("import socket,sys\nfrom pathlib import Path\np=Path(sys.argv[1])\ns=socket.socket(socket.AF_UNIX);s.bind(str(p));s.listen(1)\np.with_suffix('.ready').write_text('ready')\nc,_=s.accept()\nassert c.recv(16)==b'powerdown'\nc.sendall(b'ack');c.close();s.close()\n")
        self.children=[]
        for name in ('qemu','tpm'):
            path=self.root/(name+'.sock')
            child=subprocess.Popen([sys.executable,'-I','-B',str(self.script),str(path)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            self.children.append(child)
            def close(child=child):
                if child.poll()is None:child.terminate()
                child.communicate(timeout=5)
            self.addCleanup(close)
            end=time.monotonic()+5
            while not path.with_suffix('.ready').exists():
                self.assertIsNone(child.poll());self.assertLess(time.monotonic(),end);time.sleep(.01)
            self.rows[name]={'pid':child.pid,'startTicks':jobs._birth(child.pid)}

    def birth(self,pid):
        for child in self.children:
            if child.pid==pid and child.poll()is not None:raise FileNotFoundError()
        return jobs._birth(pid)

    def process(self,row):
        self.assertEqual(row['startTicks'],self.birth(row['pid']))

    def save(self,name,value):
        path=self.root/name
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w')as file:json.dump(value,file);file.flush();os.fsync(file.fileno())
        self.saved[name]=value

    def close_endpoint(self,name):
        with socket.socket(socket.AF_UNIX)as client:
            client.connect(str(self.root/(name+'.sock')));client.sendall(b'powerdown');self.assertEqual(b'ack',client.recv(16))
        self.children[('qemu','tpm').index(name)].wait(timeout=5)

    def call(self,timeout):
        return subject._complete_powerdown({'deploymentId':'fixture','root':str(self.root)}, {'hostBootId':'host'},'operation','a'*64,'b'*64,
                {'actor':self.rows['qemu'],'sessionFacts':{'boot':'oldboot','expectedSid':'ordinary'}},
                lambda name:self.rows['tpm'],self.save,self.process,self.birth,lambda:None,timeout=timeout,shutdown_cause=lambda deadline:{'kind':'qmp-shutdown-event','guest':True,'reason':'guest-shutdown'})

    def test_actual_live_qemu_blocks_clean_receipt_and_never_signals_it_or_tpm(self):
        with mock.patch.object(subject.original_lifecycle.os if hasattr(subject.original_lifecycle,'os')else os,'kill',side_effect=AssertionError('signal')):
            with self.assertRaisesRegex(ValueError,'instance_powerdown_original_pending'):self.call(.03)
        self.assertEqual({},self.saved)
        self.assertTrue(all(child.poll()is None for child in self.children))

    def test_actual_socket_graceful_children_close_then_receipt_seals_once(self):
        self.close_endpoint('qemu');self.close_endpoint('tpm')
        result=self.call(1)
        self.assertTrue(result['cleanPoweroff']);self.assertTrue(result['guestJobsAbsent'])
        self.assertEqual(self.rows['qemu'],result['actor'])
        with self.assertRaises(FileExistsError):self.call(1)
        self.assertEqual(1,len(self.saved))


if __name__=='__main__':unittest.main()
