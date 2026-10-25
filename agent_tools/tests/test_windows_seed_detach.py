"""Source-only selected seed ejection gates; no provider capability or VM call."""
import copy
import inspect
import json
import socket
import unittest
from uuid import UUID,uuid5
from xml.etree import ElementTree as ET

from agent_tools import readiness_windows_managed_create as creator
from agent_tools import readiness_windows_seed_detach as subject
from agent_tools.tests.test_windows_lifecycle_dispatch import managed_binding


class SeedDetachTests(unittest.TestCase):
    def setUp(self):
        self.binding,_=managed_binding();spec=self.binding['spec'];self.xml=creator.domain_xml(spec,self.binding['domain'])
        self.binding['xmlSha256']=creator.validate_canonical_xml(self.xml,spec,self.binding['domain'])
        self.op=str(uuid5(UUID(spec['deploymentId']),'private-credential-seed-detach-v1'))
        self.expected={'operationId':self.op,'binding':self.binding,'creatorOperationId':'9c15f5c2-0d68-4a78-8268-9a06b96c7987',
            'seedPath':spec['root']+'/seed.iso','seedAlias':'ua-vpn-control-credential-seed'}
        self.proof={'nonce':'58c3541a-d281-4a51-ad2c-441785e71018','machine':spec['deploymentId'],'boot':'2026-10-20T03:04:05.0000000Z',
            'principal':'S-1-5-18','account':'S-1-5-21-1-2-3-1001','ordinary':True,'setupComplete':True,'agentReady':True,'interactiveUsers':0}
        self.flags={'inactive':2,'live':1,'config':2};self.generation=[1,2,0o100600,1000,1000,1,4096,10,10]

    def test_wrong_target_or_interactive_user_never_reaches_selected_manager_effect(self):
        expected=self.expected
        class Domain:
            def UUIDString(self):return '33ef890c-c95a-4b6e-abfa-53e8fd25a980'
            def name(self):return expected['binding']['domain']
            def updateDeviceFlags(self,*args):raise AssertionError('foreign manager effect')
        with self.assertRaisesRegex(ValueError,'windows_seed_ejection_unresolved'):
            subject._eject_selected(expected,Domain(),self.flags,lambda *a,**k:None,lambda *a:None,lambda:None,lambda:self.proof,lambda:self.generation)
        for key,value in [('interactiveUsers',1),('principal','S-1-5-21-1-2-3-1001'),('ordinary',False),('setupComplete',False),('agentReady',False)]:
            bad={**self.proof,key:value}
            with self.assertRaisesRegex(ValueError,'windows_seed_original_unresolved'):
                subject.validate_system(bad,bad['machine'],bad['nonce'])
        with self.assertRaises(ValueError):subject.eject_once({},None,None,None,None,None,None,None)
        self.assertEqual(subject.QUALIFIED_RECOVERIES,frozenset())

    def test_actual_control_socket_lost_ack_observes_same_ejection_without_replay(self):
        expected=self.expected;initial=self.xml;records={};calls=[];left,right=socket.socketpair();right.settimeout(.1)
        class Domain:
            current=initial
            def UUIDString(self):return expected['binding']['spec']['deploymentId']
            def name(self):return expected['binding']['domain']
            def XMLDesc(self,flags):return self.current
            def updateDeviceFlags(self,raw,flags):
                selftest.assertIn('private-seed-'+expected['operationId']+'.intent.json',records)
                selftest.assertEqual(flags,3);calls.append(raw);left.sendall(b'selected-ejection\n')
                tree=ET.fromstring(self.current)
                target=tree.find("devices/disk/alias[@name='ua-vpn-control-credential-seed']/..")
                target.remove(target.find('source'));self.current=ET.tostring(tree,encoding='unicode')
                raise ConnectionError('controlled manager acknowledgement loss')
        selftest=self;domain=Domain()
        def read(name,missing=False):return copy.deepcopy(records.get(name))
        def save(name,value):
            self.assertNotIn(name,records);records[name]=copy.deepcopy(value)
        try:
            with self.assertRaises(ConnectionError):subject._eject_selected(expected,domain,self.flags,read,save,lambda:None,lambda:copy.deepcopy(self.proof),lambda:self.generation)
            self.assertEqual(right.recv(1024),b'selected-ejection\n')
            result=subject._eject_selected(expected,domain,self.flags,read,save,lambda:None,lambda:copy.deepcopy(self.proof),lambda:self.generation)
            self.assertEqual(len(calls),1);self.assertFalse(result['ordinarySigninAllowed']);self.assertTrue(result['readersRequired'])
            with self.assertRaises(socket.timeout):right.recv(1024)
            # No reader/boot authority can be inferred from a manager ACK.
            changed={**self.proof,'boot':'2026-10-21T03:04:05.0000000Z'}
            with self.assertRaisesRegex(ValueError,'windows_seed_ejection_unresolved'):
                subject._eject_selected(expected,domain,self.flags,read,save,lambda:None,lambda:changed,lambda:self.generation)
            self.assertEqual(len(calls),1)
        finally:left.close();right.close()

    def test_other_device_graph_change_and_duplicate_seed_reader_block(self):
        tree=ET.fromstring(self.xml);duplicate=copy.deepcopy(tree.find("devices/disk/alias[@name='ua-vpn-control-credential-seed']/.."));tree.find('devices').append(duplicate)
        with self.assertRaises(ValueError):subject._seed_graph(ET.tostring(tree,encoding='unicode'),self.expected['seedPath'],self.expected['seedAlias'],attached=True)
        for value in (None,True,'bad','00000000-0000-0000-0000-00000000000x'):
            self.assertFalse(subject._uuid(value))
        source=subject.system_source(self.binding['setup'],self.binding['spec']['deploymentId'],self.proof['nonce'])
        self.assertIn("'S-1-5-18'",source);self.assertIn('GetCurrent().Name',source);self.assertNotIn("-eq 'NT AUTHORITY\\SYSTEM'",source)
        # Selected ISO bytes are never opened: only public original sources,
        # receipts and the private seed's lstat metadata enter the ROOT gate.
        source=inspect.getsource(subject._observe_seed_readers)
        self.assertNotIn('open(seed',source);self.assertNotIn('seed.read_',source)
        self.assertIn('PermissionError is never an empty process',inspect.getsource(subject._regular_file_census))
        self.assertIn('getdents64',inspect.getsource(subject._fd_names))


class SeedOwnerSourceTests(unittest.TestCase):
    @unittest.skipIf(__import__('os').name!='posix'or __import__('os').geteuid()==0,'ordinary actual private HOST packets required')
    def test_fixed_ejection_builder_uses_actual_opaque_host_namespace_and_original_packet(self):
        import hashlib
        from unittest import mock
        from agent_tools import durable_remote_job as jobs
        from agent_tools import readiness_windows_host_jobs as host
        from agent_tools.tests.test_windows_host_jobs import WindowsHostOwnerTests
        fixture=WindowsHostOwnerTests('runTest');fixture.setUp();self.addCleanup(fixture.doCleanups)
        binding=copy.deepcopy(fixture.bound);binding.update(provider='libvirt-windows',domain='vc-recovery-libvirt-'+binding['spec']['deploymentId'][:8],
            uri='qemu+unix:///session?socket='+str(fixture.root/'.cache/libvirt/virtqemud-sock'))
        xml=creator.domain_xml(binding['spec'],binding['domain']);binding['xmlSha256']=creator.validate_canonical_xml(xml,binding['spec'],binding['domain'])
        # Explicit controlled source factory, not a native creator or public
        # ownership override. Namespace and retained packets are real private
        # immutable artifacts; no constructed Program is ever submitted.
        namespace=host.retain_namespace(fixture.root,fixture.bound,fixture.lineage,{'namespace':fixture.namespace})
        from agent_tools import readiness_resources as resources
        from agent_tools import readiness_windows_creator_registry as registry
        import os
        rid='c'*64;create_op=str(uuid5(UUID(binding['spec']['deploymentId']),rid))
        plan=creator.plan(binding['spec'],binding['setup'],binding['context'],binding['uri'],binding['domain'],create_op,rid)
        host_binding=jobs.MachineBinding(binding['spec']['host'],creator.host_machine(),jobs._boot(),str(os.geteuid()))
        # Initial metadata namespace must precede VM root creation. Preserve
        # this harmless existing test directory/inode while initializing it.
        held_vm=fixture.root/'held-before-initialization';os.rename(fixture.vm,held_vm)
        try:creator_namespace=fixture.run_source(creator.initialize_program(plan,host_binding))
        finally:os.rename(held_vm,fixture.vm)
        handle=registry.retain(fixture.root,plan,host_binding,creator_namespace)
        target=resources.ResourceTarget(create_op,binding['spec']['host'],binding['spec']['root'])
        admission=resources.ResourceAdmission(fixture.root,target,binding['spec']['deploymentId'],create_op,fixture.root,'/unopened-protected-handle',10**12)
        snapshot={'hostBootId':binding['context']['hostBootId']}
        with mock.patch.object(resources.ResourceAdmission,'submission_snapshot',return_value=snapshot):
            creator_program=creator.creator_program(plan,admission,creator_namespace,host_binding)
        original=subject.original(creator_program,handle,binding);body=original.as_dict();operation=body['operationId'];rid=body['recoveryId']
        actor=fixture.lineage.as_dict()['qemu']
        program=subject.ejection_program(original,actor,namespace)
        compile(program.source,'complete sealed ejection','exec');self.assertEqual(program.purpose,'windows-private-seed-eject')
        text=program.source.decode()
        self.assertIn('_lifecycle_host_work(operator_fd=lock)',text);self.assertTrue('GetCurrent' in text)
        self.assertIn("'seed-system-before'",text);self.assertIn('creator_guard()',text)
        self.assertTrue('VIR_DOMAIN_DEVICE_MODIFY_FORCE'not in text);self.assertTrue('guest-shutdown'not in text)
        retained=host.retain(fixture.root,namespace,operation,rid,program)
        subject.attach_ejection(original,retained);self.assertIs(subject.original_ejection(original),retained)
        reopened=subject.reopen_ejection(handle,retained)
        self.assertEqual(reopened.as_dict(),original.as_dict())
        with self.assertRaises(ValueError):subject.ejection_program(reopened,actor,namespace)
        getter=subject.request_program(reopened);compile(getter,'pure selected reader request','exec')
        import ast
        self.assertFalse(any(isinstance(node,ast.Call)and isinstance(node.func,ast.Name)and node.func.id=='_eject_selected'for node in ast.walk(ast.parse(getter))))
        self.assertEqual(host.validate_result(retained,fixture.run_source(host.operation_program(retained)))['status']['state'],'unsubmitted')
        # A different retained source can never stand in for this packet.
        wrong=host.retain(fixture.root,namespace,fixture.operation,fixture.rid,jobs.Program('windows-private-seed-eject',b'pass\n'))
        with self.assertRaises(ValueError):subject.attach_ejection(original,wrong)
        self.assertFalse((fixture.vm/'seed.iso').exists())

    def test_reader_witness_is_opaque_and_result_never_accepts_missing_visibility(self):
        with self.assertRaises(TypeError):subject.ReaderWitness()
        forged=object.__new__(subject.ReaderWitness)
        with self.assertRaises(ValueError):forged.validate(object())
        for result in ({'complete':False,'holders':[],'observedNs':1,'deadlineNs':2},
            {'complete':True,'holders':[],'observedNs':True,'deadlineNs':2},
            {'complete':True,'holders':[],'observedNs':2,'deadlineNs':1},
            {'complete':True,'holders':[],'observedNs':1,'deadlineNs':30_000_000_002}):
            with self.assertRaises(ValueError):subject.validate_reader_result(result)
        result={'complete':True,'holders':[{'pid':1,'uid':0,'birth':1}],'observedNs':1,'deadlineNs':2}
        self.assertEqual(subject.validate_reader_result(result),result)


@unittest.skipUnless(__import__('sys').platform.startswith('linux')and getattr(__import__('os'),'geteuid',lambda:-1)()==0,
    'actual ROOT Linux FD metadata qualification required')
class SeedReaderKernelTests(unittest.TestCase):
    def test_actual_nondumpable_holder_requires_root_and_root_never_reads_selected_bytes(self):
        import os,pathlib,subprocess,sys,tempfile,time
        effective=int(next(line.split()[1]for line in pathlib.Path('/proc/self/status').read_text().splitlines()if line.startswith('CapEff:')),16)
        if not effective&(1<<19):self.skipTest('actual CAP_SYS_PTRACE required')
        uid=int(os.environ.get('SUDO_UID','0'))
        if uid<=0:self.skipTest('ordinary protected HOST operator required')
        with tempfile.TemporaryDirectory()as temporary:
            root=pathlib.Path(temporary);root.chmod(0o711);selected=root/'private.iso'
            selected.write_bytes(b'controlled private sentinel never read by observer');selected.chmod(0o600);os.chown(selected,uid,-1)
            fd=os.open(selected,os.O_RDONLY);os.chown(root,uid,-1);root.chmod(0o700)
            code='import ctypes,os,sys,time;assert ctypes.CDLL(None).prctl(4,0,0,0,0)==0;os.write(1,b"ready");time.sleep(20)'
            def ordinary():os.setgid(uid);os.setuid(uid)
            child=subprocess.Popen([sys.executable,'-I','-B','-c',code],pass_fds=(fd,),preexec_fn=ordinary,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            os.close(fd)
            try:
                self.assertEqual(child.stdout.read(5),b'ready');info=selected.lstat();identity=[info.st_dev,info.st_ino]
                denied=subprocess.run([sys.executable,'-I','-B','-c','import os,sys;os.listdir("/proc/"+sys.argv[1]+"/fd")',str(child.pid)],preexec_fn=ordinary,capture_output=True,timeout=5)
                self.assertNotEqual(denied.returncode,0,'ordinary visibility must really fail on the nondumpable holder')
                # Once armed, any selected-file open by the observer fails.
                import sys as runtime
                armed=[True]
                def audit(event,args):
                    if armed[0]and event=='open'and args and str(args[0])==str(selected):raise AssertionError('observer opened private bytes')
                runtime.addaudithook(audit)
                try:
                    first,_=subject._regular_file_census(identity,time.monotonic()+10)
                    second,_=subject._regular_file_census(identity,time.monotonic()+10)
                finally:armed[0]=False
                self.assertEqual(first,second);self.assertEqual([row['pid']for row in first],[child.pid]);self.assertEqual(first[0]['uid'],uid)
            finally:
                child.terminate();child.communicate(timeout=5)


if __name__=='__main__':unittest.main()
