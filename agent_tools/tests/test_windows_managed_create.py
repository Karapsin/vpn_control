"""Unexposed new managed fixture source, private framing and explicit targets."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from uuid import UUID,uuid5
from xml.etree import ElementTree as ET

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_resources as resources
from agent_tools import readiness_windows_managed_create as subject
from agent_tools.tests.test_windows_lifecycle_dispatch import managed_binding


class ManagedCreateTests(unittest.TestCase):
    def setUp(self):
        binding,_=managed_binding();self.binding=binding;self.rid='c'*64;self.operation=str(uuid5(UUID(binding['spec']['deploymentId']),self.rid))
        self.plan=subject.plan(binding['spec'],binding['setup'],binding['context'],binding['uri'],binding['domain'],self.operation,self.rid)

    def test_missing_foreign_or_ignored_target_refused_before_resources(self):
        for key,value in [('uri','qemu:///session'),('domain','other-owned-vm')]:
            fields={k:self.binding[k]for k in ('spec','setup','context','uri','domain')};fields[key]=value
            with self.assertRaises(ValueError):subject.plan(**fields,operation=self.operation,recovery_id=self.rid)
        for key,value in [('ordinarySigninAllowed',True),('seedDetachRequired',False),('replayAllowed',True)]:
            wrong=copy.deepcopy(self.plan);wrong[key]=value
            with self.assertRaises(ValueError):subject._plan(wrong)
        xml=ET.fromstring(self.plan['xml']);self.assertEqual(xml.findtext('uuid'),self.binding['spec']['deploymentId'])
        self.assertEqual(xml.findtext('name'),self.binding['domain']);self.assertEqual(len(xml.findall("devices/disk[@device='disk']")),1)
        self.assertEqual(xml.findall('devices/disk')[-1].find('source').get('file'),self.binding['spec']['root']+'/seed.iso')
        self.assertNotIn('password',self.plan['xml']);self.assertNotIn('passwd',self.plan['xml'])

    def test_private_answer_has_no_autologon_and_system_agent_does_not_need_signin(self):
        credentials={'user':'U'*24+'!','administrator':'A'*24+'!'}
        raw=subject.private_answer(self.binding['setup'],credentials)
        self.assertNotIn(b'AutoLogon',raw);root=ET.fromstring(raw);ns={'u':'urn:schemas-microsoft-com:unattend'}
        self.assertEqual(len(root.findall('.//u:LocalAccount',ns)),2)
        self.assertIn(credentials['user'].encode(),raw);self.assertIn(credentials['administrator'].encode(),raw)
        initialize=subject.initialization_source();self.assertIn("Start-ScheduledTask -TaskName 'VpnControlFixtureInitialize'",initialize)
        self.assertIn("-UserId 'S-1-5-18'",initialize);self.assertIn('SystemSetupInProgress',subject.unattended.INSTALL_AGENT)

    def test_private_malformed_duplicate_overflow_paths_have_constant_errors(self):
        secret='PROTECTED_PRIVATE_SENTINEL_123456789'
        for raw in [secret.encode(),b'{"user":"'+secret.encode()+b'","user":"x","administrator":"y"}',json.dumps({'user':secret,'administrator':'x'}).encode(),b'x'*4097]:
            with self.assertRaisesRegex(ValueError,'^windows_managed_private_input_invalid$')as caught:subject.credential_frame(raw)
            self.assertNotIn(secret,str(caught.exception))
        self.assertEqual(subject.credential_frame(json.dumps({'user':'U'*24,'administrator':'A'*24}).encode()),{'user':'U'*24,'administrator':'A'*24})

    def test_consumed_exact_admission_produces_public_only_fixed_program(self):
        target=resources.ResourceTarget(self.operation,self.binding['spec']['host'],self.binding['spec']['root'])
        resource=resources.ResourceAdmission(Path('/tmp'),target,self.binding['spec']['deploymentId'],self.operation,Path('/tmp'),'/unopened-private-handle',time.monotonic()+30)
        snapshot={'hostBootId':self.binding['context']['hostBootId'],'census':{},'inventorySha256':'3'*64,'resourceAliases':[target.host],
            'pending':[],'requestedMemoryBytes':self.binding['spec']['memoryMiB']*1024**2,'headroomBytes':self.binding['spec']['headroomMiB']*1024**2}
        bound=jobs.MachineBinding(self.binding['spec']['host'],'host-machine',snapshot['hostBootId'],'1000')
        with mock.patch.object(resources.ResourceAdmission,'submission_snapshot',return_value=snapshot):
            namespace={'root':subject.creator_root(self.plan),'generation':[1,2],'marker':subject._namespace_expected(self.plan,bound),'markerGeneration':[1,3,0o100600,1000,1000,1,100,100,100],'admissionsGeneration':[1,4]}
            program=subject.creator_program(self.plan,resource,namespace,bound)
        text=program.source.decode();compile(text,'managed-first-private-program','exec')
        self.assertTrue(text.startswith('_CREATOR_EXECUTING_CODE='));self.assertNotIn('/unopened-private-handle',text)
        self.assertEqual(text.count('connection.defineXML(PLAN[\'xml\'])'),1);self.assertEqual(text.count('domain.createWithFlags(0)'),1)
        self.assertIn('credentials-handoff.intent.json',subject.handoff_program(program).decode())
        self.assertLess(text.index('storage.reserve('),text.index('os.mkdir(root.name'))
        self.assertLess(text.index("save('libvirt-define.intent.json'"),text.index('connection.defineXML('))
        self.assertLess(text.index("save('libvirt-start.intent.json'"),text.index('domain.createWithFlags('))
        self.assertIn('secret_media.append((fd,path,generation(info),raw))',text)
        self.assertNotIn('hashlib.sha256(raw)',text[text.index("phase='private-seed'"):])
        self.assertNotIn('clone',text[text.index("phase='disk'"):]);self.assertNotIn('qmp(',text)
        with self.assertRaises(ValueError):subject.creator_program(self.plan,object(),namespace,bound)
        forged=jobs.Program(program.purpose,program.source,program.stream_limit)
        with self.assertRaises(ValueError):subject.handoff_program(forged)
        with self.assertRaises(ValueError):subject.handoff_program(jobs.Program('other-purpose',b'pass\n'))

    @unittest.skipIf(os.name!='posix'or os.geteuid()==0,'ordinary provider HOST metadata only')
    def test_actual_metadata_namespace_is_target_derived_and_inventory_pure_before_blank_root(self):
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())as directory:
            parent=Path(directory);parent.chmod(0o700);binding=copy.deepcopy(self.binding)
            binding['spec']['root']=str(parent/'new-vm');binding['context']['hostBootId']=str(UUID(jobs._boot()))
            binding['uri']='qemu+unix:///session?socket='+str(parent/'.cache/libvirt/virtqemud-sock')
            value=subject.plan(binding['spec'],binding['setup'],binding['context'],binding['uri'],binding['domain'],self.operation,self.rid)
            host=jobs.MachineBinding(binding['spec']['host'],subject.host_machine(),jobs._boot(),str(os.geteuid()))
            result=subprocess.run([sys.executable,'-I','-B','-c','import sys;exec(compile(sys.stdin.buffer.read(),"metadata-only-init","exec"))'],input=subject.initialize_program(value,host),capture_output=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr.decode());namespace=json.loads(result.stdout)
            self.assertEqual(namespace['root'],subject.creator_root(value));self.assertFalse(Path(binding['spec']['root']).exists())
            before={p.relative_to(parent):(p.stat().st_ino,p.stat().st_mtime_ns)for p in parent.rglob('*')}
            raw=subject.inventory_program(value,host,namespace)
            observed=subprocess.run([sys.executable,'-I','-B','-c','import sys;exec(compile(sys.stdin.buffer.read(),"pure-creator-inventory","exec"))'],input=raw,capture_output=True,timeout=5)
            self.assertEqual(observed.returncode,0,observed.stderr.decode());self.assertTrue(json.loads(observed.stdout)['idle'])
            self.assertEqual(before,{p.relative_to(parent):(p.stat().st_ino,p.stat().st_mtime_ns)for p in parent.rglob('*')})
            wrong=copy.deepcopy(namespace);wrong['root']=str(parent/'other-vm')
            with self.assertRaises(ValueError):subject.inventory_program(value,host,wrong)
            marker=Path(namespace['root'])/'creator-namespace.json';replacement=marker.with_suffix('.replacement');replacement.write_bytes(marker.read_bytes());replacement.chmod(0o600);os.replace(replacement,marker)
            changed=subprocess.run([sys.executable,'-I','-B','-c','import sys;exec(compile(sys.stdin.buffer.read(),"original-creator-inventory","exec"))'],input=raw,capture_output=True,timeout=5)
            self.assertNotEqual(changed.returncode,0)

    def test_actual_private_stdin_generated_handoff_failure_never_echoes_input(self):
        bound=jobs.MachineBinding('target','machine',self.binding['context']['hostBootId'],str(os.geteuid()if hasattr(os,'geteuid')else 1000))
        expected={'operationId':self.operation,'binding':jobs.asdict(bound),'rootGeneration':[1,2],'programSha256':'f'*64,'streamLimit':65536,'admissionsGeneration':[1,3]}
        raw=subject._handoff_source('/tmp/controlled-missing-owner/'+self.operation,expected)
        secret='PRIVATE_FRAME_DO_NOT_RETAIN_123456789'
        for frame in (secret.encode(),b'x'*4097,json.dumps({'user':secret,'administrator':'A'*24}).encode()):
            with tempfile.TemporaryDirectory()as directory:
                path=Path(directory)/'fixed-handoff.py';path.write_bytes(raw)
                result=subprocess.run([sys.executable,'-I','-B',str(path)],input=frame,capture_output=True,timeout=3)
            self.assertEqual(result.returncode,0);self.assertEqual(result.stderr,b'')
            reply=json.loads(result.stdout);self.assertEqual(reply['reason'],'windows_managed_credential_handoff_unknown')
            self.assertNotIn(secret.encode(),result.stdout);self.assertNotIn(frame,result.stdout)




@unittest.skipUnless(sys.platform.startswith('linux')and os.geteuid()>0,'actual Linux selected HOST peer contract')
class CredentialWireTests(unittest.TestCase):
    def test_fixed_generated_sender_original_owner_lost_ack_never_resends(self):
        import inspect
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())as directory:
            root=Path(directory);root.chmod(0o700);remote=root/'jobs';remote.mkdir(mode=0o700);generation=jobs.root_generation(remote)
            operation=str(uuid5(UUID('2c08610c-ce69-4b1c-8721-8bdf6227c02a'),'credential-wire'))
            binding=jobs.MachineBinding('controlled-host',subject.host_machine(),jobs._boot(),str(os.geteuid()if hasattr(os,'geteuid')else 1000))
            job=remote/operation
            source=('import sys,types,os\nOWNER='+repr(jobs.owner_source())+'\nJOB='+repr(str(job))+'\nOP='+repr(operation)+'\n'
                'm=types.ModuleType("wire_owner");sys.modules[m.__name__]=m;exec(compile(OWNER,"original-owner","exec"),m.__dict__)\n'+inspect.getsource(subject.credential_frame)+'\n'+inspect.getsource(subject._receive_credentials)+'\n'
                'value=_receive_credentials(JOB,m,OP)\nvalue.clear()\nprint("accepted without retaining input")\n').encode()
            program=jobs.Program('windows-managed-first-create',source,65536)
            (remote/'admissions').mkdir(mode=0o700);ag=list(jobs.root_generation(remote/'admissions'))
            expected={'operationId':operation,'binding':jobs.asdict(binding),'rootGeneration':list(generation),'programSha256':program.digest,'streamLimit':program.stream_limit,'admissionsGeneration':ag}
            subject._creator_admission(jobs,remote,expected,create=True)
            jobs.submit(remote,operation,binding,program,generation=generation)
            end=time.monotonic()+5
            while not(job/'creator-listener.json').exists():self.assertLess(time.monotonic(),end);time.sleep(.02)
            status=root/'status.py';status.write_bytes(subject._status_source(str(job),expected,'selected-vm-machine',str(root/'never-created-vm')))
            observed=subprocess.run([sys.executable,'-I','-B',str(status)],capture_output=True,timeout=5)
            self.assertTrue(json.loads(observed.stdout)['listenerReady'])
            sender=root/'handoff.py';sender.write_bytes(subject._handoff_source(str(job),expected));sender.chmod(0o600)
            frame=json.dumps({'user':'U'*25,'administrator':'A'*25}).encode()
            first=subprocess.run([sys.executable,'-I','-B',str(sender)],input=frame,capture_output=True,timeout=5)
            self.assertEqual(first.stderr,b'');self.assertEqual(json.loads(first.stdout)['state'],'credentials-accepted')
            intent=(job/'credentials-handoff.intent.json').stat()
            while True:
                status=jobs.observe(remote,operation,binding,generation=generation)
                if status['state']=='terminal':break
                self.assertLess(time.monotonic(),end,status);time.sleep(.02)
            status,out,err=jobs.collect(remote,operation,binding,generation=generation)
            self.assertEqual(status['terminal']['exitCode'],0);self.assertEqual(err,b'');self.assertNotIn(frame,out)
            repeat=subprocess.run([sys.executable,'-I','-B',str(sender)],input=frame,capture_output=True,timeout=5)
            self.assertEqual(json.loads(repeat.stdout)['state'],'original-observation-required')
            self.assertEqual(intent,(job/'credentials-handoff.intent.json').stat())
            for path in job.iterdir():
                if path.is_file():self.assertNotIn(frame,path.read_bytes(),path.name)


if __name__=='__main__':unittest.main()
