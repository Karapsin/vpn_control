"""Retained persisted topology and complete host-only Linux lineage packets."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
import unittest
from uuid import uuid4

from agent_tools import readiness_windows_lifecycle as subject
from agent_tools.tests.test_native_vm_spec import request
from agent_tools.tests.test_readiness_windows_sockets import identity

FIXTURE=Path(__file__).parent/'fixtures/windows_existing_start_topology'


def binding():
    return {'provider':'raw-qemu-windows','spec':request(),
            'setup':{'imageName':'Windows 11 Pro','locale':'en-US','user':'recovery','administrator':'recoveryadmin'},
            'context':{'hostBootId':'25515f23-b966-4c3a-ae63-d38452375578','pending':[]},
            'uri':None,'domain':None,'xmlSha256':None}


def sample(bound):
    def actor(pid):
        words=(['/proc/self/fd/99','-uuid',bound['spec']['deploymentId'],'-m',str(bound['spec']['memoryMiB']),'-smp',str(bound['spec']['cpus'])] if pid==20 else ['/proc/self/fd/99','socket','--tpmstate','dir='+bound['spec']['root']+'/tpm'])
        return {'pid':pid,'startTicks':400+pid,'argv':words,
                'commandSha256':hashlib.sha256(b'\0'.join(x.encode()for x in words)+b'\0').hexdigest(),
                'executableGeneration':[1,pid,0o100755,0,0,1,1000,5,6]}
    qemu,tpm=actor(20),actor(21);asset=bound['spec']['assets']['firmwareCode']
    return {'schemaVersion':1,'kind':'windows-existing-lineage-v1','operationId':str(uuid4()),
            'machine':bound['spec']['deploymentId'],'provider':bound['provider'],'hostBoot':bound['context']['hostBootId'],
            'rootIdentity':[1,2,0o40700,1000,1000],'qemu':qemu,'tpm':tpm,
            'executables':{'qemu':{'path':'/usr/bin/qemu-system-x86_64','generation':list(qemu['executableGeneration']),'sha256':'12'*32},
                           'swtpm':{'path':'/usr/bin/swtpm','generation':list(tpm['executableGeneration']),'sha256':'34'*32}},
            'firmware':{**asset,'generation':[1,30,0o100644,0,0,1,asset['bytes'],5,6]},
            'mutable':{'disk.qcow2':[1,40,0o100600,1000,1000],'uefi-vars.fd':[1,41,0o100600,1000,1000]},
            'tpmState':{'path':bound['spec']['root']+'/tpm','identity':[1,42,0o40700,1000,1000]},'libvirt':None}


class ExistingWindowsTopologyTests(unittest.TestCase):
    def test_complete_fresh_setup_before_RED_persisted_plan_GREEN(self):
        raw=(FIXTURE/'hardware.before.source').read_bytes()
        self.assertEqual(json.loads((FIXTURE/'provenance.json').read_text())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('owned_windows_hardware_before');exec(compile(raw,str(FIXTURE/'hardware.before.source'),'exec'),before.__dict__)
        bound=binding();old=before.qemu_argv(bound['spec'],'/proc/self/fd/99',{'firmwareCode':1,'installer':2,'drivers':3})
        def assert_persisted(argv):
            self.assertNotIn('/proc/self/fd/', '\n'.join(argv));self.assertNotIn('seed.iso','\n'.join(argv))
            self.assertNotIn('once=', '\n'.join(argv));self.assertNotIn('/dev/fdset/2','\n'.join(argv));self.assertNotIn('/dev/fdset/3','\n'.join(argv))
        with self.assertRaises(AssertionError):assert_persisted(old)
        plan=subject.existing_start_plan(bound,subject.validate_lineage(bound,sample(bound)))
        assert_persisted(plan.qemu_argv)
        self.assertEqual('/usr/bin/qemu-system-x86_64',plan.qemu_argv[0]);self.assertIn('order=c,menu=off',plan.qemu_argv)
        for name in ('installer','drivers','seed'):
            self.assertIn('media=cdrom,readonly=on,if=none,id='+name,plan.qemu_argv)
        for word in ('-uuid', '-m', '-smp'):
            key={'-uuid':'deploymentId','-m':'memoryMiB','-smp':'cpus'}[word]
            self.assertEqual(str(bound['spec'][key]),plan.qemu_argv[plan.qemu_argv.index(word)+1])
        self.assertIn('fd={firmware-code-fd},set=1,opaque=asset:firmwareCode',plan.qemu_argv)
        self.assertIn('dir='+bound['spec']['root']+'/tpm',plan.tpm_argv)
        self.assertEqual(bound['spec']['root'],plan.root)

    def test_complete_before_accepts_inconsistent_actor_topology_RED_fixed_rejects_GREEN(self):
        folder=Path(__file__).parent/'fixtures/windows_existing_lineage_identity_before'
        raw=(folder/'before.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_text())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._windows_lineage_identity_before');before.__package__='agent_tools'
        exec(compile(raw,str(folder/'before.source'),'exec'),before.__dict__)
        bound=binding()
        for actor_name,flag,wrong in [('qemu','-uuid',str(uuid4())),('qemu','-m','4096'),('qemu','-smp','2'),('tpm','--tpmstate','dir=/other/tpm')]:
            value=sample(bound);actor=value[actor_name];actor['argv'][actor['argv'].index(flag)+1]=wrong
            actor['commandSha256']=hashlib.sha256(b'\0'.join(word.encode()for word in actor['argv'])+b'\0').hexdigest()
            with self.subTest(flag=flag):
                self.assertIsNotNone(before.validate_lineage(bound,value))
                with self.assertRaises(ValueError):subject.validate_lineage(bound,value)

    def test_lineage_is_immutable_and_never_accepts_authority_flags(self):
        bound=binding();body=sample(bound);lineage=subject.validate_lineage(bound,body)
        body['executables']['qemu']['path']='/other'
        self.assertEqual('/usr/bin/qemu-system-x86_64',lineage.as_dict()['executables']['qemu']['path'])
        exposed=lineage.as_dict();exposed['mutable'].clear()
        self.assertEqual(2,len(lineage.as_dict()['mutable']))
        for key,value in [('cleanStopped',True),('reservationReady',True),('oldActorAbsent',True)]:
            changed=sample(bound);changed[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):subject.validate_lineage(bound,changed)

    def test_changed_identity_generations_digest_and_symbolic_inputs_refuse(self):
        bound=binding()
        for change in (
            lambda v:v.update(machine=str(uuid4())),lambda v:v.update(hostBoot=str(uuid4())),
            lambda v:v.update(schemaVersion=True),lambda v:v['qemu'].update(pid=True),
            lambda v:v['qemu'].update(commandSha256='00'*32),
            lambda v:v['executables']['qemu'].update(path='/proc/self/fd/7'),
            lambda v:v['executables']['swtpm'].update(path='/usr/bin/swtpm (deleted)'),
            lambda v:v['executables']['qemu']['generation'].__setitem__(1,999),
            lambda v:v['firmware'].update(sha256='00'*32),
            lambda v:v['firmware']['generation'].__setitem__(6,0),
            lambda v:v['tpmState'].update(path='/other/tpm'),
            lambda v:v['mutable'].update(other=[1,2,3,4,5]),
        ):
            value=copy.deepcopy(sample(bound));change(value)
            with self.subTest(value=value),self.assertRaises(ValueError):subject.validate_lineage(bound,value)
        changed=binding();changed['provider']='libvirt-windows'
        with self.assertRaisesRegex(ValueError,'libvirt_lineage_unqualified'):subject.validate_lineage(changed,sample(changed))
        with self.assertRaisesRegex(ValueError,'libvirt_lineage_unqualified'):subject.lineage_program(changed,str(uuid4()))

    def test_packet_has_one_fixed_host_capture_before_wire_or_guest_branches(self):
        source=subject.lineage_program(binding(),str(uuid4())).decode()
        capture=source.index('        print(json.dumps(_capture_existing_lineage(')
        self.assertLess(capture,source.index("            suffix='readiness-"))
        self.assertIn('        return\n',source[capture:source.index("            suffix='readiness-")])
        self.assertLess(capture,source.index('        state=machine_state()'))
        compile(source,'complete host-only packet','exec')


@unittest.skipUnless(sys.platform=='linux','actual Linux executable generations and Unix socket FD ownership')
class CompleteWindowsLineageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='vc-lineage-',dir='/tmp');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700);self.binding=binding();spec=self.binding['spec'];spec['root']=str(self.root)
        self.binding['context']['hostBootId']=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        def save(name,value):
            path=self.root/name;path.write_text(json.dumps(value));path.chmod(0o600)
        self.save=save
        for name in ('disk.qcow2','uefi-vars.fd','firmware'):
            path=self.root/name;path.write_bytes(b'OWNED RETAINED DATA');path.chmod(0o600)
        asset=spec['assets']['firmwareCode'];asset.update(path=str(self.root/'firmware'),bytes=19,sha256=hashlib.sha256(b'OWNED RETAINED DATA').hexdigest())
        # Fresh spec assets must lie outside its root; firmware is held separately.
        self.media=tempfile.TemporaryDirectory(prefix='vc-lineage-media-',dir='/tmp');self.addCleanup(self.media.cleanup)
        firmware=Path(self.media.name)/'firmware';(self.root/'firmware').rename(firmware);asset['path']=str(firmware);asset['bytes']=firmware.stat().st_size
        save('fixture.json',{'firmwarePath':str(firmware)})
        (self.root/'tpm').mkdir(mode=0o700);state=self.root/'tpm/state';state.write_bytes(b'EXISTING STATE');state.chmod(0o600)
        def structure(path):
            s=path.stat();return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid]
        save('mutable-artifacts.json',{name:structure(self.root/name)for name in ('disk.qcow2','uefi-vars.fd')})
        s=firmware.stat();firmware_gen=[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
        save('intent.json',{'schemaVersion':1,'spec':spec,'setup':self.binding['setup'],'hostBootId':self.binding['context']['hostBootId'],
                           'rootIdentity':structure(self.root),'assetIdentities':{'firmwareCode':{'set':1,'generation':firmware_gen},'installer':{},'drivers':{}}})
        for role,name in [('qemu','qemu-started.json'),('tpm','swtpm-started.json')]:
            child=subprocess.Popen([sys.executable,'-I','-B',str(FIXTURE/'endpoint.py'),str(self.root),role,
                                    '--tpmstate','dir='+str(self.root/'tpm'),'-uuid',spec['deploymentId'],'-m',str(spec['memoryMiB']),'-smp',str(spec['cpus'])],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            def close(child=child):
                child.terminate();child.communicate(timeout=5)
            self.addCleanup(close);deadline=time.monotonic()+5
            while not(self.root/(role+'.ready')).exists():
                self.assertIsNone(child.poll());self.assertLess(time.monotonic(),deadline);time.sleep(.01)
            save(name,identity(child.pid))

    def run_packet(self):
        source=subject.lineage_program(self.binding,str(uuid4()));path=self.root/'lineage.py';path.write_bytes(source);path.chmod(0o600)
        result=subprocess.run([sys.executable,'-I','-B',str(path)],stdin=subprocess.DEVNULL,capture_output=True,timeout=20)
        self.assertEqual(0,result.returncode,result.stderr.decode(errors='replace'));self.assertFalse(result.stderr)
        return json.loads(result.stdout)

    def test_actual_held_binary_firmware_and_original_actors_without_any_RPC(self):
        result=self.run_packet();lineage=subject.validate_lineage(self.binding,result)
        self.assertEqual(json.loads((self.root/'qemu-started.json').read_text()),result['qemu'])
        self.assertEqual(os.path.realpath(sys.executable),result['executables']['qemu']['path'])
        plan=subject.existing_start_plan(self.binding,lineage);self.assertEqual(self.binding['spec']['deploymentId'],plan.machine)
        self.assertFalse(list(self.root.glob('*.contact')));self.assertFalse(list(self.root.glob('*.wire')))
        self.assertFalse(list(self.root.glob('readiness-recovery-*')))

    def test_replaced_firmware_or_mutable_inode_refuses_before_source_receipt(self):
        old=self.root/'disk.qcow2';old.rename(self.root/'original-disk');old.write_bytes(b'REPLACEMENT');old.chmod(0o600)
        result=self.run_packet();self.assertEqual('blocked',result['state']);self.assertEqual('instance_mutable_changed',result['reason'])
        self.assertFalse(list(self.root.glob('*.contact')))


if __name__=='__main__':unittest.main()
