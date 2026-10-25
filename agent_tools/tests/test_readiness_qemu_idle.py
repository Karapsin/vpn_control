"""Emitted process admission over physical Linux proc-shaped files."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

from agent_tools import readiness_qemu_idle as subject
from agent_tools.tests import test_readiness_qemu_guest as guest_tests


class ProcessAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.proc=self.base/'proc';self.proc.mkdir();self.machine=self.base/'machine-id';self.machine.write_text('a'*32)
        self.paths=['/usr/lib/systemd/systemd','/usr/lib/systemd/systemd-executor','/usr/bin/python3.12','/usr/bin/sudo','/usr/sbin/sshd']
        self.executables={};self.link_targets={}
        for index,name in enumerate(self.paths):
            path=self.base/('binary-'+str(index));path.write_bytes(b'PUBLIC STATIC EXECUTABLE')
            self.link_targets[name]=path;self.executables[name]=subject._idle_generation(path.stat())
        self.namespace={};exec(compile(subject.source(),'<complete idle source>','exec'),self.namespace)
        self.units={'ssh.service':('/usr/sbin/sshd',None),'user@1000.service':('/usr/lib/systemd/systemd','recovery')}
        self.namespace['IDLE_UNITS']=self.units;self.namespace['IDLE_EXECUTABLES']=set(self.paths)
        self.baseline={'schemaVersion':1,'machineId':'a'*32,'executables':self.executables,'units':{}}
        self.fields={}
        for name,main in [('ssh.service',723),('user@1000.service',2717)]:
            path='/usr/lib/systemd/system/'+('ssh.service' if name=='ssh.service' else 'user@.service')
            self.baseline['units'][name]={'fragment':path,'generation':[1,2,3,4,5,6,7,8,9],'sha256':'a'*64,
                'executable':self.units[name][0],'uid':0 if name=='ssh.service' else 1000}
            self.fields[name]={'MainPID':str(main),'ActiveState':'active','SubState':'running'}
        self.add(1,0,'/usr/lib/systemd/systemd',[0]*4,unit=None,name='systemd')
        self.add(723,1,'/usr/sbin/sshd',[0]*4,unit='ssh.service')
        self.add(2717,1,'/usr/lib/systemd/systemd',[1000]*4,unit='user@1000.service')
        self.add(2720,2717,'/usr/lib/systemd/systemd-executor',[1000]*4,unit='user@1000.service',name='(sd-pam)')
        self.add(2712,723,'/usr/sbin/sshd',[0]*4)
        self.add(2786,2712,'/usr/sbin/sshd',[1000]*4)
        self.add(2787,2786,'/usr/bin/sudo',[1000,0,0,0])
        self.add(2788,2787,'/usr/bin/python3.12',[0]*4)
    def add(self,pid,parent,exe,uids,unit=None,name='public-test-process'):
        path=self.proc/str(pid);path.mkdir()
        tail=['S',str(parent)]+['0']*18;tail[19]=str(1000+pid)
        (path/'stat').write_text(str(pid)+' (public test) '+' '.join(tail))
        (path/'status').write_text('Name:\t'+name+'\nKthread:\t0\nUid:\t'+'\t'.join(map(str,uids))+'\n')
        (path/'cgroup').write_text('0::/'+('user.slice/'+unit if unit else 'session.scope')+'\n')
        (path/'exe').symlink_to(self.link_targets[exe])
        (path/'cmdline').write_bytes(b'PUBLIC TEST\0')
        if not hasattr(self,'exe_names'):self.exe_names={}
        self.exe_names[pid]=exe
    def project(self,*,unit_changed=False):
        concrete=type(self.base)
        def path(*parts):
            value=concrete(*parts)
            if str(value)=='/proc' or str(value).startswith('/proc/'):
                return self.proc/str(value).removeprefix('/proc').lstrip('/')
            if str(value)=='/etc/machine-id':return self.machine
            return value
        def unit(name):
            item=self.baseline['units'][name]
            return self.fields[name],item['fragment'],[9]*9 if unit_changed else item['generation']
        self.namespace['_idle_unit']=unit
        self.namespace['_idle_public_file']=lambda name:self.executables[name]
        with mock.patch('pathlib.Path',side_effect=path),mock.patch.object(os,'getpid',return_value=2788),mock.patch.object(os,'readlink',side_effect=lambda value:self.exe_names[int(value.parent.name)]):
            return self.namespace['_idle_projection'](self.baseline)
    def test_exact_services_and_closed_probe_ancestry_are_idle(self):
        self.assertEqual({'complete':True,'unknown':[]},self.project())
    def test_ordinary_detached_or_user_service_descendant_is_not_a_baseline(self):
        for parent,unit in [(1,None),(2717,'user@1000.service')]:
            with self.subTest(parent=parent):
                self.add(2791,parent,'/usr/bin/python3.12',[1000]*4,unit=unit)
                value=self.project();self.assertTrue(value['complete']);self.assertEqual(2791,value['unknown'][0]['pid'])
                import shutil;shutil.rmtree(self.proc/'2791')
    def test_sd_pam_needs_actual_executable_uid_and_parent(self):
        self.assertFalse(self.project()['unknown'])
        fields=(self.proc/'2720/stat').read_text().split();fields[4]='1';(self.proc/'2720/stat').write_text(' '.join(fields))
        self.assertTrue(any(row['pid']==2720 for row in self.project()['unknown']))
    def test_sibling_ssh_process_is_work_not_transport_ancestry(self):
        self.add(2800,723,'/usr/sbin/sshd',[0]*4)
        self.assertEqual(2800,self.project()['unknown'][0]['pid'])
    def test_changed_public_fragment_is_rejected_before_bytes_are_read(self):
        with mock.patch.object(Path,'read_bytes',side_effect=AssertionError('must not hash changed input')):
            with self.assertRaisesRegex(ValueError,'idle_unit_changed'):self.project(unit_changed=True)
    def test_unreadable_live_process_blocks_positive_visibility(self):
        (self.proc/'2786/status').write_text('Name:\tsshd\nUid:\t1000\t1000\t1000\t1000\n')
        self.assertFalse(self.project()['complete'])
    def test_preserved_missing_ssh_catalog_full_projection_red_green(self):
        folder=Path(__file__).parent/'fixtures/qemu_idle_ssh_baseline_before'
        raw=(folder/'readiness_qemu_idle.py.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_text())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('qemu_idle_ssh_before');exec(compile(raw,str(folder/'readiness_qemu_idle.py.source'),'exec'),before.__dict__)
        old={};exec(compile(before.source(),'<whole unfixed idle emitter>','exec'),old)
        old['IDLE_UNITS']={key:value for key,value in self.units.items() if key in before.UNITS}
        old['IDLE_EXECUTABLES']=set(self.paths)
        original_namespace=self.namespace;original_baseline=self.baseline
        self.namespace=old
        self.baseline={**original_baseline,'units':{key:value for key,value in original_baseline['units'].items() if key in old['IDLE_UNITS']}}
        result=self.project()
        self.assertFalse(result['complete']);self.assertIn(723,{row['pid'] for row in result['unknown']})
        self.namespace=original_namespace;self.baseline=original_baseline
        self.assertEqual({'complete':True,'unknown':[]},self.project())

    def test_baseline_refresh_reuses_old_fragments_without_reading_bytes(self):
        namespace=self.namespace
        namespace['_idle_unit']=lambda name:(self.fields[name],self.baseline['units'][name]['fragment'],self.baseline['units'][name]['generation'])
        namespace['_idle_public_file']=lambda name:self.executables[str(name)]
        with mock.patch.object(Path,'read_text',return_value='a'*32),mock.patch.object(Path,'read_bytes',side_effect=AssertionError('old fragment bytes cannot be read')):
            self.assertEqual(self.baseline,namespace['_idle_baseline'](self.baseline))

    def test_whole_preserved_guest_probe_causal_red_green(self):
        folder=Path(__file__).parent/'fixtures/qemu_noncanonical_jobs_before';raw=(folder/'readiness_qemu_guest.py.source').read_bytes()
        metadata=json.loads((folder/'provenance.json').read_text());self.assertEqual(metadata['sourceSha256'],hashlib.sha256(raw).hexdigest())
        old=types.ModuleType('agent_tools.old_qemu_idle');old.__package__='agent_tools';old.__file__=str(folder/'readiness_qemu_guest.py.source')
        exec(compile(raw,old.__file__,'exec'),old.__dict__)
        fixture=guest_tests.QemuGuestFactsTests()
        self.assertTrue(fixture.observe(old.program(),process='python3')[0]['jobVisibilityComplete'])
        self.assertFalse(fixture.observe(process='python3')[0]['jobVisibilityComplete'])
        self.assertEqual([],fixture.observe(old.program(),process='python3')[0]['unknownOrRunningJobs'])
        self.assertTrue(fixture.observe(process='python3')[0]['unknownOrRunningJobs'])


@unittest.skipUnless(sys.platform.startswith('linux'),'Actual Linux kernel process identity')
class NativeProcessTests(unittest.TestCase):
    def test_actual_detached_child_birth_and_ordinary_process_are_observed(self):
        namespace={};exec(compile(subject.source(),'<emitted actual Linux proc observer>','exec'),namespace)
        child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(2)'],start_new_session=True)
        try:
            row=namespace['_idle_process'](Path('/proc')/str(child.pid))
            self.assertEqual(child.pid,row['pid']);self.assertEqual(os.getuid(),row['uids'][1])
            self.assertGreater(row['birth'],0)
            self.assertNotEqual('1',str(row['birth']))
        finally:
            child.wait(timeout=5)


if __name__=='__main__':unittest.main()
