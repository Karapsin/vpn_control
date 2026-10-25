"""Creator discovery is exact-target, local-only and immutable per artifact."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from uuid import UUID,uuid5

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_windows_managed_create as creator
from agent_tools import readiness_windows_creator_registry as subject
from agent_tools.tests.test_windows_lifecycle_dispatch import managed_binding


@unittest.skipIf(os.name!='posix'or os.geteuid()==0,'ordinary local and HOST private journals')
class CreatorRegistryTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(dir=Path('/tmp').resolve());self.addCleanup(temp.cleanup);self.root=Path(temp.name);self.root.chmod(0o700)
        binding,_=managed_binding();binding['spec']['root']=str(self.root/'uncreated-vm');binding['context']['hostBootId']=str(UUID(jobs._boot()));binding['uri']='qemu+unix:///session?socket='+str(self.root/'.cache/libvirt/virtqemud-sock')
        rid='c'*64;op=str(uuid5(UUID(binding['spec']['deploymentId']),rid));self.plan=creator.plan(binding['spec'],binding['setup'],binding['context'],binding['uri'],binding['domain'],op,rid)
        self.host=jobs.MachineBinding(binding['spec']['host'],creator.host_machine(),jobs._boot(),str(os.geteuid()));self.binding=self.plan['binding']
        result=subprocess.run([sys.executable,'-I','-B','-c','import sys;exec(compile(sys.stdin.buffer.read(),"actual-metadata-only-init","exec"))'],input=creator.initialize_program(self.plan,self.host),capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr.decode());self.namespace=json.loads(result.stdout)

    def test_actual_initialized_namespace_retained_then_discovered_without_transport_or_writes(self):
        self.assertIsNone(subject.load(self.root,self.binding));handle=subject.retain(self.root,self.plan,self.host,self.namespace)
        with self.assertRaises(TypeError):subject.CreatorHandle()
        before={p.relative_to(self.root):(p.stat().st_ino,p.stat().st_mtime_ns)for p in self.root.rglob('*')}
        with mock.patch.object(subprocess,'run',side_effect=AssertionError('transport from getter')):
            fresh=subject.load(self.root,self.binding);self.assertEqual(fresh.guard()['namespace'],self.namespace);source=fresh.definitions()
        namespace={};exec(source,namespace);self.assertTrue(namespace['_creator_host_work']()['idle'])
        self.assertEqual(before,{p.relative_to(self.root):(p.stat().st_ino,p.stat().st_mtime_ns)for p in self.root.rglob('*')})
        wrong=copy.deepcopy(self.binding);wrong['spec']['memoryMiB']+=1024
        with self.assertRaises(ValueError):subject.load(self.root,wrong)
        absent=copy.deepcopy(self.binding);absent['spec']['deploymentId']=str(uuid5(UUID(self.binding['spec']['deploymentId']),'different'))
        absent['domain']='vc-recovery-libvirt-'+absent['spec']['deploymentId'][:8]
        self.assertIsNone(subject.load(self.root,absent))
        self.assertFalse(Path(self.binding['spec']['root']).exists())

    def test_equal_bytes_replacement_and_missing_custody_are_never_adopted(self):
        for artifact in subject._FILES:
            handle=subject.retain(self.root,self.plan,self.host,self.namespace);directory=subject._HANDLES[handle][0];path=directory/artifact
            raw=path.read_bytes();replacement=path.with_suffix('.replacement');replacement.write_bytes(raw);replacement.chmod(0o600);os.replace(replacement,path)
            with self.assertRaises(ValueError):handle.guard()
            with self.assertRaises(ValueError):subject.load(self.root,self.binding)
            # Each case gets a fresh controlled local repository; remote
            # metadata is unchanged, and no missing manifest is invented.
            for child in directory.iterdir():child.unlink()
        handle=subject.retain(self.root,self.plan,self.host,self.namespace);directory=subject._HANDLES[handle][0];(directory/'creator-custody.json').unlink()
        with self.assertRaises(Exception):subject.load(self.root,self.binding)
        with self.assertRaises(Exception):subject.retain(self.root,self.plan,self.host,self.namespace)


if __name__=='__main__':unittest.main()
