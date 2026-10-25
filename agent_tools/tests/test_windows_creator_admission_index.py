"""A consumed creator admission survives disappearance of its original jobdir."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import ModuleType
import unittest
import weakref
from uuid import UUID,uuid5

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_windows_managed_create as current
from agent_tools.tests.test_windows_lifecycle_dispatch import managed_binding

FIXTURE=Path(__file__).parent/'fixtures/windows_creator_admission_index'


def subject():
    if os.environ.get('VPN_CONTROL_CREATOR_INDEX_BEFORE')!='1':return current
    raw=(FIXTURE/'before.source').read_bytes()
    assert hashlib.sha256(raw).hexdigest()==json.loads((FIXTURE/'provenance.json').read_text())['sourceSha256']
    module=ModuleType('agent_tools._creator_index_before');module.__package__='agent_tools';module.__file__=str(FIXTURE/'before.source')
    sys.modules[module.__name__]=module;exec(compile(raw,module.__file__,'exec'),module.__dict__);return module


@unittest.skipIf(os.name!='posix'or os.geteuid()==0,'ordinary actual HOST owner required')
class CreatorAdmissionIndexTests(unittest.TestCase):
    def test_consumed_original_directory_loss_is_unknown_without_second_execution(self):
        module=subject()
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())as directory:
            parent=Path(directory);parent.chmod(0o700);binding,_=managed_binding()
            binding['spec']['root']=str(parent/'never-created-vm');binding['context']['hostBootId']=str(UUID(jobs._boot()))
            binding['uri']='qemu+unix:///session?socket='+str(parent/'.cache/libvirt/virtqemud-sock')
            rid='c'*64;operation=str(uuid5(UUID(binding['spec']['deploymentId']),rid))
            plan=module.plan(binding['spec'],binding['setup'],binding['context'],binding['uri'],binding['domain'],operation,rid)
            host=jobs.MachineBinding(binding['spec']['host'],module.host_machine(),jobs._boot(),str(os.geteuid()))
            def run(source):
                result=subprocess.run([sys.executable,'-I','-B','-c','import sys;exec(compile(sys.stdin.buffer.read(),"selected-creator-caller","exec"))'],input=source,capture_output=True,timeout=8)
                self.assertEqual(result.returncode,0,result.stderr.decode());return json.loads(result.stdout)
            namespace=run(module.initialize_program(plan,host));root=Path(namespace['root']);counter=parent/'executions'
            # Controlled internal factory: only a retained ordinary HOST owner,
            # never any actual media, resource reservation or VM mutation.
            source=('PLAN='+repr(plan)+'\nfrom pathlib import Path\nwith Path('+repr(str(counter))+').open("a")as output:output.write("execution\\n")\nprint("original complete")\n').encode()
            program=jobs.Program('windows-managed-first-create',source,262144)
            expected={'operationId':operation,'binding':jobs.asdict(host),'rootGeneration':namespace['generation'],'programSha256':program.digest}
            if hasattr(module,'_creator_admission'):expected.update(streamLimit=program.stream_limit,admissionsGeneration=namespace['admissionsGeneration'])
            module._CREATE_PROGRAMS[program]=(weakref.ref(program),str(root/operation),expected)
            module._CREATE_NAMESPACES[program]=namespace;module._CREATE_PLANS[program]=plan
            packet=module.submission_program(program);run(packet);end=time.monotonic()+8
            while True:
                status=jobs.observe(root,operation,host,generation=tuple(namespace['generation']))
                if status['state']=='terminal':break
                self.assertLess(time.monotonic(),end,status);time.sleep(.02)
            status,out,err=jobs.collect(root,operation,host,generation=tuple(namespace['generation']))
            self.assertEqual(status['terminal']['exitCode'],0);self.assertEqual(out,b'original complete\n');self.assertEqual(err,b'')
            # Preserve the actual complete original receipt and every file;
            # only the exact owned job path disappears from its namespace.
            saved=parent/'preserved-original-job';os.rename(root/operation,saved)
            repeated=run(packet)
            if os.path.lexists(root/operation):
                end=time.monotonic()+8
                while jobs.observe(root,operation,host,generation=tuple(namespace['generation']))['state']!='terminal':
                    self.assertLess(time.monotonic(),end);time.sleep(.02)
                jobs.collect(root,operation,host,generation=tuple(namespace['generation']))
            self.assertEqual(counter.read_text().splitlines(),['execution'],'loss must not replace a consumed original')
            self.assertEqual(repeated['state'],'unknown');self.assertEqual(repeated['reason'],'original_creator_admission_consumed')
            observed=run(module.status_program(program));self.assertEqual(observed['status']['state'],'unknown');self.assertFalse(observed['listenerReady'])
            inventory=run(module.inventory_program(plan,host,namespace));self.assertFalse(inventory['idle'])
            self.assertEqual(inventory['jobs'][0]['operationId'],operation);self.assertEqual(inventory['jobs'][0]['status']['state'],'unknown')
            self.assertTrue((saved/'terminal.json').exists());self.assertFalse(Path(binding['spec']['root']).exists())
            # Losing the independent directory itself is missing custody,
            # never a new unsubmitted operation or a place to recreate it.
            os.rename(root/'admissions',parent/'preserved-original-admissions')
            refused=subprocess.run([sys.executable,'-I','-B','-c','import sys;exec(compile(sys.stdin.buffer.read(),"damaged-selected-admission","exec"))'],input=packet,capture_output=True,timeout=5)
            self.assertNotEqual(refused.returncode,0);self.assertEqual(counter.read_text().splitlines(),['execution'])


if __name__=='__main__':unittest.main()
