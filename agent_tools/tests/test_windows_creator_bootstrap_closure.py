"""A complete controller terminal is distinct from completed guest bootstrap."""
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
from uuid import UUID,uuid5

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_windows_managed_create as current
from agent_tools.tests.test_windows_lifecycle_dispatch import managed_binding

FIXTURE=Path(__file__).parent/'fixtures/windows_creator_bootstrap_closure'


def subject():
    if os.environ.get('VPN_CONTROL_CREATOR_CLOSURE_BEFORE')!='1':return current
    raw=(FIXTURE/'before.source').read_bytes();assert hashlib.sha256(raw).hexdigest()==json.loads((FIXTURE/'provenance.json').read_text())['sourceSha256']
    module=ModuleType('agent_tools._windows_creator_closure_before');module.__package__='agent_tools';module.__file__=str(FIXTURE/'before.source')
    sys.modules[module.__name__]=module;exec(compile(raw,module.__file__,'exec'),module.__dict__);return module


@unittest.skipIf(os.name!='posix'or os.geteuid()==0,'ordinary retained HOST owner required')
class CreatorClosureTests(unittest.TestCase):
    def test_actual_terminal_zero_blocked_pending_malformed_never_counts_bootstrap_idle(self):
        module=subject()
        for output in ({'state':'blocked','reason':'windows_managed_create_original_unknown'}, {'state':'postlaunch-observation-required','ordinarySigninAllowed':False,'seedDetachRequired':True},'malformed original output'):
            with self.subTest(output=output),tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())as directory:
                parent=Path(directory);parent.chmod(0o700);binding,_=managed_binding();binding['spec']['root']=str(parent/'uncreated-vm')
                binding['context']['hostBootId']=str(UUID(jobs._boot()));binding['uri']='qemu+unix:///session?socket='+str(parent/'.cache/libvirt/virtqemud-sock')
                rid='c'*64;op=str(uuid5(UUID(binding['spec']['deploymentId']),rid));value=module.plan(binding['spec'],binding['setup'],binding['context'],binding['uri'],binding['domain'],op,rid)
                host=jobs.MachineBinding(binding['spec']['host'],module.host_machine()if hasattr(module,'host_machine')else current.host_machine(),jobs._boot(),str(os.geteuid()))
                def run(raw):
                    result=subprocess.run([sys.executable,'-I','-B','-c','import sys;exec(compile(sys.stdin.buffer.read(),"controlled-bootstrap-caller","exec"))'],input=raw,capture_output=True,timeout=5)
                    self.assertEqual(result.returncode,0,result.stderr.decode());return json.loads(result.stdout)
                namespace=run(module.initialize_program(value,host));root=Path(namespace['root'])
                # Explicit controlled factory: a real original controller with
                # a harmless selected-target PLAN and no VM preparation call.
                source=('PLAN='+repr(value)+'\nprint('+repr(json.dumps(output))+')\n').encode()
                program=jobs.Program('windows-managed-first-create',source,65536)
                if hasattr(module,'_creator_admission'):
                    module._creator_admission(jobs,root,{'operationId':op,'binding':jobs.asdict(host),'programSha256':program.digest,'streamLimit':program.stream_limit,'admissionsGeneration':namespace['admissionsGeneration']},create=True)
                jobs.submit(root,op,host,program,generation=tuple(namespace['generation']));end=time.monotonic()+5
                while True:
                    status=jobs.observe(root,op,host,generation=tuple(namespace['generation']))
                    if status['state']=='terminal':break
                    self.assertLess(time.monotonic(),end,status);time.sleep(.02)
                self.assertEqual(status['terminal']['exitCode'],0)
                inventory=run(module.inventory_program(value,host,namespace))
                self.assertEqual(inventory['jobs'][0]['status']['state'],'terminal')
                self.assertFalse(inventory['idle'],'controller terminal0 cannot resolve unknown/pending guest bootstrap')
                self.assertFalse(Path(binding['spec']['root']).exists())


if __name__=='__main__':unittest.main()
