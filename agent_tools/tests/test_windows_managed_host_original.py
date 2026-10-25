"""Exact opaque original HOST Program precedes managed postlaunch metadata."""
import copy
import hashlib
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

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_windows_managed_start as subject
from agent_tools import readiness_windows_lifecycle as lifecycle
from agent_tools import readiness_windows_host_jobs as host
from agent_tools.tests import test_windows_host_jobs as owners
from agent_tools.tests import test_windows_managed_start as collectors
from agent_tools.tests.test_windows_lifecycle_dispatch import managed_binding
from agent_tools.tests.test_windows_tpm_owner import issued_witness

FIXTURE=Path(__file__).parent/'fixtures/windows_managed_host_original'


def causal_module():
    if os.environ.get('VPN_CONTROL_MANAGED_HOST_BEFORE')!='1':return subject
    raw=(FIXTURE/'before.source').read_bytes();assert hashlib.sha256(raw).hexdigest()==json.loads((FIXTURE/'provenance.json').read_text())['sourceSha256']
    module=ModuleType('agent_tools._managed_host_original_before');module.__package__='agent_tools';module.__file__=str(FIXTURE/'before.source')
    sys.modules[module.__name__]=module;exec(compile(raw,module.__file__,'exec'),module.__dict__);return module


class ManagedHostBoundaryTests(unittest.TestCase):
    def test_whole_before_unowned_plan_crosses_actual_socket_current_blocks_before_lookup(self):
        module=causal_module();expected=collectors.admission().as_dict()
        admission=module.original(expected['binding'],lifecycle.validate_lineage(expected['binding'],expected['lineage']),
            lifecycle.CleanStopped(lifecycle._freeze(expected['clean'])),expected['intent']['operationId'],expected['intent']['recoveryId'])
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);wire=root/'metadata.sock';ready=root/'ready';marker=root/'contacted'
            child=subprocess.Popen([sys.executable,'-I','-B','-c',
                "import socket,sys;from pathlib import Path;s=socket.socket(socket.AF_UNIX);s.bind(sys.argv[1]);s.listen(1);s.settimeout(.3);Path(sys.argv[2]).touch();\ntry:\n c,_=s.accept();assert c.recv(32)==b'lookup';Path(sys.argv[3]).touch();c.close()\nexcept TimeoutError:pass\ns.close()",str(wire),str(ready),str(marker)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                end=time.monotonic()+3
                while not ready.exists():self.assertIsNone(child.poll());self.assertLess(time.monotonic(),end);time.sleep(.005)
                def unowned_lookup(*args,**kwargs):
                    with socket.socket(socket.AF_UNIX)as client:client.connect(str(wire));client.sendall(b'lookup')
                    raise ValueError('controlled_stop_before_vm')
                with mock.patch.object(module,'_run',side_effect=unowned_lookup):
                    with self.assertRaises(ValueError):module.collect(root,admission,'/unopened-private-handle',guard=lambda:None)
                child.communicate(timeout=3);self.assertFalse(marker.exists(),'unowned current plan reached a target before original execution proof')
            finally:
                if child.poll()is None:child.terminate();child.communicate(timeout=3)

    @unittest.skipIf(os.name!='posix'or os.geteuid()==0,'ordinary HOST namespace required')
    def test_actual_opaque_program_attachment_owner_projection_and_unknown_refusal(self):
        fixture=owners.WindowsHostOwnerTests('runTest');fixture.setUp();self.addCleanup(fixture.doCleanups)
        expected=collectors.admission().as_dict();binding=expected['binding'];body=expected['lineage']
        binding['spec']['root']=str(fixture.vm);binding['context']['hostBootId']=str(UUID(jobs._boot()));body['hostBoot']=binding['context']['hostBootId']
        binding['uri']='qemu+unix:///session?socket='+str(fixture.root/'.cache/libvirt/virtqemud-sock')
        body['libvirt'].update(uri=binding['uri'],socketPath=str(fixture.root/'.cache/libvirt/virtqemud-sock'))
        body['rootIdentity']=fixture.lineage.as_dict()['rootIdentity'];body['tpmState']['path']=str(fixture.vm/'tpm')
        for pin in [*body['mutable'].values(),body['tpmState']['identity']]:pin[3:5]=body['rootIdentity'][3:5]
        body['tpm']['argv'][3]='dir='+str(fixture.vm/'tpm')
        body['tpm']['commandSha256']=hashlib.sha256(b'\0'.join(x.encode()for x in body['tpm']['argv'])+b'\0').hexdigest()
        lineage=lifecycle.validate_lineage(binding,body);clean=copy.deepcopy(expected['clean']);clean.update(hostBoot=body['hostBoot'],lineageSha256=lifecycle._lineage_sha(lineage))
        clean['artifacts'].update(rootIdentity=body['rootIdentity'],mutable=body['mutable']);clean['artifacts']['tpmState'].update(path=body['tpmState']['path'],identity=body['tpmState']['identity'])
        stopped=lifecycle.validate_clean_stopped(binding,lineage,clean)
        rid=expected['intent']['recoveryId'];op=str(uuid5(UUID(body['machine']),rid));plan=subject.original(binding,lineage,stopped,op,rid)
        namespace=host.namespace_from_observation(binding,lineage,fixture.run_source(host.enroll_program(binding,lineage)))
        constants={'SPEC':binding['spec'],'OPERATION':op,'LIFECYCLE_RID':rid,'LIFECYCLE_LINEAGE':body,'LIFECYCLE_CLEAN':clean}
        source=('\n'.join(k+'='+repr(v)for k,v in constants.items())+'\nprint("controlled manager pending")\n').encode()
        original=host.retain(fixture.root,namespace,op,rid,jobs.Program('windows-persisted-managed-start',source))
        attached=subject.attach_host_original(plan,original);self.assertIs(subject._host_original(attached),original)
        self.assertIn(b'MANAGED_HOST_SOURCE',subject.program(attached))
        with self.assertRaises(ValueError):subject._observe_host(host.operation_program(original),original.as_dict())
        fixture.observe(original,submit=True);terminal=fixture.terminal(original)
        projection=subject._observe_host(host.operation_program(original),original.as_dict())
        self.assertEqual(projection['operationId'],op);self.assertEqual(projection['owner'],terminal['status']['owner'])
        native_projection,request,_=collectors.projection_and_request(attached);native_projection['hostOwner']=projection
        result={'complete':True,'holders':[{'pid':201,'uid':request['qemu']['uid'],'birth':2001}],
                'observedNs':1_000_000_000,'deadlineNs':31_000_000_000}
        with issued_witness(request,result)as witness:
            publish=subject.program(attached,request={'original':native_projection,'request':request},witness=witness,publish=True)
        text=publish.decode();self.assertIn("'guest-admission-required'",text);self.assertIn("'guestReady':False",text)
        self.assertIn('original_after[\'hostOwner\']=_observe_host',text);self.assertIn("'.qemu-started.json'",text)
        self.assertNotIn('domain.createWithFlags(',text)

        # Losing a terminal receipt cannot be interpreted as successful old
        # completion. Observe the actual owner kernel lifetime first.
        actor=terminal['status']['owner'];end=time.monotonic()+3
        while jobs._birth(actor['pid'])==actor['birth']:
            self.assertLess(time.monotonic(),end);time.sleep(.01)
        (Path(namespace['root'])/op/'terminal.json').unlink()
        with self.assertRaises(ValueError):subject._observe_host(host.operation_program(original),original.as_dict())
        # A separate operation with the same constants cannot be attached.
        with self.assertRaises(ValueError):subject.attach_host_original(collectors.admission(),original)


if __name__=='__main__':unittest.main()
