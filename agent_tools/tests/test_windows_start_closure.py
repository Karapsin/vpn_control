"""Two real detached owners and exact clean receipts close historical starts."""
import copy
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
from unittest import mock
from uuid import UUID,uuid5,uuid4

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_windows_host_jobs as host
from agent_tools import readiness_windows_lifecycle as lifecycle
from agent_tools import readiness_windows_start_closure as subject
from agent_tools.tests import test_windows_host_jobs as owner_tests
from agent_tools.tests.test_readiness_windows_guest import SID


FIXTURE=Path(__file__).parent/'fixtures/windows_start_verified_closure'


def causal_fence():
    if os.environ.get('VPN_CONTROL_START_CLOSURE_BEFORE')!='1':return lifecycle._prior_start_fence
    raw=(FIXTURE/'before.source').read_bytes();assert hashlib.sha256(raw).hexdigest()==json.loads((FIXTURE/'provenance.json').read_text())['sourceSha256']
    module=ModuleType('agent_tools._windows_start_closure_before');module.__package__='agent_tools';module.__file__=str(FIXTURE/'before.source')
    sys.modules[module.__name__]=module;exec(compile(raw,module.__file__,'exec'),module.__dict__);return module._prior_start_fence


@unittest.skipIf(os.name!='posix'or os.geteuid()==0,'ordinary HOST process proof required')
class StartClosureTests(unittest.TestCase):
    def setUp(self):
        self.fixture=owner_tests.WindowsHostOwnerTests('runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root;self.vm=self.fixture.vm;self.bound=self.fixture.bound
        # Actual harmless kernel children are reaped before clean-stop facts.
        actors=[]
        for _ in range(2):
            child=subprocess.Popen([sys.executable,'-I','-B','-c','pass']);pid=child.pid;child.wait(timeout=3);actors.append(pid)
        body=self.fixture.lineage.as_dict()
        for key,pid in zip(('qemu','tpm'),actors):body[key]['pid']=pid
        self.lineage=lifecycle.validate_lineage(self.bound,body)
        for name in ('disk.qcow2','uefi-vars.fd'):
            path=self.vm/name;path.write_text('{}'if name=='intent.json'else'controlled private mutable bytes');path.chmod(0o600)
        (self.vm/'tpm').mkdir(mode=0o700);(self.vm/'tpm/state').write_bytes(b'controlled state');(self.vm/'tpm/state').chmod(0o600)
        artifacts=lifecycle._stopped_artifacts(self.bound['spec']);body['mutable']=artifacts['mutable'];body['tpmState']={k:artifacts['tpmState'][k]for k in ('path','identity')}
        self.lineage=lifecycle.validate_lineage(self.bound,body)
        self.start_rid='5'*64;self.stop_rid='6'*64
        self.start_op=str(uuid5(UUID(body['machine']),self.start_rid));self.stop_op=str(uuid5(UUID(body['machine']),self.stop_rid))
        self.clean={'schemaVersion':1,'kind':'windows-clean-poweroff-v1','operationId':self.stop_op,'recoveryId':self.stop_rid,
            'machine':body['machine'],'hostBoot':body['hostBoot'],'actor':{k:body['qemu'][k]for k in ('pid','startTicks')},
            'tpm':{k:body['tpm'][k]for k in ('pid','startTicks')},'bootBefore':'2026-10-20T00:00:00.000Z','account':SID,
            'lineageSha256':lifecycle._lineage_sha(self.lineage),'artifacts':lifecycle._stopped_artifacts(self.bound['spec']),
            'cleanPoweroff':True,'guestJobsAbsent':True,'cleanCause':{'kind':'qmp-shutdown-event','guest':True,'reason':'guest-shutdown'},'replayAllowed':False}
        self.stopped=lifecycle.validate_clean_stopped(self.bound,self.lineage,self.clean)
        prior_clean=copy.deepcopy(self.clean);prior_clean['operationId']=str(uuid4())
        start_values={'SPEC':self.bound['spec'],'OPERATION':self.start_op,'LIFECYCLE_RID':self.start_rid,
            'LIFECYCLE_LINEAGE':body,'LIFECYCLE_CLEAN':prior_clean}
        start_source=('\n'.join(key+'='+repr(value)for key,value in start_values.items())+'\nprint("controlled start owner complete")\n').encode()
        self.start=host.retain(self.root,self.fixture.namespace,self.start_op,self.start_rid,jobs.Program('windows-persisted-raw-start',start_source))
        stop_source=('import json\nfrom pathlib import Path\nclean='+repr(self.clean)+'\np=Path('+repr(str(self.vm/('readiness-recovery-'+self.stop_rid+'.result.json')))+')\np.write_text(json.dumps(clean));p.chmod(0o600)\nprint(json.dumps(clean))\n').encode()
        self.stop=host.retain(self.root,self.fixture.namespace,self.stop_op,self.stop_rid,jobs.Program('windows-existing-graceful-powerdown',stop_source))
        self.fixture.observe(self.start,submit=True);self.fixture.terminal(self.start)
        for suffix,value in [('.intent.json',{'schemaVersion':1,'kind':'windows-existing-start-v1','operationId':self.start_op,'recoveryId':self.start_rid,
            'machine':body['machine'],'hostBoot':body['hostBoot'],'lineageSha256':lifecycle._lineage_sha(self.lineage),'cleanPoweroffOperationId':prior_clean['operationId'],'replayAllowed':False}),
            ('.qemu-intent.json',{'operationId':self.start_op,'actor':body['qemu'],'replayAllowed':False}),('.tpm-started.json',body['tpm'])]:
            path=self.vm/('existing-start-'+self.start_op+suffix);path.write_text(json.dumps(value));path.chmod(0o600)
        self.fixture.observe(self.stop,submit=True);self.fixture.terminal(self.stop)
        self.closure=subject.original(self.bound,self.lineage,self.stopped,self.start,self.stop)

    def run_closure(self,*,publish=True):return self.fixture.run_source(subject.program(self.closure,publish=publish))

    def test_two_actual_terminal_owners_publish_once_then_real_fence_accepts_and_stays_pure(self):
        with self.assertRaisesRegex(ValueError,'prior_start_unreconciled'):lifecycle._prior_start_fence(self.vm)
        receipt=self.run_closure();self.assertEqual(receipt['startOperationId'],self.start_op)
        path=self.vm/('existing-start-'+self.start_op+'.closed.json');before=(path.stat().st_ino,path.stat().st_mtime_ns,path.read_bytes())
        self.assertEqual(self.run_closure(publish=False),receipt)
        operation,name,source=subject.definitions(self.closure);namespace={};exec(compile(source,'controlled fixed closure getter','exec'),namespace)
        fence=causal_fence()
        with mock.patch.dict(fence.__globals__,{'LIFECYCLE_PRIOR_CHECKS':{operation:namespace[name]}}):fence(self.vm)
        self.assertEqual(before,(path.stat().st_ino,path.stat().st_mtime_ns,path.read_bytes()))
        # Later legitimate state-file rotation cannot rewrite old closure. The
        # NEW start's own fresh CleanStopped still checks its current artifacts.
        (self.vm/'tpm/state').unlink();(self.vm/'tpm/state').write_bytes(b'new controlled generation');(self.vm/'tpm/state').chmod(0o600)
        self.assertEqual(self.run_closure(publish=False),receipt)

    def test_bare_closed_flag_foreign_clean_changed_native_actor_and_unknown_original_never_close(self):
        with self.assertRaises(TypeError):subject.OriginalStartClosure()
        qemu=self.vm/('existing-start-'+self.start_op+'.qemu-intent.json');before=qemu.read_bytes();value=json.loads(before);value['actor']['pid']+=1;qemu.write_text(json.dumps(value))
        result=subprocess.run([sys.executable,'-I','-B','-c','import sys;exec(sys.stdin.buffer.read())'],input=subject.program(self.closure),capture_output=True,timeout=5)
        self.assertNotEqual(result.returncode,0);self.assertFalse((self.vm/('existing-start-'+self.start_op+'.closed.json')).exists());qemu.write_bytes(before)
        # Remove only this controlled completed job's receipt. The consumed
        # original remains uncertain and is never inferred terminal from PID.
        terminal=Path(self.fixture.namespace['root'])/self.start_op/'terminal.json';terminal.unlink()
        result=subprocess.run([sys.executable,'-I','-B','-c','import sys;exec(sys.stdin.buffer.read())'],input=subject.program(self.closure),capture_output=True,timeout=5)
        self.assertNotEqual(result.returncode,0)
        path=self.vm/('existing-start-'+self.start_op+'.closed.json');path.write_text('{"closed":true}');path.chmod(0o600)
        operation,name,source=subject.definitions(self.closure);namespace={};exec(compile(source,'controlled closure getter','exec'),namespace)
        with mock.patch.dict(lifecycle._prior_start_fence.__globals__,{'LIFECYCLE_PRIOR_CHECKS':{operation:namespace[name]}}),self.assertRaises(Exception):lifecycle._prior_start_fence(self.vm)

    def test_foreign_local_original_and_uncollected_clean_stdout_cannot_authorize(self):
        other=copy.deepcopy(self.clean);other['recoveryId']='7'*64
        with self.assertRaises(ValueError):subject.original(self.bound,self.lineage,lifecycle.CleanStopped(lifecycle._freeze(other)),self.start,self.stop)
        path=self.vm/('readiness-recovery-'+self.stop_rid+'.result.json');path.write_text('{}')
        result=subprocess.run([sys.executable,'-I','-B','-c','import sys;exec(sys.stdin.buffer.read())'],input=subject.program(self.closure),capture_output=True,timeout=5)
        self.assertNotEqual(result.returncode,0)


if __name__=='__main__':unittest.main()
