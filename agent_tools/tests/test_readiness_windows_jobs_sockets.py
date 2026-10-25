"""Complete fixed Windows job callers over physical Linux QMP/QGA sockets.

Only the native Windows boundary is projected. Actual C# execution is qualified
separately on owned Windows fixtures; this harness never creates or controls VMs.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock
from uuid import uuid4

from agent_tools import readiness_windows_jobs as jobs
from agent_tools.tests import test_readiness_windows_sockets as sockets

ENDPOINT = Path(__file__).parent / 'fixtures/windows_jobs_sockets/endpoint.py'


@unittest.skipUnless(sys.platform == 'linux', 'real Linux kernel actor and Unix socket custody')
class CompleteWindowsJobSocketTests(unittest.TestCase):
    def setUp(self):
        patch = mock.patch.object(sockets, 'ENDPOINT', ENDPOINT)
        patch.start(); self.addCleanup(patch.stop)
        sockets.CompleteWindowsSocketTests.setUp(self)
        before = sockets.CompleteWindowsSocketTests.run_packet(self)
        self.expected = {k: before[k] for k in ('actor', 'hostBoot', 'controlConnection')}
        self.operation = str(uuid4())
        self.job_binding = jobs.WindowsJobBinding(self.machine, before['sessionFacts']['boot'],
            '12345678:0003000000000847:01dd6077063bd7e7', '12345678:0003000000000848:01dd6077063bd7e8')
        config = jobs._config(self.job_binding, self.operation, 3, .01)
        owner = (jobs._prefix() + '[NativeJob]::Own(' + jobs._literal(config) + ')\n').encode()
        self.observed = {'schemaVersion':1,'operationId':self.operation,'machine':self.machine,
            'boot':self.job_binding.boot,'rootGeneration':self.job_binding.root_generation,
            'admissionGeneration':self.job_binding.admission_generation,'state':'running','reason':'original_owner_running',
            'replayAllowed':False,'admissionNonce':str(uuid4()),'programSha256':hashlib.sha256(owner).hexdigest(),
            'owner':{'pid':4321,'birth':'134369629130736090','accountSid':'S-1-5-18','sessionId':0}}
        value=json.loads((self.root/'fixture.json').read_bytes());value['jobResult']=self.observed
        (self.root/'fixture.json').write_text(json.dumps(value))
        # The endpoint's fixture was loaded at startup; the finite projection
        # reloads only this public test-owned job receipt for each execution.

    def run_job(self, mode, *, expected=None):
        source = jobs.remote_program(self.binding, mode, str(uuid4()), expected=self.expected if expected is None else expected,
            job_binding=self.job_binding, job_operation=self.operation, count=3, interval_seconds=.01)
        path=self.root/(str(uuid4())+'.py');path.write_bytes(source);path.chmod(0o600)
        result=subprocess.run([sys.executable,'-I','-B',str(path)],stdin=subprocess.DEVNULL,capture_output=True,timeout=30)
        self.assertEqual(0,result.returncode,result.stderr.decode('utf8','replace'))
        return json.loads(result.stdout)

    def test_fixed_job_status_retains_actual_controller_frame_and_same_guest_owner(self):
        value=self.run_job('job-status')
        self.assertEqual('observed',value['state'])
        observed=jobs.validate_observation(value['job'],self.job_binding,self.operation,count=3,interval_seconds=.01)
        self.assertEqual(self.observed['owner'],observed['identity']['owner'])
        self.assertEqual({'intent','ack','terminal'},set(value['jobController']))
        self.assertTrue(value['jobController']['terminal']['exited'])
        self.assertEqual(0,json.loads((self.root/'counters.json').read_bytes())['jobStartCount'])

    def test_original_host_mismatch_refuses_before_any_job_control(self):
        before=json.loads((self.root/'counters.json').read_bytes())['execCount']
        value=self.run_job('job-start',expected={**self.expected,'controlConnection':'different'})
        self.assertEqual('instance_original_job_host_changed',value['reason'])
        self.assertEqual(before,json.loads((self.root/'counters.json').read_bytes())['execCount'])

    def test_real_socket_lost_start_ack_observes_original_without_repeating_start(self):
        (self.root/'drop-guest-ack-once').write_text('owned socket disconnect after control admission')
        value=self.run_job('job-start');self.assertEqual('blocked',value['state'])
        self.assertEqual(1,json.loads((self.root/'counters.json').read_bytes())['jobStartCount'])
        observed=self.run_job('job-status')
        self.assertEqual('observed',observed['state']);self.assertEqual(self.operation,observed['job']['operationId'])
        self.assertEqual(self.observed['owner'],observed['job']['owner'])
        self.assertEqual(1,json.loads((self.root/'counters.json').read_bytes())['jobStartCount'])


if __name__=='__main__':unittest.main()
