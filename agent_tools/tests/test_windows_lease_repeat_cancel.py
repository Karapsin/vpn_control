"""A repeated lease cancel answers what the original lease is now.

The first cancel's host receipt is retained once, so a repeat through a fresh client
read that receipt back. Natively (2026-11-06, operation 74e04437) the repeat answered
`active` and `running` for a lease already cancelled, restored and terminal. No second
cancel reached the guest, but the answer was stale.
"""
import hashlib,json,os,sys,tempfile,time,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import readiness_lease_workflow as workflow

FIXTURE=Path(__file__).parent/'fixtures/windows_native_tools_20261106'
FILENAME='lease_workflow.before.source'
OPERATION='74e04437-8835-46dc-8fee-9c49bd28da9c'


def before():
    raw=(FIXTURE/FILENAME).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=json.loads((FIXTURE/'provenance.json').read_bytes())['sha256'][FILENAME]:raise AssertionError('beforeimage changed')
    module=types.ModuleType('agent_tools._lease_cancel_before_'+uuid.uuid4().hex);module.__package__='agent_tools';module.__file__=str(FIXTURE/FILENAME)
    sys.modules[module.__name__]=module;exec(compile(raw,module.__file__,'exec'),module.__dict__);return module


def reply(state,job,**extra):
    return {'operationId':OPERATION,'replayAllowed':False,'state':state,'jobState':job,'nextAction':'observe_original',**extra}


TERMINAL=reply('cancelled','terminal',restored=True,nextAction='none',reason='original_lease_cancelled')
RUNNING=reply('active','running',reason='original_owner_running')


class Executor:
    provider='raw-qemu-windows'
    def __init__(self,observed):self.observed=observed;self.calls=[]
    def observe(self,operation,*,deadline=None):self.calls.append('observe');return dict(self.observed)
    def cancel(self,operation,*,deadline=None):self.calls.append('cancel');return dict(RUNNING)


@unittest.skipUnless(os.name=='posix','POSIX private-file custody')
class RepeatCancelTests(unittest.TestCase):
    def run_cancel(self,module,observed,*,repeat=False):
        executor=Executor(observed)
        value={'schemaVersion':2,'fixtureId':'fixture','operationId':OPERATION,'provider':'raw-qemu-windows','executor':{'provider':'raw-qemu-windows'}}
        with tempfile.TemporaryDirectory() as directory,mock.patch.object(module.fixtures,'lease_executor_from_snapshot',return_value=executor):
            state=Path(directory);state.chmod(0o700)
            if repeat:module._external_original(state,state,'cancel',value,{},deadline=time.monotonic()+30);executor.calls.clear()
            return module._external_original(state,state,'cancel',value,{},deadline=time.monotonic()+30),executor
    def test_before_repeat_reads_back_the_first_cancel_after_the_lease_ended(self):
        result,executor=self.run_cancel(before(),TERMINAL)
        self.assertEqual(('active','running'),(result['state'],result['jobState']));self.assertEqual(['observe','cancel'],executor.calls)
    def test_current_repeat_after_the_end_answers_the_fresh_observation_and_sends_nothing(self):
        result,executor=self.run_cancel(workflow,TERMINAL)
        self.assertEqual(('cancelled','terminal',True),(result['state'],result['jobState'],result['restored']));self.assertEqual(['observe'],executor.calls)
    def test_a_repeat_before_the_end_answers_the_fresh_observation_and_still_reaches_the_original(self):
        lost=reply('unknown','unknown',reason='original_lease_evidence_unavailable')
        result,executor=self.run_cancel(before(),lost,repeat=True);self.assertEqual('active',result['state'])
        result,executor=self.run_cancel(workflow,lost,repeat=True)
        self.assertEqual(('unknown','unknown'),(result['state'],result['jobState']));self.assertEqual(['observe','cancel'],executor.calls)
    def test_current_cancel_of_a_running_lease_still_reaches_the_original(self):
        result,executor=self.run_cancel(workflow,RUNNING)
        self.assertEqual(['observe','cancel'],executor.calls);self.assertEqual('observe_original',result['nextAction'])


if __name__=='__main__':unittest.main()
