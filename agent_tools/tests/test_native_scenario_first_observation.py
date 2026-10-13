"""Causal local controls for the real durable executor; no native transport."""
import copy
import json
import hashlib
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch
from agent_tools import native_scenario_execution as execution

class Driver:
    def __init__(self):
        self.submits = 0
        self.collects = 0
        self.exit_code = 0
        self.identity = execution.JobIdentity('owned-job', 101, 202, '/owned/receipt.json')
        self.answer = {'state': 'collected', 'scenarioId': 'linux-scheduled-refresh', 'correlationId': 'run-17',
                       'result': 'passed', 'exitCode': 0, 'mode': 'refresh-find-best', 'preflightReady': True,
                       'secondaryTotalMs': 121, 'privateActualPayload': {'actual': 'SECRET-GUEST-DATA'},
                       'traffic': {'oldPortContinuity': True, 'portMigrated': False, 'postTransitionTraffic': True},
                       'cleanup': {'state': 'complete', 'ownerStopped': True, 'workspaceRemoved': True,
                                   'protectedPreserved': True}}
        self.actual_receipt = {'schema':'vpn-control.linux-scheduled-refresh.receipt',
                               'scenarioId':'linux-scheduled-refresh','correlationId':'run-17','result':'passed',
                               'actualError':{'stderr':'SECRET-GUEST-DATA'}}
        self.bind_raw()
        self.entered = None
        self.release = None
    def bind_raw(self):
        raw=json.dumps(self.actual_receipt)
        self.answer.update(actualReceiptRaw=raw,actualReceiptSha256=hashlib.sha256(raw.encode()).hexdigest())
    def submit(self, plan):
        self.submits += 1
        return self.identity
    def discover(self, plan):
        return self.identity
    def observe(self, plan, identity):
        receipt = {**plan.as_dict(), 'jobId': identity.job_id, 'pid': identity.pid,
                   'startTicks': identity.start_ticks, 'exitCode': self.exit_code}
        return execution.DriverObservation(execution.ObservationStatus.TERMINAL, 'actual_terminal', identity, receipt)
    def collect(self, plan, identity):
        self.collects += 1
        if self.entered is not None:
            self.entered.set()
            if not self.release.wait(5):
                raise TimeoutError()
        if isinstance(self.answer, BaseException):
            raise self.answer
        return copy.deepcopy(self.answer)

@unittest.skipUnless(os.name == 'posix', 'Private journal requires POSIX')
class FirstObservationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.driver = Driver()
        self.control = execution.ScenarioExecutor(self.root / 'journal', self.driver)
        self.request = {'scenarioId': 'linux-scheduled-refresh', 'host': 'owned', 'environment': 'disposable',
                        'bundleHash': 'a'*64, 'artifactIds': {'bundleManifest': 'sha256-'+'a'*64,
                        'scenarioInput': 'sha256-'+'b'*64}, 'correlationId': 'run-17'}
        self.control.start(self.request)
    def journal(self):
        return json.loads((self.root / 'journal/run-17.json').read_text())
    def test_first_terminal_observation_collects_full_private_payload_before_safe_projection(self):
        original = getattr(execution.ScenarioExecutor, '_project_collection', None)
        def project(value):
            self.assertEqual(self.driver.answer, json.loads(self.journal()['collection']['rawJson']))
            return original(value)
        if original:
            with patch.object(execution.ScenarioExecutor, '_project_collection', staticmethod(project)):
                result = self.control.status('run-17')
        else:
            result = self.control.status('run-17')
        self.assertEqual(1, self.driver.collects)
        self.assertEqual('terminal', result['state'])
        self.assertEqual('complete', result['collectionState'])
        self.assertEqual(self.driver.answer, json.loads(self.journal()['collection']['rawJson']))
        self.assertNotIn('SECRET-GUEST-DATA', json.dumps(result))
        self.assertFalse(result['scenarioEvidence']['traffic']['portMigrated'])
        self.assertEqual(0o600, (self.root/'journal/run-17.json').stat().st_mode & 0o777)
        second = self.control.collect('run-17')
        self.assertEqual(1, self.driver.collects)
        self.assertEqual(result['scenarioEvidence'], second['scenarioEvidence'])
    def test_unknown_collector_preserves_original_failed_fact_without_terminal_promotion(self):
        self.driver.exit_code = 7
        self.driver.answer = {'state': 'unknown', 'correlationId': 'run-17', 'actualReason': 'unreadable'}
        result = self.control.status('run-17')
        self.assertEqual('unknown', result['state'])
        self.assertEqual('terminal', result['executionState'])
        self.assertEqual(7, result['executionExitCode'])
        self.assertEqual(7, self.journal()['receipt']['exitCode'])
        self.assertEqual(self.driver.answer, json.loads(self.journal()['collection']['rawJson']))
        self.assertNotIn('scenarioEvidence', result)
    def test_output_overflow_and_timeout_keep_collection_unknown(self):
        for answer in ({**self.driver.answer, 'private': 'x'*8192}, TimeoutError('private error')):
            with self.subTest(answer=type(answer).__name__):
                self.driver.answer = answer
                result = self.control.status('run-17')
                self.assertEqual('unknown', result['state'])
                self.assertEqual('unknown', result['collectionState'])
                self.assertIsNone(self.journal()['collection']['rawJson'])
                self.assertNotIn('private error', json.dumps(result))
        self.assertEqual(1, self.driver.submits)
    def test_wrong_correlation_is_retained_privately_and_never_published(self):
        self.driver.answer['correlationId'] = 'foreign-17'
        result = self.control.status('run-17')
        self.assertEqual('unknown', result['state'])
        self.assertNotIn('scenarioEvidence', result)
        self.assertEqual('foreign-17', json.loads(self.journal()['collection']['rawJson'])['correlationId'])
    def test_concurrent_status_reserves_one_collector_and_never_promotes_pending(self):
        self.driver.entered = threading.Event()
        self.driver.release = threading.Event()
        answers = []
        worker = threading.Thread(target=lambda: answers.append(self.control.status('run-17')))
        worker.start()
        try:
            self.assertTrue(self.driver.entered.wait(5))
            second = self.control.status('run-17')
            self.assertEqual('unknown', second['state'])
            self.assertEqual(1, self.driver.collects)
            self.assertEqual('collecting', self.journal()['collection']['state'])
        finally:
            self.driver.release.set()
            worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual('terminal', answers[0]['state'])
        self.assertEqual(1, self.driver.submits)
    def test_complete_failed_result_keeps_failed_terminal_exit_and_all_results(self):
        self.driver.exit_code = 3
        self.driver.answer.update(result='failed', exitCode=3)
        self.driver.actual_receipt['result']='failed'
        self.driver.bind_raw()
        result = self.control.status('run-17')
        self.assertEqual('terminal', result['state'])
        self.assertEqual(3, result['exitCode'])
        self.assertEqual('failed', result['scenarioEvidence']['result'])
    def test_readonly_reobservation_can_recover_without_resubmitting_mutation(self):
        self.driver.answer = TimeoutError()
        self.assertEqual('unknown', self.control.status('run-17')['state'])
        self.driver.answer = Driver().answer
        self.assertEqual('terminal', self.control.resume('run-17')['state'])
        self.assertEqual(1, self.driver.submits)

    def test_summary_exit_code_substitution_cannot_promote_terminal(self):
        self.driver.answer['exitCode'] = True
        self.assertEqual('unknown', self.control.status('run-17')['state'])
        self.driver.answer['exitCode'] = 4
        self.assertEqual('unknown', self.control.status('run-17')['state'])
        self.assertEqual(0, self.journal()['receipt']['exitCode'])

    def test_missing_actual_receipt_or_changed_raw_digest_never_promotes_old_summary(self):
        del self.driver.answer['actualReceiptRaw']
        self.assertEqual('unknown',self.control.status('run-17')['state'])
        self.driver.bind_raw()
        self.driver.answer['actualReceiptRaw']+=' '
        self.assertEqual('unknown',self.control.status('run-17')['state'])

    def test_keyboard_interrupt_does_not_permanently_author_collecting_state_or_replay_start(self):
        self.driver.answer=KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):self.control.status('run-17')
        self.assertEqual('unknown',self.journal()['collection']['state'])
        self.driver.answer=Driver().answer
        self.assertEqual('terminal',self.control.resume('run-17')['state'])
        self.assertEqual(1,self.driver.submits)
        self.assertEqual(2,self.driver.collects)

    def test_abrupt_observer_process_exit_releases_local_read_lease_and_same_original_can_resume(self):
        source=Path(execution.__file__).resolve().parents[1]
        code="""import os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from agent_tools.tests.test_native_scenario_first_observation import Driver
from agent_tools import native_scenario_execution as execution
driver=Driver()
def interrupted(plan,identity):
 Path(sys.argv[2],'read-entered').write_text(plan.correlation_id)
 os._exit(23)
driver.collect=interrupted
execution.ScenarioExecutor(Path(sys.argv[2])/'journal',driver).status('run-17')
"""
        child=subprocess.run([sys.executable,'-I','-B','-c',code,str(source),str(self.root)],capture_output=True,timeout=5)
        self.assertEqual(23,child.returncode,child.stderr)
        self.assertEqual('collecting',self.journal()['collection']['state'])
        original=self.journal()['receipt']
        self.assertEqual('terminal',self.control.resume('run-17')['state'])
        self.assertEqual(original,self.journal()['receipt'])
        self.assertEqual(1,self.driver.submits)
        self.assertEqual(1,self.driver.collects)

    def test_collection_lease_symlink_is_refused_without_read_or_mutation_replay(self):
        lease=self.root/'journal/run-17.collection.lock';lease.symlink_to(self.root/'foreign')
        with self.assertRaises((OSError,execution.ScenarioExecutionError)):
            self.control.status('run-17')
        self.assertEqual(0,self.driver.collects)
        self.assertEqual(1,self.driver.submits)

    def test_replacing_named_lease_while_original_collector_live_cannot_split_exclusivity(self):
        self.driver.entered=threading.Event();self.driver.release=threading.Event();errors=[]
        def observe():
            try:self.control.status('run-17')
            except execution.ScenarioExecutionError as error:errors.append(str(error))
        first=threading.Thread(target=observe);first.start()
        try:
            self.assertTrue(self.driver.entered.wait(3))
            lease=self.root/'journal/run-17.collection.lock'
            lease.rename(lease.with_suffix('.retained'));lease.touch(mode=0o600)
            with self.assertRaisesRegex(execution.ScenarioExecutionError,'lease identity changed'):
                self.control.status('run-17')
            self.assertEqual(1,self.driver.collects)
            self.assertEqual(1,self.driver.submits)
        finally:self.driver.release.set();first.join(3)
        self.assertFalse(first.is_alive());self.assertTrue(errors)
        self.assertNotEqual('complete',self.journal()['collection']['state'])

    def test_cached_collection_state_reason_payload_combinations_are_exact(self):
        self.control.status('run-17');record=self.journal()
        for state,reason,raw in (('complete','collector_pending',record['collection']['rawJson']),
                                 ('collecting','collected',None),('collecting','collector_pending','{}'),
                                 ('unknown','collector_pending',None),('unknown','collected',None)):
            invalid={**record,'collection':{'state':state,'reason':reason,'rawJson':raw}}
            with self.subTest(state=state,reason=reason),self.assertRaises(execution.ScenarioExecutionError):
                self.control._validate_record(invalid,'run-17')
        self.assertEqual(1,self.driver.collects);self.assertEqual(1,self.driver.submits)
