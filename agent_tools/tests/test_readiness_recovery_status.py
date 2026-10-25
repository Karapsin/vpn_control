"""Read original recovery journals without locks, writes or provider effects."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
import importlib.util
from importlib.machinery import SourceFileLoader
from types import SimpleNamespace
from unittest import mock
from uuid import uuid4

from agent_tools import readiness
from agent_tools import readiness_recovery_status as subject
from agent_tools import readiness_workflow as workflow
from agent_tools.tests.test_readiness import Provider, SocketAdapter
from agent_tools.tests.test_readiness_entrypoints import before_source


@unittest.skipUnless(os.name=='posix','private recovery journals')
class RecoveryStatusTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name).resolve();self.root.chmod(0o700)
        self.path=self.root/'journal';self.path.mkdir(mode=0o700)
        self.journal=readiness.RecoveryJournal(self.path)
        self.operation=str(uuid4())

    def intent(self,action='resume',version=2,key='original'):
        recovery=hashlib.sha256(key.encode()).hexdigest()
        value={'version':version,'recoveryId':recovery,'action':action,'target':'fixture','machine':'machine',
               'boot':'boot-a','account':'uid1000','session':'session-a'}
        if version==2:value['originalOperationId']=self.operation
        with self.journal.locked() as journal:
            journal.record(key,value)
        return value

    def dispatch(self,intent,*,unsubmitted=False,ended=False):
        with self.journal.locked() as journal:
            dispatch=journal.next_dispatch(intent)
            journal.consume_dispatch(dispatch)
            if unsubmitted:
                journal.record_unsubmitted(dispatch,readiness.RecoveryUnsubmitted(intent['recoveryId'],dispatch['attempt'],dispatch['dispatchDigest'],str(dispatch['attempt'])*64))
            if ended:
                journal.record_terminal(dispatch,readiness.RecoveryEnded(intent['recoveryId'],dispatch['attempt'],dispatch['dispatchDigest'],'9'*64))
        return dispatch

    def inspect(self,**kwargs):
        return subject.inspect(self.path,target='fixture',machine='machine',**kwargs)

    def files(self):
        return {p.name:(p.read_bytes(),p.stat().st_mode,p.stat().st_mtime_ns,p.stat().st_ctime_ns) for p in self.path.iterdir()}

    def test_missing_journal_stays_absent_without_creating_parent_or_lock(self):
        missing=self.root/'absent'/'journal'
        result=subject.inspect(missing,target='fixture',machine='machine')
        self.assertEqual('absent',result['state']);self.assertFalse(result['complete'])
        self.assertFalse(missing.parent.exists())

    def test_consumed_original_is_unknown_and_inspection_cannot_lock_or_mutate(self):
        intent=self.intent('login');self.dispatch(intent);before=self.files()
        with self.journal.locked(),mock.patch.object(readiness.RecoveryJournal,'reconcile',side_effect=AssertionError('no reconciliation')), \
             mock.patch('os.mkdir',side_effect=AssertionError('no writes')),mock.patch('socket.socket',side_effect=AssertionError('no transport')), \
             mock.patch.object(readiness.RecoveryJournal,'locked',side_effect=AssertionError('no locking')):
            result=self.inspect()
        self.assertEqual(before,self.files())
        self.assertEqual('outcome_unknown',result['recoveries'][0]['state'])
        self.assertEqual(1,result['pendingCount']);self.assertFalse(result['replayAllowed'])
        self.assertEqual(intent['recoveryId'],result['recoveries'][0]['recoveryId'])
        self.assertEqual(self.operation,result['recoveries'][0]['originalOperationId'])
        self.assertNotIn('account',repr(result));self.assertNotIn('session-a',repr(result));self.assertNotIn('boot-a',repr(result))

    def test_positive_no_launch_proofs_and_exhaustion_are_reported_without_retry(self):
        intent=self.intent('reconnect')
        self.assertEqual('prepared',self.inspect()['recoveries'][0]['state'])
        for attempt in range(1,4):
            self.dispatch(intent,unsubmitted=True)
            result=self.inspect()['recoveries'][0]
            self.assertEqual(attempt,result['consumedAttempts'])
            self.assertEqual(attempt,result['provenUnsubmittedAttempts'])
            self.assertEqual('attempts_exhausted' if attempt==3 else 'proven_unsubmitted',result['state'])

    def test_legacy_missing_ack_never_becomes_proven_unsubmitted(self):
        self.intent(version=1)
        result=self.inspect()['recoveries'][0]
        self.assertEqual('legacy_unknown',result['state']);self.assertIsNone(result['consumedAttempts'])
        self.assertIsNone(result['originalOperationId'])

    def test_observed_completion_keeps_failed_terminal_history_and_attempt_count(self):
        intent=self.intent('reconnect');self.dispatch(intent,ended=True)
        with self.journal.locked() as journal:
            journal._publish_named('completed-'+intent['recoveryId']+'.json',{'version':1,'recoveryId':intent['recoveryId'],'state':'observed'})
        result=self.inspect()['recoveries'][0]
        self.assertEqual('ended',result['state']);self.assertTrue(result['completionObserved'])
        self.assertTrue(result['terminalFailureObserved']);self.assertEqual(1,result['consumedAttempts'])

    def test_real_coordinator_recovery_is_visible_on_normal_vm_status_without_context_initialization(self):
        server=Provider(self.root/'provider.sock')
        thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True);thread.start()
        try:
            context=readiness.Context('fixture','machine-a',SocketAdapter(self.root/'provider.sock'),self.journal)
            server.observation=replace(server.observation,guest='paused')
            readiness.ensure_ready(context,readiness.Requirements(frozenset({'guest_agent'}),frozenset({'resume'})),self.operation)
            fixture=SimpleNamespace(adapter=context.adapter,journal_directory=self.path,required_readiness=frozenset({'guest_agent'}),
                                    context=mock.Mock(side_effect=AssertionError('status must not initialize context')))
            before=self.files();effects=list(server.effects);observations=server.observe_calls
            with mock.patch.object(workflow.fixtures,'registered_fixture',return_value=fixture):
                result=workflow.vm_workflow(self.root,'readiness-status',{'fixtureId':'owned','operationId':self.operation})
            self.assertEqual(before,self.files());self.assertEqual(effects,server.effects)
            self.assertEqual(observations+1,server.observe_calls)
            self.assertEqual('observed_complete',result['recoveryStatus']['recoveries'][0]['state'])
            self.assertEqual('resume',result['recoveryStatus']['recoveries'][0]['action'])
        finally:
            server.shutdown();server.server_close();thread.join(2)

    def test_normal_ssh_status_inspects_only_existing_internal_journal(self):
        path=self.root/'.rag_index/readiness'/hashlib.sha256(b'trusted-host').hexdigest()
        path.mkdir(mode=0o700,parents=True);path.parent.chmod(0o700);path.parent.parent.chmod(0o700)
        adapter=SimpleNamespace(root=self.root,machine='machine',observe=lambda *_: readiness.Observation('trusted-host','machine',transport='expired'))
        with mock.patch.object(workflow.ssh,'TransportAdapter',return_value=adapter), \
             mock.patch.object(workflow.ssh,'context',side_effect=AssertionError('status must not create journal')):
            result=workflow.ssh_workflow(self.root,'readiness-status','trusted-host',{'operationId':self.operation})
        self.assertEqual('observed',result['recoveryStatus']['state'])
        self.assertEqual([],list(path.iterdir()))

    def test_corrupt_digest_or_private_record_never_produces_complete_or_leaks(self):
        intent=self.intent();dispatch=self.dispatch(intent)
        path=self.path/('dispatch-'+intent['recoveryId']+'-1.json')
        dispatch['dispatchDigest']='f'*64;path.write_text(json.dumps(dispatch))
        source=before_source('readiness_recovery_status.before-dispatch-digest.source')
        spec=importlib.util.spec_from_loader('agent_tools._before_recovery_summary',SourceFileLoader('agent_tools._before_recovery_summary',str(source)))
        previous=importlib.util.module_from_spec(spec);spec.loader.exec_module(previous)
        self.assertTrue(previous.inspect(self.path,target='fixture',machine='machine')['complete'])
        result=self.inspect();self.assertFalse(result['complete'])
        self.assertEqual([],result['recoveries'])
        path.write_text('{"private":"INERT-PRIVATE-DO-NOT-ECHO"}')
        result=self.inspect();self.assertFalse(result['complete']);self.assertNotIn('INERT-PRIVATE',repr(result))

    def test_reboot_budget_and_requested_intent_are_exactly_correlated(self):
        intent=self.intent('reboot')
        with self.journal.locked() as journal:
            budget={'version':2,'operationId':self.operation,'target':'fixture','machine':'machine','recoveryId':intent['recoveryId']}
            journal.record('reboot-budget:'+self.operation,budget)
            journal.record('requested-reboot:'+self.operation,{**budget,'version':1,'boot':'boot-a'})
        self.assertTrue(self.inspect()['complete'])
        path=self.path/(hashlib.sha256(('reboot-budget:'+self.operation).encode()).hexdigest()+'.json')
        budget['operationId']=str(uuid4());path.write_text(json.dumps(budget))
        self.assertFalse(self.inspect()['complete'])

    def test_noninteger_dispatch_version_recomputed_digest_is_causal_red_then_rejected(self):
        intent=self.intent();dispatch=self.dispatch(intent)
        dispatch['version']=2.0
        body={key:value for key,value in dispatch.items() if key!='dispatchDigest'}
        dispatch['dispatchDigest']=hashlib.sha256(json.dumps(body,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        path=self.path/('dispatch-'+intent['recoveryId']+'-1.json');path.write_text(json.dumps(dispatch))
        source=before_source('readiness_recovery_status.before-dispatch-version.source')
        spec=importlib.util.spec_from_loader('agent_tools._before_dispatch_version',SourceFileLoader('agent_tools._before_dispatch_version',str(source)))
        previous=importlib.util.module_from_spec(spec);spec.loader.exec_module(previous)
        self.assertTrue(previous.inspect(self.path,target='fixture',machine='machine')['complete'])
        with self.journal.locked() as journal:
            with self.assertRaisesRegex(ValueError,'dispatch_identity_mismatch'):
                journal.next_dispatch(intent)
        self.assertFalse(self.inspect()['complete'])

    def test_real_joining_reboot_caller_shares_original_recovery_and_is_inspectable(self):
        server=Provider(self.root/'joined-provider.sock')
        server.dont_apply.add('reboot')
        thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True);thread.start()
        try:
            operations=[self.operation,str(uuid4())]
            for operation in operations:
                context=readiness.Context('fixture','machine-a',SocketAdapter(self.root/'joined-provider.sock'),self.journal,
                                          deadline=time.monotonic()+.3)
                with self.assertRaises(readiness.ReadinessBlocked):
                    readiness.idle_reboot(context,operation)
            self.assertEqual(1,len(server.effects))
            with self.journal.locked() as journal:
                first=journal.lookup('requested-reboot:'+operations[0])
                joined=journal.lookup('requested-reboot:'+operations[1])
            self.assertEqual(first['recoveryId'],joined['recoveryId'])
            self.assertNotEqual(first['operationId'],joined['operationId'])
            source=before_source('readiness_recovery_status.before-shared-reboot.source')
            spec=importlib.util.spec_from_loader('agent_tools._before_shared_reboot_summary',SourceFileLoader('agent_tools._before_shared_reboot_summary',str(source)))
            previous=importlib.util.module_from_spec(spec);spec.loader.exec_module(previous)
            self.assertFalse(previous.inspect(self.path,target='fixture',machine='machine-a')['complete'])
            result=subject.inspect(self.path,target='fixture',machine='machine-a')
            self.assertTrue(result['complete'],result)
            self.assertEqual(operations[0],result['recoveries'][0]['originalOperationId'])
            self.assertEqual('outcome_unknown',result['recoveries'][0]['state'])
        finally:
            server.shutdown();server.server_close();thread.join(2)

    def test_foreign_history_and_orphan_outcomes_are_not_complete(self):
        intent=self.intent()
        result=subject.inspect(self.path,target='other-target',machine='machine')
        self.assertFalse(result['complete']);self.assertEqual([],result['recoveries'])
        (self.path/(intent['recoveryId']+'.json')).unlink()
        orphan=self.path/('completed-'+intent['recoveryId']+'.json')
        orphan.write_text(json.dumps({'version':1,'recoveryId':intent['recoveryId'],'state':'observed'}));orphan.chmod(0o600)
        self.assertFalse(self.inspect()['complete'])

    def test_symlink_hardlink_overflow_and_duplicate_json_are_finite(self):
        intent=self.intent();name=intent['recoveryId']+'.json';path=self.path/name;body=path.read_bytes()
        other=self.root/'other';path.rename(other);path.symlink_to(other)
        self.assertFalse(self.inspect()['complete']);path.unlink();path.write_bytes(body);path.chmod(0o600)
        link=self.root/'hardlink';os.link(path,link)
        self.assertFalse(self.inspect()['complete']);link.unlink()
        path.write_text('{"version":2,"version":2}')
        self.assertFalse(self.inspect()['complete']);path.write_bytes(body)
        with mock.patch.object(subject,'MAX_RECORD_BYTES',8):self.assertFalse(self.inspect()['complete'])
        with mock.patch.object(subject,'MAX_FILES',0):self.assertFalse(self.inspect()['complete'])
        with mock.patch.object(subject,'MAX_RECOVERIES',0):self.assertFalse(self.inspect()['complete'])

    def test_concurrent_publication_is_not_a_complete_snapshot(self):
        self.intent();original=subject._Reader.finish
        def raced(reader,names):
            (self.path/('b'*64+'.json')).write_text('{}')
            return original(reader,names)
        with mock.patch.object(subject._Reader,'finish',raced):self.assertFalse(self.inspect()['complete'])


if __name__=='__main__':unittest.main()
