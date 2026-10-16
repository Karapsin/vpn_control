"""Original late-ready master, real inert transport and local publication races."""
import importlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import time
from unittest import mock

from agent_tools import ssh_gateway_tmux_d606_diagnostic as diagnostic
from agent_tools import ssh_gateway_tmux_master as owner, ssh_gateway_tmux_master_ssh as adapter
from agent_tools import ssh_connection_recovery as recovery, ssh_recovery_adoption as adoption
from agent_tools import ssh_expired_recovery_retirement as retirement
from agent_tools.tests import test_ssh_gateway_tmux_d606_diagnostic as fixtures
from agent_tools.tests.test_ssh_expired_recovery_retirement import absence

try: reconciliation = importlib.import_module('agent_tools.ssh_gateway_tmux_ready_reconciliation')
except ModuleNotFoundError: reconciliation = None


class ReadyReconciliationTests(fixtures.DiagnosticCallerTests):
    def setUp(self):
        super().setUp()
        self.launcher.stop()
        def launch(argv, **kwargs):
            ssh=json.loads(argv[-1]);command=shlex.split(ssh[-1])
            self.assertIn(command[0], ('python3','/usr/bin/python3'))
            self.assertEqual('gateway.invalid',ssh[-2]);self.assertNotIn('inert-secret',' '.join(ssh))
            return self.original_popen([os.sys.executable,'-I','-B','-c',command[4]],**kwargs)
        patch=mock.patch.object(diagnostic.subprocess,'Popen',side_effect=launch);patch.start();self.addCleanup(patch.stop)
        config=adapter.transport.load_config(self.controller);self.target=config.hosts['archlinux']
        (self.controller/'.rag_index').mkdir(mode=0o700)
        old='a'*32;oldpath=str(recovery._recovery_socket_path(self.target,old)[1])
        recovery._create_intent(self.controller,'archlinux',self.target,old,oldpath)
        recovery._update_intent(self.controller,'archlinux',self.target,old,'ready',oldpath)
        pins=retirement.authority(self.controller,'archlinux',old)
        with mock.patch.object(retirement,'_observe',return_value=absence(self.target,old)):
            self.assertEqual('retired',retirement.retire(self.controller,'archlinux',old,**pins)['state'])
        self.retired=next((self.controller/recovery._INTENT_DIRECTORY).glob('.retired-*.intent.json'))
        self.retired_bytes=self.retired.read_bytes()
        self.ssh.write_text(self.ssh.read_text().replace("assert '-M' in args", "time.sleep(6.1)\nassert '-M' in args"))
        self.prepare_adapter();self.assertEqual('released',adapter.operate(self.controller,'release',self.request_inputs)['state'])
        deadline=time.monotonic()+8
        while not owner.master_path(self.request).exists() and time.monotonic()<deadline:time.sleep(.02)
        self.assertTrue(owner.master_path(self.request).is_socket())
        self.assertEqual('unknown',adapter.operate(self.controller,'status',self.request_inputs)['state'])
        result=diagnostic.observe(self.controller);self.assertEqual('observed',result['state'],result)
        self.job=self.controller/'.rag_index/ssh-gateway-tmux-master'/diagnostic.CORRELATION
        self.historical=self.job/result['capsule'];self.historical_digest=owner.sha((self.historical/'proof.private.json').read_bytes())
        if reconciliation is not None:
            self.publisher=self.controller/'reviewed-publisher.py';self.publisher.write_bytes(Path(reconciliation.__file__).read_bytes());self.publisher.chmod(0o600)
            for patch in (mock.patch.object(reconciliation,'HISTORICAL_CAPSULE',self.historical.name),
                          mock.patch.object(reconciliation,'HISTORICAL_PROOF_SHA256',self.historical_digest),
                          mock.patch.object(reconciliation,'HISTORICAL_PROOF_GENERATION',owner.generation((self.historical/'proof.private.json').stat())),
                          mock.patch.object(reconciliation,'DIAGNOSTIC_SOURCE_SHA256',owner.sha(self.caller.read_bytes())),
                          mock.patch.object(reconciliation,'__file__',str(self.publisher))):
                patch.start();self.addCleanup(patch.stop)
        self.canonical=recovery._intent_path(self.controller,'archlinux',self.target)

    def publish(self):
        if reconciliation is None:return adapter.operate(self.controller,'status',self.request_inputs)
        return reconciliation.publish(self.controller)

    def test_real_late_ready_reconciles_into_exact_existing_adoption_flow(self):
        result=self.publish();self.assertEqual('published',result['state'],result)
        expected=recovery._intent_value('archlinux',self.target,diagnostic.CORRELATION.replace('-',''),'ready',self.request['masterControlPath'])
        self.assertEqual(expected,json.loads(self.canonical.read_bytes()))
        self.assertEqual(self.retired_bytes,self.retired.read_bytes())
        remote_job=owner.paths(self.request)[2];self.assertFalse((remote_job/'ready.json').exists())
        self.assertEqual('unknown',adapter.operate(self.controller,'status',self.request_inputs)['state'])
        with mock.patch.object(recovery,'_socket_state',side_effect=['absent','ready']):
            adopted=adoption.adopt(self.controller,'archlinux')
        self.assertEqual('ready',adopted['state'],adopted)
        self.assertNotIn('inert-secret',json.dumps(result))

    def test_consumed_publication_observes_without_queries_or_replay(self):
        self.assertEqual('published',self.publish()['state'])
        with mock.patch.object(diagnostic,'observe',side_effect=AssertionError('no remote replay')):
            self.assertEqual('published',self.publish()['state'])

    def test_second_fresh_read_config_history_source_and_original_proof_races(self):
        actual=diagnostic.observe;calls=[]
        def read(root):
            result=actual(root);calls.append(1)
            if len(calls)==2:self.retired.write_bytes(self.retired.read_bytes())
            return result
        with mock.patch.object(diagnostic,'observe',side_effect=read):self.assertEqual('unknown',self.publish()['state'])
        self.assertFalse(self.canonical.exists())
        with mock.patch.object(diagnostic,'observe',side_effect=AssertionError('consumed')):
            self.assertEqual('unknown',self.publish()['state'])

    def test_same_byte_config_exchange_after_fresh_read_is_rejected(self):
        actual=diagnostic.observe
        def read(root):
            result=actual(root);self.config.write_bytes(self.config.read_bytes());return result
        with mock.patch.object(diagnostic,'observe',side_effect=read):self.assertEqual('unknown',self.publish()['state'])
        self.assertFalse(self.canonical.exists())

    def test_source_exchange_after_fresh_read_is_rejected(self):
        actual=diagnostic.observe
        def read(root):
            result=actual(root);self.publisher.write_bytes(self.publisher.read_bytes());return result
        with mock.patch.object(diagnostic,'observe',side_effect=read):self.assertEqual('unknown',self.publish()['state'])
        self.assertFalse(self.canonical.exists())

    def test_historical_proof_same_byte_generation_exchange_blocks_before_fence(self):
        path=self.historical/'proof.private.json';path.write_bytes(path.read_bytes())
        with mock.patch.object(diagnostic,'observe',side_effect=AssertionError('no query')):
            self.assertEqual('unknown',self.publish()['state'])
        self.assertFalse((self.job/'.reconciliation.pending.json').exists())

    def test_original_job_parent_exchange_after_fresh_read_is_rejected(self):
        actual=diagnostic.observe;old=self.job.with_name('original-old')
        def read(root):
            result=actual(root);self.job.rename(old);self.job.mkdir(mode=0o700);return result
        with mock.patch.object(diagnostic,'observe',side_effect=read):self.assertEqual('unknown',self.publish()['state'])
        self.assertFalse(self.canonical.exists())
        self.job.rmdir();old.rename(self.job)

    def test_foreign_canonical_symlink_is_never_overwritten(self):
        foreign=self.controller/'foreign';foreign.write_bytes(b'foreign');foreign.chmod(0o600)
        self.canonical.symlink_to(foreign)
        self.assertEqual('unknown',self.publish()['state'])
        self.assertEqual(b'foreign',foreign.read_bytes());self.assertTrue(self.canonical.is_symlink())

    def test_pending_last_body_read_rewrite_rejects_before_canonical_create(self):
        actual=os.pread;changed=[]
        def read(fd,*args):
            result=actual(fd,*args)
            pending=self.job/'.reconciliation.pending.json'
            completed=list(self.job.glob('query-diagnostic-*/proof.private.json'))
            if not changed and len(completed)>=3 and pending.exists() and os.fstat(fd).st_ino==pending.stat().st_ino:
                changed.append(1);pending.write_bytes(b'{}')
            return result
        with mock.patch.object(os,'pread',side_effect=read):self.assertEqual('unknown',self.publish()['state'])
        self.assertTrue(changed);self.assertFalse(self.canonical.exists())

    def test_post_create_guard_failure_preserves_unknown_without_replay(self):
        actual=owner.create
        def create(directory,name,*args,**kwargs):
            pin=actual(directory,name,*args,**kwargs)
            if name==self.canonical.name:self.config.write_bytes(self.config.read_bytes())
            return pin
        with mock.patch.object(owner,'create',side_effect=create):self.assertEqual('unknown',self.publish()['state'])
        self.assertTrue(self.canonical.exists());self.assertFalse((self.job/'.reconciliation.published.json').exists())
        with mock.patch.object(diagnostic,'observe',side_effect=AssertionError('no replay')):
            self.assertEqual('unknown',self.publish()['state'])


for _name in dir(ReadyReconciliationTests):
    if _name.startswith('test_') and _name not in ReadyReconciliationTests.__dict__:setattr(ReadyReconciliationTests,_name,None)
del _name
