"""Completed real publication/adoption followed by strictly local reads."""
import importlib
import json
import os
from pathlib import Path
import subprocess
from unittest import mock

from agent_tools import ssh_gateway_tmux_ready_reconciliation as publisher
from agent_tools import ssh_gateway_tmux_d606_diagnostic as diagnostic
from agent_tools import ssh_gateway_tmux_master as owner, ssh_gateway_tmux_master_ssh as adapter
from agent_tools import ssh_connection_recovery as recovery, ssh_recovery_adoption as adoption
from agent_tools.tests import test_ssh_gateway_tmux_ready_reconciliation as fixtures

try: status = importlib.import_module('agent_tools.ssh_gateway_tmux_reconciliation_status')
except ModuleNotFoundError: status = None


class ReconciliationStatusTests(fixtures.ReadyReconciliationTests):
    def setUp(self):
        super().setUp();self.assertEqual('published',self.publish()['state'])
        if status is not None:
            self.observer=self.controller/'reviewed-status.py';self.observer.write_bytes(Path(status.__file__).read_bytes());self.observer.chmod(0o600)
            for patch in (mock.patch.object(status,'PUBLISHER_SOURCE_SHA256',owner.sha(self.publisher.read_bytes())),
                          mock.patch.object(status,'__file__',str(self.observer))):
                patch.start();self.addCleanup(patch.stop)

    def adopt(self):
        with mock.patch.object(recovery,'_socket_state',side_effect=['absent','ready']):
            self.assertEqual('ready',adoption.adopt(self.controller,'archlinux')['state'])

    def observe(self):
        if status is None:return adapter.operate(self.controller,'status',self.request_inputs)
        return status.observe(self.controller)

    def test_completed_publication_then_adoption_is_local_and_zero_write(self):
        self.assertEqual('published',self.observe()['state']);self.adopt()
        before={str(p):owner.generation(p.stat()) for p in self.controller.rglob('*') if p.is_file()}
        actual=os.open
        def readonly(path,flags,*args,**kwargs):
            self.assertFalse(flags & (os.O_CREAT|os.O_TRUNC|os.O_WRONLY|os.O_RDWR));return actual(path,flags,*args,**kwargs)
        with mock.patch.object(publisher,'publish',side_effect=AssertionError('no publication')), \
             mock.patch.object(diagnostic,'observe',side_effect=AssertionError('no gateway query')), \
             mock.patch.object(subprocess,'Popen',side_effect=AssertionError('no child')), \
             mock.patch.object(os,'open',side_effect=readonly), \
             mock.patch.object(os,'mkdir',side_effect=AssertionError('no directory write')):
            result=self.observe()
        self.assertEqual({'state':'adopted','replayAllowed':False,'launchAllowed':False,'adoptionAllowed':False},result)
        self.assertEqual(before,{str(p):owner.generation(p.stat()) for p in self.controller.rglob('*') if p.is_file()})

    def test_absent_terminal_is_unknown_without_effect(self):
        (self.job/publisher.TERMINAL).unlink()
        with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('no child')):
            self.assertEqual('unknown',self.observe()['state'])
        self.assertFalse((self.job/publisher.TERMINAL).exists())

    def test_forged_adoption_terminal_rejects(self):
        self.adopt();parent=self.controller/adoption._RECEIPTS
        terminal=next(parent.glob('*.adopted.json'));value=json.loads(terminal.read_bytes());value['adopted']['sha256']='f'*64
        terminal.write_bytes(owner.canonical(value))
        self.assertEqual('unknown',self.observe()['state'])

    def test_last_body_read_config_and_pending_drift_rejects(self):
        self.adopt();actual=os.pread;changed=[]
        terminal=self.job/publisher.TERMINAL
        def read(fd,*args):
            result=actual(fd,*args)
            if not changed and os.fstat(fd).st_ino==terminal.stat().st_ino:
                changed.append(1);self.config.write_bytes(self.config.read_bytes())
            return result
        with mock.patch.object(os,'pread',side_effect=read):self.assertEqual('unknown',self.observe()['state'])
        self.assertTrue(changed)

    def test_same_byte_publisher_source_generation_rejects(self):
        self.publisher.write_bytes(self.publisher.read_bytes())
        self.assertEqual('unknown',self.observe()['state'])

    def test_canonical_symlink_never_reads_foreign_authority(self):
        raw=self.canonical.read_bytes();self.canonical.unlink();foreign=self.controller/'foreign-canonical';foreign.write_bytes(raw);foreign.chmod(0o600)
        self.canonical.symlink_to(foreign)
        self.assertEqual('unknown',self.observe()['state']);self.assertTrue(self.canonical.is_symlink())

    def test_last_body_read_status_source_and_retirement_drift_rejects(self):
        actual=os.pread;changed=[];terminal=self.job/publisher.TERMINAL
        def read(fd,*args):
            result=actual(fd,*args)
            if not changed and os.fstat(fd).st_ino==terminal.stat().st_ino:
                changed.append(1);self.observer.write_bytes(self.observer.read_bytes())
                self.retired.write_bytes(self.retired.read_bytes())
            return result
        with mock.patch.object(os,'pread',side_effect=read):self.assertEqual('unknown',self.observe()['state'])
        self.assertTrue(changed)

    def test_original_history_parent_exchange_during_last_read_rejects(self):
        actual=os.pread;changed=[];terminal=self.job/publisher.TERMINAL;old=self.job.with_name('status-old')
        def read(fd,*args):
            result=actual(fd,*args)
            if not changed and os.fstat(fd).st_ino==terminal.stat().st_ino:
                changed.append(1);self.job.rename(old);self.job.mkdir(mode=0o700)
            return result
        with mock.patch.object(os,'pread',side_effect=read):self.assertEqual('unknown',self.observe()['state'])
        self.assertTrue(changed);self.job.rmdir();old.rename(self.job)


for _name in dir(ReconciliationStatusTests):
    if _name.startswith('test_') and _name not in ReconciliationStatusTests.__dict__:setattr(ReconciliationStatusTests,_name,None)
del _name
