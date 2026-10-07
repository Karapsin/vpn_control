"""Causal actual-writer regressions for retired nested recovery admission."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from agent_tools import ssh_connection_recovery as recovery, ssh_expired_recovery_retirement as retirement
from agent_tools import ssh_recovery_adoption as adoption, ssh_transport as transport, private_inventory_lock as private
from agent_tools.tests import test_ssh_expired_recovery_retirement as fixtures


class ExpiredRecoveryAdmissionTest(unittest.TestCase):
    def archived(self,path,terminal=True):
        root,target,corr,intent=fixtures.ExpiredRecoveryRetirementTest().fixture(path)
        pins=retirement.authority(root,'nested',corr);writer=adoption._write_receipt
        def write(directory,name,value):
            if not terminal and name.endswith('.terminal.json'):raise OSError('interrupted terminal')
            return writer(directory,name,value)
        with mock.patch.object(retirement,'_observe',return_value=fixtures.absence(target,corr)),mock.patch.object(adoption,'_write_receipt',side_effect=write):
            result=retirement.retire(root,'nested',corr,**pins)
        self.assertEqual('retired' if terminal else 'unknown',result['state']);self.assertFalse(intent.exists())
        return root,target,corr,intent

    def test_actual_create_intent_blocked_by_archived_pending_without_terminal(self):
        with tempfile.TemporaryDirectory() as path:
            root,target,corr,intent=self.archived(path,False)
            with mock.patch.object(recovery,'_socket_state',return_value='absent'),mock.patch.object(recovery,'_create_intent',wraps=recovery._create_intent) as create,mock.patch.object(recovery,'_gateway_run',return_value=None) as remote:
                result=recovery.recover(root,'nested')
            self.assertEqual({'ok':False,'state':'recovery_unavailable'},result)
            create.assert_not_called();remote.assert_not_called();self.assertFalse(intent.exists())

    def test_terminal_admits_one_actual_create_then_unknown_prevents_replay(self):
        with tempfile.TemporaryDirectory() as path:
            root,target,corr,intent=self.archived(path)
            with mock.patch.object(recovery,'_socket_state',return_value='absent'),mock.patch.object(recovery,'_gateway_run',return_value=None) as remote,mock.patch.object(recovery,'_create_intent',wraps=recovery._create_intent) as create:
                self.assertEqual('recovery_intent_pending',recovery.recover(root,'nested')['state'])
                self.assertEqual('recovery_intent_pending',recovery.recover(root,'nested')['state'])
            self.assertEqual(1,create.call_count);self.assertEqual(1,remote.call_count)
            self.assertNotEqual(corr,json.loads(intent.read_bytes())['correlationId'])

    def test_current_inventory_revalidation_rejects_stale_initial_route(self):
        with tempfile.TemporaryDirectory() as path:
            root,target,corr,intent=self.archived(path)
            def observed(*args):
                config=root/transport.CONFIG_FILENAME;value=json.loads(config.read_bytes());value['hosts']['gateway']['host']='foreign.example';config.write_text(json.dumps(value));return 'absent'
            with mock.patch.object(recovery,'_socket_state',side_effect=observed),mock.patch.object(recovery,'_create_intent',wraps=recovery._create_intent) as create,mock.patch.object(recovery,'_gateway_run') as remote:
                self.assertEqual('recovery_unavailable',recovery.recover(root,'nested')['state'])
            create.assert_not_called();remote.assert_not_called();self.assertFalse(intent.exists())

    def test_missing_host_in_consumed_pending_never_admits(self):
        with tempfile.TemporaryDirectory() as path:
            root,target,corr,intent=self.archived(path,False)
            pending=next(intent.parent.glob('.retire-*.pending.json'));value=json.loads(pending.read_bytes());del value['host'];pending.write_text(json.dumps(value))
            with self.assertRaises((ValueError,KeyError)):retirement.require_admission(root,'nested',target)

    def test_status_closes_pending_after_last_archive_body_read(self):
        with tempfile.TemporaryDirectory() as path:
            root,target,corr,intent=self.archived(path)
            pending=next(intent.parent.glob('.retire-*.pending.json'));archive=next(intent.parent.glob('.retired-*.intent.json'));real=private.Snapshot.guard;calls=[]
            def guard(snapshot):
                real(snapshot)
                if snapshot.name==archive.name:
                    calls.append(1)
                    if len(calls)==2:pending.write_bytes(b'{}')
            with mock.patch.object(private.Snapshot,'guard',new=guard):
                self.assertEqual('unknown',retirement.status(root,'nested',corr)['state'])

    def test_last_intent_body_read_cannot_change_fence_before_rename(self):
        with tempfile.TemporaryDirectory() as path:
            root,target,corr,intent=fixtures.ExpiredRecoveryRetirementTest().fixture(path);pins=retirement.authority(root,'nested',corr);real=private.Snapshot.guard;observations=[];last=[]
            def observe(*args):observations.append(1);return fixtures.absence(target,corr)
            def guard(snapshot):
                real(snapshot)
                if len(observations)==2 and snapshot.name==intent.name:
                    last.append(1)
                    if len(last)==2:next(intent.parent.glob('.retire-*.pending.json')).write_bytes(b'{}')
            with mock.patch.object(retirement,'_observe',side_effect=observe),mock.patch.object(private.Snapshot,'guard',new=guard):
                self.assertEqual('unknown',retirement.retire(root,'nested',corr,**pins)['state'])
            self.assertTrue(intent.exists());self.assertFalse(list(intent.parent.glob('.retired-*.intent.json')))

    def test_cooperative_inventory_lock_blocks_actual_successor_writer(self):
        with tempfile.TemporaryDirectory() as path:
            root,target,corr,intent=self.archived(path)
            with private.ownership(root),mock.patch.object(recovery,'_socket_state',return_value='absent'),mock.patch.object(recovery,'_create_intent',wraps=recovery._create_intent) as create,mock.patch.object(recovery,'_gateway_run') as remote:
                self.assertEqual('recovery_unavailable',recovery.recover(root,'nested')['state'])
            create.assert_not_called();remote.assert_not_called()

    def test_publisher_admission_retains_archived_generation_through_writer(self):
        with tempfile.TemporaryDirectory() as path:
            root,target,corr,intent=self.archived(path);config=transport.load_config(root)
            with self.assertRaises(ValueError):
                with recovery.successor_admission(root,'nested',config) as (canonical,current,exact_target,guard):
                    archived=next(intent.parent.glob('.retired-*.intent.json'));replacement=archived.with_suffix('.replacement')
                    replacement.write_bytes(archived.read_bytes());replacement.chmod(0o600);replacement.replace(archived)
                    guard()
            self.assertFalse(intent.exists())

    def test_last_intent_body_read_cannot_change_held_source_before_rename(self):
        with tempfile.TemporaryDirectory() as path:
            root,target,corr,intent=fixtures.ExpiredRecoveryRetirementTest().fixture(path)
            copy=root/'retirement-source.py';copy.write_bytes(Path(retirement.__file__).read_bytes());copy.chmod(0o644)
            real=private.Snapshot.guard;observations=[];last=[]
            def observe(*args):observations.append(1);return fixtures.absence(target,corr)
            def guard(snapshot):
                real(snapshot)
                if len(observations)==2 and snapshot.name==intent.name:
                    last.append(1)
                    if len(last)==2:copy.write_bytes(copy.read_bytes()+b'\n')
            with mock.patch.object(retirement,'__file__',str(copy)):
                pins=retirement.authority(root,'nested',corr)
                with mock.patch.object(retirement,'_observe',side_effect=observe),mock.patch.object(private.Snapshot,'guard',new=guard):
                    self.assertEqual('unknown',retirement.retire(root,'nested',corr,**pins)['state'])
            self.assertTrue(intent.exists());self.assertFalse(list(intent.parent.glob('.retired-*.intent.json')))

    def test_historical_status_and_publisher_reject_original_tool_source_replacement(self):
        with tempfile.TemporaryDirectory() as path:
            root=Path(path).resolve();copy=root/'tool-source.py';copy.write_bytes(Path(retirement.__file__).read_bytes());copy.chmod(0o644)
            with mock.patch.object(retirement,'__file__',str(copy)):
                root,target,corr,intent=self.archived(path)
                config=transport.load_config(root)
                with self.assertRaises(ValueError):
                    with recovery.successor_admission(root,'nested',config) as (_,_,_,guard):
                        replacement=copy.with_suffix('.replacement');replacement.write_bytes(copy.read_bytes());replacement.chmod(0o644);replacement.replace(copy)
                        guard()
                self.assertEqual('unknown',retirement.status(root,'nested',corr)['state'])
                with self.assertRaises(ValueError):retirement.require_admission(root,'nested',target)
            self.assertFalse(intent.exists())


if __name__=='__main__':unittest.main()
