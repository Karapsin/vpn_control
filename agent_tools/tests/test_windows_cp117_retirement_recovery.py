from __future__ import annotations
import tempfile
import unittest
import json
from types import SimpleNamespace
from pathlib import Path
from unittest import mock
from agent_tools import windows_cp117_retirement_recovery as recovery

class RecoveryTests(unittest.TestCase):
 def test_red_retirement_journal_has_its_own_protected_correlation_and_root(self):
  self.assertNotEqual(recovery._RECOVERY,recovery.guest_agent_recovery._RECOVERY)
  self.assertIn(r'C:\ProgramData\VpnControlCp117-retirement-',recovery._guest_journal_root())
  self.assertIn('Read-SecureJson',recovery._guest_terminal_reader())
 def test_red_missing_service_terminal_never_reserves_or_removes(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d)
   with mock.patch.object(recovery,'_admitted',return_value=({}, {}, (None,'/q',1,2,'S-1'))),mock.patch.object(recovery.retire,'_recovery_fresh',return_value=True),mock.patch.object(recovery,'_service_terminal',return_value=False),mock.patch.object(recovery,'_census') as census,mock.patch.object(recovery,'_remove_result') as remove:
    self.assertEqual('blocked',recovery.start(root,{})['state'])
   census.assert_not_called();remove.assert_not_called()
 def test_green_revalidates_before_result_delete_and_writes_compat_receipt_last(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); desc=(None,'/q',1,2,'S-1')
   with mock.patch.object(recovery,'_admitted',return_value=({}, {}, desc)),mock.patch.object(recovery.retire,'_recovery_fresh',return_value=True),mock.patch.object(recovery,'_service_terminal',return_value=True),mock.patch.object(recovery,'_census',return_value=True),mock.patch.object(recovery,'_deletion_plan',return_value=('remove','a'*64)),mock.patch.object(recovery,'_parse_sources',return_value=True),mock.patch.object(recovery,'_remove_result',return_value=True),mock.patch.object(recovery,'_root_absent',return_value=True),mock.patch.object(recovery,'_remote_terminal',return_value=True),mock.patch.object(recovery.retire,'_remove_host',return_value=True),mock.patch.object(recovery.retire,'_close',return_value=True),mock.patch.object(recovery.retire,'status',return_value={'state':'retired'}):
    self.assertEqual('retired',recovery.start(root,{})['state'])
   self.assertEqual({'stageCorrelationId':recovery.retire._STAGE,'leaseId':recovery.retire._LEASE,'removed':True},recovery.guards.secure_read(root/recovery.retire._DIR/'receipt.json'))
 def test_consumed_recovery_never_replays(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); recovery.guards.secure_directory(root/recovery._DIR); recovery.guards.secure_write_create(root/recovery._DIR/'intent.json',{})
   with mock.patch.object(recovery,'preflight',return_value={'state':'ready'}) as preflight:self.assertEqual('unknown',recovery.start(root,{})['state'])
   preflight.assert_called_once()
 def test_red_timeout_after_delete_status_observes_terminal_without_replay(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); desc=(None,'/q',1,2,'S-1'); journal=recovery.guards.secure_directory(root/recovery._DIR)
   binding=recovery._binding(desc,'a'*64)
   recovery.guards.secure_write_create(journal/'intent.json',{'binding':binding})
   with mock.patch.object(recovery,'_admitted',return_value=({}, {}, desc)),mock.patch.object(recovery,'_deletion_plan',return_value=('remove','a'*64)),mock.patch.object(recovery,'_remote_observation',return_value='terminal'),mock.patch.object(recovery,'_root_absent',return_value=True),mock.patch.object(recovery,'_remove_result') as remove:
    observed=recovery.status(root,{})
   self.assertEqual('guest-terminal',observed['state'])
   remove.assert_not_called()
 def test_red_after_delete_without_terminal_stays_unknown_for_cleanup(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); desc=(None,'/q',1,2,'S-1'); journal=recovery.guards.secure_directory(root/recovery._DIR)
   recovery.guards.secure_write_create(journal/'intent.json',{'binding':recovery._binding(desc,'a'*64)})
   with mock.patch.object(recovery,'_admitted',return_value=({}, {}, desc)),mock.patch.object(recovery,'_deletion_plan',return_value=('remove','a'*64)),mock.patch.object(recovery,'_remote_observation',return_value='after-delete'),mock.patch.object(recovery,'_root_absent',return_value=True),mock.patch.object(recovery.retire,'_remove_host') as remove:
    self.assertEqual('after-delete',recovery.status(root,{})['state'])
   remove.assert_not_called()
 def test_terminal_is_written_only_after_root_removal_and_absence_check(self):
  with mock.patch.object(recovery.guards,'remaining_result_census_powershell',return_value='$census'):
   script,_action=recovery._deletion_plan({'unused':True},('windows-cp117','/q',1,2,'S-1'))
  self.assertLess(script.index("Remove-Item -LiteralPath $f"),script.index("Write-SecureJsonCreate 'terminal.json'"))
  self.assertLess(script.index("if(Test-Path -LiteralPath $r){throw 'PRESENT'}"),script.index("Write-SecureJsonCreate 'terminal.json'"))
 def test_lost_child_reply_guest_receipt_binds_action_and_intent(self):
  desc=('windows-cp117','/q',1,2,'S-1'); action='a'*64; binding=recovery._binding(desc,action)
  receipt={'recoveryCorrelationId':recovery._RECOVERY,'state':'removed','childPid':9,'qemuPid':1,'startTicks':2,'actionSha256':action,'intentSha256':binding['intentSha256']}
  target=SimpleNamespace(fixture_transfer_root='/safe')
  with tempfile.TemporaryDirectory() as d, mock.patch.object(recovery.retire.base,'_descriptor',return_value=(None,target,desc)),mock.patch.object(recovery.retire.base,'_remote',side_effect=[json.dumps({'state':'terminal'}),json.dumps({'state':'observed','receipt':receipt})]):
   self.assertTrue(recovery._remote_terminal(Path(d),desc,action))
  receipt['actionSha256']='b'*64
  with tempfile.TemporaryDirectory() as d, mock.patch.object(recovery.retire.base,'_descriptor',return_value=(None,target,desc)),mock.patch.object(recovery.retire.base,'_remote',side_effect=[json.dumps({'state':'terminal'}),json.dumps({'state':'observed','receipt':receipt})]):
   self.assertFalse(recovery._remote_terminal(Path(d),desc,action))
 def test_red_guest_reader_rejects_extra_or_unbounded_leaf_tree(self):
  reader=recovery._guest_terminal_reader()
  self.assertIn("$nodes.Count -ne 1",reader)
  self.assertIn("$nodes[0].Name -cne 'terminal.json'",reader)
  self.assertIn('$MaxBytes=16384',reader)
 def test_actual_retirement_transport_stays_within_windows_command_limit(self):
  # Keep the real prospective source bounded as guards grow. The raw form is
  # currently within the limit too; this is a sizing gate, not native evidence.
  intent={'request':{'correlationId':recovery.retire._STAGE},'bundleSha256':'a'*64,'bundleSize':10,'fileHashes':{'fixture.json':'b'*64}}
  source,_=recovery._deletion_plan(intent,('windows-cp117','/q',1,2,'S-1-5-21-1-2-3-1001'))
  packed=len(__import__('base64').b64encode(recovery.guest_agent_recovery._launcher(source).encode('utf-16le')))
  self.assertLess(packed,28000)
 def test_parser_failure_does_not_consume_retirement_attempt(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);desc=('windows-cp117','/q',1,2,'S-1')
   with mock.patch.object(recovery,'preflight',return_value={'state':'ready'}),mock.patch.object(recovery,'_admitted',return_value=({}, {}, desc)),mock.patch.object(recovery.retire,'_recovery_fresh',return_value=True),mock.patch.object(recovery,'_service_terminal',return_value=True),mock.patch.object(recovery,'_census',return_value=True),mock.patch.object(recovery,'_parse_sources',return_value=False),mock.patch.object(recovery,'_remove_result') as remove:
    result=recovery.start(root,{})
   self.assertEqual('parser',result['phase']);remove.assert_not_called()
   self.assertFalse((root/recovery._DIR/'intent.json').exists())
 def test_closed_lease_reports_verified_retirement_without_active_admission(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);desc=('windows-cp117','/q',1,2,'S-1')
   directory=recovery.guards.secure_directory(root/recovery._DIR)
   recovery.guards.secure_write_create(directory/'intent.json',{'binding':recovery._binding(desc,'a'*64)})
   recovery.guards.secure_directory(root/recovery.retire._DIR)
   recovery.guards.secure_write_create(root/recovery.retire._DIR/'receipt.json',{'stageCorrelationId':recovery.retire._STAGE,'leaseId':recovery.retire._LEASE,'removed':True})
   with mock.patch.object(recovery,'_admitted',return_value=None),mock.patch.object(recovery.retire,'status',return_value={'state':'retired'}):
    self.assertEqual('retired',recovery.status(root,{})['state'])
if __name__=='__main__':unittest.main()
