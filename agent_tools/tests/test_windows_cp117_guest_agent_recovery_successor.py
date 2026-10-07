from __future__ import annotations
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest import mock
from agent_tools import windows_cp117_guest_agent_recovery_successor as successor

class SuccessorTests(unittest.TestCase):
 def test_red_original_start_is_never_an_escape_hatch(self):
  with tempfile.TemporaryDirectory() as d:
   with mock.patch.object(successor.original,'start') as old_start:
    self.assertEqual('blocked',successor.start(Path(d),{})['state'])
   old_start.assert_not_called()
 def test_red_consumed_successor_reservation_never_dispatches_again(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); directory=successor._directory(root); successor.guards.secure_write_create(directory/'intent.json',{})
   with mock.patch.object(successor,'preflight',return_value={'state':'ready'}),mock.patch.object(successor.original,'_run_ps') as run:
    self.assertEqual('unknown',successor.start(root,{})['state'])
   run.assert_not_called()
 def test_status_rejects_changed_bound_action_before_terminal(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); identity={'name':'qemu-ga','state':'Running','startName':'LocalSystem','pid':1,'startTicks':1,'path':'q.exe'};intent={'recoveryCorrelationId':successor._RECOVERY,'service':identity,'guestGeneration':{'socketPath':'/q','qemuPid':2,'startTicks':3}};directory=successor._directory(root)
   successor.guards.secure_write_create(directory/'intent.json',intent);successor.guards.secure_write_create(directory/'action.json',{'intentSha256':successor._digest(intent),'actionSha256':'0'*64})
   self.assertEqual('unknown',successor.status(root,{})['state'])
   self.assertIsNone(successor.guards.secure_read(directory/'terminal.json'))
 def test_parser_reports_prospective_sources_without_reserving(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); plan=(None,('windows-cp117','/q',2,3,'S-1'),{'name':'qemu-ga'}, {'recoveryCorrelationId':successor._RECOVERY})
   with mock.patch.object(successor,'_plan',return_value=plan),mock.patch.object(successor.original,'_parse_results',return_value={'task':'valid','status':'valid'}):
    self.assertEqual('passed',successor.parser(root,{})['state'])
   self.assertFalse((root/successor._DIR/'intent.json').exists())
 def test_full_shared_reader_receipt_promotes_only_exact_fresh_terminal(self):
  before={'name':'qemu-ga','state':'Running','startName':'LocalSystem','pid':1,'startTicks':1,'path':r'C:\qemu-ga.exe'}
  after={**before,'pid':4,'startTicks':5}
  for change in ({},{'service':{**after,'path':'other'}},{'outcome':'failed'},{'childPid':False},{'private':'secret'}):
   with self.subTest(change=change), tempfile.TemporaryDirectory() as d:
    root=Path(d);directory=successor._directory(root);intent={'recoveryCorrelationId':successor._RECOVERY,'service':before,'guestGeneration':{'socketPath':'/q','qemuPid':2,'startTicks':3}}
    digest=successor._digest(intent);action=successor._action(before,digest)
    successor.guards.secure_write_create(directory/'intent.json',intent);successor.guards.secure_write_create(directory/'action.json',{'intentSha256':digest,'actionSha256':action})
    seen={'binding':digest,'terminalBinding':digest,'outcome':'restarted','taskSystem':True,'taskState':'Ready','actionSha256':action,'service':after,'recoveryCorrelationId':successor._RECOVERY,'childPid':20,'childStartTicks':6,**change}
    with mock.patch.object(successor.original.base,'_descriptor',return_value=(None,None,('windows-cp117','/q',2,3,'S-1'))),mock.patch.object(successor.original,'_run_ps',return_value=seen):
     self.assertEqual('terminal' if not change else 'unknown',successor.status(root,{})['state'])
    self.assertEqual(not bool(change),(directory/'terminal.json').exists())
if __name__=='__main__':unittest.main()
