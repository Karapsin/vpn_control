from __future__ import annotations
from pathlib import Path
import tempfile
from unittest import TestCase,mock
from agent_tools import windows_msi_stale_lock_reconcile as reconcile

D=('windows-cp117','/qga',589342,520739,'S-1-5-21-1-2-3-1002')
L={'state':'absent','sourceSha':reconcile.stale._SOURCE,'correlationId':reconcile.stale._CORRELATION,'ownerProcesses':'none','installerProcesses':'none','consentProcesses':'none','runtimeProcesses':'none','stateLeaves':'none','runtimeOff':True,'replayAllowed':False,'nativeActionAllowed':False}
class ReconcileTests(TestCase):
 def _old(self,root):
  g,e=reconcile.stale._evidence(D);reconcile.stale._write_intent(root,{'version':1,'correlationId':reconcile.stale._CORRELATION,'sourceSha':reconcile.stale._SOURCE,'guestGeneration':g,'evidenceSha256':e,'state':'intent'})
 def test_original_invocation_failure_never_creates_new_intent_or_replays(self):
  with tempfile.TemporaryDirectory() as t:
   r=Path(t);self._old(r)
   with mock.patch.object(reconcile.stale,'_admit',return_value=(object(),D,'a'*64)),mock.patch.object(reconcile.stale,'diagnose',return_value={'state':'diagnosed','category':'lock-open-invocation','replayAllowed':False,'nativeActionAllowed':False}),mock.patch.object(reconcile.stale,'_run') as remove:
    self.assertEqual(reconcile.reconcile(r,{'host':'archlinux'}),reconcile._UNKNOWN);remove.assert_not_called();self.assertIsNone(reconcile._read(r))
 def test_new_intent_is_durable_before_remove_and_unknown_never_replays(self):
  with tempfile.TemporaryDirectory() as t:
   r=Path(t);self._old(r)
   safe={'state':'diagnosed','category':'safe-proven','replayAllowed':False,'nativeActionAllowed':False}
   def lost(*_):
    self.assertEqual(reconcile._read(r)['state'],'intent');return None
   with mock.patch.object(reconcile.stale,'_admit',return_value=(object(),D,'a'*64)),mock.patch.object(reconcile.stale,'diagnose',return_value=safe),mock.patch.object(reconcile.stale,'_run',side_effect=lost) as remove:
    self.assertEqual(reconcile.reconcile(r,{'host':'archlinux'}),reconcile._UNKNOWN);self.assertEqual(reconcile._read(r)['state'],'intent');remove.assert_called_once()
    self.assertEqual(reconcile.reconcile(r,{'host':'archlinux'}),reconcile._UNKNOWN);self.assertEqual(remove.call_count,1)
 def test_new_fixed_correlation_is_distinct_from_the_armed_c32_intent(self):
  self.assertNotEqual(reconcile._CORRELATION,reconcile.stale._CORRELATION)
 def test_read_only_status_then_explicit_close_requires_absent_terminal_proof(self):
  with tempfile.TemporaryDirectory() as t:
   r=Path(t);self._old(r);reconcile._write(r,reconcile._record(D,'intent'))
   with mock.patch.object(reconcile.stale,'_admit',return_value=(object(),D,'a'*64)),mock.patch.object(reconcile,'_guest_absent',return_value=True),mock.patch.object(reconcile.liveness,'observe',return_value=L):
    self.assertEqual(reconcile.status(r,{'host':'archlinux'})['state'],'terminal-proven');self.assertEqual(reconcile._read(r)['state'],'intent')
    self.assertEqual(reconcile.close(r,{'host':'archlinux'})['state'],'recovered');self.assertEqual(reconcile._read(r)['state'],'recovered')
 def test_inaccessible_lock_and_mismatched_liveness_cannot_prove_terminal_absence(self):
  self.assertIn("ObjectNotFound",reconcile._STATUS_PS);self.assertIn("Absent $lock",reconcile._STATUS_PS)
  with tempfile.TemporaryDirectory() as t:
   r=Path(t);self._old(r);reconcile._write(r,reconcile._record(D,'intent'))
   with mock.patch.object(reconcile.stale,'_admit',return_value=(object(),D,'a'*64)),mock.patch.object(reconcile,'_guest_absent',return_value=False),mock.patch.object(reconcile.liveness,'observe',return_value=L):
    self.assertEqual(reconcile.status(r,{'host':'archlinux'}),reconcile._UNKNOWN)
   with mock.patch.object(reconcile.stale,'_admit',return_value=(object(),D,'a'*64)),mock.patch.object(reconcile,'_guest_absent',return_value=True),mock.patch.object(reconcile.liveness,'observe',return_value={**L,'sourceSha':'bad'}):
    self.assertEqual(reconcile.status(r,{'host':'archlinux'}),reconcile._UNKNOWN)
 def test_historical_recovered_receipt_requires_fresh_absence_and_refuses_reappeared_lock(self):
  with tempfile.TemporaryDirectory() as t:
   r=Path(t);self._old(r);reconcile._write(r,reconcile._record(D,'intent'));reconcile._write(r,reconcile._record(D,'recovered'),replace=True)
   with mock.patch.object(reconcile.stale,'_admit',return_value=(object(),D,'a'*64)),mock.patch.object(reconcile,'_guest_absent',return_value=False),mock.patch.object(reconcile.liveness,'observe',return_value=L):
    self.assertEqual(reconcile.status(r,{'host':'archlinux'}),reconcile._UNKNOWN);self.assertEqual(reconcile.close(r,{'host':'archlinux'}),reconcile._UNKNOWN)
