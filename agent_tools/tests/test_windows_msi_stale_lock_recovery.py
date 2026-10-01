"""Causal regressions for the one-shot CP117 stale-lock recovery."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
from unittest import TestCase, mock
from agent_tools import windows_msi_stale_lock_recovery as recovery

DESCRIPTOR = ('windows-cp117','/private/qga.sock',589342,520739,'S-1-5-21-1-2-3-1002')

class StaleLockRecoveryTests(TestCase):
 def _armed(self, root):
  generation,evidence=recovery._evidence(DESCRIPTOR)
  recovery._write_intent(root,{'version':1,'correlationId':recovery._CORRELATION,'sourceSha':recovery._SOURCE,'guestGeneration':generation,'evidenceSha256':evidence,'state':'intent'})

 def test_durable_intent_precedes_guest_remove_and_unknown_is_never_replayed(self):
  with tempfile.TemporaryDirectory() as temporary, mock.patch.object(recovery, '_admit', return_value=(object(),DESCRIPTOR,'a'*64)), mock.patch.object(recovery, '_run', side_effect=['stale-proven',None]) as run:
   value=recovery.recover(temporary, {'host':'archlinux'})
   self.assertEqual(value, recovery._UNKNOWN); self.assertEqual([call.args[-1] for call in run.call_args_list], ['observe','remove'])
   intent=recovery._read_intent(Path(temporary)); self.assertEqual(intent['state'],'intent')
   self.assertEqual(recovery.recover(temporary, {'host':'archlinux'}), recovery._UNKNOWN); self.assertEqual(run.call_count,2)

 def test_removal_requires_fresh_guest_proof_and_exact_admission(self):
  with tempfile.TemporaryDirectory() as temporary, mock.patch.object(recovery, '_admit', return_value=(object(),DESCRIPTOR,'a'*64)), mock.patch.object(recovery, '_run', side_effect=['stale-proven','removed']):
   self.assertEqual(recovery.recover(temporary, {'host':'archlinux'})['state'],'recovered')
   self.assertEqual(recovery._read_intent(Path(temporary))['state'],'recovered')
  self.assertIn('Probe $true', recovery._PS)
  self.assertIn('CreateFile($lock,[uint32]2147549184,[uint32]0', recovery._PS)
  self.assertIn('[StaleLockNative]::MarkDelete($handle)', recovery._PS)
  self.assertIn('[IO.FileStream]::new($handle,[IO.FileAccess]::Read)', recovery._PS)
  self.assertNotIn('[IO.FileStream]::new($handle,[IO.FileAccess]::Read,$false)', recovery._PS)
  self.assertNotIn('Remove-Item', recovery._PS)
  for forbidden in ('Start-Process','Stop-Process','& $cli'):
   self.assertNotIn(forbidden, recovery._PS)

 def test_probe_requires_owner_acl_lock_endpoint_absence_and_complete_process_absence(self):
  for required in ('SafeAncestors','C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\cp166','$install','OwnerAcl $state $true','OwnerAcl $lock $false','Get-Item -LiteralPath $endpoint','Get-CimInstance Win32_Process','consent.exe',"'2.1.19'"):
   self.assertIn(required, recovery._PS)
  self.assertIn("mode not in ('observe','remove')", recovery._REMOTE)

 def test_bad_or_changed_base_binding_cannot_create_intent(self):
  with tempfile.TemporaryDirectory() as temporary, mock.patch.object(recovery, '_admit', return_value=None), mock.patch.object(recovery, '_run') as run:
   self.assertEqual(recovery.recover(temporary, {'host':'archlinux'}), recovery._UNKNOWN); run.assert_not_called()

 def test_admission_pins_c32_source_artifacts_and_current_qemu_sid(self):
  request={'host':'archlinux','correlationId':recovery._CORRELATION,'sourceSha':recovery._SOURCE,**recovery._ARTIFACTS,'expectedCurrentVersion':'2.1.17'}
  intent={'request':request,'environment':DESCRIPTOR[0],'socketPath':DESCRIPTOR[1],'pid':DESCRIPTOR[2],'startTicks':DESCRIPTOR[3],'expectedSid':DESCRIPTOR[4]}
  pair={'sourceSha':recovery._SOURCE,'baseVersion':'2.1.19','baseArtifactId':recovery._ARTIFACTS['baseMsiArtifactId'],'receiptArtifactId':recovery._ARTIFACTS['fixtureReceiptArtifactId'],'targetArtifactId':recovery._ARTIFACTS['targetMsiArtifactId'],'baseCliSha256':'c'*64}
  with tempfile.TemporaryDirectory() as temporary, mock.patch.object(recovery.base,'_private_intent',return_value=intent), mock.patch.object(recovery.base,'_descriptor',return_value=(object(),object(),DESCRIPTOR)), mock.patch.object(recovery.base,'_stage_artifact_readonly',return_value=(pair,1)):
   self.assertIsNotNone(recovery._admit(Path(temporary)))
   pair['targetArtifactId']='sha256-'+'0'*64
   self.assertIsNone(recovery._admit(Path(temporary)))

 def test_recovered_receipt_with_changed_guest_generation_is_not_accepted(self):
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary); generation,evidence=recovery._evidence(DESCRIPTOR)
   recovery._write_intent(root,{'version':1,'correlationId':recovery._CORRELATION,'sourceSha':recovery._SOURCE,'guestGeneration':generation,'evidenceSha256':evidence,'state':'recovered'})
   changed=(DESCRIPTOR[0],DESCRIPTOR[1],DESCRIPTOR[2],DESCRIPTOR[3]+1,DESCRIPTOR[4])
   with mock.patch.object(recovery,'_admit',return_value=(object(),changed,'a'*64)), mock.patch.object(recovery,'_run') as run:
    self.assertEqual(recovery.recover(root,{'host':'archlinux'}),recovery._UNKNOWN);run.assert_not_called()

 def test_replacement_regression_uses_the_exclusive_handle_instead_of_a_path_delete(self):
  """A replacement cannot become the deletion target after the stale proof."""
  self.assertLess(recovery._PS.index('CreateFile($lock,[uint32]2147549184,[uint32]0'),recovery._PS.index('OwnerAcl $lock $false'))
  self.assertLess(recovery._PS.index('Get-CimInstance Win32_Process'),recovery._PS.index('[StaleLockNative]::MarkDelete($handle)'))
  self.assertNotIn('DeleteOnClose',recovery._PS)

 def test_causal_diagnosis_classifies_the_exclusive_handle_acl_boundary_without_replay(self):
  """RED cause: path-based Get-Acl follows the exclusive FileShare.None open."""
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary);self._armed(root)
   with mock.patch.object(recovery,'_admit',return_value=(object(),DESCRIPTOR,'a'*64)), mock.patch.object(recovery,'_diagnostic',return_value={'category':'exclusive-handle-acl-blocked'}) as diagnostic, mock.patch.object(recovery,'_run') as mutate:
    self.assertEqual(recovery.diagnose(root,{'host':'archlinux'}),{'state':'diagnosed','category':'exclusive-handle-acl-blocked','replayAllowed':False,'nativeActionAllowed':False})
    diagnostic.assert_called_once();mutate.assert_not_called()

 def test_reconciliation_needs_fresh_separate_one_shot_after_read_only_safe_proof(self):
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary);self._armed(root)
   with mock.patch.object(recovery,'_admit',return_value=(object(),DESCRIPTOR,'a'*64)), mock.patch.object(recovery,'_diagnostic',return_value={'category':'safe-proven'}):
    self.assertEqual(recovery.reconciliation_status(root,{'host':'archlinux'}),{'state':'separate-one-shot-required','replayAllowed':False,'nativeActionAllowed':False})
   with mock.patch.object(recovery,'_admit',return_value=(object(),DESCRIPTOR,'a'*64)), mock.patch.object(recovery,'_diagnostic',return_value={'category':'lock-open-access-denied'}):
    self.assertEqual(recovery.reconciliation_status(root,{'host':'archlinux'}),recovery._UNKNOWN)

 def test_diagnostic_program_is_read_only_and_keeps_failure_categories_bounded(self):
  self.assertNotIn('MarkDelete',recovery._DIAGNOSTIC_PS)
  self.assertNotIn('Remove-Item',recovery._DIAGNOSTIC_PS)
  self.assertIn('exclusive-handle-acl-blocked',recovery._DIAGNOSTIC_PS)
  self.assertIn('CreateFile($lock,[uint32]2147483648,[uint32]0',recovery._DIAGNOSTIC_PS)

 def test_diagnostic_emits_bounded_subphase_for_each_proof_boundary(self):
  for phase in ('ancestors','cli','product','state-acl','endpoint','processes','lock-open-invocation','lock-open-other','exclusive-handle-acl-blocked'):
   with self.subTest(phase=phase):
    self.assertIn("$category='"+phase+"'",recovery._DIAGNOSTIC_PS)
    self.assertIn(phase,recovery._DIAGNOSTIC_CATEGORIES)
  self.assertNotIn("$category='unsafe-proof'",recovery._DIAGNOSTIC_PS)

 def test_createfile_error_codes_have_only_bounded_causal_categories(self):
  expected={32:'lock-open-sharing-violation',5:'lock-open-access-denied',87:'lock-open-invalid-parameter',2:'lock-open-path-issue',3:'lock-open-path-issue',123:'lock-open-path-issue',161:'lock-open-path-issue',999:'lock-open-other'}
  for code,category in expected.items():
   with self.subTest(code=code): self.assertEqual(recovery._open_error_category(code),category)
  self.assertEqual(recovery._open_error_category('32'),'lock-open-other')
  for category in set(expected.values()): self.assertIn(category,recovery._DIAGNOSTIC_CATEGORIES)
  self.assertIn('$openError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()',recovery._DIAGNOSTIC_PS)

 def test_other_open_error_projects_only_typed_bounded_win32_code_end_to_end(self):
  raw=json.dumps({'version':1,'category':'lock-open-other','win32Code':0}).encode()
  with mock.patch.object(recovery.base,'_remote',return_value=raw):
   self.assertEqual(recovery._diagnostic(object(),DESCRIPTOR,'a'*64),{'category':'lock-open-other','win32Code':0})
  for value in (-1,65536,True,'0'):
   with self.subTest(value=value), mock.patch.object(recovery.base,'_remote',return_value=json.dumps({'version':1,'category':'lock-open-other','win32Code':value}).encode()):
    self.assertIsNone(recovery._diagnostic(object(),DESCRIPTOR,'a'*64))
  with mock.patch.object(recovery.base,'_remote',return_value=json.dumps({'version':1,'category':'lock-open-access-denied','win32Code':5}).encode()):
   self.assertIsNone(recovery._diagnostic(object(),DESCRIPTOR,'a'*64))

 def test_createfile_invocation_failure_is_not_misreported_as_other_code_zero(self):
  body=recovery._DIAGNOSTIC_PS
  call=body.index('[StaleLockDiagnosticNative]::CreateFile')
  self.assertLess(body.index("$category='lock-open-invocation'"),call)
  self.assertLess(call,body.index('$openError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()'))
  self.assertLess(body.index('$openError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()'),body.index("$category='lock-open-other'"))
  with mock.patch.object(recovery.base,'_remote',return_value=json.dumps({'version':1,'category':'lock-open-invocation'}).encode()):
   self.assertEqual(recovery._diagnostic(object(),DESCRIPTOR,'a'*64),{'category':'lock-open-invocation'})
  with mock.patch.object(recovery.base,'_remote',return_value=json.dumps({'version':1,'category':'lock-open-invocation','win32Code':0}).encode()):
   self.assertIsNone(recovery._diagnostic(object(),DESCRIPTOR,'a'*64))

 def test_diagnose_projects_other_code_without_authorizing_replay(self):
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary);self._armed(root)
   with mock.patch.object(recovery,'_admit',return_value=(object(),DESCRIPTOR,'a'*64)), mock.patch.object(recovery,'_diagnostic',return_value={'category':'lock-open-other','win32Code':0}):
    self.assertEqual(recovery.diagnose(root,{'host':'archlinux'}),{'state':'diagnosed','category':'lock-open-other','win32Code':0,'replayAllowed':False,'nativeActionAllowed':False})

 def test_missing_intent_diagnostic_does_not_create_a_recovery_journal(self):
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary); journal=root/recovery._GROUP
   with mock.patch.object(recovery,'_admit',return_value=(object(),DESCRIPTOR,'a'*64)), mock.patch.object(recovery,'_diagnostic') as remote:
    self.assertEqual(recovery.diagnose(root,{'host':'archlinux'}),recovery._UNKNOWN)
    remote.assert_not_called()
   self.assertFalse(journal.exists())
