from pathlib import Path
import json, tempfile
from unittest import TestCase, mock
from agent_tools import windows_msi_owner_public_status as public

D=('windows-cp117','/qga',589342,520739,'S-1-5-21-1-2-3-1002')
class PublicStatusTests(TestCase):
 def admitted(self):
  return object(),D,'a'*64,{'socketPath':'/qga','qemuPid':589342,'startTicks':520739},'e'*64
 def intent(self,r):
  _c,_d,_h,g,e=self.admitted();public._write(r,{'version':1,'correlationId':public._CORRELATION,'sourceSha':public.relaunch._SOURCE,'guestGeneration':g,'evidenceSha256':e,'state':'intent'})
 def test_intent_precedes_submit_and_unknown_never_replays(self):
  with tempfile.TemporaryDirectory() as t:
   r=Path(t)
   with mock.patch.object(public,'_admit',return_value=self.admitted()),mock.patch.object(public,'_run',return_value='unknown') as run:
    self.assertEqual(public.start(r,{'host':'archlinux'}),public._UNKNOWN);self.assertEqual(public._read(r)['state'],'intent');self.assertEqual(public.start(r,{'host':'archlinux'}),public._UNKNOWN);self.assertEqual([c.args[-1] for c in run.call_args_list],['start','status'])
 def test_status_collect_are_read_only_terminal_proofs(self):
  with tempfile.TemporaryDirectory() as t:
   r=Path(t);self.intent(r)
   with mock.patch.object(public,'_admit',return_value=self.admitted()),mock.patch.object(public,'_run',return_value='proved'):
    self.assertEqual(public.status(r,{'host':'archlinux'})['state'],'proved');self.assertEqual(public.collect(r,{'host':'archlinux'})['state'],'proved');self.assertEqual(public._read(r)['state'],'intent')
 def test_user_task_uses_private_endpoint_only_in_guest_and_proves_public_runtime_off(self):
  for required in ('--controller-id $controller','status 2>$null','runtimeRunning -ne $false','ConvertFrom-Json'):
   self.assertIn(required,public._TASK_PS)
  self.assertEqual(public._TASK_PS.count('VerifyOwners'),3)  # declaration plus before/after public CLI
  self.assertNotIn('Out.WriteLine',public._TASK_PS)
  for forbidden in ('Stop-Process','Remove-Item','Set-Content'):
   self.assertNotIn(forbidden,public._TASK_PS)
 def test_private_endpoint_read_follows_original_user_token_and_safe_leaf_acl_proof(self):
  identity=public._TASK_PS.index('$identity=')
  read=public._TASK_PS.index('Get-Content -LiteralPath $endpoint')
  for required in ('WindowsIdentity]::GetCurrent','SessionId -ne 1','-not $limited','OwnerReadAcl','Get-Acl -LiteralPath $path','ReparsePoint','Length -lt 2','Length -gt 4096','S-1-5-18','S-1-5-32-544'):
   self.assertIn(required,public._TASK_PS)
  self.assertLess(identity,read)
  self.assertLess(public._TASK_PS.index('OwnerReadAcl $endpoint'),read)
 def test_both_system_bootstrap_and_user_task_reject_reparse_or_untrusted_ancestor_acl(self):
  for source in (public._TASK_PS,public._REMOTE):
   for required in ('ReparsePoint','Get-Acl','S-1-5-18','S-1-5-32-544','AccessControlType]::Deny'):
    self.assertIn(required,source)
  self.assertIn('Length -gt 4096',public._TASK_PS)
 def test_system_bootstrap_identity_and_trust_checks_precede_hash_endpoint_and_task_mutation(self):
  segment=public._REMOTE.split('boot=',1)[1]
  system=segment.index("WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18'")
  ancestor=segment.index('foreach($x')
  acl=segment.index('A $state')
  cli=segment.index('Get-FileHash')
  endpoint=segment.index('$l=Get-Item -LiteralPath $e')
  register=segment.index('Register-ScheduledTask')
  self.assertLess(system,ancestor)
  self.assertLess(ancestor,acl)
  self.assertLess(acl,cli)
  self.assertLess(cli,endpoint)
  self.assertLess(endpoint,register)
 def test_remote_status_hash_binds_task_without_exporting_private_values(self):
  for required in ('ComputeHash','Get-ScheduledTaskInfo','LastTaskResult','Interactive','Limited'):
   self.assertIn(required,public._REMOTE)
  self.assertNotIn("'runtimeRunning'",public._REMOTE)
 def test_real_relaunch_journal_transition_intent_and_launched_need_fresh_owner_proof(self):
  for state in ('intent','launched'):
   with self.subTest(state=state),tempfile.TemporaryDirectory() as t:
    r=Path(t);_c,_d,h,g,e=self.admitted()
    record={'version':1,'correlationId':public.relaunch._CORRELATION,'sourceSha':public.relaunch._SOURCE,'guestGeneration':g,'staleRecoveryEvidenceSha256':e,'state':'intent'}
    public.relaunch._write_intent(r,record)
    if state=='launched':public.relaunch._finish_intent(r,{**record,'state':'launched'})
    detail={'state':'detailed','baseOwners':'none','quotedStateServe':'one','unquotedStateServe':'one','otherSubcommand':'none','unrelated':'none','ownerIdentity':'exact','endpoint':'invalid','schemaVersion':'ambiguous','controllerId':'ambiguous','port':'ambiguous','token':'ambiguous','replayAllowed':False,'nativeActionAllowed':False}
    live={'state':'blocked','sourceSha':public.relaunch._SOURCE,'correlationId':public.relaunch.stale_lock._CORRELATION,'ownerProcesses':'many','installerProcesses':'none','consentProcesses':'none','runtimeProcesses':'none','stateLeaves':'both','runtimeOff':True,'replayAllowed':False,'nativeActionAllowed':False}
    with mock.patch.object(public.relaunch,'_admit',return_value=(object(),D,h,e)),mock.patch.object(public.relaunch,'detail',return_value=detail),mock.patch.object(public.relaunch.liveness,'observe',return_value=live),mock.patch.object(public,'_app_census',return_value={'gui':'none','cli':'two'}):self.assertIsNotNone(public._admit(r))
    with mock.patch.object(public.relaunch,'_admit',return_value=(object(),D,h,e)),mock.patch.object(public.relaunch,'detail',return_value={**detail,'unrelated':'one'}),mock.patch.object(public.relaunch.liveness,'observe',return_value=live):self.assertIsNone(public._admit(r))

 def test_acl_blocked_relaunch_status_does_not_block_exact_detail_based_public_proof(self):
  with tempfile.TemporaryDirectory() as t:
   r=Path(t);_c,_d,h,g,e=self.admitted();public.relaunch._write_intent(r,{'version':1,'correlationId':public.relaunch._CORRELATION,'sourceSha':public.relaunch._SOURCE,'guestGeneration':g,'staleRecoveryEvidenceSha256':e,'state':'launched'})
   detail={'state':'detailed','baseOwners':'none','quotedStateServe':'one','unquotedStateServe':'one','otherSubcommand':'none','unrelated':'none','ownerIdentity':'exact','endpoint':'invalid','schemaVersion':'ambiguous','controllerId':'ambiguous','port':'ambiguous','token':'ambiguous','replayAllowed':False,'nativeActionAllowed':False}
   live={'state':'blocked','sourceSha':public.relaunch._SOURCE,'correlationId':public.relaunch.stale_lock._CORRELATION,'ownerProcesses':'many','installerProcesses':'none','consentProcesses':'none','runtimeProcesses':'none','stateLeaves':'both','runtimeOff':True,'replayAllowed':False,'nativeActionAllowed':False}
   with mock.patch.object(public.relaunch,'_admit',return_value=(object(),D,h,e)),mock.patch.object(public.relaunch,'status',return_value=public.relaunch._UNKNOWN),mock.patch.object(public.relaunch,'detail',return_value=detail),mock.patch.object(public.relaunch.liveness,'observe',return_value=live),mock.patch.object(public,'_app_census',return_value={'gui':'none','cli':'two'}):self.assertIsNotNone(public._admit(r))

 def test_extra_gui_is_rejected_by_fresh_census_and_owner_task(self):
  self.assertIn("$_.Name -ceq 'vpn-control.exe'",public._APP_CENSUS_PS)
  self.assertIn("vpn-control.exe'}).Count -ne 0",public._TASK_PS)
  with tempfile.TemporaryDirectory() as t:
   r=Path(t);_c,_d,h,g,e=self.admitted();public.relaunch._write_intent(r,{'version':1,'correlationId':public.relaunch._CORRELATION,'sourceSha':public.relaunch._SOURCE,'guestGeneration':g,'staleRecoveryEvidenceSha256':e,'state':'launched'})
   detail={'state':'detailed','baseOwners':'none','quotedStateServe':'one','unquotedStateServe':'one','otherSubcommand':'none','unrelated':'none','ownerIdentity':'exact','endpoint':'invalid','schemaVersion':'ambiguous','controllerId':'ambiguous','port':'ambiguous','token':'ambiguous','replayAllowed':False,'nativeActionAllowed':False}
   live={'state':'blocked','sourceSha':public.relaunch._SOURCE,'correlationId':public.relaunch.stale_lock._CORRELATION,'ownerProcesses':'many','installerProcesses':'none','consentProcesses':'none','runtimeProcesses':'none','stateLeaves':'both','runtimeOff':True,'replayAllowed':False,'nativeActionAllowed':False}
   common=(mock.patch.object(public.relaunch,'_admit',return_value=(object(),D,h,e)),mock.patch.object(public.relaunch,'detail',return_value=detail),mock.patch.object(public.relaunch.liveness,'observe',return_value=live))
   with common[0],common[1],common[2],mock.patch.object(public,'_app_census',return_value={'gui':'one','cli':'two'}):self.assertIsNone(public._admit(r))
   with common[0],common[1],common[2],mock.patch.object(public,'_app_census',return_value={'gui':'none','cli':'other'}):self.assertIsNone(public._admit(r))

 def test_armed_public_intent_diagnoses_absent_or_failed_task_without_replay(self):
  with tempfile.TemporaryDirectory() as t:
   r=Path(t);self.intent(r)
   for found in ({'phase':'task','task':'absent'},{'phase':'task','task':'failed'}):
    with self.subTest(found=found),mock.patch.object(public,'_admit',return_value=self.admitted()),mock.patch.object(public,'_diagnostic',return_value=found),mock.patch.object(public,'_run') as run:
     self.assertEqual(public.diagnose(r,{'host':'archlinux'}),{'state':'diagnosed',**found,'replayAllowed':False,'nativeActionAllowed':False});run.assert_not_called()
  for required in ('system-identity','ancestors','acl','cli','endpoint','action-mismatch','__ARGS_SHA__','ComputeHash','GetBytes([string]$a[0].Arguments)'):
   self.assertIn(required,public._DIAGNOSE_PS)
