from __future__ import annotations
import json, os, subprocess, sys
import tempfile,unittest
from pathlib import Path
from unittest import mock
from types import SimpleNamespace
from agent_tools import windows_cp117_c32_archive_admission as archive
class ArchiveTests(unittest.TestCase):
 def test_verified_retained_terminal_can_be_archived_without_deleting_it(self):
  root=Path('.').resolve(); receipt={'state':'observed','baseTask':'present','guestLeaf':'present','transferTask':'absent','baseMsi':'absent','correlationProcess':'absent'}
  for terminal in ('retained-terminal','unknown'):
   with mock.patch.object(archive,'_request',return_value={'leaseId':'67eeeedb-a618-42d5-8e31-821650d16302'}),mock.patch.object(archive.base,'_descriptor',return_value=(object(),object(),())),mock.patch.object(archive.rebase,'_history',return_value=({}, {}, 'c'*64, 'd'*64)),mock.patch.object(archive.rebase,'_previous_closed_readonly'),mock.patch.object(archive,'_historical_cleanup_status',return_value={'state':'cleaned','terminalReceiptSha256':'c'*64}),mock.patch.object(archive,'host_status',return_value={'state':'absent'}),mock.patch.object(archive.absence,'observe',return_value=receipt),mock.patch.object(archive.absence,'retained_terminal',return_value={'state':terminal}),mock.patch.object(archive.absence,'diagnose_retained',return_value={'guard':'TASK'}):
    self.assertEqual('ready' if terminal=='retained-terminal' else 'blocked',archive.preflight(root,{'leaseId':'67eeeedb-a618-42d5-8e31-821650d16302'})['state'])
 def _record(self,path):
  return {'correlationId':archive._C32,'sourceSha':'a'*40,'baseMsiArtifactId':'sha256-'+'b'*64,'environment':'windows-cp117','socketPath':'/q','qemuPid':2,'startTicks':3,'expectedSid':'S-1-5-21-1-2-3-4','sha256':'b'*64,'length':10,'routeNonce':'a'*32,'artifactPath':str(path)}
 def _base_intent(self):
  return {'request':{'correlationId':archive._C32,'sourceSha':'a'*40,'baseMsiArtifactId':'sha256-'+'b'*64,'expectedCurrentVersion':'2.1.17'}}
 def test_red_requires_exact_c32_base_record_before_history(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d)
   with mock.patch.object(archive.stage,'_read_intent',return_value={'leaseId':archive._C32,'request':{'sourceSha':'a'*40,'fixtureReceiptArtifactId':'sha256-'+'a'*64,'baseMsiArtifactId':'sha256-'+'b'*64,'targetMsiArtifactId':'sha256-'+'c'*64}}),mock.patch.object(archive.base,'_private_intent',return_value=None),mock.patch.object(archive.rebase,'_history') as history:
    self.assertEqual('blocked',archive.preflight(root,{'leaseId':'67eeeedb-a618-42d5-8e31-821650d16302'})['state'])
   history.assert_not_called()
 def test_red_rejects_base_record_when_shared_artifact_identity_changes(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); stage_request={'sourceSha':'a'*40,'fixtureReceiptArtifactId':'sha256-'+'a'*64,'baseMsiArtifactId':'sha256-'+'b'*64,'targetMsiArtifactId':'sha256-'+'c'*64}
   base_request={**stage_request,'correlationId':archive._C32,'expectedCurrentVersion':'2.1.19','sourceSha':'b'*40}
   with mock.patch.object(archive.stage,'_read_intent',return_value={'leaseId':archive._C32,'request':stage_request}),mock.patch.object(archive.base,'_private_intent',return_value={'request':base_request}):
    self.assertIsNone(archive._request(root,'67eeeedb-a618-42d5-8e31-821650d16302'))
 def test_historical_cleanup_uses_top_level_record_and_never_calls_head_admission(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); artifact=root/'old.msi';artifact.write_bytes(b'x');record=self._record(artifact);dispatch={'correlationId':archive._C32,'terminalReceiptSha256':'c'*64};target=SimpleNamespace(fixture_transfer_root='/remote');desc=('windows-cp117','/q',2,3,'S-1-5-21-1-2-3-4')
   with mock.patch.object(archive.transfer,'_intent',return_value=record),mock.patch.object(archive.base,'_private_intent',return_value=self._base_intent()),mock.patch.object(archive.public,'_verified_location',return_value=artifact),mock.patch.object(archive.transfer,'_private_dir',return_value=root),mock.patch.object(archive.transfer,'_read',return_value=dispatch),mock.patch.object(archive.base,'_remote',return_value='bytes') as remote,mock.patch.object(archive.transfer,'_terminal_result',return_value={'state':'cleaned','terminalReceiptSha256':'c'*64}),mock.patch.object(archive.transfer,'_admit_current') as current:
    self.assertEqual('cleaned',archive._historical_cleanup_status(root,object(),target,desc,'c'*64)['state'])
   current.assert_not_called();remote.assert_called_once()
 def test_historical_cleanup_wrong_identity_never_contacts_remote(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);artifact=root/'old.msi';artifact.write_bytes(b'x');record=self._record(artifact);record['expectedSid']='S-1-5-21-9-9-9-9';target=SimpleNamespace(fixture_transfer_root='/remote');desc=('windows-cp117','/q',2,3,'S-1-5-21-1-2-3-4')
   with mock.patch.object(archive.transfer,'_intent',return_value=record),mock.patch.object(archive.base,'_private_intent',return_value=self._base_intent()),mock.patch.object(archive.base,'_remote') as remote:
    self.assertEqual('unknown',archive._historical_cleanup_status(root,object(),target,desc,'c'*64)['state'])
   remote.assert_not_called()
 def test_preflight_rejects_present_ambiguous_and_unknown_absence_receipts(self):
  root=Path('.').resolve();request={'host':'archlinux','leaseId':'67eeeedb-a618-42d5-8e31-821650d16302','previousLeaseId':archive._C32,'sourceSha':'a'*40,'fixtureReceiptArtifactId':'sha256-'+'a'*64,'baseMsiArtifactId':'sha256-'+'b'*64,'targetMsiArtifactId':'sha256-'+'c'*64};target=SimpleNamespace(fixture_transfer_root='/remote');desc=('windows-cp117','/q',2,3,'S-1-5-21-1-2-3-4')
  for state,field in [('observed','present'),('observed','ambiguous'),('unknown',None)]:
   receipt={'state':state,**({k:field for k in ('baseTask','transferTask','guestLeaf','baseMsi','correlationProcess')} if field else {})}
   with mock.patch.object(archive,'_request',return_value=request),mock.patch.object(archive.base,'_descriptor',return_value=(object(),target,desc)),mock.patch.object(archive.rebase,'_history',return_value=({}, {}, 'c'*64, 'd'*64)),mock.patch.object(archive.rebase,'_previous_closed_readonly'),mock.patch.object(archive,'_historical_cleanup_status',return_value={'state':'cleaned','terminalReceiptSha256':'c'*64}),mock.patch.object(archive,'host_status',return_value={'state':'absent'}),mock.patch.object(archive.absence,'observe',return_value=receipt):
    self.assertEqual('blocked',archive.preflight(root,{'leaseId':request['leaseId']})['state'])

 def test_post_retired_leaf_requires_exact_retirement_projection(self):
  root=Path('.').resolve();request={'host':'archlinux','leaseId':'67eeeedb-a618-42d5-8e31-821650d16302','previousLeaseId':archive._C32,'sourceSha':'a'*40,'fixtureReceiptArtifactId':'sha256-'+'a'*64,'baseMsiArtifactId':'sha256-'+'b'*64,'targetMsiArtifactId':'sha256-'+'c'*64};target=SimpleNamespace(fixture_transfer_root='/remote');desc=('windows-cp117','/q',2,3,'S-1-5-21-1-2-3-4')
  receipt={'state':'observed','baseTask':'absent','guestLeaf':'present','transferTask':'absent','baseMsi':'absent','correlationProcess':'absent'}
  for proof in ('post-retirement-terminal','unknown'):
   with self.subTest(proof=proof),mock.patch.object(archive,'_request',return_value=request),mock.patch.object(archive.base,'_descriptor',return_value=(object(),target,desc)),mock.patch.object(archive.rebase,'_history',return_value=({}, {}, 'c'*64, 'd'*64)),mock.patch.object(archive.rebase,'_previous_closed_readonly'),mock.patch.object(archive,'_historical_cleanup_status',return_value={'state':'cleaned','terminalReceiptSha256':'c'*64}),mock.patch.object(archive,'host_status',return_value={'state':'retained'}),mock.patch.object(archive.absence,'observe',return_value=receipt),mock.patch.object(archive.absence,'post_retirement_terminal',return_value={'state':proof}) as terminal,mock.patch.object(archive.absence,'retained_terminal') as retained:
    answer=archive.preflight(root,{'leaseId':request['leaseId']})
   self.assertEqual('ready' if proof=='post-retirement-terminal' else 'blocked',answer['state'])
   terminal.assert_called_once();retained.assert_not_called()

 def test_foreign_or_unknown_post_retirement_census_never_calls_projection(self):
  root=Path('.').resolve();request={'host':'archlinux','leaseId':'67eeeedb-a618-42d5-8e31-821650d16302','previousLeaseId':archive._C32,'sourceSha':'a'*40,'fixtureReceiptArtifactId':'sha256-'+'a'*64,'baseMsiArtifactId':'sha256-'+'b'*64,'targetMsiArtifactId':'sha256-'+'c'*64};target=SimpleNamespace(fixture_transfer_root='/remote');desc=('windows-cp117','/q',2,3,'S-1-5-21-1-2-3-4')
  # Presence of a foreign transfer task means this is not the precise post-state.
  receipt={'state':'observed','baseTask':'absent','guestLeaf':'present','transferTask':'present','baseMsi':'absent','correlationProcess':'absent'}
  with mock.patch.object(archive,'_request',return_value=request),mock.patch.object(archive.base,'_descriptor',return_value=(object(),target,desc)),mock.patch.object(archive.rebase,'_history',return_value=({}, {}, 'c'*64, 'd'*64)),mock.patch.object(archive.rebase,'_previous_closed_readonly'),mock.patch.object(archive,'_historical_cleanup_status',return_value={'state':'cleaned','terminalReceiptSha256':'c'*64}),mock.patch.object(archive,'host_status',return_value={'state':'absent'}),mock.patch.object(archive.absence,'observe',return_value=receipt),mock.patch.object(archive.absence,'post_retirement_terminal') as terminal:
   self.assertEqual('blocked',archive.preflight(root,{'leaseId':request['leaseId']})['state'])
  terminal.assert_not_called()

 def test_real_outer_shared_preflight_never_requests_campaign_exclusive_lock(self):
  program=r"""import tempfile,os,sys,json,signal
from pathlib import Path
from unittest import mock
from agent_tools import windows_cp117_c32_archive_admission as a
from agent_tools import windows_cp117_historical_base_archives as h
root=Path(sys.argv[1]);directory=root/a.lease._DIR
directory.mkdir(parents=True,mode=0o700);directory.parent.chmod(0o700)
lock=directory/'.environment.lock';lock.write_bytes(b'');lock.chmod(0o600)
request={'host':'archlinux','leaseId':'d42cb108-4d48-407e-9153-40774559ba50','previousLeaseId':a._C32,'sourceSha':'1'*40,'fixtureReceiptArtifactId':'sha256-'+'2'*64,'baseMsiArtifactId':'sha256-'+'3'*64,'targetMsiArtifactId':'sha256-'+'4'*64}
descriptor=('windows-cp117','/qga',589342,520739,'S-1-5-21-1-2-3-1002')
identity=a.base._campaign_identity({**request,'correlationId':a._C32},descriptor)
closed={'version':1,'identity':identity,'sequence':7,'state':'closed','role':None,'correlationId':None,'lastOutcome':'failed-cleaned','lastEvidenceSha256':'d'*64,'server':'stopped','credentials':'absent'}
path=directory/(a._C32+'.closed.json');path.write_text(json.dumps(closed));path.chmod(0o600)
def deadline(*args):raise TimeoutError('bounded nested-lock regression')
signal.signal(signal.SIGALRM,deadline)
with mock.patch.object(a,'_request',return_value=request),mock.patch.object(a.base,'_descriptor',return_value=(object(),object(),descriptor)),mock.patch.object(a.rebase,'_history',return_value=({}, {}, 'c'*64,'d'*64)),mock.patch.object(a.lease,'_remote_confirm',return_value=True) as remote,mock.patch.object(a.base,'_campaign_remote',return_value=object()),mock.patch.object(a,'_historical_cleanup_status',return_value={'state':'cleaned','terminalReceiptSha256':'c'*64}),mock.patch.object(a,'host_status',return_value={'state':'absent'}),mock.patch.object(a.absence,'observe',return_value={'state':'observed',**{key:'absent' for key in ('baseTask','transferTask','guestLeaf','baseMsi','correlationProcess')}}):
 with h._history_lock(root):
  signal.alarm(1)
  try:result=a.preflight(root,{'leaseId':request['leaseId']})
  finally:signal.alarm(0)
 print(json.dumps({'state':result['state'],'phase':result.get('phase'),'remoteCount':remote.call_count}))
"""
  with tempfile.TemporaryDirectory() as d:
   done=subprocess.run([sys.executable,'-c',program,d],capture_output=True,text=True,timeout=5)
   self.assertEqual(done.returncode,0,done.stderr);result=json.loads(done.stdout)
   self.assertEqual(result,{'state':'ready','phase':None,'remoteCount':1})
