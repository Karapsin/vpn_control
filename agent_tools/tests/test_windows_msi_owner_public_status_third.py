import ast
from pathlib import Path
import tempfile
import hashlib
import json
from unittest import TestCase, mock
from agent_tools import windows_msi_owner_public_status as first
from agent_tools import windows_msi_owner_public_status_retry as retry
from agent_tools import windows_msi_owner_public_status_third as third

D=('windows-cp117','/qga',1,2,'S-1-5-21-1-2-3-1002')
OLD={'state':'diagnosed','phase':'task','task':'absent','replayAllowed':False,'nativeActionAllowed':False}
class ThirdTests(TestCase):
 def admitted(self):return object(),D,'a'*64,{'socketPath':'/qga','qemuPid':1,'startTicks':2},'e'*64
 def test_all_fixed_generated_programs_compile_and_third_rechecks_prior_tasks_and_process(self):
  for name in (first._TASK,first._RETRY_TASK,first._THIRD_TASK):
   program=first._remote_for(name)
   compile(program,name,'exec')
   if name != first._TASK:
    tree=ast.parse(program)
    boots=[node for node in ast.walk(tree) if isinstance(node,ast.Assign)
           and any(isinstance(target,ast.Name) and target.id=='boot' for target in node.targets)]
    constants=[node.value for boot in boots for node in ast.walk(boot.value)
               if isinstance(node,ast.Constant) and isinstance(node.value,str)]
    self.assertFalse(any('\x0b' in value for value in constants))
    self.assertTrue(any('VPNMSIX64\\vpncp117' in value for value in constants))
  compile(third._ACTIVE_REMOTE,'<third-active-remote>','exec')
  remote=first._remote_for(first._THIRD_TASK)
  for text in (first._TASK,first._RETRY_TASK,"ACTIVE_TASK","Name='powershell.exe'"):self.assertIn(text,remote)
  self.assertLess(remote.index('ACTIVE_TASK'),remote.index('Register-ScheduledTask'))
 def test_third_intent_is_durable_and_unknown_is_never_replayed(self):
  with tempfile.TemporaryDirectory() as t,mock.patch.object(third,'_admit',return_value=self.admitted()),mock.patch.object(first,'_run_named',return_value='unknown') as run:
   root=Path(t);self.assertEqual(third.start(root,{'host':'archlinux'}),third._UNKNOWN);v=third._read(root);self.assertEqual(v['idempotencyKey'],third._CORRELATION);self.assertEqual(v['requestSha256'],third._REQUEST_SHA256)
   self.assertEqual(third.start(root,{'host':'archlinux'}),third._UNKNOWN);self.assertEqual([x.args[-2] for x in run.call_args_list],['start','status'])
 def test_admission_requires_retry_and_third_absence_and_no_active_matching_task(self):
  a=self.admitted()
  with tempfile.TemporaryDirectory() as t,mock.patch.object(first,'_admit',return_value=a),mock.patch.object(first,'diagnose',return_value=OLD),mock.patch.object(first,'_diagnostic_named',side_effect=[{'phase':'task','task':'absent'},{'phase':'task','task':'absent'}]),mock.patch.object(retry,'_preflight',return_value={'state':'ready','gate':'ready'}),mock.patch.object(third,'_active',return_value='present'):
   self.assertIsNone(third._admit(Path(t),for_start=True))

 def test_third_diagnostic_observes_fixed_task_after_owner_admission_drifts(self):
  generation={'socketPath':'/qga','qemuPid':1,'startTicks':2}
  evidence=hashlib.sha256(json.dumps(generation,sort_keys=True).encode()).hexdigest()
  value={'version':1,'correlationId':third._CORRELATION,'idempotencyKey':third._CORRELATION,
         'requestSha256':third._REQUEST_SHA256,'sourceSha':first.relaunch._SOURCE,
         'guestGeneration':generation,'evidenceSha256':evidence,'state':'intent'}
  launch={'version':1,'correlationId':first.relaunch._CORRELATION,'sourceSha':first.relaunch._SOURCE,
          'guestGeneration':generation,'staleRecoveryEvidenceSha256':evidence,'state':'launched'}
  bound=(object(),D,first.relaunch._SOURCE,'a'*64)
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);third._write(root,value)
   with mock.patch.object(first.relaunch.liveness,'_admit',return_value=bound), \
        mock.patch.object(first.relaunch,'_read_intent',return_value=launch), \
        mock.patch.object(first,'_admit',side_effect=AssertionError('live owner admission used')), \
        mock.patch.object(first,'_diagnostic_named',return_value={'phase':'task','task':'absent'}) as diagnostic:
    self.assertEqual(third.workflow(root,'third-diagnostic',{'host':'archlinux'}),
                     {'state':'diagnosed','stage':'task-observer','phase':'task','task':'absent',
                      'replayAllowed':False,'nativeActionAllowed':False})
    diagnostic.assert_called_once_with(bound[0],D,'a'*64,first._THIRD_TASK)

 def test_third_diagnostic_blocks_generation_mismatch_without_task_query(self):
  generation={'socketPath':'/qga','qemuPid':1,'startTicks':2}
  evidence=hashlib.sha256(json.dumps(generation,sort_keys=True).encode()).hexdigest()
  value={'version':1,'correlationId':third._CORRELATION,'idempotencyKey':third._CORRELATION,
         'requestSha256':third._REQUEST_SHA256,'sourceSha':first.relaunch._SOURCE,
         'guestGeneration':generation,'evidenceSha256':evidence,'state':'intent'}
  launch={'version':1,'correlationId':first.relaunch._CORRELATION,'sourceSha':first.relaunch._SOURCE,
          'guestGeneration':{**generation,'qemuPid':3},'staleRecoveryEvidenceSha256':evidence,'state':'launched'}
  bound=(object(),D,first.relaunch._SOURCE,'a'*64)
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);third._write(root,value)
   with mock.patch.object(first.relaunch.liveness,'_admit',return_value=bound), \
        mock.patch.object(first.relaunch,'_read_intent',return_value=launch), \
        mock.patch.object(first,'_diagnostic_named') as diagnostic:
    self.assertEqual(third.third_diagnostic(root,{'host':'archlinux'}),
                     {'state':'blocked','stage':'generation','replayAllowed':False,'nativeActionAllowed':False})
    diagnostic.assert_not_called()
