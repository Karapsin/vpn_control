import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from agent_tools import ssh_tmux_terminal_closure as c

@unittest.skipUnless(os.name == 'posix' and c.pipe is not None and c.fcntl is not None,
                     'POSIX descriptor-relative coordinator and flock required')
class ClosureTests(unittest.TestCase):
 def remote(self):
  return {'state':'completed-unreferenced','request':c.old.purpose(c.pipe.REQUEST),'hostBootId':'d93cd8dd-a62f-480a-abd8-478be5cc1d21','terminal':{'state':'terminal','correlationId':c.CORRELATION,'exitCode':0,'terminalPin':c.pipe.TERMINAL,'artifactVerification':'required','replayAllowed':False},'anchorPin':c.pipe.ANCHOR,'stagePin':c.pipe.STAGE,'observations':[{'complete':True,'originalPaneEnded':True,'references':[],'rowCount':4,'tableSha256':'a'*64} for _ in range(2)],'nativeActionAllowed':False,'replayAllowed':False}
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
  (self.root/'.rag_index').mkdir(mode=0o700);self.journal=self.root/c.build._JOURNAL;self.journal.mkdir(mode=0o700)
  self.claim=self.journal/'archlinux.claim';self.original=c.pipe._write_once(self.claim,b'original-claim')
  self.reservations=self.root/'.rag_index/reservations';c.pipe._write_once(self.reservations,b'keep-8GiB')
  self.local={'snapshot':{},'sources':{},'pins':{str(self.claim.relative_to(self.root)):self.original},'artifacts':[{}]*10,'outputProof':{}}
 def fixed(self,*args,**kwargs):args[3]();return self.remote(),{'private':'retained'}
 def observe(self):
  with mock.patch.object(c,'local_proof',return_value=self.local),mock.patch.object(c,'guard_local'),mock.patch.object(c,'fixed_query',side_effect=self.fixed):return c.observe(self.root)
 def identity(self,proof):return {k:proof[k] for k in ('proofId','proofPin')}
 def test_old_completed_job_rejects_unsupported_local_worker_layout(self):
  root=Path(__file__).resolve().parents[2];job=root/c.build._JOURNAL/c.CORRELATION
  if not job.exists():self.skipTest('retained completed86 absent')
  self.assertFalse((job/'state.json').exists());self.assertFalse((job/'worker-pid.json').exists())
  self.assertEqual('unknown',c.build.terminal_ready_status(root,{'correlationId':c.CORRELATION})['state'])
 def test_full_observe_archive_history_and_idempotence(self):
  proof=self.observe();identity=self.identity(proof)
  with mock.patch.object(c,'local_proof',return_value=self.local),mock.patch.object(c,'guard_local'),mock.patch.object(c,'fixed_query',side_effect=self.fixed) as query:
   self.assertEqual('closed',c.close(self.root,identity)['state']);self.assertFalse(self.claim.exists())
   c.pipe._write_once(self.claim,b'new-owner')
   self.assertEqual('closed',c.close(self.root,identity)['state']);self.assertEqual(1,query.call_count)
  self.assertEqual(b'keep-8GiB',self.reservations.read_bytes());self.assertEqual(b'original-claim',(self.root/'.rag_index/ssh-tmux-terminal-closure'/identity['proofId']/'archived-claim').read_bytes())
 def test_remote_live_or_referenced_and_private_extra_rejected(self):
  for mutation in (lambda x:x['observations'][0].update(originalPaneEnded=False),lambda x:x['observations'][1].update(references=[[12,30]]),lambda x:x.update(private='/secret'),lambda x:x['terminal'].update(exitCode=False),lambda x:x['observations'][0].update(tableSha256='z'*64)):
   value=self.remote();mutation(value)
   with self.assertRaises(ValueError):c.validate_remote(value)
 def test_refusal_after_fence_is_consumed_unknown_no_replay(self):
  identity=self.identity(self.observe())
  with mock.patch.object(c,'local_proof',return_value=self.local),mock.patch.object(c,'guard_local'),mock.patch.object(c,'fixed_query',side_effect=ValueError('live')):
   with self.assertRaises(ValueError):c.close(self.root,identity)
  with mock.patch.object(c,'fixed_query') as query:
   self.assertEqual('unknown',c.close(self.root,identity)['state']);query.assert_not_called()
  self.assertTrue(self.claim.exists())
 def test_local_drift_before_effect_no_archive(self):
  identity=self.identity(self.observe())
  with mock.patch.object(c,'local_proof',return_value={}),mock.patch.object(c,'_rename') as effect:
   with self.assertRaises(ValueError):c.close(self.root,identity)
   effect.assert_not_called()
 def test_concurrent_claim_owner_blocked(self):
  with c.claim_lock(self.root):
   with self.assertRaises(BlockingIOError):
    with c.claim_lock(self.root):pass
 def test_exclusive_archive_does_not_overwrite(self):
  target=self.root/'.rag_index/target';target.mkdir(mode=0o700);c.pipe._write_once(target/'archived',b'foreign')
  with c.Directory(self.journal) as source,c.Directory(target) as dest:
   with self.assertRaises(ValueError):c._rename(source,'archlinux.claim',dest,'archived')
  self.assertEqual(b'foreign',(target/'archived').read_bytes());self.assertTrue(self.claim.exists())
 def test_generated_program_preserves_guards_and_no_effect_dispatch(self):
  program=c.remote_program();compile(program,'<test>','exec')
  self.assertNotIn("result=ns['start']",program);self.assertNotIn("result=ns['release']",program)
  self.assertIn('closure_workspace_referenced',program);self.assertIn('closure_original_worker_live',program)
  self.assertIn("ns['source_pin'](source,request)",program)
 def test_same_byte_generation_replacement_rejected(self):
  local={'sources':{},'snapshot':{},'pins':{str(self.claim.relative_to(self.root)):self.original}}
  replacement=self.claim.with_suffix('.replacement');c.pipe._write_once(replacement,b'original-claim');os.replace(replacement,self.claim)
  with mock.patch.object(c,'_sources',return_value={}),mock.patch.object(c.adapter.McpTmuxDriver,'_guard'),mock.patch.object(c.adapter.McpTmuxDriver,'__init__',return_value=None):
   with self.assertRaises(ValueError):c.guard_local(self.root,local)

 def test_actual_generated_census_rejects_live_and_nul_token_reference(self):
  import types
  proc=self.root/'proc';proc.mkdir();(proc/'sys/kernel/random').mkdir(parents=True);(proc/'sys/kernel/random/boot_id').write_text('d93cd8dd-a62f-480a-abd8-478be5cc1d21')
  job=self.root/'remote-job';job.mkdir()
  process=proc/'123';process.mkdir()
  fields=['S']+['0']*20;fields[19]='456';(process/'stat').write_bytes(('123 (worker) '+' '.join(fields)).encode());(process/'cmdline').write_bytes(b'other\0'+str(job/'result').encode()+b'\0');(process/'cwd').symlink_to(self.root)
  class Paths:
   @staticmethod
   def Path(value):return proc/str(value)[6:] if str(value).startswith('/proc/') else proc if str(value)=='/proc' else Path(value)
  source=c._CENSUS.replace('FIXED_REQUEST',repr(c.old.purpose(c.pipe.REQUEST))).replace('FIXED_STAGE',repr(c.pipe.STAGE)).replace('FIXED_ANCHOR',repr(c.pipe.ANCHOR)).replace('FIXED_TERMINAL',repr(c.pipe.TERMINAL))
  value=self.remote()
  namespace={'pathlib':Paths,'os':os,'hashlib':c.hashlib,'json':json,'payload':{'action':'status','request':value['request'],'stagePin':c.pipe.STAGE,'anchorPin':c.pipe.ANCHOR},'action':'status','request':value['request'],'job':job,'source':job/'source','ns':{'status':lambda *args:value['terminal'],'_anchor':lambda *args:{'pane':{'pid':123,'startTicks':456}}}}
  with self.assertRaisesRegex(ValueError,'closure_original_worker_live'):exec(source,namespace)
  namespace['ns']['_anchor']=lambda *args:{'pane':{'pid':321,'startTicks':654}}
  with self.assertRaisesRegex(ValueError,'closure_workspace_referenced'):exec(source,namespace)
  (process/'cmdline').write_bytes(b'other\0');exec(source,namespace);self.assertEqual('completed-unreferenced',namespace['result']['state'])


class ClosurePortableSchemaTests(unittest.TestCase):
 def test_unsupported_coordinator_fails_before_private_journal(self):
  with mock.patch.object(c.os,'name','nt'):
   with self.assertRaisesRegex(ValueError,'unsupported_coordinator_platform'):
    with c.claim_lock(Path('/not-a-private-journal')):pass
 def test_public_closure_identity_malformed_rejected_before_private_reads(self):
  for identity in ({},{'proofId':False,'proofPin':{}},{'proofId':'not-a-uuid','proofPin':{}}):
   with self.subTest(identity=identity),self.assertRaises((ValueError,TypeError)):
    c.status(Path.cwd(),identity)
