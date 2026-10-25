"""Actual held SourceSession/journal before RED/current eager snapshot GREEN.
Complete old readiness executes in a finite copied source package. No ignored
runtime input, remote adapter, SSH, creator, credential or original journal read.
"""
from contextlib import contextmanager,closing
import hashlib,json,os,tempfile,unittest
from pathlib import Path
from uuid import uuid4
from unittest import mock
from agent_tools import readiness,private_inventory_lock,native_review_source_closure
from agent_tools.source_module_loader import SourceSession
HERE=Path(__file__).resolve().parent/'fixtures/readiness_journal_source_custody'
BEFORE_SHA='b218d0e477d29bd2150bf9b02bff18c0a9e0a2ff1dc02ccdb08409dbabf1e078'
class FixtureIntegrityTests(unittest.TestCase):
 def test_complete_before_source_is_literal_sha_authenticated(self):
  self.assertEqual(hashlib.sha256((HERE/'before.source').read_bytes()).hexdigest(),BEFORE_SHA)
  self.assertEqual(json.loads((HERE/'provenance.json').read_text())['sourceSha256'],{'before.source':BEFORE_SHA})

@unittest.skipUnless(os.name=='posix','readiness private journal/source custody requires POSIX')
class JournalCustodyTests(unittest.TestCase):
 @contextmanager
 def setup_source(self,before=False):
  FixtureIntegrityTests().test_complete_before_source_is_literal_sha_authenticated()
  with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve(),prefix='source-journal-')as td:
   root=Path(td);root.chmod(0o700);tools=root/'agent_tools';tools.mkdir(mode=0o700);journals=root/'journal';journals.mkdir(mode=0o700)
   # Exact finite three source roles; no package glob or repository discovery.
   copies={'readiness.py':(HERE/'before.source').read_bytes()if before else Path(readiness.__file__).read_bytes(),
     'private_inventory_lock.py':Path(private_inventory_lock.__file__).read_bytes(),
     'native_review_source_closure.py':Path(native_review_source_closure.__file__).read_bytes()}
   for name,body in copies.items():(tools/name).write_bytes(body)
   with closing(SourceSession(tools,'readiness'))as session:
    r=session.module;journal=r.RecoveryJournal(journals)
    # Actual current source context enters native private Directory/Snapshot/
    # flock and SourceSession __enter__ instruments the yielded journal class.
    with session.hold_result(journal.locked())as held:held.lookup('initial-absence')
    yield session,r,journal,journals
    session.guard()
 def adapter(self,r,healthy=True):
  class Adapter:
   capabilities=frozenset({'reconnect'})
   def __init__(self):self.effects=[];self.original_observations=[]
   def observe(self,requirements,deadline):
    return r.Observation(target='fixture',machine='machine-a',trusted=True,integrity=True,
      transport='ready'if healthy else'dead',connection='connection-a'if healthy else None,
      boot='boot-a'if healthy else None,account='1000:recovery'if healthy else None,guest='running'if healthy else'unknown')
   def observe_recovery(self,action,recovery,observed,deadline,attempt,digest):
    self.original_observations.append((action,recovery,attempt,digest));return None
   def recover(self,*args):self.effects.append(args);raise AssertionError('no replacement effect permitted')
  return Adapter()
 def test_authentic_whole_before_healthy_fails_masked_current_ready_without_recovery(self):
  for before in (True,False):
   with self.subTest(before=before),self.setup_source(before)as(s,r,j,root):
    a=self.adapter(r);c=r.Context('fixture','machine-a',a,j);requirements=r.Requirements(frozenset({'transport'}),frozenset({'reconnect'}));operation=str(uuid4())
    if before:
     with self.assertRaises(r.ReadinessBlocked)as error:r.ensure_ready(c,requirements,operation)
     self.assertEqual(error.exception.reason,'readiness_journal_unavailable')
    else:
     ready=r.ensure_ready(c,requirements,operation);self.assertEqual(ready.connection,'connection-a');r.revalidate(c,ready)
    self.assertEqual(a.effects,[]);self.assertEqual(a.original_observations,[])
 def pending(self,r,j,operation,*,suffix='1'):
  key='transport:'+operation+':'+suffix+':0';recovery=hashlib.sha256(key.encode()).hexdigest()
  intent={'version':2,'action':'reconnect','recoveryId':recovery,'target':'fixture','machine':'machine-a','boot':None,'account':None,'session':None,'originalOperationId':operation}
  with j.locked()as held:
   held.record(key,intent);dispatch=held.next_dispatch(intent);self.assertTrue(held.consume_dispatch(dispatch))
  return intent,dispatch
 def test_consumed_unknown_same_original_observed_no_new_dispatch_or_effect(self):
  with self.setup_source()as(s,r,j,root):
   operation=str(uuid4());intent,dispatch=self.pending(r,j,operation);before={p.name:p.read_bytes()for p in root.iterdir()};a=self.adapter(r,False)
   class Clock:
    now=1000.
    def clock(self):return self.now
    def sleep(self,seconds):self.now+=seconds
   clock=Clock();c=r.Context('fixture','machine-a',a,j,clock=clock.clock,sleep=clock.sleep,deadline=1005.)
   with self.assertRaises(r.ReadinessBlocked)as error:r.ensure_ready(c,r.Requirements(frozenset({'transport'}),frozenset({'reconnect'})),operation)
   self.assertEqual(error.exception.reason,'recovery_outcome_unknown');self.assertEqual(a.effects,[])
   self.assertEqual(a.original_observations,[('reconnect',intent['recoveryId'],1,dispatch['dispatchDigest'])])
   self.assertEqual(before,{p.name:p.read_bytes()for p in root.iterdir()})
 def test_materialized_authenticated_snapshot_has_no_late_iteration_reads(self):
  with self.setup_source()as(s,r,j,root):
   operation=str(uuid4());intent,dispatch=self.pending(r,j,operation);a=self.adapter(r,False)
   with j.locked()as held:
    result=held.pending_dispatches(a.observe(None,None));self.assertIs(type(result),tuple);self.assertEqual(result,(dispatch,))
    # Closing the exact original after the snapshot does not mutate it or
    # authorize replay. Subsequent snapshot observes the positive closure.
    held._publish_named('completed-'+intent['recoveryId']+'.json',{'version':1,'recoveryId':intent['recoveryId'],'state':'observed'})
    self.assertEqual(tuple(result),(dispatch,));self.assertEqual(held.pending_dispatches(a.observe(None,None)),())
 def test_malformed_matching_history_refuses_before_yield(self):
  with self.setup_source()as(s,r,j,root):
   key='malformed';rid=hashlib.sha256(key.encode()).hexdigest()
   with j.locked()as held:
    held.record(key,{'version':2,'recoveryId':rid,'target':'fixture','machine':'machine-a','action':'reconnect'})
    with self.assertRaisesRegex(ValueError,'recovery_identity_mismatch'):held.pending_dispatches(self.adapter(r,False).observe(None,None))
 def test_bounded_history_overflow_still_refuses(self):
  with self.setup_source()as(s,r,j,root):
   with j.locked()as held,mock.patch.object(r.os,'listdir',return_value=['bounded-control']*30001):
    with self.assertRaisesRegex(ValueError,'recovery_history_bound'):held.pending_dispatches(self.adapter(r,False).observe(None,None))
 def test_generic_lazy_export_refusal_remains_strict(self):
  with self.setup_source()as(s,r,j,root):
   def unrelated_lazy():yield 'never-exported'
   with self.assertRaisesRegex(ValueError,'lazy_adapter_exports_require_explicit_custody'):s.wrap(unrelated_lazy)()
if __name__=='__main__':unittest.main(verbosity=2)
