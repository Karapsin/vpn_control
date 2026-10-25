"""Complete retained modules, actual source holders/TCP; no native/private input."""
from pathlib import Path
from contextlib import ExitStack
import ast,hashlib,json,os,sys,tempfile,types,unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[2];FIXTURE=Path(__file__).parent/'fixtures/tart_macos_legacy_rfb_epoch';B=FIXTURE
from agent_tools import readiness_tart_macos_legacy_public_resolution as livepublic
from agent_tools import readiness_tart_macos_legacy_phases as livephases
from agent_tools import readiness_tart_macos_registry as registry
from agent_tools import readiness_tart_macos_unlock_qualification as Q
from agent_tools.tests import test_tart_macos_legacy_public_resolution as existing
sha=lambda b:hashlib.sha256(b).hexdigest()
def load(path,name,expected=None):
 raw=path.read_bytes()
 if expected is not None:assert sha(raw)==expected
 m=types.ModuleType('agent_tools._controlled_'+name);m.__file__=str(path);m.__package__='agent_tools';exec(compile(raw,str(path),'exec',dont_inherit=True),m.__dict__);return m
oldpublic=load(B/'readiness_tart_macos_legacy_public_resolution.before.source','public_old',
 'a5586f07d6af00712e22c98ffeaa80f57595dc55780a1feecfac53041cbca66f')
newpublic=livepublic
oldphases=load(B/'readiness_tart_macos_legacy_phases.before.source','phases_old',
 'dfbd80e8060b54dcce522cd2fbe1fd5320d39714cfed6431b293e0e05065a67f')
newphases=livephases
HISTORICAL=Path(__file__).parent/'fixtures/tart_vnc_protected_fd_high/vnc.before.source'
a5=load(HISTORICAL,'rfb_a5','a5b5196c62cdfb2270d3f54faf3f8c318022d16a174447722a94f9d18d2b0a1d')
current=load(Path(__file__).parent/'fixtures/tart_vnc_per_event_guard/before.source','rfb_2938','2938db527eae5879ff7a7fcfde1801e447727edd57d41868f95ac8ea45cbf4c0')
@unittest.skipUnless(os.name == 'posix', 'actual source custody and TCP RFB')
class EpochTests(unittest.TestCase):
 def controlled(self,pub,rfb):
  stack=ExitStack();self.addCleanup(stack.close)
  stack.enter_context(mock.patch.object(existing,'subject',pub));stack.enter_context(mock.patch.object(existing,'rfb',rfb));stack.enter_context(mock.patch.object(pub,'rfb',rfb))
  fixture=existing.LegacyPublicResolutionTests();fixture.setUp();self.addCleanup(fixture.doCleanups);return fixture,stack
 def guard(self,phase,pub,rfb,fixture):
  with mock.patch.object(phase,'public',pub),mock.patch.object(phase,'rfb',rfb),ExitStack()as stack:
   phase._source_contract(stack,[],fixture.custody)
 def test_whole_before_current_source_contract_actual_causal(self):
  fixture,stack=self.controlled(newpublic,current)
  with mock.patch.object(oldpublic,'rfb',current):
   with self.assertRaisesRegex(registry.MacBlocked,'macos_public_proof_changed'):self.guard(oldphases,oldpublic,current,fixture)
  self.guard(newphases,newpublic,current,fixture)
  with mock.patch.object(newpublic,'rfb',a5):self.guard(newphases,newpublic,a5,fixture)
  with mock.patch.object(oldpublic,'rfb',a5),mock.patch.object(oldpublic,'_FIXED_HELPER_SHA',newpublic._FIXED_HELPER_SHA):self.guard(oldphases,oldpublic,a5,fixture)
 def test_fingerprint_is_independent_of_ast_dump_and_empty_type_params(self):
  fixture,stack=self.controlled(newpublic,current);parse=ast.parse
  def older_shape(*args,**kwargs):
   tree=parse(*args,**kwargs)
   for node in ast.walk(tree):
    if isinstance(node,(ast.FunctionDef,ast.ClassDef))and getattr(node,'type_params',None)==[]:
     del node.type_params
   return tree
  with mock.patch.object(ast,'dump',return_value='different-host-format'),mock.patch.object(ast,'parse',older_shape):
   self.guard(newphases,newpublic,current,fixture)
 def test_actual_tcp_original_transport_historical_claim_unchanged(self):
  fixture,stack=self.controlled(newpublic,current);operation,endpoint=fixture.produce();endpoint.wait_events(14)
  original=fixture.root/'public-transitions'/(operation+'.json');original_before=(original.read_bytes(),original.stat().st_ino)
  with mock.patch.object(oldpublic,'rfb',current),mock.patch.object(oldpublic,'_FIXED_HELPER_SHA',newpublic._FIXED_HELPER_SHA):
   with self.assertRaisesRegex(registry.MacBlocked,'macos_public_proof_changed'):oldpublic.observe(fixture.custody,operation)
  with newpublic.observe(fixture.custody,operation)as proof:
   report=proof.report;self.assertEqual(report['sourceProtocol']['methodReleaseProtocol'],oldpublic._RFB_SHA);self.assertEqual(report['workState'],'transport_finished');self.assertEqual(report['semanticOutcome'],'unknown');self.assertFalse(report['genericUnlockAuthority']);self.assertTrue(report['replayForbidden'])
  self.assertEqual((original.read_bytes(),original.stat().st_ino),original_before)
 def test_authentic_old_cache_new_observe_resolve_preserves_bytes(self):
  fixture,stack=self.controlled(newpublic,current);operation,endpoint=fixture.produce();endpoint.wait_events(14)
  with mock.patch.object(oldpublic,'rfb',a5),mock.patch.object(oldpublic,'_FIXED_HELPER_SHA',newpublic._FIXED_HELPER_SHA):
   historical=oldpublic.resolve(fixture.custody,operation)
  self.assertEqual(historical['sourceProtocol']['resolver'],'a5586f07d6af00712e22c98ffeaa80f57595dc55780a1feecfac53041cbca66f')
  cache=fixture.root/'legacy-public-resolutions'/(operation+'.json');before=(cache.read_bytes(),cache.stat().st_ino)
  with newpublic.observe(fixture.custody,operation)as proof:observed=proof.report
  fresh=newpublic.resolve(fixture.custody,operation);self.assertEqual(fresh,observed)
  self.assertEqual((cache.read_bytes(),cache.stat().st_ino),before)
  wrong=json.loads(before[0]);wrong['sourceProtocol']['resolver']='0'*64;fixture.write(cache,wrong)
  with self.assertRaisesRegex(Q.QualificationBlocked,'resolution_conflict'):newpublic.resolve(fixture.custody,operation)
  wrong=historical.copy();wrong['workState']='unsubmitted';fixture.write(cache,wrong)
  with self.assertRaisesRegex(Q.QualificationBlocked,'resolution_conflict'):newpublic.resolve(fixture.custody,operation)
 def test_unreviewed_whole_source_comment_blocks(self):
  fixture,stack=self.controlled(newpublic,current)
  path=fixture.project/'unreviewed-vnc.py';path.write_bytes(Path(current.__file__).read_bytes()+b'\n# unreviewed\n')
  with mock.patch.object(current,'__file__',str(path)):
   with self.assertRaisesRegex(Q.QualificationBlocked,'method_epoch_unqualified'):self.guard(newphases,newpublic,current,fixture)
 def test_loaded_method_or_constant_tamper_rejected(self):
  fixture,stack=self.controlled(newpublic,current)
  with mock.patch.object(current.ProtectedVncSession,'key',lambda *a,**k:None):
   with self.assertRaisesRegex(Q.QualificationBlocked,'method_source_changed'):self.guard(newphases,newpublic,current,fixture)
  with mock.patch.object(current,'_MODIFIERS',{'MacMeta':1}):
   with self.assertRaisesRegex(Q.QualificationBlocked,'method_source_changed'):self.guard(newphases,newpublic,current,fixture)
 def test_secret_loaded_method_tamper_rejected(self):
  fixture,stack=self.controlled(newpublic,current)
  with mock.patch.object(current.ProtectedVncSession,'type_secret_from_fd',lambda *a,**k:None):
   with self.assertRaisesRegex(Q.QualificationBlocked,'method_epoch_unqualified'):self.guard(newphases,newpublic,current,fixture)
 def test_live_source_inode_replacement_loses_held_proof(self):
  fixture,stack=self.controlled(newpublic,current);path=fixture.project/'vnc.py';path.write_bytes(Path(current.__file__).read_bytes());other=fixture.project/'replacement.py'
  with mock.patch.object(current,'__file__',str(path)),ExitStack()as held:
   source=newpublic._hold_method_source(held);other.write_bytes(path.read_bytes());other.replace(path)
   with self.assertRaises((registry.MacBlocked,ValueError)):source.guard()
 def test_historical_ast_fingerprint_rejects_changed_transport_even_if_epoch_misconfigured(self):
  fixture,stack=self.controlled(newpublic,current);path=fixture.project/'wrong.py';raw=Path(current.__file__).read_bytes();changed=raw.replace(b'struct.pack("!BBHI", 4, int(down), 0, keysym)',b'struct.pack("!BBHI", 4, int(down), 1, keysym)')
  # Even a mistakenly added epoch cannot authorize changed transport AST.
  # The tampered module is only inspected, never dispatched as input authority.
  if changed==raw:
   changed=raw.replace(b'0xFFE9',b'0xFFEA',1).replace(b'0xffe9',b'0xffea',1)
  self.assertNotEqual(changed,raw);path.write_bytes(changed);wrong=load(path,'rfb_wrong')
  with mock.patch.object(newpublic,'rfb',wrong),mock.patch.object(newpublic,'_LIVE_RFB_SHAS',newpublic._LIVE_RFB_SHAS|{sha(changed)}),mock.patch.object(newphases,'rfb',wrong):
   with self.assertRaisesRegex(Q.QualificationBlocked,'method_source_changed'):self.guard(newphases,newpublic,wrong,fixture)
if __name__=='__main__':unittest.main()
