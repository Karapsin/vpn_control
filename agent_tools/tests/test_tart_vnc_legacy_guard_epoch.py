"""Complete reviewed source contracts only; no provider or input calls."""
from pathlib import Path
from contextlib import ExitStack
import ast,hashlib,json,os,sys,tempfile,types,unittest
from unittest import mock
from agent_tools import readiness_tart_macos_unlock_qualification as Q
from agent_tools import readiness_tart_macos_legacy_phases as phases
from agent_tools import readiness_tart_macos_registry as registry
from agent_tools.tests import test_tart_macos_legacy_public_resolution as existing
HERE=Path(__file__).absolute().parent/"fixtures"/"tart_vnc_per_event_guard"
ROOT=Path(__file__).absolute().parents[2]
SOURCE_SHAS={'current.source': 'e217651bf4a277133771c6a75c5d7ded2c3d60760092bc757058d20aa294ca68', 'public-resolution.before.source': '6ebd28e4c6d91b9aa40ae2428e012177b6092666c81e265512741f00e905b409', 'before.source': '2938db527eae5879ff7a7fcfde1801e447727edd57d41868f95ac8ea45cbf4c0', 'public-resolution.current.source': 'a496960c2180702849704aab0dc949b23e3dcc3fde95313d49118c429c29c2f5', 'public-resolution-cache.before.source': '6ee6c9112b66cdba67fa8681890f6bec80bd93a5b6e3ab3f7cc6aaf79ba56bf2', 'vnc.before.source': 'a5b5196c62cdfb2270d3f54faf3f8c318022d16a174447722a94f9d18d2b0a1d'}
def load(path,name):
 raw=path.read_bytes();assert hashlib.sha256(raw).hexdigest()==SOURCE_SHAS[path.name];m=types.ModuleType('agent_tools._guard_compat_'+name);m.__file__=str(path);m.__package__='agent_tools';sys.modules[m.__name__]=m;exec(compile(raw,str(path),'exec',dont_inherit=True),m.__dict__);return m
OLD=load(HERE/'public-resolution.before.source','old')
NEW=load(HERE/'public-resolution.current.source','new')
CACHE_BEFORE=load(HERE/'public-resolution-cache.before.source','cache_before')
A5=load(ROOT/'agent_tools/tests/fixtures/tart_vnc_protected_fd_high/vnc.before.source','a5')
V2938=load(HERE/'before.source','2938')
V217=load(HERE/'current.source','e217')
def check(pub,vnc):
 with mock.patch.object(pub,'rfb',vnc):pub._method_contract(Path(vnc.__file__).read_bytes())
class Compatibility(unittest.TestCase):
 def test_complete_old_refuses_e217_current_accepts_exact_e217(self):
  with self.assertRaisesRegex(Q.QualificationBlocked,'epoch_unqualified'):check(OLD,V217)
  check(NEW,V217)
 def test_three_exact_reviewed_source_epochs_accept_without_history_change(self):
  for vnc in (A5,V2938,V217):check(NEW,vnc)
  self.assertEqual(NEW._RFB_SHA,OLD._RFB_SHA)
  self.assertEqual(NEW._HISTORICAL_RESOLVER_SHA,OLD._HISTORICAL_RESOLVER_SHA)
  self.assertEqual(NEW._TRANSPORT_AST_SHA,OLD._TRANSPORT_AST_SHA)
 def test_portable_syntax_ignores_dump_and_empty_new_type_params(self):
  parse=ast.parse
  def alternate(*a,**kw):
   tree=parse(*a,**kw)
   for x in ast.walk(tree):
    if isinstance(x,(ast.FunctionDef,ast.ClassDef))and hasattr(x,'type_params')and not x.type_params:del x.type_params
   return tree
  with mock.patch.object(ast,'dump',return_value='foreign-format'),mock.patch.object(ast,'parse',alternate):check(NEW,V217)
 def test_unchanged_whole_legacy_phase_secret_contract_accepts_e217(self):
  with mock.patch.object(phases,'public',NEW),mock.patch.object(phases,'rfb',V217),mock.patch.object(NEW,'rfb',V217):phases._secret_release_contract()
 def test_unreviewed_comment_epoch_refused(self):
  with mock.patch.object(NEW,'rfb',V217):
   with self.assertRaisesRegex(Q.QualificationBlocked,'epoch_unqualified'):NEW._method_contract(Path(V217.__file__).read_bytes()+b'\n# foreign\n')
 def test_forged_epoch_hash_without_exact_ast_mapping_refused(self):
  raw=Path(V217.__file__).read_bytes()+b'\n# foreign\n';digest=hashlib.sha256(raw).hexdigest()
  with mock.patch.object(NEW,'rfb',V217),mock.patch.object(NEW,'_LIVE_RFB_SHAS',NEW._LIVE_RFB_SHAS|{digest}):
   with self.assertRaisesRegex(Q.QualificationBlocked,'method_source_changed'):NEW._method_contract(raw)
 def test_method_code_replacement_including_secret_refused(self):
  for name in ('_character','_key'):
   with mock.patch.object(V217.ProtectedVncSession,name,lambda *a,**kw:None):
    with self.assertRaisesRegex(Q.QualificationBlocked,'method_source_changed'):check(NEW,V217)
 def test_secret_method_tamper_keeps_actual_phase_specific_reason(self):
  with mock.patch.object(V217.ProtectedVncSession,'type_secret_from_fd',lambda *a,**kw:None),mock.patch.object(phases,'public',NEW),mock.patch.object(phases,'rfb',V217),mock.patch.object(NEW,'rfb',V217):
   with self.assertRaisesRegex(Q.QualificationBlocked,'method_epoch_unqualified'):phases._secret_release_contract()
 def test_identical_code_foreign_module_globals_refused(self):
  f=V217.ProtectedVncSession._character
  foreign=types.FunctionType(f.__code__,dict(f.__globals__),f.__name__,f.__defaults__);foreign.__module__=V217.__name__
  self.assertEqual(foreign.__code__,f.__code__)
  with mock.patch.object(V217.ProtectedVncSession,'_character',foreign):
   with self.assertRaisesRegex(Q.QualificationBlocked,'method_source_changed'):check(NEW,V217)
 def test_live_constant_tamper_refused(self):
  with mock.patch.object(V217,'_MODIFIERS',{'MacMeta':1}):
   with self.assertRaisesRegex(Q.QualificationBlocked,'method_source_changed'):check(NEW,V217)
 def test_actual_predecessor_cache_is_preserved_after_fresh_current_proof(self):
  with ExitStack()as stack:
   stack.enter_context(mock.patch.object(existing,'subject',OLD));stack.enter_context(mock.patch.object(existing,'rfb',V2938));stack.enter_context(mock.patch.object(OLD,'rfb',V2938))
   fixture=existing.LegacyPublicResolutionTests();fixture.setUp();stack.callback(fixture.doCleanups)
   operation,endpoint=fixture.produce();endpoint.wait_events(14)
   historical=OLD.resolve(fixture.custody,operation)
   self.assertEqual(historical['sourceProtocol']['resolver'],'6ebd28e4c6d91b9aa40ae2428e012177b6092666c81e265512741f00e905b409')
   cache=fixture.root/'legacy-public-resolutions'/(operation+'.json');before=(cache.read_bytes(),cache.stat().st_ino)
   for pub in (CACHE_BEFORE,NEW):
    stack.enter_context(mock.patch.object(pub,'rfb',V217));stack.enter_context(mock.patch.object(pub,'_FIXED_HELPER_SHA',OLD._FIXED_HELPER_SHA))
   with self.assertRaisesRegex(Q.QualificationBlocked,'resolution_conflict'):CACHE_BEFORE.resolve(fixture.custody,operation)
   fresh=NEW.resolve(fixture.custody,operation)
   self.assertEqual(fresh['sourceProtocol']['methodReleaseProtocol'],historical['sourceProtocol']['methodReleaseProtocol'])
   self.assertEqual((cache.read_bytes(),cache.stat().st_ino),before)
   for field in ('resolver','workState'):
    wrong=json.loads(before[0])
    if field=='resolver':wrong['sourceProtocol']['resolver']='0'*64
    else:wrong['workState']='unsubmitted'
    fixture.write(cache,wrong)
    with self.assertRaisesRegex(Q.QualificationBlocked,'resolution_conflict'):NEW.resolve(fixture.custody,operation)
   endpoint.close();self.assertFalse(endpoint.thread.is_alive())
 @unittest.skipUnless(os.name=='posix','actual held source generation')
 def test_same_bytes_inode_replacement_invalidates_source_hold(self):
  with tempfile.TemporaryDirectory()as folder:
   path=Path(folder)/'rfb.py';path.write_bytes(Path(V217.__file__).read_bytes());other=Path(folder)/'other.py'
   with mock.patch.object(V217,'__file__',str(path)),mock.patch.object(NEW,'rfb',V217),ExitStack()as stack:
    held=NEW._hold_method_source(stack)
    other.write_bytes(path.read_bytes());other.replace(path)
    with self.assertRaises((registry.MacBlocked,ValueError)):held.guard()
if __name__=='__main__':unittest.main()
