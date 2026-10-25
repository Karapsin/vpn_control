"""Actual SourceSession default original-lease route; owned temp metadata only."""
from pathlib import Path
import ast,json,time,hashlib,tempfile,unittest,sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT));F=Path(__file__).with_name('fixtures')/'tart_macos_profile_preload';CURRENT=ROOT/'agent_tools/readiness_tart_macos_unlock_qualification.py'
from agent_tools.source_module_loader import SourceSession

def literal(path,name):
 tree=ast.parse(path.read_bytes());return next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id==name for t in n.targets))
def render(template):
 for marker,value in(('@@PROJECT@@',repr(str(ROOT))),('@@FIXTURE@@',repr('controlled-profile')),('@@TARGET@@',repr('tart:controlled')),('@@SOURCE_PINS@@','{}'),('@@CAPTURE_NAME@@','controlled-capture.py')):template=template.replace(marker,value)
 return template
def guard(template,s,pins):
 tree=ast.parse(render(template));keep=[n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='DiagnosticGuard'or isinstance(n,ast.FunctionDef)and n.name in{'need','source_guard'}]
 namespace={'time':time,'Path':Path,'hashlib':hashlib,'PROJECT':ROOT,'sources':s,'global_deadline':time.monotonic()+120,'PINNED_CONSUMERS':pins};exec(compile(ast.Module(body=keep,type_ignores=[]),'actual-whole-worker-source-guard','exec'),namespace);return namespace['source_guard'],namespace['DiagnosticGuard']
def roles(s):return {str(Path(p).relative_to(ROOT)):hashlib.sha256(b).hexdigest()for p,b in s.cache.values()}
_provenance=json.loads((F/'provenance.json').read_bytes());assert _provenance['wholeBeforeSha256']==hashlib.sha256((F/'qualification.before.source').read_bytes()).hexdigest()
rows=[]
class Checks(unittest.TestCase):
 def test_actual_before_cache_grows_on_default_original_route_current_preload_stays_exact(self):
  for path,old in((F/'qualification.before.source',True),(CURRENT,False)):
   with self.subTest(old=old),tempfile.TemporaryDirectory(prefix='profile-late-source-')as tmp:
    root=Path(tmp);directory=root/'.rag_index/readiness-fixtures';directory.mkdir(parents=True,mode=0o700);p=directory/'controlled-profile.json';p.write_text('{"provider":"controlled-unqualified"}');p.chmod(0o600)
    s=SourceSession(ROOT/'agent_tools','readiness_tart_macos_registry')
    try:
     for n in literal(path,'_PROFILE_MODULES'):s.load(n)
     before=roles(s);check,error=guard(literal(path,'_PROFILE_DRIVER_TEMPLATE'),s,before);check()
     f=s.load('readiness_fixture_registry')
     # The actual source-owned default factory imports the new original route,
     # then refuses this deliberately incomplete snapshot before any custody.
     with self.assertRaises(Exception)as refusal:f.lease_executor_from_snapshot(root,{'provider':'tart-macos','kind':'qualified-tart-macos-guest-lease-v1','fixtureId':'controlled-profile'})
     self.assertIn(type(refusal.exception).__name__,{'MacLeaseBlocked','MacBlocked'})
     after=roles(s)
     if old:
      self.assertEqual(len(before),32);self.assertEqual(len(after),35)
      with self.assertRaises(error)as failure:check()
      self.assertEqual(failure.exception.args,('diagnostic_consumer_epoch_changed',))
     else:self.assertEqual(len(before),37);self.assertEqual(after,before);check()
     rows.append({'before':old,'initialCount':len(before),'afterOriginalRouteCount':len(after),'newPaths':sorted(set(after)-set(before)),'nativeCalls':0})
    finally:s.close()
 def test_finite_worker_and_issuer_preloads_and_unknown_role_refusal(self):
  path=CURRENT;names=literal(path,'_PROFILE_MODULES');required={'readiness_tart_macos_active_work_sources','readiness_tart_macos_active_work_original','readiness_tart_macos_active_work_publication'};self.assertTrue(required<=set(names));self.assertEqual(len(names),len(set(names)))
  template=literal(path,'_PROFILE_DRIVER_TEMPLATE');tree=ast.parse(render(template));loops=[n for n in tree.body if isinstance(n,ast.For)and isinstance(n.iter,ast.Tuple)];self.assertTrue(any(required<={ast.literal_eval(v)for v in n.iter.elts}for n in loops))
  s=SourceSession(ROOT/'agent_tools','readiness_tart_macos_registry')
  try:
   for n in names:s.load(n)
   before=roles(s)
   with self.assertRaises((FileNotFoundError,ImportError,ValueError,RuntimeError)):s.load('readiness_tart_macos_unreviewed_role_0')
   self.assertEqual(roles(s),before);s.guard()
  finally:s.close()
if __name__=='__main__':unittest.main(verbosity=2)
