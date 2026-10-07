"""Current epoch discovery after actual expired-owner CONFLICT, no guest."""
import tempfile,ast,copy,hashlib,json,os,stat,types,unittest
from pathlib import Path
from unittest import mock
from agent_tools import android_api29_current_owner_observation as observer
from agent_tools.tests import test_android_api29_current_permission_observation as previous
ROOT=Path(__file__).resolve().parents[2]
from agent_tools.tests.fixtures.android_api29_epoch.adjacent import AdjacentContext
CURRENT='6373d143-1372-4835-a89b-baafb0959b9f'

def scope():
 env=previous.scope();exec(observer._OBSERVER,env);calls=[];ledger=[]
 def cli(words,owner=None):
  calls.append((words,owner));ok=owner in (None,CURRENT)
  return {'returncode':0 if ok else 1,'stderrRaw':'','stdout':{'ok':ok,'final':True,'code':'OK' if ok else 'CONFLICT','controllerId':CURRENT,'configurationRevision':0,'data':{'runtimeRunning':False,'runtimeObservation':'stopped','configuredMode':'vpn','operations':copy.deepcopy(ledger)}}}
 env['getter_cli']=cli;return env,calls,ledger

class CurrentOwnerTests(unittest.TestCase):
 def test_actual_conflict_old_bound_epoch_red_new_discovery_green(self):
  env,calls,ledger=scope();old=previous.scope();old['getter_cli']=env['getter_cli'];result=old['observed_getter'](Path('/inert'));self.assertFalse(result['permissionObserved']);self.assertEqual('permission_public_unavailable',result['reason'])
  calls.clear();result=env['observed_getter'](Path('/inert'));self.assertTrue(result['ownerObserved']);self.assertEqual(CURRENT,result['controllerId']);self.assertTrue(result['ledgerEmpty']);self.assertEqual(5,len(calls));self.assertIsNone(calls[0][1]);self.assertTrue(all(owner==CURRENT for _,owner in calls[1:]))
  self.assertEqual([['status'],['operations','list'],['status'],['operations','list'],['status']],[words for words,_ in calls])
  for key in ('permissionObserved','exportSubmitted','endpointAdmitted','productAdmitted','acceptanceComplete','replayAllowed'):self.assertIs(result[key],False)
 def test_nonempty_ledger_is_recorded_and_never_declared_empty(self):
  env,calls,ledger=scope();ledger.append({'id':'owned historical operation','final':True});result=env['observed_getter'](Path('/inert'));self.assertTrue(result['ownerObserved']);self.assertFalse(result['ledgerEmpty']);self.assertEqual(ledger,result['operations'])
 def test_epoch_revision_runtime_and_ledger_drift_reject(self):
  for field,value in (('controllerId',observer.original.OWNER),('configurationRevision',False),('configurationRevision',1)):
   env,calls,ledger=scope();original=env['getter_cli']
   def cli(*args):
    r=original(*args)
    if len(calls)==3:r['stdout'][field]=value
    return r
   env['getter_cli']=cli;result=env['observed_getter'](Path('/inert'));self.assertFalse(result['ownerObserved']);self.assertTrue(result['closingGuardsVerified'])
  env,calls,ledger=scope();original=env['getter_cli']
  def cli(*args):
   r=original(*args)
   if len(calls)==4:r['stdout']['data']['operations']=[{'foreign':True}]
   return r
  env['getter_cli']=cli;self.assertEqual('owner_ledger_changed',env['observed_getter'](Path('/inert'))['reason'])
 def test_failed_public_read_preserves_raw_and_closes_generation_stage(self):
  env,calls,ledger=scope();env['getter_cli']=lambda *a:{'returncode':1,'stderrRaw':'pure virtual method called\nterminate called without an active exception\n','stdout':{'ok':False,'final':True,'code':'UNAVAILABLE','controllerId':CURRENT,'configurationRevision':0,'data':{}}};result=env['observed_getter'](Path('/inert'));self.assertFalse(result['ownerObserved']);self.assertTrue(result['closingGuardsVerified']);self.assertIn('pure virtual method called',result['records']['statusDiscovery']['stderrRaw']);self.assertIsNone(result['controllerId'])
 def test_guest_apk_stage_drift_rejects(self):
  env,_,_=scope();env['original_status']=lambda _:{};self.assertFalse(env['observed_getter'](Path('/inert'))['ownerObserved'])
  env,_,_=scope();env['getter_apk']=lambda:'changed';self.assertEqual('getter_package_changed',env['observed_getter'](Path('/inert'))['reason'])
  env,_,_=scope();pins=iter([{'gen':1},{'gen':2}]);env['getter_stage']=lambda:next(pins);result=env['observed_getter'](Path('/inert'));self.assertFalse(result['ownerObserved']);self.assertFalse(result['closingGuardsVerified'])
 def test_source_before_factory_rejects_consistent_changed_bytes(self):
  temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);context=AdjacentContext(Path(temporary.name))
  context.owner_prepared()
  actual=observer.availability._snapshot
  def changed(path):
   pin,raw=actual(path);return (pin,raw+b'\n') if Path(path)==Path(context.permission.__file__).absolute() else (pin,raw)
  with mock.patch.object(observer.availability,'_snapshot',side_effect=changed),mock.patch.object(context.permission,'prepare') as factory:
   with self.assertRaisesRegex(ValueError,'owner_original_source_changed'):context.owner_prepared()
   factory.assert_not_called()
 def test_actual_full_generated_prefix_dispatch_tail_and_no_mutating_definitions(self):
  temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);context=AdjacentContext(Path(temporary.name))
  prepared=context.owner_prepared();tree=ast.parse(prepared['program']);emitted=[]
  self.assertFalse({'permission_diagnostics','permission_parse','diagnostic_export','journal_write','write_capsule'}&{n.name for n in tree.body if isinstance(n,ast.FunctionDef)})
  for index in range(len(tree.body)-1,-1,-1):
   text=ast.unparse(tree.body[index])
   if text.startswith('_failed = read_fixed('):tree.body.insert(index,ast.parse('HOST_HISTORY(globals())').body[0])
   elif text=='alias_history_guard()':tree.body.insert(index,ast.parse('alias_history_guard=HOST_ALIAS').body[0])
  tree.body.insert(-1,ast.parse('HOST_INSTALL(globals())').body[0]);pin=[1]*9
  class Directory:
   name='inert-original-journal'
   def lstat(self):return types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o700)
  class Root:
   def __truediv__(self,_):return Directory()
  for fail in (None,'tail','intent','owner'):
   emitted.clear()
   def install(ns):
    env,calls,ledger=scope();proxy=types.SimpleNamespace(**vars(os));proxy.getuid=lambda:0;proxy.geteuid=lambda:0;proxy.open=lambda *a,**k:8;proxy.close=lambda _:None
    info=types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o600,st_nlink=1);rootinfo=types.SimpleNamespace(st_uid=1000,st_mode=stat.S_IFDIR|0o700);proxy.fstat=lambda fd:rootinfo if fd==7 else info;proxy.stat=lambda *a,**k:info;checks=[0]
    def guard(_):
     checks[0]+=1
     if fail=='tail' and checks[0]==4:raise ValueError('tail_changed')
    if fail=='owner':env['getter_cli']=lambda *a:{'returncode':1,'stdout':{'code':'CONFLICT'}}
    ns.update({k:env[k] for k in ('getter_generation','getter_stage','getter_cli','getter_envelope')})
    ns.update(getter_apk=lambda:ns['GETTER']['packageSha256'],ROOT=Root(),os=proxy,parent_fds=lambda _:([{'fd':7,'pin':pin}],None),guard_parents=guard,close_parents=lambda _:None,fp=lambda _:pin,journal_read=lambda *a:{} if fail=='intent' else ns['LAUNCH']['intent'],fcntl=types.SimpleNamespace(LOCK_EX=1,LOCK_NB=2,flock=lambda *a:None),print=lambda line:emitted.append(json.loads(line)))
   host={'HOST_INSTALL':install,'HOST_HISTORY':lambda ns:ns.update(read_fixed=lambda *a:{**ns['CFG']['failedCensus']['pin'],'raw':b''}),'HOST_ALIAS':lambda:None}
   if fail in ('tail','intent'):
    with self.assertRaises(ValueError):exec(compile(ast.fix_missing_locations(tree),'<actual-current-owner>','exec'),host)
    self.assertEqual([],emitted)
   else:
    exec(compile(ast.fix_missing_locations(tree),'<actual-current-owner>','exec'),host);self.assertEqual(1,len(emitted));self.assertEqual(fail is None,emitted[0]['ownerObserved']);self.assertFalse(emitted[0]['exportSubmitted'])
