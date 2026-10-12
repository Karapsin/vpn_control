import ast, os, unittest, uuid
from pathlib import Path
N=Path(__file__).resolve().parent
SOURCE=Path(os.environ.get('LINUX_CLEANUP_SOURCE',Path(__file__).resolve().parents[2]/'scripts/test_linux_public_install.py'))
tree=ast.parse(SOURCE.read_text())
helpers=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in('require','close_recovered_fixture_owner')]
ns={'uuid':uuid};exec(compile(ast.Module(body=helpers,type_ignores=[]),'actual-helpers','exec'),ns)
run=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='run')
cleanup_try=next(n for n in ast.walk(run)if isinstance(n,ast.Try)and any(isinstance(x,ast.Call)and isinstance(x.func,ast.Name)and x.func.id=='cleanup_synthetic_workspace'for s in n.body for x in ast.walk(s)))
prefix=[]
for statement in cleanup_try.body:
 prefix.append(statement)
 if any(isinstance(x,ast.Call)and isinstance(x.func,ast.Name)and x.func.id=='cleanup_synthetic_workspace'for x in ast.walk(statement)):break
CODE=compile(ast.Module(body=prefix,type_ignores=[]),'actual-cleanup-flow','exec')

class RecoveredOwnerCleanupTests(unittest.TestCase):
 def invoke_flow(self,runtime=False,changed=False,bad_quit=False):
  controller='6767f51c-ba54-4a3f-808e-bbcc3f7155df';events=[];state={'live':True,'cleaned':False}
  def ok(*args):
   self.assertEqual(args[:2],('--controller-id',controller));events.append(args[-1])
   if args[-1]=='status':return {'controllerId':str(uuid.uuid4())if changed else controller,'data':{'runtimeRunning':runtime},'final':True}
   self.assertEqual(args[-1],'quit');state['live']=False
   return {'controllerId':controller,'final':not bad_quit}
  def cleanup(*args,**kwargs):
   events.append('cleanup')
   if state['live']:raise RuntimeError('replacement owner still references workspace')
   state['cleaned']=True
  scope={**ns,'result':{},'recovery':{'controllerId':controller},'ok':ok,'cleanup_synthetic_workspace':cleanup,'workspace':Path('/synthetic/workspace'),'evidence':Path('/synthetic'),'owner':object(),'recovery_proven':True,'credential_restored':True}
  error=None
  try:exec(CODE,scope)
  except RuntimeError as e:error=e
  return error,events,state
 def test_replacement_owner_is_quit_before_actual_cleanup_path(self):
  error,events,state=self.invoke_flow();self.assertIsNone(error);self.assertEqual(events,['status','quit','cleanup']);self.assertTrue(state['cleaned'])
 def test_running_runtime_preserves_owner_and_workspace(self):
  error,events,state=self.invoke_flow(runtime=True);self.assertIsNotNone(error);self.assertEqual(events,['status']);self.assertTrue(state['live']);self.assertFalse(state['cleaned'])
 def test_changed_controller_preserves_owner_and_workspace(self):
  error,events,state=self.invoke_flow(changed=True);self.assertIsNotNone(error);self.assertEqual(events,['status']);self.assertTrue(state['live']);self.assertFalse(state['cleaned'])
 def test_unknown_quit_retains_workspace(self):
  error,events,state=self.invoke_flow(bad_quit=True);self.assertIsNotNone(error);self.assertEqual(events,['status','quit']);self.assertFalse(state['cleaned'])

if __name__=='__main__':unittest.main()
