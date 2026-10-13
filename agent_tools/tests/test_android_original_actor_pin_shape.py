import ast,base64,hashlib,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
D=Path(__file__).resolve().parent
mode=os.environ.get('VPN_CONTROL_ACTOR_PIN_BEFORE','fixed')
BEFORE=D/'fixtures/api35_original_actor_pin_before.source';FIXED=D/'fixtures/api35_original_actor_pin_fixed.source'
tree=ast.parse((BEFORE if mode=='before'else FIXED).read_bytes())
@unittest.skipUnless(os.name=='posix'and hasattr(os,'O_NOFOLLOW'),'Arch fake-proc FD behavior requires POSIX')
class RealFakeProc(unittest.TestCase):
 def scene(self,start=72285068,uid=1000,host_uid=1000,boot='25515f23-b966-4c3a-ae63-d38452375578',live=True):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);root=Path(self.tmp.name).resolve();proc=root/'proc';proc.mkdir();(proc/'sys/kernel/random').mkdir(parents=True);(proc/'sys/kernel/random/boot_id').write_text(boot+'\n')
  pid=1169929;folder=proc/str(pid)
  if live:
   folder.mkdir();fields=['S','100','0','100']+['0']*15+[str(start)]+['0']*10
   (folder/'stat').write_text(str(pid)+' (python3) '+' '.join(fields)+'\n');(folder/'cmdline').write_bytes(b'python3\0owned-worker\0');(folder/'status').write_bytes(('Uid:\t'+(' '.join([str(uid)]*4))+'\nGid:\t1000 1000 1000 1000\n').encode())
  real_open=os.open;real_exists=os.path.lexists
  def mapped(p):
   text=str(p)
   return proc/text[6:]if text.startswith('/proc/')else Path(p)
  def opening(path,*a,**k):return real_open(mapped(path),*a,**k)
  self.enterContext(patch.object(os,'open',side_effect=opening));self.enterContext(patch.object(os.path,'lexists',side_effect=lambda p:real_exists(mapped(p))));self.enterContext(patch.object(os,'getuid',return_value=host_uid))
  ns={'os':os,'Path':mapped,'hashlib':hashlib,'base64':base64}
  actual_tree=getattr(self,'emitted_tree',tree)
  actors=next(n for n in actual_tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='ACTORS'for t in n.targets))
  funcs=[n for n in actual_tree.body if isinstance(n,ast.FunctionDef)and n.name in ['actor','procraw','original_actor_pin_guard']]
  exec(compile(ast.Module(body=[actors,*funcs],type_ignores=[]),'<actual-actor-caller-and-proc-functions>','exec'),ns)
  return ns,proc
 def test_actual_matching_pid_start_criterion(self):
  ns,_=self.scene();value=ns['actor']('worker',ns['ACTORS']['worker']);self.assertEqual(value['state'],'matching');self.assertEqual(value['pid'],1169929);self.assertEqual(value['startTicks'],72285068)
 def test_matching_actor_is_live_not_absent(self):
  ns,_=self.scene();value=ns['actor']('worker',ns['ACTORS']['worker']);self.assertNotEqual(value['state'],'absent')
 def test_reused_start_not_admitted(self):
  ns,_=self.scene(start=72285069);self.assertEqual(ns['actor']('worker',ns['ACTORS']['worker'])['state'],'reused')
 def test_absence_has_exact_numeric_original_identity(self):
  ns,_=self.scene(live=False);value=ns['actor']('worker',ns['ACTORS']['worker']);self.assertEqual(value,{'state':'absent','pid':1169929,'expectedStartTicks':72285068})
 @unittest.skipIf(mode=='before','historical private f52 caller guard coverage')
 def test_malformed_pins_refuse_before_proc(self):
  ns,_=self.scene()
  for value in [{'pid':1169929,'startTicks':72285068},[1169929,72285068],(True,72285068),(1169929,0),(1169929,72285069)]:
   with self.subTest(value=value):
    ns['ACTORS']['worker']=value
    with self.assertRaisesRegex(ValueError,'original_actor_pin_invalid'):ns['original_actor_pin_guard']()
 @unittest.skipIf(mode=='before','historical private f52 caller guard coverage')
 def test_wrong_host_uid_refuses(self):
  ns,_=self.scene(host_uid=1001)
  with self.assertRaisesRegex(ValueError,'original_actor_host_guard'):ns['original_actor_pin_guard']()
 @unittest.skipIf(mode=='before','historical private f52 caller guard coverage')
 def test_wrong_host_boot_refuses(self):
  ns,_=self.scene(boot='wrong-boot')
  with self.assertRaisesRegex(ValueError,'original_actor_host_guard'):ns['original_actor_pin_guard']()
 @unittest.skipIf(mode=='before','historical private f52 caller guard coverage')
 def test_live_foreign_uid_is_visible_and_never_absent(self):
  ns,_=self.scene(uid=1001);value=ns['actor']('worker',ns['ACTORS']['worker']);self.assertEqual(value['uid'],[1001]*4);self.assertNotEqual(value['state'],'absent')
@unittest.skipUnless(os.name=='posix'and hasattr(os,'O_NOFOLLOW'),'Arch fake-proc FD behavior requires POSIX')
class CanonicalEmitterFakeProc(unittest.TestCase):
 """Execute the actual current emitter; f52 private guards are historical only."""
 def scene(self,**kwargs):
  from agent_tools import android_original_host_status
  emitted=android_original_host_status.remote_source({'fixtureRoot':'/inert/not-executed','remote':{}})
  self.emitted_tree=ast.parse(emitted)
  return RealFakeProc.scene(self,**kwargs)
 test_actual_matching_pid_start_criterion=RealFakeProc.test_actual_matching_pid_start_criterion
 test_matching_actor_is_live_not_absent=RealFakeProc.test_matching_actor_is_live_not_absent
 test_reused_start_not_admitted=RealFakeProc.test_reused_start_not_admitted
 test_absence_has_exact_numeric_original_identity=RealFakeProc.test_absence_has_exact_numeric_original_identity
 def test_live_foreign_uid_is_visible_and_never_absent(self):
  ns,_=self.scene(uid=1001);value=ns['actor']('worker',ns['ACTORS']['worker']);self.assertEqual(value['uid'],[1001]*4);self.assertNotEqual(value['state'],'absent')
if __name__=='__main__':unittest.main()
