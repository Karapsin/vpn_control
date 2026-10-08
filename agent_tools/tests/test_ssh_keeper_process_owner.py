"""Actual syscall mutation and harmless original child causal regressions."""
import json,os,sys,tempfile,unittest
from pathlib import Path
from unittest import mock
from agent_tools import ssh_keeper_process_owner as m
@unittest.skipUnless(os.name=='posix' and hasattr(os,'O_NOFOLLOW') and Path('/bin/ps').exists(),'requires POSIX fd custody and process birth observer')
class ProcessOwnerTests(unittest.TestCase):
 def test_actual_stderr_setup_source_mutation_refuses_before_popen_and_closes_fds(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t).resolve();output=root/'output';output.mkdir(mode=0o700);source=root/'PUBLIC_SOURCE';source.write_bytes(b'original public source');marker=root/'PUBLIC_CHILD_MARKER';held=m.closure._Held();self.addCleanup(held.close);held.read(str(source),m.hashlib.sha256(source.read_bytes()).hexdigest());changed=[];opened=[];original=os.open
   def opening(path,*args,**kwargs):
    fd=original(path,*args,**kwargs)
    if Path(path)in (output/'keeper.stdout.private',output/'keeper.stderr.private'):opened.append(fd)
    if Path(path)==output/'keeper.stderr.private' and not changed:source.write_bytes(b'changed public source');changed.append(True)
    return fd
   owner=m.Owner(root,output,held.finish,emit=lambda _:None)
   with mock.patch.object(m.os,'open',opening),self.assertRaises(ValueError):owner.start('keeper',[sys.executable,'-I','-B','-c','from pathlib import Path;import time;Path('+repr(str(marker))+').write_text("ran");print("{}");time.sleep(.2)'])
   self.assertTrue(changed);self.assertFalse(marker.exists());self.assertEqual([],owner.children);self.assertEqual(2,len(opened))
   for fd in opened:
    with self.assertRaises(OSError):os.fstat(fd)
 def test_actual_final_stdout_body_source_mutation_refuses_terminal_result(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t).resolve();source=root/'PUBLIC_SOURCE';source.write_bytes(b'original source');held=m.closure._Held();self.addCleanup(held.close);held.read(str(source),m.hashlib.sha256(source.read_bytes()).hexdigest());owner=m.Owner(root,root,held.finish,emit=lambda _:None)
   p,_,_=owner.start('keeper',[sys.executable,'-I','-B','-c','import time,json;print(json.dumps(dict(state="completed")));time.sleep(.15)']);p.wait();inode=(root/'keeper.stdout.private').stat().st_ino;original=m.closure._read_all;reads=[];changed=[]
   def read(fd):
    raw=original(fd)
    if os.fstat(fd).st_ino==inode:
     reads.append(True)
     if len(reads)==3:source.write_bytes(b'changed source');changed.append(True)
    return raw
   with mock.patch.object(m.closure,'_read_all',read),self.assertRaises(ValueError):owner.finish('keeper',p)
   self.assertTrue(changed);self.assertEqual(0,p.returncode);self.assertEqual(1,len(owner.children));owner.wait_all()
 def test_actual_original_terminal_record_mutation_refuses_without_adoption(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t).resolve();holder=m.closure._Held();self.addCleanup(holder.close);source=root/'PUBLIC';source.write_bytes(b'original');holder.read(str(source),m.hashlib.sha256(source.read_bytes()).hexdigest());owner=m.Owner(root,root,holder.finish,emit=lambda _:None)
   p,_,_=owner.start('keeper',[sys.executable,'-I','-B','-c','import json,time;print(json.dumps(dict(state="completed")));time.sleep(.15)']);p.wait();inode=(root/'keeper.stdout.private').stat().st_ino;terminal=root/'keeper.terminal.json';changed=[];original=m.closure._read_all
   def read(fd):
    body=original(fd)
    if os.fstat(fd).st_ino==inode and not changed:
     value=json.loads(terminal.read_bytes());value['returnCode']=91;terminal.write_text(json.dumps(value));changed.append(True)
    return body
   with mock.patch.object(m.closure,'_read_all',read),self.assertRaises(ValueError):owner.finish('keeper',p)
   self.assertTrue(changed);self.assertEqual(0,p.returncode);self.assertEqual(91,json.loads(terminal.read_bytes())['returnCode']);self.assertEqual(1,len(owner.children));owner.wait_all()
if __name__=='__main__':unittest.main()
