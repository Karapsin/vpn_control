"""Authentic whole lock modules, native processes/flocks and exact IO barrier."""
import hashlib,json,os,select,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest import mock
from agent_tools import private_inventory_lock as current

FIXTURE=Path(__file__).parent/'fixtures/private_inventory_lock_publication'
WORKER=r'''
import hashlib,json,os,sys,types
from pathlib import Path
source,expected,root,mode,*pipes=sys.argv[1:];raw=Path(source).read_bytes()
assert hashlib.sha256(raw).hexdigest()==expected
module=types.ModuleType('owned_lock');module.__file__=source
exec(compile(raw,source,'exec'),module.__dict__)
class Named(module.InventoryLock):
 name='readiness.lock';body=b'readiness-coordinator-lock-v1\n'
if mode=='first':
 ready,release=map(int,pipes);original=os.open;paused=False
 def barrier(name,flags,*args,**kwargs):
  global paused
  fd=original(name,flags,*args,**kwargs)
  if not paused and flags&os.O_CREAT and flags&os.O_EXCL:
   paused=True;os.write(ready,b'R');assert os.read(release,1)==b'X'
  return fd
 os.open=barrier
try:
 with module.Directory(Path(root))as directory,Named(directory)as lock:
  lock.guard();print(json.dumps({'state':'acquired','generation':lock.pin()['generation'],'body':lock.snapshot.body.decode()}),flush=True)
  if mode=='second':assert sys.stdin.buffer.read(1)==b'X';lock.guard()
except BaseException as error:
 print(json.dumps({'state':'error','errorClass':type(error).__name__,'reason':str(error)if type(error)is ValueError else None,'errno':getattr(error,'errno',None)}),flush=True)
assert hashlib.sha256(Path(source).read_bytes()).hexdigest()==expected
'''

@unittest.skipUnless(os.name=='posix','POSIX cooperative ownership')
class PublicationTests(unittest.TestCase):
    def line(self,child):
        ready,_,_=select.select([child.stdout],[],[],5)
        self.assertTrue(ready,'owned child did not reach bounded native barrier')
        line=child.stdout.readline()
        if not line:self.fail(child.stderr.read().decode())
        return json.loads(line)

    def race(self,source):
        raw=source.read_bytes();digest=hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory(prefix='vc-lock-')as temporary:
            root=Path(temporary).resolve();root.chmod(0o700)
            ready_read,ready_write=os.pipe();release_read,release_write=os.pipe();children=[]
            try:
                first=subprocess.Popen([sys.executable,'-I','-B','-c',WORKER,str(source),digest,str(root),'first',str(ready_write),str(release_read)],pass_fds=(ready_write,release_read),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                children.append(first);os.close(ready_write);ready_write=-1;os.close(release_read);release_read=-1
                self.assertTrue(select.select([ready_read],[],[],5)[0]);self.assertEqual(b'R',os.read(ready_read,1))
                named=root/'readiness.lock';publishedBeforeSecond=named.exists()
                if publishedBeforeSecond:self.assertEqual(0,named.stat().st_size)
                second=subprocess.Popen([sys.executable,'-I','-B','-c',WORKER,str(source),digest,str(root),'second'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                children.append(second);observed=self.line(second)
                if observed['state']=='acquired':
                    self.assertEqual(b'readiness-coordinator-lock-v1\n',named.read_bytes());self.assertEqual(1,named.stat().st_nlink)
                os.write(release_write,b'X');original=self.line(first)
                self.assertEqual(0,first.wait(timeout=5),first.stderr.read().decode())
                if observed['state']=='acquired':second.stdin.write(b'X');second.stdin.flush()
                second.stdin.close();self.assertEqual(0,second.wait(timeout=5),second.stderr.read().decode())
                self.assertEqual(['readiness.lock'],sorted(p.name for p in root.iterdir()))
                self.assertEqual(digest,hashlib.sha256(source.read_bytes()).hexdigest())
                return {'namedEmptyBeforeSecond':publishedBeforeSecond,'second':observed,'first':original}
            finally:
                for child in children:
                    if child.poll()is None:child.kill();child.wait(timeout=5)
                    for stream in(child.stdin,child.stdout,child.stderr):
                        if stream is not None and not stream.closed:stream.close()
                for fd in(ready_read,ready_write,release_read,release_write):
                    if fd>=0:os.close(fd)

    def test_whole_preserved_lock_real_process_empty_publication_red_current_atomic_green(self):
        before=FIXTURE/'private_inventory_lock.py.before.source';manifest=json.loads((FIXTURE/'provenance.json').read_bytes())
        self.assertEqual(manifest['beforeSha256'],hashlib.sha256(before.read_bytes()).hexdigest())
        red=self.race(before)
        self.assertTrue(red['namedEmptyBeforeSecond']);self.assertEqual({'state':'error','errorClass':'ValueError','reason':'unsafe private file','errno':None},red['second'])
        self.assertEqual('acquired',red['first']['state'])
        green=self.race(Path(current.__file__))
        self.assertFalse(green['namedEmptyBeforeSecond']);self.assertEqual('acquired',green['second']['state'])
        self.assertEqual('BlockingIOError',green['first']['errorClass'])

    def test_existing_unsafe_empty_symlink_hardlink_or_partial_file_never_adopted_or_overwritten(self):
        for kind in('empty','symlink','hardlink','partial'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory()as temporary:
                root=Path(temporary).resolve();path=root/current.InventoryLock.name;other=root/'other'
                other.write_bytes(current.InventoryLock.body);other.chmod(0o600)
                if kind=='symlink':path.symlink_to(other)
                elif kind=='hardlink':os.link(other,path)
                else:path.write_bytes(b''if kind=='empty'else b'partial');path.chmod(0o600)
                original=path.lstat();body=path.read_bytes()
                with current.Directory(root)as directory:
                    with self.assertRaises((ValueError,OSError)):current.InventoryLock(directory)
                self.assertEqual(original.st_ino,path.lstat().st_ino);self.assertEqual(body,path.read_bytes())

    def test_failed_atomic_primitive_never_falls_back_to_rename_replace_or_leaves_staging_name(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary).resolve()
            with current.Directory(root)as directory,mock.patch.object(current,'_rename_create_only',side_effect=OSError('unsupported atomic publication')):
                with self.assertRaises(OSError):current.InventoryLock(directory)
            self.assertEqual([],list(root.iterdir()))

    def test_actual_atomic_syscall_never_replaces_existing_unsafe_destination(self):
        for kind in('empty','symlink','directory'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory()as temporary:
                root=Path(temporary).resolve();source=root/'complete';target=root/'existing'
                source.write_bytes(current.InventoryLock.body);source.chmod(0o600)
                if kind=='empty':target.touch(mode=0o600)
                elif kind=='symlink':target.symlink_to('absent-untrusted-target')
                else:target.mkdir(mode=0o700)
                before=target.lstat();original=source.stat()
                with current.Directory(root)as directory:
                    with self.assertRaises(FileExistsError):current._rename_create_only(directory.fd,source.name,target.name)
                self.assertEqual(before.st_ino,target.lstat().st_ino);self.assertEqual(original.st_ino,source.stat().st_ino)
                self.assertEqual(current.InventoryLock.body,source.read_bytes());self.assertFalse((root/'absent-untrusted-target').exists())

if __name__=='__main__':unittest.main()
