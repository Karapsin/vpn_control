"""Routine causal coverage of the fixed launcher caller's exact source reader."""
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import types

from agent_tools.tests.fixtures import android_launcher_version_source_snapshot as fixture


class SourceAuthenticationTests(unittest.TestCase):
    def test_exact_function_and_original_attribution(self):
        tree = ast.parse(Path(fixture.__file__).read_bytes())
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "snapshot")
        normalized = (ast.unparse(node) + "\n").encode()
        self.assertEqual(hashlib.sha256(normalized).hexdigest(), fixture.CURRENT_FUNCTION_SHA256)
        self.assertEqual(hashlib.sha256(fixture.PREVIOUS_SNAPSHOT_SOURCE.encode()).hexdigest(),
                         fixture.ORIGINAL_FUNCTION_SHA256)
        self.assertEqual(fixture.snapshot.__globals__, fixture.__dict__)
        expected = fixture.PREVIOUS_SNAPSHOT_SOURCE.replace(
            "os.O_RDONLY | os.O_NOFOLLOW, dir_fd=chain[-1]",
            "os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=chain[-1]")
        self.assertEqual(normalized.decode(), expected)


@unittest.skipUnless(os.name == "posix", "Exact reader requires POSIX dir_fd and no-follow file opens")
class SourceReaderTests(unittest.TestCase):
    def test_regular_full_bytes_hash_fd_named_generation_and_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "source"
            path.write_bytes(b"fixed source\n")
            fd, raw, pin = fixture.snapshot(path)
            try:
                self.assertEqual(raw, b"fixed source\n")
                self.assertEqual(pin["sha256"], hashlib.sha256(raw).hexdigest())
                self.assertEqual(set(pin), {"generation", "sha256", "parents"})
                self.assertEqual(len(pin["generation"]), 9)
                self.assertTrue(all(type(item) is int for item in pin["generation"]))
                self.assertEqual(pin["generation"][0:3],
                                 [os.fstat(fd).st_dev, os.fstat(fd).st_ino, len(raw)])
                self.assertEqual(pin["parents"][-1]["path"], str(path.parent))
                self.assertEqual(json.loads(json.dumps(pin)), pin)
            finally:
                os.close(fd)

    def test_symlink_directory_hardlink_and_size_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            path = parent / "source"
            path.write_bytes(b"1234")
            with self.assertRaises(ValueError):
                fixture.snapshot(path, maximum=3)
            link = parent / "symlink"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                fixture.snapshot(link)
            with self.assertRaises(ValueError):
                fixture.snapshot(parent)
            os.link(path, parent / "hardlink")
            with self.assertRaises(ValueError):
                fixture.snapshot(path)

    def test_fifo_actual_old_hang_to_current_immediate_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            fifo = Path(temporary).resolve() / "source"
            os.mkfifo(fifo)
            code = ("import importlib.util,sys;"
                    "s=importlib.util.spec_from_file_location('exact_fixture',sys.argv[1]);"
                    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
                    "ns=dict(m.__dict__);"
                    "exec(compile(m.PREVIOUS_SNAPSHOT_SOURCE,'original-snapshot','exec'),ns);"
                    "f=ns['snapshot'] if sys.argv[2]=='old' else m.snapshot;"
                    "f(sys.argv[3])")
            argv = [sys.executable, "-I", "-B", "-c", code, fixture.__file__]
            old = subprocess.Popen([*argv, "old", str(fifo)], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
            try:
                with self.assertRaises(subprocess.TimeoutExpired):
                    old.communicate(timeout=1)
            finally:
                if old.poll() is None:
                    old.kill()
                old.communicate(timeout=2)
            current = subprocess.run([*argv, "current", str(fifo)], capture_output=True,
                                     timeout=2)
            self.assertNotEqual(current.returncode, 0)
            self.assertIn(b"local_source_shape", current.stderr)


class CollectorSourceTests(unittest.TestCase):
    def test_authenticated_fixed_bodies_and_topology(self):
        for name in ('CANONICAL_HELPERS_SOURCE', 'OLD_RETAINER_SOURCE',
                     'CURRENT_RETAINER_SOURCE', 'HELD_GUARD_SOURCE',
                     'OLD_HOST_GUARD_SOURCE', 'CURRENT_HOST_GUARD_SOURCE',
                     'PREVIOUS_SHARED_RETAINER_SOURCE'):
            source = getattr(fixture, name)
            self.assertEqual(hashlib.sha256(source.encode()).hexdigest(),
                             getattr(fixture, name + '_SHA256'))
            compile(source, '<authenticated-collector-body>', 'exec')
        self.assertEqual(fixture.CURRENT_RETAINER_SOURCE,
                         fixture.PREVIOUS_SHARED_RETAINER_SOURCE.replace(
                             'os.O_RDONLY | os.O_NOFOLLOW, dir_fd=',
                             'os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd='))
        self.assertEqual(len(fixture.STAGE_PATHS), 153)
        self.assertEqual(len(set(fixture.STAGE_PATHS)), 153)
        self.assertTrue(all(not Path(p).is_absolute() and '..' not in Path(p).parts
                            for p in fixture.STAGE_PATHS))
        self.assertEqual(fixture.MEASURED_GROUPS, (953, 958, 961, 964, 990, 998, 1000))

    def test_actual_old_and_new_group_predicates(self):
        groups = list(fixture.MEASURED_GROUPS)
        observed = list(groups)
        resource = types.SimpleNamespace(RLIM_INFINITY=-1, RLIMIT_NOFILE=7,
                                         getrlimit=lambda _: (1024, 524288))
        identity = dict(uid=1000, euid=1000, gid=1000, egid=1000, groups=list(groups))
        namespace = dict(resource=resource, FILE_LIMIT=(-1, -1), FD_LIMIT=(1024, 524288),
                         collector_fd_demand={'minimumSoftLimit':234},
                         EXPECTED_GROUPS=list(groups), identity_host=identity,
                         EXPECTED_BOOT='measured-boot',
                         pathlib=types.SimpleNamespace(Path=lambda _: types.SimpleNamespace(
                             read_text=lambda: 'measured-boot')),
                         os=types.SimpleNamespace(getuid=lambda:1000, geteuid=lambda:1000,
                             getgid=lambda:1000, getegid=lambda:1000,
                             getgroups=lambda:list(observed)))
        # Isolate the original measured group refusal after its independent 2048 gate.
        old = dict(namespace, FD_LIMIT=(2048, 524288))
        exec(compile(fixture.OLD_HOST_GUARD_SOURCE, '<consumed-b80-guard>', 'exec'), old)
        with self.assertRaisesRegex(ValueError, 'host_identity_changed'):
            old['host_guard']()
        exec(compile(fixture.CURRENT_HOST_GUARD_SOURCE, '<fixed-group-guard>', 'exec'), namespace)
        namespace['host_guard']()
        for wrong in ([1000], groups[:-1], groups+[1001], [True]+groups[1:],
                      [str(groups[0])]+groups[1:]):
            observed[:] = wrong
            with self.assertRaisesRegex(ValueError, 'host_identity_changed'):
                namespace['host_guard']()
        observed[:] = groups
        namespace['resource'].getrlimit = lambda _: (2048, 524288)
        with self.assertRaisesRegex(ValueError, 'host_fd_limit_changed'):
            namespace['host_guard']()


@unittest.skipUnless(os.name == 'posix', 'Actual constrained FD child requires POSIX')
class CollectorDescriptorTests(unittest.TestCase):
    def test_actual_remote_retainer_fifo_replacement_red_to_green(self):
        code = """
import importlib.util,sys,os,pathlib,json,hashlib,stat,tempfile
spec=importlib.util.spec_from_file_location('fixture',sys.argv[1])
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
exec(f.CANONICAL_HELPERS_SOURCE)
exec(f.PREVIOUS_SHARED_RETAINER_SOURCE if sys.argv[2]=='old' else f.CURRENT_RETAINER_SOURCE)
with tempfile.TemporaryDirectory() as temporary:
 ROOT=pathlib.Path(temporary).resolve();GETTER={'stageId':'inert-fixed-stage'}
 held=[];parent_cache={};directory=ROOT/('android-cli-stage-'+GETTER['stageId']);pins={}
 for name in ('intent.json','receipt.json',*f.STAGE_PATHS):
  path=directory/name if name in ('intent.json','receipt.json') else directory/'tree'/name
  path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'inert fixed source')
  pins[name]=read_fixed(path,65536);pins[name].pop('raw')
 target=directory/'intent.json';target.unlink();os.mkfifo(target)
 print('BEFORE_RETAIN',flush=True)
 try:retain_stage(pins);raise AssertionError('FIFO accepted')
 except ValueError as error:assert str(error)=='stage_generation_changed';print('FIFO_REFUSED',flush=True)
 finally:
  for chain,name,fd,generation in reversed(held):os.close(fd)
  close_parents(list(parent_cache.values()))
"""
        argv = [sys.executable, '-I', '-B', '-c', code, fixture.__file__]
        old = subprocess.Popen([*argv, 'old'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            try:
                out, err = old.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            else:
                self.fail('old remote FIFO child exited before timeout: '
                          f'returncode={old.returncode}; stdout={out!r}; stderr={err!r}')
        finally:
            if old.poll() is None:
                old.kill()
            out, err = old.communicate(timeout=2)
        self.assertIn(b'BEFORE_RETAIN', out)
        current = subprocess.run([*argv, 'new'], capture_output=True, timeout=2)
        self.assertEqual(current.returncode, 0, current.stderr)
        self.assertIn(b'FIFO_REFUSED', current.stdout)

    def test_actual_155_file_old_emfile_new_shared_under_unchanged_1024(self):
        code = r"""
import importlib.util,sys,os,pathlib,json,hashlib,stat,resource,tempfile
spec=importlib.util.spec_from_file_location('fixture',sys.argv[1])
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
exec(f.CANONICAL_HELPERS_SOURCE)
exec(f.OLD_RETAINER_SOURCE if sys.argv[2]=='old' else f.CURRENT_RETAINER_SOURCE)
exec(f.HELD_GUARD_SOURCE)
original=resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE,(1024,original[1]))
with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
 ROOT=pathlib.Path(temporary).resolve();GETTER={'stageId':'inert-fixed-stage'}
 held=[];parent_cache={};directory=ROOT/('android-cli-stage-'+GETTER['stageId']);pins={}
 for name in ('intent.json','receipt.json',*f.STAGE_PATHS):
  path=directory/name if name in ('intent.json','receipt.json') else directory/'tree'/name
  path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'inert fixed source')
  pins[name]=read_fixed(path,65536);pins[name].pop('raw')
 try:
  retain_stage(pins)
 except OSError as error:
  assert sys.argv[2]=='old' and error.errno==24
  print(json.dumps({'state':'old-emfile','errno':error.errno,'held':len(held),'limit':resource.getrlimit(resource.RLIMIT_NOFILE)[0]}))
 else:
  assert sys.argv[2] in ('new','parent');held_guard()
  assert len(held)==155 and len(parent_cache)<64
  if sys.argv[2]=='parent':
   parent=directory/'tree'/'opt';parent.chmod(0o711)
   try:held_guard();raise AssertionError('ancestor drift accepted')
   except ValueError as error:assert str(error)=='census_ancestry_changed'
  else:
   file=directory/'tree'/f.STAGE_PATHS[0];file.write_bytes(b'changed')
   try:held_guard();raise AssertionError('file drift accepted')
   except ValueError as error:assert str(error)=='stage_generation_changed'
  print(json.dumps({'state':'new-shared','files':len(held),'parents':len(parent_cache),'limit':resource.getrlimit(resource.RLIMIT_NOFILE)[0]}))
 finally:
  for chain,name,fd,generation in reversed(held):
   os.close(fd)
   if sys.argv[2]=='old':close_parents(chain)
  if sys.argv[2]!='old':close_parents(list(parent_cache.values()))
"""
        outputs = {}
        for mode in ('old', 'new', 'parent'):
            result = subprocess.run([sys.executable, '-I', '-B', '-c', code,
                                     fixture.__file__, mode], capture_output=True, timeout=8)
            self.assertEqual(result.returncode, 0, result.stderr)
            outputs[mode] = json.loads(result.stdout)
        self.assertEqual(outputs['old']['state'], 'old-emfile')
        self.assertLess(outputs['old']['held'], 155)
        self.assertEqual(outputs['new']['files'], 155)
        self.assertEqual(outputs['parent']['files'], 155)
        self.assertLess(outputs['new']['parents'], 64)
        self.assertEqual(outputs['old']['limit'], 1024)
        self.assertEqual(outputs['new']['limit'], 1024)


class OwnedDescendantSourceTests(unittest.TestCase):
    def test_finite_source_authentication(self):
        self.assertEqual(hashlib.sha256(fixture.OWNED_DESCENDANT_SOURCE.encode()).hexdigest(),
                         fixture.OWNED_DESCENDANT_SOURCE_SHA256)
        compile(fixture.OWNED_DESCENDANT_SOURCE, '<owned-linux-descendant-collector>', 'exec')
        tree = ast.parse(fixture.OWNED_DESCENDANT_SOURCE)
        self.assertEqual({n.name for n in tree.body},
                         {'subreaper_flag', 'children_of', 'ownership_admit',
                          'descendant_birth', 'collect_descendants', 'close_descendants',
                          'cleanup_selftest', 'write_record'})
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Attribute)]
        self.assertFalse(any(n.func.attr in ('kill', 'killpg', 'setrlimit') for n in calls))
        self.assertTrue(any(n.func.attr == 'pidfd_send_signal' for n in calls))


@unittest.skipUnless(sys.platform.startswith('linux') and hasattr(os, 'pidfd_open'),
                     'Actual subreaper/PIDfd causal test requires Linux; Mac does not prove viability')
class OwnedDescendantLinuxTests(unittest.TestCase):
    def test_actual_separate_session_descendants_reaped_and_flag_restored(self):
        code = """
import importlib.util,sys,os,pathlib,ctypes,signal,select,time,json
s=importlib.util.spec_from_file_location('fixture',sys.argv[1]);f=importlib.util.module_from_spec(s);s.loader.exec_module(f)
exec(f.OWNED_DESCENDANT_SOURCE)
identity_host={'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups()}
EXPECTED_BOOT=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
original_subreaper=None;owned_descendants={};wait_status=None;process=None;child_deadline=None
original=subreaper_flag()
import tempfile,hashlib
CORRELATION='fixed-routine-correlation'
with tempfile.TemporaryDirectory() as directory:
 result_fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
 try:
  proof=cleanup_selftest();assert proof['state']=='selftest-own-descendant-closure-proven'
  persisted=json.loads(pathlib.Path(directory,'selftest-proof.json').read_bytes())
  assert persisted==proof and subreaper_flag()==original and children_of(os.getpid())==[]
 finally:os.close(result_fd)
ownership_admit();read,write=os.pipe();process=os.fork()
if process==0:
 os.close(read);os.setsid();escape=os.fork()
 if escape==0:
  os.setsid();os.write(write,(str(os.getpid())+'\n').encode());os.close(write);time.sleep(5);os._exit(0)
 os.close(write);time.sleep(5);os._exit(0)
os.close(write)
assert select.select([read],[],[],2)[0];escape=int(os.read(read,128));os.close(read)
assert os.getpgid(escape)==escape and os.getpgid(process)==process
collect_descendants();assert process in owned_descendants and escape in owned_descendants
proof=close_descendants()
assert proof['allDescendantsExited'] and proof['finalChildren']==[]
assert set(proof['reapedPids'])=={process,escape} and children_of(os.getpid())==[]
assert subreaper_flag()==original
print(json.dumps(proof,sort_keys=True))
"""
        result = subprocess.run([sys.executable, '-I', '-B', '-c', code, fixture.__file__],
                                capture_output=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr)
        proof = json.loads(result.stdout)
        self.assertEqual(len(proof['identities']), 2)
        self.assertTrue(proof['allDescendantsExited'])
        self.assertEqual(proof['originalSubreaper'], proof['restoredSubreaper'])


class DebuggerControlTests(unittest.TestCase):
    def replay(self, source, mode='target'):
        import types, contextlib, io
        calls=[]; ns={'observed':False,'json':json,'time':types.SimpleNamespace(monotonic=lambda:0)}
        class Inferior:
            num=1;pid=101
            def is_valid(self):return True
        parent=Inferior();helper=Inferior();helper.num=4;helper.pid=104
        selected=[helper]
        def identity(pid):
            if mode=='foreign':raise ValueError('debugger_foreign_inferior')
            return {'pid':pid,'startTicks':99,'uid':1000,'gid':1000,'groups':[1000]}
        def execute(command):
            calls.append(command)
            if command=='run':
                helper.pid=0
                if mode=='exited':parent.pid=0
                if mode=='malformed':parent.num=True
            elif command=='inferior 1':selected[0]=parent
            elif command=='continue' and mode=='target':ns['observed']=True
        ns.update(identity=identity,gdb=types.SimpleNamespace(execute=execute,inferiors=lambda:(parent,helper),selected_inferior=lambda:selected[0]))
        with contextlib.redirect_stdout(io.StringIO()):exec(compile(source,'exact-gdb-control-tail','exec'),ns)
        return ns,calls
    def test_exact_old_helper_exit_red_current_target_green(self):
        self.assertEqual(hashlib.sha256(fixture.GDB_CONTROL_SOURCE.encode()).hexdigest(),fixture.GDB_CONTROL_SHA256)
        old,calls=self.replay(fixture.OLD_GDB_CONTROL_SOURCE)
        self.assertFalse(old['observed']);self.assertNotIn('continue',calls)
        current,calls=self.replay(fixture.GDB_CONTROL_SOURCE)
        self.assertTrue(current['observed']);self.assertIn('inferior 1',calls);self.assertIn('continue',calls)
    def test_finite_exited_foreign_malformed_and_stuck(self):
        state,calls=self.replay(fixture.GDB_CONTROL_SOURCE,'exited');self.assertFalse(state['observed']);self.assertNotIn('continue',calls)
        for mode in ('foreign','malformed','stuck'):
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.replay(fixture.GDB_CONTROL_SOURCE,mode)


if __name__ == "__main__":
    unittest.main()
