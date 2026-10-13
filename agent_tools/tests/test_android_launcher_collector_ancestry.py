"""Source-only collector ancestry controls; no launcher or remote authority."""
import ast
import json
import hashlib
import pathlib
import tempfile
import os
import stat
import types
from pathlib import Path
import unittest
from unittest import mock


class CollectorFixtureOS:
    """Stable volatile facts for exact external ancestors of one inert fixture.

    Device/inode/type/permissions/principals and every owned object stay live.
    Authenticated collector bodies and their strict native guards are unchanged.
    """
    volatile = ('st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
    identity = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid')

    def __init__(self, root):
        self.external = {}
        self.live = set()
        for parent in Path(root).resolve().parents:
            info = os.stat(parent, follow_symlinks=False)
            self.external[(info.st_dev, info.st_ino)] = (
                tuple(getattr(info, name) for name in self.identity),
                {name: getattr(info, name) for name in self.volatile})

    def __getattr__(self, name):
        return getattr(os, name)

    def view(self, info):
        record = self.external.get((info.st_dev, info.st_ino))
        if not stat.S_ISDIR(info.st_mode) or record is None or tuple(getattr(info, name) for name in self.identity) != record[0]:
            return info
        values = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
        return types.SimpleNamespace(**{**values, **record[1]})

    def stat(self, *args, **kwargs):
        return self.view(os.stat(*args, **kwargs))

    def fstat(self, fd):
        return self.view(os.fstat(fd))

    def open(self, *args, **kwargs):
        fd = os.open(*args, **kwargs)
        self.live.add(fd)
        return fd

    def close(self, fd):
        try:
            return os.close(fd)
        finally:
            self.live.discard(fd)


_PROBE = r'''
import os as probe_real_os, atexit
class ChurnOS:
 def __init__(self, delegate, root):
  self.delegate=delegate;self.target=root if __OWNED__ else root.parent
  self.identity=probe_real_os.stat(self.target);self.hits=0;self.sibling=None;self.live=set()
 def __getattr__(self, name):return getattr(self.delegate,name)
 def open(self,*a,**kw):
  fd=self.delegate.open(*a,**kw);self.live.add(fd);return fd
 def close(self,fd):
  try:return self.delegate.close(fd)
  finally:self.live.discard(fd)
 def fstat(self,fd):
  raw=probe_real_os.fstat(fd)
  if (raw.st_dev,raw.st_ino)==(self.identity.st_dev,self.identity.st_ino):
   self.hits+=1
   if self.hits==2:
    self.sibling=pathlib.Path(tempfile.mkdtemp(prefix='collector-owned-churn-',dir=self.target))
    after=probe_real_os.fstat(fd);fields=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_uid','st_gid','st_nlink')
    print('ANCESTRY_PROBE '+json.dumps({'before':[getattr(raw,n) for n in fields],'after':[getattr(after,n) for n in fields],'changed':[i for i,n in enumerate(fields) if getattr(raw,n)!=getattr(after,n)]}),flush=True)
  return self.delegate.fstat(fd)
 def finish(self):
  if self.sibling is not None and self.sibling.exists():self.sibling.rmdir()
  print('ANCESTRY_CLOSED '+str(len(self.live)),flush=True)
  assert not self.live
os=ChurnOS(os,ROOT);atexit.register(os.finish)
'''


@unittest.skipUnless(os.name == 'posix', 'Actual collector FDs require POSIX')
class CollectorAncestryTests(unittest.TestCase):
    def case(self, owned=False):
        from agent_tools.tests import test_android_launcher_version_source_snapshot as target
        actual = target.subprocess.run
        results = []
        def run(argv, *args, **kwargs):
            tree = ast.parse(argv[4])
            block = next(node for node in tree.body if isinstance(node, ast.With))
            index = next(i for i, node in enumerate(block.body)
                         if isinstance(node, ast.Assign) and any(isinstance(n, ast.Name) and n.id == 'held' for n in node.targets))
            block.body[index:index] = ast.parse(_PROBE.replace('__OWNED__', repr(owned))).body
            instrumented = list(argv); instrumented[4] = ast.unparse(ast.fix_missing_locations(tree))
            result = actual(instrumented, *args, **kwargs)
            results.append(result)
            return result
        case = target.CollectorDescriptorTests('test_actual_remote_retainer_fifo_replacement_red_to_green')
        try:
            with mock.patch.object(target.subprocess, 'run', side_effect=run):
                case.test_actual_remote_retainer_fifo_replacement_red_to_green()
        finally:
            self.results = results
        self.assertEqual(1, len(results))
        self.assertIn(b'FIFO_REFUSED', results[0].stdout)
        return self.proof()

    def proof(self):
        self.assertEqual(1, len(self.results))
        output = self.results[0].stdout.decode()
        self.assertIn('ANCESTRY_CLOSED 0', output)
        rows = [json.loads(line.removeprefix('ANCESTRY_PROBE ')) for line in output.splitlines() if line.startswith('ANCESTRY_PROBE ')]
        self.assertEqual(1, len(rows))
        self.assertTrue(rows[0]['changed'])
        self.assertFalse(set(rows[0]['changed']) & {0, 1, 5, 6, 7})
        self.observation = rows[0]
        return rows[0]

    def test_external_sibling_churn_preserves_actual_fifo_red_green(self):
        self.case()

    def test_owned_directory_churn_still_refuses_before_fifo_retainer(self):
        with self.assertRaisesRegex(AssertionError, 'census_ancestry_changed'):
            self.case(owned=True)
        self.proof()
        self.assertNotIn(b'BEFORE_RETAIN', self.results[0].stdout)


@unittest.skipUnless(os.name == 'posix', 'Actual collector FDs require POSIX')
class CollectorIdentityTests(unittest.TestCase):
    def fixture(self):
        from agent_tools.tests.fixtures import android_launcher_version_source_snapshot as source
        self.assertEqual(source.CANONICAL_HELPERS_SOURCE_SHA256,
                         hashlib.sha256(source.CANONICAL_HELPERS_SOURCE.encode()).hexdigest())
        temporary = tempfile.TemporaryDirectory(prefix='collector-private-')
        self.addCleanup(temporary.cleanup)
        outer = Path(temporary.name).resolve()
        external = outer / 'external'; external.mkdir(mode=0o700)
        root = external / 'owned'; root.mkdir(mode=0o700)
        path = root / 'source'; path.write_bytes(b'fixed collector source')
        view = CollectorFixtureOS(root)
        namespace = dict(os=view, pathlib=pathlib, hashlib=hashlib, stat=stat)
        exec(source.CANONICAL_HELPERS_SOURCE, namespace)
        return namespace, view, path, external, outer

    def test_real_regular_source_bytes_and_descriptor_closure(self):
        namespace, view, path, _, _ = self.fixture()
        reply = namespace['read_fixed'](path, 65536)
        self.assertEqual(path.read_bytes(), reply['raw'])
        self.assertEqual(hashlib.sha256(reply['raw']).hexdigest(), reply['sha256'])
        self.assertEqual(set(), view.live)

    def external_change(self, mutation):
        namespace, view, path, external, outer = self.fixture()
        original = external.stat(); fstat = view.fstat; hits = 0
        def changed(fd):
            nonlocal hits
            info = fstat(fd)
            if (info.st_dev, info.st_ino) == (original.st_dev, original.st_ino):
                hits += 1
                if hits == 2:
                    mutation(external, outer)
                    return fstat(fd)
            return info
        with mock.patch.object(view, 'fstat', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'census_ancestry_changed'):
                namespace['read_fixed'](path, 65536)
        self.assertGreaterEqual(hits, 2)
        self.assertEqual(set(), view.live)

    def test_external_named_inode_replacement_remains_refused(self):
        def replace(external, outer):
            external.rename(outer / 'retained')
            external.mkdir(mode=0o700)
        self.external_change(replace)

    def test_external_permissions_change_remains_refused(self):
        self.external_change(lambda external, _: external.chmod(0o751))

    def test_external_principal_drift_is_not_given_synthetic_volatile_facts(self):
        for field in ('st_uid', 'st_gid'):
            with self.subTest(field=field):
                namespace, view, path, external, _ = self.fixture()
                original = external.stat(); fstat = view.fstat; hits = 0
                def changed(fd):
                    nonlocal hits
                    info = fstat(fd)
                    if (info.st_dev, info.st_ino) == (original.st_dev, original.st_ino):
                        hits += 1
                        if hits == 2:
                            # Modeled foreign principal; actual descriptors remain owned.
                            values = {n: getattr(original, n) for n in dir(original) if n.startswith('st_')}
                            values[field] += 1
                            changed_info = types.SimpleNamespace(**values)
                            self.assertIs(changed_info, view.view(changed_info))
                            return changed_info
                    return info
                with mock.patch.object(view, 'fstat', side_effect=changed):
                    with self.assertRaisesRegex(ValueError, 'census_ancestry_changed'):
                        namespace['read_fixed'](path, 65536)
                self.assertEqual(2, hits)
                self.assertEqual(set(), view.live)

    def file_change(self, mutation):
        namespace, view, path, _, _ = self.fixture()
        original = view.read; calls = 0
        def changed(fd, limit):
            nonlocal calls
            calls += 1
            if calls == 1:
                mutation(path)
            return original(fd, limit)
        with mock.patch.object(view, 'read', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'census_file_changed'):
                namespace['read_fixed'](path, 65536)
        self.assertEqual(1, calls)
        self.assertEqual(set(), view.live)

    def test_owned_file_bytes_change_remains_refused(self):
        self.file_change(lambda path: path.write_bytes(b'changed collector source bytes'))

    def test_owned_named_file_exchange_refuses_held_descriptor(self):
        def replace(path):
            raw = path.read_bytes(); path.rename(path.with_name('retained'))
            path.write_bytes(raw)
        self.file_change(replace)

    def test_owned_symlink_file_refuses_before_read(self):
        namespace, view, path, _, _ = self.fixture()
        path.rename(path.with_name('retained')); path.symlink_to(path.with_name('retained'))
        with self.assertRaises(OSError):
            namespace['read_fixed'](path, 65536)
        self.assertEqual(set(), view.live)


if __name__ == '__main__':
    unittest.main()
