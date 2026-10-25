"""Actual APFS self-entry failure; only exact directory/file guard AST executes."""
import ast
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest

FIXTURE = Path(__file__).parent / 'fixtures/archive_directory_identity'
FILES = ('writer.before.source', 'writer.fixed.source', 'native-failure.json')
FUNCTIONS = ('generation', 'directory_guard', 'parent_fd', 'guard')


def need(value, reason):
    if not value:
        raise ValueError(reason)


class ArchiveDirectoryIdentityTests(unittest.TestCase):
    def setUp(self):
        provenance = json.loads((FIXTURE / 'provenance.json').read_bytes())
        self.assertEqual(set(FILES), set(provenance['files']))
        self.raw = {}
        for name in FILES:
            raw = (FIXTURE / name).read_bytes()
            self.assertEqual(provenance['files'][name], hashlib.sha256(raw).hexdigest())
            self.raw[name] = raw

    def scope(self, before):
        tree = ast.parse(self.raw['writer.before.source' if before else 'writer.fixed.source'])
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS]
        self.assertEqual(set(FUNCTIONS), {node.name for node in nodes})
        scope = {'os': os, 'stat': __import__('stat'), 'Path': Path, 'need': need,
                 'DIR_HOLDS': [], 'HOLDS': [], 'INPUTS': {'aliases': []},
                 'time': time, 'OWNER_DEADLINE': time.monotonic() + 60}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), 'authenticated-exact-guards', 'exec'), scope)
        return scope

    def directory(self):
        # Canonical ordinary-owned directory; no shared fixture/runtime tree.
        temporary = tempfile.TemporaryDirectory(prefix='.archive-guard-test-', dir=Path.home())
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name).resolve() / 'owned'
        path.mkdir(mode=0o700)
        return path

    def admit(self, scope, path):
        fd = scope['parent_fd'](path)
        self.addCleanup(os.close, fd)
        return fd

    def test_authenticated_actual_failure_changed_only_mutable_directory_membership(self):
        native = json.loads(self.raw['native-failure.json'])
        old = native['expectedOutputDirectoryGeneration']
        new = native['actualOutputDirectoryGeneration']
        self.assertEqual(old[:5], new[:5])
        self.assertEqual((2, 3), (old[5], new[5]))
        self.assertEqual(0, native['partialArchiveBytes'])
        self.assertTrue(native['originalRawGenerationUnchanged'])
        self.assertTrue(native['allArchiveActorsAbsent'])
        self.assertTrue(native['allTwelveOldClaimsUnchanged'])

    @unittest.skipUnless(sys.platform == 'darwin', 'actual Darwin/APFS file-entry link-count semantics')
    def test_actual_apfs_create_file_whole_before_guard_red_fixed_green(self):
        path = self.directory()
        old, current = self.scope(True), self.scope(False)
        old_fd = self.admit(old, path)
        self.admit(current, path)
        before = os.fstat(old_fd).st_nlink
        (path / 'exclusive-output.gz').write_bytes(b'')
        self.assertEqual(before + 1, os.fstat(old_fd).st_nlink)
        with self.assertRaisesRegex(ValueError, 'parent_generation_changed'):
            old['directory_guard']()
        current['directory_guard']()

    @unittest.skipUnless(os.name == 'posix', 'owned nofollow directory FDs')
    def test_actual_create_child_directory_before_red_fixed_green(self):
        path = self.directory()
        old, current = self.scope(True), self.scope(False)
        self.admit(old, path)
        self.admit(current, path)
        (path / 'owned-child').mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, 'parent_generation_changed'):
            old['directory_guard']()
        current['directory_guard']()

    @unittest.skipUnless(os.name == 'posix', 'owned nofollow directory FDs')
    def test_inode_mode_and_uid_mismatches_remain_blocked(self):
        for kind in ('inode', 'mode', 'uid'):
            with self.subTest(kind=kind):
                path = self.directory()
                current = self.scope(False)
                fd = self.admit(current, path)
                if kind == 'inode':
                    path.rename(path.with_name('old-inode'))
                    path.mkdir(mode=0o700)
                elif kind == 'mode':
                    path.chmod(0o750)
                else:
                    actual = os.fstat(fd)
                    values = {name: getattr(actual, name) for name in (
                        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                        'st_size', 'st_mtime_ns', 'st_ctime_ns')}
                    values['st_uid'] += 1
                    # Only the UID field at the native metadata boundary varies;
                    # the exact source guard and named filesystem object stay real.
                    current['os'] = types.SimpleNamespace(fstat=lambda value: types.SimpleNamespace(**values))
                with self.assertRaisesRegex(ValueError, 'parent_generation_changed'):
                    current['directory_guard']()

    @unittest.skipUnless(os.name == 'posix', 'real regular-file hardlink custody')
    def test_regular_file_full_generation_and_nlink_guard_is_unchanged(self):
        path = self.directory()
        source = path / 'held-source'
        source.write_bytes(b'fixed-public-source')
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        current = self.scope(False)
        expected = current['generation'](os.fstat(fd))
        self.assertEqual(9, len(expected))
        current['HOLDS'].append((source, fd, expected, hashlib.sha256(source.read_bytes()).hexdigest()))
        current['guard']()
        os.link(source, path / 'other-link')
        with self.assertRaisesRegex(ValueError, 'input_changed'):
            current['guard']()

    @unittest.skipUnless(os.name == 'posix', 'real nofollow parent walk')
    def test_symlink_parent_is_never_adopted(self):
        path = self.directory()
        alias = path.with_name('symlink-parent')
        alias.symlink_to(path, target_is_directory=True)
        with self.assertRaises(OSError):
            self.scope(False)['parent_fd'](alias)


if __name__ == '__main__':
    unittest.main()
