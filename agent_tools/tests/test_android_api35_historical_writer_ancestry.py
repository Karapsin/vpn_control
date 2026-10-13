"""Actual historical FD writer controls; inert API35 transport only."""
import ast
import hashlib
import json
import re
import stat
import uuid
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
from agent_tools.tests import test_android_api35_remaining_proxy_cleanup as remaining


@unittest.skipUnless(all(hasattr(os, n) for n in ('O_DIRECTORY', 'O_NOFOLLOW')), 'requires POSIX descriptor custody primitives')
class HistoricalWriterAncestryTests(unittest.TestCase):
    def run_case(self, owned=False):
        original = os.fstat
        observation = {'hits': 0, 'changed': []}
        sibling = None

        def fstat(fd):
            nonlocal sibling
            info = original(fd)
            frame = sys._getframe(1)
            writer = None
            while frame:
                if frame.f_code.co_name == '_write_local_intent' and frame.f_code.co_filename == '<frozen-local-fd-writer>':
                    writer = frame
                    break
                frame = frame.f_back
            if writer is None:
                return info
            path = writer.f_locals['path']
            if not path.parent.parent.name.startswith('android-api35-proxy-readmission-'):
                return info
            root = path.parents[3]
            target = root if owned else root.parent
            target_info = target.stat()
            if (info.st_dev, info.st_ino) != (target_info.st_dev, target_info.st_ino):
                return info
            observation['hits'] += 1
            if observation['hits'] == 2:
                sibling = Path(tempfile.mkdtemp(prefix='ancestry-owned-churn-', dir=target))
                changed = original(fd)
                fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_uid', 'st_gid', 'st_nlink')
                observation['before'] = [getattr(info, n) for n in fields]
                observation['after'] = [getattr(changed, n) for n in fields]
                observation['changed'] = [i for i, n in enumerate(fields) if getattr(info, n) != getattr(changed, n)]
                return changed
            return info

        case = remaining.RemainingTests('test_partial_effect_failure_stops_and_preserves_original_unknown')
        try:
            with mock.patch.object(os, 'fstat', side_effect=fstat):
                try:
                    case.setUp()
                    case.test_partial_effect_failure_stops_and_preserves_original_unknown()
                finally:
                    case.doCleanups()
        finally:
            if sibling is not None and sibling.exists():
                sibling.rmdir()
            self.observation = observation
            if hasattr(case, 'history') and hasattr(case.history, 'local_writer_os'):
                self.assertEqual(set(), case.history.local_writer_os.live)
        if hasattr(case, 'history') and hasattr(case.history, 'local_writer_os'):
            self.assertEqual(set(), case.history.local_writer_os.live)
        self.assertGreaterEqual(observation['hits'], 2)
        self.assertTrue(observation['changed'])
        self.assertFalse(set(observation['changed']) & {0, 1, 5, 6, 7})
        return observation

    def test_external_sibling_churn_keeps_actual_remaining_unknown_case(self):
        self.run_case()

    def test_owned_ancestry_churn_still_refuses_before_remaining_effects(self):
        with self.assertRaisesRegex(ValueError, 'coldboot_local_ancestry_changed'):
            self.run_case(owned=True)
        self.assertEqual(2, self.observation['hits'])
        self.assertTrue(self.observation['changed'])


@unittest.skipUnless(all(hasattr(os, n) for n in ('O_DIRECTORY', 'O_NOFOLLOW')), 'requires POSIX descriptor custody primitives')
class LocalWriterSecurityTests(unittest.TestCase):
    def writer(self, root):
        from agent_tools.tests.fixtures import android_api35_historical_context as history
        path, sha = history.SOURCES['coldboot']
        raw = (history.BASE / path).read_bytes()
        self.assertEqual(sha, hashlib.sha256(raw).hexdigest())
        tree = ast.parse(raw)
        functions = [n for n in tree.body if isinstance(n, ast.FunctionDef)
                     and n.name in ('_local_generation', '_write_local_intent')]
        self.assertEqual(2, len(functions))
        view = history.LocalWriterOS(root)
        namespace = dict(os=view, Path=Path, json=json, stat=stat, re=re, sys=sys)
        exec(compile(ast.Module(body=functions, type_ignores=[]), '<actual-frozen-coldboot-writer>', 'exec'), namespace)
        return namespace['_write_local_intent'], view

    def fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix='ancestry-private-')
        self.addCleanup(temporary.cleanup)
        outer = Path(temporary.name).resolve()
        external = outer / 'external'; external.mkdir(mode=0o700)
        root = external / 'owned'; root.mkdir(mode=0o700)
        path = root / '.rag_index/android-avd-coldboot' / str(uuid.uuid4()) / 'launch.json'
        writer, view = self.writer(root)
        return writer, view, path, external, outer

    def test_create_only_private_bytes_and_all_descriptors_closed(self):
        writer, view, path, _, _ = self.fixture()
        writer(path, {'originalOutcome': 'unknown'})
        self.assertEqual({'originalOutcome': 'unknown'}, json.loads(path.read_bytes()))
        self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
        with self.assertRaises(FileExistsError):
            writer(path, {})
        self.assertEqual(set(), view.live)

    def change_external(self, change):
        writer, view, path, external, outer = self.fixture()
        snapshot = external.stat()
        fstat = view.fstat
        calls = 0
        def changed(fd):
            nonlocal calls
            info = fstat(fd)
            if (info.st_dev, info.st_ino) == (snapshot.st_dev, snapshot.st_ino):
                calls += 1
                if calls == 2:
                    change(external, outer)
                    return fstat(fd)
            return info
        with mock.patch.object(view, 'fstat', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'coldboot_local_ancestry_changed'):
                writer(path, {})
        self.assertGreaterEqual(calls, 2)
        self.assertEqual(set(), view.live)
        self.assertFalse(path.exists())

    def test_external_named_inode_replacement_is_live_and_rejected(self):
        def replace(external, outer):
            external.rename(outer / 'retained')
            external.mkdir(mode=0o700)
        self.change_external(replace)

    def test_external_directory_mode_drift_is_live_and_rejected(self):
        self.change_external(lambda external, _: external.chmod(0o751))

    def test_private_parent_permissions_refuse_before_create(self):
        writer, view, path, _, _ = self.fixture()
        (path.parents[2]).mkdir(mode=0o777)
        path.parents[2].chmod(0o777)
        with self.assertRaisesRegex(ValueError, 'coldboot_local_private_parent_unsafe'):
            writer(path, {})
        self.assertEqual(set(), view.live)
        self.assertFalse(path.exists())

    def test_symlink_private_parent_refuses_before_create(self):
        writer, view, path, _, outer = self.fixture()
        target = outer / 'target'; target.mkdir(mode=0o700)
        path.parents[2].symlink_to(target, target_is_directory=True)
        with self.assertRaises(OSError):
            writer(path, {})
        self.assertEqual(set(), view.live)
        self.assertFalse(path.exists())
        self.assertEqual([], list(target.iterdir()))


if __name__ == '__main__':
    unittest.main()
