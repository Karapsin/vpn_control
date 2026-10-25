"""Causal local admission from the complete native evidence caller sources.

The ignored qualification helper is not a public executable. These immutable
whole-caller copies retain its actual native failure and fixed execution bytes;
only its real folder-admission block runs here, against actual private files.
"""
import ast
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from agent_tools import durable_remote_job as jobs


@unittest.skipUnless(os.name == 'posix', 'private POSIX state admission')
class EvidenceFolderTests(unittest.TestCase):
    def caller(self, root, suffix):
        source = Path(__file__).parent / 'fixtures' / ('macos_evidence_folder.' + suffix + '.source')
        tree = ast.parse(source.read_bytes())
        # Preserve every actual statement from folder selection through the
        # private-root admission. No restatement of either implementation.
        blocks = []
        for node in ast.walk(tree):
            body = getattr(node, 'body', None)
            if not isinstance(body, list):
                continue
            start = next((i for i, row in enumerate(body)
                          if isinstance(row, ast.Assign) and any(isinstance(name, ast.Name) and name.id == 'folder' for name in row.targets)), None)
            end = next((i for i, row in enumerate(body)
                        if isinstance(row, ast.Expr) and isinstance(row.value, ast.Call)
                        and ast.unparse(row.value.func) == 'jobs._root'), None)
            if start is not None and end is not None:
                blocks = body[start:end + 1]
        self.assertTrue(blocks)
        namespace = {'ROOT': root, 'args': SimpleNamespace(operation_id='076cd86e-f095-44a1-93ea-2c44158cc413'), 'jobs': jobs}
        exec(compile(ast.fix_missing_locations(ast.Module(body=blocks, type_ignores=[])), str(source), 'exec'), namespace)
        return namespace['folder']

    def setup_root(self, temporary):
        root = Path(temporary).resolve()
        parent = root / '.runtime/tool-recovery/direct-entrypoints'
        parent.mkdir(parents=True, mode=0o700)
        return root, parent / 'macos-normal-lease-076cd86e-f095-44a1-93ea-2c44158cc413'

    def test_whole_before_refuses_missing_evidence_folder_fixed_caller_admits_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, folder = self.setup_root(temporary)
            with self.assertRaisesRegex(jobs.DurableJobError, '^private_state_unavailable$'):
                self.caller(root, 'before')
            self.assertFalse(folder.exists())
            self.assertEqual(self.caller(root, 'after'), folder)
            self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
            # Existing admission is inspected, not replaced or chmodded.
            inode = folder.stat().st_ino
            self.assertEqual(self.caller(root, 'after').stat().st_ino, inode)

    def test_fixed_caller_rejects_symlink_without_following_or_modifying_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, folder = self.setup_root(temporary)
            destination = root / 'unrelated'; destination.mkdir(mode=0o700)
            folder.symlink_to(destination, target_is_directory=True)
            with self.assertRaises(jobs.DurableJobError):
                self.caller(root, 'after')
            self.assertEqual(list(destination.iterdir()), [])

    def test_fixed_caller_does_not_repair_an_unsafe_existing_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, folder = self.setup_root(temporary)
            folder.mkdir(mode=0o755); folder.chmod(0o755)
            with self.assertRaises(jobs.DurableJobError):
                self.caller(root, 'after')
            self.assertEqual(folder.stat().st_mode & 0o777, 0o755)


if __name__ == '__main__':
    unittest.main()
