import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from agent_tools.windows_diagnostic_authority_capture import AuthorityCapture


class TestAuthorityCapture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve(strict=True)
        self.root.chmod(0o755)
        (self.root / '.runtime').mkdir(mode=0o755)
        (self.root / '.runtime').chmod(0o755)
        (self.root / '.runtime/parity-evidence').mkdir(mode=0o755)
        (self.root / '.runtime/parity-evidence').chmod(0o755)
        for parent in (self.root, self.root / '.runtime', self.root / '.runtime/parity-evidence'):
            self.assertEqual(0o755, parent.stat().st_mode & 0o777)
        self.leaf = self.root / '.runtime/parity-evidence/diagnostic-one'
        self.leaf.mkdir(mode=0o700)
        self.assertEqual(0o700, self.leaf.stat().st_mode & 0o777)
        self.capture = AuthorityCapture(self.root, self.leaf.name)
        self.addCleanup(self.capture.close)

    def test_actual_public_ancestor_stream_exit255_retains_fd_authority(self):
        # The old reader rejected the exact approved 0755 shared ancestry.
        from agent_tools import windows_cp117_static_tasks_absence_close as old
        for received in (True, False):
            with self.subTest(received=received):
                payload = 'METADATA-ANCHOR {"pid":456}\n' if received else ''
                proc = subprocess.Popen([sys.executable, '-c',
                    'import sys;sys.stderr.write(' + repr(payload) + ');sys.stderr.flush();sys.exit(255)'],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    line = proc.stderr.readline()
                    name = 'anchor-' + str(received) + '.json'
                    authority = 'authority-' + str(received) + '.json'
                    if line.startswith(b'METADATA-ANCHOR '):
                        frame = line.split(b' ', 1)[1].strip()
                        pin = self.capture.create(name, frame)
                        self.capture.create(authority, json.dumps(pin).encode())
                    proc.communicate(timeout=5)
                    self.assertEqual(proc.returncode, 255)
                    self.assertEqual((self.leaf / authority).exists(), received)
                    if received:
                        self.assertEqual(self.capture.verify(name, pin), b'{"pid":456}')
                        with self.assertRaises(ValueError):
                            old._anchor_read(self.leaf / name)
                finally:
                    if proc.poll() is None:
                        proc.kill(); proc.wait()
                    proc.stdout.close(); proc.stderr.close()

    def test_pin_is_captured_while_original_fd_open(self):
        original = os.fstat
        observed = []
        def fstat(fd):
            s = original(fd)
            if s.st_size == 3 and s.st_mode & 0o777 == 0o600:
                observed.append(fd)
            return s
        with mock.patch('agent_tools.windows_diagnostic_authority_capture.os.fstat', fstat):
            pin = self.capture.create('a.json', b'abc')
        self.assertTrue(observed)
        self.assertEqual(pin['sha256'], hashlib.sha256(b'abc').hexdigest())
        self.assertEqual(self.capture.verify('a.json', pin), b'abc')

    def test_same_bytes_rewrite_rejected(self):
        pin = self.capture.create('a.json', b'abc')
        (self.leaf / 'a.json').write_bytes(b'abc')
        with self.assertRaises(ValueError): self.capture.verify('a.json', pin)

    def test_hardlink_rejected(self):
        pin = self.capture.create('a.json', b'abc')
        os.link(self.leaf / 'a.json', self.leaf / 'alias')
        with self.assertRaises(ValueError): self.capture.verify('a.json', pin)

    def test_sibling_creation_allowed(self):
        (self.root / '.runtime/parity-evidence/sibling').mkdir()
        pin = self.capture.create('a.json', b'abc')
        self.assertEqual(self.capture.verify('a.json', pin), b'abc')

    def test_parent_exchange_blocks_create(self):
        parent = self.leaf.parent
        parent.rename(parent.with_name('retained'))
        parent.mkdir(mode=0o755)
        (parent / self.leaf.name).mkdir(mode=0o700)
        with self.assertRaises(ValueError): self.capture.create('a.json', b'abc')
        self.assertFalse((self.leaf / 'a.json').exists())

    def test_mode_change_blocks_create(self):
        self.leaf.parent.chmod(0o700)
        with self.assertRaises(ValueError): self.capture.create('a.json', b'abc')

    def test_symlink_leaf_and_record_rejected(self):
        (self.leaf / 'a.json').symlink_to(self.root / 'unknown')
        with self.assertRaises(OSError): self.capture.create('a.json', b'abc')
        with self.assertRaises(OSError): self.capture.verify('a.json', {'generation': [], 'sha256': ''})

    def test_write_failure_produces_no_authority(self):
        with mock.patch('agent_tools.windows_diagnostic_authority_capture.os.write', side_effect=OSError('write')):
            with self.assertRaises(OSError): self.capture.create('a.json', b'abc')
        self.assertFalse((self.leaf / 'authority.json').exists())
        with self.assertRaises(FileExistsError): self.capture.create('a.json', b'abc')

    def test_names_and_public_leaf_rejected(self):
        for name in ('../a', '/a', ''):
            with self.assertRaises(ValueError): self.capture.create(name, b'')
        self.leaf.chmod(0o755)
        with self.assertRaises(ValueError): AuthorityCapture(self.root, self.leaf.name)

    def test_restrictive_umask_preserves_actual_public_parent_and_mode_drift_cases(self):
        # These exact native-causal conditions previously disappeared under077:
        # the old reader wrongly became eligible and700 was no mode transition.
        previous = os.umask(0o077)
        try:
            result = unittest.TestResult()
            for name in ('test_actual_public_ancestor_stream_exit255_retains_fd_authority',
                         'test_mode_change_blocks_create'):
                TestAuthorityCapture(name).run(result)
            self.assertEqual(2, result.testsRun)
            self.assertTrue(result.wasSuccessful(), repr(result.failures + result.errors))
            self.assertEqual([], result.skipped)
        finally:
            os.umask(previous)
