import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from agent_tools.windows_diagnostic_authority_capture import AuthorityCapture, private_exception_chain


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


    def test_private_exception_chain_is_private_bounded_and_capture_pinned(self):
        class Inner(ValueError):
            pass
        class Outer(ValueError):
            pass
        inner = Inner("selected-status-detail")
        outer = Outer("outer-rendered-error")
        outer.__context__ = inner
        outer.__suppress_context__ = True
        raw = private_exception_chain(outer)
        value = json.loads(raw)
        self.assertEqual([row["exceptionType"] for row in value["contextChain"]], ["Outer", "Inner"])
        self.assertEqual("selected-status-detail", value["contextChain"][1]["message"])
        self.assertTrue(value["contextChain"][0]["displaySuppressed"])
        pin = self.capture.create("original-exception.private", raw)
        self.assertEqual(raw, self.capture.verify("original-exception.private", pin))
        (self.leaf / "original-exception.private").write_bytes(raw)
        with self.assertRaises(ValueError):
            self.capture.verify("original-exception.private", pin)


    def test_private_exception_chain_eight_unicode_control_nodes_fit_serialized_budget(self):
        text = ('é' * 200) + '\x00\x01\n' * 100
        rows = [ValueError(text) for _ in range(8)]
        for left, right in zip(rows, rows[1:]): left.__context__ = right
        raw = private_exception_chain(rows[0])
        value = json.loads(raw)
        self.assertLessEqual(len(raw), 8192)
        self.assertEqual(['ValueError'] * 8, [row['exceptionType'] for row in value['contextChain']])
        self.assertTrue(value['chainTruncated'])
        for row in value['contextChain']:
            self.assertLessEqual(len(row['message'].encode('utf-8')), 512)
        pin = self.capture.create('escaped-chain.private', raw)
        self.assertEqual(raw, self.capture.verify('escaped-chain.private', pin))




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


class PrivateExceptionChainTests(unittest.TestCase):
    """Pure serializer contract; no native filesystem or POSIX fixture."""
    def test_private_exception_chain_is_private_bounded_and_context_preserved(self):
            class Inner(ValueError):
                pass
            class Outer(ValueError):
                pass
            inner = Inner("selected-status-detail")
            outer = Outer("outer-rendered-error")
            outer.__context__ = inner
            outer.__suppress_context__ = True
            raw = private_exception_chain(outer)
            value = json.loads(raw)
            self.assertEqual([row["exceptionType"] for row in value["contextChain"]], ["Outer", "Inner"])
            self.assertEqual("selected-status-detail", value["contextChain"][1]["message"])
            self.assertTrue(value["contextChain"][0]["displaySuppressed"])

    def test_private_exception_chain_cycles_and_large_messages_are_bounded(self):
            value = ValueError("x" * 50000)
            value.__context__ = value
            raw = private_exception_chain(value)
            self.assertLessEqual(len(raw), 8192)
            self.assertTrue(json.loads(raw)["chainTruncated"])

    def test_private_exception_chain_eight_unicode_control_nodes_fit_serialized_budget(self):
            text = ('é' * 200) + '\x00\x01\n' * 100
            rows = [ValueError(text) for _ in range(8)]
            for left, right in zip(rows, rows[1:]): left.__context__ = right
            raw = private_exception_chain(rows[0])
            value = json.loads(raw)
            self.assertLessEqual(len(raw), 8192)
            self.assertEqual(['ValueError'] * 8, [row['exceptionType'] for row in value['contextChain']])
            self.assertTrue(value['chainTruncated'])
            for row in value['contextChain']:
                self.assertLessEqual(len(row['message'].encode('utf-8')), 512)

    def test_private_exception_chain_final_false_flag_width_edge_is_honest(self):
            kind = type('Edge', (ValueError,), {})
            kind.__name__ = '\x01' * 128
            rows = [kind('x' * 512), kind('x' * 188)] + [kind('') for _ in range(6)]
            for left, right in zip(rows, rows[1:]): left.__context__ = right
            raw = private_exception_chain(rows[0]); value = json.loads(raw)
            self.assertEqual(8191, len(raw)); self.assertTrue(value['chainTruncated'])
            self.assertEqual(8, len(value['contextChain']))
            self.assertEqual([kind.__name__] * 8, [row['exceptionType'] for row in value['contextChain']])
            self.assertEqual(699, sum(len(row['message']) for row in value['contextChain']))
            # This actual boundary is8192 with True but8193 with False.
            value['contextChain'][-1]['message'] += 'x'
            encoded = lambda: json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
            self.assertEqual(8192, len(encoded()))
            value['chainTruncated'] = False; self.assertEqual(8193, len(encoded()))

    def test_private_exception_chain_complete_and_small_cycle_flags_preserve_nodes(self):
            one = ValueError('first é'); two = RuntimeError('second'); one.__context__ = two
            value = json.loads(private_exception_chain(one))
            self.assertFalse(value['chainTruncated'])
            self.assertEqual(['ValueError', 'RuntimeError'], [row['exceptionType'] for row in value['contextChain']])
            self.assertEqual(['first é', 'second'], [row['message'] for row in value['contextChain']])
            two.__context__ = one
            value = json.loads(private_exception_chain(one))
            self.assertTrue(value['chainTruncated']); self.assertEqual(2, len(value['contextChain']))

    def test_private_exception_chain_unprintable_invalid_and_utf8_type_bounds(self):
            class Unprintable(ValueError):
                def __str__(self): raise RuntimeError('not printable')
            value = json.loads(private_exception_chain(Unprintable()))
            self.assertEqual('<unprintable>', value['contextChain'][0]['message'])
            self.assertTrue(value['chainTruncated'])
            kind = type('Long', (ValueError,), {}); kind.__name__ = 'é' * 128
            value = json.loads(private_exception_chain(kind('message')))
            self.assertLessEqual(len(value['exceptionType'].encode('utf-8')), 128)
            self.assertLessEqual(len(value['contextChain'][0]['exceptionType'].encode('utf-8')), 128)
            self.assertTrue(value['chainTruncated'])
            with self.assertRaises(ValueError): private_exception_chain('foreign')
