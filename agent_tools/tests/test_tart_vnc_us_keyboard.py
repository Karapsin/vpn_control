"""Complete RFB callers against a controlled physical US keyboard projection.

Apple's native keysym-without-Shift failure is retained independently. This TCP
fixture models that behavior; it does not substitute for native qualification.
Private keystrokes exist only in endpoint memory and never enter test messages.
"""
import contextlib
import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
import io
import json
import logging
import os
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from agent_tools import readiness_tart_vnc as current
from agent_tools.tests.test_readiness_tart_vnc import RfbEndpoint

_SHIFTED = '~!@#$%^&*()_+{}|:"<>?'
_BASE = '`1234567890-=[]\\;\',./'


def physical_us_text(events):
    shift = False
    result = []
    for kind, down, code in events:
        if kind != 'key':
            raise AssertionError('unexpected non-key event')
        if code == 0xFFE1:
            shift = bool(down)
            continue
        if not down:
            continue
        char = chr(code)
        if 'A' <= char <= 'Z':
            char = char.lower()
        elif char in _SHIFTED:
            char = _BASE[_SHIFTED.index(char)]
        if shift:
            if 'a' <= char <= 'z':
                char = char.upper()
            elif char in _BASE:
                char = _SHIFTED[_BASE.index(char)]
        result.append(char)
    return ''.join(result)


@unittest.skipUnless(os.name == 'posix', 'protected FD and private input journal')
class PhysicalUsKeyboardTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)

    def original(self):
        path = Path(__file__).parent / 'fixtures/tart_vnc_us_shift.before.source'
        source = path.read_bytes()
        self.assertEqual('0a6fee82aee519f5f1fca489a14e705e7b168a31fec3d6393498e629c959bc49', hashlib.sha256(source).hexdigest())
        loader = SourceFileLoader('agent_tools._before_us_shift', str(path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        return module

    def fd(self, body):
        reader, writer = os.pipe()
        os.write(writer, body)
        os.close(writer)
        self.addCleanup(os.close, reader)
        return reader

    def exercise(self, module, text, *, private=False):
        endpoint = RfbEndpoint()
        self.addCleanup(endpoint.close)
        receipt = None
        with module.ProtectedVncSession(port=endpoint.port, credential_fd=self.fd(b'controlled-rfb'), guard=lambda: None) as view:
            if private:
                operation = str(uuid4())
                journal = module.SecretInputJournal(self.root, str(uuid4()))
                endpoint.receipt_probe = (self.root / (operation + '.json')).exists
                receipt = view.type_secret_from_fd(self.fd(text.encode()), operation_id=operation, journal=journal, guard=lambda: None)
            else:
                view.type_public(text)
            expected = 2 * len(text) + (2 * sum(char.isupper() or char in _SHIFTED for char in text) if module is current else 0)
            events = endpoint.wait_events(expected)
        self.assertFalse(endpoint.missing_receipt)
        result = physical_us_text(events)
        endpoint.close()
        return result, receipt

    def test_public_complete_before_caller_red_current_green_for_us_ascii(self):
        # All printable US ASCII characters, including uppercase and every
        # shifted punctuation symbol. This is public synthetic fixture input.
        text = ''.join(chr(value) for value in range(32, 127))
        red, _ = self.exercise(self.original(), text)
        self.assertNotEqual(text, red)
        green, _ = self.exercise(current, text)
        self.assertEqual(text, green)

    def test_private_complete_before_red_green_has_no_recorded_derived_input(self):
        text = 'Synthetic-ONLY!A@Z?'
        output = io.StringIO()
        handler = logging.StreamHandler(output)
        logging.getLogger().addHandler(handler)
        self.addCleanup(logging.getLogger().removeHandler, handler)
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            red, _ = self.exercise(self.original(), text, private=True)
            green, receipt = self.exercise(current, text, private=True)
        self.assertTrue(red != text, 'original private input unexpectedly matches')
        self.assertTrue(green == text, 'private input modifier sequence incorrect')
        self.assertEqual('unknown', receipt['state'])
        self.assertEqual('', output.getvalue())
        for path in self.root.glob('*.json'):
            record = json.loads(path.read_text())
            self.assertEqual({'schemaVersion', 'operationId', 'bindingId', 'action', 'state'}, set(record))
            self.assertEqual('unknown', record['state'])
            self.assertTrue(text not in path.read_text(), 'private input leaked into receipt')

    def test_stale_guard_after_shift_down_leaves_original_unknown_and_no_retry(self):
        endpoint = RfbEndpoint()
        self.addCleanup(endpoint.close)
        armed = False
        calls = 0
        def guard():
            nonlocal calls
            if armed:
                calls += 1
                if calls == 4:
                    raise RuntimeError('private diagnostic')
        operation = str(uuid4())
        journal = current.SecretInputJournal(self.root, str(uuid4()))
        with current.ProtectedVncSession(port=endpoint.port, credential_fd=self.fd(b'controlled-rfb'), guard=guard) as view:
            armed = True
            with self.assertRaisesRegex(current.VncBlocked, '^vnc_binding_changed$'):
                view.type_secret_from_fd(self.fd(b'A'), operation_id=operation, journal=journal, guard=lambda: None)
        self.assertTrue(endpoint.wait_events(1) == [('key', 1, 0xFFE1)], 'stale admission sent additional input')
        self.assertEqual('unknown', json.loads((self.root / (operation + '.json')).read_text())['state'])
        with self.assertRaisesRegex(current.VncBlocked, '^vnc_secret_original_unknown$'):
            journal.begin(operation)
