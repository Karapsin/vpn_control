"""Real TCP caller regressions for the natively observed Apple VZ dialect.

Generic TigerVNC/vncdotool Super_L mapping demonstrably failed on this owned
Tart/VZ server. Its native Command uses Alt_L and Option uses Meta_L; the finite
public observations and both failed whole caller sources remain preserved.
No controlled transcript substitutes for native corrected public API proof.
"""
import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
import os
import json
from pathlib import Path
import unittest

from agent_tools import readiness_tart_vnc as current
from agent_tools.tests.test_readiness_tart_vnc import RfbEndpoint


@unittest.skipUnless(os.name == 'posix', 'protected authentication FD')
class MacCommandTests(unittest.TestCase):
    def fd(self):
        reader, writer = os.pipe()
        os.write(writer, b'controlled-rfb-auth')
        os.close(writer)
        self.addCleanup(os.close, reader)
        return reader

    def test_actual_whole_before_caller_red_correct_command_wire_green(self):
        path = Path(__file__).parent / 'fixtures/tart_vnc_mac_command.before.source'
        source = path.read_bytes()
        self.assertEqual('4b83be6b11f98c496c1ebad1c947883d3062160d039a11e3f3cc536df49911b1', hashlib.sha256(source).hexdigest())
        loader = SourceFileLoader('agent_tools._before_mac_command', str(path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        before = importlib.util.module_from_spec(spec)
        loader.exec_module(before)
        expected = [('key', 1, 0xFFE9), ('key', 1, ord('a')), ('key', 0, ord('a')), ('key', 0, 0xFFE9)]
        for module in (before, current):
            with self.subTest(source=module.__name__):
                endpoint = RfbEndpoint()
                self.addCleanup(endpoint.close)
                with module.ProtectedVncSession(port=endpoint.port, credential_fd=self.fd(), guard=lambda: None) as view:
                    view.key('a', modifiers=('MacMeta',))
                    events = endpoint.wait_events(4)
                if module is before:
                    self.assertEqual(0xFFE7, events[0][2])
                    self.assertNotEqual(expected, events)
                else:
                    self.assertEqual(expected, events)
                endpoint.close()

    def test_stale_guard_after_command_down_stops_before_key_without_release(self):
        endpoint = RfbEndpoint()
        self.addCleanup(endpoint.close)
        armed = False
        count = 0
        def guard():
            nonlocal count
            if armed:
                count += 1
                if count == 3:
                    raise RuntimeError('private custody diagnostic')
        with current.ProtectedVncSession(port=endpoint.port, credential_fd=self.fd(), guard=guard) as view:
            armed = True
            with self.assertRaisesRegex(current.VncBlocked, '^vnc_binding_changed$'):
                view.key('a', modifiers=('MacMeta',))
            self.assertEqual([('key', 1, 0xFFE9)], endpoint.wait_events(1))
            with self.assertRaisesRegex(current.VncBlocked, '^vnc_session_closed$'):
                view.key('a', modifiers=('MacMeta',))
        self.assertEqual([('key', 1, 0xFFE9)], endpoint.events)

    def test_native_vz_command_option_dialect_both_before_sources_red_current_green(self):
        fixtures = Path(__file__).parent / 'fixtures'
        path = fixtures / 'tart_vnc_vz_modifiers.before.source'
        source = path.read_bytes()
        self.assertEqual('8dbd9f8256232a449c8628e63cf09c2d0949f62935ee29cc91b1c8759dc0cd2c', hashlib.sha256(source).hexdigest())
        facts = json.loads((fixtures / 'tart_vnc_vz_modifiers.native-facts.json').read_text())
        self.assertEqual({65511: 'option', 65515: 'unqualified', 65513: 'command'},
                         {row['keysym']: row['role'] for row in facts['nativeEvidence']})
        self.assertFalse(facts['privateInputCreatedOrSubmitted'])
        loader = SourceFileLoader('agent_tools._before_vz_modifiers', str(path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        before = importlib.util.module_from_spec(spec)
        loader.exec_module(before)
        expected = [('key', 1, 0xFFE9), ('key', 1, ord('a')), ('key', 0, ord('a')), ('key', 0, 0xFFE9),
                    ('key', 1, 0xFFE7), ('key', 1, ord('a')), ('key', 0, ord('a')), ('key', 0, 0xFFE7)]
        for module in (before, current):
            with self.subTest(source=module.__name__):
                endpoint = RfbEndpoint()
                self.addCleanup(endpoint.close)
                with module.ProtectedVncSession(port=endpoint.port, credential_fd=self.fd(), guard=lambda: None) as view:
                    view.key('a', modifiers=('MacMeta',))
                    view.key('a', modifiers=('Alt',))
                    events = endpoint.wait_events(8)
                if module is before:
                    self.assertEqual((0xFFEB, 0xFFE9), (events[0][2], events[4][2]))
                    self.assertNotEqual(expected[:4], events[:4])
                    self.assertNotEqual(expected[4:], events[4:])
                else:
                    self.assertEqual(expected, events)
                endpoint.close()
