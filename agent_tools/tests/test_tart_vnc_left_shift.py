"""Named modifier API only; never an automatic wake or native input test."""
import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
import os
from pathlib import Path
import unittest

from agent_tools import readiness_tart_vnc as current
from agent_tools.tests.test_readiness_tart_vnc import RfbEndpoint


@unittest.skipUnless(os.name == 'posix', 'protected authentication FD')
class NamedLeftShiftTests(unittest.TestCase):
    def fd(self):
        reader, writer = os.pipe()
        os.write(writer, b'controlled-rfb-auth')
        os.close(writer)
        self.addCleanup(os.close, reader)
        return reader

    def test_complete_before_refuses_zero_events_current_sends_exact_pair(self):
        path = Path(__file__).parent / 'fixtures/tart_vnc_left_shift.before.source'
        source = path.read_bytes()
        self.assertEqual('e255c36b37fcda19843b1276d0727bc46c1080b6ca98e2f460eea00b473ee7e8', hashlib.sha256(source).hexdigest())
        loader = SourceFileLoader('agent_tools._before_left_shift', str(path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        before = importlib.util.module_from_spec(spec)
        loader.exec_module(before)
        for module in (before, current):
            with self.subTest(source=module.__name__):
                endpoint = RfbEndpoint()
                self.addCleanup(endpoint.close)
                with module.ProtectedVncSession(port=endpoint.port, credential_fd=self.fd(), guard=lambda: None) as view:
                    if module is before:
                        with self.assertRaisesRegex(before.VncBlocked, '^vnc_public_key_invalid$'):
                            view.key('LEFT_SHIFT')
                        self.assertEqual([], endpoint.events)
                    else:
                        view.key('LEFT_SHIFT')
                        self.assertEqual([('key', 1, 0xFFE1), ('key', 0, 0xFFE1)], endpoint.wait_events(2))
                endpoint.close()

    def test_stale_guard_between_down_and_up_stops_without_auto_release(self):
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
                view.key('LEFT_SHIFT')
            self.assertEqual([('key', 1, 0xFFE1)], endpoint.wait_events(1))
            with self.assertRaisesRegex(current.VncBlocked, '^vnc_session_closed$'):
                view.key('LEFT_SHIFT')
        self.assertEqual([('key', 1, 0xFFE1)], endpoint.events)
