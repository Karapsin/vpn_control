"""Complete real TCP wake callers, with no VM, ordinary credential or power."""
import contextlib
from dataclasses import replace
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from uuid import uuid4

from agent_tools import readiness
from agent_tools import readiness_tart_macos_wake as wake
from agent_tools.tests.test_readiness_tart_vnc import RfbEndpoint


@unittest.skipUnless(os.name == "posix", "protected RFB FD requires POSIX")
class WakeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve(); self.root.chmod(0o700)
        self.credential = self.root / "rfb-auth.bin"
        self.credential.write_bytes(b"public-fixture"); self.credential.chmod(0o600)
        self.endpoint = RfbEndpoint()
        self.operation = str(uuid4())
        self.original = readiness.Observation("owned", "machine", "connection", "boot", "ordinary", "session",
            transport="ready", guest="running", guest_agent=True, ordinary_session="locked",
            display="sleeping", trusted=True, owned=True, integrity=True)
        credential = SimpleNamespace(credential_fd=lambda: os.open(self.credential, os.O_RDONLY))
        custody = SimpleNamespace(lifecycle_root=self.root, endpoint={"port":self.endpoint.port},
                                  _credentials={"vnc":credential})
        self.calls = 0; self.change = None
        def observe(requirements, deadline):
            self.calls += 1
            if self.change is not None: return self.change(self.calls)
            # The full native display state settles only after the key pair.
            return replace(self.original, display="ready") if self.calls >= 10 else self.original
        self.backend = SimpleNamespace(custody=custody, observe=observe,
                                       operation_scope=lambda **kwargs: contextlib.nullcontext())

    def tearDown(self):
        self.endpoint.close(); self.temp.cleanup()

    def run_wake(self):
        return wake.wake_once(self.backend, self.operation, deadline=time.monotonic()+5)

    def test_one_journaled_pair_then_settled_observation_with_no_replay(self):
        self.endpoint.receipt_probe = lambda: (self.root/('macos-wake-'+self.operation+'.json')).exists()
        result = self.run_wake()
        self.assertEqual(result['state'], 'observed_ready')
        self.assertEqual(result['inputGroups'], 1)
        self.endpoint.closed.wait(.2)
        self.assertEqual(self.endpoint.events, [('key',1,0xFFE1),('key',0,0xFFE1)])
        self.assertFalse(self.endpoint.missing_receipt)
        self.backend.observe = lambda *args: self.original
        with self.assertRaisesRegex(wake.WakeBlocked, 'original_pending'): self.run_wake()
        self.assertEqual(len(self.endpoint.events), 2)

    def test_wrong_or_unknown_session_is_rejected_before_authentication(self):
        self.original = replace(self.original, ordinary_session='unknown')
        with self.assertRaisesRegex(wake.WakeBlocked, 'session_unrecognized'): self.run_wake()
        self.assertFalse(self.endpoint.responses)
        self.assertFalse(any(p.name.startswith('macos-wake-') for p in self.root.iterdir()))

    def test_identity_change_after_down_preserves_unknown_without_release(self):
        self.change = lambda count: replace(self.original, boot='different') if count >= 8 else self.original
        with self.assertRaises(wake.rfb.VncBlocked): self.run_wake()
        self.endpoint.closed.wait(.2)
        self.assertEqual(self.endpoint.events, [('key',1,0xFFE1)])
        self.assertTrue((self.root/('macos-wake-'+self.operation+'.json')).exists())
        self.assertFalse((self.root/('macos-wake-'+self.operation+'-transport.json')).exists())

    def test_status_observes_original_without_authentication_or_new_input(self):
        self.run_wake()
        count = len(self.endpoint.events)
        result = wake.status(self.backend, self.operation, deadline=time.monotonic()+3)
        self.assertEqual(result['state'], 'observed_ready')
        self.assertEqual(len(self.endpoint.events), count)


    def test_whole_native_before_source_change_after_down_red_current_blocks(self):
        import hashlib, importlib.util, sys
        from importlib.machinery import SourceFileLoader
        before = Path(__file__).parent / 'fixtures/tart_macos_wake_source/whole_before.source'
        self.assertEqual(hashlib.sha256(before.read_bytes()).hexdigest(),
                         '4864dec7d3f513ce1d7eb8ceb69c4cf08cdb2d7660dd9d96e985c97f924a4f5c')
        for index, raw in enumerate((before.read_bytes(), Path(wake.__file__).read_bytes())):
            with self.subTest(index=index):
                self.endpoint.close(); self.endpoint = RfbEndpoint()
                self.backend.custody.endpoint = {'port': self.endpoint.port}
                self.operation = str(uuid4()); self.calls = 0
                source = self.root / ('copied-producer-'+str(index)+'.py')
                source.write_bytes(raw); source.chmod(0o600)
                name = 'agent_tools._owned_wake_source_test_'+str(index)
                loader = SourceFileLoader(name, str(source)); spec = importlib.util.spec_from_loader(name, loader)
                module = importlib.util.module_from_spec(spec); sys.modules[name] = module
                loader.exec_module(module)
                def changing(count):
                    if count == 8:
                        with source.open('ab') as stream: stream.write(b'\n# owned test source changed during event observation\n')
                    return replace(self.original, display='ready') if count >= 10 else self.original
                self.change = changing
                try:
                    if index == 0:
                        module.wake_once(self.backend,self.operation,deadline=time.monotonic()+5)
                        self.assertEqual(self.endpoint.wait_events(2), [('key',1,0xFFE1),('key',0,0xFFE1)])
                    else:
                        with self.assertRaises(wake.rfb.VncBlocked):
                            module.wake_once(self.backend,self.operation,deadline=time.monotonic()+5)
                        self.assertEqual(self.endpoint.wait_events(1), [('key',1,0xFFE1)])
                finally:
                    sys.modules.pop(name,None)


if __name__ == '__main__': unittest.main()
