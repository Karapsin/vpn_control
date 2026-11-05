"""Actual native Tart output shape through complete original owner observers."""
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

from agent_tools import readiness_tart_macos_known_off as known
from agent_tools.tests import test_readiness_tart_macos_known_off as controls


FIXTURES = Path(__file__).parent / "fixtures/tart_macos_known_off_provider_shape"


def beforeimage():
    path = FIXTURES / "known_off.before.source"
    expected = json.loads((FIXTURES / "provenance.json").read_bytes())["files"][path.name]["sha256"]
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise AssertionError("known-off provider beforeimage changed")
    name = "agent_tools._known_off_provider_shape_before"
    if name not in sys.modules:
        loader = importlib.machinery.SourceFileLoader(name, str(path))
        spec = importlib.util.spec_from_loader(name, loader)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        loader.exec_module(module)
    return sys.modules[name]


@unittest.skipUnless(os.name == "posix" and getattr(os, "geteuid", lambda: 0)() != 0,
                     "actual ordinary POSIX durable owners and provider locks")
class ProviderShapeTests(unittest.TestCase):
    def observe(self, implementation):
        with mock.patch.object(controls, "known", implementation):
            with controls.KnownOffTests().fixture(native_provider_shape=True) as fixture:
                return fixture["observe"]().as_dict()

    def test_complete_observer_accepts_actual_named_list_shape(self):
        implementation = beforeimage() if os.environ.get("VPN_CONTROL_TEST_KNOWN_OFF_PROVIDER_BEFORE") == "1" else known
        reply = self.observe(implementation)
        self.assertEqual(reply["kind"], "macos-original-off-phase-closed-v1")
        self.assertEqual(reply["stopCause"], "off_unknown")
        self.assertFalse(reply["cleanStopped"])

    def test_retained_complete_observer_refuses_actual_nameless_get_shape(self):
        with self.assertRaises(beforeimage().KnownOffBlocked):
            self.observe(beforeimage())

    def test_native_observations_and_whole_beforeimages_are_retained(self):
        provenance = json.loads((FIXTURES / "provenance.json").read_bytes())
        self.assertFalse(provenance["nativeStartSubmitted"])
        for name, pin in provenance["files"].items():
            raw = (FIXTURES / name).read_bytes()
            self.assertEqual({"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}, pin)
        detail = json.loads((FIXTURES / "native-get.stdout.json").read_bytes())
        listing = json.loads((FIXTURES / "native-list.stdout.json").read_bytes())
        self.assertNotIn("Name", detail)
        self.assertEqual(detail["State"], "stopped")
        self.assertIs(detail["Running"], False)
        self.assertEqual(len(listing), 1)
        self.assertEqual(listing[0]["Name"], "vpn-tool-recovery-tart-macos-7686d4aa")
        self.assertEqual(listing[0]["State"], "stopped")
        self.assertIs(listing[0]["Running"], False)


if __name__ == "__main__":
    unittest.main()
