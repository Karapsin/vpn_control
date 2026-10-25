"""Causal parent recovery checks using retained public source and real children.

The exact old/current callers are data fixtures. Each harness gets a separate
module namespace and controlled temporary filesystem. VM dispatch is translated
into a local Python child; normal lease responses are fixtures. No ignored
runtime inventory, credentials, framebuffer, or native VM is accessed.
"""
import hashlib
import json
import os
from pathlib import Path
import types
import unittest

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).with_name("fixtures") / "tart_macos_parent_recovery"
HARNESSES = ("lostack", "parent", "ledger", "raw", "permissions")
SOURCES = (
    "capture.source", "controller.source", "parent.ambient.before.source",
    "parent.before.source", "parent.current.source", "parent.permission.before.source",
    "permission-preparer.source", "public.before.source", "public.current.source",
    "public.raw-loss.before.source", "registry.before.source", "wake.source",
)


def _checked_fixtures():
    provenance = json.loads((FIXTURE / "provenance.json").read_bytes())
    expected = {"harnesses/" + name + ".source" for name in HARNESSES}
    expected.update("sources/" + name for name in SOURCES)
    if set(provenance["files"]) != expected:
        raise AssertionError("finite parent fixture set changed")
    for filename in sorted(expected):
        body = (FIXTURE / filename).read_bytes()
        if hashlib.sha256(body).hexdigest() != provenance["files"][filename]:
            raise AssertionError("retained parent fixture changed: " + filename)


class FixtureIntegrityTest(unittest.TestCase):
    def test_exact_finite_source_fixture_hashes(self):
        _checked_fixtures()


@unittest.skip("the parent custody uses POSIX no-follow file descriptors")
class UnsupportedHostTest(unittest.TestCase):
    def test_posix_parent_custody(self):
        pass


def load_tests(loader, standard_tests, pattern):
    suite = loader.loadTestsFromTestCase(FixtureIntegrityTest)
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        suite.addTests(loader.loadTestsFromTestCase(UnsupportedHostTest))
        return suite
    _checked_fixtures()
    for name in HARNESSES:
        path = FIXTURE / "harnesses" / (name + ".source")
        module = types.ModuleType(__name__ + "_" + name)
        module.__file__ = str(path)
        module.ROOT, module.FIXTURE = ROOT, FIXTURE
        exec(compile(path.read_bytes(), str(path), "exec", dont_inherit=True), module.__dict__)
        for value in tuple(module.__dict__.values()):
            if isinstance(value, type) and issubclass(value, unittest.TestCase) and value is not unittest.TestCase:
                suite.addTests(loader.loadTestsFromTestCase(value))
    return suite


if __name__ == "__main__":
    unittest.main(verbosity=2)
