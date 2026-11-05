"""Use the complete consumed bundle implementation to reproduce native reuse.

Only the transferred sources are harmless fixture bytes. The actual original
create-only staging, private readers, inventory and receipt loader execute.
"""
import base64
import hashlib
import os
from pathlib import Path
import tempfile
import types
import unittest
import uuid

from agent_tools import android_component_successor as successor

FIXTURE = Path(__file__).parent / "fixtures/android_component_successor/bundle.before.source"
FIXTURE_SHA = "6d2ff26ae551d1d7c3b2b7ba7428b02fdd1e28e91beb760a4a4ee12de7738a85"


@unittest.skipUnless(os.name == "posix", "The consumed Android bundle is POSIX-only")
class ExistingComponentBundleTests(unittest.TestCase):
    def fixture(self, root):
        raw = FIXTURE.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), FIXTURE_SHA)
        bundle = types.ModuleType("existing_component_bundle_fixture")
        bundle.__file__ = str(FIXTURE)
        exec(compile(raw, str(FIXTURE), "exec"), bundle.__dict__)
        files = {name: (b"# owned inert fixture: " + name.encode() + b"\n") for name in bundle.FILES}
        tree = bundle._tree({name: (raw, {"sha256": hashlib.sha256(raw).hexdigest()})
                             for name, raw in files.items()})
        digest = hashlib.sha256(bundle._raw(tree)).hexdigest()
        payload = {"schema": 1, "kind": "android-installer-component-transfer",
                   "treeSha256": digest,
                   "files": {name: base64.b64encode(raw).decode() for name, raw in files.items()}}
        directory = root / ("android-installer-component-bundle-" + str(uuid.uuid4()))
        original = bundle.stage_payload(payload, directory, digest)
        return bundle, payload, directory, digest, original

    def test_existing_original_stage_is_qualified_without_another_create(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            bundle, payload, directory, digest, original = self.fixture(root)
            before = {str(p.relative_to(root)): successor._pin(p.lstat())
                      for p in root.rglob("*")}
            if os.environ.get("VPN_CONTROL_TEST_LEGACY_STAGE") == "1":
                actual = bundle.stage_payload(payload, directory, digest)
            else:
                actual = successor.qualify_existing_bundle(bundle, payload, directory, digest)
            self.assertEqual(actual, original)
            self.assertEqual({str(p.relative_to(root)): successor._pin(p.lstat())
                              for p in root.rglob("*")}, before)

    def test_fresh_metadata_does_not_adopt_different_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            bundle, payload, directory, digest, _ = self.fixture(root)
            target = directory / bundle.FILES[0]
            raw = target.read_bytes()
            target.write_bytes(b"x" * len(raw))
            with self.assertRaisesRegex(ValueError, "successor_existing_bundle_source_changed"):
                successor.qualify_existing_bundle(bundle, payload, directory, digest)

    def test_symbolic_exchange_is_refused_without_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            bundle, payload, directory, digest, _ = self.fixture(root)
            target = directory / bundle.FILES[0]
            raw = target.read_bytes()
            target.unlink()
            foreign = root / "foreign"
            foreign.write_bytes(raw)
            foreign.chmod(0o600)
            target.symlink_to(foreign)
            with self.assertRaises((ValueError, OSError)):
                successor.qualify_existing_bundle(bundle, payload, directory, digest)
            self.assertTrue(target.is_symlink())


if __name__ == "__main__":
    unittest.main()
