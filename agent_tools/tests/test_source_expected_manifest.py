"""Complete authentic loader admission before any imported top-level effect."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import types
import unittest

from agent_tools import source_module_loader as current


@unittest.skipUnless(os.name == "posix", "held POSIX manifest source")
class ExpectedSourceManifestTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=Path("/tmp").resolve())
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.directory = self.root / "agent_tools"
        self.directory.mkdir(mode=0o700)
        primitive = Path(current.__file__).with_name("native_review_source_closure.py")
        shutil.copyfile(primitive, self.directory / primitive.name)
        (self.directory / "entry.py").write_text("from . import helper\ndef value():return helper.VALUE\n")
        (self.directory / "helper.py").write_text("VALUE='original'\n")
        for path in self.directory.iterdir():
            path.chmod(0o600)
        self.expected = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in self.directory.iterdir()}
        self.marker = self.root / "top-level-effect"

    def preserved(self):
        folder = Path(__file__).parent / "fixtures/expected_source_manifest"
        path = folder / "before.source"
        raw = path.read_bytes()
        provenance = json.loads((folder / "provenance.json").read_bytes())
        self.assertEqual(provenance["sourceSha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(provenance["sourceBytes"], len(raw))
        module = types.ModuleType("_manifest_before_loader")
        module.__file__ = str(path)
        sys.modules[module.__name__] = module
        self.addCleanup(sys.modules.pop, module.__name__, None)
        exec(compile(raw, str(path), "exec"), module.__dict__)
        return module

    def change(self, name):
        path = self.directory / name
        path.write_text("from pathlib import Path\nPath(" + repr(str(self.marker)) + ").write_text('executed')\n" + path.read_text())

    def assert_no_effect(self):
        self.assertFalse(self.marker.exists(), "unmanifested top-level code executed")

    def test_preserved_loader_executes_changed_import_before_post_import_validation(self):
        before = self.preserved()
        self.change("helper.py")
        session = before.SourceSession(self.directory, "entry")
        try:
            with self.assertRaises(AssertionError):
                self.assert_no_effect()
        finally:
            session.close()
        self.marker.unlink()
        with self.assertRaisesRegex(ValueError, "expected_source_bytes_changed"):
            current.SourceSession(self.directory, "entry", expected_sources=self.expected)
        self.assert_no_effect()

    def test_preserved_loader_executes_changed_custody_primitive_before_validation(self):
        before = self.preserved()
        # Insert after the future statement so the authentic primitive remains
        # executable and supplies its real _Held implementation to the loader.
        path = self.directory / "native_review_source_closure.py"
        body = path.read_text().replace("from __future__ import annotations\n",
            "from __future__ import annotations\nfrom pathlib import Path\nPath(" + repr(str(self.marker)) + ").write_text('primitive executed')\n", 1)
        path.write_text(body)
        session = before.SourceSession(self.directory, "entry")
        try:
            with self.assertRaises(AssertionError):
                self.assert_no_effect()
        finally:
            session.close()
        self.marker.unlink()
        with self.assertRaisesRegex(ValueError, "expected_source_bytes_changed"):
            current.SourceSession(self.directory, "entry", expected_sources=self.expected)
        self.assert_no_effect()

    def test_complete_manifest_executes_real_import_and_is_copied_from_caller(self):
        expected = dict(self.expected)
        with current.request_scope(self.directory, expected_sources=expected):
            adapter = current.adapter(self.directory, "entry")
            self.assertEqual("original", adapter.value())
            expected.clear()
            self.assertEqual("original", adapter.value())

    def test_missing_entry_or_import_cannot_execute_and_manifest_paths_are_strict(self):
        for missing in ("entry.py", "helper.py"):
            expected = {name: digest for name, digest in self.expected.items() if Path(name).name != missing}
            with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, "expected_source_bytes_changed"):
                current.SourceSession(self.directory, "entry", expected_sources=expected)
        for name in ("relative.py", str(self.directory / ".." / "foreign.py"), str(self.root / "foreign.py")):
            with self.subTest(path=name), self.assertRaisesRegex(ValueError, "expected_source_manifest_entry"):
                current.SourceSession(self.directory, "entry", expected_sources={**self.expected, name: "a" * 64})
        self.assert_no_effect()


if __name__ == "__main__":
    unittest.main()
