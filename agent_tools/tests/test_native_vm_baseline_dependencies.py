"""Actual QEMU metadata admission and capture gate; no QEMU or VM execution."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import native_vm_baseline as baseline


def standalone():
    return {"format": "qcow2", "virtual-size": 96 * 1024 ** 3,
            "format-specific": {"type": "qcow2", "data": {
                "compat": "1.1", "refcount-bits": 16, "compression-type": "zlib"}}}


class Qcow2DependencyTests(unittest.TestCase):
    def inspect(self, value):
        result = subprocess.CompletedProcess([], 0, json.dumps(value).encode())
        with patch.object(baseline.subprocess, "run", return_value=result) as run:
            baseline.QemuProvider.inspect_flat_qcow2(Path("/fixture/source.qcow2"))
        self.assertEqual(run.call_args.args[0],
                         ("qemu-img", "info", "--output=json", "/fixture/source.qcow2"))

    def test_measured_external_data_dependency_refused(self):
        value = standalone()
        value["format-specific"]["data"].update({"data-file": "/fixture/external.raw",
                                                 "data-file-raw": True})
        with self.assertRaisesRegex(baseline.VmBaselineError, "external data"):
            self.inspect(value)

    def test_presence_at_each_dependency_level_refused_even_empty(self):
        for key in ("data-file", "data-file-raw"):
            for item in (None, "", False):
                for location in ("image", "descriptor", "data"):
                    with self.subTest(key=key, item=item, location=location):
                        value = standalone()
                        target = {"image": value, "descriptor": value["format-specific"],
                                  "data": value["format-specific"]["data"]}[location]
                        target[key] = item
                        with self.assertRaisesRegex(baseline.VmBaselineError, "external data"):
                            self.inspect(value)

    def test_malformed_dependency_descriptor_refused(self):
        for descriptor in (None, [], "qcow2", {}, {"type": "raw", "data": {}},
                           {"type": "qcow2"}, {"type": "qcow2", "data": None},
                           {"type": "qcow2", "data": []}):
            with self.subTest(descriptor=descriptor):
                value = standalone()
                value["format-specific"] = descriptor
                with self.assertRaisesRegex(baseline.VmBaselineError, "dependency descriptor"):
                    self.inspect(value)

    def test_standalone_metadata_and_existing_backing_gates(self):
        self.inspect(standalone())
        self.inspect({"format": "qcow2"})  # Existing minimal metadata compatibility.
        for key in ("backing-filename", "full-backing-filename"):
            value = standalone()
            value[key] = "/fixture/base.qcow2"
            with self.assertRaisesRegex(baseline.VmBaselineError, "backing chain"):
                self.inspect(value)


@unittest.skipUnless(os.name == "posix", "capture filesystem ownership requires POSIX")
class CaptureDependencyTests(unittest.TestCase):
    def capture(self, metadata, *, rejected):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source_root, store = root / "source", root / "store"
            source_root.mkdir(mode=0o700)
            store.mkdir(mode=0o700)
            source = source_root / "source.qcow2"
            source.write_bytes(b"PUBLIC_SOURCE_BYTES")
            source.chmod(0o600)
            observed = baseline.SourceObservation("source-one", "generation-one", source,
                True, True, True, "none", "a" * 64, "b" * 64, {"runtime": "c" * 64})
            provider = baseline.QemuProvider(source_root=source_root,
                sources={"source-one": baseline.SourceBinding(
                    "source-one", source, "generation-one", "source-one")},
                observe=lambda _: observed)
            manager = baseline.BaselineManager(root=store, providers={"qemu": provider})
            response = subprocess.CompletedProcess([], 0, json.dumps(metadata).encode())
            with patch.object(baseline.subprocess, "run", return_value=response), \
                 patch.object(provider, "copy", wraps=provider.copy) as copy:
                if rejected:
                    with self.assertRaisesRegex(baseline.VmBaselineError, "external data"):
                        manager.capture(provider="qemu", source_id="source-one",
                            baseline="baseline-one", generation="generation-one")
                    copy.assert_not_called()
                    folder = store / "baselines/qemu/baseline-one"
                    self.assertTrue((folder / "intent.json").is_file())
                    self.assertFalse((folder / "disk.qcow2").exists())
                    self.assertFalse((folder / "manifest.json").exists())
                else:
                    receipt = manager.capture(provider="qemu", source_id="source-one",
                        baseline="baseline-one", generation="generation-one")
                    copy.assert_called_once()
                    self.assertEqual(source.read_bytes(), Path(receipt["baselinePath"]).read_bytes())
                    self.assertEqual(manager.verify(receipt), receipt)

    def test_actual_capture_rejects_dependency_before_copy_and_keeps_intent(self):
        metadata = standalone()
        metadata["format-specific"]["data"]["data-file"] = "/fixture/external.raw"
        self.capture(metadata, rejected=True)

    def test_actual_flat_capture_and_verification_still_pass(self):
        self.capture(standalone(), rejected=False)
