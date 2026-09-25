import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from agent_tools import native_vm_baseline as b


class FlatQemu(b.QemuProvider):
    def inspect_flat_qcow2(self, path):
        if Path(path).suffix != ".qcow2":
            raise b.VmBaselineError("QEMU source must be qcow2")


@unittest.skipIf(os.name != "posix", "private VM filesystem admission requires POSIX")
class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        home = Path(self.temp.name).resolve()
        self.source_root = home / "sources"
        self.source_root.mkdir(mode=0o700)
        self.store = home / "store"
        self.store.mkdir(mode=0o700)
        self.source = self.source_root / "source.qcow2"
        self.source.write_bytes(b"qcow2 fixture bytes" * 1000)
        self.observation_calls = 0
        self.state = {
            "source_id": "linux-one", "generation": "generation-one", "path": self.source,
            "owned": True, "stopped": True, "quiescent": True,
            "installer_job": "terminal", "access_receipt": "a" * 64,
            "dependency_receipt": "b" * 64, "fingerprint": {"runtime": "c" * 64},
        }
        self.commands = []

        def observe(source_id):
            self.observation_calls += 1
            return b.SourceObservation(**self.state)

        def run(argv):
            self.commands.append(argv)
            if argv[:3] == ("qemu-img", "create", "-f"):
                Path(argv[-1]).write_bytes(b"fresh overlay")
            elif argv[:2] == ("tart", "clone"):
                shutil.copytree(self.source_root / argv[2], self.source_root / argv[3])
            else:
                raise AssertionError(argv)

        self.run = run
        self.provider = FlatQemu(source_root=self.source_root,
                                 sources={"linux-one": b.SourceBinding("linux-one", self.source,
                                                                        "generation-one", "linux-one")},
                                 observe=observe, runner=run)
        self.manager = b.BaselineManager(root=self.store, providers={"qemu": self.provider})

    def capture(self, baseline="baseline-one"):
        return self.manager.capture(provider="qemu", source_id="linux-one", baseline=baseline,
                                    generation="generation-one")

    def test_qemu_capture_verify_and_fresh_overlay(self):
        manifest = self.capture()
        self.assertGreaterEqual(self.observation_calls, 3)
        self.assertEqual(self.source.read_bytes(), Path(manifest["baselinePath"]).read_bytes())
        self.assertEqual(manifest, self.manager.verify(manifest))
        result = self.manager.restore(manifest, destination="run-one")
        self.assertEqual("disposable-created", result["state"])
        self.assertEqual(b"fresh overlay", Path(result["path"]).read_bytes())
        self.assertEqual(("qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b",
                          manifest["baselinePath"], result["path"]), self.commands[-1])
        self.assertEqual(self.source.read_bytes(), Path(manifest["baselinePath"]).read_bytes())
        with self.assertRaises(b.VmBaselineError):
            self.manager.restore(manifest, destination="run-one")

    def test_manifest_and_bytes_are_verified(self):
        manifest = self.capture()
        altered = dict(manifest, baselineSha256="d" * 64)
        with self.assertRaises(b.VmBaselineError):
            self.manager.verify(altered)
        os.chmod(manifest["baselinePath"], 0o600)
        Path(manifest["baselinePath"]).write_bytes(b"changed")
        with self.assertRaises(b.VmBaselineError):
            self.manager.verify(manifest)

    def test_admission_blocks_unsafe_observations(self):
        for change in ({"owned": False}, {"stopped": False}, {"quiescent": False},
                       {"installer_job": "running"}, {"installer_job": "unknown"},
                       {"access_receipt": ""}, {"dependency_receipt": ""},
                       {"fingerprint": {}}, {"generation": "generation-two"}):
            with self.subTest(change=change):
                self.state.update(change)
                with self.assertRaises(b.VmBaselineError):
                    self.capture("test-" + str(len(self.commands) + self.observation_calls))
                for key in change:
                    self.state[key] = self.original_state[key]
        self.assertFalse(self.commands)

    @property
    def original_state(self):
        return {"owned": True, "stopped": True, "quiescent": True, "installer_job": "terminal",
                "access_receipt": "a" * 64, "dependency_receipt": "b" * 64,
                "fingerprint": {"runtime": "c" * 64}, "generation": "generation-one"}

    def test_reobserve_blocks_changed_state_before_effect(self):
        original = self.provider.observe
        def change_on_second(source_id):
            if self.observation_calls == 1:
                self.state["stopped"] = False
            return original(source_id)
        self.provider.observe = change_on_second
        with self.assertRaises(b.VmBaselineError):
            self.capture()
        self.assertFalse(self.commands)
        self.assertTrue((self.store / "baselines/qemu/baseline-one/intent.json").exists())
        self.assertFalse((self.store / "baselines/qemu/baseline-one/manifest.json").exists())

    def test_qemu_baseline_must_remain_sealed(self):
        manifest = self.capture()
        os.chmod(manifest["baselinePath"], 0o600)
        with self.assertRaises(b.VmBaselineError):
            self.manager.verify(manifest)

    def test_rejects_changed_source_without_generation_change(self):
        manifest = self.capture()
        self.source.write_bytes(b"new source content")
        with self.assertRaises(b.VmBaselineError):
            self.manager.verify(manifest)

    def test_rejects_stale_generation_and_provenance(self):
        manifest = self.capture()
        self.state["generation"] = "generation-two"
        with self.assertRaises(b.VmBaselineError):
            self.manager.verify(manifest)
        self.state["generation"] = "generation-one"
        self.state["dependency_receipt"] = "d" * 64
        with self.assertRaises(b.VmBaselineError):
            self.manager.verify(manifest)
        self.assertEqual([], self.commands)

    def test_rejects_symlink_before_resolution_and_collision(self):
        link = self.source_root / "link.qcow2"
        link.symlink_to(self.source)
        self.provider.sources["linux-one"] = b.SourceBinding("linux-one", link, "generation-one", "linux-one")
        self.state["path"] = link
        with self.assertRaises(b.VmBaselineError):
            self.capture()
        self.assertFalse(self.commands)

    def test_rejects_missing_inventory_and_unsafe_name(self):
        with self.assertRaises(b.VmBaselineError):
            self.manager.capture(provider="qemu", source_id="other-source", baseline="safe-one", generation="generation-one")
        with self.assertRaises(b.VmBaselineError):
            self.manager.capture(provider="qemu", source_id="linux-one", baseline="../bad", generation="generation-one")
        with self.assertRaises(b.VmBaselineError):
            self.manager.capture(provider="qemu", source_id="linux-one", baseline="safe-one", generation="old-generation")

    def test_qemu_refuses_backing_chain_and_preserves_intent(self):
        def reject(_):
            raise b.VmBaselineError("backing chain")
        self.provider.inspect_flat_qcow2 = reject
        with self.assertRaises(b.VmBaselineError):
            self.capture()
        self.assertTrue((self.store / "baselines/qemu/baseline-one/intent.json").exists())
        self.assertFalse((self.store / "baselines/qemu/baseline-one/manifest.json").exists())

    def test_real_qemu_inspector_rejects_backing_chain_and_unknown_format(self):
        provider = b.QemuProvider(source_root=self.source_root,
                                  sources=self.provider.sources,
                                  observe=self.provider.observe, runner=self.run)
        for payload in ({"format": "qcow2", "backing-filename": "parent.qcow2"},
                        {"format": "raw"}):
            with self.subTest(payload=payload), mock.patch.object(b.subprocess, "run") as run:
                run.return_value.returncode = 0
                run.return_value.stdout = json.dumps(payload).encode()
                with self.assertRaises(b.VmBaselineError):
                    provider.inspect_flat_qcow2(self.source)
        with mock.patch.object(b.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = b'{"format":"qcow2"}'
            provider.inspect_flat_qcow2(self.source)
            self.assertEqual(("qemu-img", "info", "--output=json", str(self.source)),
                             run.call_args.args[0])

    def test_capture_refuses_changed_source_during_copy(self):
        original_copy = self.provider.copy
        def mutate(source, destination):
            original_copy(source, destination)
            self.source.write_bytes(b"changed while copying")
        self.provider.copy = mutate
        with self.assertRaises(b.VmBaselineError):
            self.capture()
        self.assertFalse((self.store / "baselines/qemu/baseline-one/manifest.json").exists())
        self.assertTrue((self.store / "baselines/qemu/baseline-one/disk.qcow2").exists())

    def test_streaming_copy_is_bounded(self):
        self.source.write_bytes(b"x" * (b._CHUNK * 3 + 17))
        manifest = self.capture()
        self.assertEqual(self.source.stat().st_size, Path(manifest["baselinePath"]).stat().st_size)

    def test_tart_clone_is_real_and_tree_hash_detects_change(self):
        tart_source = self.source_root / "tart-source"
        tart_source.mkdir()
        (tart_source / "disk.img").write_bytes(b"disk")
        self.state.update(source_id="mac-one", path=tart_source)
        tart = b.TartProvider(source_root=self.source_root,
                              sources={"mac-one": b.SourceBinding("mac-one", tart_source,
                                                                   "generation-one", "tart-source")},
                              observe=lambda source_id: b.SourceObservation(**self.state), runner=self.run)
        manager = b.BaselineManager(root=self.store, providers={"tart": tart})
        manifest = manager.capture(provider="tart", source_id="mac-one", baseline="baseline-one",
                                   generation="generation-one")
        self.assertEqual(("tart", "clone", "tart-source", "vcb-baseline-one"), self.commands[0])
        self.assertEqual(b"disk", (self.source_root / "vcb-baseline-one/disk.img").read_bytes())
        restored = manager.restore(manifest, destination="run-one")
        self.assertEqual(("tart", "clone", "vcb-baseline-one", "vcr-run-one"), self.commands[1])
        self.assertTrue(Path(restored["path"]).is_dir())
        os.chmod(self.source_root / "vcb-baseline-one/disk.img", 0o600)
        (self.source_root / "vcb-baseline-one/disk.img").write_bytes(b"changed")
        with self.assertRaises(b.VmBaselineError):
            manager.verify(manifest)


if __name__ == "__main__":
    unittest.main()


class PortableBaselineValidationTests(unittest.TestCase):
    def test_identity_and_fingerprint_validation(self):
        self.assertEqual("safe-one", b._name("safe-one"))
        for unsafe in ("../escape", "", "-option"):
            with self.assertRaises(b.VmBaselineError):
                b._name(unsafe)
        with self.assertRaises(b.VmBaselineError):
            b._fingerprint({})
        with self.assertRaises(b.VmBaselineError):
            b._fingerprint({"runtime": ""})
