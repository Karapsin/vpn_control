import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from agent_tools.native_scenario_bundle import (
    MANIFEST_NAME, NativeScenarioBundleError, prepare_bundle, verify_bundle,
)


class NativeScenarioBundleTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repository"
        source = self.root / "scripts"
        source.mkdir(parents=True)
        names = ("test_linux_public_install.py", "linux_fixture_auth.py", "arch_public_update.py", "rpm_public_update.py",
                 "prepare_desktop_update_fixture.py", "fixture_environment.py", "macos_packaging_jdk_preflight.py",
                 "native_fixture_run.sh")
        for name in names:
            (source / name).write_text("# harmless fixture module\n", encoding="utf-8")

    def tearDown(self):
        self.temporary.cleanup()

    def test_prepares_and_verifies_linux_driver_from_foreign_cwd(self):
        destination = self.root.parent / "frozen"
        receipt = prepare_bundle(self.root, "linux-public-update-driver", destination)
        self.assertEqual(receipt["scenarioId"], "linux-public-update-driver")
        self.assertEqual(len(receipt["files"]), 8)
        verified = verify_bundle(self.root, destination, receipt["manifestSha256"])
        self.assertEqual(verified["manifestSha256"], receipt["manifestSha256"])

    def test_real_linux_driver_imports_without_running_a_native_action(self):
        repository = Path(__file__).resolve().parents[2]
        destination = self.root.parent / "real-driver"
        receipt = prepare_bundle(repository, "linux-public-update-driver", destination)
        self.assertEqual(len(verify_bundle(repository, destination, receipt["manifestSha256"])["files"]), 8)

    def test_nested_scheduled_driver_imports_only_its_frozen_parent_sibling(self):
        source = self.root / "scripts"
        nested = source / "integration"
        nested.mkdir()
        (nested / "linux_scheduled_refresh_scenario.py").write_text(
            "from native_fixture_preflight import READY\nfrom socks_http_fixture import FIXTURE\n"
            "assert READY and FIXTURE\n", encoding="utf-8")
        (nested / "socks_http_fixture.py").write_text("FIXTURE = True\n", encoding="utf-8")
        (source / "native_fixture_preflight.py").write_text("READY = True\n", encoding="utf-8")
        destination = self.root.parent / "scheduled"
        receipt = prepare_bundle(self.root, "linux-scheduled-refresh-driver", destination)
        self.assertEqual(4, len(verify_bundle(self.root, destination, receipt["manifestSha256"])["files"]))

    def test_missing_sibling_fails_before_creating_bundle(self):
        (self.root / "scripts/rpm_public_update.py").unlink()
        destination = self.root.parent / "frozen"
        with self.assertRaisesRegex(NativeScenarioBundleError, "missing or unsafe"):
            prepare_bundle(self.root, "linux-public-update-driver", destination)
        self.assertFalse(destination.exists())

    def test_tampered_file_fails_verification(self):
        destination = self.root.parent / "frozen"
        receipt = prepare_bundle(self.root, "linux-public-update-driver", destination)
        (destination / "scripts/test_linux_public_install.py").write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(NativeScenarioBundleError, "Bundle file differs"):
            verify_bundle(self.root, destination, receipt["manifestSha256"])

    def test_tampered_frozen_runner_fails_verification(self):
        destination = self.root.parent / "frozen"
        receipt = prepare_bundle(self.root, "linux-public-update-driver", destination)
        (destination / "scripts/native_fixture_run.sh").write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(NativeScenarioBundleError, "Bundle file differs"):
            verify_bundle(self.root, destination, receipt["manifestSha256"])

    @unittest.skipIf(os.name == "nt", "Windows symlink creation requires extra privilege")
    def test_symlink_bundle_root_is_rejected(self):
        destination = self.root.parent / "frozen"
        receipt = prepare_bundle(self.root, "linux-public-update-driver", destination)
        link = self.root.parent / "link-to-frozen"
        link.symlink_to(destination, target_is_directory=True)
        with self.assertRaisesRegex(NativeScenarioBundleError, "Bundle directory is unsafe"):
            verify_bundle(self.root, link, receipt["manifestSha256"])

    def test_destination_created_during_finalize_is_never_replaced(self):
        destination = self.root.parent / "frozen"
        import agent_tools.native_scenario_bundle as bundles
        original = bundles.os.mkdir

        def competing_mkdir(path, mode=0o777):
            if Path(path).resolve(strict=False) == destination.resolve(strict=False):
                original(path, mode)
                (destination / "sentinel").write_text("existing", encoding="utf-8")
                raise FileExistsError(path)
            return original(path, mode)

        bundles.os.mkdir = competing_mkdir
        try:
            with self.assertRaisesRegex(NativeScenarioBundleError, "fresh directory"):
                prepare_bundle(self.root, "linux-public-update-driver", destination)
        finally:
            bundles.os.mkdir = original
        self.assertEqual((destination / "sentinel").read_text(encoding="utf-8"), "existing")

    def test_path_traversal_manifest_is_rejected(self):
        destination = self.root.parent / "frozen"
        receipt = prepare_bundle(self.root, "linux-public-update-driver", destination)
        manifest_path = destination / MANIFEST_NAME
        manifest = json.loads(manifest_path.read_text())
        manifest["files"][0]["path"] = "../outside.py"
        raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        manifest_path.write_bytes(raw)
        with self.assertRaisesRegex(NativeScenarioBundleError, "path is not allowlisted"):
            verify_bundle(self.root, destination, hashlib.sha256(raw).hexdigest())

    def test_stale_snapshot_is_rejected_when_source_changes_during_copy(self):
        destination = self.root.parent / "frozen"
        import agent_tools.native_scenario_bundle as bundles
        original = bundles._regular_snapshot
        changed = False

        def mutate_after_copy(source, **kwargs):
            nonlocal changed
            result = original(source, **kwargs)
            if kwargs.get("copy_to") is not None and not changed:
                changed = True
                (self.root / "scripts/test_linux_public_install.py").write_text("# changed\n", encoding="utf-8")
            return result

        bundles._regular_snapshot = mutate_after_copy
        try:
            with self.assertRaisesRegex(NativeScenarioBundleError, "changed during capture"):
                prepare_bundle(self.root, "linux-public-update-driver", destination)
        finally:
            bundles._regular_snapshot = original
        self.assertFalse(destination.exists())

    def test_preflight_import_does_not_run_driver_actions(self):
        marker = self.root / "action-ran"
        driver = self.root / "scripts/test_linux_public_install.py"
        driver.write_text(
            "from pathlib import Path\n"
            "def main():\n    Path(" + repr(str(marker)) + ").write_text('ran')\n",
            encoding="utf-8")
        destination = self.root.parent / "frozen"
        receipt = prepare_bundle(self.root, "linux-public-update-driver", destination)
        verify_bundle(self.root, destination, receipt["manifestSha256"])
        self.assertFalse(marker.exists())
