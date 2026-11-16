"""A new Windows fixture clone needs the operator-recorded base image hash.

Offline: no VM, host or credential is contacted; the pin lives in a temporary
stand-in for the private .runtime directory.
"""
import contextlib
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

from agent_tools import windows_vm_base_image_pin as pin
from agent_tools import windows_vm_deploy as deploy

IMAGE = {"imageId": "0b0b0b0b-1c1c-4d4d-8e8e-2f2f2f2f2f2f", "manifestSha256": "a" * 64}
OTHER = "b" * 64


class BaseImagePinTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_legacy_checkout_without_a_pin_refuses_and_names_the_refresh_step(self):
        with self.assertRaisesRegex(pin.BasePinError, "^deployment_base_image_unpinned: .*windows_vm_base_image_pin refresh"):
            pin.require_pinned(self.root, IMAGE)

    def test_matching_hash_is_accepted_and_a_different_hash_is_refused(self):
        pin.refresh(self.root, IMAGE["manifestSha256"])
        pin.require_pinned(self.root, IMAGE)
        with self.assertRaisesRegex(pin.BasePinError, "^deployment_base_image_hash_mismatch: "):
            pin.require_pinned(self.root, {**IMAGE, "manifestSha256": OTHER})

    def test_refresh_is_deliberate_private_and_keeps_history(self):
        pin.refresh(self.root, IMAGE["manifestSha256"], now_ms=1)
        value = pin.refresh(self.root, OTHER, now_ms=2)
        self.assertEqual(OTHER, value["expectedManifestSha256"])
        self.assertEqual([{"manifestSha256": IMAGE["manifestSha256"], "recordedAtUnixMs": 1, "supersededAtUnixMs": 2}],
                         value["history"])
        self.assertEqual(0o600, pin.pin_path(self.root).stat().st_mode & 0o777)
        pin.require_pinned(self.root, {**IMAGE, "manifestSha256": OTHER})
        with self.assertRaises(pin.BasePinError):
            pin.require_pinned(self.root, IMAGE)

    def test_malformed_hash_and_corrupt_pin_are_refused(self):
        for bad in ("", "A" * 64, "a" * 63, None):
            with self.assertRaises(pin.BasePinError, msg=repr(bad)):
                pin.refresh(self.root, bad)
        pin.pin_path(self.root).parent.mkdir(parents=True, exist_ok=True)
        pin.pin_path(self.root).write_text("{")
        with self.assertRaisesRegex(pin.BasePinError, "corrupt"):
            pin.require_pinned(self.root, IMAGE)

    def test_cli_show_and_refresh(self):
        def run(*args):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = pin.main(["--root", str(self.root), *args])
            return code, json.loads(out.getvalue())
        self.assertEqual((0, {"pinned": False}), run("show"))
        self.assertEqual(0, run("refresh", "--manifest-sha256", OTHER)[0])
        self.assertEqual(OTHER, run("show")[1]["expectedManifestSha256"])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(2, pin.main(["--root", str(self.root), "refresh", "--manifest-sha256", "x"]))

    def test_clone_entry_points_refuse_before_the_deployment_runs_without_or_with_a_wrong_pin(self):
        args = (self.root, {"request": "inert"}, {"setup": "inert"}, "inert-credential-file")
        with mock.patch.object(deploy, "start", side_effect=AssertionError("no deployment")) as start, \
                mock.patch.object(deploy, "images", side_effect=AssertionError("no host contact")):
            with self.assertRaisesRegex(pin.BasePinError, "^deployment_base_image_unpinned"):
                pin.start_clone(*args, image=IMAGE)
            pin.refresh(self.root, OTHER)
            with self.assertRaisesRegex(pin.BasePinError, "^deployment_base_image_hash_mismatch"):
                pin.start_clone(*args, image=IMAGE)
            with self.assertRaisesRegex(pin.BasePinError, "^deployment_base_image_required"):
                pin.start_clone(*args, image=None)
            start.assert_not_called()

    def test_pinned_clone_start_delegates_unchanged(self):
        pin.refresh(self.root, IMAGE["manifestSha256"])
        with mock.patch.object(deploy, "start", return_value={"state": "unknown"}) as start:
            result = pin.start_clone(self.root, {"r": 1}, {"s": 1}, "cred", image=IMAGE, network=None)
        self.assertEqual({"state": "unknown"}, result)
        start.assert_called_once_with(self.root, {"r": 1}, {"s": 1}, "cred", image=IMAGE, network=None)

    def test_no_other_production_code_creates_a_clone(self):
        """windows_vm_deploy is source-pinned, so the gate lives in the callers: only this module may pass an image."""
        agent_tools = Path(pin.__file__).parent
        offenders = []
        for path in sorted(agent_tools.glob("*.py")):
            if path.name in {"windows_vm_base_image_pin.py", "windows_vm_deploy.py"}:
                continue
            text = path.read_text(errors="replace")
            if re.search(r"\b(?:deploy|deployment)\.create\(", text) or re.search(r"\bdeploy\.start\([^)]*image\s*=", text):
                offenders.append(path.name)
        self.assertEqual([], offenders, "route clone creation through windows_vm_base_image_pin.create_clone/start_clone")


if __name__ == "__main__":
    unittest.main()
