"""One-shot admission tests for the pinned Windows VM driver ISO."""
from __future__ import annotations

import tempfile
import unittest
from unittest import mock
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
from threading import Barrier

from agent_tools import windows_vm_driver_fetch as fetch


CORR = "123e4567-e89b-12d3-a456-426614174000"


class WindowsVmDriverFetchTest(unittest.TestCase):
    def test_remote_script_is_fixed_and_compiles(self) -> None:
        program = (fetch._REMOTE.replace("__URL__", repr(fetch.URL))
                   .replace("__SHA__", repr(fetch.SHA256))
                   .replace("__SIZE__", repr(fetch.SIZE))
                   .replace("__ROOT__", repr(fetch.ROOT))
                   .replace("__DEST__", repr(fetch.DEST))
                   .replace("__CORR__", repr(CORR))
                   .replace("__MODE__", repr("start")))
        compile(program, "<windows-vm-driver-fetch>", "exec")
        self.assertIn("os.O_EXCL", program)
        self.assertIn("os.link(part,DEST", program)
        self.assertIn(fetch.SHA256, program)

    def test_start_journals_before_submission_and_replay_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as root, mock.patch.object(
                fetch, "_remote", return_value={"state": "verified", "sha256": fetch.SHA256,
                                                 "sizeBytes": fetch.SIZE}) as remote:
            result = fetch.start(root, host="archlinux", correlation_id=CORR)
            self.assertEqual("verified", result["state"])
            self.assertFalse(result["replayAllowed"])
            self.assertTrue((fetch._journal(root, CORR, create=False)).exists())
            with self.assertRaisesRegex(ValueError, "already exists"):
                fetch.start(root, host="archlinux", correlation_id=CORR)
            remote.assert_called_once()

    def test_uncertain_transport_preserves_intent_and_forbids_replay(self) -> None:
        with tempfile.TemporaryDirectory() as root, mock.patch.object(
                fetch, "_remote", side_effect=TimeoutError) as remote:
            result = fetch.start(root, host="archlinux", correlation_id=CORR)
            self.assertEqual("unknown", result["state"])
            self.assertFalse(result["replayAllowed"])
            self.assertTrue(fetch._journal(root, CORR, create=False).exists())
            with self.assertRaisesRegex(ValueError, "already exists"):
                fetch.start(root, host="archlinux", correlation_id=CORR)
            remote.assert_called_once()

    def test_status_observes_existing_intent_only(self) -> None:
        with tempfile.TemporaryDirectory() as root, mock.patch.object(
                fetch, "_remote", return_value={"state": "partial"}) as remote:
            with self.assertRaises(FileNotFoundError):
                fetch.status(root, host="archlinux", correlation_id=CORR)
            fetch._save_intent(fetch._journal(root, CORR, create=True), CORR)
            result = fetch.status(root, host="archlinux", correlation_id=CORR)
            self.assertEqual("partial", result["state"])
            self.assertFalse(result["replayAllowed"])
            remote.assert_called_once()

    def test_other_correlation_cannot_start_over_existing_intent(self) -> None:
        other = "123e4567-e89b-12d3-a456-426614174001"
        with tempfile.TemporaryDirectory() as root, mock.patch.object(fetch, "_remote") as remote:
            fetch._save_intent(fetch._journal(root, CORR, create=True), CORR)
            with self.assertRaisesRegex(ValueError, "already exists"):
                fetch.start(root, host="archlinux", correlation_id=other)
            remote.assert_not_called()

    def test_distinct_correlations_race_for_one_atomic_intent(self) -> None:
        other = "123e4567-e89b-12d3-a456-426614174001"
        with tempfile.TemporaryDirectory() as root:
            path = fetch._journal(root, CORR, create=True)
            barrier = Barrier(2)

            def claim(correlation_id):
                barrier.wait(timeout=5)
                try:
                    fetch._save_intent(path, correlation_id)
                    return "claimed"
                except FileExistsError:
                    return "rejected"

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(claim, (CORR, other)))
            self.assertCountEqual(["claimed", "rejected"], results)

    def test_crash_after_link_remains_linked_partial(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            task_root = Path(root) / "task"
            runtime = task_root / "runtime"
            runtime.mkdir(parents=True, mode=0o700)
            os.chmod(task_root, 0o700)
            os.chmod(runtime, 0o700)
            dest = runtime / "virtio-win-0.1.285.iso"
            part = runtime / (".download-" + CORR + ".part")
            part.write_bytes(b"test")
            os.chmod(part, 0o400)
            os.link(part, dest)
            program = (fetch._REMOTE.replace("__URL__", repr(fetch.URL))
                       .replace("__SHA__", repr(fetch.SHA256))
                       .replace("__SIZE__", repr(fetch.SIZE))
                       .replace("__ROOT__", repr(str(task_root)))
                       .replace("__DEST__", repr(str(dest)))
                       .replace("__CORR__", repr(CORR))
                       .replace("__MODE__", repr("status")))
            run = subprocess.run([sys.executable, "-c", program], check=True,
                                 capture_output=True, text=True, timeout=5)
            self.assertEqual("linked-partial", json.loads(run.stdout)["state"])
            self.assertTrue(dest.exists())
            self.assertTrue(part.exists())


if __name__ == "__main__":
    unittest.main()
