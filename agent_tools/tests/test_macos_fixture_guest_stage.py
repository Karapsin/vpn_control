"""The guest fixture mode repair is exact, durable, and never replayed."""

import json
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agent_tools import macos_fixture_guest_stage as stage


SOURCE = "2a7b6a4cbbca75a8a3e9740f6be33f9ed1bac6bf"
BASE_SHA = "b" * 64
TARGET_SHA = "d" * 64
CORRELATION = "5ea92866-61f9-4963-9f33-25ac6bdf7e14"


def request():
    return {
        "correlationId": CORRELATION,
        "sourceSha": SOURCE,
        "guestRoot": "/Users/admin/macos-parity2a7b6a4",
        "baseSha256": BASE_SHA,
        "baseSizeBytes": 141026827,
        "targetSha256": TARGET_SHA,
        "targetSizeBytes": 140970648,
    }


def observed(mode=0o444):
    return {"base": {"sha256": BASE_SHA, "sizeBytes": 141026827, "mode": mode},
            "target": {"sha256": TARGET_SHA, "sizeBytes": 140970648, "mode": mode}}


class FixtureGuestStageTest(unittest.TestCase):
    def test_guest_code_checks_both_hashes_before_changing_either_mode(self):
        with tempfile.TemporaryDirectory() as root:
            fixture = Path(root).resolve()
            for label, name, data in (("base", stage.BASE_NAME, b"base"),
                                      ("target", stage.TARGET_NAME, b"target")):
                directory = fixture / "pair/packages" / label
                directory.mkdir(parents=True)
                path = directory / name
                path.write_bytes(data)
                path.chmod(0o644)
            base = hashlib.sha256(b"base").hexdigest()
            target = hashlib.sha256(b"target").hexdigest()
            command = [sys.executable, "-c", stage._GUEST_CODE, "mutate", str(fixture),
                       base, "4", "0" * 64, "6"]
            rejected = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(0, rejected.returncode)
            self.assertEqual(0o644, (fixture / "pair/packages/base" / stage.BASE_NAME).stat().st_mode & 0o777)
            command[-2] = target
            accepted = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(0, accepted.returncode, accepted.stderr)
            self.assertEqual(observed(0o444)["base"]["mode"],
                             json.loads(accepted.stdout)["base"]["mode"])
            for label, name in (("base", stage.BASE_NAME), ("target", stage.TARGET_NAME)):
                self.assertEqual(0o444, (fixture / "pair/packages" / label / name).stat().st_mode & 0o777)

    def test_writable_transfer_is_repaired_once_and_repeated_start_is_read_only(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, json.dumps(observed()), "")

        with tempfile.TemporaryDirectory() as root:
            first = stage.start(Path(root), request(), runner=runner)
            self.assertEqual("complete", first["state"])
            self.assertEqual(1, len(calls))
            self.assertIn("mutate", calls[0])
            second = stage.start(Path(root), request(), runner=runner)
            self.assertEqual(first, second)
            self.assertEqual(1, len(calls))

    def test_unknown_mutation_is_never_replayed_and_status_only_inspects(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            if len(calls) == 1:
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
            return subprocess.CompletedProcess(argv, 0, json.dumps(observed()), "")

        with tempfile.TemporaryDirectory() as root:
            first = stage.start(Path(root), request(), runner=runner)
            self.assertEqual("unknown", first["state"])
            self.assertFalse(first["ok"])
            repeated = stage.start(Path(root), request(), runner=runner)
            self.assertEqual("unknown", repeated["state"])
            self.assertFalse(repeated["ok"])
            self.assertEqual(1, len(calls))
            recovered = stage.status(Path(root), {"correlationId": CORRELATION}, runner=runner)
            self.assertEqual("complete", recovered["state"])
            self.assertTrue(recovered["ok"])
            self.assertIn("inspect", calls[1])

    def test_guest_root_is_bound_to_source_and_wrong_bytes_fail_closed(self):
        wrong = request()
        wrong["guestRoot"] = "/Users/admin/macos-parity31b3c11"
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                stage.start(Path(root), wrong, runner=lambda *_args, **_kwargs: self.fail("ran guest"))

            def runner(argv, **kwargs):
                bad = observed()
                bad["target"]["sha256"] = "0" * 64
                return subprocess.CompletedProcess(argv, 0, json.dumps(bad), "")

            self.assertEqual("unknown", stage.start(Path(root), request(), runner=runner)["state"])


if __name__ == "__main__":
    unittest.main()
