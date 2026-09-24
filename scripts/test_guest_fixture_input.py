#!/usr/bin/env python3
"""Causal regression for an input lost while a guest transport drops stdin."""

import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from guest_fixture_input import (
    FixtureInputError,
    GuestFixtureInput,
    guest_probe_argv,
    launch_after_verified_input,
)


class GuestFixtureInputTest(unittest.TestCase):
    def test_dropped_stdin_refuses_to_launch_probe_sentinel(self):
        """The old pipe accepted an empty helper and its no-op probe exited zero."""
        helper = b"import sys\nraise SystemExit(0)\n"
        expected = GuestFixtureInput.from_contents(helper)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staged = root / "helper.py"
            sentinel = root / "probe-launched"

            # This models ``tart exec ... cat > helper.py`` accepting stdin
            # while the transport silently drops the source bytes.
            subprocess.run(
                [sys.executable, "-c", "import sys; sys.stdin.read()"],
                input=helper,
                text=False,
                check=True,
            )
            staged.write_bytes(b"")
            old_probe = subprocess.run(
                [sys.executable, str(staged), "probe-pom"],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, old_probe.returncode, "RED: empty helper was historically accepted as a probe")

            probe = root / "probe.py"
            probe.write_text(
                "from pathlib import Path\nimport sys\nPath(sys.argv[1]).write_text('probe ran\\n')\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                (sys.executable, *guest_probe_argv(
                    str(staged), expected, (sys.executable, str(probe), str(sentinel)),
                )[1:]),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(64, result.returncode)
            self.assertIn("size mismatch", result.stderr)
            self.assertFalse(sentinel.exists(), "empty helper must fail before probe-pom launches")

    def test_exact_helper_is_admitted_and_launches_once(self):
        contents = b"public helper contents\n"
        expected = GuestFixtureInput.from_contents(contents)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staged = root / "helper.py"
            staged.write_bytes(contents)
            sentinel = root / "probe-launched"
            launch_after_verified_input(
                staged, expected, lambda: sentinel.write_text("probe ran\n", encoding="utf-8"),
            )
            self.assertEqual("probe ran\n", sentinel.read_text(encoding="utf-8"))

    def test_wrong_or_stale_helper_is_rejected_before_launch(self):
        expected = GuestFixtureInput.from_contents(b"current public helper\n")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staged = root / "helper.py"
            staged.write_bytes(b"oldest public helperx\n")
            sentinel = root / "probe-launched"
            probe = root / "probe.py"
            probe.write_text(
                "from pathlib import Path\nimport sys\nPath(sys.argv[1]).write_text('probe ran\\n')\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                (sys.executable, *guest_probe_argv(
                    str(staged), expected, (sys.executable, str(probe), str(sentinel)),
                )[1:]),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(64, result.returncode)
            self.assertIn("SHA-256 mismatch", result.stderr)
            self.assertFalse(sentinel.exists(), "stale helper must fail before probe-pom launches")

    def test_missing_helper_is_rejected_before_generated_probe_launch(self):
        expected = GuestFixtureInput.from_contents(b"public helper contents\n")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staged = root / "missing-helper.py"
            sentinel = root / "probe-launched"
            probe = root / "probe.py"
            probe.write_text(
                "from pathlib import Path\nimport sys\nPath(sys.argv[1]).write_text('probe ran\\n')\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                (sys.executable, *guest_probe_argv(
                    str(staged), expected, (sys.executable, str(probe), str(sentinel)),
                )[1:]),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(64, result.returncode)
            self.assertIn("guest fixture helper is missing", result.stderr)
            self.assertFalse(sentinel.exists(), "missing helper must fail before probe-pom launches")

    def test_generated_guest_argv_is_structured_and_executes_only_after_verification(self):
        contents = b"public helper\n"
        expected = GuestFixtureInput.from_contents(contents)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staged = root / "helper.py"
            staged.write_bytes(contents)
            sentinel = root / "probe-launched"
            probe = root / "probe.py"
            probe.write_text(
                "from pathlib import Path\nimport sys\nPath(sys.argv[1]).write_text('probe ran\\n')\n",
                encoding="utf-8",
            )
            argv = guest_probe_argv(str(staged), expected, (sys.executable, str(probe), str(sentinel)))
            self.assertEqual("python3", argv[0])
            self.assertEqual("-c", argv[1])
            self.assertNotIn("stdin", argv[2])
            result = subprocess.run(
                (sys.executable, *argv[1:]),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("probe ran\n", sentinel.read_text(encoding="utf-8"))

    def test_windows_absolute_helper_path_is_accepted_without_accepting_drive_relative_paths(self):
        expected = GuestFixtureInput.from_contents(b"public helper\n")
        argv = guest_probe_argv(r"C:\\fixture\\helper.py", expected, ("python3", "probe-pom"))
        self.assertEqual(r"C:\\fixture\\helper.py", argv[3])
        with self.assertRaisesRegex(FixtureInputError, "must be absolute"):
            guest_probe_argv(r"C:fixture\\helper.py", expected, ("python3", "probe-pom"))


if __name__ == "__main__":
    unittest.main()
