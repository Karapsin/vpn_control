"""Causal checks for the fixed read-only Python installer source probe."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from agent_tools import windows_fixture_python_host_source as source


REQUEST = {"host": "archlinux", "timeoutSeconds": 30}


def remote_for(path: Path, size: int, digest: str) -> dict[str, str]:
    program = source._REMOTE.replace(repr(source.SOURCE), repr(str(path)))
    program = program.replace(repr(source.SIZE_BYTES), repr(size)).replace(repr(source.SHA256), repr(digest))
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        exec(program, {"__name__": "__main__"})
    return json.loads(output.getvalue())


class WindowsFixturePythonHostSourceTest(unittest.TestCase):
    def test_exact_bytes_hash_and_safe_mode_are_the_only_present_proof(self):
        self.assertEqual(29_452_944, source.SIZE_BYTES)
        self.assertEqual("edec09c4853aeae9ac36efb8c9f95b6b8e2fee65eee56d9767a8b7c69c574403", source.SHA256)
        with tempfile.TemporaryDirectory() as directory:
            installer = Path(directory) / "python.exe"
            raw = b"fixed installer receipt bytes"
            installer.write_bytes(raw); installer.chmod(0o600)
            self.assertEqual({"state": "present"}, remote_for(installer, len(raw), hashlib.sha256(raw).hexdigest()))

    def test_hash_or_size_mismatch_is_not_present(self):
        with tempfile.TemporaryDirectory() as directory:
            installer = Path(directory) / "python.exe"
            raw = b"fixed installer receipt bytes"
            installer.write_bytes(raw); installer.chmod(0o600)
            for size, digest in ((len(raw), "0" * 64), (len(raw) + 1, hashlib.sha256(raw).hexdigest())):
                with self.subTest(size=size, digest=digest):
                    self.assertEqual({"state": "absent-or-mismatch"}, remote_for(installer, size, digest))

    def test_symlink_is_never_admitted(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.exe"; target.write_bytes(b"receipt"); target.chmod(0o600)
            installer = Path(directory) / "python.exe"; installer.symlink_to(target)
            self.assertEqual({"state": "absent-or-mismatch"}, remote_for(installer, 7, hashlib.sha256(b"receipt").hexdigest()))

    def test_transport_failure_is_unknown_not_absent(self):
        config = SimpleNamespace(hosts={"archlinux": object()})
        with mock.patch.object(source.ssh_transport, "load_config", return_value=config), \
             mock.patch.object(source.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)), \
             mock.patch.object(source.ssh_transport, "build_ssh_argv", return_value=["ssh", "archlinux"]), \
             mock.patch.object(source.subprocess, "run", side_effect=OSError("offline")):
            self.assertEqual("unknown", source.observe(".", REQUEST)["state"])

    def test_public_result_rejects_paths_and_unexpected_remote_shapes(self):
        self.assertEqual("unknown", source._public(b'{"state":"present","path":"private"}')["state"])
        self.assertEqual("unknown", source._public(b'{"state":"other"}')["state"])
        for request in ({}, {**REQUEST, "path": "/tmp/x"}, {**REQUEST, "timeoutSeconds": 61}):
            with self.subTest(request=request), self.assertRaises(ValueError):
                source._request(request)


if __name__ == "__main__":
    unittest.main()
