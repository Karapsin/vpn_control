from __future__ import annotations

import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import socket
import stat
import struct
import sys
import shlex
import tempfile
import unittest
from unittest import mock

from agent_tools import ssh_transport
from agent_tools import windows_credential_probe_ssh as backend


class WindowsCredentialProbeSshTest(unittest.TestCase):
    correlation = "123e4567-e89b-12d3-a456-426614174000"

    def config(self, root: Path, credential: Path):
        descriptor = ssh_transport.WindowsCredentialProbe(
            environment="windows-fixture", qga_socket_path=PurePosixPath("/run/owned/qga.sock"),
            qemu_pid=42, qemu_start_ticks=99, account_name="vpnfixture",
            expected_sid="S-1-5-21-1-2-3-1001", credential_path=credential,
        )
        host = mock.Mock(transport="direct", gateway=None, password=None,
                         fixture_transfer_root=PurePosixPath("/var/lib/owned-fixtures"),
                         windows_credential_probe=descriptor)
        return mock.Mock(hosts={"arch": host})

    def transport_config(self, root: Path, credential: Path):
        descriptor = ssh_transport.WindowsCredentialProbe(
            environment="windows-fixture", qga_socket_path=PurePosixPath("/run/owned/qga.sock"),
            qemu_pid=42, qemu_start_ticks=99, account_name="vpnfixture",
            expected_sid="S-1-5-21-1-2-3-1001", credential_path=credential,
        )
        host = ssh_transport.SshHost(
            "arch", "fixture.example", 22, "fixture", Path("/tmp/fixture-key"), Path("/tmp/fixture-known"),
            fixture_transfer_root=PurePosixPath("/var/lib/owned-fixtures"), windows_credential_probe=descriptor,
        )
        return ssh_transport.SshConfig(root, {"arch": host})

    def private_credential(self, root: Path) -> Path:
        path = root / "credential"; path.write_bytes(b"top-secret\n"); path.chmod(0o600)
        self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode)); return path

    def test_start_freezes_exact_three_helpers_and_public_output_never_contains_secret(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); credential = self.private_credential(root); config = self.config(root, credential)
            seen: list[dict] = []
            def sent(_config, _host, _command, payload, _timeout):
                self.assertIsNotNone(payload)
                declared = struct.unpack(">I", payload[:4])[0]
                self.assertEqual(declared, len(payload) - 4)
                value = json.loads(payload[4:])
                seen.append(value)
                return b'{"state":"submitted","pid":7}'
            with mock.patch.object(backend.ssh_transport, "load_config", return_value=config), \
                 mock.patch.object(backend, "_run_ssh", side_effect=sent):
                result = backend.start(root, "arch", self.correlation)
            self.assertEqual(("submitted", 7), (result["state"], result["pid"]))
            self.assertEqual([name for name, _ in backend._HELPERS], [x["name"] for x in seen[0]["helpers"]])
            self.assertEqual(3, len(seen[0]["helpers"]))
            self.assertNotIn("top-secret", json.dumps(result))
            self.assertNotIn("top-secret", str(backend._read_intent(root, self.correlation)))

    def test_large_helper_payload_uses_bounded_stdin_frame_not_a_line_or_argv(self):
        value = {"helpers": [{"data": "a" * 17000}]}
        framed = backend._remote_payload(value)
        self.assertGreater(len(framed), 16385)
        self.assertEqual(len(framed) - 4, struct.unpack(">I", framed[:4])[0])
        self.assertEqual(value, json.loads(framed[4:]))
        self.assertIn('sys.stdin.buffer.read(4)', backend._REMOTE_START)
        self.assertNotIn('sys.stdin.buffer.readline(16385)', backend._REMOTE_START)

    def test_raw_multiline_helpers_are_rejected_but_both_real_paths_build_encoded_argv(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); credential = self.private_credential(root); config = self.transport_config(root, credential)
            with self.assertRaises(ssh_transport.SshConfigError):
                ssh_transport.build_ssh_argv(config, "arch", command=("python3", "-c", backend._REMOTE_START, "/var/lib/owned-fixtures", "windows-fixture", self.correlation))
            for program in (backend._REMOTE_START, backend._REMOTE_STATUS):
                command = backend._remote_command(program, "/var/lib/owned-fixtures", "windows-fixture", self.correlation)
                argv = ssh_transport.build_ssh_argv(config, "arch", command=command)
                self.assertNotIn("\n", command[2])
                self.assertIn("exec(", command[2])
                self.assertEqual(command, tuple(shlex.split(argv[-1])))

            completed = mock.Mock(returncode=0, stdout=b'{"state":"submitted","pid":7}')
            with mock.patch.object(backend.ssh_transport, "load_config", return_value=config), \
                 mock.patch.object(backend.subprocess, "run", return_value=completed) as run:
                self.assertEqual("submitted", backend.start(root, "arch", self.correlation)["state"])
                completed.stdout = b'{"state":"terminal","pid":7,"success":false,"errorCategory":"invalid-credentials"}'
                self.assertEqual("terminal", backend.status(root, "arch", self.correlation)["state"])
            self.assertEqual(2, run.call_count)
            for call in run.call_args_list:
                argv = call.args[0]
                self.assertNotIn("top-secret", " ".join(argv))
                remote = shlex.split(argv[-1])
                self.assertIn("exec(", remote[2])
                self.assertNotIn("\n", remote[2])

    def test_helper_capture_keeps_immutable_byte_identity(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); paths = []
            for name, contents in (("windows_credential_validity_qga.py", b"one"),
                                   ("native_fixture_qga.py", b"two"),
                                   ("windows_task_admission.ps1", b"three")):
                path = root / name; path.write_bytes(contents); paths.append((name, path))
            with mock.patch.object(backend, "_HELPERS", tuple(paths)):
                frozen, hashes = backend._capture_helpers()
                paths[0][1].write_bytes(b"changed")
            self.assertEqual("one", __import__("base64").b64decode(frozen[0]["data"]).decode())
            self.assertEqual(frozen[0]["sha256"], hashes["windows_credential_validity_qga.py"])

    def test_wrong_vm_is_checked_before_qga_import_or_dispatch(self):
        self.assertLess(backend._REMOTE_START.index("live(value"), backend._REMOTE_START.index("from windows_credential_validity_qga"))
        self.assertIn('bad("vm_binding_unverified")', backend._REMOTE_START)

    @unittest.skipUnless(sys.platform.startswith("linux") and Path("/proc/net/unix").is_file(),
                         "requires Linux /proc Unix-socket ownership observations")
    def test_live_socket_binding_matches_process_fd_inode_through_proc_net_unix(self):
        with tempfile.TemporaryDirectory() as raw:
            path = str(Path(raw) / "qga.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(path)
                ticks = int(Path(f"/proc/{os.getpid()}/stat").read_bytes().split()[21])
                self.assertTrue(backend._linux_socket_binding(path, os.getpid(), ticks))
                self.assertFalse(backend._linux_socket_binding(path, os.getpid(), ticks + 1))
            finally:
                listener.close()
        self.assertIn('open("/proc/net/unix","rb")', backend._REMOTE_START)
        self.assertIn('open("/proc/net/unix","rb")', backend._REMOTE_STATUS)

    def test_lost_start_response_preserves_intent_and_never_replays(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); config = self.config(root, self.private_credential(root))
            with mock.patch.object(backend.ssh_transport, "load_config", return_value=config), \
                 mock.patch.object(backend, "_run_ssh", return_value=None) as run:
                first = backend.start(root, "arch", self.correlation)
                self.assertEqual("unknown", first["state"])
                with self.assertRaisesRegex(backend.WindowsCredentialProbeSshError, "durable intent"):
                    backend.start(root, "arch", self.correlation)
            self.assertEqual(1, run.call_count)

    def test_status_observes_durable_remote_journal_after_local_helpers_change(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); config = self.config(root, self.private_credential(root))
            with mock.patch.object(backend.ssh_transport, "load_config", return_value=config), \
                 mock.patch.object(backend, "_run_ssh", return_value=b'{"state":"submitted","pid":7}'):
                backend.start(root, "arch", self.correlation)
            # Status does not capture or compare the current source helpers.
            with mock.patch.object(backend, "_capture_helpers", side_effect=AssertionError("must not read source")), \
                 mock.patch.object(backend.ssh_transport, "load_config", return_value=config), \
                 mock.patch.object(backend, "_run_ssh", return_value=b'{"state":"terminal","pid":7,"success":false,"errorCategory":"invalid-credentials"}'):
                result = backend.status(root, "arch", self.correlation)
            self.assertEqual(("terminal", False, "invalid-credentials"),
                             (result["state"], result["success"], result["errorCategory"]))

    def test_ssh_errors_and_secret_never_escape_public_result(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); config = self.config(root, self.private_credential(root))
            with mock.patch.object(backend.ssh_transport, "load_config", return_value=config), \
                 mock.patch.object(backend, "_run_ssh", return_value=b"top-secret\nnot-json"):
                result = backend.start(root, "arch", self.correlation)
            self.assertEqual({"state": "unknown", "correlationId": self.correlation}, result)
            self.assertNotIn("top-secret", repr(result))


if __name__ == "__main__":
    unittest.main()
