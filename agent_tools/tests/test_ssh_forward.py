import importlib.util
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, SOURCE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


transport = load("ssh_transport")
recovery = load("ssh_connection_recovery")
forward = load("ssh_forward")


class SshForwardTest(unittest.TestCase):
    def config(self):
        gateway = transport.SshHost("gateway", "gateway.example", 2228, "tester", Path("/tmp/gateway-key"), Path("/tmp/gateway-known"))
        nested = transport.SshHost("archlinux", "unused", 22, "unused", Path("/tmp/unused"), transport.PurePosixPath("/remote/known"),
                                  transport="nested", gateway="gateway", remote_host_alias="archlinux",
                                  remote_control_path=transport.PurePosixPath("/remote/master.sock"))
        return transport.SshConfig(Path.cwd(), {"gateway": gateway, "archlinux": nested})

    def test_remote_argv_is_fixed_loopback_vnc_only(self):
        target = self.config().hosts["archlinux"]
        self.assertEqual(
            ("ssh", "-S", "/remote/master.sock", "-O", "forward", "-L", "127.0.0.1:45909:127.0.0.1:5909", "archlinux"),
            forward._remote_forward_command(target, "forward"),
        )
        self.assertEqual("cancel", forward._remote_forward_command(target, "cancel")[4])

    def test_local_argv_uses_transport_auth_and_loopback_bind(self):
        config = self.config()
        argv = forward._local_argv(config, config.hosts["archlinux"], "/private/owned.sock", "open")
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn("127.0.0.1:45909:127.0.0.1:45909", argv)
        self.assertNotIn("0.0.0.0", " ".join(argv))
        self.assertIn("ExitOnForwardFailure=yes", argv)
        self.assertEqual("gateway.example", argv[-1])

    def test_vnc_readiness_requires_a_complete_rfb_banner_after_tcp_accept(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def accept_without_vnc_banner():
            connection, _ = listener.accept()
            with connection:
                connection.sendall(b"not-a-vnc!\n")

        thread = threading.Thread(target=accept_without_vnc_banner)
        thread.start()
        try:
            self.assertFalse(forward._port_is_ready(port))
        finally:
            thread.join(timeout=2)
            listener.close()

    def test_vnc_readiness_accepts_the_fixed_rfb_server_banner(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve_rfb_banner():
            connection, _ = listener.accept()
            with connection:
                connection.sendall(b"RFB 003.008\n")

        thread = threading.Thread(target=serve_rfb_banner)
        thread.start()
        try:
            self.assertTrue(forward._port_is_ready(port))
        finally:
            thread.join(timeout=2)
            listener.close()

    def test_occupied_local_port_refuses_before_remote_action(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(forward.ssh_transport, "load_config", return_value=self.config()), \
                mock.patch.object(forward, "_port_is_free", return_value=False), \
                mock.patch.object(forward, "_remote_result") as remote:
            result = forward.open_forward(directory)
        self.assertEqual({"ok": False, "state": "local_port_occupied"}, result)
        remote.assert_not_called()

    def test_pending_intent_refuses_replay_after_remote_response_loss(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(forward.ssh_transport, "load_config", return_value=self.config()), \
                mock.patch.object(forward, "_port_is_free", return_value=True), \
                mock.patch.object(forward, "_remote_master_identity", return_value="a" * 64), \
                mock.patch.object(forward, "_control_directory", return_value=(Path(directory) / "ctl", Path(directory) / "ctl" / "m")), \
                mock.patch.object(forward, "_remote_result", return_value=None) as remote:
            (Path(directory) / "ctl").mkdir()
            first = forward.open_forward(directory)
            second = forward.open_forward(directory)
            intent = forward._read_intent(Path(directory), self.config().hosts["archlinux"])
        self.assertEqual("remote_forward_pending", first["state"])
        self.assertEqual({"ok": False, "state": "intent_exists"}, second)
        self.assertEqual("pending", intent["state"])
        self.assertEqual(0, intent["pid"])
        remote.assert_called_once()

    def test_confirmed_remote_listener_is_closed_after_local_popen_failure(self):
        config = self.config()
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(forward.ssh_transport, "load_config", return_value=config), \
                mock.patch.object(forward, "_port_is_free", return_value=True), \
                mock.patch.object(forward, "_remote_master_identity", return_value="a" * 64), \
                mock.patch.object(forward, "_control_directory", return_value=(Path(directory) / "ctl", Path(directory) / "ctl" / "m")), \
                mock.patch.object(forward, "_remote_result", side_effect=(True, True)) as remote, \
                mock.patch.object(forward.subprocess, "Popen", side_effect=OSError("simulated launch failure")), \
                mock.patch.object(forward.subprocess, "run") as run:
            (Path(directory) / "ctl").mkdir()
            opened = forward.open_forward(directory)
            intent = forward._read_intent(Path(directory), config.hosts["archlinux"])
            closed = forward.close(directory, {"correlationId": opened["correlationId"]})
        self.assertEqual("local_forward_pending", opened["state"])
        self.assertEqual("remote_created", intent["state"])
        self.assertEqual({"ok": True, "state": "closed", "correlationId": opened["correlationId"]}, closed)
        self.assertEqual(2, remote.call_count)
        run.assert_not_called()

    def test_full_open_requires_vnc_readiness_before_marking_the_intent_ready(self):
        config = self.config()
        process = mock.Mock(pid=123)
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(forward.ssh_transport, "load_config", return_value=config), \
                mock.patch.object(forward, "_port_is_free", return_value=True), \
                mock.patch.object(forward, "_remote_master_identity", return_value="a" * 64), \
                mock.patch.object(forward, "_control_directory", return_value=(Path(directory) / "ctl", Path(directory) / "ctl" / "m")), \
                mock.patch.object(forward, "_remote_result", return_value=True), \
                mock.patch.object(forward.subprocess, "Popen", return_value=process), \
                mock.patch.object(forward, "_process_generation", return_value="42"), \
                mock.patch.object(forward, "_owned", return_value=True), \
                mock.patch.object(forward, "_local_control_ready", return_value=True), \
                mock.patch.object(forward, "_port_is_ready", return_value=True):
            (Path(directory) / "ctl").mkdir()
            opened = forward.open_forward(directory)
            intent = forward._read_intent(Path(directory), config.hosts["archlinux"])
        self.assertTrue(opened["ok"])
        self.assertEqual("ready", intent["state"])

    def test_status_never_opens_or_retries(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(forward.ssh_transport, "load_config", return_value=self.config()), \
                mock.patch.object(forward, "_remote_result") as remote:
            result = forward.status(directory)
        self.assertEqual({"ok": False, "state": "not_open"}, result)
        remote.assert_not_called()

    def test_close_requires_exact_captured_identity_and_never_kills(self):
        config = self.config()
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(forward.ssh_transport, "load_config", return_value=config), \
                mock.patch.object(forward, "_process_generation", return_value="42"), \
                mock.patch.object(forward, "_process_command_matches", return_value=True), \
                mock.patch.object(forward, "_remote_master_identity", return_value="a" * 64), \
                mock.patch.object(forward.subprocess, "run") as run, \
                mock.patch.object(forward, "_remote_result") as remote:
            intent = forward._identity(config.hosts["archlinux"], "/private/owned.sock", 123, "42", "correlation", "ready", "/private/owned", "a" * 64)
            forward._write_intent(Path(directory), intent)
            mismatch = forward.close(directory, {"correlationId": "other"})
            run.return_value = subprocess.CompletedProcess([], 0)
            remote.return_value = True
            closed = forward.close(directory, {"correlationId": "correlation"})
            repeated = forward.close(directory, {"correlationId": "correlation"})
            self.assertEqual(closed, repeated)
            self.assertEqual("closed", forward.status(directory)["state"])
        self.assertEqual({"ok": False, "state": "identity_mismatch"}, mismatch)
        self.assertEqual({"ok": True, "state": "closed", "correlationId": "correlation"}, closed)
        self.assertEqual(1, run.call_count)
        self.assertEqual(1, remote.call_count)

    def test_unknown_owner_refuses_close_without_running_ssh(self):
        config = self.config()
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(forward.ssh_transport, "load_config", return_value=config), \
                mock.patch.object(forward, "_process_generation", return_value=None), \
                mock.patch.object(forward.subprocess, "run") as run:
            intent = forward._identity(config.hosts["archlinux"], "/private/owned.sock", 123, "42", "correlation", "ready", "/private/owned", "a" * 64)
            forward._write_intent(Path(directory), intent)
            result = forward.close(directory, {"correlationId": "correlation"})
        self.assertEqual({"ok": False, "state": "owner_unknown"}, result)
        run.assert_not_called()

    def test_pending_open_never_cancels_an_unconfirmed_remote_listener(self):
        config = self.config()
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(forward.ssh_transport, "load_config", return_value=config), \
                mock.patch.object(forward, "_process_generation", return_value="42"), \
                mock.patch.object(forward.subprocess, "run") as run, \
                mock.patch.object(forward, "_remote_result") as remote:
            intent = forward._identity(config.hosts["archlinux"], "/private/owned.sock", 123, "42", "correlation", "pending", "/private/owned", "a" * 64)
            forward._write_intent(Path(directory), intent)
            result = forward.close(directory, {"correlationId": "correlation"})
        self.assertEqual({"ok": False, "state": "close_pending", "correlationId": "correlation"}, result)
        run.assert_not_called()
        remote.assert_not_called()

    def test_replaced_remote_master_never_receives_our_cancel(self):
        config = self.config()
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(forward.ssh_transport, "load_config", return_value=config), \
                mock.patch.object(forward, "_process_generation", return_value="42"), \
                mock.patch.object(forward, "_process_command_matches", return_value=True), \
                mock.patch.object(forward, "_remote_master_identity", return_value="b" * 64), \
                mock.patch.object(forward.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run, \
                mock.patch.object(forward, "_remote_result") as remote:
            intent = forward._identity(config.hosts["archlinux"], "/private/owned.sock", 123, "42", "correlation", "ready", "/private/owned", "a" * 64)
            forward._write_intent(Path(directory), intent)
            result = forward.close(directory, {"correlationId": "correlation"})
        self.assertEqual({"ok": False, "state": "close_pending", "correlationId": "correlation"}, result)
        self.assertEqual(1, run.call_count)
        remote.assert_not_called()

    def test_status_rejects_an_arbitrary_listener_without_the_owned_control_master(self):
        config = self.config()
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(forward.ssh_transport, "load_config", return_value=config), \
                mock.patch.object(forward, "_process_generation", return_value="42"), \
                mock.patch.object(forward, "_process_command_matches", return_value=True), \
                mock.patch.object(forward, "_local_control_ready", return_value=False), \
                mock.patch.object(forward, "_port_is_ready", return_value=True):
            intent = forward._identity(config.hosts["archlinux"], "/private/owned.sock", 123, "42", "correlation", "ready", "/private/owned", "a" * 64)
            forward._write_intent(Path(directory), intent)
            result = forward.status(directory)
        self.assertEqual({"ok": False, "state": "ready", "correlationId": "correlation", "localPort": 45909}, result)

    def test_status_rejects_a_live_control_master_when_the_vnc_endpoint_has_no_banner(self):
        config = self.config()
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(forward.ssh_transport, "load_config", return_value=config), \
                mock.patch.object(forward, "_process_generation", return_value="42"), \
                mock.patch.object(forward, "_process_command_matches", return_value=True), \
                mock.patch.object(forward, "_local_control_ready", return_value=True), \
                mock.patch.object(forward, "_port_is_ready", return_value=False):
            intent = forward._identity(config.hosts["archlinux"], "/private/owned.sock", 123, "42", "correlation", "ready", "/private/owned", "a" * 64)
            forward._write_intent(Path(directory), intent)
            result = forward.status(directory)
        self.assertEqual({"ok": False, "state": "ready", "correlationId": "correlation", "localPort": 45909}, result)

    @unittest.skipUnless(platform.system() == "Darwin", "Darwin generation check")
    def test_darwin_generation_is_stable_for_a_harmless_live_child(self):
        child = subprocess.Popen(["/bin/sleep", "2"])
        try:
            first = forward._process_generation(child.pid)
            second = forward._process_generation(child.pid)
        finally:
            child.terminate()
            child.wait(timeout=2)
        self.assertIsNotNone(first)
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("darwin:"))

    @unittest.skipIf(os.name != "posix", "private Unix control sockets require POSIX ownership admission")
    def test_short_private_control_directory_reserves_open_ssh_suffix_budget(self):
        directory, control = forward._control_directory()
        try:
            self.assertEqual(forward._CONTROL_ROOT, directory.parent)
            self.assertTrue(directory.name.startswith("vcf-"))
            self.assertLessEqual(len(os.fsencode(control)) + forward._OPENSSH_SOCKET_SUFFIX_RESERVE,
                                 forward._MAX_UNIX_SOCKET_BYTES)
        finally:
            directory.rmdir()

    def test_windows_coordinator_mode_is_explicitly_unsupported_before_config_access(self):
        with mock.patch.object(forward.os, "name", "nt"), \
                mock.patch.object(forward.ssh_transport, "load_config") as load:
            self.assertEqual({"ok": False, "state": "unsupported_platform"}, forward.status("."))
            self.assertEqual({"ok": False, "state": "unsupported_platform"}, forward.open_forward("."))
            self.assertEqual({"ok": False, "state": "unsupported_platform"}, forward.close(".", {}))
        load.assert_not_called()


if __name__ == "__main__":
    unittest.main()
