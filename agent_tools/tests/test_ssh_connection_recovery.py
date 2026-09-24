import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
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


class SshConnectionRecoveryTest(unittest.TestCase):
    def config(self):
        gateway = transport.SshHost("gateway", "gateway.example", 2228, "tester", Path("/tmp/gateway-key"), Path("/tmp/gateway-known"))
        nested = transport.SshHost("archlinux", "unused", 22, "unused", Path("/tmp/unused"), transport.PurePosixPath("/remote/known"),
                                  transport="nested", gateway="gateway", remote_host_alias="archlinux",
                                  remote_control_path=transport.PurePosixPath("/remote/configured.sock"), password="nested-passphrase-value")
        return transport.SshConfig(Path.cwd(), {"gateway": gateway, "archlinux": nested})

    def test_ready_configured_master_does_not_create_or_write_intent(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(recovery.ssh_transport, "load_config", return_value=self.config()), \
                mock.patch.object(recovery, "_socket_state", return_value="ready") as check, \
                mock.patch.object(recovery, "_gateway_run") as run:
            result = recovery.recover(directory, "archlinux")
        self.assertEqual({"ok": True, "state": "configured_master_ready"}, result)
        check.assert_called_once()
        run.assert_not_called()

    def test_unknown_configured_socket_never_launches_recovery(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(recovery.ssh_transport, "load_config", return_value=self.config()), \
                mock.patch.object(recovery, "_socket_state", return_value="unknown"), \
                mock.patch.object(recovery, "_gateway_run") as run:
            result = recovery.recover(directory, "archlinux")
        self.assertEqual({"ok": False, "state": "configured_master_unknown"}, result)
        run.assert_not_called()

    def test_pending_intent_prevents_second_master_launch(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(recovery.ssh_transport, "load_config", return_value=self.config()), \
                mock.patch.object(recovery, "_socket_state", side_effect=("absent", "unknown")), \
                mock.patch.object(recovery, "_gateway_run") as run:
            recovery._create_intent(Path(directory), "archlinux", self.config().hosts["archlinux"], "correlation", "/remote/new.sock")
            result = recovery.recover(directory, "archlinux")
        self.assertEqual({"ok": False, "state": "recovery_intent_pending"}, result)
        run.assert_not_called()

    def test_absent_socket_records_intent_before_secret_stdin_request(self):
        completed = mock.Mock(returncode=0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(recovery.ssh_transport, "load_config", return_value=self.config()), \
                mock.patch.object(recovery, "_socket_state", return_value="absent"), \
                mock.patch.object(recovery, "_gateway_run", return_value=completed) as run:
            expected_parent = "/remote/r-"
            def response(*args, **kwargs):
                command = args[2]
                control_path = command[-1]
                return mock.Mock(returncode=0, stdout=json.dumps({"state": "ready", "control_path": control_path}), stderr="")
            run.side_effect = response
            result = recovery.recover(directory, "archlinux")
            intent = recovery._read_intent(Path(directory), "archlinux", self.config().hosts["archlinux"])
        self.assertEqual({"ok": True, "state": "recovery_master_ready"}, result)
        self.assertEqual("ready", intent["state"])
        self.assertTrue(intent["controlPath"].startswith(expected_parent))
        secret = json.loads(run.call_args.kwargs["input_text"])["passphrase"]
        self.assertEqual("nested-passphrase-value", secret)
        self.assertNotIn(secret, " ".join(run.call_args.args[2]))
        self.assertIn("StrictHostKeyChecking=yes", recovery._REMOTE_RECOVERY_SCRIPT)

    def test_response_loss_keeps_deterministic_path_for_readonly_retry(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(recovery.ssh_transport, "load_config", return_value=self.config()), \
                mock.patch.object(recovery, "_socket_state", return_value="absent"), \
                mock.patch.object(recovery, "_gateway_run", return_value=None):
            result = recovery.recover(directory, "archlinux")
            intent = recovery._read_intent(Path(directory), "archlinux", self.config().hosts["archlinux"])
        self.assertEqual({"ok": False, "state": "recovery_intent_pending"}, result)
        self.assertTrue(intent["controlPath"].startswith("/remote/r-"))
        self.assertTrue(intent["controlPath"].endswith("/m"))

    def test_configured_like_long_socket_parent_is_rejected_before_intent(self):
        base = self.config().hosts["archlinux"]
        target = transport.SshHost(base.alias, base.host, base.port, base.user, base.identity_file,
                                   base.known_hosts_file, transport=base.transport, gateway=base.gateway,
                                   remote_host_alias=base.remote_host_alias,
                                   remote_control_path=transport.PurePosixPath("/" + "a" * 80 + "/configured.sock"),
                                   password=base.password)
        self.assertIsNone(recovery._recovery_socket_path(target, "1234567890abcdef1234567890abcdef"))

    def test_real_transport_accepts_encoded_remote_recovery_command(self):
        target = self.config().hosts["archlinux"]
        command = recovery._remote_command(target, 30, transport.PurePosixPath("/remote/r-1234567890abcdef"),
                                           "/remote/r-1234567890abcdef/m")
        argv = transport.build_ssh_argv(self.config(), "gateway", 30, command=command)
        self.assertNotIn("\n", command[2])
        self.assertIn("exec(", command[2])
        self.assertEqual("gateway.example", argv[-2])

    def test_exclusive_intent_rejects_a_duplicate_creator(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self.config().hosts["archlinux"]
            recovery._create_intent(Path(directory), "archlinux", target, "first", "/remote/first.sock")
            with self.assertRaises(FileExistsError):
                recovery._create_intent(Path(directory), "archlinux", target, "second", "/remote/second.sock")

    def test_gateway_capture_retains_a_fixed_maximum(self):
        with tempfile.TemporaryDirectory() as directory:
            writer = Path(directory) / "writer"
            writer.write_text("#!/bin/sh\nhead -c 20000 /dev/zero | tr '\\000' x >&2\n", encoding="utf-8")
            writer.chmod(0o700)
            completed = recovery._bounded_run([str(writer)], 2)
        self.assertEqual(0, completed.returncode)
        self.assertEqual(recovery._MAX_CAPTURE_CHARS, len(completed.stderr))

    def test_remote_helper_uses_askpass_stdin_and_resolved_known_hosts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ssh = root / "ssh"
            evidence = root / "evidence"
            ssh.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"-G\" ]; then printf '%s\\n' 'userknownhostsfile /fixture/known'; exit 0; fi\n"
                "if [ \"$1\" = \"-M\" ]; then \"$SSH_ASKPASS\" > \"$SSH_TEST_EVIDENCE\"; printf '%s\\n' \"$*\" >> \"$SSH_TEST_EVIDENCE\"; exit 0; fi\n"
                "if [ \"$3\" = \"-O\" ]; then exit 0; fi\n"
                "exit 1\n", encoding="utf-8")
            ssh.chmod(0o700)
            control_directory = root / "remote-control"
            control_path = control_directory / "master.sock"
            environment = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}", "SSH_TEST_EVIDENCE": str(evidence)}
            completed = subprocess.run(
                ["python3", "-c", recovery._REMOTE_RECOVERY_SCRIPT, "archlinux", "5",
                 str(control_directory), str(control_path)],
                input=json.dumps({"passphrase": "test-only-secret"}), text=True, capture_output=True, check=False, env=environment)
            self.assertEqual(0, completed.returncode)
            self.assertEqual({"state": "ready", "control_path": str(control_path)}, json.loads(completed.stdout))
            captured = evidence.read_text(encoding="utf-8")
            self.assertIn("test-only-secret", captured)
            self.assertEqual(1, captured.count("test-only-secret"))
            self.assertIn("UserKnownHostsFile=/fixture/known", captured)
            self.assertIn("BatchMode=no", captured)
            self.assertIn("ConnectTimeout=5", captured)


if __name__ == "__main__":
    unittest.main()
