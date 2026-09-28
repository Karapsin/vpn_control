from dataclasses import replace
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

    def test_adopted_ready_master_can_recover_after_expiry_without_replacing_history(self):
        config = self.config()
        old = config.hosts["archlinux"]
        adopted = replace(old, remote_control_path=transport.PurePosixPath("/remote/recovered/m"))
        config = replace(config, hosts={**config.hosts, "archlinux": adopted})
        with tempfile.TemporaryDirectory() as directory:
            legacy = Path(directory) / ".rag_index/ssh-recovery/archlinux.json"
            legacy.parent.mkdir(parents=True)
            history = recovery._intent_value("archlinux", old, "previous", "ready", str(adopted.remote_control_path))
            legacy.write_text(json.dumps(history))
            def response(*args, **kwargs):
                return mock.Mock(stdout=json.dumps({"state": "ready", "control_path": args[2][-1]}))
            with mock.patch.object(recovery.ssh_transport, "load_config", return_value=config), \
                    mock.patch.object(recovery, "_socket_state", return_value="absent"), \
                    mock.patch.object(recovery, "_gateway_run", side_effect=response) as run:
                result = recovery.recover(directory, "archlinux")
            self.assertEqual({"ok": True, "state": "recovery_master_ready"}, result)
            self.assertEqual(history, json.loads(legacy.read_text()))
            self.assertEqual(1, run.call_count)
            with mock.patch.object(recovery.ssh_transport, "load_config", return_value=config), \
                    mock.patch.object(recovery, "_socket_state", side_effect=("absent", "unknown")), \
                    mock.patch.object(recovery, "_gateway_run") as replay:
                self.assertEqual("recovery_intent_pending", recovery.recover(directory, "archlinux")["state"])
                replay.assert_not_called()

    def test_unknown_or_foreign_legacy_recovery_cannot_be_bypassed(self):
        old = self.config().hosts["archlinux"]
        adopted = replace(old, remote_control_path=transport.PurePosixPath("/remote/adopted/m"))
        for state, gateway in (("pending", old.gateway), ("ready", "other-gateway")):
            with self.subTest(state=state, gateway=gateway), tempfile.TemporaryDirectory() as directory:
                legacy = Path(directory) / ".rag_index/ssh-recovery/archlinux.json"
                legacy.parent.mkdir(parents=True)
                history = recovery._intent_value("archlinux", old, "previous", state, str(adopted.remote_control_path))
                history["gateway"] = gateway
                legacy.write_text(json.dumps(history))
                with self.assertRaises(recovery.RecoveryError):
                    recovery._read_intent(Path(directory), "archlinux", adopted)

    def test_changed_socket_or_config_cannot_bypass_unknown_hashed_recovery(self):
        initial = self.config()
        old = initial.hosts["archlinux"]
        recovered_path = recovery._recovery_socket_path(old, "0" * 32)[1]
        targets = (
            replace(old, remote_control_path=recovered_path),
            replace(old, remote_config_file=transport.PurePosixPath("/fixture/new-config")),
        )
        for target in targets:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                recovery._create_intent(Path(directory), "archlinux", old, "previous", str(recovered_path))
                history_path = recovery._intent_path(Path(directory), "archlinux", old)
                history = history_path.read_bytes()
                config = replace(initial, hosts={**initial.hosts, "archlinux": target})
                with mock.patch.object(recovery.ssh_transport, "load_config", return_value=config), \
                        mock.patch.object(recovery, "_socket_state", return_value="absent"), \
                        mock.patch.object(recovery, "_gateway_run") as run:
                    result = recovery.recover(directory, "archlinux")
                self.assertEqual({"ok": False, "state": "recovery_unavailable"}, result)
                run.assert_not_called()
                self.assertEqual(history, history_path.read_bytes())
                self.assertFalse(recovery._intent_path(Path(directory), "archlinux", target).exists())

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

    def test_socket_observation_uses_the_configured_remote_config(self):
        config = self.config()
        target = replace(config.hosts["archlinux"], remote_config_file=transport.PurePosixPath("/fixture/private-config"))
        with mock.patch.object(recovery, "_gateway_run", return_value=mock.Mock(returncode=0)) as run:
            self.assertEqual("ready", recovery._socket_state(config, target, target.remote_control_path, 5))
        self.assertEqual(("ssh", "-F", "/fixture/private-config", "-S", "/remote/configured.sock", "-O", "check", "archlinux"),
                         run.call_args.args[2])

    def test_recovery_intent_binds_the_remote_config_file(self):
        target = self.config().hosts["archlinux"]
        other = replace(target, remote_config_file=transport.PurePosixPath("/fixture/private-config"))
        self.assertNotEqual(recovery._intent_path(Path("/repo"), "archlinux", target),
                            recovery._intent_path(Path("/repo"), "archlinux", other))

    def test_pending_intent_prevents_second_master_launch(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(recovery.ssh_transport, "load_config", return_value=self.config()), \
                mock.patch.object(recovery, "_socket_state", side_effect=("absent", "unknown")), \
                mock.patch.object(recovery, "_gateway_run") as run:
            recovery._create_intent(Path(directory), "archlinux", self.config().hosts["archlinux"], "correlation", "/remote/new.sock")
            result = recovery.recover(directory, "archlinux")
        self.assertEqual({"ok": False, "state": "recovery_intent_pending"}, result)
        run.assert_not_called()

    def test_observed_master_readiness_resolves_intent_without_resubmitting(self):
        target = self.config().hosts["archlinux"]
        with tempfile.TemporaryDirectory() as directory:
            recovery._create_intent(Path(directory), "archlinux", target, "correlation", "/remote/new.sock")
            with mock.patch.object(recovery.ssh_transport, "load_config", return_value=self.config()), \
                    mock.patch.object(recovery, "_socket_state", side_effect=("absent", "ready")), \
                    mock.patch.object(recovery, "_gateway_run") as run:
                result = recovery.recover(directory, "archlinux")
            intent = recovery._read_intent(Path(directory), "archlinux", target)
        self.assertEqual({"ok": True, "state": "recovery_master_ready"}, result)
        self.assertEqual("ready", intent["state"])
        self.assertEqual("correlation", intent["correlationId"])
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

    def test_67_byte_configured_socket_allows_bounded_recovery_master(self):
        config = self.config()
        base = config.hosts["archlinux"]
        target = replace(base, remote_control_path=transport.PurePosixPath("/" + "a" * 64 + "/m"))
        config = replace(config, hosts={**config.hosts, "archlinux": target})
        self.assertEqual(67, len(str(target.remote_control_path).encode("utf-8")))
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(recovery.ssh_transport, "load_config", return_value=config), \
                mock.patch.object(recovery, "_socket_state", return_value="absent"), \
                mock.patch.object(recovery, "_gateway_run") as run:
            run.side_effect = lambda *args, **kwargs: mock.Mock(
                stdout=json.dumps({"state": "ready", "control_path": args[2][-1]}))
            result = recovery.recover(directory, "archlinux")
            intent = recovery._read_intent(Path(directory), "archlinux", target)
        self.assertEqual({"ok": True, "state": "recovery_master_ready"}, result)
        self.assertEqual("ready", intent["state"])
        self.assertLessEqual(len(intent["controlPath"].encode("utf-8")), recovery._MAX_REMOTE_SOCKET_BYTES)
        run.assert_called_once()

    def test_adopted_bounded_recovery_uses_a_sibling_without_replaying_a_mutation(self):
        initial = self.config()
        original = replace(initial.hosts["archlinux"], remote_control_path=transport.PurePosixPath("/" + "a" * 64 + "/m"))
        first_path = recovery._recovery_socket_path(original, "0" * 32)[1]
        adopted = replace(original, remote_control_path=first_path)
        config = replace(initial, hosts={**initial.hosts, "archlinux": adopted})
        old_history = recovery._intent_value("archlinux", original, "old-correlation", "ready", str(first_path))
        expected_path = original.remote_control_path.parent / f"r-{'1' * recovery._RECOVERY_CORRELATION_CHARS}" / "m"
        with tempfile.TemporaryDirectory() as directory:
            old_path = recovery._intent_path(Path(directory), "archlinux", original)
            old_path.parent.mkdir(parents=True)
            old_path.write_text(json.dumps(old_history))
            with mock.patch.object(recovery.ssh_transport, "load_config", return_value=config), \
                    mock.patch.object(recovery, "uuid4", return_value=mock.Mock(hex="1" * 32)), \
                    mock.patch.object(recovery, "_socket_state", side_effect=("absent", "absent", "unknown")), \
                    mock.patch.object(recovery, "_gateway_run") as run:
                run.side_effect = lambda *args, **kwargs: mock.Mock(
                    stdout=json.dumps({"state": "ready", "control_path": args[2][-1]}))
                first = recovery.recover(directory, "archlinux")
                second = recovery.recover(directory, "archlinux")
            current_intent = recovery._read_intent(Path(directory), "archlinux", adopted)
            stored_history = json.loads(old_path.read_text())
        self.assertEqual({"ok": True, "state": "recovery_master_ready"}, first)
        self.assertEqual({"ok": False, "state": "recovery_intent_pending"}, second)
        self.assertEqual(old_history, stored_history)
        self.assertEqual(str(expected_path), current_intent["controlPath"])
        self.assertLessEqual(len(current_intent["controlPath"].encode("utf-8")), recovery._MAX_REMOTE_SOCKET_BYTES)
        run.assert_called_once()

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
                ["python3", "-c", recovery._REMOTE_RECOVERY_SCRIPT, "", "archlinux", "5",
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

    def test_remote_helper_resolves_and_creates_only_the_private_config_route(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ssh = root / "ssh"
            evidence = root / "evidence"
            ssh.write_text(
                "#!/bin/sh\n"
                "test \"$1\" = '-F' && test \"$2\" = '/fixture/private config' || exit 19\n"
                "shift 2\n"
                "printf '%s\\n' \"$*\" >> \"$SSH_TEST_EVIDENCE\"\n"
                "if [ \"$1\" = '-G' ]; then printf '%s\\n' 'userknownhostsfile /fixture/known'; exit 0; fi\n"
                "if [ \"$1\" = '-M' ]; then exit 0; fi\n"
                "if [ \"$3\" = '-O' ]; then exit 0; fi\n"
                "exit 1\n", encoding="utf-8")
            ssh.chmod(0o700)
            target = replace(self.config().hosts["archlinux"],
                             remote_config_file=transport.PurePosixPath("/fixture/private config"))
            control_directory = root / "remote-control"
            control_path = str(control_directory / "master.sock")
            command = recovery._remote_command(target, 5, control_directory, control_path)
            environment = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}", "SSH_TEST_EVIDENCE": str(evidence)}
            completed = subprocess.run(command, input=json.dumps({"passphrase": "test-only-secret"}),
                                       text=True, capture_output=True, check=False, env=environment)
            self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
            self.assertEqual({"state": "ready", "control_path": control_path}, json.loads(completed.stdout))
            self.assertEqual(3, len(evidence.read_text(encoding="utf-8").splitlines()))


if __name__ == "__main__":
    unittest.main()
