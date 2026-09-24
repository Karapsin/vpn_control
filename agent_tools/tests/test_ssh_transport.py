import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ssh_transport", SOURCE / "ssh_transport.py")
ssh = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ssh
assert spec.loader is not None
spec.loader.exec_module(ssh)


class SshTransportTest(unittest.TestCase):
    def write_config(self, root, contents, mode=0o600):
        path = root / ".vm-hosts.local.json"
        path.write_text(json.dumps(contents), encoding="utf-8")
        path.chmod(mode)
        return path

    def config(self, hosts=None):
        key = str((SOURCE / "test-key").resolve())
        known_hosts = str((SOURCE / "test-known-hosts").resolve())
        return {"schemaVersion": 1, "hosts": hosts or {"vm": {"host": "127.0.0.1", "port": 22, "user": "tester", "identityFile": key, "knownHostsFile": known_hosts}}}

    def test_inventory_is_aliases_only_and_argv_uses_strict_host_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key, known = self.config()["hosts"]["vm"]["identityFile"], self.config()["hosts"]["vm"]["knownHostsFile"]
            config = ssh.SshConfig(root=root, hosts={"vm": ssh.SshHost("vm", "vm.example", 2222, "tester", Path(key), Path(known))})
            argv = ssh.build_ssh_argv(config, "vm", 7)
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertIn(f"UserKnownHostsFile={known}", argv)
            self.assertEqual(argv[-1], "true")
            self.assertNotIn("s3cr3t", " ".join(argv))

    def test_nested_route_uses_declared_gateway_and_quoted_remote_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = ssh.SshConfig(root=root, hosts={
                "gateway": ssh.SshHost("gateway", "ssh.example", 2228, "kardinal", Path("C:/id_ed25519"), Path("C:/gateway-known")),
                "arch": ssh.SshHost("arch", "unused", 22, "unused", Path("C:/unused"), ssh.PurePosixPath("/home/kardinal/.ssh/known_hosts"), transport="nested", gateway="gateway", remote_host_alias="archlinux", remote_control_path=ssh.PurePosixPath("/home/kardinal/.ssh/control path.sock")),
            })
            argv = ssh.build_ssh_argv(config, "arch")
            self.assertEqual(argv[-2], "ssh.example")
            self.assertIn("-S '/home/kardinal/.ssh/control path.sock'", argv[-1])
            self.assertIn("StrictHostKeyChecking=yes", argv[-1])

    @unittest.skipUnless(os.name == "posix", "native private inventory validation")
    def test_rejects_malformed_or_unsafe_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.write_config(root, self.config())
            path.write_text('{"schemaVersion": 1, "hosts": {}, "extra": true}', encoding="utf-8")
            with self.assertRaises(ssh.SshConfigError):
                ssh.load_config(root)
            self.write_config(root, self.config({
                "one": {"host": "one", "port": 22, "user": "one", "identityFile": "/tmp/key", "knownHostsFile": "/tmp/known", "proxyJump": "two"},
                "two": {"host": "two", "port": 22, "user": "two", "identityFile": "/tmp/key", "knownHostsFile": "/tmp/known", "proxyJump": "one"},
            }))
            with self.assertRaisesRegex(ssh.SshConfigError, "not supported"):
                ssh.load_config(root)
            self.write_config(root, self.config({
                "bad": {"host": "-oProxyCommand=unsafe", "port": 22, "user": "tester", "identityFile": "/tmp/key", "knownHostsFile": "/tmp/known"},
            }))
            with self.assertRaisesRegex(ssh.SshConfigError, "Invalid host"):
                ssh.load_config(root)

    @unittest.skipUnless(os.name == "posix", "POSIX private-file permission semantics")
    def test_rejects_insecure_mode_and_symlink_inventory_on_posix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.write_config(root, self.config(), mode=0o644)
            with self.assertRaisesRegex(ssh.SshConfigError, "0600"):
                ssh.load_config(root)
            path.chmod(0o600)
            path.unlink()
            target = root / "target.json"
            target.write_text(json.dumps(self.config()), encoding="utf-8")
            target.chmod(0o600)
            path.symlink_to(target)
            with self.assertRaisesRegex(ssh.SshConfigError, "regular"):
                ssh.load_config(root)

    @unittest.skipUnless(os.name == "posix", "native private inventory and POSIX askpass")
    def test_probe_uses_subprocess_argv_and_redacts_password(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = self.config()
            cfg["hosts"]["vm"]["password"] = "s3cr3t"
            self.write_config(root, cfg)
            completed = mock.Mock(returncode=255, stdout="", stderr="Permission denied: s3cr3t")
            with mock.patch.object(ssh.subprocess, "run", return_value=completed) as run:
                result = ssh.probe(root, "vm", 3)
            argv = run.call_args.args[0]
            self.assertIsInstance(argv, list)
            self.assertNotIn("s3cr3t", argv)
            self.assertEqual(result.status, ssh.ProbeStatus.AUTHENTICATION_FAILED)
            self.assertNotIn("s3cr3t", result.output)
            self.assertEqual(result.output, "SSH probe failed: authentication_failed.")
            environment = run.call_args.kwargs["env"]
            self.assertNotIn("VPN_CONTROL_SSH_PASSWORD", environment)
            self.assertIn("VPN_CONTROL_SSH_PASSWORD_FILE", environment)
            self.assertFalse(any(path.name.startswith("vpn-control-askpass-") for path in Path(tempfile.gettempdir()).iterdir()))

    def test_probe_classifies_bytes_timeout(self):
        self.assertEqual(ssh._status_for_output(ssh._sanitized_output(b"Permission denied", ())), ssh.ProbeStatus.AUTHENTICATION_FAILED)
    @unittest.skipUnless(os.name == "posix", "POSIX shell fake SSH executable")
    def test_real_fake_ssh_argument_forwarding_and_timeout_on_posix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_config(root, self.config())
            fake_ssh = root / "fake-ssh"
            fake_ssh.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\n", encoding="utf-8")
            fake_ssh.chmod(0o700)
            argv = ssh.build_ssh_argv(ssh.load_config(root), "vm", command=("printf", "%s", "two words"), ssh_binary=str(fake_ssh))
            output = ssh.subprocess.run(argv, capture_output=True, text=True, check=False)
            self.assertIn("printf %s 'two words'", output.stdout)
            slow_ssh = root / "slow-ssh"
            slow_ssh.write_text("#!/bin/sh\nsleep 3\n", encoding="utf-8")
            slow_ssh.chmod(0o700)
            self.assertEqual(ssh.probe(root, "vm", timeout_seconds=1, ssh_binary=str(slow_ssh)).status, ssh.ProbeStatus.TIMEOUT)


if __name__ == "__main__":
    unittest.main()
