import importlib.util
import json
import os
from pathlib import Path
import shlex
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

    @unittest.skipUnless(os.name == "posix", "native private inventory validation")
    def test_optional_baseline_inventory_does_not_change_ssh_host_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = {**self.config(), "nativeBaselines": {"schemaVersion": 1, "sources": {}}}
            self.write_config(root, value)
            self.assertEqual(("vm",), ssh.inventory(root))
            self.write_config(root, {**value, "nativeBaselines": "not-an-object"})
            with self.assertRaises(ssh.SshConfigError):
                ssh.load_config(root)

    def test_android_profiles_require_complete_explicit_device_identity(self):
        root = Path.cwd()
        entry = {"host": "example", "port": 22, "user": "tester",
                 "identityFile": str(root / "key"), "knownHostsFile": str(root / "known")}
        device = {"adb": "/opt/android/adb", "cli": "/opt/fixture/vpn-control",
                  "serial": "emulator-5684", "expectedAvd": "owned-api29", "api": 29}
        host = ssh._host_from_entry("vm", {**entry, "androidDevices": {"api29": device}})
        self.assertEqual(device, host.android_devices["api29"])
        for invalid in ({**device, "api": True}, {**device, "adb": "adb"},
                        {**device, "serial": "any-device"}, {**device, "extra": "ignored"}):
            with self.subTest(device=invalid), self.assertRaises(ssh.SshConfigError):
                ssh._host_from_entry("vm", {**entry, "androidDevices": {"api29": invalid}})

    def test_windows_probe_requires_exact_private_vm_and_account_identity(self):
        entry = self.config()["hosts"]["vm"]
        profile = {"environment": "owned-windows", "qgaSocketPath": "/home/tester/owned/qga.sock",
                   "qemuPid": 123, "qemuStartTicks": 456, "accountName": "fixtureuser",
                   "expectedSid": "S-1-5-21-1-2-3-1002", "credentialPath": str(Path.cwd() / "private-credential")}
        host = ssh._host_from_entry("vm", {**entry, "windowsCredentialProbe": profile})
        self.assertEqual(123, host.windows_credential_probe.qemu_pid)
        self.assertEqual(profile["expectedSid"], host.windows_credential_probe.expected_sid)
        for invalid in ({**profile, "qemuPid": True}, {**profile, "qemuStartTicks": 0},
                        {**profile, "expectedSid": "S-1-5-18"}, {**profile, "credentialPath": "relative"},
                        {**profile, "qgaSocketPath": "/tmp/../foreign.sock"}, {**profile, "command": "arbitrary"}):
            with self.subTest(profile=invalid), self.assertRaises(ssh.SshConfigError):
                ssh._host_from_entry("vm", {**entry, "windowsCredentialProbe": invalid})

    def test_windows_recovery_admission_requires_complete_task_binding(self):
        profile = {"environment": "owned-windows", "qgaSocketPath": "/owned/qga.sock",
                   "qemuPid": 123, "qemuStartTicks": 456, "accountName": "fixtureuser",
                   "expectedSid": "S-1-5-21-1-2-3-1002", "credentialPath": str(Path.cwd() / "credential")}
        task = {"taskName": "OwnedTask", "taskPath": "\\", "expectedLastResult": 1601,
                "expectedTaskExecute": "C:\\Windows\\powershell.exe", "expectedTaskPrincipal": "fixtureuser",
                "expectedTaskArgumentsSha256": "a" * 64, "expectedTaskState": "Disabled"}
        admitted = ssh._windows_credential_probe({**profile, "recoveryAdmission": task})
        self.assertEqual("OwnedTask", admitted.recovery_admission.task_name)
        self.assertIsNone(ssh._windows_credential_probe(profile).recovery_admission)
        for invalid in ({}, {**task, "expectedLastResult": True}, {**task, "expectedLastResult": -1},
                        {**task, "expectedTaskArgumentsSha256": "bad"}, {**task, "expectedTaskState": "Running"}, {**task, "command": "untrusted"}):
            with self.subTest(admission=invalid), self.assertRaises(ssh.SshConfigError):
                ssh._windows_credential_probe({**profile, "recoveryAdmission": invalid})

    def test_transfer_root_is_optional_absolute_remote_and_not_filesystem_root(self):
        root = Path.cwd()
        entry = {"host": "example", "port": 22, "user": "tester",
                 "identityFile": str(root / "key"), "knownHostsFile": str(root / "known"),
                 "fixtureTransferRoot": "/home/tester/.owned-fixtures"}
        value = ssh._host_from_entry("vm", entry)
        self.assertEqual("/home/tester/.owned-fixtures", str(value.fixture_transfer_root))
        for invalid in ("relative", "/", "/home/tester/../other"):
            with self.subTest(path=invalid), self.assertRaises(ssh.SshConfigError):
                ssh._host_from_entry("vm", {**entry, "fixtureTransferRoot": invalid})

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
    def test_three_host_route_retains_every_hop_and_quotes_guest_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gateway = self.config()["hosts"]["vm"] | {"host": "gateway.example", "port": 2228, "password": "gateway-secret"}
            arch = {"host": "unused", "port": 22, "user": "unused", "identityFile": "/unused/key",
                    "knownHostsFile": "/home/owner/.ssh/known_hosts", "transport": "nested",
                    "gateway": "gateway", "remoteHostAlias": "archlinux",
                    "remoteControlPath": "/home/owner/.ssh/arch socket"}
            fedora = {"host": "unused", "port": 2328, "user": "unused", "identityFile": "/unused/key",
                      "knownHostsFile": "/home/owner/.ssh/guest_known_hosts", "transport": "nested",
                      "gateway": "arch", "remoteHostAlias": "fedora",
                      "remoteConfigFile": "/home/owner/owned fixture/scp-config"}
            self.write_config(root, self.config({"gateway": gateway, "arch": arch, "fedora": fedora}))
            config = ssh.load_config(root)
            self.assertEqual("gateway", ssh.connection_host(config, "fedora").alias)
            argv = ssh.build_ssh_argv(config, "fedora", command=("printf", "%s", "a; $(touch /tmp/unsafe)"))
            self.assertEqual("gateway.example", argv[-2])
            self.assertEqual("BatchMode=no", argv[-3])
            arch_ssh = shlex.split(argv[-1])
            self.assertEqual(["ssh", "-S", "/home/owner/.ssh/arch socket"], arch_ssh[:3])
            self.assertEqual("archlinux", arch_ssh[-2])
            guest_ssh = shlex.split(arch_ssh[-1])
            self.assertEqual(["ssh", "-F", "/home/owner/owned fixture/scp-config"], guest_ssh[:3])
            self.assertNotIn("-S", guest_ssh)
            self.assertIn("StrictHostKeyChecking=yes", guest_ssh)
            self.assertIn("UserKnownHostsFile=/home/owner/.ssh/guest_known_hosts", guest_ssh)
            self.assertEqual("fedora", guest_ssh[-2])
            self.assertEqual(["printf", "%s", "a; $(touch /tmp/unsafe)"], shlex.split(guest_ssh[-1]))
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_ssh = fake_bin / "ssh"
            fake_ssh.write_text('#!/bin/sh\nfor last; do :; done\nexec /bin/sh -c "$last"\n', encoding="utf-8")
            fake_ssh.chmod(0o700)
            marker = root / "escaped"
            argument = f"two words; $(touch {marker})"
            simulated = ssh.build_ssh_argv(config, "fedora", ssh_binary=str(fake_ssh),
                                            command=("python3", "-c", "import json,sys; print(json.dumps(sys.argv[1:]))", argument))
            completed = ssh.subprocess.run(simulated, capture_output=True, text=True,
                                           env={**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}"}, check=False)
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual([argument], json.loads(completed.stdout))
            self.assertFalse(marker.exists())
            with mock.patch.object(ssh.subprocess, "run", return_value=mock.Mock(returncode=0, stdout="", stderr="")) as run:
                self.assertTrue(ssh.probe(root, "fedora").ok)
            self.assertIn("VPN_CONTROL_SSH_PASSWORD_FILE", run.call_args.kwargs["env"])
            self.assertNotIn("gateway-secret", " ".join(run.call_args.args[0]))

    @unittest.skipUnless(os.name == "posix", "native private inventory validation")
    def test_nested_routes_reject_cycles_excess_hops_and_unsafe_options(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            direct = self.config()["hosts"]["vm"]
            def nested(gateway, **changes):
                return {"host": "unused", "port": 22, "user": "unused", "identityFile": "/unused/key",
                        "knownHostsFile": "/owned/known_hosts", "transport": "nested", "gateway": gateway,
                        "remoteHostAlias": "safe-alias", "remoteControlPath": "/owned/master.sock", **changes}
            for hosts in (
                {"one": nested("two"), "two": nested("one")},
                {"gateway": direct, "a": nested("gateway"), "b": nested("a"), "c": nested("b"), "d": nested("c")},
                {"gateway": direct, "guest": nested("gateway", remoteConfigFile="relative/config")},
                {"gateway": direct, "guest": nested("gateway", remoteConfigFile="/owned/../foreign/config")},
                {"gateway": direct, "guest": nested("gateway", remoteHostAlias="-oProxyCommand=unsafe")},
            ):
                with self.subTest(hosts=tuple(hosts)):
                    self.write_config(root, self.config(hosts))
                    with self.assertRaises(ssh.SshConfigError):
                        ssh.load_config(root)

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
