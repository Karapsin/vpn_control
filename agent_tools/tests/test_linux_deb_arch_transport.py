"""Causal checks for fixed DEB/Arch live guest observation."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

from agent_tools import linux_deb_arch_acceptance as acceptance
from agent_tools import linux_deb_arch_transport as transport


class LiveObserverTest(unittest.TestCase):
    def fixture(self):
        request = {"profile": "package-update", "distribution": "ubuntu", "correlationId": str(uuid.uuid4()),
                   "sourceSha": "a" * 40, "artifactIds": {key: "sha256-" + str(index) * 64 for index, key
                                                      in enumerate(sorted(acceptance._ARTIFACT_KEYS), 1)}}
        intent = acceptance.Intent.parse(request)
        guest = {"guestRole": intent.guest_role, "sshPort": intent.guest_port,
                 "tree": "/home/kardinal/vpn-control-install-vm-parity-ubuntu-update",
                 "qemuPid": 123, "qemuStartTicks": 456, "diskDevice": 7, "diskInode": 8}
        preparation = {"guestRole": intent.guest_role, "profile": intent.profile,
                       "qemu": {"pid": 123}, "baseline": {"installedBaseVersion": "2.1.19"},
                       "fixture": {"serverPid": 100, "serverStartTicks": 200},
                       "workerIntentSha256": "d" * 64,
                       "nativeWorkerSha256": "e" * 64, "rollbackWorkerSha256": "f" * 64}
        return intent, guest, preparation

    def test_fixed_program_contains_only_owned_roles_and_compiles(self):
        for distribution in ("ubuntu", "arch"):
            program = transport._program(distribution, "package-update", distribution + "-update", "2.1.19",
                                         {"serverPid": 100, "serverStartTicks": 200}, "d" * 64,
                                         "e" * 64, "f" * 64)
            compile(program, "fixed-host-program", "exec")
            self.assertIn("vpn-control-install-vm-parity-", program)
            self.assertNotIn("vpn-control-install-vm-9540bc92", program)

    def test_embedded_guest_process_census_executes_without_self_match_and_fails_closed(self):
        source = transport._GUEST
        start = source.index(" ancestors=set();current=os.getpid()")
        end = source.index(" if expected=='ubuntu':", start)
        with tempfile.TemporaryDirectory() as temp:
            proc = Path(temp)
            self_pid = proc / "100"
            self_pid.mkdir()
            (self_pid / "stat").write_text("100 (python) S 1 0 0 0\n")
            (self_pid / "cmdline").write_bytes(b"python3\0-c\0/opt/vpn-control/literal-in-probe\0")
            (self_pid / "exe").symlink_to("/usr/bin/python3")
            other = proc / "101"
            other.mkdir()
            (other / "cmdline").write_bytes(b"/usr/bin/sleep\0")
            (other / "exe").symlink_to("/usr/bin/sleep")
            snippet = "if True:\n" + source[start:end].replace("/proc", str(proc))
            with mock.patch.object(os, "getpid", return_value=100):
                facts = {"os": os}
                exec(snippet, facts)
                self.assertEqual([], facts["procs"])
                self.assertEqual([], facts["package_procs"])
                (other / "cmdline").write_bytes(b"/usr/bin/dpkg\0")
                facts = {"os": os}
                exec(snippet, facts)
                self.assertEqual(["101"], facts["package_procs"])
                (other / "cmdline").unlink()
                with self.assertRaisesRegex(ValueError, "unreadable"):
                    exec(snippet, {"os": os})

    def test_embedded_arch_base_version_rejects_substring(self):
        source = transport._GUEST
        start = source.index(" if expected=='ubuntu':")
        end = source.index(" def ticks(pid):", start)
        snippet = "if True:\n" + source[start:end]
        fake_subprocess = SimpleNamespace(
            PIPE=-1, DEVNULL=-2,
            run=lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b"12.1.19\n"))
        with mock.patch.object(os.path, "isfile", return_value=True):
            facts = {"os": os, "subprocess": fake_subprocess, "expected": "arch",
                     "base_version": "2.1.19"}
            exec(snippet, facts)
        self.assertIsNone(facts["installed_version"])

    def test_embedded_guest_rejects_dangling_protected_job_root(self):
        source = transport._GUEST
        start = source.index(" jobs_root='/var/lib/vpn-control-install-jobs'")
        end = source.index(" jobs_clear=not names", start)
        with tempfile.TemporaryDirectory() as temp:
            dangling = Path(temp) / "jobs"
            dangling.symlink_to(Path(temp) / "absent", target_is_directory=True)
            snippet = "if True:\n" + source[start:end].replace(
                "/var/lib/vpn-control-install-jobs", str(dangling))
            with self.assertRaisesRegex(ValueError, "protected job root unsafe"):
                exec(snippet, {"os": os})

    def test_live_observer_uses_fixed_ssh_route_and_rejects_mismatch(self):
        intent, guest, preparation = self.fixture()
        calls = []
        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return SimpleNamespace(returncode=0, stdout=json.dumps({"ready": True, "qemuPid": 123}).encode())
        config = SimpleNamespace(hosts={"archlinux": SimpleNamespace()})
        with mock.patch.object(transport.ssh_transport, "load_config", return_value=config), \
             mock.patch.object(transport.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)), \
             mock.patch.object(transport.ssh_transport, "build_ssh_argv", return_value=["ssh", "fixed-host"]):
            observer = transport.FixedLiveObserver(Path(tempfile.gettempdir()), runner=runner)
            self.assertTrue(observer(intent, guest, preparation)["ready"])
            self.assertEqual(1, len(calls))
            self.assertEqual(["ssh", "fixed-host"], calls[0][0])
            self.assertFalse(observer(intent, {**guest, "sshPort": 22}, preparation)["ready"])
            self.assertEqual(1, len(calls))

    def test_live_observer_returns_unknown_on_transport_failure(self):
        intent, guest, preparation = self.fixture()
        with mock.patch.object(transport.ssh_transport, "load_config", side_effect=ValueError("missing")):
            self.assertEqual({"ready": False}, transport.FixedLiveObserver("/")(intent, guest, preparation))

    def test_fixed_native_plan_has_only_public_package_and_harness_actions(self):
        for profile, distro, command in (("fresh-deb-dependencies", "ubuntu", "apt-get"),
                                         ("package-update", "ubuntu", "test_linux_public_install.py"),
                                         ("package-update", "arch", "test_linux_public_install.py"),
                                         ("arch-rollback", "arch", "test_linux_public_install.py")):
            request = {"profile": profile, "distribution": distro, "correlationId": str(uuid.uuid4()),
                       "sourceSha": "a" * 40, "artifactIds": {key: "sha256-" + str(index) * 64 for index, key
                                                          in enumerate(sorted(acceptance._ARTIFACT_KEYS), 1)}}
            intent = acceptance.Intent.parse(request)
            admitted = {"ready": True, "guestRole": intent.guest_role, "sourceSha": intent.source_sha,
                        "fixture": {"targetVersion": "2.2.0"},
                        "preparation": {"stage": "/var/lib/vpn-control-parity/" + intent.guest_role}}
            plan = transport.fixed_native_plan(intent, admitted)
            self.assertIn(command, " ".join(plan.argv))
            self.assertEqual(profile == "arch-rollback", plan.requires_rollback_trace)
            self.assertEqual(intent.artifact_ids["targetPackage"].removeprefix("sha256-"), plan.target_sha256)
            if profile != "fresh-deb-dependencies":
                self.assertIn("--retained-fixture-auth", plan.argv)
                self.assertNotIn("--preserve-existing-fixture-password", plan.argv)
                self.assertNotIn("-I", plan.argv)  # Harness imports frozen sibling modules.
            with self.assertRaises(ValueError):
                transport.fixed_native_plan(intent, {**admitted, "sourceSha": "b" * 40})


if __name__ == "__main__":
    unittest.main()
