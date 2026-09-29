"""Public native guest package action guards."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock
import uuid

from agent_tools import linux_deb_arch_native_driver as native


class NativeDriverTest(unittest.TestCase):
    def intent(self, target_sha: str) -> dict:
        return {"profile": "fresh-deb-dependencies", "distribution": "ubuntu",
                "guestRole": "ubuntu-fresh", "correlationId": str(uuid.uuid4()),
                "sourceSha": "a" * 40, "sourceFingerprint": "b" * 64,
                "targetVersion": "2.2.0", "targetSha256": target_sha,
                "fixtureReceiptArtifactId": "sha256-" + "f" * 64, "trustStoreSha256": None,
                "harnessSha256": None}

    def test_wrong_staged_package_never_invokes_apt(self):
        with tempfile.TemporaryDirectory() as temp:
            stage = Path(temp)
            (stage / "target.deb").write_bytes(b"different")
            called = []
            with mock.patch.object(native, "_stage", return_value=stage), \
                 mock.patch.object(native, "_sha_staged_file", return_value=hashlib.sha256(b"different").hexdigest()), \
                 mock.patch.object(native, "_read_small_owned", return_value=json.dumps(self.intent("c" * 64)).encode()), \
                 mock.patch.object(native, "_guest_quiet", return_value=True), \
                 mock.patch.object(native, "_claim"), \
                 mock.patch.object(native.os, "getuid", return_value=1000):
                with self.assertRaisesRegex(ValueError, "package bytes differ"):
                    current = self.intent("c" * 64)
                    with mock.patch.object(native, "_read_small_owned", return_value=json.dumps(current).encode()):
                        native.fixed_guest_action(current, runner=lambda argv, **kw: called.append(argv))
            self.assertEqual([], called)

    def test_fresh_apt_transaction_keeps_other_packages_and_checks_dependencies(self):
        before = {"bash": "1"}
        after = {"bash": "1", "vpn-control": "2.2.0-1", "xdg-utils": "1"}
        calls = []
        def runner(argv, **kwargs):
            calls.append(tuple(argv))
            if argv[:2] == ["dpkg", "--audit"]:
                return SimpleNamespace(returncode=0, stdout="")
            if argv[:2] == ["sudo", "-n"]:
                return SimpleNamespace(returncode=0)
            if argv[:1] == ["/opt/vpn-control/bin/vpn-control"]:
                return SimpleNamespace(returncode=0, stdout="2.2.0\n")
            raise AssertionError(argv)
        with mock.patch.object(native, "_sha_staged_file", return_value="c" * 64), \
             mock.patch.object(native, "_packages", side_effect=[before, after]), \
             mock.patch.object(Path, "exists", return_value=False), \
             mock.patch.object(Path, "is_dir", return_value=True):
            result = native._fresh_deb(self.intent("c" * 64), Path("/fixed"), runner)
        self.assertTrue(result["packageTransaction"]["onlyExpectedPackagesAdded"])
        self.assertTrue(result["launcherVersionMatched"])
        self.assertTrue(any(command[:4] == ("sudo", "-n", "apt-get", "install") for command in calls))

    def test_fresh_version_substring_cannot_pass_launcher_match(self):
        before = {"bash": "1"}
        after = {"bash": "1", "vpn-control": "2.2.0-1", "xdg-utils": "1"}
        def runner(argv, **kwargs):
            if argv[:2] == ["dpkg", "--audit"]:
                return SimpleNamespace(returncode=0, stdout="")
            if argv[:2] == ["sudo", "-n"]:
                return SimpleNamespace(returncode=0)
            if argv[:1] == ["/opt/vpn-control/bin/vpn-control"]:
                return SimpleNamespace(returncode=0, stdout="12.2.0\n")
            raise AssertionError(argv)
        with mock.patch.object(native, "_sha_staged_file", return_value="c" * 64), \
             mock.patch.object(native, "_packages", side_effect=[before, after]), \
             mock.patch.object(Path, "exists", return_value=False), \
             mock.patch.object(Path, "is_dir", return_value=True):
            result = native._fresh_deb(self.intent("c" * 64), Path("/fixed"), runner)
        self.assertFalse(result["launcherVersionMatched"])

    def test_guest_intent_rejects_invalid_correlation_and_role(self):
        intent = self.intent("c" * 64)
        with self.assertRaises(ValueError):
            native._request({**intent, "correlationId": "bad"})
        with self.assertRaises(ValueError):
            native._request({**intent, "guestRole": "ubuntu-update"})

    def test_live_package_process_blocks_before_role_claim(self):
        current = self.intent("c" * 64)
        with mock.patch.object(native.os, "getuid", return_value=1000), \
             mock.patch.object(native, "_stage", return_value=Path("/fixed")), \
             mock.patch.object(native, "_read_small_owned", return_value=json.dumps(current).encode()), \
             mock.patch.object(native, "_guest_quiet", return_value=False), \
             mock.patch.object(native, "_claim") as claim:
            with self.assertRaisesRegex(ValueError, "process, or job is active"):
                native.fixed_guest_action(current)
            claim.assert_not_called()

    def test_guest_process_census_ignores_probe_ancestor_and_denies_package_pid(self):
        with tempfile.TemporaryDirectory() as temp:
            proc = Path(temp)
            self_pid = proc / "100"
            self_pid.mkdir()
            (self_pid / "stat").write_text("100 (python) S 1 0 0 0\n")
            (self_pid / "cmdline").write_bytes(b"/opt/vpn-control/literal-in-probe\0")
            (self_pid / "exe").symlink_to("/usr/bin/python3")
            other = proc / "101"
            other.mkdir()
            (other / "cmdline").write_bytes(b"/usr/bin/dpkg\0")
            (other / "exe").symlink_to("/usr/bin/dpkg")
            with mock.patch.object(native.os, "getpid", return_value=100):
                self.assertFalse(native._guest_quiet(proc))
                (other / "cmdline").write_bytes(b"/usr/bin/sleep\0")
                (other / "exe").unlink()
                (other / "exe").symlink_to("/usr/bin/sleep")
                self.assertTrue(native._guest_quiet(proc))
                (other / "cmdline").unlink()
                self.assertFalse(native._guest_quiet(proc))

    def test_dangling_protected_job_root_blocks_guest_claim(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            proc = root / "proc"
            proc.mkdir()
            current = proc / "100"
            current.mkdir()
            (current / "stat").write_text("100 (python) S 1 0 0 0\n")
            dangling = root / "protected-jobs"
            dangling.symlink_to(root / "absent", target_is_directory=True)
            with mock.patch.object(native.os, "getpid", return_value=100), \
                 mock.patch.object(native, "_PROTECTED_JOBS", dangling):
                self.assertFalse(native._guest_quiet(proc))

    def test_update_invokes_frozen_public_harness_with_retained_pty(self):
        intent = {**self.intent("c" * 64), "profile": "package-update", "guestRole": "ubuntu-update",
                  "trustStoreSha256": "d" * 64, "harnessSha256": "e" * 64}
        stage = Path("/var/lib/vpn-control-parity/ubuntu-update")
        receipt = {"sourceFingerprint": "b" * 64,
                   "derivedFrom": {"derivedFromArtifactId": intent["fixtureReceiptArtifactId"]}}
        ready = {"sourceFingerprint": "b" * 64, "port": 33913}
        observed = []
        def read(path, **kwargs):
            if path.name == "fixture-receipt.json":
                return json.dumps(receipt).encode()
            if path.name == "public-fixture.json":
                return json.dumps(ready).encode()
            return b"script"
        def runner(argv, **kwargs):
            observed.append((argv, kwargs))
            return SimpleNamespace(returncode=0, stdout='{"evidence":"/private/result"}\n' +
                                   json.dumps({"targetVersion": "2.2.0", "sourceFingerprint": "b" * 64,
                                               "productionTrustedInstallSucceeded": True}), stderr="")
        with mock.patch.object(native, "_sha_staged_file", side_effect=["c" * 64, "d" * 64, "e" * 64]), \
             mock.patch.object(native, "_read_small_owned", side_effect=read), \
             mock.patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)):
            result = native._update(intent, stage, runner)
        self.assertEqual(0, result["exitCode"])
        command, options = observed[0]
        self.assertIn("--retained-fixture-auth", command)
        self.assertIn("--require-same-source-recovery", command)
        self.assertNotIn("--preserve-existing-fixture-password", command)
        self.assertIn("127.0.0.1", options["env"]["JAVA_TOOL_OPTIONS"])

    def test_update_rejects_wrong_target_before_harness(self):
        intent = {**self.intent("c" * 64), "profile": "package-update", "guestRole": "ubuntu-update",
                  "trustStoreSha256": "d" * 64, "harnessSha256": "e" * 64}
        called = []
        with mock.patch.object(native, "_sha_staged_file", return_value="e" * 64):
            with self.assertRaisesRegex(ValueError, "package bytes differ"):
                native._update(intent, Path("/fixed"), lambda argv, **kw: called.append(argv))
        self.assertEqual([], called)

    def test_guest_stage_intent_mismatch_blocks_before_claim(self):
        current = self.intent("c" * 64)
        wrong = {**current, "sourceSha": "e" * 40}
        with mock.patch.object(native.os, "getuid", return_value=1000), \
             mock.patch.object(native, "_stage", return_value=Path("/fixed")), \
             mock.patch.object(native, "_read_small_owned", return_value=json.dumps(wrong).encode()), \
             mock.patch.object(native, "_claim") as claim:
            with self.assertRaisesRegex(ValueError, "intent differs"):
                native.fixed_guest_action(current)
            claim.assert_not_called()

    def test_guest_role_claim_is_one_shot(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(Path, "home", return_value=Path(temp)):
                correlation = str(uuid.uuid4())
                native._claim("ubuntu-fresh", correlation)
                with self.assertRaises(FileExistsError):
                    native._claim("ubuntu-fresh", correlation)

    def test_invalid_role_does_not_burn_guest_claim(self):
        current = {**self.intent("c" * 64), "profile": "arch-rollback", "distribution": "arch",
                   "guestRole": "unknown-rollback", "trustStoreSha256": "d" * 64,
                   "harnessSha256": "e" * 64}
        with mock.patch.object(native.os, "getuid", return_value=1000), \
             mock.patch.object(native, "_stage", return_value=Path("/fixed")), \
             mock.patch.object(native, "_read_small_owned", return_value=json.dumps(current).encode()), \
             mock.patch.object(native, "_claim") as claim:
            with self.assertRaisesRegex(ValueError, "identity is invalid"):
                native.fixed_guest_action(current)
            claim.assert_not_called()

    def test_staged_package_symlink_is_never_followed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "bytes.deb"
            target.write_bytes(b"package")
            link = root / "target.deb"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                native._sha_staged_file(link, max_bytes=100)

    def test_rollback_unknown_protected_outcome_preserves_fault(self):
        with tempfile.TemporaryDirectory() as temp:
            stage = Path(temp)
            (stage / "scripts").mkdir()
            module_path = stage / "scripts/arch_public_update.py"
            module_path.write_text("# test fixture\n")
            fake_module = SimpleNamespace(__file__=str(module_path), verify_arch_bundle_base=lambda *args: {
                "sourceFingerprint": "b" * 64})
            intent = {**self.intent("c" * 64), "profile": "arch-rollback", "distribution": "arch",
                      "guestRole": "arch-rollback", "trustStoreSha256": "d" * 64,
                      "harnessSha256": "e" * 64}
            original_lstat = Path.lstat
            icon = Path("/usr/share/icons/hicolor/256x256/apps/vpn-control.png")
            def lstat(path):
                if path == icon:
                    return SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_dev=7, st_ino=8)
                if path == stage / "scripts":
                    return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
                return original_lstat(path)
            calls = []
            def runner(argv, **kwargs):
                calls.append(tuple(argv))
                if argv[0] == "lsattr":
                    return SimpleNamespace(returncode=0, stdout="------------- icon\n")
                if argv[:4] == ["sudo", "-n", "/usr/bin/chattr", "+i"]:
                    return SimpleNamespace(returncode=0)
                return SimpleNamespace(returncode=1, stdout='{"evidence":"/tmp/unknown"}', stderr="failed")
            trace = SimpleNamespace(close=mock.Mock())
            with mock.patch.object(native, "_update_setup", return_value=(["python3", "harness"], {})), \
                 mock.patch.object(Path, "lstat", autospec=True, side_effect=lstat), \
                 mock.patch.dict(sys.modules, {"arch_public_update": fake_module}):
                with self.assertRaisesRegex(ValueError, "unknown"):
                    native._rollback(intent, stage, runner, trace_factory=lambda: trace,
                                     evidence_reader=lambda *_: (_ for _ in ()).throw(ValueError("unknown")))
            trace.close.assert_called_once()
            self.assertFalse(any(command[:4] == ("sudo", "-n", "/usr/bin/chattr", "-i") for command in calls))


if __name__ == "__main__":
    unittest.main()
