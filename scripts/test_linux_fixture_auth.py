#!/usr/bin/env python3
"""Deterministic tests for owned Linux fixture OS-authentication inputs."""
import json
import os
import stat
import tempfile
import unittest
import runpy
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import linux_fixture_auth as subject


class Runner:
    def __init__(self, status="vpnfixture L 2026-09-24 0 99999 7 -1", password_rc=0):
        self.status, self.password_rc, self.calls = status, password_rc, []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[:2] == ["passwd", "--status"]:
            return SimpleNamespace(returncode=0, stdout=self.status)
        return SimpleNamespace(returncode=self.password_rc, stdout="")


class PasswordBaselineRunner(Runner):
    def __init__(self, fail=None):
        super().__init__(status="vpnfixture P 2026-09-24 0 99999 7 -1")
        self.shadow = ["vpnfixture", "$6$original-hash", "20355", "0", "99999", "7", "", "", ""]
        self.fail, self.shadow_reads = fail, 0

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[:2] == ["passwd", "--status"]:
            return SimpleNamespace(returncode=0, stdout=self.status)
        if argv == ["sudo", "-n", "getent", "shadow", "vpnfixture"]:
            self.shadow_reads += 1
            failed = self.fail == "shadow" or (self.fail == "post-shadow" and self.shadow_reads > 1)
            return SimpleNamespace(returncode=1 if failed else 0,
                                   stdout=":".join(self.shadow) + "\n")
        if argv == ["sudo", "-n", "chpasswd"]:
            if self.fail == "set": return SimpleNamespace(returncode=1, stdout="")
            self.shadow[1] = "$6$temporary-hash"; self.shadow[2] = "20400"
            return SimpleNamespace(returncode=0, stdout="")
        if argv == ["sudo", "-n", "chpasswd", "-e"]:
            if self.fail == "restore": return SimpleNamespace(returncode=1, stdout="")
            self.shadow[1] = kwargs["input"].split(":", 1)[1].rstrip("\n")
            return SimpleNamespace(returncode=0, stdout="")
        if argv[:4] == ["sudo", "-n", "chage", "-d"]:
            if self.fail == "age": return SimpleNamespace(returncode=1, stdout="")
            self.shadow[2] = "" if argv[4] == "-1" else argv[4]
            return SimpleNamespace(returncode=0, stdout="")
        return SimpleNamespace(returncode=0, stdout="")


class LinuxFixtureAuthTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.directory = self.root / "auth"
        self.runner = Runner(); self.uid = os.geteuid()
        self.account = lambda _: SimpleNamespace(pw_name="vpnfixture", pw_uid=self.uid)
        self.identity = dict(platform="linux", geteuid=lambda: self.uid)
        self.args = dict(credential_dir=self.directory, correlation="fedora-2328", purpose=subject.PURPOSE,
                         guest_confirmation=subject.OWNED_GUEST_CONFIRMATION, runner=self.runner,
                         account_lookup=self.account, password_factory=lambda: "unit-test-password", **self.identity)

    def prepare(self):
        return subject.prepare(**self.args)

    def test_prepare_uses_locked_account_stdin_only_and_safe_receipt(self):
        receipt = self.prepare()
        self.assertEqual({"account", "correlation", "credentialPath", "credentialPathInode", "purpose", "uid"}, set(receipt))
        self.assertNotIn("unit-test-password", json.dumps(receipt))
        self.assertEqual(0o700, stat.S_IMODE(self.directory.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE((self.directory / "credential").stat().st_mode))
        command, kwargs = self.runner.calls[-1]
        self.assertEqual(["sudo", "-n", "chpasswd"], command)
        self.assertNotIn("unit-test-password", " ".join(command))
        self.assertEqual("vpnfixture:unit-test-password\n", kwargs["input"])
        self.assertEqual(receipt, subject.status(credential_dir=self.directory, correlation="fedora-2328", purpose=subject.PURPOSE,
                                                 account_lookup=self.account, **self.identity))

    def test_wrong_purpose_truststore_cannot_create_or_read_os_credential(self):
        self.args["purpose"] = "public-truststore-password"
        with self.assertRaisesRegex(subject.FixtureAuthError, "purpose"):
            self.prepare()
        self.assertEqual([], self.runner.calls)
        self.assertFalse(self.directory.exists())

    def test_nonlocked_account_is_rejected_before_directory_or_password_change(self):
        self.runner.status = "vpnfixture P 2026-09-24 0 99999 7 -1"
        with self.assertRaisesRegex(subject.FixtureAuthError, "locked-only"):
            self.prepare()
        self.assertEqual(1, len(self.runner.calls))
        self.assertFalse(self.directory.exists())

    def test_existing_password_requires_explicit_opt_in(self):
        self.runner.status = "vpnfixture P 2026-09-24 0 99999 7 -1"
        with self.assertRaisesRegex(subject.FixtureAuthError, "locked-only"):
            self.prepare()
        self.assertFalse(self.directory.exists())

    def test_preserved_password_baseline_is_restored_exactly_without_public_leak(self):
        runner = PasswordBaselineRunner()
        original = runner.shadow.copy()
        args = self.args | {"runner": runner, "preserve_existing_password": True}
        receipt = subject.prepare(**args)
        self.assertTrue(receipt["preservesExistingPassword"])
        self.assertNotIn("original-hash", json.dumps(receipt))
        self.assertNotIn("original-hash", (self.directory / "receipt.json").read_text())
        self.assertEqual(0o600, stat.S_IMODE((self.directory / "baseline.json").stat().st_mode))
        result = subject.restore(credential_dir=self.directory, correlation="fedora-2328", account_lookup=self.account,
                                 terminal_receipt={"final": True}, terminal_validator=lambda *_: True,
                                 runner=runner, **self.identity)
        self.assertEqual({"account": "vpnfixture", "correlation": "fedora-2328", "restored": True}, result)
        self.assertEqual(original, runner.shadow)
        commands = [call[0] for call in runner.calls]
        self.assertIn(["sudo", "-n", "chpasswd", "-e"], commands)
        self.assertIn(["sudo", "-n", "chage", "-d", "20355", "vpnfixture"], commands)
        self.assertFalse(self.directory.exists())
        self.assertTrue(all("original-hash" not in " ".join(command) for command in commands))

    def test_preserved_password_rejects_concurrent_change_and_keeps_private_evidence(self):
        runner = PasswordBaselineRunner()
        subject.prepare(**(self.args | {"runner": runner, "preserve_existing_password": True}))
        runner.shadow[1] = "$6$concurrent-hash"
        with self.assertRaisesRegex(subject.FixtureAuthError, "concurrently") as failure:
            subject.restore(credential_dir=self.directory, correlation="fedora-2328", account_lookup=self.account,
                            terminal_receipt={"final": True}, terminal_validator=lambda *_: True,
                            runner=runner, **self.identity)
        self.assertNotIn("concurrent-hash", str(failure.exception))
        self.assertTrue((self.directory / "baseline.json").exists())
        self.assertNotIn(["sudo", "-n", "chpasswd", "-e"], [call[0] for call in runner.calls])

    def test_preserved_password_command_failure_keeps_private_evidence(self):
        runner = PasswordBaselineRunner(fail="restore")
        subject.prepare(**(self.args | {"runner": runner, "preserve_existing_password": True}))
        with self.assertRaisesRegex(subject.FixtureAuthError, "restoration failed"):
            subject.restore(credential_dir=self.directory, correlation="fedora-2328", account_lookup=self.account,
                            terminal_receipt={"final": True}, terminal_validator=lambda *_: True,
                            runner=runner, **self.identity)
        self.assertTrue((self.directory / "baseline.json").exists())

    def test_preserved_password_unknown_live_state_keeps_private_evidence(self):
        runner = PasswordBaselineRunner()
        subject.prepare(**(self.args | {"runner": runner, "preserve_existing_password": True}))
        runner.fail = "shadow"
        with self.assertRaisesRegex(subject.FixtureAuthError, "unavailable") as failure:
            subject.restore(credential_dir=self.directory, correlation="fedora-2328", account_lookup=self.account,
                            terminal_receipt={"final": True}, terminal_validator=lambda *_: True,
                            runner=runner, **self.identity)
        self.assertNotIn("original-hash", str(failure.exception))
        self.assertTrue((self.directory / "baseline.json").exists())
        self.assertNotIn(["sudo", "-n", "chpasswd", "-e"], [call[0] for call in runner.calls])

    def test_preserved_password_partial_setup_keeps_original_private_baseline(self):
        runner = PasswordBaselineRunner(fail="post-shadow")
        with self.assertRaisesRegex(subject.FixtureAuthError, "unavailable") as failure:
            subject.prepare(**(self.args | {"runner": runner, "preserve_existing_password": True}))
        self.assertNotIn("original-hash", str(failure.exception))
        baseline = json.loads((self.directory / "baseline.json").read_text())
        self.assertEqual("$6$original-hash", baseline["original"][1])
        self.assertEqual([], baseline["post"])

    def test_private_credential_files_survive_short_writes(self):
        real_write = os.write

        def one_byte_at_a_time(fd, value):
            return real_write(fd, value[:1])

        with mock.patch.object(subject.os, "write", side_effect=one_byte_at_a_time):
            receipt = self.prepare()
        self.assertEqual(receipt, subject.status(credential_dir=self.directory, correlation="fedora-2328",
                                                 purpose=subject.PURPOSE, account_lookup=self.account,
                                                 **self.identity))
        self.assertEqual("unit-test-password", subject.read_credential_after_prompt(
            credential_dir=self.directory, correlation="fedora-2328", purpose=subject.PURPOSE,
            prompt_confirmed=True, account_lookup=self.account, **self.identity))

    def test_existing_private_file_and_directory_are_never_overwritten(self):
        self.directory.mkdir(mode=0o700)
        old = self.directory / "credential"; old.write_text("keep", encoding="utf-8"); old.chmod(0o600)
        with self.assertRaisesRegex(subject.FixtureAuthError, "already exists"):
            self.prepare()
        self.assertEqual("keep", old.read_text(encoding="utf-8"))
        self.assertEqual(1, len(self.runner.calls))

    def test_group_writable_parent_is_rejected_before_creating_private_content(self):
        parent = self.root / "shared"; parent.mkdir(mode=0o700); parent.chmod(0o770)
        self.args["credential_dir"] = parent / "auth"
        with self.assertRaisesRegex(subject.FixtureAuthError, "parent identity or mode"):
            self.prepare()
        self.assertFalse((parent / "auth").exists())

    def test_unknown_terminal_preserves_files_and_account_state(self):
        self.prepare()
        with self.assertRaisesRegex(subject.FixtureAuthError, "unknown"):
            subject.restore(credential_dir=self.directory, correlation="fedora-2328", account_lookup=self.account, **self.identity,
                            terminal_receipt={"correlation": "other", "final": True, "authoritative": True},
                            terminal_validator=lambda *_: False, runner=self.runner)
        self.assertTrue((self.directory / "credential").exists())
        self.assertFalse(any(call[0][:3] == ["sudo", "-n", "passwd"] for call in self.runner.calls))

    def test_exact_terminal_relocks_then_removes_private_files(self):
        self.prepare()
        result = subject.restore(credential_dir=self.directory, correlation="fedora-2328", account_lookup=self.account, **self.identity,
                                 terminal_receipt={"correlation": "fedora-2328", "final": True, "authoritative": True},
                                 terminal_validator=lambda receipt, correlation: receipt["correlation"] == correlation and receipt["final"] is True,
                                 runner=self.runner)
        self.assertEqual({"account": "vpnfixture", "correlation": "fedora-2328", "restored": True}, result)
        self.assertFalse(self.directory.exists())
        self.assertIn(["sudo", "-n", "passwd", "--lock", "--", "vpnfixture"], [call[0] for call in self.runner.calls])

    def test_read_requires_prompt_confirmation_and_never_exposes_it_in_status(self):
        self.prepare()
        with self.assertRaisesRegex(subject.FixtureAuthError, "prompt"):
            subject.read_credential_after_prompt(credential_dir=self.directory, correlation="fedora-2328", purpose=subject.PURPOSE, prompt_confirmed=False, account_lookup=self.account, **self.identity)
        self.assertEqual("unit-test-password", subject.read_credential_after_prompt(
            credential_dir=self.directory, correlation="fedora-2328", purpose=subject.PURPOSE, prompt_confirmed=True, account_lookup=self.account, **self.identity))

    @unittest.skipUnless(os.name == "posix", "POSIX symlink admission")
    def test_symlinked_credential_directory_is_rejected(self):
        target = self.root / "target"; target.mkdir(mode=0o700)
        self.directory.symlink_to(target)
        with self.assertRaisesRegex(subject.FixtureAuthError, "already exists"):
            self.prepare()

    def test_replaced_credential_symlink_is_rejected_without_following_it(self):
        self.prepare(); credential = self.directory / "credential"; credential.unlink()
        credential.symlink_to(self.root / "outside")
        with self.assertRaisesRegex(subject.FixtureAuthError, "file is unsafe"):
            subject.status(credential_dir=self.directory, correlation="fedora-2328", purpose=subject.PURPOSE,
                           account_lookup=self.account, **self.identity)

    def test_root_and_wrong_uid_are_rejected_before_reading_fixture_paths(self):
        with self.assertRaisesRegex(subject.FixtureAuthError, "non-root"):
            subject.status(credential_dir=self.directory, correlation="fedora-2328", purpose=subject.PURPOSE,
                           account_lookup=self.account, platform="linux", geteuid=lambda: 0)
        with self.assertRaisesRegex(subject.FixtureAuthError, "non-root"):
            subject.status(credential_dir=self.directory, correlation="fedora-2328", purpose=subject.PURPOSE,
                           account_lookup=self.account, platform="linux", geteuid=lambda: self.uid + 1)

    def test_import_does_not_require_posix_pwd_or_geteuid(self):
        # This is the routine Windows-import regression: Linux-only APIs are
        # reached only after the runtime platform gate.
        namespace = {"__name__": "linux_fixture_auth_windows_probe"}
        original = getattr(os, "geteuid", None)
        try:
            if original is not None: del os.geteuid
            runpy.run_path(str(Path(subject.__file__)), init_globals=namespace)
        finally:
            if original is not None: os.geteuid = original


if __name__ == "__main__":
    unittest.main()
