#!/usr/bin/env python3
"""Exercise fixture setup across a simulated sudo boundary and real temp paths."""
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import linux_public_install_fixture as subject


class TargetBoundary:
    """Model the three native failure boundaries without needing root or sudo."""
    uid, gid = 1234, 1234

    def __init__(self):
        self.calls = []
        self.foreign = set()

    def lstat(self, path):
        info = os.lstat(path)
        uid = 0 if path in self.foreign else self.uid
        return SimpleNamespace(st_mode=info.st_mode, st_uid=uid, st_gid=uid)

    def run(self, command, **kwargs):
        self.calls.append(command)
        if "-u" not in command or command[command.index("-u") + 1] != "fixture":
            raise PermissionError("metadata/private setup requires target actor")
        start = command.index("env") + 2
        action = command[start:]
        if action[0] == "mkdir":
            destination = Path(action[-1])
            if any(parent in self.foreign for parent in destination.parents):
                raise PermissionError("root-owned ancestor prevents target mkdir")
            destination.mkdir(parents=True, exist_ok=True)
        elif action[0] == "chmod":
            os.chmod(action[-1], int(action[1], 8))
        elif Path(action[0]).name == "keytool":
            flag = "--preserve-env=" + subject.PUBLIC_STORE_ENV
            effective = kwargs["env"].get(subject.PUBLIC_STORE_ENV) if flag in command else None
            if effective != "public-ca-only":
                raise RuntimeError("sudo discarded public truststore environment")
        elif action[0] == "stat":
            return subprocess.CompletedProcess(command, 0, "1234:1234:600\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")


class FixtureProvisioningTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name) / "home"
        self.home.mkdir(mode=0o700)
        self.boundary = TargetBoundary()

    def prepare(self, root=None):
        return subject.prepare_target_paths("fixture", self.home,
            root or self.home / ".local" / "share" / "fixture",
            uid=1234, gid=1234, runner=self.boundary.run,
            stat_reader=self.boundary.lstat)

    def test_target_creates_state_and_fixture_without_root_owned_intermediates(self):
        paths = self.prepare()
        self.assertTrue((self.home / ".local" / "state").is_dir())
        self.assertTrue(paths[-1].is_dir())
        self.assertTrue(all("-u" in call for call in self.boundary.calls))

    def test_foreign_local_is_rejected_without_mutation(self):
        local = self.home / ".local"
        local.mkdir(mode=0o755)
        before = local.stat()
        self.boundary.foreign.add(local)
        with self.assertRaisesRegex(subject.FixtureSetupError, "not target-owned"):
            self.prepare()
        self.assertEqual([], self.boundary.calls)
        self.assertEqual(before.st_mode, local.stat().st_mode)
        self.assertFalse((local / "state").exists())

    def test_keytool_receives_public_store_environment_across_sudo(self):
        with mock.patch.dict(os.environ, {subject.PUBLIC_STORE_ENV: "public-ca-only"}):
            subject.run_keytool_as_target("fixture", self.home,
                ["keytool", "-list", "-storepass:env", subject.PUBLIC_STORE_ENV],
                runner=self.boundary.run)
        self.assertNotIn("public-ca-only", self.boundary.calls[0])

    def test_metadata_is_read_as_target_and_wrong_metadata_is_rejected(self):
        args = dict(expected_uid=1234, expected_gid=1234, expected_mode=0o600,
                    runner=self.boundary.run)
        self.assertEqual("1234:1234:600", subject.read_target_metadata(
            "fixture", self.home, self.home / "private", **args))
        args["expected_uid"] = 4321
        with self.assertRaisesRegex(subject.FixtureSetupError, "metadata differs"):
            subject.read_target_metadata("fixture", self.home, self.home / "private", **args)

    def test_lexical_escape_rejected_before_commands(self):
        with self.assertRaisesRegex(subject.FixtureSetupError, "lexical"):
            self.prepare(self.home / ".." / "outside")
        self.assertEqual([], self.boundary.calls)

    def test_directory_appearing_at_mkdir_keeps_its_mode(self):
        local = self.home / ".local"
        original = self.boundary.run
        def race(command, **kwargs):
            if "mkdir" in command and command[-1] == str(local) and not local.exists():
                local.mkdir(mode=0o750)
            return original(command, **kwargs)
        self.boundary.run = race
        self.prepare()
        if os.name == "posix":
            self.assertEqual(0o750, stat.S_IMODE(local.stat().st_mode))
        self.assertFalse(any("chmod" in call for call in self.boundary.calls))

    def test_literal_keytool_password_is_rejected_before_execution(self):
        with mock.patch.dict(os.environ, {subject.PUBLIC_STORE_ENV: "public-ca-only"}):
            with self.assertRaisesRegex(subject.FixtureSetupError, "public-store"):
                subject.run_keytool_as_target("fixture", self.home,
                    ["keytool", "-list", "-storepass", "not-a-real-secret"],
                    runner=self.boundary.run)
        self.assertEqual([], self.boundary.calls)

    def test_unrelated_host_environment_does_not_cross_privilege_boundary(self):
        with mock.patch.dict(os.environ, {"UNRELATED_TEST_SECRET": "sentinel-only"}, clear=True):
            _, environment = subject.target_command("fixture", self.home, ["keytool"],
                {subject.PUBLIC_STORE_ENV: "public-ca-only"})
        self.assertNotIn("UNRELATED_TEST_SECRET", environment)
        self.assertEqual({"PATH", subject.PUBLIC_STORE_ENV}, set(environment))
        self.assertEqual("public-ca-only", environment[subject.PUBLIC_STORE_ENV])

    def test_cli_keytool_separator_and_account_home_validation(self):
        account = SimpleNamespace(pw_uid=1234, pw_gid=1234, pw_dir=str(self.home))
        fake_pwd = SimpleNamespace(getpwnam=lambda user: account)
        arguments = ["fixture", "keytool", "--target-user", "fixture",
                     "--target-home", str(self.home), "--", "keytool", "-list"]
        with mock.patch.dict("sys.modules", {"pwd": fake_pwd}), \
             mock.patch.object(subject.sys, "platform", "linux"), \
             mock.patch.object(subject.sys, "argv", arguments), \
             mock.patch.object(subject, "run_keytool_as_target") as keytool:
            subject.main()
            keytool.assert_called_once_with("fixture", self.home, ["keytool", "-list"])
            account.pw_dir = str(self.home.parent)
            with self.assertRaisesRegex(subject.FixtureSetupError, "account home"):
                subject.main()
            self.assertEqual(1, keytool.call_count)

    @unittest.skipUnless(os.name == "posix", "POSIX symlink admission")
    def test_symlink_ancestor_is_rejected(self):
        (self.home / ".local").symlink_to(Path(self.temp.name))
        with self.assertRaisesRegex(subject.FixtureSetupError, "symlink"):
            self.prepare()
        self.assertEqual([], self.boundary.calls)

    @unittest.skipUnless(os.name == "posix", "POSIX permission preservation")
    def test_existing_modes_are_preserved(self):
        local = self.home / ".local"
        local.mkdir(mode=0o750)
        self.prepare()
        self.assertEqual(0o750, stat.S_IMODE(local.stat().st_mode))
        self.assertFalse(any(call[-1] == str(local) and "chmod" in call
                             for call in self.boundary.calls))


if __name__ == "__main__":
    unittest.main()
