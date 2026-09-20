import json
import os
import shutil
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import patch

import android_installer_lifecycle as driver


class Adb:
    def __init__(self): self.windows = "ordinary window"; self.calls = []
    def shell_id(self): return "uid=2000"
    def shell(self, *words): self.calls.append(words); return self.windows


def record(code, final, operation=None):
    response = {"code": code, "final": final}
    if operation: response["operationId"] = operation
    return {"argv": [], "exit": driver.EXIT[code], "response": response, "stderr": ""}


def argv(root, output, callback=None, adb=None):
    values = ["driver", "--adb", str(adb or root / "adb"), "--serial", "serial", "--api", "35", "--avd", "avd",
        "--device-port", "45635", "--cli", str(root / "cli"), "--ca-certificate", str(root / "ca.pem"),
        "--leaf-certificate", str(root / "leaf.pem"), "--private-key", str(root / "leaf.key"),
        "--output", str(output), "--base-apk", str(root / "base.apk"), "--base-sha256", "base-hash",
        "--base-version", "2.1.13", "--base-code", "16660", "--target-apk", str(root / "target.apk"),
        "--target-sha256", "target-hash", "--target-version", "2.1.14", "--target-code", "16680"]
    if callback is not None: values.extend(["--continue-file", str(callback)])
    return values


def portable_checkpoint_privacy(checkpoint):
    """Windows does not expose POSIX file modes; retain the actual write path."""
    if os.name == "nt":
        original_stat = Path.stat
        def checkpoint_stat(path, *args, **kwargs):
            info = original_stat(path, *args, **kwargs)
            if path == checkpoint:
                return os.stat_result((info.st_mode & ~0o077, *info[1:]))
            return info
        return patch.object(Path, "stat", new=checkpoint_stat)
    return nullcontext()


class InstallerLifecycleTest(unittest.TestCase):
    def test_windows_privacy_mock_preserves_real_missing_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = Path(temporary) / "checkpoint"
            with patch.object(os, "name", "nt"):
                context = portable_checkpoint_privacy(checkpoint)
            with context:
                with self.assertRaises(FileNotFoundError):
                    checkpoint.stat()
                checkpoint.write_text("actual checkpoint")
                self.assertTrue(checkpoint.is_file())
                self.assertEqual("actual checkpoint", checkpoint.read_text())

    @unittest.skipIf(os.name == "nt", "POSIX callback modes are checked by the POSIX fixture")
    def test_private_continue_file_accepts_only_literal_continue(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary); parent.chmod(0o700)
            callback = parent / "continue"; callback.write_text("continue\n"); callback.chmod(0o600)
            driver.wait_for_continue_file(callback, parent)

    @unittest.skipIf(os.name == "nt", "POSIX callback modes are checked by the POSIX fixture")
    def test_private_continue_file_rejects_wrong_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary); parent.chmod(0o700)
            callback = parent / "continue"; callback.write_text("continue\n"); callback.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "private"):
                driver.wait_for_continue_file(callback, parent)

    @unittest.skipIf(os.name == "nt", "POSIX callback-parent modes are checked by the POSIX fixture")
    def test_preexisting_continue_file_rejects_before_fixture_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); output, callback = root / "output", root / "output" / "continue"
            adb = root / "adb"; adb.write_text("#!/bin/sh\n"); adb.chmod(0o700)
            original_mkdir = Path.mkdir
            def mkdir_with_callback(path, *args, **kwargs):
                result = original_mkdir(path, *args, **kwargs)
                if path == output: callback.write_text("continue\n")
                return result
            with patch.object(Path, "mkdir", new=mkdir_with_callback), \
                 patch.object(driver.fixture, "launch_supervised_fixture") as launched, \
                 patch.object(sys, "argv", argv(root, output, callback)):
                with self.assertRaisesRegex(RuntimeError, "new direct private file"):
                    driver.main()
            launched.assert_not_called()

    def test_main_forwards_file_callback_and_fixture_identity_without_stdin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); output, callback = root / "output", root / "output" / "continue"
            adb = root / "adb"; adb.write_text("#!/bin/sh\n"); adb.chmod(0o700)
            observed = {}
            def launched(*parameters):
                observed["launch"] = parameters
                callback.write_text("continue\n")
                if os.name != "nt": callback.chmod(0o600)
                return object()
            def lifecycle(args, action, **kwargs):
                observed["args"] = args; observed["lifecycle"] = kwargs
                return action(args, Adb(), {})
            replies = [record("OK", True), record("OK", True), record("INTERACTION_REQUIRED", True),
                       record("ACCEPTED", False, "operation"), record("OK", False, "operation"),
                       record("CANCELLED", True, "operation")]
            windows_callback_guards = (patch.object(driver, "prepare_continue_file"),
                                       patch.object(driver, "wait_for_continue_file")) if os.name == "nt" else (nullcontext(), nullcontext())
            with windows_callback_guards[0], windows_callback_guards[1], portable_checkpoint_privacy(output / "probe.json"), \
                 patch.object(sys, "argv", argv(root, output, callback)), \
                 patch.object(driver.tls, "public_cli_environment", return_value={"PATH": "safe"}), \
                 patch.object(driver.tls, "require_artifact_hash") as hashed, \
                 patch.object(driver.fixture, "launch_supervised_fixture", side_effect=launched), \
                 patch.object(driver.fixture, "read_ready_file", return_value=12345), \
                 patch.object(driver.fixture, "make_manifest", return_value={}), \
                 patch.object(driver.fixture, "_stop_fixture"), \
                 patch.object(driver.tls, "run_fixture_lifecycle", side_effect=lifecycle), \
                 patch.object(driver, "invoke", side_effect=replies), \
                 patch("builtins.input") as entered:
                driver.main()
            entered.assert_not_called()
            self.assertEqual("operation", json.loads((output / "probe.json").read_text())["callbackReceipt"]["installerLifecycle"]["operationId"])
            self.assertEqual(callback, observed["args"].continue_file)
            self.assertEqual("target-hash", observed["args"].target_sha256)
            self.assertEqual("2.1.13", observed["args"].expected_version)
            self.assertEqual("16660", observed["args"].expected_code)
            self.assertEqual((root / "target.apk", "2.1.14", 16680), observed["launch"][:3])
            self.assertEqual([(root / "base.apk", "base-hash"), (root / "target.apk", "target-hash")],
                             [call.args for call in hashed.call_args_list])

    def test_bad_base_hash_rejects_before_fixture_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); output = root / "output"; adb = root / "adb"
            adb.write_text("#!/bin/sh\n"); adb.chmod(0o700)
            (root / "base.apk").write_bytes(b"different bytes")
            with patch.object(sys, "argv", argv(root, output)), \
                 patch.object(driver.tls, "public_cli_environment", return_value={}), \
                 patch.object(driver.tls, "require_interactive_stdin"), \
                 patch.object(driver.fixture, "launch_supervised_fixture") as launched:
                with self.assertRaisesRegex(RuntimeError, "hash does not match"):
                    driver.main()
            launched.assert_not_called()

    def test_driver_pins_packaged_cli_to_absolute_adb_before_fixture_launch(self):
        self.assert_driver_pins_adb("adb.exe" if os.name == "nt" else "adb")

    def test_driver_pins_adb_with_windows_executable_discovery(self):
        original_which = shutil.which
        def windows_lookup(*args, **kwargs):
            with patch.object(sys, "platform", "win32"), patch.dict(os.environ, {"PATHEXT": ".exe"}), \
                 patch.object(shutil, "_winapi", SimpleNamespace(NeedCurrentDirectoryForExePath=lambda _: False), create=True):
                return original_which(*args, **kwargs)
        with patch.object(driver.tls.shutil, "which", side_effect=windows_lookup):
            self.assert_driver_pins_adb("adb.exe")

    def assert_driver_pins_adb(self, executable_name):
        class Tty:
            def isatty(self): return True
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); output = root / "output"; adb = root / executable_name; adb.write_text("#!/bin/sh\n"); adb.chmod(0o700)
            observed = []
            original = driver.tls.public_cli_environment
            def child_environment(selected, cli):
                value = original(selected, cli, {"PATH": "/missing"}); observed.append(value); return value
            with patch.object(driver.tls, "public_cli_environment", side_effect=child_environment), \
                 patch.object(driver.tls, "require_artifact_hash"), \
                 patch.object(driver.fixture, "launch_supervised_fixture", side_effect=RuntimeError("LAUNCHED")), \
                 patch.object(sys, "argv", argv(root, output, adb=adb)), patch.object(sys, "stdin", Tty()):
                with self.assertRaisesRegex(RuntimeError, "LAUNCHED"):
                    driver.main()
            self.assertEqual(str(adb.resolve().parent) + os.pathsep + "/missing", observed[0]["PATH"])

    def test_checkpoint_precedes_interactive_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = SimpleNamespace(cli=Path("cli"), serial="serial", probe_output=Path(temporary) / "checkpoint", target_sha256="target")
            replies = [record("OK", True), record("OK", True), record("INTERACTION_REQUIRED", True),
                       record("ACCEPTED", False, "operation"), record("OK", False, "operation"),
                       record("CANCELLED", True, "operation")]
            observed = []
            calls = []
            def invoke(*call_args, **call_kwargs):
                calls.append((call_args, call_kwargs))
                return replies.pop(0)
            with portable_checkpoint_privacy(args.probe_output), patch.object(driver, "invoke", side_effect=invoke), \
                 patch("builtins.input", side_effect=lambda: observed.append(args.probe_output.exists())):
                driver.action(args, Adb(), {})
            self.assertEqual([True], observed)
            self.assertTrue(args.probe_output.exists())
            self.assertEqual(2, sum(call[0][2:] == ("updates", "install") for call in calls))
            self.assertTrue(calls[3][1]["interactive"] and calls[3][1]["asynchronous"])
            self.assertEqual(("operations", "status", "operation"), calls[4][0][2:])

    def test_async_ok_is_not_accepted_and_input_is_not_reached(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = SimpleNamespace(cli=Path("cli"), serial="serial", probe_output=Path(temporary) / "checkpoint", target_sha256="target")
            replies = [record("OK", True), record("OK", True), record("INTERACTION_REQUIRED", True), record("OK", True)]
            with patch.object(driver, "invoke", side_effect=replies), patch("builtins.input") as entered:
                with self.assertRaisesRegex(RuntimeError, "not accepted"):
                    driver.action(args, Adb(), {})
            entered.assert_not_called()

    def test_noninteractive_snapshot_only_compares_dialog_surfaces(self):
        class ChurnAdb(Adb):
            def shell(self, *words):
                self.calls.append(words)
                if words == ("dumpsys", "window", "windows"):
                    self.windows = "unrelated timestamp" if self.windows == "ordinary window" else "other timestamp"
                return self.windows
        with tempfile.TemporaryDirectory() as temporary:
            args = SimpleNamespace(cli=Path("cli"), serial="serial", probe_output=Path(temporary) / "checkpoint", target_sha256="target")
            replies = [record("OK", True), record("OK", True), record("INTERACTION_REQUIRED", True), record("OK", True)]
            with patch.object(driver, "invoke", side_effect=replies), patch("builtins.input"):
                with self.assertRaisesRegex(RuntimeError, "not accepted"):
                    driver.action(args, ChurnAdb(), {})


if __name__ == "__main__":
    unittest.main()
