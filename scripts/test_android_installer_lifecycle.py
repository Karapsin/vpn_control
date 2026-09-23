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


def record(code, final, operation=None, data=None, ok=None, controller="controller"):
    response = {"code": code, "final": final, "ok": code in {"OK", "ACCEPTED"} if ok is None else ok,
                "controllerId": controller}
    if operation: response["operationId"] = operation
    if data is not None: response["data"] = data
    return {"argv": [], "exit": driver.EXIT[code], "response": response, "stderr": ""}


def argv(root, output, callback=None, handoff_ready=None, adb=None, expected_terminal=None, extra=()):
    values = ["driver", "--adb", str(adb or root / "adb"), "--serial", "serial", "--api", "35", "--avd", "avd",
        "--device-port", "45635", "--cli", str(root / "cli"), "--ca-certificate", str(root / "ca.pem"),
        "--leaf-certificate", str(root / "leaf.pem"), "--private-key", str(root / "leaf.key"),
        "--output", str(output), "--base-apk", str(root / "base.apk"), "--base-sha256", "base-hash",
        "--base-version", "2.1.13", "--base-code", "16660", "--target-apk", str(root / "target.apk"),
        "--target-sha256", "target-hash", "--target-version", "2.1.14", "--target-code", "16680"]
    if callback is not None: values.extend(["--continue-file", str(callback)])
    if handoff_ready is not None: values.extend(["--handoff-ready-file", str(handoff_ready)])
    if expected_terminal is not None: values.extend(["--expected-terminal", expected_terminal])
    values.extend(extra)
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
    class InstalledAdb(Adb):
        def shell(self, *words):
            self.calls.append(words)
            if words == ("dumpsys", "package", "com.kardinal.vpncontrol"):
                return "versionName=2.1.14 versionCode=16680"
            if words == ("pm", "path", "com.kardinal.vpncontrol"):
                return "package:/data/app/com.kardinal.vpncontrol/base.apk"
            return self.windows

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
            self.assertEqual(120.0, observed["args"].reconciliation_timeout_seconds)
            self.assertEqual(1.0, observed["args"].reconciliation_poll_seconds)
            self.assertEqual("2.1.13", observed["args"].expected_version)
            self.assertEqual("16660", observed["args"].expected_code)
            self.assertEqual((root / "target.apk", "2.1.14", 16680), observed["launch"][:3])
            self.assertEqual([(root / "base.apk", "base-hash"), (root / "target.apk", "target-hash")],
                             [call.args for call in hashed.call_args_list])

    def test_main_forwards_handoff_ready_to_two_phase_action(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); output = root / "output"; callback = output / "continue"; ready = output / "handoff-ready"
            adb = root / "adb"; adb.write_text("#!/bin/sh\n"); adb.chmod(0o700)
            observed = {}
            def launched(*_):
                for path in (ready, callback):
                    path.write_text("continue\n")
                    if os.name != "nt": path.chmod(0o600)
                return object()
            def lifecycle(args, action, **_):
                observed["args"] = args
                return action(args, self.InstalledAdb(), {})
            handoff = {"installerStarted": True, "installed": None, "availableVersion": "2.1.14",
                       "installReceiptId": "receipt", "installSessionId": 17, "installPhase": "handed_off"}
            installed = {"phase": "idle", "availableVersion": None,
                         "installReceipt": {"installReceiptId": "receipt", "installSessionId": 17,
                                            "installPhase": "installed", "installed": True}}
            replies = [record("OK", True), record("OK", True), record("INTERACTION_REQUIRED", True),
                       record("ACCEPTED", False, "operation"), record("OK", True, "operation", handoff),
                       record("OK", True, data=installed)]
            windows_guards = (patch.object(driver, "prepare_continue_file"), patch.object(driver, "wait_for_continue_file")) if os.name == "nt" else (nullcontext(), nullcontext())
            with windows_guards[0], windows_guards[1], portable_checkpoint_privacy(output / "probe.json"), \
                 patch.object(sys, "argv", argv(root, output, callback, handoff_ready=ready, adb=adb, expected_terminal="installed")), \
                 patch.object(driver.tls, "public_cli_environment", return_value={}), \
                 patch.object(driver.tls, "require_artifact_hash"), \
                 patch.object(driver.fixture, "launch_supervised_fixture", side_effect=launched), \
                 patch.object(driver.fixture, "read_ready_file", return_value=12345), \
                 patch.object(driver.fixture, "make_manifest", return_value={}), \
                 patch.object(driver.fixture, "_stop_fixture"), \
                 patch.object(driver.tls, "run_fixture_lifecycle", side_effect=lifecycle), \
                 patch.object(driver, "invoke", side_effect=replies), \
                 patch.object(driver.tls, "require_installed_base_hash", return_value="target-hash"):
                driver.main()
            self.assertEqual(ready, observed["args"].handoff_ready_file)
            self.assertTrue((output / "handoff.json").is_file())

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

    def test_nonfinite_reconciliation_flags_reject_before_fixture_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); output = root / "output"; adb = root / "adb"
            adb.write_text("#!/bin/sh\n"); adb.chmod(0o700)
            with patch.object(sys, "argv", argv(root, output, adb=adb,
                extra=("--reconciliation-timeout-seconds", "nan"))), \
                 patch.object(driver.fixture, "launch_supervised_fixture") as launched:
                with self.assertRaisesRegex(SystemExit, "finite positive"):
                    driver.main()
            launched.assert_not_called()

    def test_installed_callback_requires_distinct_handoff_ready_callback_before_fixture_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); output = root / "output"; callback = output / "continue"; adb = root / "adb"
            adb.write_text("#!/bin/sh\n"); adb.chmod(0o700)
            with patch.object(sys, "argv", argv(root, output, callback, adb=adb, expected_terminal="installed")), \
                 patch.object(driver.fixture, "launch_supervised_fixture") as launched:
                with self.assertRaisesRegex(SystemExit, "handoff-ready"):
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

    def acceptance_args(self, directory, expected_terminal="installed"):
        return SimpleNamespace(
            cli=Path("cli"), serial="serial", probe_output=Path(directory) / "checkpoint",
            target_sha256="target-hash", target_version="2.1.14", target_code="16680",
            expected_terminal=expected_terminal,
        )

    @staticmethod
    def accepted_replies(terminal, operation="operation"):
        terminal_data = {"availableVersion": "2.1.14", "installReceiptId": "receipt", "installSessionId": 17,
                         "installPhase": "installed", "installed": True}
        if terminal == "CANCELLED": terminal_data["installPhase"] = "cancelled"; terminal_data["installed"] = False
        return [record("OK", True), record("OK", True), record("INTERACTION_REQUIRED", True),
                record("ACCEPTED", False, operation), record(terminal, True, operation, terminal_data),
                record(terminal, True, operation, terminal_data)]

    def test_installed_acceptance_requires_correlated_terminal_and_target_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.acceptance_args(temporary)
            args.continue_file = Path(temporary) / "continue"; args.fixture_parent = Path(temporary)
            with portable_checkpoint_privacy(args.probe_output), \
                 patch.object(driver, "invoke", side_effect=self.accepted_replies("OK")), \
                 patch.object(driver.tls, "require_installed_base_hash", return_value="target-hash") as hashed, \
                 patch.object(driver, "wait_for_continue_file"):
                result = driver.action(args, self.InstalledAdb(), {})
            self.assertEqual("terminal-confirmed", result["acceptance"])
            self.assertEqual("target-hash", result["installedBaseSha256"])
            hashed.assert_called_once()

    def test_installed_acceptance_rejects_cancelled_without_replaying_install(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.acceptance_args(temporary)
            args.continue_file = Path(temporary) / "continue"; args.fixture_parent = Path(temporary)
            calls = []
            def invoke(*values, **kwargs):
                calls.append(values)
                return self.accepted_replies("CANCELLED")[len(calls) - 1]
            with portable_checkpoint_privacy(args.probe_output), patch.object(driver, "invoke", side_effect=invoke), \
                 patch.object(driver, "wait_for_continue_file"):
                with self.assertRaisesRegex(RuntimeError, "confirmed installed"):
                    driver.action(args, self.InstalledAdb(), {})
            self.assertEqual(2, sum(values[2:] == ("updates", "install") for values in calls))

    def test_cancelled_acceptance_requires_exact_cancelled_terminal(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.acceptance_args(temporary, "cancelled")
            with portable_checkpoint_privacy(args.probe_output), \
                 patch.object(driver, "invoke", side_effect=self.accepted_replies("CANCELLED")), \
                 patch.object(driver.tls, "require_installed_base_hash") as hashed, patch("builtins.input"):
                result = driver.action(args, self.InstalledAdb(), {})
            self.assertEqual("terminal-confirmed", result["acceptance"])
            hashed.assert_not_called()

    def test_cancelled_acceptance_reconciles_later_receipt_after_historical_handoff(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.acceptance_args(temporary, "cancelled")
            args.reconciliation_timeout_seconds = 1
            args.reconciliation_poll_seconds = 0.01
            handoff = {"installerStarted": True, "installed": None,
                       "availableVersion": "2.1.14", "installReceiptId": "receipt",
                       "installSessionId": 17, "installPhase": "handed_off"}
            pending = {"phase": "installing", "availableVersion": "2.1.14",
                       "installReceipt": {"installReceiptId": "receipt", "installSessionId": 17,
                                          "installPhase": "handed_off", "installed": None}}
            cancelled = {"phase": "idle", "availableVersion": None,
                         "installReceipt": {"installReceiptId": "receipt", "installSessionId": 17,
                                            "installPhase": "cancelled", "installed": False}}
            replies = [record("OK", True), record("OK", True), record("INTERACTION_REQUIRED", True),
                       record("ACCEPTED", False, "operation"), record("OK", True, "operation", handoff),
                       record("OK", True, "operation", handoff), record("OK", True, data=pending),
                       record("OK", True, data=cancelled)]
            with portable_checkpoint_privacy(args.probe_output), \
                 patch.object(driver, "invoke", side_effect=replies), patch("builtins.input"), \
                 patch.object(driver.time, "sleep"):
                result = driver.action(args, self.InstalledAdb(), {})
            self.assertEqual("terminal-confirmed", result["acceptance"])
            self.assertEqual("handed_off", result["originalOperation"]["stage"])
            self.assertEqual("cancelled", result["reconciliation"]["terminal"]["response"]["data"]["installReceipt"]["installPhase"])

    def test_reconciliation_timeout_retains_handoff_identity_without_another_install_or_cancel(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.acceptance_args(temporary, "cancelled")
            args.reconciliation_timeout_seconds = 1
            args.reconciliation_poll_seconds = 0.01
            handoff = {"installerStarted": True, "installed": None,
                       "availableVersion": "2.1.14", "installReceiptId": "receipt",
                       "installSessionId": 17, "installPhase": "handed_off"}
            pending = {"phase": "installing", "availableVersion": "2.1.14",
                       "installReceipt": {"installReceiptId": "receipt", "installSessionId": 17,
                                          "installPhase": "handed_off", "installed": None}}
            replies = [record("OK", True), record("OK", True), record("INTERACTION_REQUIRED", True),
                       record("ACCEPTED", False, "operation"), record("OK", True, "operation", handoff),
                       record("OK", True, "operation", handoff), record("OK", True, data=pending)]
            receipt, calls = {}, []
            def invoke(*values, **kwargs):
                calls.append(values)
                return replies.pop(0)
            with portable_checkpoint_privacy(args.probe_output), patch.object(driver, "invoke", side_effect=invoke), \
                 patch("builtins.input"), patch.object(driver.time, "monotonic", side_effect=[0, 0, 2]):
                with self.assertRaisesRegex(RuntimeError, "outcome unknown"):
                    driver.action(args, self.InstalledAdb(), receipt)
            lifecycle = receipt["installerLifecycle"]
            self.assertEqual("handed_off", lifecycle["originalOperation"]["stage"])
            self.assertEqual("receipt", lifecycle["reconciliation"]["identity"]["receiptId"])
            self.assertEqual("OUTCOME_UNKNOWN", lifecycle["reconciliation"]["outcome"])
            self.assertEqual(2, sum(values[2:] == ("updates", "install") for values in calls))
            self.assertEqual(1, sum(values[2:] == ("updates", "status") for values in calls))

    def test_reconciliation_timeout_retains_partial_subprocess_output(self):
        args = SimpleNamespace(cli=Path("cli"), serial="serial", reconciliation_timeout_seconds=1,
                               reconciliation_poll_seconds=0.01)
        identity = {"operationId": "operation", "receiptId": "receipt", "sessionId": 17,
                    "version": "2.1.14", "targetSha256": "target-hash"}
        partial = {"argv": ["cli", "updates", "status"], "exit": None,
                   "stdout": "partial-json", "stderr": "partial-error", "timeoutSeconds": 1}
        with patch.object(driver, "invoke", side_effect=driver.InvocationFailure("timed out", partial)), \
             patch.object(driver.time, "monotonic", side_effect=[0, 0, 2]):
            result = driver.await_reconciled_terminal(args, identity, "cancelled")
        self.assertEqual("OUTCOME_UNKNOWN", result["outcome"])
        self.assertEqual([partial], result["rawErrors"])

    def test_historical_status_and_wait_must_retain_the_same_receipt_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.acceptance_args(temporary, "cancelled")
            handoff = {"installerStarted": True, "installed": None, "availableVersion": "2.1.14",
                       "installReceiptId": "receipt", "installSessionId": 17, "installPhase": "handed_off"}
            changed = handoff | {"installReceiptId": "other-receipt"}
            replies = [record("OK", True), record("OK", True), record("INTERACTION_REQUIRED", True),
                       record("ACCEPTED", False, "operation"), record("OK", True, "operation", handoff),
                       record("OK", True, "operation", changed)]
            with portable_checkpoint_privacy(args.probe_output), patch.object(driver, "invoke", side_effect=replies), \
                 patch("builtins.input"):
                with self.assertRaisesRegex(RuntimeError, "identity changed"):
                    driver.action(args, self.InstalledAdb(), {})

    def test_two_phase_capture_precedes_approval_and_reconciles_after_owner_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary); parent.chmod(0o700)
            args = self.acceptance_args(temporary, "installed")
            args.fixture_parent = parent
            args.handoff_ready_file = parent / "handoff-ready"
            args.continue_file = parent / "continue"
            args.reconciliation_timeout_seconds = 1
            args.reconciliation_poll_seconds = 0.01
            handoff = {"installerStarted": True, "installed": None, "availableVersion": "2.1.14",
                       "installReceiptId": "receipt", "installSessionId": 17, "installPhase": "handed_off"}
            installed = {"phase": "idle", "availableVersion": None,
                         "installReceipt": {"installReceiptId": "receipt", "installSessionId": 17,
                                            "installPhase": "installed", "installed": True}}
            replies = [record("OK", True), record("OK", True), record("INTERACTION_REQUIRED", True),
                       record("ACCEPTED", False, "operation"), record("OK", True, "operation", handoff),
                       record("OK", True, data=installed)]
            events, calls = [], []
            def wait(path, _): events.append(path.name)
            def invoke(*values, **kwargs):
                calls.append(values)
                if values[2:] == ("operations", "status", "operation"):
                    self.assertEqual(["handoff-ready"], events)
                if values[2:] == ("updates", "status"):
                    self.assertEqual(["handoff-ready", "continue"], events)
                return replies.pop(0)
            with portable_checkpoint_privacy(args.probe_output), patch.object(driver, "wait_for_continue_file", side_effect=wait), \
                 patch.object(driver, "invoke", side_effect=invoke), \
                 patch.object(driver.tls, "require_installed_base_hash", return_value="target-hash") as hashed:
                result = driver.action(args, self.InstalledAdb(), {})
            handoff_file = json.loads((parent / "handoff.json").read_text())
            self.assertEqual("receipt", handoff_file["identity"]["receiptId"])
            self.assertEqual("terminal-confirmed", result["acceptance"])
            self.assertEqual(1, sum(values[2:] == ("operations", "status", "operation") for values in calls))
            self.assertEqual(0, sum(values[2:] == ("operations", "wait", "operation") for values in calls))
            hashed.assert_called_once()

    def test_tty_installed_run_uses_two_prompts_and_captures_handoff_before_approval(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary); parent.chmod(0o700)
            args = self.acceptance_args(temporary, "installed")
            args.fixture_parent = parent; args.handoff_ready_file = None; args.continue_file = None
            handoff = {"installerStarted": True, "installed": None, "availableVersion": "2.1.14",
                       "installReceiptId": "receipt", "installSessionId": 17, "installPhase": "handed_off"}
            installed = {"phase": "idle", "availableVersion": None,
                         "installReceipt": {"installReceiptId": "receipt", "installSessionId": 17,
                                            "installPhase": "installed", "installed": True}}
            replies = [record("OK", True), record("OK", True), record("INTERACTION_REQUIRED", True),
                       record("ACCEPTED", False, "operation"), record("OK", True, "operation", handoff),
                       record("OK", True, data=installed)]
            with portable_checkpoint_privacy(args.probe_output), patch.object(driver, "invoke", side_effect=replies), \
                 patch("builtins.input", side_effect=[None, None]) as prompted, \
                 patch.object(driver.tls, "require_installed_base_hash", return_value="target-hash"):
                result = driver.action(args, self.InstalledAdb(), {})
            self.assertEqual(2, prompted.call_count)
            self.assertTrue((parent / "handoff.json").is_file())
            self.assertEqual("terminal-confirmed", result["acceptance"])

    def test_two_phase_wrong_replacement_receipt_times_out_without_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary); parent.chmod(0o700)
            args = self.acceptance_args(temporary, "cancelled")
            args.fixture_parent = parent; args.handoff_ready_file = parent / "handoff-ready"; args.continue_file = parent / "continue"
            args.reconciliation_timeout_seconds = 1; args.reconciliation_poll_seconds = 0.01
            handoff = {"installerStarted": True, "installed": None, "availableVersion": "2.1.14",
                       "installReceiptId": "receipt", "installSessionId": 17, "installPhase": "handed_off"}
            wrong = {"phase": "idle", "availableVersion": None,
                     "installReceipt": {"installReceiptId": "other", "installSessionId": 17,
                                        "installPhase": "cancelled", "installed": False}}
            replies = [record("OK", True), record("OK", True), record("INTERACTION_REQUIRED", True),
                       record("ACCEPTED", False, "operation"), record("OK", True, "operation", handoff),
                       record("OK", True, data=wrong)]
            calls = []
            def invoke(*values, **kwargs): calls.append(values); return replies.pop(0)
            with portable_checkpoint_privacy(args.probe_output), patch.object(driver, "wait_for_continue_file"), \
                 patch.object(driver, "invoke", side_effect=invoke), patch.object(driver.time, "monotonic", side_effect=[0, 0, 0, 0, 2]):
                with self.assertRaisesRegex(RuntimeError, "reconciliation outcome unknown"):
                    driver.action(args, self.InstalledAdb(), {})
            self.assertTrue((parent / "handoff.json").is_file())
            self.assertEqual(2, sum(values[2:] == ("updates", "install") for values in calls))

    def test_two_phase_foreign_controller_handoff_is_unknown_before_approval_without_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary); parent.chmod(0o700)
            args = self.acceptance_args(temporary, "installed")
            args.fixture_parent = parent; args.handoff_ready_file = parent / "handoff-ready"; args.continue_file = parent / "continue"
            args.reconciliation_timeout_seconds = 1; args.reconciliation_poll_seconds = 0.01
            handoff = {"installerStarted": True, "installed": None, "availableVersion": "2.1.14",
                       "installReceiptId": "receipt", "installSessionId": 17, "installPhase": "handed_off"}
            replies = [record("OK", True), record("OK", True), record("INTERACTION_REQUIRED", True),
                       record("ACCEPTED", False, "operation"), record("OK", True, "operation", handoff,
                       controller="foreign-controller")]
            calls = []
            def invoke(*values, **kwargs): calls.append(values); return replies.pop(0)
            with portable_checkpoint_privacy(args.probe_output), patch.object(driver, "wait_for_continue_file"), \
                 patch.object(driver, "invoke", side_effect=invoke), patch.object(driver.time, "monotonic", side_effect=[0, 0, 2]):
                with self.assertRaisesRegex(RuntimeError, "handoff outcome unknown"):
                    driver.action(args, self.InstalledAdb(), {})
            capture = (parent / "handoff.json")
            self.assertFalse(capture.exists())
            self.assertEqual(2, sum(values[2:] == ("updates", "install") for values in calls))
            self.assertEqual(0, sum(values[2:] == ("updates", "status") for values in calls))

    def test_reconciled_terminal_rejects_boolean_session_id(self):
        identity = {"operationId": "operation", "receiptId": "receipt", "sessionId": 1,
                    "version": "2.1.14", "targetSha256": "target-hash"}
        current = record("OK", True, data={"installReceipt": {"installReceiptId": "receipt",
            "installSessionId": True, "installPhase": "cancelled", "installed": False}})
        self.assertFalse(driver.reconciled_terminal(current, identity, "cancelled"))

    def test_handoff_identity_rejects_boolean_session_id(self):
        record_with_boolean = record("OK", True, "operation", {"installerStarted": True, "installed": None,
            "availableVersion": "2.1.14", "installReceiptId": "receipt", "installSessionId": True,
            "installPhase": "handed_off"})
        with self.assertRaisesRegex(RuntimeError, "historical installer handoff"):
            driver.handoff_identity(record_with_boolean, "operation", "2.1.14", "target-hash")

    def test_terminal_rejects_wrong_operation_and_unknown_outcome(self):
        installed = {"installPhase": "installed", "installed": True}
        with self.assertRaisesRegex(RuntimeError, "correlation"):
            driver.correlated_terminal(record("OK", True, "other", installed), "operation", "installed")
        with self.assertRaisesRegex(RuntimeError, "confirmed installed"):
            driver.correlated_terminal(record("OUTCOME_UNKNOWN", False, "operation", {}), "operation", "installed")
        with self.assertRaisesRegex(RuntimeError, "confirmed installed"):
            driver.correlated_terminal(record("OK", True, "operation", installed, ok=False), "operation", "installed")
        with self.assertRaisesRegex(RuntimeError, "confirmed cancelled"):
            driver.correlated_terminal(record("CANCELLED", True, "operation",
                {"installPhase": "cancelled", "installed": False}, ok=True), "operation", "cancelled")

    def test_target_verification_rejects_wrong_version_or_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.acceptance_args(temporary)
            class WrongVersion(self.InstalledAdb):
                def shell(self, *words):
                    if words == ("dumpsys", "package", "com.kardinal.vpncontrol"):
                        return "versionName=2.1.13 versionCode=16660"
                    return super().shell(*words)
            with self.assertRaisesRegex(RuntimeError, "version/code"):
                driver.verify_installed_target(args, WrongVersion())
            class SuffixCollision(self.InstalledAdb):
                def shell(self, *words):
                    if words == ("dumpsys", "package", "com.kardinal.vpncontrol"):
                        return "versionName=2.1.140 versionCode=166800"
                    return super().shell(*words)
            with self.assertRaisesRegex(RuntimeError, "version/code"):
                driver.verify_installed_target(args, SuffixCollision())
            with patch.object(driver.tls, "require_installed_base_hash", side_effect=RuntimeError("hash mismatch")):
                with self.assertRaisesRegex(RuntimeError, "hash mismatch"):
                    driver.verify_installed_target(args, self.InstalledAdb())

    def test_capture_mode_is_explicitly_nonacceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.acceptance_args(temporary, "capture")
            replies = self.accepted_replies("CANCELLED")
            with portable_checkpoint_privacy(args.probe_output), patch.object(driver, "invoke", side_effect=replies), \
                 patch("builtins.input"):
                result = driver.action(args, self.InstalledAdb(), {})
            self.assertEqual("capture-only-nonacceptance", result["acceptance"])

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
