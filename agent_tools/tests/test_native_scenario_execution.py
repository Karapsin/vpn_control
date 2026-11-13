"""Durability checks using a harmless local fixed-scenario driver.

The driver starts ``native_fixture_run.sh`` in a new session.  It is deliberately
not an SSH substitute; it proves the core's crash/disconnect semantics against
a real child process and durable receipt files without touching a VM.
"""
from __future__ import annotations

import importlib.util
import builtins
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import threading
from unittest import mock
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "agent_tools"
RUNNER = ROOT / "scripts" / "native_fixture_run.sh"


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, SOURCE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


execution = load("native_scenario_execution")


class LocalFixtureDriver:
    """Fixed harmless core fixture; its PID-derived generation is synthetic, not native proof."""
    def __init__(self, root: Path, *, lose_submit_response: bool = False):
        self.root = root
        self.lose_submit_response = lose_submit_response
        self.submit_calls = 0
        self.processes = []

    def _directory(self, plan):
        return self.root / plan.correlation_id

    def submit(self, plan):
        self.submit_calls += 1
        directory = self._directory(plan)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        starts = directory / "starts"
        child = directory / "child.sh"
        child.write_text("#!/bin/sh\nprintf 'started\\n' >> \"$1\"\nsleep 0.15\nprintf 'done\\n' > \"$2\"\n", encoding="utf-8")
        child.chmod(0o700)
        self.processes.append(subprocess.Popen(
            ["/bin/sh", str(RUNNER), "--pid-file", str(directory / "child.pid"), "--exit-file",
             str(directory / "child.exit"), "--", "/bin/sh", str(child), str(starts), str(directory / "done")],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        ))
        identity = self._identity(plan, wait=True)
        if self.lose_submit_response:
            raise TimeoutError("simulated observer disconnect after remote acceptance")
        return identity

    def discover(self, plan):
        return self._identity(plan, wait=False)

    def _identity(self, plan, *, wait):
        path = self._directory(plan) / "child.pid"
        for _ in range(100 if wait else 1):
            if path.exists():
                pid = int(path.read_text(encoding="utf-8").strip())
                # This test driver records a stable synthetic generation token.
                # Production SSH adapters must use /proc start ticks instead.
                return execution.JobIdentity("local-" + plan.correlation_id, pid, pid + 10_000, str(self._directory(plan) / "receipt.json"))
            time.sleep(0.01)
        return None

    def observe(self, plan, identity):
        directory = self._directory(plan)
        marker = directory / "child.exit"
        evidence = (str(directory / "done"),)
        if not marker.exists():
            return execution.DriverObservation(execution.ObservationStatus.RUNNING, "live_pid", identity, evidence_paths=evidence)
        exit_code = int(marker.read_text(encoding="utf-8").strip())
        receipt = {**plan.as_dict(), "jobId": identity.job_id, "pid": identity.pid,
                   "startTicks": identity.start_ticks, "exitCode": exit_code}
        (directory / "receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
        return execution.DriverObservation(execution.ObservationStatus.TERMINAL, "receipt", identity, receipt, evidence)

    def close(self):
        for process in self.processes:
            process.wait(timeout=5)


class NativeScenarioExecutionTest(unittest.TestCase):
    def request(self, correlation="run-17"):
        return {"scenarioId": "linux-public-update-preflight", "host": "owned-guest", "environment": "test",
                "bundleHash": "a" * 64, "artifactIds": {"fixture": "sha256-" + "b" * 64}, "correlationId": correlation}

    def wait_terminal(self, executor, correlation):
        for _ in range(100):
            result = executor.status(correlation)
            if result["state"] == "terminal":
                return result
            time.sleep(0.02)
        self.fail("fixture did not become terminal")

    @unittest.skipIf(os.name != "posix", "local fixture runner requires POSIX shell and private journal")
    def test_submit_response_loss_survives_observer_disconnect_without_reexecution(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            first_driver = LocalFixtureDriver(root / "fixture", lose_submit_response=True)
            self.addCleanup(first_driver.close)
            first = execution.ScenarioExecutor(root / "journal", first_driver)
            started = first.start(self.request())
            self.assertEqual(("submitting", "submit_response_unavailable"), (started["state"], started["reason"]))
            # A fresh observer models an MCP connection ending after submit.
            resumed_driver = LocalFixtureDriver(root / "fixture")
            self.addCleanup(resumed_driver.close)
            resumed = execution.ScenarioExecutor(root / "journal", resumed_driver)
            terminal = self.wait_terminal(resumed, "run-17")
            self.assertEqual(0, terminal["exitCode"])
            self.assertEqual(0, resumed_driver.submit_calls)
            self.assertEqual(["started"], (root / "fixture" / "run-17" / "starts").read_text().splitlines())
            collected = resumed.collect("run-17")
            self.assertEqual("terminal", collected["state"])
            self.assertEqual([str(root / "fixture" / "run-17" / "done")], collected["evidencePaths"])

    @unittest.skipIf(os.name != "posix", "private journal requires POSIX ownership admission")
    def test_repeated_start_returns_same_operation_without_second_effect(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); driver = LocalFixtureDriver(root / "fixture")
            self.addCleanup(driver.close)
            executor = execution.ScenarioExecutor(root / "journal", driver)
            executor.start(self.request())
            duplicate = executor.start(self.request())
            self.assertTrue(duplicate["duplicate"])
            self.assertEqual(1, driver.submit_calls)
            self.wait_terminal(executor, "run-17")
            self.assertEqual(["started"], (root / "fixture" / "run-17" / "starts").read_text().splitlines())

    @unittest.skipIf(os.name != "posix", "private journal requires POSIX ownership admission")
    def test_wrong_artifact_receipt_cannot_become_success(self):
        class BadReceiptDriver(LocalFixtureDriver):
            def observe(self, plan, identity):
                receipt = {**plan.as_dict(), "artifactIds": {"fixture": "sha256-" + "c" * 64}, "jobId": identity.job_id,
                           "pid": identity.pid, "startTicks": identity.start_ticks, "exitCode": 0}
                return execution.DriverObservation(execution.ObservationStatus.TERMINAL, "receipt", identity, receipt)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); driver = BadReceiptDriver(root / "fixture")
            self.addCleanup(driver.close)
            executor = execution.ScenarioExecutor(root / "journal", driver)
            executor.start(self.request())
            result = executor.status("run-17")
            self.assertEqual("unknown", result["state"])
            self.assertEqual("receipt", result["reason"])

    @unittest.skipIf(os.name != "posix", "private journal requires POSIX ownership admission")
    def test_correlation_cannot_be_rebound_to_another_plan(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); driver = LocalFixtureDriver(root / "fixture")
            self.addCleanup(driver.close)
            executor = execution.ScenarioExecutor(root / "journal", driver)
            executor.start(self.request())
            changed = self.request(); changed["bundleHash"] = "d" * 64
            with self.assertRaisesRegex(execution.ScenarioExecutionError, "different immutable"):
                executor.start(changed)

    @unittest.skipIf(os.name != "posix", "private journal requires POSIX ownership admission")
    def test_concurrent_running_observation_cannot_erase_terminal_receipt(self):
        class RacingDriver(LocalFixtureDriver):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.barrier = threading.Barrier(2)
                self.calls = 0
                self.calls_lock = threading.Lock()

            def observe(self, plan, identity):
                with self.calls_lock:
                    self.calls += 1
                    number = self.calls
                self.barrier.wait(timeout=2)
                if number == 1:
                    receipt = {**plan.as_dict(), "jobId": identity.job_id, "pid": identity.pid,
                               "startTicks": identity.start_ticks, "exitCode": 0}
                    return execution.DriverObservation(execution.ObservationStatus.TERMINAL, "receipt", identity, receipt)
                return execution.DriverObservation(execution.ObservationStatus.RUNNING, "live_pid", identity)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); driver = RacingDriver(root / "fixture")
            self.addCleanup(driver.close)
            executor = execution.ScenarioExecutor(root / "journal", driver)
            executor.start(self.request())
            threads = [threading.Thread(target=executor.status, args=("run-17",)) for _ in range(2)]
            for thread in threads: thread.start()
            for thread in threads: thread.join(timeout=3)
            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual("terminal", executor.collect("run-17")["state"])

    @unittest.skipIf(os.name != "posix", "private journal requires POSIX ownership admission")
    def test_same_job_id_with_different_pid_generation_cannot_terminal(self):
        class ReusedJobDriver(LocalFixtureDriver):
            def observe(self, plan, identity):
                changed = execution.JobIdentity(identity.job_id, identity.pid + 1, identity.start_ticks + 1, identity.receipt_path)
                receipt = {**plan.as_dict(), "jobId": changed.job_id, "pid": changed.pid,
                           "startTicks": changed.start_ticks, "exitCode": 0}
                return execution.DriverObservation(execution.ObservationStatus.TERMINAL, "receipt", changed, receipt)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); driver = ReusedJobDriver(root / "fixture")
            self.addCleanup(driver.close)
            executor = execution.ScenarioExecutor(root / "journal", driver)
            executor.start(self.request())
            result = executor.status("run-17")
            self.assertEqual(("unknown", "job_identity_mismatch"), (result["state"], result["reason"]))

    @unittest.skipIf(os.name != "posix", "private journal requires POSIX ownership admission")
    def test_stale_pre_submit_status_cannot_erase_submitted_identity(self):
        class DelayedSubmitDriver:
            def __init__(self):
                self.submit_entered = threading.Event()
                self.release_submit = threading.Event()
                self.discover_entered = threading.Event()
                self.release_discover = threading.Event()

            def submit(self, plan):
                self.submit_entered.set()
                self.release_submit.wait(timeout=2)
                return execution.JobIdentity("job-17", 17, 1_017, "/tmp/receipt")

            def discover(self, plan):
                self.discover_entered.set()
                self.release_discover.wait(timeout=2)
                return None

            def observe(self, plan, identity):
                raise AssertionError("status must not observe without a discovered identity")

        with tempfile.TemporaryDirectory() as raw:
            driver = DelayedSubmitDriver()
            executor = execution.ScenarioExecutor(Path(raw) / "journal", driver)
            start_result = []
            start_thread = threading.Thread(target=lambda: start_result.append(executor.start(self.request())))
            start_thread.start(); self.assertTrue(driver.submit_entered.wait(timeout=2))
            status_result = []
            status_thread = threading.Thread(target=lambda: status_result.append(executor.status("run-17")))
            status_thread.start(); self.assertTrue(driver.discover_entered.wait(timeout=2))
            driver.release_submit.set(); start_thread.join(timeout=2)
            driver.release_discover.set(); status_thread.join(timeout=2)
            self.assertFalse(start_thread.is_alive()); self.assertFalse(status_thread.is_alive())
            self.assertEqual("submitted", executor.collect("run-17")["state"])
            self.assertEqual(17, executor.collect("run-17")["jobIdentity"]["pid"])

    @unittest.skipIf(os.name != "posix", "private journal requires POSIX ownership admission")
    def test_corrupt_terminal_and_rebound_filename_are_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); journal = root / "journal"; journal.mkdir(mode=0o700)
            plan = self.request("actual")
            corrupt = {"journalVersion": 1, "plan": plan, "state": "terminal", "identity": None,
                       "lastReason": "correlated_receipt", "evidencePaths": [], "exitCode": 0}
            target = journal / "claimed.json"
            target.write_text(json.dumps(corrupt), encoding="utf-8")
            target.chmod(0o600)
            executor = execution.ScenarioExecutor(journal, LocalFixtureDriver(root / "fixture"))
            with self.assertRaisesRegex(execution.ScenarioExecutionError, "correlation"):
                executor.status("claimed")
            target.unlink()
            corrupt["plan"]["correlationId"] = "claimed"
            target.write_text(json.dumps(corrupt), encoding="utf-8")
            target.chmod(0o600)
            with self.assertRaisesRegex(execution.ScenarioExecutionError, "terminal journal"):
                executor.status("claimed")

    @unittest.skipIf(os.name != "posix", "private journal and symlink test require POSIX")
    def test_symlink_journal_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); journal = root / "journal"; journal.mkdir(mode=0o700)
            other = root / "other.json"; other.write_text("{}", encoding="utf-8"); other.chmod(0o600)
            os.symlink(other, journal / "run-17.json")
            executor = execution.ScenarioExecutor(journal, LocalFixtureDriver(root / "fixture"))
            with self.assertRaisesRegex(execution.ScenarioExecutionError, "unsafe"):
                executor.status("run-17")

    def windows_request(self):
        return {"scenarioId": "windows-ordinary-qualification", "host": "owned-host", "environment": "33333333-4444-4555-8666-777777777777",
                "bundleHash": "a" * 64, "artifactIds": {"bundleManifest": "sha256-" + "a" * 64}, "correlationId": "11111111-1111-4111-8111-111111111111"}

    class WindowsDriver:
        """The job's owner on the host: identity from its birth, a known exit only from the job."""
        def __init__(self):
            self.submits = 0
            self.exit_code = None

        def submit(self, plan):
            self.submits += 1
            return execution.JobIdentity("windows-" + plan.correlation_id, 42, 4242, "/owned/" + plan.correlation_id + "/scenario-receipt.json")

        def discover(self, plan):
            raise AssertionError("the original identity is already journaled")

        def observe(self, plan, identity):
            if self.exit_code is None:
                return execution.DriverObservation(execution.ObservationStatus.RUNNING, "original_owner_running", identity)
            receipt = {**plan.as_dict(), "jobId": identity.job_id, "pid": identity.pid, "startTicks": identity.start_ticks, "exitCode": self.exit_code}
            return execution.DriverObservation(execution.ObservationStatus.TERMINAL, "remote_receipt", identity, receipt)

    @unittest.skipIf(os.name != "posix", "private journal requires POSIX ownership admission")
    def test_windows_repeated_start_returns_the_original_and_submits_once(self):
        with tempfile.TemporaryDirectory() as raw:
            driver = self.WindowsDriver()
            executor = execution.ScenarioExecutor(Path(raw) / "journal", driver)
            first = executor.start(self.windows_request())
            again = executor.start(self.windows_request())
            self.assertEqual(1, driver.submits)
            self.assertTrue(again["duplicate"])
            self.assertEqual(first["jobIdentity"], again["jobIdentity"])
            changed = self.windows_request()
            changed["environment"] = "ff6b5d84-f546-4a96-baf7-f9c801c743c0"
            with self.assertRaisesRegex(execution.ScenarioExecutionError, "different immutable"):
                executor.start(changed)

    @unittest.skipIf(os.name != "posix", "private journal requires POSIX ownership admission")
    def test_windows_terminal_without_collection_stays_unknown(self):
        with tempfile.TemporaryDirectory() as raw:
            driver = self.WindowsDriver()
            executor = execution.ScenarioExecutor(Path(raw) / "journal", driver)
            correlation = self.windows_request()["correlationId"]
            executor.start(self.windows_request())
            self.assertEqual("submitted", executor.status(correlation)["state"])
            driver.exit_code = 0
            result = executor.status(correlation)
            self.assertEqual(("unknown", "terminal_collection_unverified", "terminal", 0, "unknown"),
                             (result["state"], result["reason"], result["executionState"], result["executionExitCode"], result["collectionState"]))
            self.assertNotIn("scenarioEvidence", result)

    def test_only_a_windows_row_shows_its_job_failure_and_only_as_a_token(self):
        def public(scenario, excerpt):
            return execution.ScenarioExecutor._public({"plan": {**self.windows_request(), "scenarioId": scenario}, "state": "terminal", "lastReason": "correlated_receipt",
                                                       "exitCode": 2, "failureExcerpt": excerpt})
        self.assertEqual("host_setup:instance_host_epoch", public("windows-ordinary-qualification", "host_setup:instance_host_epoch")["executionFailure"])
        self.assertNotIn("executionFailure", public("windows-ordinary-qualification", "C:\\Users\\private account"))
        self.assertNotIn("executionFailure", public("linux-scheduled-refresh", "host_setup:instance_host_epoch"))

    def test_windows_names_are_closed(self):
        for name in ("windows-other", "windows-ordinary-qualification.extra", "WINDOWS-ORDINARY-QUALIFICATION"):
            changed = self.windows_request()
            changed["scenarioId"] = name
            with self.assertRaisesRegex(execution.ScenarioExecutionError, "allowlisted"):
                execution.ScenarioPlan.from_mapping(changed)
        updates = {"windows-public-update." + variant for variant in (
            "public-ready", "download-cancelled", "checksum-rejected", "uac-denied", "install-cancelled", "participating-copy-lock",
            "protected-storage-rejected", "native-install-failed", "success-off", "success-reconnect", "different-admin",
            "wait-client-loss", "installer-wait-client-loss")}
        self.assertEqual(frozenset({"windows-ordinary-qualification", "windows-python-install", "windows-msi-base-install",
                                    "windows-msi-base-reset", "windows-packaged-cli-smoke", "windows-disconnected-cli-config",
                                    "windows-streaming-client-interrupt", "windows-disconnected-cli-config.ssh-import-routing",
                                    "windows-disconnected-cli-config.ssh-relay-transfer",
                                    "windows-autostart-migration.pre", "windows-autostart-migration.post",
                                    "windows-reboot-reconnect.pre", "windows-reboot-reconnect.post", "windows-reboot-explicit-off.pre",
                                    "windows-reboot-explicit-off.post", "windows-query-owner-gui-reconnect",
                                    *("windows-proxy-lifecycle." + variant for variant in (
                                        "gui-pending", "find-best-success", "find-best-verification-failure", "find-best-cancel", "generated",
                                        "custom", "large", "prepare-failure", "commit-readiness-failure", "sibling-off", "scheduled-refresh",
                                        "no-tray-close")),
                                    *("windows-scoped-tun." + variant for variant in ("restart-deny", "restart-grant", "find-best-deny", "find-best-grant")),
                                    *updates,
                                    "windows-document-acceptance", *("windows-document-cold." + variant for variant in (
                                        "cold-reopen", "legacy-newline", "gui-owner", "cache-bytes")),
                                    "windows-document-responsive"}),
                         execution.WINDOWS_SCENARIOS)
        for name in ("windows-proxy-lifecycle", "windows-proxy-lifecycle.no-tray", "windows-proxy-lifecycle.scheduled",
                     "windows-disconnected-cli-config.other", "windows-streaming-client-interrupt.ssh-import-routing",
                     "windows-streaming-client-interrupt.ssh-relay-transfer", "windows-disconnected-cli-config.ssh-relay",
                     "windows-proxy-lifecycle.restart-deny", "windows-public-update.transport-loss", "windows-public-update",
                     "windows-public-update.public-ready.extra", "windows-document-cold", "windows-document-cold.cache",
                     "windows-document-acceptance.gui-owner", "windows-document-cold.gui-transfer", "windows-document-responsive.cancel",
                     "windows-document-acceptance.responsive"):
            changed = self.windows_request()
            changed["scenarioId"] = name
            with self.assertRaisesRegex(execution.ScenarioExecutionError, "allowlisted"):
                execution.ScenarioPlan.from_mapping(changed)

    def test_windows_private_journal_is_explicitly_unsupported_before_path_access(self):
        with tempfile.TemporaryDirectory() as raw:
            executor = execution.ScenarioExecutor(Path(raw) / "journal", LocalFixtureDriver(Path(raw) / "fixture"))
            with mock.patch.object(execution.os, "name", "nt"):
                with self.assertRaisesRegex(execution.ScenarioExecutionError, "POSIX private journal"):
                    executor.status("run-17")

    def test_module_imports_when_fcntl_is_unavailable(self):
        name = "native_scenario_execution_without_fcntl"
        spec = importlib.util.spec_from_file_location(name, SOURCE / "native_scenario_execution.py")
        module = importlib.util.module_from_spec(spec)
        original_import = builtins.__import__

        def without_fcntl(import_name, *args, **kwargs):
            if import_name == "fcntl":
                raise ImportError("simulated Windows")
            return original_import(import_name, *args, **kwargs)

        sys.modules[name] = module
        try:
            assert spec.loader is not None
            with mock.patch("builtins.__import__", side_effect=without_fcntl):
                spec.loader.exec_module(module)
            self.assertIsNone(module.fcntl)
        finally:
            sys.modules.pop(name, None)


if __name__ == "__main__":
    unittest.main()
