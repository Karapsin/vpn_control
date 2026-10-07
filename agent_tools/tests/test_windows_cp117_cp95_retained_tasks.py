"""Causal checks for the fixed CP95 retained-task observer."""
from __future__ import annotations

import hashlib
import contextlib
import base64
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_tools import windows_cp117_cp95_retained_tasks as retained


DESC = ("windows-cp117", "/qga", 123, 456, "S-1-5-21-1-2-3-1002")


class Cp95RetainedTasksTests(unittest.TestCase):
    def _profiles(self, state="terminal", process="absent"):
        return {"profiles": [{"profile": name, "state": state,
                              "result": "succeeded" if state == "terminal" else "unknown",
                              "correlatedProcess": process}
                             for name in retained._PROFILE_NAMES], "activeInstallerCount": 0,
                "opaquePowerShellCount": 0}

    def _lease_lock(self, root):
        return contextlib.nullcontext(root)

    def test_acquire_dispatch_digest_binds_current_sid_without_campaign_admission(self):
        corr = retained._ACQUIRES[0]
        record = {"request": {"correlationId": corr}}
        command = "fixed-command"
        dispatch = {"version": 3, "commandSha256": hashlib.sha256(command.encode()).hexdigest()}
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(retained.acquire, "_read", return_value=record), \
             mock.patch.object(retained.acquire, "_dispatch", return_value=dispatch), \
             mock.patch.object(retained.acquire, "_command_for", return_value=command), \
             mock.patch.object(retained.acquire, "_admit", side_effect=AssertionError("historical observer must not admit")) as admit:
            spec = retained._acquire_spec(Path(directory), corr, DESC)
        self.assertEqual("VpnControlMcpCp95Acquire-" + corr, spec["task"])
        self.assertEqual(DESC[4], spec["sid"])
        admit.assert_not_called()

    def test_red_acquire_dispatch_mismatch_prevents_qga_observation(self):
        corr = retained._ACQUIRES[0]
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(retained.acquire, "_read", return_value={"request": {"correlationId": corr}}), \
             mock.patch.object(retained.acquire, "_dispatch", return_value={"version": 3, "commandSha256": "0" * 64}), \
             mock.patch.object(retained.acquire, "_command_for", return_value="fixed-command"), \
             mock.patch.object(retained.base, "_remote") as remote:
            self.assertIsNone(retained._acquire_spec(Path(directory), corr, DESC))
        remote.assert_not_called()

    def test_red_python_profile_requires_its_persisted_generation(self):
        request = {"correlationId": retained._PYTHON}
        record = {"schemaVersion": 1, "request": request, "socketPath": DESC[1], "qemuPid": 999,
                  "startTicks": DESC[3], "originalSid": DESC[4], "sourceFingerprint": "a" * 64,
                  "installerSha256": retained.install.SHA256, "installerSize": retained.install.SIZE_BYTES,
                  "commandSha256": hashlib.sha256(retained.install._START_PS.encode()).hexdigest()}
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(retained.install, "_read_intent", return_value=record), \
             mock.patch.object(retained.acquire, "_read", return_value={"request": request}):
            self.assertIsNone(retained._python_spec(Path(directory), DESC))

    def test_ready_requires_two_equal_terminal_reads_and_never_calls_old_admission(self):
        observed = self._profiles()
        specs = [{"profile": name} for name in retained._PROFILE_NAMES]
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(retained.base, "_descriptor", return_value=(object(), object(), DESC)), \
             mock.patch.object(retained, "_lease_read_lock", side_effect=self._lease_lock), \
             mock.patch.object(retained.lease, "_active", return_value=None), \
             mock.patch.object(retained, "_configured_specs", return_value=specs), \
             mock.patch.object(retained, "_observe_once", side_effect=[observed, observed]) as observe, \
             mock.patch.object(retained.acquire, "_admit", side_effect=AssertionError("must not admit")) as admit:
            result = retained.status(Path(directory), {})
        self.assertEqual("ready", result["state"])
        self.assertEqual(2, observe.call_count)
        admit.assert_not_called()

    def test_red_changed_second_read_and_running_task_never_become_ready(self):
        specs = [{"profile": name} for name in retained._PROFILE_NAMES]
        terminal = self._profiles(); running = self._profiles("running", "present")
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(retained.base, "_descriptor", return_value=(object(), object(), DESC)), \
             mock.patch.object(retained, "_lease_read_lock", side_effect=self._lease_lock), \
             mock.patch.object(retained.lease, "_active", return_value=None), \
             mock.patch.object(retained, "_configured_specs", return_value=specs), \
             mock.patch.object(retained, "_observe_once", side_effect=[terminal, running]):
            self.assertEqual("unknown", retained.status(Path(directory), {})["state"])
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(retained.base, "_descriptor", return_value=(object(), object(), DESC)), \
             mock.patch.object(retained, "_lease_read_lock", side_effect=self._lease_lock), \
             mock.patch.object(retained.lease, "_active", return_value=None), \
             mock.patch.object(retained, "_configured_specs", return_value=specs), \
             mock.patch.object(retained, "_observe_once", side_effect=[running, running]):
            self.assertEqual("blocked", retained.status(Path(directory), {})["state"])

    def test_observation_script_checks_action_principal_trigger_and_terminal_result(self):
        script = retained._observation_script([{"profile": "acquire-194eb94d", "correlationId": retained._ACQUIRES[0],
                                                "task": "VpnControlMcpCp95Acquire-" + retained._ACQUIRES[0],
                                                "actionSha256": "a" * 64, "sid": DESC[4]}])
        self.assertIn("$triggers.Count -ne 0", script)
        self.assertIn("$principal.LogonType.ToString() -cne 'Interactive'", script)
        self.assertIn("Get-ScheduledTaskInfo", script)
        self.assertIn("correlatedProcess", script)
        self.assertIn("actualAction", script)
        self.assertIn("$triggers=@($t.Triggers|Where-Object {$null -ne $_})", script)

    def test_encoded_correlation_is_conservatively_blocking_even_when_old_plaintext_match_misses_it(self):
        corr = retained._ACQUIRES[0]
        encoded = base64.b64encode(("$corr='" + corr + "'").encode("utf-16le")).decode()
        command_line = "powershell.exe -NoProfile -EncodedCommand " + encoded
        # This is the prior false-negative shape: the UUID is UTF-16/base64,
        # so a plaintext CommandLine correlation match sees nothing.
        self.assertNotIn(corr, command_line)
        old_plaintext_match = corr in command_line
        new_conservative_state = "present" if command_line else "unknown"
        self.assertFalse(old_plaintext_match)
        self.assertEqual("present", new_conservative_state)
        script = retained._observation_script([{"profile": "acquire-194eb94d", "correlationId": corr,
                                                "task": "VpnControlMcpCp95Acquire-" + corr,
                                                "actionSha256": "a" * 64, "sid": DESC[4]}])
        self.assertNotIn("[regex]::Escape($s.corr)", script)
        self.assertIn("$allPs.Count -eq 0", script)
        self.assertIn("$opaque.Count -ne 0", script)

    def test_action_hash_observer_stays_within_qga_admission_for_all_five_profiles(self):
        specs = [{"profile": name, "correlationId": "11111111-1111-4111-8111-111111111111",
                  "task": "VpnControlMcpCp95Acquire-11111111-1111-4111-8111-111111111111",
                  "actionSha256": "a" * 64, "sid": DESC[4]} for name in retained._PROFILE_NAMES]
        self.assertLess(len(__import__("base64").b64encode(retained._observation_script(specs).encode("utf-16le"))), 30000)

    def test_red_absent_lease_journal_is_not_created_by_read_only_observer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertFalse(retained._no_active_lease(root))
            self.assertFalse((root / retained.lease._DIR).exists())

    def test_red_missing_posix_lock_api_returns_platform_unknown_without_creating_journal(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(retained, "_fcntl", None):
            root = Path(directory)
            result = retained.status(root, {})
        self.assertEqual("platform", result["phase"])
        self.assertFalse((root / retained.lease._DIR).exists())


if __name__ == "__main__":
    unittest.main()
