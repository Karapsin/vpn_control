"""Causal regressions for read-only CP117 guest download observation."""
from __future__ import annotations

import ast
import json
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import re
import unittest
from unittest import mock
from urllib.request import urlopen

from agent_tools import windows_update_fixture_http_stage as http


CORR = "af3360e5-a53b-4cd2-b91a-4c6abfd6b118"
SID = "S-1-5-21-1-2-3-1002"
DESCRIPTOR = ("windows-cp117", "/qga", 1, 2, SID)
RECORD = {"request": {"correlationId": CORR}, "bundleSha256": "e" * 64,
          "bundleSize": 17, "routeNonce": "x" * 32}


class GuestDownloadDiagnosticTests(unittest.TestCase):
    def _observe(self, *, listener=("stopped", "false", 1234), qga=None, phase="download-submitted"):
        script = http.guest_download_script(correlation_id=CORR, sid=SID, sha256="e" * 64,
                                            length=17, port=listener[2], path="/" + "x" * 32)
        action = http._task_action_fingerprint(*http._download_task_action(script))
        if qga is None:
            qga = b'{"actionSha256":"unknown","download":"absent","state":"observed","task":"absent","taskResult":"unknown"}'
        else:
            value = json.loads(qga)
            value.setdefault("actionSha256", action if value.get("task") not in {"absent", "unknown"} else "unknown")
            value.setdefault("taskResult", "unknown")
            qga = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        target = mock.Mock(fixture_transfer_root="/fixture")
        with (mock.patch.object(http, "_record", return_value=(Path.cwd(), RECORD, object(), target)),
              mock.patch.object(http.base, "_descriptor", return_value=(object(), target, DESCRIPTOR)),
              mock.patch.object(http.large_transfer, "read", return_value={"phase": phase}),
              mock.patch.object(http, "_listener_forensic", return_value=listener) as forensic,
              mock.patch.object(http.base, "_remote", return_value=qga) as remote,
              mock.patch.object(http, "_large_advance", side_effect=AssertionError("read-only")),
              mock.patch.object(http, "guest_download", side_effect=AssertionError("must not submit")),
              mock.patch.object(http, "stage_extract", side_effect=AssertionError("must not extract"))):
            result = http.workflow(Path.cwd(), "guest-download-diagnostic", {"correlationId": CORR})
        return result, forensic, remote

    def test_stopped_unserved_listener_and_absent_task_are_reported_without_replay(self):
        result, forensic, remote = self._observe()
        self.assertEqual({"state": "diagnosed", "correlationId": CORR, "preEffect": True,
                          "replayAllowed": False, "nativeActionAllowed": False, "productAction": False,
                          "phase": "task-absent", "listener": "stopped", "listenerServed": "false",
                          "task": "absent", "taskResult": "unknown", "download": "absent"}, result)
        forensic.assert_called_once()
        self.assertEqual(http._REMOTE_QGA_GUEST_DOWNLOAD_DIAGNOSTIC, remote.call_args.args[1])

    def test_diagnostic_admits_another_exact_submitted_correlation_without_allowlist(self):
        other = "07708dc7-6884-40a5-9a78-c75dbb391dbd"
        record = {**RECORD, "request": {"correlationId": other}}
        target = mock.Mock(fixture_transfer_root="/fixture")
        with (mock.patch.object(http, "_record", return_value=(Path.cwd(), record, object(), target)),
              mock.patch.object(http.base, "_descriptor", return_value=(object(), target, DESCRIPTOR)),
              mock.patch.object(http.large_transfer, "read", return_value={"phase": "download-submitted"}),
              mock.patch.object(http, "_listener_forensic", return_value=("listening", "unknown", 1234)),
              mock.patch.object(http.base, "_remote", return_value=b'{"actionSha256":"unknown","download":"absent","state":"observed","task":"absent","taskResult":"unknown"}') as remote):
            result = http.guest_download_diagnostic(Path.cwd(), {"correlationId": other})
        self.assertEqual(other, result["correlationId"])
        self.assertEqual("task-absent", result["phase"])
        self.assertEqual(http._REMOTE_QGA_GUEST_DOWNLOAD_DIAGNOSTIC, remote.call_args.args[1])

    def test_projects_task_and_file_outcomes_with_complete_file_winning(self):
        cases = (
            (b'{"download":"absent","state":"observed","task":"running"}', "task-running"),
            (b'{"download":"absent","state":"observed","task":"failed"}', "task-failed"),
            (b'{"download":"hash-mismatch","state":"observed","task":"completed"}', "download-hash-mismatch"),
            (b'{"download":"complete","state":"observed","task":"failed"}', "download-complete"),
        )
        for reply, phase in cases:
            with self.subTest(phase=phase):
                result, _forensic, _remote = self._observe(listener=("served", "true", 1234), qga=reply)
                self.assertEqual(phase, result["phase"])
                self.assertEqual("served", result["listener"])
                self.assertEqual("true", result["listenerServed"])

    def test_non_submitted_or_malformed_observation_cannot_authorize_an_action(self):
        result, forensic, remote = self._observe(phase="guest-created")
        self.assertEqual("not-submitted", result["phase"])
        forensic.assert_not_called()
        remote.assert_not_called()
        malformed, _forensic, _remote = self._observe(qga=b'{"state":"observed","task":"present","download":"absent"}')
        self.assertEqual("unknown", malformed["phase"])
        self.assertEqual("unknown", malformed["task"])

    def test_wrong_task_action_payload_is_unknown_even_when_no_file_exists(self):
        result, _forensic, _remote = self._observe(qga=b'{"actionSha256":"' + b"f" * 64
                                                    + b'","download":"absent","state":"observed","task":"running"}')
        self.assertEqual("task-action-mismatch", result["phase"])
        self.assertEqual("unknown", result["task"])

    def test_action_projector_accepts_exact_control_and_rejects_wrong_arguments(self):
        download = http.guest_download_script(correlation_id=CORR, sid=SID, sha256="e" * 64,
                                              length=17, port=1234, path="/" + "x" * 32)
        executable, arguments = http._download_task_action(download)
        expected = http._task_action_fingerprint(executable, arguments)
        control = {"state": "observed", "task": "running", "download": "absent",
                   "actionSha256": expected}
        self.assertEqual(("task-running", "running", "absent", "unknown"),
                         http._project_guest_download_observation(control, expected))
        wrong = dict(control, actionSha256=http._task_action_fingerprint(executable, arguments + " changed"))
        self.assertEqual(("task-action-mismatch", "unknown", "absent", "unknown"),
                         http._project_guest_download_observation(wrong, expected))

    def test_projector_keeps_wrapper_metadata_and_file_failures_finite(self):
        expected = "e" * 64
        for observed, phase in (
            ({"state":"wrapper-timeout","task":"unknown","download":"unknown","actionSha256":"unknown"}, "qga-wrapper-timeout"),
            ({"state":"wrapper-failed","task":"unknown","download":"unknown","actionSha256":"unknown"}, "qga-wrapper-failed"),
            ({"state":"observed","task":"metadata-error","download":"unknown","actionSha256":"unknown"}, "task-metadata-error"),
            ({"state":"observed","task":"completed","download":"read-error","actionSha256":expected}, "guest-file-read-error"),
        ):
            with self.subTest(phase=phase):
                self.assertEqual(phase, http._project_guest_download_observation(observed, expected)[0])

    def test_task_present_subgates_have_distinct_finite_projections(self):
        expected = "e" * 64
        for task in ("principal-mismatch", "action-count-mismatch", "state-unsupported",
                     "task-info-failed", "action-hash-unknown"):
            observed = {"state": "observed", "task": task, "download": "absent",
                        "actionSha256": "unknown"}
            self.assertEqual("task-" + task,
                             http._project_guest_download_observation(observed, expected)[0])

    def test_task_result_requires_integer_and_projects_concrete_failure_code(self):
        expected = "e" * 64
        malformed = {"state":"observed", "task":"failed", "taskResult":None,
                     "download":"absent", "actionSha256":expected}
        self.assertIsNone(http._project_guest_download_observation(malformed, expected))
        failed = dict(malformed, taskResult=2147942405)
        self.assertEqual(("task-failed", "failed", "absent", 2147942405),
                         http._project_guest_download_observation(failed, expected))
        download = http.guest_download_script(correlation_id=CORR, sid=SID, sha256="e" * 64,
                                              length=17, port=1, path="/" + "x" * 32)
        rendered = http._guest_download_diagnostic_script(CORR, SID, "e" * 64, 17, download)
        self.assertIn("[TypeCode]::UInt32", rendered)
        self.assertIn("[TypeCode]::Int64", rendered)
        self.assertIn("$null -eq $rawResult", rendered)

    def test_diagnostic_script_parses_frozen_download_without_invoking_it(self):
        download = http.guest_download_script(correlation_id=CORR, sid=SID, sha256="e" * 64,
                                              length=17, port=1, path="/" + "x" * 32)
        script = http._guest_download_diagnostic_script(CORR, SID, "e" * 64, 17, download)
        self.assertIn("Parser]::ParseInput", script)
        self.assertIn("Get-ScheduledTaskInfo", script)
        self.assertIn("Get-FileHash", script)
        self.assertIn("$actions[0].Execute", script)
        self.assertIn("$actions[0].Arguments", script)
        self.assertIn("$actionSha256", script)
        self.assertNotIn("Start-ScheduledTask", script)
        self.assertNotIn("Register-ScheduledTask", script)
        self.assertNotIn("HttpClient", script)
        self.assertIn("$expectedSid", script)
        self.assertIn("$principal -notmatch '^S-1-5-(?:[0-9]+-)*[0-9]+$'", script)
        self.assertIn("NTAccount]::new($principal)", script)
        self.assertNotIn("$principal -ceq 'VPNMSIX64\\vpncp117'", script)

    def test_ps5_download_loads_http_assembly_before_constructing_handler(self):
        generated = http.guest_download_script(correlation_id=CORR, sid=SID, sha256="e" * 64,
                                               length=17, port=1, path="/" + "x" * 32)
        prerequisite = "Add-Type -AssemblyName System.Net.Http"
        handler = "[Net.Http.HttpClientHandler]::new()"
        self.assertIn(prerequisite, generated)
        self.assertLess(generated.index(prerequisite), generated.index(handler))

    def test_exact_legacy_submitted_download_reconstructs_pre_fix_action_only(self):
        args = dict(correlation_id="07708dc7-6884-40a5-9a78-c75dbb391dbd", sid=SID,
                    sha256="e" * 64, length=17, port=1, path="/" + "x" * 32)
        self.assertNotIn("Add-Type -AssemblyName System.Net.Http", http._submitted_download_script(**args))
        self.assertIn("Add-Type -AssemblyName System.Net.Http", http._submitted_download_script(
            **{**args, "correlation_id": CORR}))

    def test_rendered_task_root_is_one_backslash_and_not_the_absent_double_root(self):
        download = http.guest_download_script(correlation_id=CORR, sid=SID, sha256="e" * 64,
                                              length=17, port=1, path="/" + "x" * 32)
        rendered = http._guest_download_diagnostic_script(CORR, SID, "e" * 64, 17, download)
        roots = re.findall(r"-TaskPath '([^']*)'", rendered)
        self.assertEqual(["\\", "\\"], roots)
        self.assertNotIn("\\\\", roots)
        # The same root lookup is what the submit wrapper registers before
        # starting the task, so a regression to a double-root cannot hide it.
        self.assertIn("Get-ScheduledTask -TaskPath '\\'", http._REMOTE_QGA_DOWNLOAD)

    def test_forensic_listener_projects_expired_unserved_receipt_without_endpoint_details(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = (Path(directory) / "windows-cp117" / "windows-update-fixture-http-stage" / CORR)
            stage.mkdir(parents=True)
            for path in (Path(directory) / "windows-cp117",
                         Path(directory) / "windows-cp117" / "windows-update-fixture-http-stage", stage):
                path.chmod(0o700)
            ready = stage / "listener-ready.json"; done_receipt = stage / "listener-done.json"
            route_hash = hashlib.sha256(("/" + "x" * 32).encode()).hexdigest()
            ready.write_text('{"pid":1,"startTicks":"2","port":3,"pathSha256":"' + route_hash + '"}')
            done_receipt.write_text('{"served":false}')
            ready.chmod(0o600); done_receipt.chmod(0o600)
            done = subprocess.run([sys.executable, "-c", http._REMOTE_LISTENER_FORENSIC,
                                   directory, CORR, route_hash], capture_output=True, check=False, timeout=10)
        self.assertEqual(0, done.returncode)
        self.assertEqual({"state": "stopped", "served": "false", "port": 3}, json.loads(done.stdout))
        mismatch = subprocess.run([sys.executable, "-c", http._REMOTE_LISTENER_FORENSIC,
                                   directory, CORR, "f" * 64], capture_output=True, check=False, timeout=10)
        self.assertEqual({"state": "unknown", "served": "unknown", "port": None}, json.loads(mismatch.stdout))

    def test_worker_has_fixed_ten_minute_bound_and_still_closes_after_one_request(self):
        """Execute the rendered worker and inspect its compiled deadline policy.

        This catches a regression to the observed two-minute ceiling without
        waiting ten minutes, while the real subprocess verifies that the larger
        bound did not weaken one-use closure.
        """
        tree = ast.parse(http._HTTP_WORKER)
        assignments = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == "deadline"
                               for target in node.targets)]
        self.assertEqual(1, len(assignments))
        deadline = assignments[0].value
        self.assertIsInstance(deadline, ast.BinOp)
        self.assertIsInstance(deadline.op, ast.Add)
        self.assertIsInstance(deadline.right, ast.Constant)
        self.assertEqual(600, deadline.right.value)
        payload = b"bounded-one-use"; digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            bundle = stage / "bundle.zip"; bundle.write_bytes(payload); bundle.chmod(0o600)
            worker = subprocess.Popen([sys.executable, "-c", http._HTTP_WORKER, directory],
                                      stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL)
            assert worker.stdin is not None
            worker.stdin.write(json.dumps({"path": "/" + "x" * 32, "sha256": digest,
                                           "length": len(payload)}).encode())
            worker.stdin.close()
            ready = stage / "listener-ready.json"
            for _ in range(100):
                if ready.exists(): break
                time.sleep(.01)
            self.assertTrue(ready.exists())
            port = json.loads(ready.read_text())["port"]
            with urlopen("http://127.0.0.1:" + str(port) + "/" + "x" * 32, timeout=3) as response:
                self.assertEqual(payload, response.read())
            self.assertEqual(0, worker.wait(timeout=3))
            self.assertEqual({"served": True}, json.loads((stage / "listener-done.json").read_text()))


if __name__ == "__main__":
    unittest.main()
