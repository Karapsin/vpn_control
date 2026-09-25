from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from agent_tools import native_scenario_execution as execution
from agent_tools import native_scheduled_refresh_ssh as scheduled


class NativeScheduledRefreshSshTest(unittest.TestCase):
    def plan(self, raw: bytes) -> execution.ScenarioPlan:
        return execution.ScenarioPlan.from_mapping({"scenarioId": "linux-scheduled-refresh", "host": "owned",
            "environment": "fixture", "bundleHash": "a" * 64,
            "artifactIds": {"bundleManifest": "sha256-" + "a" * 64,
                            "scenarioInput": "sha256-" + hashlib.sha256(raw).hexdigest()},
            "correlationId": "cf46f003-2d9b-4bb7-92d2-98786f00e92f"})

    def input(self, **changes) -> bytes:
        value = {"schema": "vpn-control.linux-scheduled-refresh.input", "schemaVersion": 1,
            "scenarioId": "linux-scheduled-refresh", "correlationId": "cf46f003-2d9b-4bb7-92d2-98786f00e92f",
            "ownedWorkspaceRoot": "/tmp/owned", "protectedStateDir": "/tmp/protected",
            "protectedControllerId": "8221c3ea-3055-46cc-80a0-7de5cdb08a33",
            "expectedPackageNevra": "vpn-control-2.2.1-1.x86_64", "expectedDesktopJarSha256": "b" * 64,
            "mode": "refresh-find-best", "scheduleHours": 0.084, "maxObservationSeconds": 334}
        value.update(changes)
        return json.dumps(value, sort_keys=True).encode()

    def test_valid_frozen_input_and_changed_bytes(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "input.json"
            content = self.input()
            path.write_bytes(content)
            plan = self.plan(content)
            self.assertEqual(content, scheduled.NativeScheduledRefreshSshDriver._input_bytes(path, plan))
            path.write_bytes(self.input(expectedDesktopJarSha256="c" * 64))
            with self.assertRaisesRegex(scheduled.NativeScheduledRefreshSshError, "changed"):
                scheduled.NativeScheduledRefreshSshDriver._input_bytes(path, plan)

    def test_wrong_correlation_and_unsafe_paths_fail_before_submit(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "input.json"
            for content in (self.input(correlationId="wrong"), self.input(ownedWorkspaceRoot="/tmp/../personal"),
                            self.input(maxObservationSeconds=20)):
                path.write_bytes(content)
                with self.assertRaises(scheduled.NativeScheduledRefreshSshError):
                    scheduled.NativeScheduledRefreshSshDriver._input_bytes(path, self.plan(content))

    def test_remote_programs_compile_and_script_mode_imports(self):
        compile(scheduled._SUBMIT, "<scheduled-submit>", "exec")
        compile(scheduled._LAUNCHER, "<scheduled-launcher>", "exec")
        compile(scheduled._COLLECT, "<scheduled-collect>", "exec")
        command = [sys.executable, "-c", "import sys;sys.path.insert(0,'agent_tools');import native_scheduled_refresh_ssh"]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(0, completed.returncode, completed.stderr)

    @unittest.skipUnless(os.name == "posix", "Receipt ownership and mode checks require POSIX.")
    def test_collect_admits_bounded_long_receipt_and_rejects_oversize(self):
        plan = self.plan(self.input())
        with tempfile.TemporaryDirectory() as raw:
            job = Path(raw) / "native-scenario-jobs" / plan.environment / plan.scenario_id / plan.correlation_id
            job.mkdir(parents=True, mode=0o700)
            job.chmod(0o700)
            expected = {"scenarioId": plan.scenario_id, "host": plan.host,
                        "environment": plan.environment, "bundleHash": plan.bundle_hash,
                        "artifactIds": dict(plan.artifact_ids), "correlationId": plan.correlation_id}
            identity = {"pid": 1234, "startTicks": 5678}
            receipt = {"schema": "vpn-control.linux-scheduled-refresh.receipt",
                       "scenarioId": plan.scenario_id, "correlationId": plan.correlation_id,
                       "result": "passed", "mode": "refresh-find-best",
                       "cleanup": {"state": "complete", "ownerStopped": True,
                                   "protectedPreserved": True, "workspaceRemoved": True},
                       "traffic": {"oldPortSamples": [{"probe": "x" * 200} for _ in range(400)]}}
            files = {"intent.json": {**expected, "identity": identity},
                     "receipt.json": {**expected, **identity, "exitCode": 0},
                     "scenario-receipt.json": receipt}
            for name, value in files.items():
                path = job / name
                path.write_text(json.dumps(value), encoding="utf-8")
                path.chmod(0o600)
            args = [raw, plan.host, plan.environment, plan.scenario_id,
                    plan.correlation_id, plan.bundle_hash, json.dumps(dict(plan.artifact_ids)), "1234", "5678"]
            completed = subprocess.run([sys.executable, "-c", scheduled._COLLECT, *args],
                                       capture_output=True, text=True, check=False)
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual("collected", json.loads(completed.stdout)["state"])
            receipt["traffic"]["oldPortSamples"] = [{"probe": "x" * 200} for _ in range(22000)]
            path = job / "scenario-receipt.json"
            path.write_text(json.dumps(receipt), encoding="utf-8")
            path.chmod(0o600)
            completed = subprocess.run([sys.executable, "-c", scheduled._COLLECT, *args],
                                       capture_output=True, text=True, check=False)
            self.assertEqual("unknown", json.loads(completed.stdout)["state"])


if __name__ == "__main__":
    unittest.main()
