from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

from agent_tools import native_scenario_batch as batch


class Dispatcher:
    def __init__(self, responses=None):
        self.responses = {key: list(value) for key, value in (responses or {}).items()}
        self.calls = []

    def __call__(self, surface, action, inputs):
        self.calls.append((surface, action, dict(inputs)))
        if action in self.responses and self.responses[action]:
            value = self.responses[action].pop(0)
            if isinstance(value, Exception):
                raise value
            return value
        if action == "artifact-verify":
            return {"verification": "verified"}
        if action == "scenario-start":
            return {"state": "submitted", "correlationId": inputs["correlationId"]}
        if action == "scenario-status":
            return {"state": "terminal", "exitCode": 0, "correlationId": inputs["correlationId"]}
        if action == "scenario-collect":
            value = {"state": "terminal", "correlationId": inputs["correlationId"],
                     "evidencePaths": ["/private/owned/evidence.json"]}
            if any(action == "scenario-start" and previous.get("scenarioId") == "linux-scheduled-refresh"
                   for _, action, previous in self.calls):
                value["scenarioEvidence"] = {"correlationId": inputs["correlationId"], "result": "passed",
                    "mode": "refresh-find-best", "exitCode": 0, "preflightReady": True,
                    "cleanup": {"state": "complete", "ownerStopped": True,
                                "protectedPreserved": True, "workspaceRemoved": True}}
            return value
        raise AssertionError(action)


class Preflight:
    def __init__(self, answers=None):
        self.answers = list(answers or [])
        self.calls = []

    def __call__(self, request):
        self.calls.append(dict(request))
        return self.answers.pop(0) if self.answers else {"ready": True, "requirements": {}}


@unittest.skipUnless(os.name == "posix", "Durable batch journals require POSIX file locks and modes.")
class NativeScenarioBatchTest(unittest.TestCase):
    def request(self):
        return {"batchId": "batch-17", "recipe": "linux-public-update-preflight", "host": "arch",
                "environment": "owned", "bundleManifestArtifactId": "sha256-" + "a" * 64,
                "scenarioCorrelationId": "scenario-17"}

    def control(self, directory, dispatch=None, preflight=None):
        dispatch = dispatch or Dispatcher()
        preflight = preflight or Preflight()
        return batch.NativeScenarioBatch(Path(directory), dispatch, preflight=preflight), dispatch, preflight

    def test_real_recipe_freezes_plan_and_collects_scoped_evidence(self):
        with tempfile.TemporaryDirectory() as raw:
            control, dispatch, preflight = self.control(raw)
            self.assertEqual("pending", control.plan(self.request())["nodes"]["start"]["state"])
            result = control.start("batch-17")
            self.assertEqual("success", result["nodes"]["collect"]["state"])
            self.assertEqual(["/private/owned/evidence.json"], control.collect("batch-17")["collection"]["evidencePaths"])
            self.assertEqual(2, len(preflight.calls))
            self.assertEqual("scenario-17", next(inputs["correlationId"] for _, action, inputs in dispatch.calls
                                                  if action == "scenario-start"))
            self.assertEqual("not_applicable", result["cleanup"]["state"])
            self.assertEqual("success", result["state"])

    def test_independent_preflight_continues_and_blocks_dependent_mutation(self):
        with tempfile.TemporaryDirectory() as raw:
            dispatch = Dispatcher({"artifact-verify": [{"verification": "mismatch"}]})
            control, _, preflight = self.control(raw, dispatch)
            control.plan(self.request())
            result = control.start("batch-17")
            self.assertEqual("failed", result["nodes"]["artifact"]["state"])
            self.assertEqual("failed", result["state"])
            self.assertEqual("success", result["nodes"]["fixture"]["state"])
            self.assertEqual(1, len(preflight.calls))
            self.assertEqual("blocked", result["nodes"]["start"]["state"])
            self.assertNotIn("scenario-start", [action for _, action, _ in dispatch.calls])

    def test_fresh_preflight_failure_before_mutation_does_not_submit(self):
        with tempfile.TemporaryDirectory() as raw:
            preflight = Preflight([{"ready": True, "requirements": {}},
                                   {"ready": False, "requirements": {"endpoint": {"state": "failed"}}}])
            control, dispatch, _ = self.control(raw, preflight=preflight)
            control.plan(self.request())
            result = control.start("batch-17")
            self.assertEqual("blocked", result["nodes"]["start"]["state"])
            self.assertNotIn("scenario-start", [action for _, action, _ in dispatch.calls])

    def test_unknown_mutation_is_observed_but_never_replayed(self):
        with tempfile.TemporaryDirectory() as raw:
            dispatch = Dispatcher({"scenario-start": [{"state": "unknown", "correlationId": "scenario-17"}]})
            control, _, _ = self.control(raw, dispatch)
            control.plan(self.request())
            first = control.start("batch-17")
            second = control.resume("batch-17")
            self.assertEqual("unknown", first["nodes"]["start"]["state"])
            self.assertEqual("unknown", first["state"])
            self.assertEqual("success", second["nodes"]["status"]["state"])
            self.assertEqual(1, [action for _, action, _ in dispatch.calls].count("scenario-start"))

    def test_status_failure_still_collects_failure_evidence(self):
        with tempfile.TemporaryDirectory() as raw:
            dispatch = Dispatcher({"scenario-status": [
                {"state": "submitted", "correlationId": "scenario-17"},
                {"state": "terminal", "exitCode": 1, "correlationId": "scenario-17"}]})
            control, _, _ = self.control(raw, dispatch)
            control.plan(self.request())
            first = control.start("batch-17")
            self.assertEqual("waiting", first["nodes"]["status"]["state"])
            second = control.status("batch-17")
            self.assertEqual("failed", second["nodes"]["status"]["state"])
            self.assertEqual("failed", second["state"])
            self.assertEqual("success", second["nodes"]["collect"]["state"])
            self.assertEqual(["/private/owned/evidence.json"], second["nodes"]["collect"]["evidence"]["evidencePaths"])

    def test_wrong_correlation_never_counts_as_terminal_success(self):
        with tempfile.TemporaryDirectory() as raw:
            dispatch = Dispatcher({"scenario-status": [{"state": "terminal", "exitCode": 0,
                                                        "correlationId": "someone-else"}]})
            control, _, _ = self.control(raw, dispatch)
            control.plan(self.request())
            result = control.start("batch-17")
            self.assertEqual("failed", result["nodes"]["status"]["state"])
            self.assertEqual("correlation_mismatch", result["nodes"]["status"]["outcome"])

    def test_waiting_preflight_can_refresh_on_resume_without_mutation(self):
        with tempfile.TemporaryDirectory() as raw:
            preflight = Preflight([{"ready": False, "requirements": {"host": {"state": "unknown"}}},
                                   {"ready": True, "requirements": {}}])
            control, dispatch, _ = self.control(raw, preflight=preflight)
            control.plan(self.request())
            first = control.start("batch-17")
            self.assertEqual("waiting", first["nodes"]["fixture"]["state"])
            second = control.resume("batch-17")
            self.assertEqual("success", second["nodes"]["fixture"]["state"])
            self.assertEqual("pending", second["nodes"]["start"]["state"])
            self.assertNotIn("scenario-start", [action for _, action, _ in dispatch.calls])

    def test_windows_fixed_probe_recipe_collects_terminal_invalid_credential(self):
        correlation = str(uuid.uuid4())
        request = {"batchId": "windows-17", "recipe": "windows-credential-validity-v1", "host": "arch",
                   "environment": "owned-vm", "probeCorrelationId": correlation}
        dispatch = Dispatcher({"windows-credential-probe-start": [{"state": "submitted", "correlationId": correlation}],
                               "windows-credential-probe-status": [
                                   {"state": "terminal", "success": False, "errorCategory": "invalid-credentials", "correlationId": correlation},
                                   {"state": "terminal", "success": False, "errorCategory": "invalid-credentials", "correlationId": correlation}]})
        with tempfile.TemporaryDirectory() as raw:
            control, _, _ = self.control(raw, dispatch)
            control.plan(request)
            result = control.start("windows-17")
            self.assertEqual("failed", result["nodes"]["status"]["state"])
            self.assertEqual("success", result["nodes"]["collect"]["state"])
            self.assertEqual("invalid-credentials", result["nodes"]["collect"]["evidence"]["errorCategory"])
            self.assertEqual(1, [action for _, action, _ in dispatch.calls].count("windows-credential-probe-start"))

    def test_scheduled_refresh_recipe_uses_frozen_input_and_static_preflight(self):
        correlation = str(uuid.uuid4())
        request = {"batchId": "scheduled-17", "recipe": "linux-scheduled-refresh", "host": "arch",
                   "environment": "owned", "bundleManifestArtifactId": "sha256-" + "a" * 64,
                   "scenarioInputArtifactId": "sha256-" + "b" * 64, "scenarioCorrelationId": correlation}
        dispatch = Dispatcher()
        with tempfile.TemporaryDirectory() as raw:
            control, _, preflight = self.control(raw, dispatch)
            control.plan(request)
            result = control.start("scheduled-17")
            self.assertEqual("success", result["nodes"]["collect"]["state"])
            self.assertEqual("complete", result["cleanup"]["state"])
            self.assertTrue(result["cleanup"]["workspaceRemoved"])
            self.assertEqual("success", result["state"])
            start = next(inputs for _, action, inputs in dispatch.calls if action == "scenario-start")
            self.assertEqual(correlation, start["correlationId"])
            self.assertEqual({"bundleManifest", "scenarioInput"}, set(start["artifactIds"]))
            self.assertEqual("linux-scheduled-refresh", preflight.calls[-1]["scenarioId"])
            self.assertNotIn("expectedTestUrl", preflight.calls[-1])

    def test_scheduled_failed_receipt_preserves_failure_and_cleanup(self):
        correlation = str(uuid.uuid4())
        request = {"batchId": "scheduled-failed", "recipe": "linux-scheduled-refresh", "host": "arch",
                   "environment": "owned", "bundleManifestArtifactId": "sha256-" + "a" * 64,
                   "scenarioInputArtifactId": "sha256-" + "b" * 64, "scenarioCorrelationId": correlation}
        receipt = {"state": "terminal", "correlationId": correlation,
                   "scenarioEvidence": {"correlationId": correlation, "result": "failed", "exitCode": 1,
                       "cleanup": {"state": "preserved-for-recovery", "ownerStopped": False,
                                   "protectedPreserved": True, "workspaceRemoved": False}}}
        dispatch = Dispatcher({"scenario-status": [{"state": "terminal", "exitCode": 1,
                                                    "correlationId": correlation}],
                               "scenario-collect": [receipt]})
        with tempfile.TemporaryDirectory() as raw:
            control, _, _ = self.control(raw, dispatch)
            control.plan(request)
            result = control.start("scheduled-failed")
            self.assertEqual("failed", result["state"])
            self.assertEqual("success", result["nodes"]["collect"]["state"])
            self.assertEqual("preserved-for-recovery", result["cleanup"]["state"])
            self.assertFalse(result["cleanup"]["workspaceRemoved"])

    def test_scheduled_missing_receipt_does_not_claim_cleanup(self):
        correlation = str(uuid.uuid4())
        request = {"batchId": "scheduled-missing", "recipe": "linux-scheduled-refresh", "host": "arch",
                   "environment": "owned", "bundleManifestArtifactId": "sha256-" + "a" * 64,
                   "scenarioInputArtifactId": "sha256-" + "b" * 64, "scenarioCorrelationId": correlation}
        dispatch = Dispatcher({"scenario-collect": [{"state": "terminal", "correlationId": correlation}]})
        with tempfile.TemporaryDirectory() as raw:
            control, _, _ = self.control(raw, dispatch)
            control.plan(request)
            result = control.start("scheduled-missing")
            self.assertEqual("running", result["state"])
            self.assertEqual("waiting", result["nodes"]["collect"]["state"])
            self.assertEqual("unknown", result["cleanup"]["state"])


class NativeScenarioBatchPortableTest(unittest.TestCase):
    def test_cycle_is_rejected_deterministically(self):
        with self.assertRaisesRegex(batch.NativeScenarioBatchError, "cycle"):
            batch._ensure_acyclic({"one": {"after": ["two"]}, "two": {"after": ["one"]}})

    def test_invalid_windows_correlation_rejected_before_batch_journal(self):
        request = {"batchId": "windows-17", "recipe": "windows-credential-validity-v1", "host": "arch",
                   "environment": "owned-vm", "probeCorrelationId": "not-a-uuid"}
        with tempfile.TemporaryDirectory() as raw:
            control = batch.NativeScenarioBatch(Path(raw), Dispatcher(), preflight=Preflight())
            with self.assertRaisesRegex(batch.NativeScenarioBatchError, "UUID"):
                control.plan(request)
            self.assertEqual([], list(Path(raw).iterdir()))

    def test_unavailable_posix_lock_support_denies_journal_before_dispatch(self):
        dispatcher = Dispatcher()
        with tempfile.TemporaryDirectory() as raw, patch.object(batch, "fcntl", None):
            control = batch.NativeScenarioBatch(Path(raw), dispatcher, preflight=Preflight())
            request = {"batchId": "batch-17", "recipe": "linux-public-update-preflight", "host": "arch",
                       "environment": "owned", "bundleManifestArtifactId": "sha256-" + "a" * 64,
                       "scenarioCorrelationId": "scenario-17"}
            with self.assertRaisesRegex(batch.NativeScenarioBatchError, "POSIX"):
                control.plan(request)
            self.assertEqual([], dispatcher.calls)


if __name__ == "__main__":
    unittest.main()
