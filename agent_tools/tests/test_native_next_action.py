"""Table tests for safe next-action guidance using public workflow response shapes."""
import unittest
from unittest import mock

from agent_tools.native_next_action import next_action


class NativeNextActionTest(unittest.TestCase):
    def test_public_ssh_wrapper_preserves_fixed_recovery_guidance(self):
        from agent_tools import mcp_server, native_failure_evidence
        result = {"tool": "ssh_workflow", "host": "guest", "status": "nested_master_absent",
                  "ok": False, "recoveryHost": "archlinux"}
        with mock.patch.object(mcp_server, "_ssh_workflow_impl", return_value=result), \
                mock.patch.object(native_failure_evidence, "record_failure", return_value={}):
            actual = mcp_server.ssh_workflow("probe", "guest")
        self.assertEqual("recover-configured-ssh-master", actual["nextAction"]["kind"])
        self.assertEqual({"tool": "ssh_workflow", "action": "connection-recover",
                          "args": {"host": "archlinux"}}, actual["nextAction"]["action"])
        self.assertFalse(actual["nextAction"]["replayAllowed"])

    def test_expired_nested_probe_guidance_survives_boundary_reclassification(self):
        result = {"host": "guest", "status": "nested_master_absent", "ok": False,
                  "recoveryHost": "archlinux", "nextAction": {"action": "foreign-command"}}
        actual = next_action("ssh_workflow", "probe", result)
        self.assertEqual("recover-configured-ssh-master", actual["kind"])
        self.assertEqual({"tool": "ssh_workflow", "action": "connection-recover",
                          "args": {"host": "archlinux"}}, actual["action"])
        self.assertFalse(actual["replayAllowed"])
        for invalid in (None, [], "arch;touch /tmp/foreign", "a" * 65, ":foreign"):
            with self.subTest(host=invalid):
                rejected = next_action("ssh_workflow", "probe", {**result, "recoveryHost": invalid})
                self.assertEqual("inspect-evidence", rejected["kind"])
                self.assertNotIn("action", rejected)
        for tool, action, extra in (("vm_workflow", "probe", {}),
                                    ("ssh_workflow", "job-status", {}),
                                    ("ssh_workflow", "probe", {"status": "authentication_failed"}),
                                    ("ssh_workflow", "probe", {"ok": True})):
            self.assertNotEqual("recover-configured-ssh-master", next_action(tool, action, {**result, **extra})["kind"])

    def test_known_response_taxonomy(self):
        job = {"host": "vm", "identity": {"jobId": "job-17", "pid": 417, "startTicks": 9981}, "status": "running", "reason": "process_live", "ok": True}
        cases = (
            ("ssh_workflow", "job-status", job, "observe-job", "job-status", False),
            ("ssh_workflow", "job-status", {**job, "status": "unknown", "reason": "timeout", "ok": False}, "observe-job", "job-status", False),
            ("ssh_workflow", "job-status", {**job, "status": "terminal", "exitCode": 23}, "inspect-evidence", None, False),
            ("ssh_workflow", "probe", {"host": "vm", "status": "timeout", "ok": False, "output": "SSH probe timed out."}, "retry-readonly", "probe", True),
            ("ssh_workflow", "forward-open", {"state": "local_forward_pending", "correlationId": "forward-17", "ok": False}, "inspect-evidence", None, False),
            ("ssh_workflow", "fixture-publish", {"state": "unknown", "reason": "interrupted_or_unverified", "identity": {"correlationId": "retained"}}, "inspect-evidence", None, False),
            ("vm_workflow", "artifact-verify", {"verification": "mismatch", "ok": False}, "missing-dependency", None, False),
            ("vm_workflow", "artifact-verify", {"verification": "unverified-remote", "ok": False}, "verify-artifact", None, False),
            ("vm_workflow", "environment-status", {"freshness": "stale", "ready": False}, "refresh-measurement", None, False),
            ("vm_workflow", "scenario-start", {"state": "submitted", "correlationId": "run-17", "reason": "submitted"}, "observe-scenario", "scenario-status", False),
            ("vm_workflow", "scenario-resume", {"state": "submitting", "correlationId": "run-17", "reason": "submit_response_unavailable"}, "observe-scenario", "scenario-status", False),
            ("vm_workflow", "scenario-status", {"state": "unknown", "correlationId": "run-17", "reason": "observer_unavailable"}, "observe-scenario", "scenario-status", False),
            ("vm_workflow", "scenario-collect", {"state": "terminal", "correlationId": "run-17", "exitCode": 0}, "complete", None, False),
            ("vm_workflow", "scenario-collect", {"state": "terminal", "correlationId": "run-17", "exitCode": 23}, "inspect-evidence", None, False),
            ("ssh_workflow", "forward-status", {"state": "unsupported_host", "ok": False}, "unsupported", None, False),
            ("vm_workflow", "restart-unknown-installer", {"ok": False, "summary": "installer failed"}, "inspect-evidence", None, False),
            ("vm_workflow", "unknown", {"state": "unknown", "ok": False}, "inspect-evidence", None, False),
        )
        for tool, action, result, kind, suggested, replay in cases:
            with self.subTest(tool=tool, action=action, state=result.get("state", result.get("status"))):
                actual = next_action(tool, action, result)
                self.assertEqual(kind, actual["kind"])
                self.assertEqual(replay, actual["replayAllowed"])
                self.assertEqual(suggested, actual.get("action", {}).get("action"))

    def test_suggested_arguments_are_only_host_and_identity(self):
        actual = next_action("ssh_workflow", "job-status", {
            "host": "vm", "identity": {"jobId": "job-17", "pid": 417, "startTicks": 9981},
            "status": "running", "reason": "process_live", "secret": "ignored",
        })
        self.assertEqual({"host", "identity"}, set(actual["action"]["args"]))
        self.assertNotIn("secret", actual["action"]["args"])

    def test_scenario_status_uses_the_vm_inputs_envelope(self):
        actual = next_action("vm_workflow", "scenario-start", {
            "state": "submitted", "correlationId": "run-17", "reason": "submitted",
        })
        self.assertEqual({"inputs": {"correlationId": "run-17"}}, actual["action"]["args"])
        self.assertNotIn("correlationId", actual["action"]["args"])

    def test_environment_unknown_distinguishes_fresh_missing_facts_from_stale_receipts(self):
        probes_ready = next_action("vm_workflow", "environment-status", {
            "state": "UNKNOWN", "requestedProbesReady": True, "freshness": "fresh", "observations": [], "ready": False,
        })
        stale = next_action("vm_workflow", "environment-status", {
            "state": "UNKNOWN", "requestedProbesReady": False, "freshness": "fresh",
            "observations": [{"kind": "memory", "stale": True}], "ready": False,
        })
        self.assertEqual("missing-dependency", probes_ready["kind"])
        self.assertEqual("refresh-measurement", stale["kind"])

    def test_unknown_response_never_replays(self):
        actual = next_action("ssh_workflow", "fixture-publish", {"state": "unknown", "identity": "bad"})
        self.assertEqual("inspect-evidence", actual["kind"])
        self.assertFalse(actual["replayAllowed"])
        self.assertTrue(actual["requiresFreshEvidence"])


if __name__ == "__main__":
    unittest.main()
