"""Fixed MCP admission for the read-only Arch ai_loop observer."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import arch_ai_loop_observe, mcp_server


class ArchAiLoopObserveRouteTest(unittest.TestCase):
    def setUp(self):
        source_guard = patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        source_guard.start()
        self.addCleanup(source_guard.stop)

    def test_fixed_request_only_and_no_native_action(self):
        request = {"host": "archlinux", "timeoutSeconds": 15}
        observation = {"available": True, "outcome": "available", "reason": "ok",
                       "installation": {"package": "absent", "executable": "absent", "version": None},
                       "activity": {"userService": "inactive", "systemService": "inactive",
                                    "process": "not_running"},
                       "safeProjection": {"state": "absent"}}
        with patch.object(arch_ai_loop_observe, "observe", return_value=observation) as observe:
            result = mcp_server._vm_workflow_impl("arch-ai-loop-observe", request)
        observe.assert_called_once_with(mcp_server.REPO_ROOT, 15)
        self.assertTrue(result["ok"])
        self.assertEqual("observed", result["state"])
        self.assertFalse(result["nativeActionAllowed"])
        self.assertFalse(result["productAction"])
        with patch.object(arch_ai_loop_observe, "observe", side_effect=AssertionError("unsafe dispatch")):
            for invalid in ({**request, "host": "fedora2328"},
                            {**request, "timeoutSeconds": True},
                            {**request, "timeoutSeconds": 31},
                            {**request, "command": "ai_loop"}):
                with self.subTest(invalid=invalid):
                    self.assertFalse(mcp_server._vm_workflow_impl("arch-ai-loop-observe", invalid)["ok"])

    def test_uncertain_observation_cannot_admit_action(self):
        request = {"host": "archlinux", "timeoutSeconds": 15}
        with patch.object(arch_ai_loop_observe, "observe", return_value={
                "available": False, "outcome": "unknown", "reason": "malformed_observation",
                "installation": None, "activity": None, "safeProjection": None}):
            result = mcp_server._vm_workflow_impl("arch-ai-loop-observe", request)
        self.assertFalse(result["ok"])
        self.assertEqual("unknown", result["state"])
        self.assertFalse(result["nativeActionAllowed"])
        self.assertFalse(result["productAction"])

    def test_malformed_observer_output_is_redacted_at_route(self):
        request = {"host": "archlinux", "timeoutSeconds": 15}
        poisoned = {"available": True, "outcome": "available", "reason": "ok",
                    "installation": {"package": "absent", "executable": "absent", "version": None},
                    "activity": {"userService": "inactive", "systemService": "inactive",
                                 "process": "not_running"},
                    "safeProjection": {"state": "absent"}, "secret": "should-never-return"}
        with patch.object(arch_ai_loop_observe, "observe", return_value=poisoned):
            result = mcp_server._vm_workflow_impl("arch-ai-loop-observe", request)
        self.assertFalse(result["ok"])
        self.assertEqual("unknown", result["state"])
        self.assertNotIn("secret", result)
        self.assertNotIn("should-never-return", str(result))
        self.assertFalse(result["nativeActionAllowed"])

    def test_cli_dispatches_fixed_action_with_inputs_file(self):
        request = {"host": "archlinux", "timeoutSeconds": 15}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inputs.json"
            path.write_text(json.dumps(request), encoding="utf-8")
            output = io.StringIO()
            with patch.object(mcp_server, "vm_workflow", return_value={"tool": "vm_workflow", "ok": True}) as route, \
                    contextlib.redirect_stdout(output):
                code = mcp_server.main(["vm-workflow", "arch-ai-loop-observe", "--inputs-file", str(path)])
        route.assert_called_once_with("arch-ai-loop-observe", request)
        self.assertEqual(0, code)
        self.assertTrue(json.loads(output.getvalue())["ok"])


if __name__ == "__main__":
    unittest.main()
