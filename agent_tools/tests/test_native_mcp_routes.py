"""Public MCP/CLI routing tests; no network or VM mutations."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from agent_tools import mcp_server


class NativeRoutesTest(unittest.TestCase):
    def test_fixture_publish_requires_exact_fields_before_transport(self):
        from agent_tools import ssh_transfer
        with patch.object(ssh_transfer, "publish") as publish:
            result = mcp_server.ssh_workflow("fixture-publish", host="vm", transfer={"command": "unexpected"})
        self.assertFalse(result["ok"])
        publish.assert_not_called()

    def test_fixture_status_preserves_unknown_identity(self):
        from agent_tools import ssh_transfer
        identity = {"correlationId": "retained"}
        result = {"ok": False, "state": "unknown", "identity": identity}
        with patch.object(ssh_transfer, "status", return_value=result) as observe:
            actual = mcp_server.ssh_workflow("fixture-status", host="vm", identity=identity)
        self.assertEqual(identity, actual["identity"])
        self.assertEqual("unknown", actual["state"])
        observe.assert_called_once()

    def test_command_noise_filter_preserves_real_errors_and_exit_status(self):
        from subprocess import CompletedProcess
        noise = "2026-09-24 15:24:09.612 zsh[44632:4550809] [AppleSharpener] Not in Dock process (bundle ID: (null)), skipping setup\n"
        other = "2026-09-24 15:24:09.612 zsh[44632:4550809] [AppleSharpener] unexpected failure\n"
        completed = CompletedProcess(["test"], 7, noise + "actual stdout\n", noise + other + "actual stderr\n")
        with patch.object(mcp_server.subprocess, "run", return_value=completed) as run:
            result = mcp_server._run(["test"])
        self.assertEqual(7, result["returncode"])
        self.assertFalse(result["ok"])
        self.assertEqual("actual stdout", result["stdout"])
        self.assertEqual(other + "actual stderr", result["stderr"])
        self.assertNotIn("DYLD_INSERT_LIBRARIES", run.call_args.kwargs["env"])

    def test_private_inventory_cannot_be_managed_staged(self):
        self.assertIsNotNone(mcp_server._validate_commit_paths([".vm-hosts.local.json"]))

    def test_inventory_failure_does_not_leak_private_configuration(self):
        with tempfile.TemporaryDirectory() as root, patch.object(mcp_server, "REPO_ROOT", Path(root)):
            result = mcp_server.ssh_workflow()
            self.assertFalse(result["ok"])
            self.assertNotIn(root, json.dumps(result))

    def test_vm_unknown_action_is_structured_failure(self):
        self.assertFalse(mcp_server.vm_workflow("restart-unknown-installer", {})["ok"])

    def test_memory_plan_is_never_start_authorization(self):
        result = mcp_server.vm_workflow("admit-plan", {
            "measurement": {"physicalMemoryBytes": 16000, "runningConfiguredMemoryBytes": 4000,
                            "pressure": "normal", "swapUsedBytes": 0},
            "requestedMemoryBytes": 4000, "headroomBytes": 4000,
        })
        self.assertTrue(result["ok"])
        self.assertFalse(result["nativeActionAllowed"])
        self.assertEqual("caller-supplied", result["measurementSource"])

    def test_cli_requires_json_object(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "inputs.json"
            path.write_text("[]")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = mcp_server.main(["vm-workflow", "admit-plan", "--inputs-file", str(path)])
            self.assertEqual(1, code)
            self.assertFalse(json.loads(output.getvalue())["ok"])


if __name__ == "__main__":
    unittest.main()
