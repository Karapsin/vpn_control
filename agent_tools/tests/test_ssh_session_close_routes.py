"""Receipt-only owned-session close routes cannot expose arbitrary SSH actions."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from agent_tools import mcp_server as server
from agent_tools import ssh_connection_session_close as close


class SessionCloseRoutes(unittest.TestCase):
    identity = {"receiptSha256": "a" * 64}

    def setUp(self):
        patch = mock.patch.object(server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        patch.start(); self.addCleanup(patch.stop)

    def test_exact_receipt_only_dispatch_and_finite_result(self):
        for action, method, state in (("connection-session-close", "close", "exit_sent"),
                                      ("connection-session-close-status", "status", "closed")):
            output = {"state": state, "host": "archlinux", **self.identity, "replayAllowed": False}
            with self.subTest(action=action), mock.patch.object(close, method, return_value=output) as call:
                result = server._ssh_workflow_impl(action, "archlinux", identity=dict(self.identity))
                call.assert_called_once_with(server.REPO_ROOT, "archlinux", self.identity["receiptSha256"])
                self.assertTrue(result["ok"]); self.assertEqual(output, {k: result[k] for k in output})

    def test_invalid_input_never_calls_close_or_status(self):
        for edit in ({"identity": None}, {"identity": {}}, {"identity": {"receiptSha256": True}},
                     {"identity": {**self.identity, "command": "foreign"}}, {"transfer": {}},
                     {"device": "api29"}, {"timeout_seconds": True}, {"host": "../foreign"}):
            for action in ("connection-session-close", "connection-session-close-status"):
                args = {"host": "archlinux", "identity": self.identity, **edit}
                with self.subTest(action=action, edit=edit), mock.patch.object(close, "close") as effect, mock.patch.object(close, "status") as observe:
                    self.assertFalse(server._ssh_workflow_impl(action, **args)["ok"])
                    effect.assert_not_called(); observe.assert_not_called()

    def test_invalid_output_remains_unknown_and_does_not_leak(self):
        output = {"state": "exit_sent", "host": "archlinux", **self.identity, "replayAllowed": False}
        for edit in ({"private": "secret-marker"}, {"state": "closed"}, {"host": "foreign"},
                     {"receiptSha256": "b" * 64}, {"replayAllowed": 0}, {"replayAllowed": True}):
            with self.subTest(edit=edit), mock.patch.object(close, "close", return_value={**output, **edit}):
                result = server._ssh_workflow_impl("connection-session-close", "archlinux", identity=self.identity)
                self.assertFalse(result["ok"]); self.assertEqual("unknown", result["state"])
                self.assertFalse(result["replayAllowed"]); self.assertNotIn("secret-marker", str(result))
        with mock.patch.object(close, "close", side_effect=ValueError("secret-marker")):
            result = server._ssh_workflow_impl("connection-session-close", "archlinux", identity=self.identity)
        self.assertFalse(result["ok"]); self.assertNotIn("secret-marker", str(result))

    def test_fresh_script_context_and_identity_file_cli(self):
        program = """import importlib.util,json,sys
from pathlib import Path
from unittest import mock
source=Path(sys.argv[1]);sys.path.insert(0,str(source.parent))
spec=importlib.util.spec_from_file_location('close_cli_server',source)
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
from agent_tools import ssh_connection_session_close as close
output={'state':'closed','host':'archlinux','receiptSha256':'a'*64,'replayAllowed':False}
with mock.patch.object(close,'status',return_value=output) as call:
 result=s.main(['ssh-workflow','connection-session-close-status','--host','archlinux','--identity-file',sys.argv[2]])
 assert call.call_count==1
 raise SystemExit(result)
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"; path.write_text(json.dumps(self.identity)); path.chmod(0o600)
            child = subprocess.run([sys.executable, "-I", "-c", program, str(Path(server.__file__).resolve()), str(path)],
                                   cwd=directory, capture_output=True, text=True, timeout=30)
        self.assertEqual(0, child.returncode, child.stderr)
        self.assertTrue(json.loads(child.stdout)["ok"])

