"""Actual SDK/stdio/retained-relay protocol and authentic client import failure."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).parent / "fixtures/program_mcp_client"


@unittest.skipUnless(os.name == "posix" and importlib.util.find_spec("mcp"), "actual MCP SDK on POSIX")
class ProgramMcpClientTests(unittest.TestCase):
    def invoke(self, parent, source, label, extra=()):
        # Preserve the authentic client's original module location while loading
        # its exact retained bytes. No source statement or protocol is replaced.
        filename = ROOT / "agent_tools/ssh_program_mcp_client.py"
        loader = ("from pathlib import Path;import sys;"
                  "filename,source=sys.argv[1:3];sys.argv=[filename,*sys.argv[3:]];"
                  "exec(compile(Path(source).read_bytes(),filename,'exec'),"
                  "{'__name__':'__main__','__file__':filename})")
        environment = {key: value for key, value in os.environ.items()
                       if key != "PYTHONPATH" and not key.startswith("DYLD_")}
        args = [sys.executable, "-I", "-B", "-c", loader, str(filename), str(source),
                "--session", label, "--server-sha256",
                hashlib.sha256((ROOT / "agent_tools/mcp_server.py").read_bytes()).hexdigest(),
                "--output-root", str(parent), *extra]
        child = subprocess.run(args, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
        self.assertEqual(b"", child.stderr)
        directory = parent / label
        result = json.loads((directory / "client-result.json").read_bytes())
        self.assertIs(result["sdkCallAttempted"], bool(extra))
        self.assertIs(result["automaticReplay"], False)
        return child, result, directory

    def assert_protocol_ready(self, child, result):
        self.assertEqual(0, child.returncode)
        self.assertEqual("protocol_ready", result["state"])
        self.assertIs(result["originalServerTerminalClosed"], True)
        self.assertEqual(0, result["forwardedToolCalls"])

    def test_original_missing_import_path_is_red_and_whole_fixed_client_is_green(self):
        before = FIXTURE / "before.source"
        raw = before.read_bytes()
        provenance = json.loads((FIXTURE / "provenance.json").read_bytes())
        self.assertEqual(provenance["sourceSha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(provenance["sourceBytes"], len(raw))
        with tempfile.TemporaryDirectory(prefix="program-mcp-import-") as temporary:
            parent = Path(temporary).resolve()
            child, result, directory = self.invoke(parent, before, "before")
            with self.assertRaises(AssertionError):
                self.assert_protocol_ready(child, result)
            self.assertEqual(1, child.returncode)
            self.assertEqual("unknown", result["state"])
            self.assertIn("ModuleNotFoundError: No module named 'agent_tools'",
                          (directory / "sdk.stderr").read_text())
            self.assertFalse((directory / "server-intent.json").exists())
            child, result, directory = self.invoke(parent, ROOT / "agent_tools/ssh_program_mcp_client.py", "after")
            self.assert_protocol_ready(child, result)
            self.assertTrue((directory / "initialize.json").is_file())
            inventory = json.loads((directory / "tools.json").read_bytes())
            self.assertIn("ssh_workflow", {tool["name"] for tool in inventory["tools"]})
            terminal = json.loads((directory / "server-terminal.json").read_bytes())
            self.assertEqual({"stdout": True, "stderr": True}, terminal["eof"])
            self.assertEqual(0, terminal["delivery"]["toolCallFrameCount"])

    def test_actual_program_route_refuses_unsupported_language_before_dispatch(self):
        operation = str(uuid.uuid4())
        request = {"operationId": operation, "program": {"language": "powershell",
                   "source": "Write-Output unused", "args": [], "cwd": "/", "targetContext": {}}}
        with tempfile.TemporaryDirectory(prefix="program-mcp-route-") as temporary:
            parent = Path(temporary).resolve()
            path = parent / "request.private.json"
            path.write_text(json.dumps(request)); path.chmod(0o600)
            child, result, directory = self.invoke(parent, ROOT / "agent_tools/ssh_program_mcp_client.py", "refused",
                ("--action", "program-start", "--host", "explicit-peer", "--request-file", str(path)))
            self.assertEqual(0, child.returncode)
            self.assertEqual("rpc_returned", result["state"])
            self.assertIs(result["originalServerTerminalClosed"], True)
            self.assertEqual(1, result["forwardedToolCalls"])
            call = json.loads((directory / "call-result.json").read_bytes())["structuredContent"]
            self.assertEqual("refused", call["state"])
            self.assertEqual("program_language_unsupported", call["reason"])
            self.assertEqual(operation, call["operationId"])
            self.assertIs(call["replayAllowed"], False)
            self.assertFalse((ROOT / ".rag_index/ssh-program-execution" / operation).exists())
            terminal = json.loads((directory / "server-terminal.json").read_bytes())
            self.assertEqual({"stdout": True, "stderr": True}, terminal["eof"])
            self.assertEqual(1, terminal["delivery"]["toolCallFrameCount"])
            self.assertEqual(1, terminal["delivery"]["fullyForwardedToolCallFrameCount"])

    def test_actual_program_dispatch_refuses_windows_before_owner_import(self):
        from agent_tools import mcp_server as server
        fixture = Path(__file__).parent / "fixtures/program_coordinator_guard"
        raw = (fixture / "before.route.source").read_bytes()
        provenance = json.loads((fixture / "provenance.json").read_bytes())
        self.assertEqual(provenance["routeSha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(provenance["routeBytes"], len(raw))
        actual_os_name = os.name
        class CoordinatorOs:
            name = "nt"
            def __getattr__(self, name):
                return getattr(os, name)
        facade = CoordinatorOs()
        attempted = []
        def refuse_owner_import(name):
            attempted.append(name)
            raise ModuleNotFoundError("native POSIX owner unavailable on this coordinator")
        namespace = dict(vars(server))
        namespace.update(os=facade, _agent_module=refuse_owner_import)
        exec(compile(raw, provenance["originalFile"], "exec", dont_inherit=True), namespace)
        original = namespace["_ssh_workflow_impl"]
        operation = str(uuid.uuid4())
        request = {"operationId": operation, "program": {"language": "python3", "source": "print('unused')",
                   "args": [], "cwd": "/", "targetContext": {}}}
        for action in ("program-start", "program-status", "program-collect"):
            fields = {"transfer": request} if action == "program-start" else {"identity": {"operationId": operation}}
            # Execute the exact complete old dispatcher. It tries the POSIX
            # owner before a platform guard and cannot provide a typed refusal.
            with self.assertRaisesRegex(ModuleNotFoundError, "native POSIX owner unavailable"):
                original(action, host="explicit-peer", **fields)
            self.assertEqual(["ssh_program_execution"], attempted)
            attempted.clear()
            # Scope only this module's os binding; pathlib and the process-wide
            # os module retain their actual platform throughout source guards.
            with mock.patch.object(server, "os", facade), mock.patch.object(server, "_agent_module", side_effect=refuse_owner_import):
                result = server._ssh_workflow_impl(action, host="explicit-peer", **fields)
            self.assertEqual({"tool": "ssh_workflow", "ok": False, "state": "refused",
                "reason": "program_coordinator_unsupported", "host": "explicit-peer", "operationId": operation,
                "nativeActionAllowed": False, "replayAllowed": False}, result)
            self.assertEqual([], attempted)
            self.assertEqual(actual_os_name, os.name)


if __name__ == "__main__":
    unittest.main()
