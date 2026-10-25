"""Portable POSIX custody regression for the complete private parent caller.

The retained producers are public source bytes, never executable authority in
this test. MCP is replaced before its context can start; process and network
dispatch are forbidden. The caller still uses real SourceSession and private
Directory/Snapshot guards on actual files.
"""
from contextlib import ExitStack, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).with_name("fixtures") / "tart_macos_parent_caller"


class DispatchFenced(RuntimeError):
    pass


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
                     "the Mac parent uses POSIX held-directory custody")
class ParentCallerTest(unittest.TestCase):
    def _exercise(self, name, *, change_producer=False):
        from agent_tools.source_module_loader import SourceSession

        provenance = json.loads((FIXTURE / "provenance.json").read_text())
        for filename, expected in provenance["files"].items():
            self.assertEqual(hashlib.sha256((FIXTURE / filename).read_bytes()).hexdigest(), expected)
        original_path = tuple(sys.path)
        sdk_entries = []
        sessions = []
        errors = []
        with tempfile.TemporaryDirectory(prefix="mac-parent-caller-") as temporary, ExitStack() as held:
            # Darwin's default temporary path can contain /var -> /private/var.
            # The actual no-follow guard gets its canonical existing spelling.
            directory = Path(temporary).resolve()
            os.chmod(directory, 0o700)
            producer_dir = directory / "producers"
            producer_dir.mkdir(mode=0o700)
            parent = producer_dir / "parent.py"
            source = (FIXTURE / name).read_bytes()
            parent.write_bytes(source)
            parent.chmod(0o600)
            copies = {
                "macos-known-session-wake-review.inert.py": "dependencies/wake.source",
                "macos-unlock-nonce-public-preflight.inert.py": "dependencies/benchmark.source",
                "macos-normal-lease.py": "dependencies/lease-evidence.source",
                "macos-public-nonce-wake-plan.prepared-v3.json": "dependencies/plan.json",
            }
            for filename, captured in copies.items():
                path = producer_dir / filename
                path.write_bytes((FIXTURE / captured).read_bytes())
                path.chmod(0o600)
            run_root = directory / "run"
            run_root.mkdir(mode=0o700)
            literal = run_root / "native-iopm-v2-qualification-64faf820-ed64-44fc-a4f0-bfb8f31c2241"
            literal.mkdir(mode=0o700)
            literal_file = literal / "cancel-death-and-original-evidence-v2.inert.py"
            literal_file.write_bytes((FIXTURE / "dependencies/original-evidence.source").read_bytes())
            literal_file.chmod(0o600)

            namespace = {"__file__": str(parent), "__name__": "retained_parent_caller"}
            try:
                # Executes the entire unchanged original module. __main__ is
                # false; main() below receives only controlled filesystem data.
                exec(compile(source, str(parent), "exec", dont_inherit=True), namespace)
                namespace["ROOT"], namespace["RUN"] = ROOT, run_root
                namespace["time"] = types.SimpleNamespace(
                    time=lambda: namespace["APPROVAL_FIRST_OBSERVED"] + 30,
                    monotonic=lambda: 1000.0,
                )

                def source_session(*args, **kwargs):
                    session = SourceSession(*args, **kwargs)
                    sessions.append(session)
                    load = session.load

                    def controlled_load(entry):
                        module = load(entry)
                        if entry == "durable_remote_job":
                            # Host boot is an input to the caller, not a reason
                            # to execute sysctl in a portable routine check.
                            held.enter_context(mock.patch.object(module, "_boot", return_value="test-host-boot"))
                        return module

                    session.load = controlled_load
                    return session

                namespace["SourceSession"] = source_session
                sdk = types.ModuleType("mcp")
                sdk.__path__ = []
                sdk.ClientSession = mock.Mock(side_effect=AssertionError("client must not start"))
                sdk.StdioServerParameters = lambda **kwargs: kwargs
                client = types.ModuleType("mcp.client")
                client.__path__ = []
                stdio = types.ModuleType("mcp.client.stdio")

                def fenced(parameters, **kwargs):
                    sdk_entries.append(parameters["args"])
                    raise DispatchFenced("routine check forbids MCP dispatch")

                stdio.stdio_client = fenced
                held.enter_context(mock.patch.dict(sys.modules, {
                    "mcp": sdk, "mcp.client": client, "mcp.client.stdio": stdio,
                }))
                process = held.enter_context(mock.patch.object(subprocess, "Popen",
                    side_effect=AssertionError("routine check forbids subprocess dispatch")))
                network = held.enter_context(mock.patch.object(socket, "create_connection",
                    side_effect=AssertionError("routine check forbids network dispatch")))
                held.enter_context(mock.patch.object(sys, "argv", [str(parent), "--execute-plan", namespace["PLAN_SHA"]]))

                def trace(frame, event, argument):
                    if frame.f_code.co_filename == str(parent):
                        if event == "exception" and argument[0] is AttributeError:
                            errors.append(str(argument[1]))
                        if (change_producer and event == "line"
                                and source.decode().splitlines()[frame.f_lineno - 1].strip()
                                == "return asyncio.run(pipeline())"):
                            target = producer_dir / "macos-normal-lease.py"
                            target.write_bytes(target.read_bytes() + b"\n# controlled source change\n")
                    return trace

                old_trace = sys.gettrace()
                output = io.StringIO()
                with redirect_stdout(output):
                    sys.settrace(trace)
                    try:
                        result = namespace["main"]()
                    finally:
                        sys.settrace(old_trace)
                self.assertEqual(result, 1)  # The SDK fence is deliberately terminal in this test.
                folder, = run_root.glob("native-public-nonce-parent-*")
                receipts = {path.name: json.loads(path.read_text()) for path in folder.glob("*.json")}
                self.assertEqual(sdk.ClientSession.call_count, 0)
                process.assert_not_called()
                network.assert_not_called()
                self.assertTrue(sessions and all(session.closed for session in sessions))
                return receipts, sdk_entries, errors
            finally:
                sys.path[:] = original_path

    def test_whole_before_red_and_current_green_without_native_dispatch(self):
        before, before_sdk, errors = self._exercise("parent.before.source")
        self.assertEqual(before["phase-failure.json"]["failureClass"], "AttributeError")
        self.assertTrue(any("function" in error and "guard" in error for error in errors))
        self.assertFalse(before["complete.json"]["acquireSubmittedOnce"])
        self.assertNotIn("acquire-dispatch-unknown.json", before)
        self.assertEqual(before_sdk, [])

        current, current_sdk, errors = self._exercise("parent.current.source")
        self.assertEqual(errors, [])
        self.assertEqual(current["phase-failure.json"]["failureClass"], "DispatchFenced")
        self.assertTrue(current["complete.json"]["acquireSubmittedOnce"])
        self.assertTrue(current["complete.json"]["allProducerActorsAbsent"])
        self.assertEqual(current["complete.json"]["producerActors"], [])
        # One fenced acquire, then original-only status in the finally block.
        self.assertEqual(len(current_sdk), 2)
        self.assertEqual(current["01-readiness-lease-acquire.request.json"]["inputs"]["ttlSeconds"], 180)
        self.assertEqual(current["02-readiness-lease-status.request.json"]["inputs"]["operationId"],
                         current["intent.json"]["leaseOperationId"])
        self.assertNotIn("cancel-dispatch-unknown.json", current)

    def test_real_captured_producer_change_stops_before_acquire(self):
        receipts, sdk, errors = self._exercise("parent.current.source", change_producer=True)
        self.assertEqual(errors, [])
        self.assertEqual(receipts["phase-failure.json"]["failureClass"], "ValueError")
        self.assertFalse(receipts["complete.json"]["acquireSubmittedOnce"])
        self.assertNotIn("acquire-dispatch-unknown.json", receipts)
        self.assertEqual(sdk, [])


if __name__ == "__main__":
    unittest.main()
