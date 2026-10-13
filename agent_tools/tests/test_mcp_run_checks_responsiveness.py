"""Actual registered FastMCP check dispatch with owned inert command runners."""
import asyncio
import inspect
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

from agent_tools import mcp_server as server


def value(response):
    if isinstance(response, tuple):
        return response[1]
    if isinstance(response, dict):
        return response
    return json.loads(response[0].text)


@unittest.skipIf(server.MCP_SERVER is None, "MCP SDK unavailable; install agent_tools/requirements-mcp.txt")
class RunChecksResponsivenessTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="inert-mcp-checks-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.started = threading.Event()
        self.terminal = threading.Event()
        self.events = []
        self.calls = []
        self.workers = []

        def inert_commands(area, level, commands, planned_fingerprint=None):
            self.workers.append(threading.current_thread())
            self.calls.append((area, level))
            self.events.append("check-started")
            self.started.set()
            try:
                time.sleep(0.35)
                return {"ok": True, "tool": "run_checks", "result": {"inert": True}}
            finally:
                self.events.append("check-terminal")
                self.terminal.set()

        # The actual run_checks function, registered callback, SDK conversion and
        # real managed lease stay intact. No command, repository query or native
        # tool executes; only the owned command boundary and path-list seam vary.
        self.patches = [
            mock.patch.object(server, "REPO_ROOT", self.root),
            mock.patch.object(server, "_changed_paths", return_value=[]),
            mock.patch.object(server, "_commands_for", return_value=[["owned-inert-check"]]),
            mock.patch.object(server, "_snapshot_fingerprint", return_value="a" * 64),
            mock.patch.object(server, "_run_check_commands", side_effect=inert_commands),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    async def start_check(self):
        task = asyncio.create_task(server.MCP_SERVER.call_tool(
            "run_checks", {"area": "agent_tools", "level": "prepush"}))
        limit = time.monotonic() + 5
        while not self.started.is_set():
            self.assertLess(time.monotonic(), limit, "inert check did not start")
            await asyncio.sleep(0.002)
        return task

    async def close_original(self, task):
        # All tests retain the original task/worker even when an assertion fails.
        # A client cancellation is never interpreted as worker cancellation.
        try:
            await task
        except asyncio.CancelledError:
            pass
        self.assertTrue(await asyncio.to_thread(self.terminal.wait, 5))
        for worker in self.workers:
            if worker is not threading.main_thread():
                # Executor threads live until loop shutdown; terminal + released
                # lease is the relevant work completion, not thread termination.
                self.assertTrue(self.terminal.is_set())
        # Runner terminal precedes the core's lease-finally by a few instructions.
        # Observe the actual release, rather than assuming that event is release.
        limit = time.monotonic() + 5
        while True:
            try:
                with server.managed_check_lease.acquire(self.root):
                    pass
                break
            except server.managed_check_lease.ManagedCheckLeaseError as error:
                self.assertEqual("busy", error.state)
                self.assertLess(time.monotonic(), limit, "original lease did not close")
                await asyncio.sleep(0.002)

    async def test_heartbeat_and_dryrun_reply_before_original_check_terminal(self):
        async def heartbeat():
            await asyncio.sleep(0.01)
            self.events.append("heartbeat")

        async def plan():
            await asyncio.sleep(0.02)
            result = value(await server.MCP_SERVER.call_tool("run_checks", {
                "area": "agent_tools", "level": "prepush", "dry_run": True}))
            self.assertTrue(result["ok"])
            self.assertTrue(result["result"]["commands"])
            self.events.append("dryrun-replied")

        heartbeat_task = asyncio.create_task(heartbeat())
        await asyncio.sleep(0)
        original = asyncio.create_task(server.MCP_SERVER.call_tool(
            "run_checks", {"area": "agent_tools", "level": "prepush"}))
        plan_task = asyncio.create_task(plan())
        try:
            await asyncio.gather(heartbeat_task, original, plan_task)
            self.assertLess(self.events.index("heartbeat"), self.events.index("check-terminal"))
            self.assertLess(self.events.index("dryrun-replied"), self.events.index("check-terminal"))
            self.assertEqual(1, len(self.calls))
        finally:
            await self.close_original(original)

    async def test_second_execution_refuses_busy_while_original_worker_runs(self):
        original = await self.start_check()
        try:
            result = value(await server.MCP_SERVER.call_tool(
                "run_checks", {"area": "agent_tools", "level": "prepush"}))
            self.assertFalse(result["ok"])
            self.assertEqual("busy", result["blockers"][0]["state"])
            self.assertFalse(self.terminal.is_set())
            self.assertEqual(1, len(self.calls))
        finally:
            await self.close_original(original)

    async def test_cancelled_caller_keeps_original_worker_and_lease(self):
        original = await self.start_check()
        try:
            self.assertFalse(self.terminal.is_set(), "MCP loop delayed cancellation until worker ended")
            original.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await original
            with self.assertRaises(server.managed_check_lease.ManagedCheckLeaseError) as caught:
                with server.managed_check_lease.acquire(self.root):
                    pass
            self.assertEqual("busy", caught.exception.state)
            self.assertEqual(1, len(self.calls))
        finally:
            await self.close_original(original)

    async def test_callable_schema_cli_core_and_source_refusal_are_unchanged(self):
        reference = server.FastMCP("inert-reference-core")
        reference.tool()(server.run_checks)
        registered = next(t for t in await server.MCP_SERVER.list_tools() if t.name == "run_checks")
        expected = next(t for t in await reference.list_tools() if t.name == "run_checks")
        self.assertEqual(expected.inputSchema, registered.inputSchema)
        self.assertEqual(expected.outputSchema, registered.outputSchema)
        self.assertEqual(expected.description, registered.description)
        self.assertFalse(inspect.iscoroutinefunction(server.run_checks))
        self.assertFalse(server.run_checks(level="not-a-level")["ok"])
        refused = {"ok": False, "tool": "run_checks", "blockers": [{
            "phase": "check-source", "state": "changed-after-load"}]}
        with mock.patch.object(server, "_check_runner_source_error", return_value=refused):
            self.assertEqual(refused, value(await server.MCP_SERVER.call_tool(
                "run_checks", {"area": "agent_tools", "level": "prepush"})))
        self.assertEqual([], self.calls)


if __name__ == "__main__":
    unittest.main(verbosity=2)
