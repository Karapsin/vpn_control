"""A stale check daemon must not run commands or publish validation receipts."""
from contextlib import nullcontext
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from agent_tools import mcp_server as server


class ManagedCheckSourceFreshnessTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.source = Path(directory.name) / "loaded-runner.py"
        self.source.write_bytes(b"original check runner\n")
        self.pins = {self.source: hashlib.sha256(self.source.read_bytes()).hexdigest()}
        context = patch.object(server, "_CHECK_RUNNER_SOURCE_DIGESTS", self.pins, create=True)
        context.start()
        self.addCleanup(context.stop)

    def assert_refused(self, result, state):
        self.assertIs(result["ok"], False)
        self.assertEqual(result["blockers"], [{"phase": "check-source", "state": state}])
        self.assertIn("mcp_tool.sh", result["summary"])

    def entry(self, *, dry_run=False):
        inspect = Mock(return_value=[])
        lease = Mock(return_value=nullcontext())
        child = Mock(return_value={"ok": True})
        with patch.object(server, "_changed_paths", inspect), \
                patch.object(server, "_infer_area", return_value="docs"), \
                patch.object(server, "_commands_for", return_value=[["inert"]]), \
                patch.object(server.managed_check_lease, "acquire", lease), \
                patch.object(server, "_run_check_commands", child):
            result = server.run_checks(level="focused", dry_run=dry_run)
        return result, inspect, lease, child

    def test_changed_loaded_source_refuses_before_inspection_or_lease(self):
        self.source.write_bytes(b"changed check runner\n")
        result, inspect, lease, child = self.entry()
        self.assert_refused(result, "changed-after-load")
        inspect.assert_not_called()
        lease.assert_not_called()
        child.assert_not_called()

    def test_missing_loaded_source_refuses_before_execution(self):
        self.source.unlink()
        result, inspect, lease, child = self.entry()
        self.assert_refused(result, "source-unavailable")
        inspect.assert_not_called()
        lease.assert_not_called()
        child.assert_not_called()

    def test_dry_run_cannot_advertise_a_stale_plan(self):
        self.source.write_bytes(b"changed check runner\n")
        result, inspect, lease, child = self.entry(dry_run=True)
        self.assert_refused(result, "changed-after-load")
        inspect.assert_not_called()
        lease.assert_not_called()
        child.assert_not_called()

    def test_unchanged_content_remains_admitted_after_touch(self):
        self.source.touch()
        result, inspect, lease, child = self.entry()
        self.assertIs(result["ok"], True)
        inspect.assert_called_once_with()
        lease.assert_called_once_with(server.REPO_ROOT)
        child.assert_called_once()

    def test_source_change_between_commands_stops_remaining_work(self):
        def run(command, **kwargs):
            self.source.write_bytes(b"changed check runner\n")
            return {"ok": True, "command": command, "returncode": 0}
        with patch.object(server, "_run", side_effect=run) as child:
            result = server._run_check_commands("docs", "focused", [["first"], ["second"]])
        self.assert_refused(result, "changed-after-load")
        self.assertEqual(child.call_count, 1)
        self.assertEqual(len(result["command_results"]), 1)

    def test_final_source_change_blocks_prepush_receipt(self):
        def run(command, **kwargs):
            self.source.write_bytes(b"changed check runner\n")
            return {"ok": True, "command": command, "returncode": 0}
        with patch.object(server, "_snapshot_fingerprint", return_value="a" * 64), \
                patch.object(server, "_run", side_effect=run), \
                patch.object(server, "_git_stdout", return_value="b" * 40), \
                patch.object(server, "_write_json") as publish:
            result = server._run_check_commands("docs", "prepush", [["first"]])
        self.assert_refused(result, "changed-after-load")
        self.assertEqual(len(result["command_results"]), 1)
        publish.assert_not_called()


if __name__ == "__main__":
    unittest.main()
