"""A repeated lease cancel leaves no temporary file next to the retained marker.

Natively (2026-11-09, lease e78a3ca9 on clone 9059be98, desktop alias
windows-raw9059be98-desktop-v1) the CLI and MCP cancel repeats both answered cancelled,
terminal and restored, as they should, but each left
e78a3ca9-...cancelled.json.<uuid>.tmp in .rag_index/readiness-leases/admissions/: the
repeat published the marker again, and the create-only link refused after the
temporary copy was written. Both cancel paths run under the admission lock.
"""
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from agent_tools import readiness_lease_workflow as workflow
from agent_tools.tests import test_readiness_lease_workflow as android

OPERATION = "e78a3ca9-e449-42db-b9cb-15c98ce29669"
TERMINAL = {"operationId": OPERATION, "replayAllowed": False, "state": "cancelled", "jobState": "terminal",
            "restored": True, "nextAction": "none", "reason": "original_lease_cancelled"}


class Executor:
    """The ended original lease: cancelled, restored and terminal, as natively."""
    provider = "raw-qemu-windows"

    def observe(self, operation, *, deadline=None):
        return dict(TERMINAL)

    def cancel(self, operation, *, deadline=None):
        raise AssertionError("an ended lease is never cancelled again")


def temporary(directory):
    return sorted(path.name for path in Path(directory).iterdir() if path.name.endswith(".tmp"))


@unittest.skipUnless(os.name == "posix", "POSIX private-file custody")
class ExternalCancelRepeatTests(unittest.TestCase):
    def test_e78a3ca9_cancel_repeats_RED_temporary_files_GREEN_none(self):
        executor = Executor()
        value = {"schemaVersion": 2, "fixtureId": "windows-raw9059be98-desktop-v1", "operationId": OPERATION,
                 "provider": "raw-qemu-windows", "executor": {"provider": "raw-qemu-windows"}}
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(workflow.fixtures, "lease_executor_from_snapshot", return_value=executor):
            state = Path(directory)
            state.chmod(0o700)
            answers = [workflow._external_original(state, state, "cancel", value, {}, deadline=time.monotonic() + 30)
                       for _ in range(3)]
            self.assertEqual([], temporary(state), "a cancel repeat left its temporary copy behind")
            self.assertTrue((state / (OPERATION + ".cancelled.json")).exists())
        self.assertTrue(all(answer["state"] == "cancelled" for answer in answers))


@unittest.skipUnless(os.name == "posix", "POSIX private-file custody")
class AndroidCancelRepeatTests(android.LeaseWorkflowTests):
    """The schema 1 path: a real original with its controlled owner."""

    def test_cancel_repeats_RED_temporary_files_GREEN_none(self):
        operation, setting, _, _, _ = self.original()
        self.wait(operation, {"active"})
        for _ in range(3):
            self.call("cancel", operation)
        result = self.wait(operation, {"cancelled"})
        self.assertTrue(result["restored"])
        state, _ = workflow._paths(self.root, self.fixture, create=False)
        self.assertEqual([], temporary(state), "a cancel repeat left its temporary copy behind")


# Only the cancel repeat runs here; the inherited lease workflow cases run in their own module.
for _name in [name for name in dir(android.LeaseWorkflowTests) if name.startswith("test_")]:
    setattr(AndroidCancelRepeatTests, _name, None)


if __name__ == "__main__":
    unittest.main()
