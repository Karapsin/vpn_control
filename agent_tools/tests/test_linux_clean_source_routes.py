"""Actual MCP Linux build routes preserve coordinator ownership with clean source."""
from __future__ import annotations

import copy
import unittest
from unittest import mock

from agent_tools import linux_package_fixture_build as build
from agent_tools import mcp_server as server

REQUEST = {"sourceSha": "a" * 40, "baseVersion": "2.2.1", "targetVersion": "2.2.2",
           "correlationId": "11111111-1111-4111-8111-111111111111"}
SOURCE_ROOT = "/private/clean source checkout"


class LinuxCleanSourceRouteTests(unittest.TestCase):
    def setUp(self):
        # Keep actual adapter discovery while isolating source freshness from
        # module edits made by concurrent implementation owners in this suite.
        boot = mock.patch.object(server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        boot.start()
        self.addCleanup(boot.stop)

    def test_clean_source_forwards_coordinator_and_unchanged_original_request(self):
        for action in ("preflight", "start"):
            with self.subTest(action=action), mock.patch.object(build, action, return_value={"state": "ready"}) as dispatch:
                inputs = {**REQUEST, "sourceRoot": SOURCE_ROOT}
                original = copy.deepcopy(inputs)
                result = server._vm_workflow_impl("linux-package-fixture-build-" + action, inputs)
                self.assertTrue(result["ok"])
                dispatch.assert_called_once_with(server.REPO_ROOT, REQUEST, source_root=SOURCE_ROOT)
                self.assertEqual(original, inputs)

    def test_legacy_request_dispatches_without_source_root_keyword(self):
        for action in ("preflight", "start"):
            with self.subTest(action=action), mock.patch.object(build, action, return_value={"state": "ready"}) as dispatch:
                result = server._vm_workflow_impl("linux-package-fixture-build-" + action, dict(REQUEST))
                self.assertTrue(result["ok"])
                dispatch.assert_called_once_with(server.REPO_ROOT, REQUEST)

    def test_invalid_source_root_is_rejected_without_dispatch(self):
        invalid = ("relative/source", "", "/private/source\0foreign", 123, None, {},
                   "/" + "x" * 4096)
        for action in ("preflight", "start"):
            for value in invalid:
                with self.subTest(action=action, value=value), mock.patch.object(build, action) as dispatch:
                    result = server._vm_workflow_impl("linux-package-fixture-build-" + action,
                                                     {**REQUEST, "sourceRoot": value})
                    self.assertFalse(result["ok"])
                    dispatch.assert_not_called()

    def test_extra_fields_are_rejected_even_with_valid_source_root(self):
        for action in ("preflight", "start"):
            with self.subTest(action=action), mock.patch.object(build, action) as dispatch:
                result = server._vm_workflow_impl("linux-package-fixture-build-" + action,
                                                 {**REQUEST, "sourceRoot": SOURCE_ROOT, "retry": True})
                self.assertFalse(result["ok"])
                dispatch.assert_not_called()

    def test_status_and_collect_reject_source_root_without_dispatch(self):
        for action in ("status", "collect"):
            with self.subTest(action=action), mock.patch.object(build, action) as dispatch:
                result = server._vm_workflow_impl("linux-package-fixture-build-" + action,
                                                 {"correlationId": REQUEST["correlationId"],
                                                  "sourceRoot": SOURCE_ROOT})
                self.assertFalse(result["ok"])
                dispatch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
