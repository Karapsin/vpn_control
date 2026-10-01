from __future__ import annotations

import subprocess
import unittest

from agent_tools import mcp_server


class UnittestDiscoveryRegressionTest(unittest.TestCase):
    def test_repository_top_level_avoids_scripts_module_collision(self) -> None:
        command = [
            mcp_server.AGENT_TEST_PYTHON,
            "-m",
            "unittest",
            "discover",
            "-s",
            "agent_tools/tests",
            "-k",
            "test_status_binds_title_sha_unique_run_and_artifact",
        ]
        missing_top_level = subprocess.run(
            command,
            cwd=mcp_server.REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(0, missing_top_level.returncode)
        self.assertIn("module incorrectly imported", missing_top_level.stderr)
        self.assertIn("/scripts", missing_top_level.stderr)

        passing = subprocess.run(
            [*command, "-t", "."],
            cwd=mcp_server.REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, passing.returncode, passing.stderr)

        expected = [*command[:4], "-s", "agent_tools/tests", "-t", "."]
        for area, level in (("agent_tools", "focused"), ("agent_tools", "prepush")):
            with self.subTest(level=level):
                discovered = [
                    candidate
                    for candidate in mcp_server._commands_for(area, level)
                    if "discover" in candidate and "agent_tools/tests" in candidate
                ]
                self.assertEqual([expected], discovered)

