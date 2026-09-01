from __future__ import annotations

import inspect
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_tools import mcp_server

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:  # The base development Python may omit agent-only dependencies.
    ClientSession = None  # type: ignore[assignment]
    StdioServerParameters = None  # type: ignore[assignment]
    stdio_client = None  # type: ignore[assignment]


def command_result(*, stdout: str = "", stderr: str = "", ok: bool = True) -> dict[str, object]:
    return {
        "ok": ok,
        "command": "mock command",
        "returncode": 0 if ok else 1,
        "stdout": stdout,
        "stderr": stderr,
    }


class McpSurfaceTest(unittest.TestCase):
    def test_public_tools_do_not_accept_repository_root(self) -> None:
        tools = (
            mcp_server.prepare_start,
            mcp_server.docs,
            mcp_server.change_impact,
            mcp_server.workflow_status,
            mcp_server.run_checks,
            mcp_server.git_workflow,
        )
        for tool in tools:
            self.assertNotIn("root", inspect.signature(tool).parameters)

    def test_critical_instructions_are_at_start(self) -> None:
        prefix = mcp_server.SERVER_INSTRUCTIONS[:512]
        self.assertIn("prepare_start", prefix)
        self.assertIn("Never stop the VPN", prefix)
        self.assertIn("exact-SHA CI", prefix)

    def test_commit_path_validation_rejects_broad_or_generated_paths(self) -> None:
        invalid = [
            ["."],
            ["../outside"],
            ["/tmp/file"],
            [":(glob)**"],
            ["docs/*.md"],
            [".rag_index/prepush_receipt.json"],
            ["app/build/output.apk"],
            ["desktopApp/src/main/resources/bin/sing-box"],
        ]
        for paths in invalid:
            self.assertIsNotNone(mcp_server._validate_commit_paths(paths), paths)
        self.assertIsNone(mcp_server._validate_commit_paths(["AGENTS.md", "agent_tools"]))

    def test_required_workflow_manifest_matches_workflow_names(self) -> None:
        workflows = mcp_server._required_workflows()
        self.assertEqual(
            {
                "Fast Checks",
                "Android Release APK",
                "Linux Desktop Package",
                "Windows Desktop Package",
                "macOS Desktop Package",
            },
            {entry["name"] for entry in workflows},
        )
        for entry in workflows:
            workflow_path = mcp_server.REPO_ROOT / ".github" / "workflows" / entry["workflow"]
            self.assertTrue(workflow_path.is_file(), workflow_path)
            first_name = next(
                line.removeprefix("name:").strip()
                for line in workflow_path.read_text(encoding="utf-8").splitlines()
                if line.startswith("name:")
            )
            self.assertEqual(entry["name"], first_name)

    @mock.patch.object(mcp_server.docs_assistant, "build_docs_index")
    @mock.patch.object(mcp_server, "_ahead_behind", return_value=(0, 1, None))
    @mock.patch.object(mcp_server, "_repo_state")
    @mock.patch.object(mcp_server, "_run")
    def test_prepare_start_blocks_dirty_behind_main(
        self,
        run: mock.Mock,
        state: mock.Mock,
        _ahead: mock.Mock,
        build: mock.Mock,
    ) -> None:
        state.return_value = {"branch": "main", "dirty": True}
        run.return_value = command_result()

        result = mcp_server.prepare_start("change UI")

        self.assertFalse(result["ok"])
        self.assertIn("behind", result["summary"])
        build.assert_not_called()


@unittest.skipIf(ClientSession is None, "mcp dependency is not installed in this Python")
class McpProtocolTest(unittest.IsolatedAsyncioTestCase):
    async def test_stdio_server_lists_the_six_repository_tools(self) -> None:
        parameters = StdioServerParameters(
            command=sys.executable,
            args=[str(Path(mcp_server.__file__).resolve()), "serve"],
            cwd=str(mcp_server.REPO_ROOT),
        )
        async with stdio_client(parameters) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()
                result = await session.list_tools()

        self.assertEqual(
            {
                "prepare_start",
                "docs",
                "change_impact",
                "workflow_status",
                "run_checks",
                "git_workflow",
            },
            {tool.name for tool in result.tools},
        )


class FingerprintTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.email", "tests@example.com"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.name", "Agent Tests"], cwd=self.root, check=True)
        (self.root / "tracked.txt").write_text("one\n", encoding="utf-8")
        subprocess.run(["git", "add", "tracked.txt"], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "initial"], cwd=self.root, check=True)
        self.root_patch = mock.patch.object(mcp_server, "REPO_ROOT", self.root)
        self.root_patch.start()

    def tearDown(self) -> None:
        self.root_patch.stop()
        self.temporary.cleanup()

    def test_fingerprint_survives_commit_but_changes_with_content(self) -> None:
        (self.root / "tracked.txt").write_text("two\n", encoding="utf-8")
        before = mcp_server._snapshot_fingerprint()
        subprocess.run(["git", "add", "tracked.txt"], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "update"], cwd=self.root, check=True)
        self.assertEqual(before, mcp_server._snapshot_fingerprint())

        (self.root / "tracked.txt").write_text("three\n", encoding="utf-8")
        self.assertNotEqual(before, mcp_server._snapshot_fingerprint())

    def test_untracked_content_is_fingerprinted(self) -> None:
        before = mcp_server._snapshot_fingerprint()
        (self.root / "new.txt").write_text("new\n", encoding="utf-8")
        self.assertNotEqual(before, mcp_server._snapshot_fingerprint())

    def test_fingerprint_survives_committed_addition_and_deletion(self) -> None:
        (self.root / "tracked.txt").unlink()
        (self.root / "replacement.txt").write_text("replacement\n", encoding="utf-8")
        before = mcp_server._snapshot_fingerprint()
        subprocess.run(["git", "add", "--all"], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "replace"], cwd=self.root, check=True)
        self.assertEqual(before, mcp_server._snapshot_fingerprint())


class WorkflowWatchTest(unittest.TestCase):
    def test_watcher_uses_only_exact_sha_and_latest_run(self) -> None:
        sha = "a" * 40
        required = [
            {"name": "Fast Checks", "workflow": "fast-checks.yml"},
            {"name": "Android Release APK", "workflow": "android-release.yml"},
        ]
        payload = [
            {
                "databaseId": 1,
                "workflowName": "Fast Checks",
                "status": "completed",
                "conclusion": "failure",
                "url": "https://example.invalid/old",
                "headSha": sha,
            },
            {
                "databaseId": 3,
                "workflowName": "Fast Checks",
                "status": "completed",
                "conclusion": "success",
                "url": "https://example.invalid/new",
                "headSha": sha,
            },
            {
                "databaseId": 4,
                "workflowName": "Android Release APK",
                "status": "completed",
                "conclusion": "success",
                "url": "https://example.invalid/android",
                "headSha": sha,
            },
            {
                "databaseId": 9,
                "workflowName": "Fast Checks",
                "status": "completed",
                "conclusion": "success",
                "url": "https://example.invalid/wrong-sha",
                "headSha": "b" * 40,
            },
        ]
        with (
            mock.patch.object(mcp_server, "_required_workflows", return_value=required),
            mock.patch.object(mcp_server, "_run", return_value=command_result(stdout=json.dumps(payload))) as run,
            mock.patch.object(mcp_server, "_write_json"),
        ):
            result = mcp_server._watch_required_workflows(sha)

        self.assertTrue(result["ok"])
        self.assertEqual(3, result["result"]["workflows"]["Fast Checks"]["databaseId"])
        called_command = run.call_args.args[0]
        self.assertEqual(sha, called_command[called_command.index("--commit") + 1])


if __name__ == "__main__":
    unittest.main()
