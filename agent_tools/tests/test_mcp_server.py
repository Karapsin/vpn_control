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
    def test_unbounded_internal_command_output_is_not_truncated(self) -> None:
        expected = "x" * (mcp_server.MAX_OUTPUT_CHARS + 100)

        bounded = mcp_server._run([sys.executable, "-c", f"print('{expected}')"])
        unbounded = mcp_server._run(
            [sys.executable, "-c", f"print('{expected}')"],
            output_limit=None,
        )

        self.assertTrue(str(bounded["stdout"]).endswith("...[truncated]"))
        self.assertEqual(expected, unbounded["stdout"])

    def test_public_tools_do_not_accept_repository_root(self) -> None:
        tools = (
            mcp_server.prepare_start,
            mcp_server.docs,
            mcp_server.change_impact,
            mcp_server.workflow_status,
            mcp_server.run_checks,
            mcp_server.version_bump,
            mcp_server.release_workflow,
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
            self.assertEqual("push", entry["event"])
            self.assertEqual(["success"], entry["allowed_conclusions"])
        self.assertEqual({"VPN Integration"}, mcp_server._advisory_workflow_names())

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
        state.return_value = {"branch": "dev", "dirty": True}
        run.return_value = command_result()

        result = mcp_server.prepare_start("change UI")

        self.assertFalse(result["ok"])
        self.assertIn("behind", result["summary"])
        build.assert_not_called()


@unittest.skipIf(ClientSession is None, "mcp dependency is not installed in this Python")
class McpProtocolTest(unittest.IsolatedAsyncioTestCase):
    async def test_stdio_server_lists_the_eight_repository_tools(self) -> None:
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
                "version_bump",
                "release_workflow",
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


class VersionPolicyTest(unittest.TestCase):
    def test_four_part_version_carries_with_base_twenty_components(self) -> None:
        self.assertEqual("1.3.7.0", mcp_server._increment_version("1.3.6.19"))
        self.assertEqual("1.4.0.0", mcp_server._increment_version("1.3.19.19"))
        self.assertEqual("2.0.0.0", mcp_server._increment_version("1.19.19.19"))

    def test_invalid_versions_are_rejected(self) -> None:
        for value in ("1.2.3", "1.2.3.x", "1.2.3.20"):
            with self.assertRaises(ValueError, msg=value):
                mcp_server._increment_version(value)

    def test_manual_release_is_never_an_automatic_workflow_event(self) -> None:
        workflow = (mcp_server.REPO_ROOT / ".github/workflows/release-publish.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("workflow_run:", workflow)
        self.assertNotRegex(workflow, r"(?m)^\s+push:")

    def test_tenth_unreleased_bullet_rolls_version_metadata_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            changelog = root / "docs/CHANGELOG.md"
            changelog.parent.mkdir()
            (root / "gradle.properties").write_text("vpnControlVersion=1.3.6.19\n", encoding="utf-8")
            (root / "README.md").write_text("**Version:** `1.3.6.19`\n", encoding="utf-8")
            changelog.write_text(
                "# Changelog\n\n## Unreleased\n\n"
                + "\n".join(f"- Existing change {index}." for index in range(1, 10))
                + "\n\n## 1.3.6.19 - 2026-01-01\n\n- Previous.\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(mcp_server, "REPO_ROOT", root),
                mock.patch.object(mcp_server, "CHANGELOG_PATH", changelog),
            ):
                result = mcp_server.version_bump("Tenth change")

            self.assertTrue(result["ok"])
            self.assertEqual("bump", result["result"]["decision"])
            self.assertIn("vpnControlVersion=1.3.7.0", (root / "gradle.properties").read_text())
            self.assertIn("**Version:** `1.3.7.0`", (root / "README.md").read_text())
            updated = changelog.read_text(encoding="utf-8")
            self.assertIn("## 1.3.7.0 -", updated)
            self.assertIn("- Tenth change.", updated)
            self.assertEqual([], mcp_server._unreleased_bullets(updated))

    def test_below_threshold_only_adds_unreleased_note(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            changelog = root / "docs/CHANGELOG.md"
            changelog.parent.mkdir()
            (root / "gradle.properties").write_text("vpnControlVersion=1.2.3.4\n", encoding="utf-8")
            (root / "README.md").write_text("**Version:** `1.2.3.4`\n", encoding="utf-8")
            changelog.write_text(
                "# Changelog\n\n## Unreleased\n\n## 1.2.3.4 - 2026-01-01\n\n- Previous.\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(mcp_server, "REPO_ROOT", root),
                mock.patch.object(mcp_server, "CHANGELOG_PATH", changelog),
            ):
                result = mcp_server.version_bump("New behavior")

            self.assertTrue(result["ok"])
            self.assertEqual("unreleased", result["result"]["decision"])
            self.assertEqual("vpnControlVersion=1.2.3.4\n", (root / "gradle.properties").read_text())
            self.assertEqual(["- New behavior."], mcp_server._unreleased_bullets(changelog.read_text()))

class WorkflowWatchTest(unittest.TestCase):
    def test_watcher_uses_only_exact_sha_and_latest_run(self) -> None:
        sha = "a" * 40
        required = [
            {
                "name": "Fast Checks",
                "workflow": "fast-checks.yml",
                "event": "push",
                "allowed_conclusions": ["success"],
            },
            {
                "name": "Android Release APK",
                "workflow": "android-release.yml",
                "event": "push",
                "allowed_conclusions": ["success"],
            },
        ]
        payload = [
            {
                "databaseId": 1,
                "workflowName": "Fast Checks",
                "event": "push",
                "status": "completed",
                "conclusion": "failure",
                "url": "https://example.invalid/old",
                "headSha": sha,
            },
            {
                "databaseId": 3,
                "workflowName": "Fast Checks",
                "event": "push",
                "status": "completed",
                "conclusion": "success",
                "url": "https://example.invalid/new",
                "headSha": sha,
            },
            {
                "databaseId": 4,
                "workflowName": "Android Release APK",
                "event": "push",
                "status": "completed",
                "conclusion": "success",
                "url": "https://example.invalid/android",
                "headSha": sha,
            },
            {
                "databaseId": 9,
                "workflowName": "Fast Checks",
                "event": "push",
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
        self.assertEqual(1, result["result"]["poll_count"])
        self.assertEqual(1, len(result["command_results"]))
        called_command = run.call_args.args[0]
        self.assertEqual(sha, called_command[called_command.index("--commit") + 1])


if __name__ == "__main__":
    unittest.main()
