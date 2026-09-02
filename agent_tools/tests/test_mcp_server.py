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
            mcp_server.visual_workflow,
            mcp_server.visual_review,
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
        manifest = json.loads(mcp_server.REQUIRED_WORKFLOWS_PATH.read_text(encoding="utf-8"))
        release_only = manifest["branches"]["dev"]["classified_non_push_workflows"]
        self.assertIn("Visual Capture", {entry["name"] for entry in release_only})
        self.assertEqual(
            {"vpn-control/agent-visual"},
            {entry["context"] for entry in manifest["branches"]["dev"]["release_statuses"]},
        )

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
    async def test_stdio_server_lists_repository_tools(self) -> None:
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
                "visual_workflow",
                "visual_review",
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
        self.assertIn("vpn-control/agent-visual", workflow)
        self.assertIn("visual_receipt_sha256", workflow)

    def test_release_merge_dispatches_vpn_and_starts_agent_visual_review(self) -> None:
        sha = "a" * 40
        command_results = [
            command_result(),
            command_result(stdout=sha),
            command_result(stdout=sha),
            command_result(),
            command_result(),
            command_result(),
            command_result(),
            command_result(),
        ]
        with (
            mock.patch.object(mcp_server, "_repo_state", return_value={"branch": "dev", "dirty": False}),
            mock.patch.object(mcp_server, "_run", side_effect=command_results) as run,
            mock.patch.object(mcp_server, "_git_stdout", return_value=sha),
            mock.patch.object(
                mcp_server,
                "_visual_command",
                return_value={"ok": True, "result": {"target_sha": sha}, "command_results": []},
            ) as visual,
        ):
            result = mcp_server._merge_dev_for_release()

        self.assertTrue(result["ok"])
        commands = [call.args[0] for call in run.call_args_list]
        self.assertTrue(any("vpn-integration.yml" in command for command in commands))
        self.assertFalse(any("visual-regression.yml" in command for command in commands))
        self.assertIn(f"target_sha={sha}", commands[-1])
        visual.assert_called_once()
        self.assertIn("--release", visual.call_args.args[0])

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
    def test_visual_attestation_binds_receipt_manifest_and_commit_status(self) -> None:
        sha = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            visual_root = root / ".rag_index/visual-review-receipts"
            visual_root.mkdir(parents=True)
            test_root = root / "visual-tests"
            test_root.mkdir()
            manifest = test_root / "scenes.json"
            environments = test_root / "environments.json"
            manifest.write_text(
                json.dumps({"schema_version": 1, "scenes": [{"id": "main", "platforms": ["android"]}]}),
                encoding="utf-8",
            )
            environments.write_text("{}\n", encoding="utf-8")
            payload = {
                "schema_version": 1,
                "target_sha": sha,
                "release": True,
                "platforms": ["android", "linux", "windows", "macos"],
                "manifest_sha256": mcp_server._file_digest(manifest),
                "environments_sha256": mcp_server._file_digest(environments),
                "scenes": {
                    "android/main": {"automation": "pass", "review": "pass"},
                },
            }
            digest = mcp_server._json_digest(payload)
            (visual_root / f"{sha}.json").write_text(
                json.dumps({**payload, "receipt_sha256": digest}), encoding="utf-8",
            )
            statuses = [
                {
                    "context": "vpn-control/agent-visual",
                    "state": "success",
                    "description": f"Agent reviewed 1/1 scenes; receipt {digest[:16]}",
                },
            ]
            with (
                mock.patch.object(mcp_server, "REPO_ROOT", root),
                mock.patch.object(mcp_server, "VISUAL_RECEIPT_ROOT", visual_root),
                mock.patch.object(
                    mcp_server,
                    "_run",
                    side_effect=[
                        command_result(stdout="owner/repo"),
                        command_result(stdout=json.dumps(statuses)),
                    ],
                ),
            ):
                result = mcp_server._visual_attestation(sha)

        self.assertFalse(result["blockers"])
        self.assertEqual(digest, result["receipt_sha256"])

    def test_visual_attestation_rejects_status_for_other_receipt(self) -> None:
        sha = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            visual_root = root / ".rag_index/visual-review-receipts"
            visual_root.mkdir(parents=True)
            test_root = root / "visual-tests"
            test_root.mkdir()
            manifest = test_root / "scenes.json"
            environments = test_root / "environments.json"
            manifest.write_text(
                json.dumps({"schema_version": 1, "scenes": [{"id": "main", "platforms": ["android"]}]}),
                encoding="utf-8",
            )
            environments.write_text("{}\n", encoding="utf-8")
            payload = {
                "target_sha": sha,
                "release": True,
                "platforms": ["android", "linux", "windows", "macos"],
                "manifest_sha256": mcp_server._file_digest(manifest),
                "environments_sha256": mcp_server._file_digest(environments),
                "scenes": {"android/main": {"automation": "pass", "review": "pass"}},
            }
            digest = mcp_server._json_digest(payload)
            (visual_root / f"{sha}.json").write_text(
                json.dumps({**payload, "receipt_sha256": digest}), encoding="utf-8",
            )
            with (
                mock.patch.object(mcp_server, "REPO_ROOT", root),
                mock.patch.object(mcp_server, "VISUAL_RECEIPT_ROOT", visual_root),
                mock.patch.object(
                    mcp_server,
                    "_run",
                    side_effect=[
                        command_result(stdout="owner/repo"),
                        command_result(
                            stdout=json.dumps(
                                [{
                                    "context": "vpn-control/agent-visual",
                                    "state": "success",
                                    "description": "receipt bbbbbbbbbbbbbbbb",
                                }],
                            ),
                        ),
                    ],
                ),
            ):
                result = mcp_server._visual_attestation(sha)

        self.assertTrue(any(blocker["phase"] == "visual_status" for blocker in result["blockers"]))

    def test_visual_attestation_uses_latest_status_for_context(self) -> None:
        sha = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            visual_root = root / ".rag_index/visual-review-receipts"
            visual_root.mkdir(parents=True)
            test_root = root / "visual-tests"
            test_root.mkdir()
            manifest = test_root / "scenes.json"
            environments = test_root / "environments.json"
            manifest.write_text(
                json.dumps({"schema_version": 1, "scenes": [{"id": "main", "platforms": ["android"]}]}),
                encoding="utf-8",
            )
            environments.write_text("{}\n", encoding="utf-8")
            payload = {
                "target_sha": sha,
                "release": True,
                "platforms": ["android", "linux", "windows", "macos"],
                "manifest_sha256": mcp_server._file_digest(manifest),
                "environments_sha256": mcp_server._file_digest(environments),
                "scenes": {"android/main": {"automation": "pass", "review": "pass"}},
            }
            digest = mcp_server._json_digest(payload)
            (visual_root / f"{sha}.json").write_text(
                json.dumps({**payload, "receipt_sha256": digest}), encoding="utf-8",
            )
            statuses = [
                {
                    "id": 10,
                    "context": "vpn-control/agent-visual",
                    "state": "success",
                    "description": f"receipt {digest[:16]}",
                },
                {
                    "id": 11,
                    "context": "vpn-control/agent-visual",
                    "state": "failure",
                    "description": "review restarted",
                },
            ]
            with (
                mock.patch.object(mcp_server, "REPO_ROOT", root),
                mock.patch.object(mcp_server, "VISUAL_RECEIPT_ROOT", visual_root),
                mock.patch.object(
                    mcp_server,
                    "_run",
                    side_effect=[
                        command_result(stdout="owner/repo"),
                        command_result(stdout=json.dumps(statuses)),
                    ],
                ),
            ):
                result = mcp_server._visual_attestation(sha)

        self.assertTrue(any(blocker["phase"] == "visual_status" for blocker in result["blockers"]))

    def test_visual_attestation_rejects_changed_local_evidence(self) -> None:
        sha = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            visual_root = root / ".rag_index/visual-review-receipts"
            visual_root.mkdir(parents=True)
            test_root = root / "visual-tests"
            test_root.mkdir()
            manifest = test_root / "scenes.json"
            environments = test_root / "environments.json"
            actual = root / "actual.png"
            manifest.write_text(
                json.dumps({"schema_version": 1, "scenes": [{"id": "main", "platforms": ["android"]}]}),
                encoding="utf-8",
            )
            environments.write_text("{}\n", encoding="utf-8")
            actual.write_bytes(b"reviewed")
            payload = {
                "target_sha": sha,
                "release": True,
                "platforms": ["android", "linux", "windows", "macos"],
                "manifest_sha256": mcp_server._file_digest(manifest),
                "environments_sha256": mcp_server._file_digest(environments),
                "reports": {},
                "scenes": {
                    "android/main": {
                        "automation": "pass",
                        "review": "pass",
                        "actual": str(actual),
                        "actual_sha256": mcp_server._file_digest(actual),
                    },
                },
            }
            digest = mcp_server._json_digest(payload)
            (visual_root / f"{sha}.json").write_text(
                json.dumps({**payload, "receipt_sha256": digest}), encoding="utf-8",
            )
            actual.write_bytes(b"mutated")
            with (
                mock.patch.object(mcp_server, "REPO_ROOT", root),
                mock.patch.object(mcp_server, "VISUAL_RECEIPT_ROOT", visual_root),
                mock.patch.object(
                    mcp_server,
                    "_run",
                    side_effect=[
                        command_result(stdout="owner/repo"),
                        command_result(stdout="[]"),
                    ],
                ),
            ):
                result = mcp_server._visual_attestation(sha)

        self.assertTrue(any("evidence changed" in blocker["message"] for blocker in result["blockers"]))

    def test_release_readiness_requires_exact_sha_agent_visual_attestation(self) -> None:
        sha = "a" * 40
        required = [
            {
                "name": "Fast Checks",
                "workflow": "fast-checks.yml",
                "event": "push",
                "allowed_conclusions": ["success"],
            },
        ]
        base_runs = [
            {
                "databaseId": 1,
                "workflowName": "Fast Checks",
                "displayTitle": "Fast Checks",
                "event": "push",
                "status": "completed",
                "conclusion": "success",
                "headSha": sha,
            },
            {
                "databaseId": 2,
                "workflowName": "VPN Integration",
                "displayTitle": f"VPN Integration / all / {sha}",
                "event": "workflow_dispatch",
                "status": "completed",
                "conclusion": "success",
                "headSha": sha,
            },
        ]
        visual_status = {
            "context": "vpn-control/agent-visual",
            "state": "success",
            "description": "Agent reviewed 4/4 scenes; receipt deadbeefdeadbeef",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            changelog = root / "docs/CHANGELOG.md"
            changelog.parent.mkdir()
            (root / "gradle.properties").write_text("vpnControlVersion=1.0.0.1\n", encoding="utf-8")
            (root / "README.md").write_text("**Version:** `1.0.0.1`\n", encoding="utf-8")
            changelog.write_text("# Changelog\n\n## 1.0.0.1 - 2026-09-02\n\n- Ready.\n", encoding="utf-8")

            def run_with(attestation: dict[str, object]) -> dict[str, object]:
                with (
                    mock.patch.object(mcp_server, "REPO_ROOT", root),
                    mock.patch.object(mcp_server, "CHANGELOG_PATH", changelog),
                    mock.patch.object(mcp_server, "_repo_state", return_value={"branch": "main", "dirty": False}),
                    mock.patch.object(mcp_server, "_required_workflows", return_value=required),
                    mock.patch.object(
                        mcp_server,
                        "_run",
                        side_effect=[command_result(), command_result(stdout=json.dumps(base_runs))],
                    ),
                    mock.patch.object(mcp_server, "_visual_attestation", return_value=attestation),
                    mock.patch.object(
                        mcp_server,
                        "_git_stdout",
                        side_effect=lambda command: "" if command[:2] == ["tag", "--list"] else sha,
                    ),
                ):
                    return mcp_server._release_readiness()

            missing = run_with(
                {
                    "receipt_sha256": "",
                    "status": None,
                    "blockers": [{"phase": "visual", "message": "missing receipt"}],
                    "command_results": [],
                },
            )
            complete = run_with(
                {
                    "receipt_sha256": "deadbeef" * 8,
                    "status": visual_status,
                    "blockers": [],
                    "command_results": [],
                },
            )

        self.assertTrue(any(blocker["phase"] == "visual" for blocker in missing["blockers"]))
        self.assertFalse(complete["blockers"])
        self.assertEqual(visual_status, complete["runs"]["Agent Visual Review"])
        self.assertEqual("deadbeef" * 8, complete["visual_receipt_sha256"])

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
