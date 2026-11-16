from __future__ import annotations

import inspect
from datetime import datetime, timezone
import json
import re
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
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
    def test_managed_agent_suite_runs_only_affected_modules(self) -> None:
        # The SSH-close gate alone first, then the two hosted CI shards without it.
        gate = "agent_tools.tests.test_ssh_connection_session_close"
        modules = ("agent_tools.tests.test_agent_test_runner", "agent_tools.tests.test_docs_assistant",
                   "agent_tools.tests.test_mcp_server", gate, "agent_tools.tests.test_ssh_transport",
                   "agent_tools.tests.test_workflow_selection_blocker")
        selection = mcp_server.affected_agent_tests.Selection("a" * 40, ("agent_tools/docs_assistant.py",), modules, 9)
        unit = [mcp_server.AGENT_TEST_PYTHON, "-m", "unittest"]
        expected = [unit + [gate], unit + [modules[0], modules[2], modules[4]], unit + [modules[1], modules[5]]]
        with mock.patch.object(mcp_server, "_agent_test_selection", return_value=selection):
            for area, level in (("agent_tools", "focused"), ("agent_tools", "prepush")):
                commands = mcp_server._commands_for(area, level)
                self.assertEqual(expected, [command for command in commands if "unittest" in command])
        workflow = (mcp_server.REPO_ROOT / ".github/workflows/fast-checks.yml").read_text()
        self.assertIn("python agent_tools/affected_agent_tests.py --run", workflow)
        self.assertNotIn("python -m unittest discover -s agent_tools/tests", workflow)

    def test_android_native_tool_setup_uses_sdk_resolver(self) -> None:
        for name in ("android-release.yml", "fast-checks.yml"):
            workflow = (mcp_server.REPO_ROOT / ".github/workflows" / name).read_text()
            self.assertIn("run: bash scripts/prepare_android_native_tools.sh", workflow)
            self.assertNotIn("run: sdkmanager ", workflow)
        integration = (mcp_server.REPO_ROOT / ".github/workflows/vpn-integration.yml").read_text()
        self.assertEqual(2, integration.count("run: bash scripts/prepare_android_native_tools.sh"))

    def test_sdk_graph_check_runs_after_build_setup_not_in_hygiene(self) -> None:
        script = "scripts/test_desktop_sdk_independence.py"
        hygiene = (mcp_server.REPO_ROOT / "scripts/check_release_hygiene.sh").read_text()
        self.assertNotIn(script, hygiene, "Hygiene must not bootstrap Gradle before toolchain setup")
        commands = mcp_server.PREPUSH_COMMANDS
        graph = next(i for i, command in enumerate(commands) if script in command)
        build = next(i for i, command in enumerate(commands) if ":desktopApp:test" in command)
        self.assertGreater(graph, build)
        workflow = (mcp_server.REPO_ROOT / ".github/workflows/fast-checks.yml").read_text()
        self.assertGreater(workflow.index("python " + script), workflow.index("- name: Run fast unit tests"))

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

    def test_checkpoint_pushes_ci_branch_and_commit_or_push_gate_through_ci(self) -> None:
        # RELEASE-001: no push reaches dev directly; checkpoint only starts the ci/* runs.
        sha = "a" * 40
        for action, gate_expected in (("checkpoint", False), ("commit", True)):
            with self.subTest(action=action), \
                 mock.patch.object(mcp_server, "_repo_state", return_value={"branch": "dev"}), \
                 mock.patch.object(mcp_server, "_changed_paths", side_effect=[
                     ["agent_tools/mcp_server.py", "docs/CHANGELOG.md"], []]), \
                 mock.patch.object(mcp_server, "_run", return_value=command_result()) as run, \
                 mock.patch.object(mcp_server, "_git_stdout", return_value=sha), \
                 mock.patch.object(mcp_server, "_receipt_error", return_value=None, create=True), \
                 mock.patch.object(mcp_server, "_watch_required_workflows", return_value={"ok": True}), \
                 mock.patch.object(mcp_server, "_ci_gate", create=True,
                                   return_value={"ok": True, "tool": "git_workflow", "result": {"sha": sha}}) as gate:
                result = mcp_server.git_workflow(action, "checkpoint message",
                    ["agent_tools/mcp_server.py", "docs/CHANGELOG.md"])
            pushes = [call.args[0] for call in run.call_args_list if call.args[0][:2] == ["git", "push"]]
            self.assertFalse(any(command[-1].endswith(":dev") or command[-1].endswith("refs/heads/dev")
                                 for command in pushes), pushes)
            self.assertTrue(result["ok"])
            if gate_expected:
                gate.assert_called_once_with(sha, exact=False)
                self.assertEqual([], pushes)
            else:
                gate.assert_not_called()
                self.assertEqual([["git", "push", "origin", f"{sha}:refs/heads/ci/{sha[:12]}"]], pushes)
                self.assertEqual(sha, result["result"]["sha"])
                self.assertFalse(result["result"]["requiredWorkflowsVerified"])
                self.assertFalse(result["result"]["devAdvanced"])
                self.assertEqual("intermediate-checkpoint", result["result"]["deferredReason"])
        with mock.patch.object(mcp_server, "_repo_state", return_value={"branch": "dev"}), \
             mock.patch.object(mcp_server, "_changed_paths", return_value=[]), \
             mock.patch.object(mcp_server, "_run", return_value=command_result()), \
             mock.patch.object(mcp_server, "_git_stdout", return_value=sha), \
             mock.patch.object(mcp_server, "_ci_gate",
                               return_value={"ok": True, "tool": "git_workflow", "result": {"sha": sha}}) as gate:
            self.assertTrue(mcp_server.git_workflow("push", exact=True)["ok"])
        gate.assert_called_once_with(sha, exact=True)

    def test_push_needs_no_local_prepush_receipt_but_rejects_uncovered_paths(self) -> None:
        # RELEASE-001: the ci/* gate, not a local pre-push receipt, is the completeness gate.
        sha = "a" * 40
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(mcp_server, "RECEIPT_PATH", Path(directory) / "absent.json"), \
             mock.patch.object(mcp_server, "_repo_state", return_value={"branch": "dev"}), \
             mock.patch.object(mcp_server, "_changed_paths", return_value=[]), \
             mock.patch.object(mcp_server, "_run", return_value=command_result()), \
             mock.patch.object(mcp_server, "_git_stdout", return_value=sha), \
             mock.patch.object(mcp_server, "_watch_required_workflows", return_value={"ok": True}), \
             mock.patch.object(mcp_server, "_ci_gate", create=True,
                               return_value={"ok": True, "tool": "git_workflow", "result": {"sha": sha}}) as gate:
            result = mcp_server.git_workflow("push")
        self.assertTrue(result["ok"], result)
        gate.assert_called_once_with(sha, exact=False)
        with mock.patch.object(mcp_server, "_repo_state", return_value={"branch": "dev"}), \
             mock.patch.object(mcp_server, "_changed_paths", return_value=[
                 "agent_tools/mcp_server.py", "docs/CHANGELOG.md", "agent_tools/README.md"]), \
             mock.patch.object(mcp_server, "_run") as run:
            denied = mcp_server.git_workflow("checkpoint", "message",
                ["agent_tools/mcp_server.py", "docs/CHANGELOG.md"])
        self.assertFalse(denied["ok"])
        self.assertIn("uncovered", str(denied))
        run.assert_not_called()
        with mock.patch.object(mcp_server, "_run") as run:
            denied = mcp_server.git_workflow("checkpoint", "message", ["docs/CHANGELOG.md"],
                                             sha="a" * 40)
        self.assertFalse(denied["ok"])
        run.assert_not_called()

    def test_macos_package_pr_filters_include_native_installer_inputs(self) -> None:
        workflow = (mcp_server.REPO_ROOT / ".github/workflows/macos-desktop.yml").read_text(encoding="utf-8")
        pull_request = workflow.split("  pull_request:\n", 1)[1].split("\njobs:\n", 1)[0]
        for source in ("scripts/prepare_macos_install_worker.sh", "scripts/native/macos_install_worker.c"):
            self.assertIn(f'      - "{source}"', pull_request)
            self.assertTrue((mcp_server.REPO_ROOT / source).is_file())
        package = (mcp_server.REPO_ROOT / "scripts/package_macos_desktop.sh").read_text(encoding="utf-8")
        self.assertLess(package.index("bash ./scripts/prepare_macos_install_worker.sh"), package.index("./gradlew :desktopApp:compileKotlin"))

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
        # VPN Integration no longer runs on dev pushes; it is an advisory dispatch.
        self.assertEqual(set(), mcp_server._advisory_workflow_names())
        manifest = json.loads(mcp_server.REQUIRED_WORKFLOWS_PATH.read_text(encoding="utf-8"))
        release_only = manifest["branches"]["dev"]["classified_non_push_workflows"]
        self.assertIn("Visual Capture", {entry["name"] for entry in release_only})
        integration = next(entry for entry in release_only if entry["name"] == "VPN Integration")
        self.assertEqual("advisory_dispatch", integration["classification"])
        workflow = (mcp_server.REPO_ROOT / integration["path"]).read_text(encoding="utf-8")
        triggers = "\n" + workflow.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertNotIn("\n  push:", triggers)
        self.assertIn("\n  workflow_dispatch:", triggers)
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
                "ssh_workflow",
                "vm_workflow",
            },
            {tool.name for tool in result.tools},
        )


class FingerprintTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        (self.root / ".git" / "info" / "exclude").write_text(".rag_index/\n", encoding="utf-8")
        subprocess.run(["git", "config", "user.email", "tests@example.com"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.name", "Agent Tests"], cwd=self.root, check=True)
        (self.root / "tracked.txt").write_text("one\n", encoding="utf-8")
        subprocess.run(["git", "add", "tracked.txt"], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "initial"], cwd=self.root, check=True)
        self.root_patch = mock.patch.object(mcp_server, "REPO_ROOT", self.root)
        self.root_patch.start()
        # Import bound RECEIPT_PATH, and the TEST-006 failure set beside it, to
        # the real checkout; keep that state under this temporary root too.
        self.receipt_patch = mock.patch.object(mcp_server, "RECEIPT_PATH", self.root / ".rag_index" / "prepush_receipt.json")
        self.receipt_patch.start()

    def tearDown(self) -> None:
        self.receipt_patch.stop()
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

    def test_prepush_rejects_content_changed_while_checks_run(self) -> None:
        receipt = self.root / ".rag_index" / "prepush_receipt.json"
        command = [sys.executable, "-c",
                   "from pathlib import Path; Path('tracked.txt').write_text('changed during check\\n')"]
        with mock.patch.object(mcp_server, "RECEIPT_PATH", receipt), \
                mock.patch.object(mcp_server, "_commands_for", return_value=[command]):
            result = mcp_server.run_checks(level="prepush")
        self.assertFalse(result["ok"])
        self.assertIn("changed during", result["summary"])
        self.assertFalse(receipt.exists())

    def test_overlapping_managed_checks_reject_second_before_execution(self) -> None:
        started, release = threading.Event(), threading.Event()
        executions = []

        def harmless_check(command, **kwargs):
            executions.append(command)
            if len(executions) == 1:
                started.set()
                self.assertTrue(release.wait(10))
            return command_result()

        with mock.patch.object(mcp_server, "_changed_paths", return_value=[]), \
                mock.patch.object(mcp_server, "_commands_for", return_value=[["fixture-check"]]), \
                mock.patch.object(mcp_server, "_run", side_effect=harmless_check), \
                ThreadPoolExecutor(max_workers=1) as executor:
            first = executor.submit(mcp_server.run_checks, area="docs")
            try:
                self.assertTrue(started.wait(10))
                second = mcp_server.run_checks(area="docs")
                self.assertFalse(second["ok"])
                self.assertEqual("busy", second["blockers"][0]["state"])
                self.assertEqual(1, len(executions))
            finally:
                release.set()
            self.assertTrue(first.result(timeout=10)["ok"])

    def _assert_prepush_completion_matches_retention_capability(self) -> None:
        receipt = self.root / ".rag_index" / "prepush_receipt.json"
        before = mcp_server._snapshot_fingerprint()
        retention_os = mcp_server.check_output_retention.os
        supported = retention_os.name == "posix" and all(
            hasattr(retention_os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY", "geteuid", "fsync"))
        command = [sys.executable, "-c",
                   "import sys; sys.stdout.buffer.write(b'private stdout\\n'); sys.stderr.buffer.write(b'private stderr\\n')"]
        # Each platform scenario is an independent first pass; a recorded
        # TEST-006 failure set from another scenario would refuse it.
        receipt.with_name("managed_check_failures.json").unlink(missing_ok=True)
        with mock.patch.object(mcp_server, "RECEIPT_PATH", receipt), \
                mock.patch.object(mcp_server, "_commands_for", return_value=[command]):
            result = mcp_server.run_checks(level="prepush")
        child = result["command_results"][0]
        self.assertEqual(0, child["returncode"])
        self.assertEqual("private stdout", child["stdout"])
        self.assertEqual("private stderr", child["stderr"])
        self.assertEqual(before, mcp_server._snapshot_fingerprint())
        if supported:
            self.assertTrue(result["ok"])
            self.assertTrue(child["ok"])
            self.assertNotIn("retentionError", child)
            self.assertEqual(before, json.loads(receipt.read_text())["fingerprint"])
            capture = child["completionOutput"]
            directory = self.root / ".rag_index" / "check-runs" / capture["runId"]
            self.assertEqual(b"private stdout\n", (directory / "stdout.private").read_bytes())
            self.assertEqual(b"private stderr\n", (directory / "stderr.private").read_bytes())
        else:
            self.assertFalse(result["ok"])
            self.assertFalse(child["ok"])
            self.assertEqual("unsupported_private_retention", child["retentionError"])
            self.assertNotIn("completionOutput", child)
            self.assertFalse(receipt.exists())
            self.assertFalse((self.root / ".rag_index" / "check-runs").exists())

    def test_prepush_records_only_unchanged_checked_content(self) -> None:
        self._assert_prepush_completion_matches_retention_capability()

    def test_prepush_unsupported_private_retention_never_creates_receipt(self) -> None:
        # Scope the capability seam to the real retainer's module binding;
        # subprocess, pathlib and the rest of the host retain their actual OS.
        for capability in (SimpleNamespace(name="nt"), SimpleNamespace(name="posix")):
            with self.subTest(platform=capability.name), \
                    mock.patch.object(mcp_server.check_output_retention, "os", capability):
                self._assert_prepush_completion_matches_retention_capability()

    def test_fingerprint_survives_committed_addition_and_deletion(self) -> None:
        (self.root / "tracked.txt").unlink()
        (self.root / "replacement.txt").write_text("replacement\n", encoding="utf-8")
        before = mcp_server._snapshot_fingerprint()
        subprocess.run(["git", "add", "--all"], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "replace"], cwd=self.root, check=True)
        self.assertEqual(before, mcp_server._snapshot_fingerprint())


class VersionPolicyTest(unittest.TestCase):
    def test_three_part_version_carries_with_base_twenty_components(self) -> None:
        self.assertEqual("2.3.0", mcp_server._increment_version("2.2.19"))
        self.assertEqual("3.0.0", mcp_server._increment_version("2.19.19"))
        self.assertEqual("19.0.0", mcp_server._increment_version("18.19.19"))

    def test_invalid_versions_are_rejected(self) -> None:
        for value in ("1.2", "1.2.x", "1.2.20", "1.2.3.4", "0.2.0"):
            with self.assertRaises(ValueError, msg=value):
                mcp_server._increment_version(value)

    def test_manual_release_is_never_an_automatic_workflow_event(self) -> None:
        workflow = (mcp_server.REPO_ROOT / ".github/workflows/release-publish.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("workflow_run:", workflow)
        self.assertNotRegex(workflow, r"(?m)^\s+push:")
        self.assertIn("vpn-control/agent-visual", workflow)
        self.assertIn("visual_receipt_sha256", workflow)
        self.assertIn("python3 scripts/check_release_metadata.py --require-release-ready", workflow)
        self.assertNotIn("./scripts/check_release_metadata.py --require-release-ready", workflow)

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
            mock.patch.object(mcp_server, "_required_snapshot", create=True, return_value={
                "state": "success", "listed": command_result(), "runs": {}, "missing": []}) as snapshot,
            mock.patch.object(
                mcp_server,
                "_visual_command",
                return_value={"ok": True, "result": {"target_sha": sha}, "command_results": []},
            ) as visual,
        ):
            result = mcp_server._merge_dev_for_release()

        self.assertTrue(result["ok"])
        snapshot.assert_called_once_with(sha)
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
            (root / "gradle.properties").write_text("vpnControlVersion=1.3.19\n", encoding="utf-8")
            (root / "README.md").write_text("**Version:** `1.3.19`\n", encoding="utf-8")
            changelog.write_text(
                "# Changelog\n\n## Unreleased\n\n"
                + "\n".join(f"- Existing change {index}." for index in range(1, 10))
                + "\n\n## 1.3.19 - 2026-01-01\n\n- Previous.\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(mcp_server, "REPO_ROOT", root),
                mock.patch.object(mcp_server, "CHANGELOG_PATH", changelog),
            ):
                result = mcp_server.version_bump("Tenth change")

            self.assertTrue(result["ok"])
            self.assertEqual("bump", result["result"]["decision"])
            self.assertIn("vpnControlVersion=1.4.0", (root / "gradle.properties").read_text())
            self.assertIn("**Version:** `1.4.0`", (root / "README.md").read_text())
            updated = changelog.read_text(encoding="utf-8")
            self.assertIn("## 1.4.0 -", updated)
            self.assertIn("- Tenth change.", updated)
            self.assertEqual([], mcp_server._unreleased_bullets(updated))

    def test_below_threshold_only_adds_unreleased_note(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            changelog = root / "docs/CHANGELOG.md"
            changelog.parent.mkdir()
            (root / "gradle.properties").write_text("vpnControlVersion=1.2.3\n", encoding="utf-8")
            (root / "README.md").write_text("**Version:** `1.2.3`\n", encoding="utf-8")
            changelog.write_text(
                "# Changelog\n\n## Unreleased\n\n## 1.2.3 - 2026-01-01\n\n- Previous.\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(mcp_server, "REPO_ROOT", root),
                mock.patch.object(mcp_server, "CHANGELOG_PATH", changelog),
            ):
                result = mcp_server.version_bump("New behavior")

            self.assertTrue(result["ok"])
            self.assertEqual("unreleased", result["result"]["decision"])
            self.assertEqual("vpnControlVersion=1.2.3\n", (root / "gradle.properties").read_text())
            self.assertEqual(["- New behavior."], mcp_server._unreleased_bullets(changelog.read_text()))

    def test_explicit_release_target_migrates_legacy_version_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            changelog = root / "docs/CHANGELOG.md"
            changelog.parent.mkdir()
            (root / "gradle.properties").write_text("vpnControlVersion=0.1.7.3\n", encoding="utf-8")
            (root / "README.md").write_text("**Version:** `0.1.7.3`\n", encoding="utf-8")
            changelog.write_text(
                "# Changelog\n\n## Unreleased\n\n- Existing work.\n\n"
                "## 0.1.7.3 - 2026-01-01\n\n- Previous.\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(mcp_server, "REPO_ROOT", root),
                mock.patch.object(mcp_server, "CHANGELOG_PATH", changelog),
            ):
                result = mcp_server.version_bump(
                    "Unified versioning and visual release validation.",
                    "release",
                    force_release=True,
                    target_version="2.0.0",
                )

            self.assertTrue(result["ok"])
            self.assertEqual("2.0.0", result["result"]["planned_version"])
            self.assertEqual("vpnControlVersion=2.0.0\n", (root / "gradle.properties").read_text())
            updated = changelog.read_text(encoding="utf-8")
            self.assertIn("## 2.0.0 -", updated)
            self.assertIn("- Unified versioning and visual release validation.", updated)

    def test_forced_release_can_roll_into_unpublished_current_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            changelog = root / "docs/CHANGELOG.md"
            changelog.parent.mkdir()
            (root / "gradle.properties").write_text("vpnControlVersion=2.0.0\n", encoding="utf-8")
            (root / "README.md").write_text("**Version:** `2.0.0`\n", encoding="utf-8")
            changelog.write_text(
                "# Changelog\n\n## Unreleased\n\n- Final visual repair.\n\n"
                "## 2.0.0 - 2026-09-03\n\n- Initial release work.\n\n"
                "## 1.19.19 - 2026-09-02\n\n- Previous.\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(mcp_server, "REPO_ROOT", root),
                mock.patch.object(mcp_server, "CHANGELOG_PATH", changelog),
            ):
                result = mcp_server.version_bump(
                    None,
                    "release",
                    force_release=True,
                    target_version="2.0.0",
                )

            self.assertTrue(result["ok"])
            self.assertEqual("2.0.0", result["result"]["planned_version"])
            self.assertEqual("vpnControlVersion=2.0.0\n", (root / "gradle.properties").read_text())
            updated = changelog.read_text(encoding="utf-8")
            self.assertNotIn("## Unreleased", updated)
            self.assertEqual(1, updated.count("## 2.0.0 -"))
            self.assertIn("- Initial release work.\n- Final visual repair.", updated)

class WorkflowWatchTest(unittest.TestCase):
    def test_failed_ci_log_keeps_late_failure_context_with_bounded_output(self) -> None:
        sha = "a" * 40
        failure = "AssertionError: same-UID process ownership is unknown"
        logs = [
            "healthy setup output\n" * 600
            + "Traceback (most recent call last):\n  causal frame\n" + failure + "\n"
            + "other checks succeeded\n" * 600 + "FAILED (failures=1)\n",
            "healthy setup output\n" * 600 + "unrecognized diagnostic at end\n",
        ]
        original_run = mcp_server._run
        for log in logs:
            with self.subTest(log_kind="traceback" if failure in log else "tail"):
                def run(command, **kwargs):
                    if command[:3] == ["gh", "run", "list"]:
                        return command_result(stdout=json.dumps([{
                            "databaseId": 7, "workflowName": "Fast Checks", "event": "push",
                            "status": "completed", "conclusion": "failure", "headSha": sha,
                        }]))
                    # Exercise the real subprocess output-boundary behavior.
                    return original_run([sys.executable, "-c", "print(" + repr(log) + ")"], **kwargs)

                with (
                    mock.patch.object(mcp_server, "_required_workflows", return_value=[{
                        "name": "Fast Checks", "event": "push", "allowed_conclusions": ["success"],
                    }]),
                    mock.patch.object(mcp_server, "_write_json"),
                    mock.patch.object(mcp_server, "_run", side_effect=run),
                ):
                    result = mcp_server._watch_required_workflows(sha)
                self.assertFalse(result["ok"])
                excerpt = result["blockers"][0]["failed_log_excerpts"][0]["excerpt"]
                self.assertLessEqual(len(excerpt), 8000)
                if failure in log:
                    self.assertIn(failure, excerpt)
                    self.assertIn("causal frame", excerpt)
                    self.assertIn("FAILED (failures=1)", excerpt)
                else:
                    self.assertIn("unrecognized diagnostic at end", excerpt)

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
                "manifest_sha256": mcp_server._json_file_digest(manifest),
                "environments_sha256": mcp_server._json_file_digest(environments),
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
                "manifest_sha256": mcp_server._json_file_digest(manifest),
                "environments_sha256": mcp_server._json_file_digest(environments),
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
                "manifest_sha256": mcp_server._json_file_digest(manifest),
                "environments_sha256": mcp_server._json_file_digest(environments),
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
                "manifest_sha256": mcp_server._json_file_digest(manifest),
                "environments_sha256": mcp_server._json_file_digest(environments),
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
            (root / "gradle.properties").write_text("vpnControlVersion=1.0.1\n", encoding="utf-8")
            (root / "README.md").write_text("**Version:** `1.0.1`\n", encoding="utf-8")
            changelog.write_text("# Changelog\n\n## 1.0.1 - 2026-09-02\n\n- Ready.\n", encoding="utf-8")

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


class FakeGitHub:
    """A fake origin and GitHub Actions for the ci/* gate and documentation-only reuse; every other command fails the test."""

    WORKFLOWS = ("Fast Checks", "Windows Desktop Package")

    def __init__(self, test: unittest.TestCase, *, head: str, dev: str, ancestry: set[tuple[str, str]],
                 first_parent: dict[str, list[str]] | None = None,
                 diffs: dict[tuple[str, str], list[str]] | None = None) -> None:
        self.test = test
        self.head = head
        self.remote = {"dev": dev}
        self.local_refs: set[str] = set()
        self.ancestry = ancestry
        self.first_parent = first_parent or {}
        self.diffs = diffs or {}
        self.runs: list[dict[str, object]] = []
        # Per pushed SHA: workflow -> (conclusion or None for never-started/unfinished, polls until completed).
        self.plans: dict[str, dict[str, tuple[str | None, int]]] = {}
        self.polls: dict[str, int] = {}
        self.next_id = 100
        self.calls: list[list[str]] = []
        self.failing_checks: set[str] = set()
        self.on_complete = None
        self.commit_times: dict[str, int] = {}
        # (sha, its required-run state) for every dev update: the gate's central invariant.
        self.dev_pushes: list[tuple[str, str]] = []

    @staticmethod
    def ok(stdout: str = "", returncode: int = 0, stderr: str = "") -> dict[str, object]:
        return {"ok": returncode == 0, "command": "fake", "returncode": returncode,
                "stdout": stdout, "stderr": stderr}

    def is_ancestor(self, older: str, newer: str) -> bool:
        return older == newer or (older, newer) in self.ancestry

    def add_runs(self, sha: str, branch: str, plan: dict[str, tuple[str | None, int]], created: str) -> None:
        for name, (conclusion, polls) in plan.items():
            if polls < 0:
                continue  # never starts
            self.next_id += 1
            self.runs.append({"databaseId": self.next_id, "workflowName": name, "event": "push",
                              "status": "in_progress", "conclusion": "", "headSha": sha,
                              "headBranch": branch, "createdAt": created, "url": f"https://x.invalid/{self.next_id}",
                              "_done_after": polls, "_conclusion": conclusion})

    def __call__(self, command, **_kwargs):
        command = [str(part) for part in command]
        self.calls.append(command)
        git = command[0] == "git"
        if git and command[1] == "fetch":
            return self.ok()
        if git and command[1] == "rev-parse":
            return self.ok(self.head if command[2] == "HEAD" else self.remote.get("dev", ""))
        if git and command[1:3] == ["merge-base", "--is-ancestor"]:
            return self.ok(returncode=0 if self.is_ancestor(command[3], command[4]) else 1)
        if git and command[1] == "rev-list":
            return self.ok("\n".join(self.first_parent.get(command[-1], [command[-1]])))
        if git and command[1:3] == ["diff", "--name-only"]:
            return self.ok("\n".join(self.diffs[(command[-2], command[-1])]))
        if git and command[1:3] == ["diff", "--check"]:
            return self.ok(returncode=1 if "diff-check" in self.failing_checks else 0)
        if git and command[1] == "ls-remote":
            branch = command[-1].removeprefix("refs/heads/")
            return self.ok(f"{self.remote[branch]}\t{command[-1]}" if branch in self.remote else "")
        if git and command[1] == "push":
            if command[3] == "--delete":
                branch = command[4]
                if branch not in self.remote:
                    return self.ok(returncode=1, stderr=f"error: unable to delete '{branch}': remote ref does not exist")
                del self.remote[branch]
                self.local_refs.discard(f"refs/remotes/origin/{branch}")
                return self.ok()
            source, destination = command[-1].split(":")
            source = self.head if source == "HEAD" else source
            branch = destination.removeprefix("refs/heads/")
            if branch == "dev":
                own = [run for run in self.runs if run["headSha"] == source]
                state = ("none" if not own else "success" if all(
                    run["status"] == "completed" and run["conclusion"] == "success" for run in own) else "not-green")
                self.dev_pushes.append((source, state))
                # The gate may advance dev only to a SHA whose own runs succeeded, or by a docs-only reuse.
                if not self.is_ancestor(self.remote["dev"], source):
                    return self.ok(returncode=1, stderr="! [rejected] (non-fast-forward)")
                self.remote["dev"] = source
                return self.ok()
            self.test.assertTrue(branch.startswith("ci/"), command)
            self.remote[branch] = source
            self.local_refs.add(f"refs/remotes/origin/{branch}")
            self.add_runs(source, branch, self.plans.get(source, {}), "2026-11-16T10:00:00Z")
            return self.ok()
        if git and command[1] == "show-ref":
            return self.ok(returncode=0 if command[-1] in self.local_refs else 1)
        if git and command[1] == "update-ref":
            self.local_refs.discard(command[-1])
            return self.ok()
        if git and command[1] == "for-each-ref":
            lines = [f"refs/remotes/origin/{name} {sha}" for name, sha in self.remote.items() if name.startswith("ci/")]
            lines += [f"{ref} {self.head}" for ref in sorted(self.local_refs) if ref.startswith("refs/heads/ci/")]
            return self.ok("\n".join(lines))
        if git and command[1] == "log":
            return self.ok(str(self.commit_times.get(command[-1], 0)))
        if command[:3] == ["gh", "run", "list"]:
            sha = command[command.index("--commit") + 1]
            self.polls[sha] = self.polls.get(sha, 0) + 1
            visible = []
            for run in self.runs:
                if run["headSha"] != sha:
                    continue
                if run["status"] != "completed" and run["_conclusion"] is not None:
                    run["_done_after"] = int(run["_done_after"]) - 1
                    if int(run["_done_after"]) <= 0:
                        run["status"], run["conclusion"] = "completed", run["_conclusion"]
                visible.append({key: value for key, value in run.items() if not key.startswith("_")})
            if self.on_complete and visible and all(run["status"] == "completed" for run in visible):
                callback, self.on_complete = self.on_complete, None
                callback()
            return self.ok(json.dumps(visible))
        if command[:3] == ["gh", "run", "view"]:
            return self.ok(f"Traceback\nAssertionError: run {command[3]} failed\nFAILED (failures=1)\n")
        if command[:3] == ["gh", "run", "cancel"]:
            for run in self.runs:
                if str(run["databaseId"]) == command[3]:
                    run["status"], run["conclusion"] = "completed", "cancelled"
            return self.ok()
        if command == ["./scripts/check_docs_hygiene.sh"]:
            return self.ok(returncode=1 if "docs-hygiene" in self.failing_checks else 0)
        if command[1:] == ["scripts/check_source_whitespace.py"]:
            return self.ok()
        if git and command[1] == "switch":
            self.test.fail(f"release merge switched to {command[2]} without exact-SHA runs")
        self.test.fail(f"unexpected command: {command}")

    def pushes(self, branch: str) -> list[list[str]]:
        return [command for command in self.calls if command[:2] == ["git", "push"]
                and command[-1].endswith(f":refs/heads/{branch}")]


class CiBranchGateTest(unittest.TestCase):
    DEV = "d" * 40
    HEAD = "e" * 40
    BRANCH = "ci/" + "e" * 12

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        required = [{"name": name, "workflow": "x.yml", "event": "push", "allowed_conclusions": ["success"]}
                    for name in FakeGitHub.WORKFLOWS]
        for patcher in (
            mock.patch.object(mcp_server, "CI_GATE_LEDGER_DIR", root / "ci-gate", create=True),
            # The unfixed source demanded a local receipt; the ci/* gate does not (see McpSurfaceTest).
            mock.patch.object(mcp_server, "_receipt_error", return_value=None, create=True),
            mock.patch.object(mcp_server, "DISCOVERY_TIMEOUT_SECONDS", 0),
            mock.patch.object(mcp_server, "WATCH_STATE_PATH", root / "watch.json"),
            mock.patch.object(mcp_server, "POLL_SECONDS", 0),
            mock.patch.object(mcp_server.time, "sleep"),
            mock.patch.object(mcp_server, "_required_workflows", return_value=required),
            mock.patch.object(mcp_server, "_advisory_runs", return_value={}),
            mock.patch.object(mcp_server, "_repo_state", return_value={"branch": "dev"}),
            mock.patch.object(mcp_server, "_changed_paths", return_value=[]),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.ledger = root / "ci-gate"

    def fake(self, **kwargs) -> FakeGitHub:
        fake = FakeGitHub(self, head=self.HEAD, dev=kwargs.pop("dev", self.DEV),
                          ancestry=kwargs.pop("ancestry", {(self.DEV, self.HEAD)}),
                          first_parent=kwargs.pop("first_parent", {self.HEAD: [self.HEAD, self.DEV]}),
                          diffs=kwargs.pop("diffs", {(self.DEV, self.HEAD): ["agent_tools/mcp_server.py"]}))
        patcher = mock.patch.object(mcp_server, "_run", side_effect=fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        return fake

    def record(self, sha: str | None = None) -> dict[str, object]:
        return json.loads((self.ledger / f"{sha or self.HEAD}.json").read_text(encoding="utf-8"))

    def test_dev_fast_forwards_only_after_every_required_exact_sha_run_succeeds(self) -> None:
        fake = self.fake()
        fake.plans[self.HEAD] = {"Fast Checks": ("success", 2), "Windows Desktop Package": ("success", 3)}
        result = mcp_server.git_workflow("push")
        self.assertEqual([(self.HEAD, "success")], fake.dev_pushes)
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.HEAD, fake.remote["dev"])
        # The candidate ran on its own ci branch first; dev moved only once every run had succeeded.
        ci_push = fake.calls.index(["git", "push", "origin", f"{self.HEAD}:refs/heads/{self.BRANCH}"])
        dev_push = fake.calls.index(["git", "push", "origin", f"{self.HEAD}:refs/heads/dev"])
        self.assertLess(ci_push, dev_push)
        self.assertGreaterEqual(fake.polls[self.HEAD], 3)
        self.assertTrue(all(run["status"] == "completed" and run["conclusion"] == "success" for run in fake.runs))
        # No second run on dev is demanded: the gate matched the ci/* runs by SHA.
        self.assertEqual(1, len(fake.pushes("dev")))
        self.assertEqual("merged", self.record()["outcome"])
        self.assertTrue(result["result"]["branchDeleted"])
        self.assertNotIn(self.BRANCH, fake.remote)
        self.assertNotIn(f"refs/remotes/origin/{self.BRANCH}", fake.local_refs)
        self.assertLess(dev_push, fake.calls.index(["git", "push", "origin", "--delete", self.BRANCH]))

    def test_red_result_is_recorded_complete_then_the_branch_is_deleted_and_dev_kept(self) -> None:
        fake = self.fake()
        fake.local_refs.add(f"refs/heads/{self.BRANCH}")
        # Fast Checks fails first; the gate still waits for Windows so the failure set is complete (TEST-006).
        fake.plans[self.HEAD] = {"Fast Checks": ("failure", 1), "Windows Desktop Package": ("failure", 3)}
        result = mcp_server.git_workflow("push")
        self.assertEqual([], fake.dev_pushes)
        self.assertFalse(result["ok"])
        self.assertEqual(self.DEV, fake.remote["dev"])
        record = self.record()
        self.assertEqual("failed", record["outcome"])
        self.assertEqual(set(FakeGitHub.WORKFLOWS), set(record["failures"]))
        excerpts = result["blockers"][0]["failed_log_excerpts"]
        self.assertEqual(2, len(excerpts))
        self.assertIn("AssertionError", excerpts[0]["excerpt"])
        self.assertNotIn(self.BRANCH, fake.remote)
        self.assertNotIn(f"refs/heads/{self.BRANCH}", fake.local_refs)
        self.assertTrue(result["result"]["branchDeleted"])

    def test_missing_workflow_is_a_failed_gate_and_pending_keeps_the_branch(self) -> None:
        fake = self.fake()
        fake.plans[self.HEAD] = {"Fast Checks": ("success", 1), "Windows Desktop Package": (None, -1)}
        missing = mcp_server.git_workflow("push")
        self.assertEqual([], fake.dev_pushes)
        self.assertFalse(missing["ok"])
        self.assertEqual(["Windows Desktop Package"], self.record()["missing"])
        self.assertEqual("ci_discovery", missing["blockers"][0]["phase"])
        self.assertEqual(self.DEV, fake.remote["dev"])
        self.assertNotIn(self.BRANCH, fake.remote)

        pending = self.fake()
        pending.plans[self.HEAD] = {name: (None, 1) for name in FakeGitHub.WORKFLOWS}
        with mock.patch.object(mcp_server, "WATCH_TIMEOUT_SECONDS", 0):
            result = mcp_server.git_workflow("push")
        self.assertEqual([], pending.dev_pushes)
        self.assertFalse(result["ok"])
        self.assertEqual("pending", self.record()["outcome"])
        self.assertEqual(self.DEV, pending.remote["dev"])
        self.assertEqual(self.HEAD, pending.remote[self.BRANCH])
        self.assertEqual([], pending.pushes("dev"))

    def test_rerun_of_a_red_sha_ignores_its_older_runs(self) -> None:
        fake = self.fake()
        fake.add_runs(self.HEAD, self.BRANCH, {name: ("failure", 0) for name in FakeGitHub.WORKFLOWS},
                      "2026-11-15T10:00:00Z")
        fake.plans[self.HEAD] = {name: ("success", 2) for name in FakeGitHub.WORKFLOWS}
        result = mcp_server.git_workflow("push")
        self.assertEqual(1, len(fake.pushes(self.BRANCH)))
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.HEAD, fake.remote["dev"])

    def test_refuses_when_dev_is_not_an_ancestor_before_or_after_ci(self) -> None:
        moved = "f" * 40
        fake = self.fake(dev=moved, ancestry=set())
        before = mcp_server.git_workflow("push")
        self.assertFalse(before["ok"])
        self.assertEqual("rebase", before["blockers"][0]["phase"])
        self.assertEqual([], fake.pushes(self.BRANCH))
        self.assertEqual(moved, fake.remote["dev"])

        racing = self.fake()
        racing.plans[self.HEAD] = {name: ("success", 1) for name in FakeGitHub.WORKFLOWS}
        racing.on_complete = lambda: racing.remote.__setitem__("dev", moved)
        result = mcp_server.git_workflow("push")
        self.assertEqual([], racing.dev_pushes)
        self.assertFalse(result["ok"])
        self.assertEqual("rebase-needed", self.record()["outcome"])
        self.assertEqual(moved, racing.remote["dev"])
        self.assertEqual([], racing.pushes("dev"))
        self.assertNotIn(self.BRANCH, racing.remote)

    def test_abandon_cancels_unfinished_runs_records_and_deletes(self) -> None:
        fake = self.fake()
        fake.remote[self.BRANCH] = self.HEAD
        fake.local_refs.add(f"refs/remotes/origin/{self.BRANCH}")
        fake.add_runs(self.HEAD, self.BRANCH, {name: ("success", 50) for name in FakeGitHub.WORKFLOWS},
                      "2026-11-16T10:00:00Z")
        result = mcp_server.git_workflow("abandon", sha=self.HEAD)
        self.assertTrue(result["ok"], result)
        self.assertEqual(2, len([command for command in fake.calls if command[:3] == ["gh", "run", "cancel"]]))
        self.assertEqual("abandoned", self.record()["outcome"])
        self.assertNotIn(self.BRANCH, fake.remote)
        self.assertEqual(self.DEV, fake.remote["dev"])

    def test_cleanup_deletes_contained_and_stale_ci_branches_only(self) -> None:
        contained, stale, flying, recent = ("1" * 40, "2" * 40, "3" * 40, "4" * 40)
        fake = self.fake(ancestry={(contained, self.DEV)})
        for sha, created, polls in ((stale, "2026-11-01T00:00:00Z", 0), (flying, "2026-11-01T00:00:00Z", 99),
                                    (recent, "2026-11-15T00:00:00Z", 0)):
            fake.add_runs(sha, f"ci/{sha[:12]}", {"Fast Checks": ("success", polls)}, created)
            for run in fake.runs:
                if run["headSha"] == sha and polls == 0:
                    run["status"], run["conclusion"] = "completed", "success"
        for sha in (contained, stale, flying, recent):
            fake.remote[f"ci/{sha[:12]}"] = sha
        fake.local_refs.add("refs/heads/ci/orphan")
        now = datetime(2026, 11, 16, tzinfo=timezone.utc).timestamp()
        with mock.patch.object(mcp_server.time, "time", return_value=now):
            result = mcp_server.git_workflow("cleanup")
        self.assertTrue(result["ok"], result)
        reasons = {item["branch"]: item["reason"] for item in result["result"]["deleted"]}
        self.assertEqual({f"ci/{contained[:12]}": "contained-in-dev", f"ci/{stale[:12]}": "stale",
                          "ci/orphan": "local-without-remote"}, reasons)
        kept = {item["branch"]: item["reason"] for item in result["result"]["kept"]}
        self.assertEqual({f"ci/{flying[:12]}": "in-flight", f"ci/{recent[:12]}": "recent"}, kept)
        self.assertEqual({"dev", f"ci/{flying[:12]}", f"ci/{recent[:12]}"}, set(fake.remote))
        self.assertEqual("cleaned", self.record(stale)["outcome"])
        self.assertEqual(set(), {ref for ref in fake.local_refs if ref.startswith("refs/heads/ci/")})

    def test_docs_only_change_reuses_the_nearest_green_sha_after_docs_checks(self) -> None:
        middle = "c" * 40
        fake = self.fake(ancestry={(self.DEV, self.HEAD), (self.DEV, middle), (middle, self.HEAD)},
                         first_parent={self.HEAD: [self.HEAD, middle, self.DEV]},
                         diffs={(middle, self.HEAD): ["agent_docs/development.md"],
                                (self.DEV, self.HEAD): ["agent_docs/development.md", "AGENTS.md"]})
        fake.add_runs(self.DEV, "ci/" + self.DEV[:12], {name: ("success", 0) for name in FakeGitHub.WORKFLOWS},
                      "2026-11-16T09:00:00Z")
        for run in fake.runs:
            run["status"], run["conclusion"] = "completed", "success"
        result = mcp_server.git_workflow("push")
        self.assertIn(["./scripts/check_docs_hygiene.sh"], fake.calls)
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.DEV, result["result"]["docsOnlyReuse"]["reference"])
        self.assertEqual(self.HEAD, fake.remote["dev"])
        self.assertEqual([], fake.pushes(self.BRANCH))
        self.assertIn(["./scripts/check_docs_hygiene.sh"], fake.calls)
        self.assertIn(["git", "diff", "--check", self.DEV, self.HEAD], fake.calls)
        # An unrun documentation-only SHA is reported verified by the same equivalence.
        checked = mcp_server.git_workflow("checks", sha=self.HEAD)
        self.assertTrue(checked["ok"], checked)
        self.assertEqual(self.DEV, checked["result"]["docsOnlyReuse"]["reference"])

    def test_docs_reuse_refuses_failed_docs_checks_and_non_documentation_paths(self) -> None:
        for paths in (["docs/CHANGELOG.md"], ["README.md"], ["gradle.properties"], ["agent_tools/README.md", "x.py"],
                      ["agent_tools/tests/fixtures/notes.md"]):
            with self.subTest(paths=paths):
                fake = self.fake(diffs={(self.DEV, self.HEAD): paths})
                fake.add_runs(self.DEV, "ci/" + self.DEV[:12], {name: ("success", 0) for name in FakeGitHub.WORKFLOWS},
                              "2026-11-16T09:00:00Z")
                for run in fake.runs:
                    run["status"], run["conclusion"] = "completed", "success"
                fake.plans[self.HEAD] = {name: ("success", 1) for name in FakeGitHub.WORKFLOWS}
                result = mcp_server.git_workflow("push")
                self.assertEqual([(self.HEAD, "success")], fake.dev_pushes)
                self.assertTrue(result["ok"], result)
                self.assertNotIn("docsOnlyReuse", result["result"])
                self.assertEqual(1, len(fake.pushes(self.BRANCH)))
        fake = self.fake(diffs={(self.DEV, self.HEAD): ["agent_docs/development.md"]})
        fake.add_runs(self.DEV, "ci/" + self.DEV[:12], {name: ("success", 0) for name in FakeGitHub.WORKFLOWS},
                      "2026-11-16T09:00:00Z")
        for run in fake.runs:
            run["status"], run["conclusion"] = "completed", "success"
        fake.failing_checks.add("docs-hygiene")
        refused = mcp_server.git_workflow("push")
        self.assertEqual([], fake.dev_pushes)
        self.assertFalse(refused["ok"])
        self.assertEqual(self.DEV, fake.remote["dev"])
        self.assertEqual([], fake.pushes(self.BRANCH))

    def test_exact_and_release_never_reuse_a_documentation_only_equivalence(self) -> None:
        # A docs-reached dev SHA has no exact runs of its own, so the release merge refuses before touching main.
        docs_reached = self.fake(dev=self.HEAD, diffs={(self.DEV, self.HEAD): ["agent_docs/development.md"]})
        docs_reached.head = self.HEAD
        with mock.patch.object(mcp_server, "_repo_state", return_value={"branch": "dev", "dirty": False}):
            release = mcp_server._merge_dev_for_release()
        self.assertFalse(release["ok"])
        self.assertIn("exact=True", release["summary"])
        self.assertFalse(any(command[:2] == ["git", "switch"] for command in docs_reached.calls))
        self.assertEqual([], docs_reached.pushes("main"))
        fake = self.fake(diffs={(self.DEV, self.HEAD): ["agent_docs/development.md"]})
        fake.add_runs(self.DEV, "ci/" + self.DEV[:12], {name: ("success", 0) for name in FakeGitHub.WORKFLOWS},
                      "2026-11-16T09:00:00Z")
        for run in fake.runs:
            run["status"], run["conclusion"] = "completed", "success"
        fake.plans[self.HEAD] = {name: ("success", 1) for name in FakeGitHub.WORKFLOWS}
        exact = mcp_server.git_workflow("push", exact=True)
        self.assertEqual([(self.HEAD, "success")], fake.dev_pushes)
        self.assertTrue(exact["ok"], exact)
        self.assertNotIn("docsOnlyReuse", exact["result"])
        self.assertEqual(1, len(fake.pushes(self.BRANCH)))
        with mock.patch.object(mcp_server, "_watch_required_workflows", return_value={"ok": False}) as watch:
            mcp_server.git_workflow("checks", sha="c" * 40, exact=True)
        watch.assert_called_once_with("c" * 40)


class RequiredWorkflowTriggerTest(unittest.TestCase):
    REQUIRED = ("fast-checks.yml", "android-release.yml", "linux-desktop.yml", "windows-desktop.yml",
                "macos-desktop.yml")

    @staticmethod
    def push_branches(text: str) -> list[str]:
        block = re.search(r"(?m)^  push:\n    branches:\n((?:      - .*\n|      #.*\n)+)", text)
        if block is None:
            return []
        return [line.strip()[2:].strip('"') for line in block.group(1).splitlines() if line.strip().startswith("- ")]

    def test_required_workflows_run_on_ci_gate_branches_without_dev_only_side_effects(self) -> None:
        workflows = mcp_server.REPO_ROOT / ".github/workflows"
        manifest = json.loads(mcp_server.REQUIRED_WORKFLOWS_PATH.read_text(encoding="utf-8"))
        required_paths = {Path(entry["path"]).name for entry in manifest["branches"]["dev"]["workflows"]
                          if entry["classification"] == "required_push"}
        self.assertEqual(set(self.REQUIRED), required_paths)
        for name in self.REQUIRED:
            text = (workflows / name).read_text(encoding="utf-8")
            self.assertEqual(["dev", "ci/**"], self.push_branches(text), name)
        # Advisory and release-only workflows never run for a ci/* candidate.
        for name in ("vpn-integration.yml", "release-publish.yml", "visual-regression.yml", "environment-canary.yml"):
            self.assertNotIn("ci/**", self.push_branches((workflows / name).read_text(encoding="utf-8")), name)
        # Every dev-only condition is an exact dev ref, which a ci/* push can never satisfy.
        for path in sorted(workflows.glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            for match in re.finditer(r"github\.(ref|ref_name)\s*(?:==|!=)\s*'([^']*)'", text):
                expected = "refs/heads/dev" if match.group(1) == "ref" else "dev"
                self.assertEqual(expected, match.group(2), path.name)
            self.assertNotRegex(text, r"startsWith\(\s*github\.ref", path.name)
            # A cache may be written only by dev; a ci/* run stays read-only.
            for value in re.findall(r"(?m)^\s+cache-read-only:\s*(.+)$", text):
                self.assertIn("github.ref != 'refs/heads/dev'", value, path.name)


if __name__ == "__main__":
    unittest.main()
