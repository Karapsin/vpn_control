"""Tracked Claude Code configuration starts only this checkout's MCP launcher."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from agent_tools import affected_agent_tests as selector
from agent_tools import mcp_server

ROOT = Path(__file__).resolve().parents[2]
MCP_CONFIG = ROOT / ".mcp.json"
SETTINGS = ROOT / ".claude/settings.json"
STUB = '#!/usr/bin/env bash\nprintf "%s\\n" "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"\n'


def server():
    return json.loads(MCP_CONFIG.read_text(encoding="utf-8"))["mcpServers"]["vpn_control"]


def fake_checkout(parent, name):
    root = Path(parent).resolve() / name
    (root / "agent_tools").mkdir(parents=True)
    (root / "agent_tools/mcp_server.sh").write_text(STUB)
    (root / ".mcp.json").write_bytes(MCP_CONFIG.read_bytes())
    return root


def launch(project_dir, cwd):
    # Claude Code passes args verbatim and sets CLAUDE_PROJECT_DIR in the child.
    config = server()
    env = {key: value for key, value in os.environ.items() if key != "CLAUDE_PROJECT_DIR"}
    if project_dir is not None:
        env["CLAUDE_PROJECT_DIR"] = str(project_dir)
    return subprocess.run([config["command"], *config["args"]], cwd=cwd, env=env,
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)


class ClaudeCodeConfigTest(unittest.TestCase):
    def test_server_matches_codex_limits_and_permissions_are_server_scoped(self):
        self.assertEqual(list(json.loads(MCP_CONFIG.read_text())["mcpServers"]), ["vpn_control"])
        config = server()
        self.assertEqual((config["type"], config["command"], config["args"][0]), ("stdio", "bash", "-c"))
        self.assertEqual(config["timeout"], 3_600_000)
        self.assertIs(config["alwaysLoad"], True)
        # Claude expands ${VAR} in args itself; the guard must read the runtime value.
        self.assertNotIn("${", config["args"][1])
        settings = json.loads(SETTINGS.read_text())
        self.assertEqual(settings["enabledMcpjsonServers"], ["vpn_control"])
        self.assertIs(settings["enableAllProjectMcpServers"], False)
        self.assertEqual(settings["env"], {"MCP_TIMEOUT": "300000"})
        self.assertEqual(settings["permissions"], {"allow": ["mcp__vpn_control__*"]})
        self.assertNotIn("hooks", settings)

    def test_instruction_bridge_imports_agents(self):
        lines = (ROOT / "CLAUDE.md").read_text().splitlines()
        self.assertIn("@AGENTS.md", lines)
        self.assertTrue((ROOT / "AGENTS.md").is_file())
        ignored = (ROOT / ".gitignore").read_text().splitlines()
        self.assertIn(".claude/settings.local.json", ignored)
        self.assertIn("CLAUDE.local.md", ignored)

    @unittest.skipIf(os.name == "nt", "POSIX path fixtures")
    def test_launcher_is_resolved_from_project_root_with_unusual_paths(self):
        names = ["plain", "with space", "dollar $HOME and `tick`", "quote ' \" ; & | *", "café ${x}"]
        with tempfile.TemporaryDirectory() as directory:
            other = fake_checkout(directory, "other checkout")
            for name in names:
                root = fake_checkout(directory, name)
                (root / "nested/deeper").mkdir(parents=True)
                for cwd in (root, root / "nested/deeper", other):
                    with self.subTest(name=name, cwd=cwd):
                        result = launch(root, cwd)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout.strip(), str(root.resolve()))

    @unittest.skipIf(os.name == "nt", "POSIX path fixtures")
    def test_missing_or_foreign_root_fails_without_selecting_another_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            other = fake_checkout(directory, "other checkout")
            not_checkout = Path(directory) / "not a checkout"
            (not_checkout / "agent_tools").mkdir(parents=True)
            (not_checkout / "agent_tools/mcp_server.sh").write_text(STUB)
            for project_dir in (None, "", "relative/root", "${CLAUDE_PROJECT_DIR}", not_checkout, Path(directory) / "absent"):
                with self.subTest(project_dir=project_dir):
                    result = launch(project_dir, other)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("[vpn-control MCP] CLAUDE_PROJECT_DIR", result.stderr)

    def test_config_changes_select_this_consumer_and_bridge_is_prose(self):
        sources = {"agent_tools/tests/test_claude_code_config.py": Path(__file__).read_text(),
                   ".mcp.json": None, ".claude/settings.json": None, "CLAUDE.md": None}
        for changed in (".mcp.json", ".claude/settings.json"):
            with self.subTest(changed=changed):
                self.assertEqual(selector.select_from_sources(sources, {changed}).modules,
                                 ("agent_tools.tests.test_claude_code_config",))
        self.assertEqual(selector.select_from_sources(sources, {"CLAUDE.md"}).modules, ())
        with self.assertRaisesRegex(selector.SelectionError, "no known consumers: .mcp.json"):
            selector.select_from_sources({".mcp.json": None, "agent_tools/tests/test_other.py": "pass\n"}, {".mcp.json"})

    def test_claude_configuration_routes_to_agent_tools(self):
        for path in (".mcp.json", ".claude/settings.json"):
            with self.subTest(path=path):
                self.assertEqual(mcp_server._infer_area("update client setup", "auto", [path]), "agent_tools")
        self.assertEqual(mcp_server._infer_area("Add Claude Code support", "auto", []), "agent_tools")


if __name__ == "__main__":
    unittest.main()
