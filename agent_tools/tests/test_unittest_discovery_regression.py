from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import mcp_server


ROOT = Path(mcp_server.__file__).resolve().parents[1]


class UnittestDiscoveryRegressionTest(unittest.TestCase):
    def test_repository_top_level_avoids_scripts_module_collision(self) -> None:
        # The same test is executable by discovery, MCP selection and the actual
        # CI helper. A conflicting tests/scripts.py makes a lost import root fail.
        with tempfile.TemporaryDirectory(prefix="unittest-import-root-") as temporary:
            root = Path(temporary).resolve()
            files = {
                ".gitignore": ".rag_index/\n__pycache__/\n",
                "agent_tools/__init__.py": "",
                "agent_tools/tests/__init__.py": "",
                "scripts/__init__.py": "ORIGIN = 'repository'\n",
                "agent_tools/tests/scripts.py": "ORIGIN = 'collision'\n",
                "agent_tools/leaf.py": "value = 1\n",
                "agent_tools/tests/test_leaf.py": """import unittest
from pathlib import Path
from agent_tools import leaf
import scripts
class Case(unittest.TestCase):
 def test_import_root(self):
  self.assertEqual('repository', scripts.ORIGIN, 'SCRIPTS_COLLISION')
  self.assertEqual(Path.cwd()/'scripts/__init__.py', Path(scripts.__file__).resolve())
  self.assertGreater(leaf.value, 0)
  print('ROOT_IMPORT_CONFIRMED', flush=True)
""",
            }
            for name, text in files.items():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text)
            for name in ("affected_agent_tests.py", "affected_agent_test_dependencies.json", "agent_test_runner.py", "agent_ci_evidence.py"):
                (root / "agent_tools" / name).write_bytes((ROOT / "agent_tools" / name).read_bytes())

            def run(command, env=None):
                return subprocess.run(command, cwd=root, env=env, text=True,
                                      capture_output=True, check=False, timeout=30)

            for command in (["git", "init", "-q"], ["git", "add", "."],
                            ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                             "commit", "-qm", "owned import-root fixture"]):
                result = run(command)
                self.assertEqual(0, result.returncode, result.stderr)
            baseline = run(["git", "rev-parse", "HEAD"]).stdout.strip()
            (root / "agent_tools/leaf.py").write_text("value = 2\n")

            discovery = [mcp_server.AGENT_TEST_PYTHON, "-m", "unittest", "discover", "-s", "agent_tools/tests"]
            collision = run(discovery)
            self.assertNotEqual(0, collision.returncode)
            self.assertIn("SCRIPTS_COLLISION", collision.stderr)
            retained_root = run([*discovery, "-t", "."])
            self.assertEqual(0, retained_root.returncode, retained_root.stderr)
            self.assertIn("ROOT_IMPORT_CONFIRMED", retained_root.stdout)

            with patch.object(mcp_server, "REPO_ROOT", root), patch.dict(os.environ, {"AGENT_TEST_BASELINE": baseline}):
                for level in ("focused", "prepush"):
                    with self.subTest(level=level):
                        commands = [command for command in mcp_server._commands_for("agent_tools", level)
                                    if command[1:3] == ["-m", "unittest"]]
                        self.assertEqual(1, len(commands))
                        selected = run(commands[0])
                        self.assertEqual(0, selected.returncode, selected.stderr)
                        self.assertIn("ROOT_IMPORT_CONFIRMED", selected.stdout)

            # Execute the workflow's real run body, including its current helper,
            # against the same changed tool and collision fixture.
            lines = (ROOT / ".github/workflows/fast-checks.yml").read_text().splitlines()
            start = next(i for i, line in enumerate(lines) if "- name: Test affected agent tools" in line)
            run_line = next(i for i in range(start + 1, len(lines)) if lines[i].lstrip().startswith("run:"))
            value = lines[run_line].split("run:", 1)[1].strip()
            if value == "|":
                body = []
                for line in lines[run_line + 1:]:
                    if line and not line.startswith("          "):
                        break
                    body.append(line[10:] if line else "")
                value = "\n".join(body)
            value = value.replace("python ", shlex.quote(mcp_server.AGENT_TEST_PYTHON) + " ")
            env = {**os.environ, "AGENT_TEST_BASELINE": baseline, "AUDIT_AGENT_TESTS": "",
                   "PYTHONDONTWRITEBYTECODE": "1"}
            selected_ci = run(["bash", "-c", value], env)
            self.assertEqual(0, selected_ci.returncode, selected_ci.stderr)
            self.assertIn('"selectedModuleCount": 1', selected_ci.stdout)
            reports = list((root / ".rag_index/agent-test-runs").glob("*/report.json"))
            if os.name == "posix":
                self.assertEqual(1, len(reports))
                report = json.loads(reports[0].read_text())
                self.assertTrue(report["successful"])
                self.assertEqual(1, report["counts"]["testsRun"])
                worker_stdout = "".join(path.read_text() for path in reports[0].parent.glob("worker-*/stdout.txt"))
                self.assertIn("ROOT_IMPORT_CONFIRMED", worker_stdout)
            else:
                self.assertIn("ROOT_IMPORT_CONFIRMED", selected_ci.stdout)
