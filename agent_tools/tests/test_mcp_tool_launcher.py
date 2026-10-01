"""Regression coverage for the fresh-process MCP launcher."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = REPO_ROOT / "agent_tools" / "mcp_tool.sh"


class McpToolLauncherTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name) / "repo"
        (self.root / "agent_tools").mkdir(parents=True)
        shutil.copy2(LAUNCHER, self.root / "agent_tools" / "mcp_tool.sh")
        (self.root / "agent_tools" / "mcp_server.py").write_text("# fake server\n")
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write_executable(self, path: Path, body: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def _run(self) -> subprocess.CompletedProcess[str]:
        environment = {
            "PATH": f"{self.bin_dir}{os.pathsep}{os.environ['PATH']}",
            "LC_ALL": "C",
        }
        return subprocess.run(
            ["/bin/bash", str(self.root / "agent_tools" / "mcp_tool.sh"), "prepare_start"],
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )

    def test_prefers_existing_repository_venv_over_system_python(self) -> None:
        self._write_executable(
            self.root / ".agent_venv" / "bin" / "python",
            'if [ "$1" = "-c" ]; then exit 0; fi\nprintf "venv:%s\\n" "$*"\n',
        )
        self._write_executable(self.bin_dir / "python3", 'printf "system:%s\\n" "$*"\n')

        result = self._run()

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("venv:", result.stdout)
        self.assertNotIn("system:", result.stdout)

    def test_does_not_fall_back_when_existing_venv_lacks_dependencies(self) -> None:
        self._write_executable(
            self.root / ".agent_venv" / "bin" / "python",
            'if [ "$1" = "-c" ]; then exit 1; fi\nprintf "venv-run\\n"\n',
        )
        self._write_executable(self.bin_dir / "python3", 'printf "system-run\\n"\n')

        result = self._run()

        self.assertEqual(1, result.returncode)
        self.assertIn("missing required dependencies", result.stderr)
        self.assertNotIn("system-run", result.stdout)

    def test_uses_system_python_when_repository_venv_is_absent(self) -> None:
        self._write_executable(self.bin_dir / "python3", 'printf "system:%s\\n" "$*"\n')

        result = self._run()

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("system:", result.stdout)


if __name__ == "__main__":
    unittest.main()
