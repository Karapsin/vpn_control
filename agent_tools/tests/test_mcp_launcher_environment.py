"""Injected desktop library diagnostics must not enter MCP/SSH child protocols."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(Path("/bin/bash").exists(), "repository launchers require bash")
class McpLauncherEnvironmentTest(unittest.TestCase):
    def test_both_launchers_clear_injection_before_any_interpreter(self):
        for launcher in ("mcp_tool.sh", "mcp_server.sh"):
            for injected in (False, True):
                with self.subTest(launcher=launcher, injected=injected), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "agent_tools").mkdir()
                    shutil.copy2(ROOT / "agent_tools" / launcher, root / "agent_tools" / launcher)
                    (root / "agent_tools/requirements-mcp.txt").write_text("fixture\n")
                    (root / "agent_tools/mcp_server.py").write_text("# inert fixture\n")
                    (root / "bin").mkdir()
                    (root / ".agent_venv/bin").mkdir(parents=True)
                    (root / ".agent_venv/.requirements.sha256").write_text("0" * 64 + "\n")
                    interpreter = """#!/bin/sh
if [ "${DYLD_INSERT_LIBRARIES+x}" = x ]; then
    printf 'injected\n' >> "$MCP_ENV_FIXTURE_LOG"
fi
if [ "$1" = '-c' ]; then printf '%064d\n' 0; exit 0; fi
if [ "$1" = '-m' ]; then exit 0; fi
if [ "$MCP_ENV_FIXTURE_KEEP" != 'preserved' ]; then exit 9; fi
if [ "${DYLD_INSERT_LIBRARIES+x}" = x ]; then printf 'injected diagnostics\n'; fi
printf 'Master running (pid=123)\n'
"""
                    for path in (root / "bin/python3", root / ".agent_venv/bin/python"):
                        path.write_text(interpreter); path.chmod(0o700)
                    log = root / "interpreter-environment.log"
                    env = dict(os.environ)
                    env.pop("DYLD_INSERT_LIBRARIES", None)
                    env.update(PATH=str(root / "bin") + os.pathsep + env["PATH"],
                               MCP_ENV_FIXTURE_LOG=str(log), MCP_ENV_FIXTURE_KEEP="preserved")
                    if injected:
                        # Empty is loader-safe on macOS while still exercising
                        # propagation of the injection variable to every child.
                        # Actual noisy control replies are retained separately.
                        env["DYLD_INSERT_LIBRARIES"] = ""
                    result = subprocess.run(["/bin/bash", str(root / "agent_tools" / launcher), "fixture"],
                                            env=env, capture_output=True, text=True, timeout=15)
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertEqual("Master running (pid=123)\n", result.stdout)
                    self.assertFalse(log.exists(), "injection reached an interpreter before protocol execution")
