import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_tools import local_build_environment, mcp_server


class LocalBuildEnvironmentTest(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "getuid"), "Requires POSIX file ownership")
    def test_managed_command_receives_private_local_java_home(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".codex").mkdir()
            java_home = root / "jdk"
            (java_home / "bin").mkdir(parents=True)
            java = java_home / "bin" / "java"
            java.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            java.chmod(0o700)
            config = root / ".codex" / "build-env.local.json"
            config.write_text(json.dumps({"JAVA_HOME": str(java_home)}), encoding="utf-8")
            config.chmod(0o600)
            with mock.patch.object(mcp_server, "REPO_ROOT", root), mock.patch.dict(os.environ, {"JAVA_HOME": "original"}):
                result = mcp_server._run([sys.executable, "-c", "import os; print('JAVA_HOME=' + os.environ['JAVA_HOME'])"], output_limit=None)
                self.assertEqual("original", os.environ["JAVA_HOME"])
            self.assertTrue(result["ok"], result)
            self.assertIn(f"JAVA_HOME={java_home}", result["stdout"])

    @unittest.skipUnless(hasattr(os, "getuid"), "Requires POSIX file ownership")
    def test_invalid_or_world_readable_config_cannot_set_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".codex").mkdir()
            config = root / ".codex" / "build-env.local.json"
            config.write_text(json.dumps({"JAVA_HOME": "relative/path"}), encoding="utf-8")
            config.chmod(0o600)
            with mock.patch.object(mcp_server, "REPO_ROOT", root), mock.patch.dict(os.environ, {}, clear=True):
                invalid = mcp_server._run([sys.executable, "-c", "pass"])
            self.assertFalse(invalid["ok"])
            config.write_text(json.dumps({"JAVA_HOME": "/tmp"}), encoding="utf-8")
            config.chmod(0o644)
            with mock.patch.object(mcp_server, "REPO_ROOT", root), mock.patch.dict(os.environ, {}, clear=True):
                public = mcp_server._run([sys.executable, "-c", "pass"])
            self.assertFalse(public["ok"])

    def test_missing_config_does_not_require_posix_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(os, "getuid", create=True):
            del os.getuid
            self.assertEqual({"JAVA_HOME": "inherited"},
                             local_build_environment.apply(Path(temporary), {"JAVA_HOME": "inherited"}))

    def test_existing_config_without_ownership_support_never_starts_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".codex").mkdir()
            (root / ".codex" / "build-env.local.json").write_text("{}", encoding="utf-8")
            with mock.patch.object(os, "getuid", create=True), mock.patch.object(mcp_server, "REPO_ROOT", root), \
                    mock.patch.object(mcp_server.subprocess, "run") as child:
                del os.getuid
                result = mcp_server._run([sys.executable, "-c", "pass"])
            self.assertFalse(result["ok"])
            self.assertIn("POSIX ownership", result["stderr"])
            child.assert_not_called()

    @unittest.skipUnless(hasattr(os, "getuid"), "Requires POSIX file ownership")
    def test_replacement_after_inspection_cannot_bypass_private_file_checks(self) -> None:
        for replacement_kind in ("public-file", "symlink"):
            with self.subTest(replacement=replacement_kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / ".codex").mkdir()
                config = root / ".codex" / "build-env.local.json"
                config.write_text("{}", encoding="utf-8")
                config.chmod(0o600)
                replacement = root / "replacement.json"
                replacement.write_text(json.dumps({"ANDROID_HOME": str(root)}), encoding="utf-8")
                replacement.chmod(0o644 if replacement_kind == "public-file" else 0o600)
                original_lstat = Path.lstat

                def inspect_then_replace(path):
                    info = original_lstat(path)
                    if path == config:
                        if replacement_kind == "public-file":
                            os.replace(replacement, config)
                        else:
                            config.unlink()
                            config.symlink_to(replacement)
                    return info

                with mock.patch.object(Path, "lstat", inspect_then_replace):
                    with self.assertRaises(local_build_environment.LocalBuildEnvironmentError):
                        local_build_environment.apply(root, {})


if __name__ == "__main__":
    unittest.main()
