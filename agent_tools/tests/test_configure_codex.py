import importlib.util
from pathlib import Path
import tempfile
import unittest
import tomllib

SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("configure_codex", SOURCE / "configure_codex.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ConfigureCodexTest(unittest.TestCase):
    def test_paths_are_derived_and_existing_settings_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'checkout café $literal "quote"'
            (root / "agent_tools").mkdir(parents=True)
            (root / "agent_tools/codex-config.toml.in").write_bytes((SOURCE / "codex-config.toml.in").read_bytes())
            output = module.configure(root, "/bin/bash")
            config = tomllib.loads(output.read_text())["mcp_servers"]["vpn_control"]
            self.assertEqual(config["cwd"], str(root.resolve()))
            self.assertEqual(config["args"], [str(root.resolve() / "agent_tools/mcp_server.sh")])
            output.write_text("# personal settings\n")
            with self.assertRaises(FileExistsError):
                module.configure(root, "/bin/bash")
            self.assertEqual(output.read_text(), "# personal settings\n")
            module.configure(root, "/bin/bash", replace=True)
            self.assertEqual(next(output.parent.glob("config.backup-*.toml")).read_text(), "# personal settings\n")
            self.assertEqual(module.configure(root, "/bin/bash"), output)


if __name__ == "__main__":
    unittest.main()
