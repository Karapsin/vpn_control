"""Regression for current live Linux runtime config and user proxy port selection."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from linux_fixture_runtime_config import (RuntimeConfigError, RuntimeProcess,
                                          resolve_owned_runtime_config,
                                          select_user_proxy_port)


class RuntimeConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / "state"
        self.config = self.state / "runtime" / "candidate-actual" / "config.json"
        self.config.parent.mkdir(parents=True)
        self.payload = {"inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 31234},
            {"type": "mixed", "tag": "management-in", "listen": "127.0.0.1", "listen_port": 34567},
        ]}
        self.config.write_text(json.dumps(self.payload))
        self.owner = RuntimeProcess(10, 1, ("/opt/vpn-control/bin/vpn-control", "serve"))
        self.runtime = RuntimeProcess(11, 10, (str(self.state / "runtime" / "tools" / "sing-box"),
                                               "run", "-c", str(self.config)))

    def test_live_candidate_config_and_user_port_with_management_inbound(self):
        # The product writes candidate-*/config.json, not the old static filename.
        self.assertFalse((self.state / "runtime" / "runtime-sing-box-proxy_only.json").exists())
        path = resolve_owned_runtime_config(self.state, 10, (self.owner, self.runtime))
        self.assertEqual(self.config.resolve(), path)
        self.assertEqual(31234, select_user_proxy_port(json.loads(path.read_text())))

    def test_foreign_runtime_is_not_selected(self):
        foreign = RuntimeProcess(11, 99, self.runtime.argv)
        with self.assertRaisesRegex(RuntimeConfigError, "exactly one"):
            resolve_owned_runtime_config(self.state, 10, (self.owner, foreign))

    def test_ambiguous_owned_runtime_is_rejected(self):
        second = RuntimeProcess(12, 10, self.runtime.argv)
        with self.assertRaisesRegex(RuntimeConfigError, "exactly one"):
            resolve_owned_runtime_config(self.state, 10, (self.owner, self.runtime, second))

    @unittest.skipUnless(os.name == "posix", "POSIX fixture symlink admission")
    def test_config_symlink_escape_is_rejected(self):
        outside = Path(self.temp.name) / "outside.json"
        outside.write_text(json.dumps(self.payload))
        self.config.unlink()
        self.config.symlink_to(outside)
        with self.assertRaisesRegex(RuntimeConfigError, "exactly one"):
            resolve_owned_runtime_config(self.state, 10, (self.owner, self.runtime))

    def test_missing_user_tag_is_rejected_even_with_management_mixed(self):
        with self.assertRaisesRegex(RuntimeConfigError, "exactly one"):
            select_user_proxy_port({"inbounds": [self.payload["inbounds"][1]]})


if __name__ == "__main__":
    unittest.main()
