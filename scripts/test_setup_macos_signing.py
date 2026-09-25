#!/usr/bin/env python3
"""Regression tests for repeatable, owned macOS signing-keychain setup."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
SETUP = ROOT / "scripts/setup_macos_signing.sh"


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "requires POSIX Bash fake-command fixture")
class MacosSigningSetupTest(unittest.TestCase):
    def test_two_fixture_stages_reuse_only_the_owned_runner_keychain(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        tools = root / "tools"
        tools.mkdir()
        log = root / "security.log"
        (tools / "uname").write_text("#!/usr/bin/env bash\necho Darwin\n", encoding="utf-8")
        (tools / "base64").write_text("#!/usr/bin/env bash\ncat\n", encoding="utf-8")
        (tools / "security").write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\nprintf '%s\\n' \"$*\" >> \"$SECURITY_LOG\"\n"
            "if [[ \"$1\" == create-keychain ]]; then\n"
            "  path=\"${@: -1}\"; [[ ! -e \"$path\" ]] || exit 42; touch \"$path\"\n"
            "elif [[ \"$1\" == find-identity ]]; then\n"
            "  printf '1) fixture-identity\\n'\n"
            "fi\n",
            encoding="utf-8",
        )
        for tool in tools.iterdir():
            tool.chmod(0o755)
        environment = os.environ | {
            "PATH": str(tools) + os.pathsep + os.environ["PATH"],
            "RUNNER_TEMP": str(root / "runner-temp"),
            "SECURITY_LOG": str(log),
            "VPN_CONTROL_MACOS_SIGNING_CERTIFICATE_BASE64": "fixture-certificate",
            "VPN_CONTROL_MACOS_SIGNING_CERTIFICATE_PASSWORD": "certificate-password",
            "VPN_CONTROL_MACOS_SIGNING_IDENTITY": "fixture-identity",
            "VPN_CONTROL_MACOS_KEYCHAIN_PASSWORD": "keychain-password",
        }
        result = subprocess.run(
            ["bash", "-e", "-c", f'. "{SETUP}"; . "{SETUP}"'],
            text=True,
            capture_output=True,
            env=environment,
            timeout=10,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        calls = log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(1, sum(call.startswith("create-keychain ") for call in calls))
        self.assertEqual(2, sum(call.startswith("unlock-keychain ") for call in calls))
        self.assertFalse(any(call.startswith("delete-keychain ") for call in calls))
        marker = root / "runner-temp/macos-signing/vpn-control-signing.keychain-db.owner"
        self.assertEqual("vpn-control-managed-keychain-v1\n", marker.read_text(encoding="utf-8"))

    def test_setup_refuses_an_unmarked_existing_keychain_without_deleting_it(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        tools = root / "tools"
        tools.mkdir()
        log = root / "security.log"
        keychain = root / "runner-temp/macos-signing/vpn-control-signing.keychain-db"
        keychain.parent.mkdir(parents=True)
        keychain.touch()
        (tools / "uname").write_text("#!/usr/bin/env bash\necho Darwin\n", encoding="utf-8")
        (tools / "security").write_text("#!/usr/bin/env bash\nprintf 'CALLED\\n' >> \"$SECURITY_LOG\"\n", encoding="utf-8")
        for tool in tools.iterdir():
            tool.chmod(0o755)
        environment = os.environ | {
            "PATH": str(tools) + os.pathsep + os.environ["PATH"],
            "RUNNER_TEMP": str(root / "runner-temp"),
            "SECURITY_LOG": str(log),
            "VPN_CONTROL_MACOS_SIGNING_CERTIFICATE_BASE64": "fixture-certificate",
            "VPN_CONTROL_MACOS_SIGNING_CERTIFICATE_PASSWORD": "certificate-password",
            "VPN_CONTROL_MACOS_SIGNING_IDENTITY": "fixture-identity",
            "VPN_CONTROL_MACOS_KEYCHAIN_PASSWORD": "keychain-password",
        }
        result = subprocess.run(["bash", "-c", f'. "{SETUP}"'], text=True, capture_output=True,
                                env=environment, timeout=10)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("keychain ownership marker is missing or invalid", result.stderr)
        self.assertFalse(log.exists())
        self.assertTrue(keychain.exists())


if __name__ == "__main__":
    unittest.main()
