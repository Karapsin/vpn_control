from __future__ import annotations

import json
import hashlib
from pathlib import Path
import ssl
import subprocess
import tempfile
import unittest
from unittest.mock import patch

try:
    from scripts import native_fixture_preflight as preflight
except ModuleNotFoundError:  # Direct script invocation puts scripts/ on sys.path.
    import native_fixture_preflight as preflight


class NativeFixtureGuestProbeTest(unittest.TestCase):
    def workspace(self, directory: str, *, url="https://fixture.example/test", enabled=True):
        path = Path(directory) / "workspace.json"
        path.write_text(json.dumps({"subscription_refresh_policy": "EVERY_HOUR",
            "find_best_after_subscription_refresh": enabled,
            "validation_settings": {"test_url": url, "batch_size": 3,
                "subscription_refresh_concurrency": 2, "retry_count": 1,
                "active_verification_window_size": 4}}), encoding="utf-8")
        return path

    def test_wrong_validation_url_blocks_find_best_fixture(self):
        with tempfile.TemporaryDirectory() as raw:
            path = self.workspace(raw, url="https://other.example/test")
            result = preflight._settings(path, "https://fixture.example/test")
        self.assertTrue(result["workspace"])
        self.assertFalse(result["settings"])
        self.assertFalse(result["benchmarkSettings"])

    def test_disabled_find_best_and_invalid_measurement_knobs_block(self):
        with tempfile.TemporaryDirectory() as raw:
            path = self.workspace(raw, enabled=False)
            self.assertFalse(preflight._settings(path, "https://fixture.example/test")["settings"])
            self.assertTrue(preflight._settings(path, "https://fixture.example/test", require_find_best=False)["settings"])
            value = json.loads(path.read_text())
            value["find_best_after_subscription_refresh"] = True
            value["validation_settings"]["batch_size"] = False
            path.write_text(json.dumps(value))
            self.assertFalse(preflight._settings(path, "https://fixture.example/test")["benchmarkSettings"])

    def test_endpoint_rejects_wrong_protocol_before_network(self):
        with patch.object(preflight.socket, "create_connection") as connect:
            result = preflight._endpoint("http://fixture.example/test", 2, None)
        self.assertFalse(result["protocol"])
        connect.assert_not_called()

    def test_expired_or_wrong_certificate_cannot_admit_endpoint(self):
        class Raw:
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def settimeout(self, *_): pass
        class Context:
            def wrap_socket(self, *_args, **_kwargs):
                raise ssl.SSLCertVerificationError("certificate has expired")
        with patch.object(preflight.socket, "create_connection", return_value=Raw()), \
             patch.object(preflight.ssl, "create_default_context", return_value=Context()):
            result = preflight._endpoint("https://fixture.example/test", 2, None)
        self.assertTrue(result["protocol"])
        self.assertFalse(result["certificate"])
        self.assertFalse(result["endpoint"])

    def test_static_admission_requires_exact_package_jar_and_stopped_protected_owner(self):
        with tempfile.TemporaryDirectory() as raw:
            jar = Path(raw) / "desktopApp-fixed.jar"
            jar.write_bytes(b"frozen")
            typed = {"expectedPackageNevra": "vpn-control-2.2.1-1.x86_64",
                     "expectedDesktopJarSha256": hashlib.sha256(b"frozen").hexdigest(),
                     "protectedStateDir": "/owned/state", "protectedControllerId": "owner-17"}
            replies = [subprocess.CompletedProcess([], 0, "vpn-control-2.2.1-1.x86_64\n", ""),
                       subprocess.CompletedProcess([], 0, "", ""),
                       subprocess.CompletedProcess([], 0, json.dumps({"controllerId": "owner-17",
                           "data": {"runtimeRunning": False}}), "")]
            with patch.object(preflight.subprocess, "run", side_effect=replies), \
                 patch.object(Path, "glob", return_value=[jar]):
                self.assertTrue(preflight.linux_scheduled_static(typed)["ready"])
            replies[-1] = subprocess.CompletedProcess([], 0, json.dumps({"controllerId": "owner-18",
                "data": {"runtimeRunning": False}}), "")
            with patch.object(preflight.subprocess, "run", side_effect=replies), \
                 patch.object(Path, "glob", return_value=[jar]):
                failed = preflight.linux_scheduled_static(typed)
            self.assertFalse(failed["ready"])
            self.assertFalse(failed["checks"]["protectedOwner"])


if __name__ == "__main__":
    unittest.main()
