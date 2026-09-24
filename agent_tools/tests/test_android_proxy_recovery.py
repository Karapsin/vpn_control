"""Causal API29 proxy cache regression with a small Android service model."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from agent_tools import android_proxy_recovery as recovery


PORT = 32123
PROFILE = {"adb": "/opt/android/adb", "cli": "/opt/vpn-control",
           "serial": "emulator-5554", "expectedAvd": "owned-api29", "api": 29}


class AndroidServiceModel:
    """Settings storage and ProxyTracker's in-memory value are distinct."""

    def __init__(self):
        self.stored = dict.fromkeys(recovery._FIELDS, "null")
        self.effective_port = PORT
        self.log = [self._line(time.time() - 5, f"NetworkMonitor/100: PROBE_HTTP Failed to connect to /127.0.0.1:{PORT}")]
        self.commands = []
        self.put_uncertain = False
        self.concurrent_change = False
        self.active_operation = False
        self.no_broadcast = False

    @staticmethod
    def _line(when, message):
        return f"{when:.3f}  1000  1001 D {message}"

    def invoke(self, _root, _host, _profile, _directory, _label, words, _timeout=30):
        self.commands.append(words)
        if words[0] == "env":
            if words[-1] == "status":
                return 0, json.dumps({"ok": True, "final": True, "code": "OK", "controllerId": "owner",
                                      "data": {"runtimeRunning": False, "runtimeObservation": "stopped"}}), ""
            if words[-2:] == ["operations", "list"]:
                entries = [{"final": True} for _ in range(5)]
                if self.active_operation:
                    entries[-1]["final"] = False
                return 0, json.dumps({"ok": True, "final": True, "code": "OK", "controllerId": "owner",
                                      "data": {"operations": entries}}), ""
            raise AssertionError(words)
        args = words[3:]
        if args == ["shell", "id", "-u"]:
            return 0, "2000\n", ""
        if args == ["shell", "getprop", "ro.build.version.sdk"]:
            return 0, "29\n", ""
        if args == ["shell", "getprop", "ro.kernel.qemu.avd_name"]:
            return 0, "owned-api29\n", ""
        if args == ["shell", "getprop", "ro.boot.qemu.avd_name"]:
            return 0, "\n", ""
        if args[:1] == ["logcat"]:
            return 0, "\n".join(self.log) + "\n", ""
        if args[:4] == ["shell", "settings", "get", "global"]:
            field = args[4]
            if self.concurrent_change and _label == "prerestore-http_proxy":
                self.stored[field] = "corp.example:8080"
            return 0, self.stored[field] + "\n", ""
        if args == ["shell", "settings", "put", "global", "http_proxy", ":0"]:
            self.stored.update(dict(zip(recovery._FIELDS, recovery._CLEARED)))
            self.effective_port = None
            if not self.no_broadcast:
                now = time.time() + .01
                self.log.extend([
                    self._line(now, "ProxyTracker: sending Proxy Broadcast for [] 0 xl="),
                    self._line(now + .01, "NetworkMonitor/100: PROBE_HTTP ret=204"),
                    self._line(now + .02, "NetworkMonitor/100: PROBE_HTTPS ret=204"),
                ])
            return (None if self.put_uncertain else 0), "", ""
        if args[:4] == ["shell", "settings", "delete", "global"]:
            self.stored[args[4]] = "null"
            return 0, "Deleted 1 rows\n", ""
        raise AssertionError(words)

    def delete_stored_values_only(self):
        for field in recovery._FIELDS:
            self.stored[field] = "null"


class AndroidProxyRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / ".rag_index").mkdir(mode=0o700)
        self.model = AndroidServiceModel()
        self.config = SimpleNamespace(hosts={"archlinux": SimpleNamespace(android_devices={"api29": PROFILE})})
        load = mock.patch.object(recovery.ssh_transport, "load_config", return_value=self.config)
        invoke = mock.patch.object(recovery, "_invoke", side_effect=self.model.invoke)
        load.start(); invoke.start()
        self.invoke_patch = invoke
        self.addCleanup(load.stop); self.addCleanup(invoke.stop)
        self.correlation = "646b5c7b-e051-4d45-b0de-64164e09f8a7"

    def run_recovery(self):
        return recovery.recover_owned_stale_proxy(self.root, "archlinux", "api29", PORT, self.correlation)

    def actions(self, verb):
        return [x for x in self.model.commands if x[3:6] == ["shell", "settings", verb]]

    def test_delete_only_leaves_cached_proxy_but_observer_clear_succeeds(self):
        self.model.delete_stored_values_only()
        self.assertEqual(PORT, self.model.effective_port)  # the old cleanup's causal failure
        result = self.run_recovery()
        self.assertEqual((True, "complete"), (result["ok"], result["state"]))
        self.assertEqual(None, self.model.effective_port)
        self.assertEqual(("null",) * 5, tuple(self.model.stored.values()))
        self.assertEqual(1, len(self.actions("put")))
        self.assertEqual(5, len(self.actions("delete")))
        self.assertTrue((self.root / ".rag_index" / "android-proxy-recovery" /
                         self.correlation / "complete.json").is_file())

    def test_active_operation_or_legitimate_proxy_rejects_without_write(self):
        self.model.active_operation = True
        result = self.run_recovery()
        self.assertEqual("active_or_unknown_operation", result["reason"])
        self.assertEqual([], self.actions("put"))
        with tempfile.TemporaryDirectory() as second:
            self.root = Path(second)
            (self.root / ".rag_index").mkdir(mode=0o700)
            self.model.active_operation = False
            self.model.stored["global_http_proxy_host"] = "corp.example"
            result = recovery.recover_owned_stale_proxy(self.root, "archlinux", "api29", PORT,
                                                         "50b709b4-5de4-49d4-8c03-15fd965f68c7")
            self.assertEqual("configured_or_unknown_proxy", result["reason"])
            self.assertEqual([], self.actions("put"))

    def test_wrong_profile_rejects_before_any_command(self):
        self.config.hosts["archlinux"].android_devices["api29"] = {**PROFILE, "api": 35}
        with self.assertRaisesRegex(recovery.AndroidProxyRecoveryError, "API29"):
            self.run_recovery()
        self.assertEqual([], self.model.commands)

    def test_uncertain_clear_never_replays_same_correlation(self):
        self.model.put_uncertain = True
        first = self.run_recovery()
        self.assertEqual(("unknown", "clear_write_uncertain"), (first["state"], first["reason"]))
        second = self.run_recovery()
        self.assertEqual(("unknown", "clear_applied_restoration_pending"),
                         (second["state"], second["reason"]))
        self.assertEqual(1, len(self.actions("put")))
        self.assertEqual([], self.actions("delete"))

    def test_concurrent_proxy_change_before_restoration_is_preserved(self):
        self.model.concurrent_change = True
        result = self.run_recovery()
        self.assertEqual(("unknown", "concurrent_proxy_change"), (result["state"], result["reason"]))
        self.assertEqual("corp.example:8080", self.model.stored["http_proxy"])
        self.assertEqual([], self.actions("delete"))

    def test_no_independent_network_evidence_rejects_stored_absence(self):
        self.model.log.clear()
        result = self.run_recovery()
        self.assertEqual("stale_endpoint_unverified", result["reason"])
        self.assertEqual([], self.actions("put"))

    def test_nonzero_ssh_streams_are_retained_privately(self):
        self.invoke_patch.stop()
        directory = self.root / "streams"
        directory.mkdir(mode=0o700)
        with mock.patch.object(recovery.ssh_transport, "build_ssh_argv", return_value=["fake-ssh"]), \
             mock.patch.object(recovery.subprocess, "run", return_value=subprocess.CompletedProcess(
                 ["fake-ssh"], 7, b"partial result", b"specific remote error")):
            code, stdout, stderr = recovery._invoke(self.root, "archlinux", PROFILE, directory,
                                                     "failed-read", ["read-only-command"])
        self.assertEqual((7, "partial result", "specific remote error"), (code, stdout, stderr))
        saved = next(directory.iterdir())
        self.assertEqual(0o600, stat.S_IMODE(os.stat(saved).st_mode))
        self.assertEqual({"label": "failed-read", "exitCode": 7, "stdout": "partial result",
                          "stderr": "specific remote error"},
                         {k: v for k, v in json.loads(saved.read_text()).items() if k != "atEpoch"})


if __name__ == "__main__":
    unittest.main()
