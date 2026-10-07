"""Causal regressions for the API29 disposable VPN permission reset."""
from __future__ import annotations

import base64
import io
import os
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from agent_tools import android_vpn_permission_reset as subject

CORRELATION = "b68a93e0-445d-4cf5-8fee-2f5d90065bd3"
OWNER = "e8d73f61-f7bf-4e24-b13a-aff40b1c8e1b"
SHA = "d" * 64


class _FakeDevice:
    def __init__(self, *, appop="allow", closing_permission="false", operations=None, opening_census=None):
        self.appop = appop
        self.opening_census = opening_census
        self.census_count = 0
        self.closing_permission = closing_permission
        self.operations = operations if operations is not None else []
        self.calls: list[list[str]] = []
        self.adb = ""; self.cli = ""; self.job: Path | None = None
        self.set_calls: list[list[str]] = []
        self.intent_seen_before_set = False
        self.routing_calls = 0
        self.export_bytes: bytes | None = None

    @staticmethod
    def done(text, code=0): return SimpleNamespace(returncode=code, stdout=text.encode())

    def run(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[0] == "python3":
            return self.done(json.dumps({"state": "published", "correlationId": CORRELATION,
                                         "receipt": {"manifestSha256": "a" * 64, "rpmSha256": "b" * 64,
                                                     "launcherSha256": "c" * 64, "desktopJarSha256": "d" * 64,
                                                     "cliPath": self.cli}}))
        if argv[:5] == [self.adb, "-s", "emulator-5554", "shell", "-T"]:
            words = argv[5:]
            facts = {
                ("id", "-u"): "2000\n", ("getprop", "ro.build.version.sdk"): "29\n",
                ("getprop", "ro.kernel.qemu.avd_name"): "owned-api29\n",
                ("getprop", "ro.boot.qemu.avd_name"): "\n", ("getprop", "ro.product.cpu.abi"): "x86_64\n",
                ("pm", "path", "com.kardinal.vpncontrol"): "package:/data/app/owned/base.apk\n",
                ("sha256sum", "/data/app/owned/base.apk"): SHA + "  /data/app/owned/base.apk\n",
            }
            if tuple(words) in facts: return self.done(facts[tuple(words)])
            if words == ["cmd", "appops", "get", "--user", "0", "com.kardinal.vpncontrol", "ACTIVATE_VPN"]:
                self.census_count += 1
                value = self.opening_census if self.census_count == 1 and self.opening_census is not None else self.appop
                return self.done("ACTIVATE_VPN: " + value + "\n")
            if words[:3] == ["cmd", "appops", "set"]:
                self.set_calls.append(words)
                assert self.job is not None
                marker = self.job / "mutation-intent.json"
                self.intent_seen_before_set = marker.is_file() and stat.S_IMODE(marker.stat().st_mode) == 0o600
                if words != ["cmd", "appops", "set", "--user", "0", "com.kardinal.vpncontrol", "ACTIVATE_VPN", "ignore"]:
                    raise AssertionError("unexpected or broad AppOps mutation")
                self.appop = "ignore"
                return self.done("")
            raise AssertionError(f"unexpected shell: {words!r}")
        if argv[:5] != [self.cli, "--json", "--android", "--serial", "emulator-5554"] and argv[:4] != [self.cli, "--android", "--serial", "emulator-5554"]:
            raise AssertionError(f"unexpected public argv: {argv!r}")
        if "diagnostics" in argv:
            permission = self.closing_permission if self.appop == "ignore" else "true"
            return self.done("[runtime]\nmode=VPN\nvpn_permission_granted=" + permission + "\nis_vpn_running=false\n")
        if "status" in argv:
            return self.done(json.dumps({"ok": True, "final": True, "code": "OK", "controllerId": OWNER,
                                         "configurationRevision": 2, "data": {"runtimeRunning": False, "runtimeObservation": "stopped"}}))
        if "routing" in argv:
            self.routing_calls += 1
            target = Path(argv[argv.index("--output") + 1])
            # CLI exports carry generated metadata; semantic rules remain equal.
            payload = self.export_bytes if self.export_bytes is not None else json.dumps({"type": "vpn_control_routing_rules", "version": 7,
                                          "exported_at": "2026-10-02T03:00:%02dZ" % self.routing_calls,
                                          "rules": {"ignore_rules": False}}, sort_keys=True).encode()
            target.write_bytes(payload)
            target.chmod(0o600)
            return self.done(json.dumps({"ok": True, "final": True, "code": "OK", "controllerId": OWNER,
                                         "configurationRevision": 2}))
        if "operations" in argv:
            return self.done(json.dumps({"ok": True, "final": True, "code": "OK", "controllerId": OWNER,
                                         "configurationRevision": 2, "data": {"operations": self.operations}}))
        raise AssertionError(f"unexpected public command: {argv!r}")


def _remote(device: _FakeDevice):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); root.chmod(0o700)
        adb = root / "adb"; cli = root / "vpn-control"
        for path in (adb, cli): path.write_text("#!/bin/sh\nexit 0\n"); path.chmod(0o700)
        job = root / ("android-vpn-permission-reset-" + CORRELATION); job.mkdir(mode=0o700)
        readback = root / ("android-readback-" + CORRELATION); readback.mkdir(mode=0o700)
        backup = {"type": "vpn_control_routing_rules", "version": 7, "rules": {"ignore_rules": False}}
        (readback / "routing.json").write_text(json.dumps(backup, sort_keys=True)); (readback / "routing.json").chmod(0o600)
        backup_sha = __import__("hashlib").sha256((readback / "routing.json").read_bytes()).hexdigest()
        device.adb, device.cli, device.job = str(adb), str(cli), job
        output = io.StringIO()
        argv = ["worker", str(adb), str(cli), "emulator-5554", "owned-api29", str(root), CORRELATION, SHA, OWNER, "2", CORRELATION, backup_sha, CORRELATION, "a" * 64, "b" * 64, "c" * 64, "d" * 64]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(subprocess, "run", side_effect=device.run), mock.patch("sys.stdout", output):
            try: exec(subject._REMOTE, {"__name__": "__main__"})
            except SystemExit: pass
        return json.loads(output.getvalue()), device


def _collect_remote(device: _FakeDevice, *, symlink_export: bool = False, hardlink_export: bool = False) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); root.chmod(0o700)
        adb = root / "adb"; cli = root / "vpn-control"
        for path in (adb, cli): path.write_text("#!/bin/sh\nexit 0\n"); path.chmod(0o700)
        job = root / ("android-vpn-permission-reset-" + CORRELATION); job.mkdir(mode=0o700)
        readback = root / ("android-readback-" + CORRELATION); readback.mkdir(mode=0o700)
        backup = {"type": "vpn_control_routing_rules", "version": 7, "rules": {"ignore_rules": False}}
        route = readback / "routing.json"; route.write_text(json.dumps(backup, sort_keys=True)); route.chmod(0o600)
        backup_sha = __import__("hashlib").sha256(route.read_bytes()).hexdigest()
        if symlink_export:
            outside = root / "outside.json"; outside.write_text("{}"); outside.chmod(0o600)
            (job / "collect-routing.json").symlink_to(outside)
        if hardlink_export:
            outside = root / "outside.json"; outside.write_text("{}"); outside.chmod(0o600)
            (job / "collect-routing.json").hardlink_to(outside)
        device.appop = "ignore"; device.closing_permission = "false"
        device.adb, device.cli, device.job = str(adb), str(cli), job
        out = io.StringIO()
        argv = ["collect", str(adb), str(cli), "emulator-5554", "owned-api29", str(root), CORRELATION, SHA,
                OWNER, "2", CORRELATION, backup_sha]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(subprocess, "run", side_effect=device.run), \
                mock.patch("sys.stdout", out):
            try: exec(subject._COLLECT, {"__name__": "__main__"})
            except SystemExit: pass
        return json.loads(out.getvalue())


class AndroidVpnPermissionResetTest(unittest.TestCase):
    def test_one_exact_scoped_ignore_mutation_is_journaled_before_execution(self):
        value, device = _remote(_FakeDevice())
        self.assertEqual(value["state"], "complete")
        self.assertEqual(device.set_calls, [["cmd", "appops", "set", "--user", "0", "com.kardinal.vpncontrol", "ACTIVATE_VPN", "ignore"]])
        self.assertTrue(device.intent_seen_before_set)
        self.assertGreaterEqual(device.routing_calls, 3)  # differing exported_at values did not cause false drift
        remote = subject._REMOTE
        self.assertNotIn('"default"', remote)
        self.assertNotIn('"reset"', remote)
        self.assertNotIn('"allow")', remote)

    def test_unknown_opening_appop_never_mutates(self):
        value, device = _remote(_FakeDevice(opening_census="ignore"))
        self.assertEqual(value, {"state": "unknown", "reason": "opening_appop_not_allow"})
        self.assertEqual(device.set_calls, [])

    def test_permission_or_post_census_failure_preserves_unknown_and_never_replays(self):
        value, device = _remote(_FakeDevice(closing_permission="true"))
        self.assertEqual(value, {"state": "unknown", "reason": "closing_diagnostics_changed"})
        self.assertEqual(len(device.set_calls), 1)

    def test_active_or_unknown_operation_blocks_before_mutation(self):
        value, device = _remote(_FakeDevice(operations=[{"controllerId": OWNER, "final": False, "phase": "running"}]))
        self.assertEqual(value, {"state": "unknown", "reason": "opening_operations_active_or_unknown"})
        self.assertEqual(device.set_calls, [])

    def test_endpoint_lease_is_an_admission_blocker_without_deleting_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); lease = root / ".rag_index/android-native-device-leases/lease-archlinux-api29.json"
            lease.parent.mkdir(mode=0o700, parents=True); lease.write_text('{"correlationId":"x"}')
            lease.chmod(0o600)
            self.assertTrue(subject._endpoint_lease_active(root))
            self.assertTrue(lease.exists())

    def test_local_intent_is_durable_and_status_missing_intent_has_no_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(subject.status(root, CORRELATION)["reason"], "missing_local_intent")
            intent = {"correlationId": CORRELATION, "host": "archlinux"}
            subject._save(root, intent)
            self.assertEqual(subject._load(root, CORRELATION), intent)
            self.assertEqual(stat.S_IMODE(subject._journal(root, CORRELATION).stat().st_mode), 0o600)

    def test_submit_uses_reset_job_prefix_so_worker_and_status_share_one_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); root.chmod(0o700)
            intent = {"fixtureRoot": str(root), "correlationId": CORRELATION}
            output = io.StringIO()
            # This local detached worker is inert; it proves only the submit-to-job transition.
            fake = SimpleNamespace(pid=4242, kill=lambda: None, wait=lambda timeout: None)
            original_read_text = Path.read_text
            def proc_stat(path, *args, **kwargs):
                if str(path) == "/proc/4242/stat": return "4242 (worker) " + " ".join(["S"] + ["0"] * 19 + ["77"])
                return original_read_text(path, *args, **kwargs)
            with mock.patch.object(sys, "argv", ["submit", str(root), CORRELATION,
                                                  json.dumps(intent), base64.urlsafe_b64encode(b"pass").decode()]), \
                    mock.patch("sys.stdout", output), mock.patch.object(subprocess, "Popen", return_value=fake), \
                    mock.patch.object(Path, "read_text", proc_stat):
                exec(subject._SUBMIT, {"__name__": "__main__"})
            value = json.loads(output.getvalue())
            self.assertEqual(value["state"], "submitted")
            job = root / ("android-vpn-permission-reset-" + CORRELATION)
            self.assertTrue((job / "intent.json").is_file())
            self.assertTrue((job / "release").is_file())
            self.assertFalse((root / ("android-document-job-" + CORRELATION)).exists())

    def test_exact_reset_lease_releases_only_after_matching_owner_and_foreign_lease_is_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); directory = root / ".rag_index/android-native-device-leases"
            directory.mkdir(mode=0o700, parents=True)
            lease = directory / "lease-archlinux-api29.json"
            exact = {"owner": "android-vpn-permission-reset", "correlationId": CORRELATION,
                     "device": "api29", "host": "archlinux"}
            lease.write_text(json.dumps(exact)); lease.chmod(0o600)
            self.assertTrue(subject._release_reset_lease(root, CORRELATION))
            self.assertFalse(lease.exists())
            lease.write_text(json.dumps({**exact, "owner": "foreign"})); lease.chmod(0o600)
            self.assertFalse(subject._release_reset_lease(root, CORRELATION))
            self.assertTrue(lease.exists())

    def test_lease_same_inode_replacement_after_read_is_not_released(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); directory = root / ".rag_index/android-native-device-leases"
            directory.mkdir(mode=0o700, parents=True); lease = directory / "lease-archlinux-api29.json"
            exact = {"owner": "android-vpn-permission-reset", "correlationId": CORRELATION,
                     "device": "api29", "host": "archlinux"}
            lease.write_text(json.dumps(exact)); lease.chmod(0o600)
            original = os.read
            changed = False
            def mutate(fd, size):
                nonlocal changed
                value = original(fd, size)
                if not changed:
                    changed = True
                    os.utime(lease, None)
                return value
            with mock.patch("os.read", side_effect=mutate):
                self.assertFalse(subject._release_reset_lease(root, CORRELATION))
            self.assertTrue(lease.exists())

    def test_collector_source_uses_configured_avd_and_bounded_private_exports(self):
        self.assertIn('!={avd}', subject._COLLECT)
        self.assertIn('getattr(os,"O_NOFOLLOW",0)', subject._COLLECT)
        self.assertIn('info.st_nlink!=1', subject._COLLECT)
        self.assertIn('0<info.st_size<=limit', subject._COLLECT)
        self.assertNotIn('target.read_bytes()', subject._COLLECT)

    def test_collector_executes_fresh_success_not_status_mock_only(self):
        self.assertEqual(_collect_remote(_FakeDevice()), {"state": "complete"})

    def test_collector_rejects_symlink_export_before_any_lease_release(self):
        value = _collect_remote(_FakeDevice(), symlink_export=True)
        self.assertEqual(value, {"state": "unknown", "reason": "collect_private_file_unsafe"})

    def test_collector_rejects_hardlink_and_oversize_export(self):
        self.assertEqual(_collect_remote(_FakeDevice(), hardlink_export=True),
                         {"state": "unknown", "reason": "collect_private_file_unsafe"})
        device = _FakeDevice(); device.export_bytes = b"x" * (67_108_865)
        self.assertEqual(_collect_remote(device), {"state": "unknown", "reason": "collect_private_file_unsafe"})

    def test_fixed_api29_constants_prevent_foreign_user_package_or_operation(self):
        self.assertEqual((subject._HOST, subject._DEVICE, subject._API, subject._USER, subject._PACKAGE, subject._OP, subject._MODE),
                         ("archlinux", "api29", 29, "0", "com.kardinal.vpncontrol", "ACTIVATE_VPN", "ignore"))


class PermissionTerminalTypesTest(unittest.TestCase):
    """Execute the actual status programme over private synthetic receipt files."""
    def observe(self, mutation=None):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            job = root / ("android-vpn-permission-reset-" + CORRELATION)
            job.mkdir(mode=0o700)
            intent = {"expectedOwner": OWNER, "expectedRevision": 2}
            result = {"state": "complete", "api": 29, "package": "com.kardinal.vpncontrol",
                      "appOp": "ACTIVATE_VPN", "mode": "ignore", "runtimeOff": True,
                      "permissionAbsent": True, "owner": OWNER, "revision": 2}
            if mutation is not None: mutation(result)
            records = {"intent.json": intent, "identity.json": {"pid": 42, "startTicks": 43},
                       "result.json": {"state": "complete", "result": result}}
            for name, value in records.items():
                path = job / name; path.write_text(json.dumps(value)); path.chmod(0o600)
            before = {p.name: p.read_bytes() for p in job.iterdir()}
            output = io.StringIO()
            from contextlib import redirect_stdout
            with mock.patch("sys.argv", ["status", str(root), CORRELATION, json.dumps(intent)]), redirect_stdout(output):
                with self.assertRaises(SystemExit):
                    exec(subject._STATUS, {"__name__": "terminal_types_test"})
            self.assertEqual(before, {p.name: p.read_bytes() for p in job.iterdir()})
            return json.loads(output.getvalue())

    def test_genuine_receipt_is_complete(self):
        self.assertEqual("complete", self.observe()["state"])

    def test_numeric_boolean_and_float_integer_substitutes_stay_unknown(self):
        for key, value in (("runtimeOff", 1), ("permissionAbsent", 1), ("api", 29.0), ("revision", 2.0)):
            with self.subTest(key=key):
                actual = self.observe(lambda result: result.update({key: value}))
                self.assertEqual("unknown", actual["state"])
                self.assertEqual("terminal_binding_invalid", actual["reason"])

    def test_missing_extra_and_false_fields_stay_unknown(self):
        for mutation in (lambda result: result.pop("api"), lambda result: result.update(extra=True),
                         lambda result: result.update(runtimeOff=False), lambda result: result.update(api=True)):
            with self.subTest(mutation=mutation):
                self.assertEqual("unknown", self.observe(mutation)["state"])


if __name__ == "__main__": unittest.main()
