"""Causal and safety checks for the fixed API29 document workflow."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from contextlib import redirect_stdout

from agent_tools import android_admission_readback, android_document_acceptance as subject


class AndroidDocumentAcceptanceTest(unittest.TestCase):
    def test_remote_fixture_is_exact_historical_56k_bytes(self) -> None:
        prefix = "." + "a" * 60 + "." + "b" * 60 + "." + "c" * 60 + ".example.test"
        fixture = {"type": "vpn_control_routing_rules", "version": 7,
                   "rules": {"ignore_rules": False, "block_quic_udp_443": False,
                             "proxy_packages": [],
                             "direct_domain_suffixes": [f"d{i:05d}" + prefix for i in range(56_000)]}}
        payload = json.dumps(fixture).encode()
        self.assertEqual(len(payload), subject._FIXTURE_SIZE)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), subject._FIXTURE_SHA)

    def _terminal(self, root: Path) -> tuple[dict, Path]:
        root.chmod(0o700)
        correlation = "b68a93e0-445d-4cf5-8fee-2f5d90065bd3"
        job = root / ("android-document-job-" + correlation)
        job.mkdir(mode=0o700)
        payloads = {"opening-routing.json": b"{}", "routing-v7-56000.json": b"fixture", "fixture-export.json": b"export"}
        for name, payload in payloads.items():
            path = job / name
            path.write_bytes(payload); path.chmod(0o600)
        digest = lambda name: hashlib.sha256(payloads[name]).hexdigest()
        intent = {"fixtureRoot": str(root), "packageSha256": "a" * 64,
                  "expectedOwner": "b" * 36, "expectedRevision": 0,
                  "fixtureSha256": digest("routing-v7-56000.json"), "fixtureSize": 7}
        receipt = {"state": "complete", "result": {
            "state": "complete", "sourcePackageSha256": "a" * 64,
            "opening": {"controllerId": "b" * 36, "revision": 0,
                        "routingSha256": digest("opening-routing.json"), "routingBytes": 2},
            "fixture": {"sha256": digest("routing-v7-56000.json"), "bytes": 7, "domainCount": 56000},
            "privateExport": {"sha256": digest("fixture-export.json"), "bytes": 6},
            "restore": {"openingRulesRestored": True, "runtimeOff": True}}}
        for name, value in (("intent.json", intent), ("identity.json", {"pid": 1, "startTicks": 1}),
                            ("result.json", receipt)):
            path = job / name
            path.write_text(json.dumps(value)); path.chmod(0o600)
        return intent, job

    @staticmethod
    def _run_status(source: str, root: Path, intent: dict) -> dict:
        command = [sys.executable, "-I", "-B", "-c", "exec(" + repr(source) + ")",
                   str(root), "b68a93e0-445d-4cf5-8fee-2f5d90065bd3",
                   json.dumps(intent, sort_keys=True, separators=(",", ":"))]
        done = subprocess.run(command, capture_output=True, check=True, timeout=10)
        return json.loads(done.stdout)

    def test_document_status_admits_its_own_receipt_and_legacy_reader_rejects_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            intent, _ = self._terminal(Path(tmp))
            legacy = android_admission_readback._ASYNC_STATUS.replace("android-readback-job-", "android-document-job-")
            self.assertEqual(self._run_status(legacy, Path(tmp), intent)["state"], "unknown")
            observed = self._run_status(subject._STATUS, Path(tmp), intent)
            self.assertEqual(observed["state"], "complete")
            self.assertEqual(observed["receipt"]["result"]["fixture"]["domainCount"], 56000)

    def test_document_status_rejects_changed_private_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            intent, job = self._terminal(Path(tmp))
            (job / "fixture-export.json").write_bytes(b"tamper")
            observed = self._run_status(subject._STATUS, Path(tmp), intent)
            self.assertEqual(observed["state"], "unknown")
            self.assertEqual(observed["reason"], "private_hash_mismatch")

    def test_document_status_rejects_symlinked_private_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            intent, job = self._terminal(Path(tmp))
            target = job / "foreign-export.json"
            target.write_bytes(b"export"); target.chmod(0o600)
            (job / "fixture-export.json").unlink()
            (job / "fixture-export.json").symlink_to(target)
            observed = self._run_status(subject._STATUS, Path(tmp), intent)
            self.assertEqual(observed["state"], "unknown")

    def test_unknown_command_failure_reports_only_fixed_private_stage_presence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            intent, job = self._terminal(Path(tmp))
            receipt = job / "result.json"
            receipt.write_text(json.dumps({"state": "unknown", "reason": "command_failed"}))
            receipt.chmod(0o600)
            (job / "fixture-export.json").unlink()
            observed = self._run_status(subject._STATUS, Path(tmp), intent)
            self.assertEqual("unknown", observed["state"])
            self.assertEqual("command_failed", observed["reason"])
            self.assertEqual({"openingRouting": "present", "fixture": "present", "privateExport": "absent"},
                             observed["stageFiles"])
            self.assertNotIn("routing-v7-56000.json", json.dumps(observed))

    def test_unknown_command_failure_reports_durable_nonsecret_phase(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            intent, job = self._terminal(Path(tmp))
            receipt = job / "result.json"
            receipt.write_text(json.dumps({"state": "unknown", "reason": "command_failed",
                                           "command": "SECRET_COMMAND", "stdout": "SECRET_OUTPUT",
                                           "config": "SECRET_CONFIG"}))
            receipt.chmod(0o600)
            phase = job / "phase.json"
            phase.write_text(json.dumps({"phase": "public_import_submitted"}))
            phase.chmod(0o600)
            observed = self._run_status(subject._STATUS, Path(tmp), intent)
            self.assertEqual(observed["state"], "unknown")
            self.assertEqual(observed["reason"], "command_failed")
            self.assertEqual(observed["phase"], "public_import_submitted")
            self.assertNotIn("SECRET_", json.dumps(observed))
            self.assertNotIn("command", observed)
            self.assertNotIn("stdout", observed)
            self.assertNotIn("config", observed)

    def test_unknown_command_failure_rejects_symlinked_phase(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            intent, job = self._terminal(Path(tmp))
            receipt = job / "result.json"
            receipt.write_text(json.dumps({"state": "unknown", "reason": "command_failed"}))
            receipt.chmod(0o600)
            target = job / "foreign-phase.json"
            target.write_text(json.dumps({"phase": "public_import_submitted"}))
            target.chmod(0o600)
            (job / "phase.json").symlink_to(target)
            observed = self._run_status(subject._STATUS, Path(tmp), intent)
            self.assertEqual(observed["state"], "unknown")
            self.assertNotEqual(observed.get("phase"), "public_import_submitted")
            self.assertNotIn("foreign-phase.json", json.dumps(observed))

    def test_worker_writes_durable_phase_before_public_import_failure(self) -> None:
        correlation = "b68a93e0-445d-4cf5-8fee-2f5d90065bd3"
        owner = "c" * 36
        package_hash = "d" * 64
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); root.chmod(0o700)
            job = root / ("android-document-job-" + correlation)
            job.mkdir(mode=0o700)
            original = {"type": "vpn_control_routing_rules", "version": 7,
                        "rules": {"ignore_rules": False, "block_quic_udp_443": False,
                                  "proxy_packages": [], "direct_domain_suffixes": []}}
            original_bytes = json.dumps(original).encode()
            observed_phase = []

            def completed(payload: str | bytes, code: int = 0):
                raw = payload.encode() if isinstance(payload, str) else payload
                return SimpleNamespace(returncode=code, stdout=raw)

            def fake_run(args, **kwargs):
                if args[0] == "/fake/adb":
                    command = args[5:]
                    if command == ["id", "-u"]: return completed("2000")
                    if command == ["getprop", "ro.build.version.sdk"]: return completed("29")
                    if command == ["getprop", "ro.kernel.qemu.avd_name"]: return completed("owned-api29")
                    if command == ["getprop", "ro.boot.qemu.avd_name"]: return completed("")
                    if command == ["getprop", "ro.product.cpu.abi"]: return completed("x86_64")
                    if command == ["getprop", "dalvik.vm.heapsize"]: return completed("48m")
                    if command == ["getprop", "dalvik.vm.heapgrowthlimit"]: return completed("48m")
                    if command == ["pm", "path", "com.kardinal.vpncontrol"]:
                        return completed("package:/data/app/owned/base.apk")
                    if command == ["sha256sum", "/data/app/owned/base.apk"]:
                        return completed(package_hash + "  /data/app/owned/base.apk")
                    raise AssertionError(f"unexpected shell command {command!r}")
                self.assertEqual(args[0], "/fake/cli.py")
                words = args[7:]
                base = {"ok": True, "final": True, "code": "OK",
                        "controllerId": owner, "configurationRevision": 0}
                if words == ["status"]:
                    return completed(json.dumps({**base, "data": {
                        "runtimeRunning": False, "runtimeObservation": "stopped"}}))
                if words == ["operations", "list"]:
                    return completed(json.dumps({**base, "data": {"operations": []}}))
                if words[:2] == ["routing", "export"]:
                    target = Path(words[words.index("--output") + 1])
                    target.write_bytes(original_bytes); target.chmod(0o600)
                    return completed(json.dumps(base))
                if "import" in words:
                    marker = job / "phase.json"
                    self.assertTrue(marker.exists(), "phase must precede public import invoke")
                    self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
                    observed_phase.append(json.loads(marker.read_text()))
                    return completed("SECRET_IMPORT_OUTPUT", code=1)
                raise AssertionError(f"unexpected public command {words!r}")

            args = ["remote-worker", "/fake/adb", "/fake/cli.py", "emulator-5554",
                    "owned-api29", "29", str(root), correlation, package_hash, owner, "0",
                    subject._FIXTURE_SHA, str(subject._FIXTURE_SIZE)]
            output = io.StringIO()
            old_mask = os.umask(0o077)
            os.umask(old_mask)
            try:
                with mock.patch.object(sys, "argv", args), \
                        mock.patch.object(subprocess, "run", side_effect=fake_run), \
                        redirect_stdout(output), self.assertRaises(SystemExit):
                    exec(subject._REMOTE, {"__name__": "__main__"})
            finally:
                os.umask(old_mask)
            self.assertEqual(observed_phase, [{"phase": "public_import_submitted"}])
            self.assertEqual(json.loads(output.getvalue()),
                             {"state": "unknown", "reason": "command_failed"})
            self.assertNotIn("SECRET_IMPORT_OUTPUT", output.getvalue())

    def test_status_requires_exact_existing_intent_without_submission(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            response = subject.status(tmp, "b68a93e0-445d-4cf5-8fee-2f5d90065bd3")
            self.assertEqual(response["state"], "unknown")
            self.assertFalse(response["replayAllowed"])

    def test_start_rejects_foreign_device_before_any_remote_submission(self) -> None:
        with mock.patch.object(subject.ssh_transport, "load_config", side_effect=AssertionError("remote reached")):
            with self.assertRaisesRegex(ValueError, "owned API29"):
                subject.start("/unused", "archlinux", "api35", "b68a93e0-445d-4cf5-8fee-2f5d90065bd3",
                              "sha256-" + "a" * 64, "b68a93e0-445d-4cf5-8fee-2f5d90065bd3",
                              "b68a93e0-445d-4cf5-8fee-2f5d90065bd3", 0)

    def test_device_lease_rejects_second_submission(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            subject._claim_device(tmp, "archlinux", "api29", "b68a93e0-445d-4cf5-8fee-2f5d90065bd3")
            with self.assertRaises(FileExistsError):
                subject._claim_device(tmp, "archlinux", "api29", "2a5d9b68-482d-4405-bd88-65180f5be303")
            self.assertFalse(subject._release_device(tmp, "archlinux", "api29", "2a5d9b68-482d-4405-bd88-65180f5be303"))
            self.assertTrue(subject._lease(tmp, "archlinux", "api29", "b68a93e0-445d-4cf5-8fee-2f5d90065bd3").exists())
            self.assertTrue(subject._release_device(tmp, "archlinux", "api29", "b68a93e0-445d-4cf5-8fee-2f5d90065bd3"))
            self.assertTrue(subject._release_device(tmp, "archlinux", "api29", "b68a93e0-445d-4cf5-8fee-2f5d90065bd3"))

    def test_failed_local_journal_never_claims_device(self) -> None:
        intent = {"host": "archlinux", "device": "api29",
                  "correlationId": "b68a93e0-445d-4cf5-8fee-2f5d90065bd3"}
        with mock.patch.object(subject, "_save", side_effect=OSError("disk full")), \
                mock.patch.object(subject, "_claim_device") as claim:
            with self.assertRaisesRegex(OSError, "disk full"):
                subject._reserve("/unused", intent)
            claim.assert_not_called()

    def test_start_reaches_real_apk_identity_check_before_remote_submission(self) -> None:
        profile = {"api": 29, "adb": "/adb", "cli": "/cli", "serial": "emulator-1",
                   "expectedAvd": "owned-api29"}
        config = SimpleNamespace(hosts={"archlinux": SimpleNamespace(
            android_devices={"api29": profile}, fixture_transfer_root=Path("/fixture"))})
        artifact = {"verification": "verified", "artifact": {"platform": "android",
                    "artifactKind": "native-fixture-apk", "sourceSha": "a" * 40,
                    "sha256": "b" * 64}, "location": {"localPath": "/verified.apk"}}
        with mock.patch.object(subject.ssh_transport, "load_config", return_value=config), \
                mock.patch.object(subject.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)), \
                mock.patch.object(subject.android_observation, "_profile", return_value=profile), \
                mock.patch.object(subject.native_artifact_registry, "verify_artifact", return_value=artifact), \
                mock.patch.object(subject.subprocess, "run", return_value=SimpleNamespace(stdout="a" * 40 + "\n")), \
                mock.patch.object(subject.android_package_install, "_inspect_apk", side_effect=RuntimeError("apk check reached")) as apk_check, \
                mock.patch.object(subject.android_cli_stage, "status", side_effect=AssertionError("remote reached")):
            with self.assertRaisesRegex(RuntimeError, "apk check reached"):
                subject.start("/unused", "archlinux", "api29", "b68a93e0-445d-4cf5-8fee-2f5d90065bd3",
                              "sha256-" + "b" * 64, "b68a93e0-445d-4cf5-8fee-2f5d90065bd3",
                              "b68a93e0-445d-4cf5-8fee-2f5d90065bd3", 0)
            artifact["artifact"]["artifactKind"] = "apk"
            with self.assertRaisesRegex(RuntimeError, "apk check reached"):
                subject.start("/unused", "archlinux", "api29", "b68a93e0-445d-4cf5-8fee-2f5d90065bd3",
                              "sha256-" + "b" * 64, "b68a93e0-445d-4cf5-8fee-2f5d90065bd3",
                              "b68a93e0-445d-4cf5-8fee-2f5d90065bd3", 0)
            self.assertEqual(2, apk_check.call_count)

    def test_start_rejects_unrelated_artifact_kind_before_apk_inspection(self) -> None:
        profile = {"api": 29, "adb": "/adb", "cli": "/cli", "serial": "emulator-1", "expectedAvd": "owned-api29"}
        config = SimpleNamespace(hosts={"archlinux": SimpleNamespace(
            android_devices={"api29": profile}, fixture_transfer_root=Path("/fixture"))})
        artifact = {"verification": "verified", "artifact": {"platform": "android", "artifactKind": "desktop-package"}}
        with mock.patch.object(subject.ssh_transport, "load_config", return_value=config), \
                mock.patch.object(subject.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)), \
                mock.patch.object(subject.android_observation, "_profile", return_value=profile), \
                mock.patch.object(subject.native_artifact_registry, "verify_artifact", return_value=artifact), \
                mock.patch.object(subject.android_package_install, "_inspect_apk") as apk_check:
            with self.assertRaisesRegex(ValueError, "not verified"):
                subject.start("/unused", "archlinux", "api29", "b68a93e0-445d-4cf5-8fee-2f5d90065bd3",
                              "sha256-" + "a" * 64, "b68a93e0-445d-4cf5-8fee-2f5d90065bd3",
                              "b68a93e0-445d-4cf5-8fee-2f5d90065bd3", 0)
            apk_check.assert_not_called()

    def test_heap_probe_rejects_a_larger_guest_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            adb = Path(tmp) / "adb"
            adb.write_text("#!/usr/bin/env python3\nimport sys\na=sys.argv[1:]\n" \
                           "key=a[-1]\nvalues={'ro.kernel.qemu.avd_name':'owned-api29'," \
                           "'ro.boot.qemu.avd_name':'','ro.build.version.sdk':'29'," \
                           "'ro.product.cpu.abi':'x86_64','dalvik.vm.heapsize':'192m'," \
                           "'dalvik.vm.heapgrowthlimit':'192m'}\n" \
                           "print('2000' if key=='-u' else values.get(key,''))\n")
            adb.chmod(0o700)
            command = [sys.executable, "-I", "-B", "-c", "exec(" + repr(subject._HEAP_PROBE) + ")",
                       str(adb), "emulator-owned", "owned-api29"]
            result = subprocess.run(command, capture_output=True, check=True, timeout=10)
            self.assertEqual(json.loads(result.stdout), {"ready": False})
            adb.write_text(adb.read_text().replace("192m", "48m"))
            result = subprocess.run(command, capture_output=True, check=True, timeout=10)
            self.assertEqual(json.loads(result.stdout), {"ready": True})


if __name__ == "__main__":
    unittest.main()
