"""Causal guards for exact-correlation Android endpoint trust and reverse setup."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from agent_tools import android_endpoint_admission as admission


CORRELATION = "0f3d981d-7d2a-4d15-8cdf-34b884b0e091"
CAMPAIGN = "704f816c-d672-4cbf-a73e-e31ca4bc303b"
BACKUP = "8ff9c1e6-05e5-4e82-910c-14310ed32ff0"
SOURCE = "a" * 40
PACKAGE = "b" * 64
BACKUP_HASH = "c" * 64
LEAF = "d" * 64
CA = b"-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n"


class AndroidEndpointAdmissionTest(unittest.TestCase):
    def _admitted(self, root: Path):
        profile = {"adb": "/opt/android/adb", "cli": "/opt/vpn-control/bin/vpn-control", "serial": "emulator-5554",
                   "expectedAvd": "vpn-control-api35", "api": 35}
        host = SimpleNamespace(android_devices={"api35": profile}, fixture_transfer_root=Path("/private/fixture"))
        config = SimpleNamespace(hosts={"archlinux": host})
        remote = mock.patch.object(admission, "_remote", return_value={"state": "unknown", "reason": "transport_uncertain"})
        patches = [
            mock.patch.object(admission.ssh_transport, "load_config", return_value=config),
            mock.patch.object(admission.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)),
            mock.patch.object(admission.android_native_fixture, "prepare_requirements", return_value={"sourceSha": SOURCE}),
            mock.patch.object(admission.android_native_fixture, "verify_target", return_value={"targetSha256": PACKAGE}),
            mock.patch.object(admission.android_native_fixture_lifecycle, "status", return_value={
                "state": "running", "endpoint": {"hostHttpsPort": 41001, "hostSocksPort": 41002}}),
            mock.patch.object(admission.android_native_fixture_lifecycle, "_read_plan", return_value={
                "host": "archlinux", "device": "api35", "sourceSha": SOURCE, "certificateSha256": LEAF}),
            mock.patch.object(admission.android_admission_readback, "async_collect", return_value={
                "ok": True, "state": "complete", "result": {
                    "package": {"baseSha256": PACKAGE},
                    "device": {"uid": "2000", "api": 35, "avd": "vpn-control-api35"},
                    "guard": {"controllerId": "owner-a", "configurationRevision": 3},
                    "backup": {"path": "/private/fixture/android-readback-" + BACKUP + "/routing.json",
                               "sha256": BACKUP_HASH}}}),
            mock.patch.object(admission.android_admission_readback, "readback_status", return_value={
                "ok": True, "result": {"deviceIdentity": True, "stage": "backup_present",
                                       "controllerId": "owner-a", "configurationRevision": 3,
                                       "backup": {"sha256": BACKUP_HASH}}}),
            mock.patch.object(admission, "_stable_ca", return_value=CA),
            mock.patch.object(admission.subprocess, "run", return_value=SimpleNamespace(stdout="0123abcd\n")),
            remote,
        ]
        stack = contextlib.ExitStack()
        for patcher in patches:
            stack.enter_context(patcher)
        return stack, patches[-1].target, remote

    def _start(self, root: Path):
        return admission.start(root, "archlinux", "api35", CORRELATION, CAMPAIGN, SOURCE,
                               "sha256-" + PACKAGE, "sha256-" + hashlib.sha256(CA).hexdigest(),
                               BACKUP, "owner-a", 3, BACKUP_HASH)

    def test_one_shot_intent_precedes_remote_submission_and_unknown_retains_lease(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with self._admitted(root)[0]:
                result = self._start(root)
                self.assertEqual("unknown", result["state"])
                self.assertFalse(result["replayAllowed"])
                self.assertFalse(result["installerTargetAdmitted"])
                intent = json.loads((root / ".rag_index/android-endpoint-admission" / (CORRELATION + ".json")).read_text())
                self.assertEqual(PACKAGE, intent["remote"]["packageSha256"])
                self.assertEqual(BACKUP_HASH, intent["remote"]["backupSha256"])
                lease = root / ".rag_index/android-native-device-leases/lease-archlinux-api35.json"
                self.assertTrue(lease.exists())
                with self.assertRaises(FileExistsError):
                    self._start(root)
                self.assertTrue(lease.exists())

    def test_owner_or_backup_drift_blocks_submission_before_intent(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with self._admitted(root)[0], mock.patch.object(admission.android_admission_readback, "readback_status",
                    return_value={"ok": True, "result": {"deviceIdentity": True, "stage": "backup_present",
                                                        "controllerId": "other", "configurationRevision": 3,
                                                        "backup": {"sha256": BACKUP_HASH}}}) as _:
                with self.assertRaisesRegex(ValueError, "live owner or backup"):
                    self._start(root)
                self.assertFalse(admission._intent_path(root, CORRELATION).exists())

    def test_remote_reverse_inventory_rejects_duplicate_or_malformed_routes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            expected = {"host": "archlinux", "adb": "/bin/adb", "cli": "/bin/cli", "serial": "emulator-5554",
                        "api": 35, "avd": "vpn-control-api35"}
            namespace = {"__name__": "remote_test", "public_cli_environment": lambda *_args: {}}
            with mock.patch("sys.argv", ["remote", "status", str(root), "api35", CORRELATION,
                                         json.dumps(expected)]), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    exec(admission._REMOTE, namespace)
            namespace["adb_call"] = lambda *_args, **_kwargs: (
                "emulator-5554 tcp:18080 tcp:41001\nemulator-5554 tcp:18080 tcp:41002")
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    namespace["routes"]()
            namespace["routes"] = lambda: {18080: 41001, 18081: 41002, 19000: 44000}
            namespace["expected"].update({"httpsHostPort": 41001, "socksHostPort": 41002})
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    namespace["fixture_routes"]()

    def test_remote_runtime_or_backup_drift_blocks_trust_guard(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700)
            backup = root / "routing.json"; backup.write_bytes(b"opening"); backup.chmod(0o600)
            expected = {"adb": "/bin/adb", "cli": "/bin/cli", "serial": "emulator-5554",
                        "api": 35, "avd": "vpn-control-api35", "owner": "owner-a", "revision": 3,
                        "backupPath": str(backup), "backupSha256": hashlib.sha256(b"opening").hexdigest()}
            namespace = {"__name__": "remote_test", "public_cli_environment": lambda *_args: {}}
            with mock.patch("sys.argv", ["remote", "status", str(root), "api35", CORRELATION,
                                         json.dumps(expected)]), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    exec(admission._REMOTE, namespace)
            namespace["identity"] = mock.Mock()
            namespace["installed"] = mock.Mock()
            namespace["public"] = lambda *args: ({"data": {"runtimeRunning": True,
                                                               "runtimeObservation": "running"}}
                                                    if args == ("status",) else {"data": {"operations": []}})
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    namespace["guard"]()
            namespace["public"] = lambda *args: ({"data": {"runtimeRunning": False,
                                                               "runtimeObservation": "stopped"}}
                                                    if args == ("status",) else {"data": {"operations": []}})
            backup.write_bytes(b"changed")
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    namespace["guard"]()
            namespace["identity"].assert_called()
            namespace["installed"].assert_called()

    def test_lost_response_after_mount_intent_is_partial_and_never_replayed(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700)
            expected = {"host": "archlinux", "adb": "/bin/adb", "cli": "/bin/cli", "serial": "emulator-5554",
                        "api": 35, "avd": "vpn-control-api35", "caSha256": "a" * 64}
            job = root / ("android-endpoint-" + CORRELATION); job.mkdir(mode=0o700)
            for name, value in (("intent.json", expected),
                                ("mount-intent.json", {"target": "/apex/com.android.conscrypt/cacerts"})):
                path = job / name; path.write_text(json.dumps(value)); path.chmod(0o600)
            lease = root / "android-native-device-api35.lease"
            lease.write_text(json.dumps({"owner": "android-endpoint", "correlationId": CORRELATION,
                                         "device": "api35", "host": "archlinux"})); lease.chmod(0o600)
            output = io.StringIO()
            with mock.patch("sys.argv", ["remote", "status", str(root), "api35", CORRELATION,
                                         json.dumps(expected)]), contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit):
                    exec(admission._REMOTE, {"__name__": "remote_test", "public_cli_environment": lambda *_: {}})
            receipt = json.loads(output.getvalue())
            self.assertEqual("partial", receipt["state"])
            self.assertEqual("mount-intent", receipt["phase"])

    def test_partial_cleanup_refuses_foreign_route_or_reused_zygote_before_unmount(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700)
            expected = {"adb": "/bin/adb", "cli": "/bin/cli", "serial": "emulator-5554",
                        "api": 35, "avd": "vpn-control-api35", "httpsHostPort": 41001,
                        "socksHostPort": 41002}
            namespace = {"__name__": "remote_test", "public_cli_environment": lambda *_: {}}
            with mock.patch("sys.argv", ["remote", "status", str(root), "api35", CORRELATION,
                                         json.dumps(expected)]), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    exec(admission._REMOTE, namespace)
            plan = {"target": "/apex/com.android.conscrypt/cacerts",
                    "staging": "/data/local/tmp/vpn-control-endpoint-" + CORRELATION,
                    "stagingIdentity": "0:755:1:2",
                    "zygote": {"pid": "177", "startTicks": 123456,
                               "namespace": "mnt:[4026532888]"}}
            namespace["shell"] = mock.Mock(return_value="2000")
            namespace["guard"] = mock.Mock()
            namespace["routes"] = lambda: {19000: 44000}
            namespace["adb_call"] = mock.Mock()
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    namespace["cleanup_effects"](plan)
            namespace["adb_call"].assert_not_called()
            namespace["routes"] = lambda: {}
            namespace["record"] = mock.Mock()
            namespace["identity"] = mock.Mock()
            namespace["zygote_identity"] = lambda _pid: {"pid": "177", "startTicks": 123457,
                                                          "namespace": "mnt:[4026532888]"}
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    namespace["cleanup_effects"](plan)
            self.assertFalse(any(call.args[:1] == ("nsenter",) or call.args[:1] == ("rm",)
                                 for call in namespace["shell"].call_args_list))

    def test_status_mount_proof_fails_when_ca_bind_disappears(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700)
            expected = {"adb": "/bin/adb", "cli": "/bin/cli", "serial": "emulator-5554",
                        "api": 35, "avd": "vpn-control-api35"}
            namespace = {"__name__": "remote_test", "public_cli_environment": lambda *_: {}}
            with mock.patch("sys.argv", ["remote", "status", str(root), "api35", CORRELATION,
                                         json.dumps(expected)]), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    exec(admission._REMOTE, namespace)
            plan = {"target": "/apex/com.android.conscrypt/cacerts",
                    "staging": "/data/local/tmp/vpn-control-endpoint-" + CORRELATION,
                    "zygote": {"pid": "177", "startTicks": 123456,
                               "namespace": "mnt:[4026532888]"}}
            namespace["zygote_identity"] = lambda _pid: plan["zygote"]
            namespace["shell"] = lambda *_args: ""
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    namespace["mount_observed"](plan)

    def test_nsenter_mount_and_unmount_refuse_generation_change_before_effect(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700)
            expected = {"host": "archlinux", "adb": "/bin/adb", "cli": "/bin/cli",
                        "serial": "emulator-5554", "api": 35, "avd": "vpn-control-api35"}
            namespace = {"__name__": "remote_test", "public_cli_environment": lambda *_: {}}
            with mock.patch("sys.argv", ["remote", "status", str(root), "api35", CORRELATION,
                                         json.dumps(expected)]), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    exec(admission._REMOTE, namespace)
            plan = {"target": "/apex/com.android.conscrypt/cacerts",
                    "staging": "/data/local/tmp/vpn-control-endpoint-" + CORRELATION,
                    "zygote": {"pid": "177", "startTicks": 123456,
                               "namespace": "mnt:[4026532888]"}}
            namespace["zygote_identity"] = lambda _pid: {**plan["zygote"], "startTicks": 123457}
            namespace["shell"] = mock.Mock()
            for action in ("mount_exact", "unmount_exact"):
                with self.subTest(action=action), contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        namespace[action](plan)
            namespace["shell"].assert_not_called()

    def test_premount_partial_cleanup_unroots_without_deleting_unowned_stage(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700)
            expected = {"host": "archlinux", "adb": "/bin/adb", "cli": "/bin/cli",
                        "serial": "emulator-5554", "api": 35, "avd": "vpn-control-api35"}
            job = root / ("android-endpoint-" + CORRELATION); job.mkdir(mode=0o700)
            stage = {"phase": "before_root", "target": "/apex/com.android.conscrypt/cacerts",
                     "staging": "/data/local/tmp/vpn-control-endpoint-" + CORRELATION}
            path = job / "stage.json"; path.write_text(json.dumps(stage)); path.chmod(0o600)
            namespace = {"__name__": "remote_test", "public_cli_environment": lambda *_: {}}
            with mock.patch("sys.argv", ["remote", "status", str(root), "api35", CORRELATION,
                                         json.dumps(expected)]), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    exec(admission._REMOTE, namespace)
            namespace["routes"] = lambda: {}
            namespace["shell"] = mock.Mock(side_effect=lambda *args: "0" if args == ("id", "-u") else "absent")
            namespace["identity"] = mock.Mock()
            namespace["adb_call"] = mock.Mock()
            namespace["finish_cleaned"] = mock.Mock(side_effect=SystemExit)
            with self.assertRaises(SystemExit):
                namespace["cleanup_before_mount"]()
            namespace["adb_call"].assert_any_call("unroot", timeout=30)
            self.assertFalse(any(call.args[:1] == ("rm",) for call in namespace["shell"].call_args_list))

    def test_premount_owned_stage_cleanup_checks_generation_and_inode(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700)
            expected = {"host": "archlinux", "adb": "/bin/adb", "cli": "/bin/cli",
                        "serial": "emulator-5554", "api": 35, "avd": "vpn-control-api35"}
            job = root / ("android-endpoint-" + CORRELATION); job.mkdir(mode=0o700)
            staging = "/data/local/tmp/vpn-control-endpoint-" + CORRELATION
            generation = {"pid": "177", "startTicks": 123456, "namespace": "mnt:[4026532888]"}
            for name, value in (("stage.json", {"phase": "before_root",
                                                "target": "/apex/com.android.conscrypt/cacerts", "staging": staging}),
                                ("stage-owned.json", {"staging": staging, "stagingIdentity": "0:755:1:2",
                                                      "zygote": generation})):
                path = job / name; path.write_text(json.dumps(value)); path.chmod(0o600)
            namespace = {"__name__": "remote_test", "public_cli_environment": lambda *_: {}}
            with mock.patch("sys.argv", ["remote", "status", str(root), "api35", CORRELATION,
                                         json.dumps(expected)]), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    exec(admission._REMOTE, namespace)
            namespace["routes"] = lambda: {}
            namespace["shell"] = mock.Mock(side_effect=lambda *args: "0" if args == ("id", "-u") else "")
            namespace["identity"] = mock.Mock()
            namespace["zygote_identity"] = lambda _pid: generation
            namespace["staging_identity"] = lambda _path: "0:755:1:2"
            namespace["adb_call"] = mock.Mock()
            namespace["finish_cleaned"] = mock.Mock(side_effect=SystemExit)
            with self.assertRaises(SystemExit):
                namespace["cleanup_before_mount"]()
            namespace["shell"].assert_any_call("rm", "-r", staging)

    def test_crash_after_cleaned_receipt_keeps_status_partial_until_exact_lease_release(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700)
            expected = {"host": "archlinux", "adb": "/bin/adb", "cli": "/bin/cli",
                        "serial": "emulator-5554", "api": 35, "avd": "vpn-control-api35",
                        "caSha256": "a" * 64, "packageSha256": PACKAGE, "owner": "owner-a", "revision": 3}
            namespace = {"__name__": "remote_test", "public_cli_environment": lambda *_: {}}
            with mock.patch("sys.argv", ["remote", "status", str(root), "api35", CORRELATION,
                                         json.dumps(expected)]), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    exec(admission._REMOTE, namespace)
            job = root / ("android-endpoint-" + CORRELATION); job.mkdir(mode=0o700)
            cleaned = job / "cleaned.json"
            cleaned.write_text(json.dumps({"correlationId": CORRELATION, "caSha256": expected["caSha256"]})); cleaned.chmod(0o600)
            lease = root / "android-native-device-api35.lease"
            lease.write_text(json.dumps({"owner": "android-endpoint", "host": "archlinux",
                                         "device": "api35", "correlationId": CORRELATION})); lease.chmod(0o600)
            namespace["guard"] = mock.Mock()
            namespace["routes"] = lambda: {}
            status_output = io.StringIO()
            with contextlib.redirect_stdout(status_output):
                with self.assertRaises(SystemExit):
                    namespace["cleaned_terminal"]()
            self.assertEqual("partial", json.loads(status_output.getvalue())["state"])
            self.assertTrue(lease.exists())
            namespace["action"] = "cleanup"
            cleanup_output = io.StringIO()
            with contextlib.redirect_stdout(cleanup_output):
                with self.assertRaises(SystemExit):
                    namespace["cleaned_terminal"]()
            self.assertEqual("cleaned", json.loads(cleanup_output.getvalue())["state"])
            self.assertFalse(lease.exists())

    def test_premount_dangling_symlink_is_not_treated_as_absent_stage(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700)
            expected = {"host": "archlinux", "adb": "/bin/adb", "cli": "/bin/cli",
                        "serial": "emulator-5554", "api": 35, "avd": "vpn-control-api35"}
            job = root / ("android-endpoint-" + CORRELATION); job.mkdir(mode=0o700)
            staging = "/data/local/tmp/vpn-control-endpoint-" + CORRELATION
            stage = job / "stage.json"
            stage.write_text(json.dumps({"phase": "before_root", "target": "/apex/com.android.conscrypt/cacerts",
                                         "staging": staging})); stage.chmod(0o600)
            namespace = {"__name__": "remote_test", "public_cli_environment": lambda *_: {}}
            with mock.patch("sys.argv", ["remote", "status", str(root), "api35", CORRELATION,
                                         json.dumps(expected)]), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    exec(admission._REMOTE, namespace)
            namespace["routes"] = lambda: {}
            namespace["guard"] = mock.Mock()
            namespace["shell"] = lambda *args: "2000" if args == ("id", "-u") else "present" if "-L" in args[-1] else "absent"
            namespace["finish_cleaned"] = mock.Mock()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit):
                    namespace["cleanup_before_mount"]()
            self.assertEqual("unowned_stage_possible", json.loads(output.getvalue())["reason"])
            namespace["finish_cleaned"].assert_not_called()

    def test_cleanup_unknown_never_releases_local_lease(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            directory = admission._local_directory(root)
            intent = {"host": "archlinux", "device": "api35", "correlationId": CORRELATION,
                      "remoteRoot": "/private/fixture", "remote": {}}
            admission.android_native_fixture.write_private_plan(directory / (CORRELATION + ".json"), intent)
            lease_dir = root / ".rag_index/android-native-device-leases"; lease_dir.mkdir(mode=0o700)
            lease = lease_dir / "lease-archlinux-api35.json"
            admission.android_native_fixture.write_private_plan(lease, {"owner": "android-endpoint", "host": "archlinux", "device": "api35", "correlationId": CORRELATION})
            with mock.patch.object(admission, "_remote", return_value={"state": "unknown", "reason": "owner_changed"}):
                result = admission.cleanup(root, CORRELATION)
            self.assertEqual("unknown", result["state"])
            self.assertTrue(lease.exists())

    def test_forged_ready_receipt_cannot_authorize_endpoint(self):
        remote = {"api": 35, "avd": "vpn-control-api35", "packageSha256": PACKAGE,
                  "owner": "owner-a", "revision": 3, "caSha256": hashlib.sha256(CA).hexdigest()}
        intent = {"correlationId": CORRELATION, "remote": remote}
        ready = {"state": "ready", "correlationId": CORRELATION,
                 "device": {"uid": "2000", "api": 35, "avd": "vpn-control-api35"},
                 "packageSha256": PACKAGE, "owner": "owner-a", "revision": 3,
                 "caSha256": remote["caSha256"], "reversePorts": [18080, 18081]}
        self.assertTrue(admission._bound_result(intent, ready, "status")["ok"])
        for field, changed in (("owner", "other"), ("packageSha256", "0" * 64),
                               ("caSha256", "0" * 64), ("reversePorts", [18080])):
            with self.subTest(field=field):
                self.assertEqual("unknown", admission._bound_result(intent, {**ready, field: changed}, "status")["state"])
        self.assertEqual("unknown", admission._bound_result(intent, {**ready, "state": "cleaned", "reversePorts": []}, "start")["state"])

    def test_ca_artifact_requires_verified_exact_bytes_and_no_symlink_ancestry(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            private = root / "private"; private.mkdir(mode=0o700)
            certificate = private / "ca.pem"; certificate.write_bytes(CA); certificate.chmod(0o600)
            artifact = "sha256-" + hashlib.sha256(CA).hexdigest()
            verified = {"verification": "verified", "artifact": {"platform": "android", "artifactKind": "fixture-ca",
                        "sha256": artifact[7:], "sourceSha": SOURCE}, "location": {"localPath": str(certificate)}}
            with mock.patch.object(admission.native_artifact_registry, "verify_artifact", return_value=verified):
                self.assertEqual(CA, admission._stable_ca(root, artifact, SOURCE))
                verified["artifact"]["sourceSha"] = "e" * 40
                with self.assertRaisesRegex(ValueError, "source"):
                    admission._stable_ca(root, artifact, SOURCE)
                verified["artifact"]["sourceSha"] = SOURCE
                certificate.write_bytes(CA + b"tampered")
                with self.assertRaisesRegex(ValueError, "changed"):
                    admission._stable_ca(root, artifact, SOURCE)
                certificate.write_bytes(CA)
                alias = root / "alias"; alias.symlink_to(private, target_is_directory=True)
                verified["location"]["localPath"] = str(alias / "ca.pem")
                with self.assertRaisesRegex(ValueError, "symlink ancestry"):
                    admission._stable_ca(root, artifact, SOURCE)

    def test_mount_and_zygote_proof_reject_stale_generation_or_missing_mount(self):
        expected = {"pid": "177", "startTicks": 123456, "namespace": "mnt:[4026532888]",
                    "target": "/apex/com.android.conscrypt/cacerts",
                    "staging": "/data/local/tmp/vpn-control-endpoint-" + CORRELATION}
        mounted = ("15 1 0:1 /data/local/tmp/vpn-control-endpoint-" + CORRELATION +
                   " /apex/com.android.conscrypt/cacerts rw - tmpfs tmpfs rw\n")
        self.assertTrue(admission._mount_proof(expected, {"pid": "177", "startTicks": 123456,
                                               "namespace": "mnt:[4026532888]"}, mounted))
        self.assertFalse(admission._mount_proof(expected, {"pid": "177", "startTicks": 123457,
                                                "namespace": "mnt:[4026532888]"}, mounted))
        self.assertFalse(admission._mount_proof(expected, {"pid": "177", "startTicks": 123456,
                                                "namespace": "mnt:[4026532999]"}, mounted))
        self.assertFalse(admission._mount_proof(expected, {"pid": "177", "startTicks": 123456,
                                                "namespace": "mnt:[4026532888]"}, ""))


if __name__ == "__main__":
    unittest.main()
