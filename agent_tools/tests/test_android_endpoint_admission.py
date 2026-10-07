"""Causal guards for exact-correlation Android endpoint trust and reverse setup."""

from __future__ import annotations

import shlex
import subprocess

import contextlib
import hashlib
import io
import json
import os
import stat
import sys
from pathlib import Path
import tempfile
import threading
import time
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


def _public_words(argv):
    words = argv[7:]
    return words[2:] if words[:1] == ['--controller-id'] else words


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
                    "device": {"uid": "2000", "api": 35, "avd": "vpn-control-api35", "abi": "x86_64"},
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

    def test_clean_linked_source_admits_dirty_coordinator_without_serializing_path(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            clean_source = root / "clean-source"; clean_source.mkdir()
            requirements = {"sourceSha": SOURCE}
            verified = {"targetSha256": PACKAGE}
            with self._admitted(root)[0], \
                    mock.patch.object(admission.android_native_fixture, "_source_root", return_value=clean_source) as bind, \
                    mock.patch.object(admission.android_native_fixture, "prepare_requirements", return_value=requirements) as prepare, \
                    mock.patch.object(admission.android_native_fixture, "verify_target", return_value=verified) as verify:
                result = admission.start(root, "archlinux", "api35", CORRELATION, CAMPAIGN, SOURCE,
                                         "sha256-" + PACKAGE, "sha256-" + hashlib.sha256(CA).hexdigest(),
                                         BACKUP, "owner-a", 3, BACKUP_HASH, source_root=clean_source)
            self.assertEqual("unknown", result["state"])
            bind.assert_called_once_with(root, clean_source)
            prepare.assert_called_once_with(root, SOURCE, source_root=clean_source)
            verify.assert_called_once_with(root, requirements, "sha256-" + PACKAGE, source_root=clean_source)
            intent = admission._read_intent(root, CORRELATION)
            self.assertNotIn("sourceRoot", intent)
            self.assertNotIn(str(clean_source), json.dumps(intent, sort_keys=True))

    def test_invalid_source_root_rejects_before_endpoint_lease_or_dispatch(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            for reason in ("foreign", "dirty", "symlink"):
                with self.subTest(reason=reason), self._admitted(root)[0], \
                        mock.patch.object(admission.android_native_fixture, "_source_root", side_effect=ValueError(reason)), \
                        mock.patch.object(admission, "_remote") as remote:
                    with self.assertRaisesRegex(ValueError, reason):
                        admission.start(root, "archlinux", "api35", CORRELATION, CAMPAIGN, SOURCE,
                                        "sha256-" + PACKAGE, "sha256-" + hashlib.sha256(CA).hexdigest(),
                                        BACKUP, "owner-a", 3, BACKUP_HASH, source_root=root / "source")
                    remote.assert_not_called()
                    self.assertFalse((root / ".rag_index/android-endpoint-admission" /
                                      (CORRELATION + ".json")).exists())
                    self.assertFalse((root / ".rag_index/android-native-device-leases/lease-archlinux-api35.json").exists())

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

    def test_partial_status_reports_bounded_reverse_grammar_and_documented_host_route(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700)
            expected = {"host": "archlinux", "adb": "/bin/adb", "cli": "/bin/cli", "serial": "emulator-5554",
                        "api": 35, "avd": "vpn-control-api35", "caSha256": "a" * 64}
            job = root / ("android-endpoint-" + CORRELATION); job.mkdir(mode=0o700)
            intent = job / "intent.json"; intent.write_text(json.dumps(expected)); intent.chmod(0o600)
            mount = job / "mount-intent.json"; mount.write_text(json.dumps({"target": "/apex/com.android.conscrypt/cacerts"})); mount.chmod(0o600)
            lease = root / "android-native-device-api35.lease"
            lease.write_text(json.dumps({"owner": "android-endpoint", "correlationId": CORRELATION,
                                         "device": "api35", "host": "archlinux"})); lease.chmod(0o600)
            completed = SimpleNamespace(returncode=0, stdout=b"host tcp:18080 tcp:41001\n", stderr=b"")
            output = io.StringIO()
            with mock.patch("subprocess.run", return_value=completed), \
                    mock.patch("sys.argv", ["remote", "status", str(root), "api35", CORRELATION, json.dumps(expected)]), \
                    contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit):
                    exec(admission._REMOTE, {"__name__": "remote_test", "public_cli_environment": lambda *_: {}})
            result = json.loads(output.getvalue())
            self.assertEqual("partial", result["state"])
            self.assertEqual("mount-intent", result["phase"])
            self.assertEqual({"state": "observed", "recordCount": 1,
                              "records": [{"form": "three-host", "ports": [18080, 41001], "portsValid": True}]},
                             result["reverseInventory"])
            namespace = {"__name__": "remote_test", "public_cli_environment": lambda *_: {}}
            with mock.patch("sys.argv", ["remote", "status", str(root), "api35", CORRELATION, json.dumps(expected)]), \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    exec(admission._REMOTE, namespace)
            namespace["adb_call"] = lambda *_args, **_kwargs: "host tcp:18080 tcp:41001\n"
            self.assertEqual({18080: 41001}, namespace["routes"]())

    def test_reverse_inventory_accepts_bounded_adb_host_transport_not_literal_generation(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700)
            expected = {"host": "archlinux", "adb": "/bin/adb", "cli": "/bin/cli", "serial": "emulator-5554",
                        "api": 35, "avd": "vpn-control-api35"}
            namespace = {"__name__": "remote_test", "public_cli_environment": lambda *_: {}}
            with mock.patch("sys.argv", ["remote", "status", str(root), "api35", CORRELATION, json.dumps(expected)]), \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    exec(admission._REMOTE, namespace)
            namespace["adb_call"] = lambda *_args, **_kwargs: "host-15 tcp:18080 tcp:60881\n"
            self.assertEqual({18080: 60881}, namespace["routes"]())
            for prefix in ("host-0", "host-01", "host-2147483648", "host--1", "host-foreign"):
                with self.subTest(prefix=prefix):
                    namespace["adb_call"] = lambda *_args, prefix=prefix, **_kwargs: prefix + " tcp:18080 tcp:60881\n"
                    with contextlib.redirect_stdout(io.StringIO()):
                        with self.assertRaises(SystemExit):
                            namespace["routes"]()

    def test_reverse_inventory_three_other_prefix_stays_finite_without_disclosure(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700)
            expected = {"host": "archlinux", "adb": "/bin/adb", "cli": "/bin/cli", "serial": "emulator-5554",
                        "api": 35, "avd": "vpn-control-api35"}
            namespace = {"__name__": "remote_test", "public_cli_environment": lambda *_: {}}
            with mock.patch("sys.argv", ["remote", "status", str(root), "api35", CORRELATION, json.dumps(expected)]), \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    exec(admission._REMOTE, namespace)
            completed = SimpleNamespace(returncode=0, stdout=b"TransportLabel tcp:18080 tcp:60881\n", stderr=b"")
            with mock.patch("subprocess.run", return_value=completed):
                observed = namespace["reverse_inventory_diagnostic"]()
            self.assertEqual({"state": "observed", "recordCount": 1, "records": [{
                "form": "three-other", "ports": [18080, 60881], "portsValid": True}]}, observed)

    def test_reverse_inventory_retains_reviewed_usbffs_form(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700)
            expected = {"host": "archlinux", "adb": "/bin/adb", "cli": "/bin/cli", "serial": "emulator-5554",
                        "api": 35, "avd": "vpn-control-api35"}
            namespace = {"__name__": "remote_test", "public_cli_environment": lambda *_: {}}
            with mock.patch("sys.argv", ["remote", "status", str(root), "api35", CORRELATION, json.dumps(expected)]), \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    exec(admission._REMOTE, namespace)
            namespace["adb_call"] = lambda *_args, **_kwargs: "UsbFfs tcp:18080 tcp:60881\n"
            self.assertEqual({18080: 60881}, namespace["routes"]())

    def test_partial_binding_retains_only_exact_finite_reverse_diagnostic(self):
        intent = {"correlationId": CORRELATION, "remote": {}}
        value = {"state": "partial", "reason": "setup_incomplete", "phase": "mount-intent",
                 "reverseInventory": {"state": "observed", "recordCount": 1,
                                      "records": [{"form": "three-adb-host-transport", "ports": [18080, 41001], "portsValid": True}]}}
        result = admission._bound_result(intent, value, "status")
        self.assertEqual(value["reverseInventory"], result["reverseInventory"])
        malformed = {**value, "reverseInventory": {"state": "observed", "recordCount": 1,
                                                       "records": [{"form": "three-other", "ports": [18080], "portsValid": True}]}}
        self.assertNotIn("reverseInventory", admission._bound_result(intent, malformed, "status"))
        disclosed = {**value, "reverseInventory": {**value["reverseInventory"], "records": [{
            **value["reverseInventory"]["records"][0], "prefix": "host-15"}]}}
        self.assertNotIn("reverseInventory", admission._bound_result(intent, disclosed, "status"))

    def test_checkpoint_precedes_failed_command_without_following_effect(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700)
            expected = {"host": "archlinux", "adb": "/bin/adb", "cli": "/bin/cli", "serial": "emulator-5554",
                        "api": 35, "avd": "vpn-control-api35"}
            namespace = {"__name__": "remote_test", "public_cli_environment": lambda *_: {}}
            with mock.patch("sys.argv", ["remote", "status", str(root), "api35", CORRELATION, json.dumps(expected)]), \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    exec(admission._REMOTE, namespace)
            namespace["job"].mkdir(mode=0o700)
            namespace["checkpoint"]("mount")
            # A start-side root checkpoint must not consume cleanup's distinct root gate.
            namespace["checkpoint"]("root")
            namespace["checkpoint"]("cleanup-root")
            failed = SimpleNamespace(returncode=1, stdout=b"", stderr=b"ignored")
            with mock.patch("subprocess.run", return_value=failed) as runner, contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    namespace["command"](["effect"])
            self.assertEqual({"phase": "mount"}, json.loads((namespace["job"] / "checkpoint-mount.json").read_text()))
            self.assertEqual({"phase": "cleanup-root"}, json.loads((namespace["job"] / "checkpoint-cleanup-root.json").read_text()))
            runner.assert_called_once()

    def test_partial_binding_retains_only_exact_command_failure_diagnostic(self):
        intent = {"correlationId": CORRELATION, "remote": {}}
        diagnostic = {"uid": "root", "stage": "before-root", "mountPlan": "recorded",
                      "zygoteGeneration": "recorded", "stagingIdentity": "recorded",
                      "mount": "unobserved", "ca": "present", "commandPhase": "mount"}
        value = {"state": "partial", "reason": "setup_incomplete", "phase": "mount-intent",
                 "partialDiagnostic": diagnostic}
        self.assertEqual(diagnostic, admission._bound_result(intent, value, "status")["partialDiagnostic"])
        forged = {**value, "partialDiagnostic": {**diagnostic, "extra": "disclosed"}}
        self.assertNotIn("partialDiagnostic", admission._bound_result(intent, forged, "status"))

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
            namespace["guard"] = mock.Mock()
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
            namespace["guard"] = mock.Mock()
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

    def _cleanup_intent(self, root: Path) -> dict[str, object]:
        intent = {"host": "archlinux", "device": "api35", "correlationId": CORRELATION,
                  "remoteRoot": "/private/fixture", "remote": {"api": 35, "avd": "vpn-control-api35",
                  "packageSha256": PACKAGE, "owner": "owner-a", "revision": 3, "caSha256": "a" * 64,
                  "campaignId": CAMPAIGN, "adb": "/bin/adb", "cli": "/bin/cli", "serial": "emulator-5554"}}
        admission.android_native_fixture.write_private_plan(admission._local_directory(root) / (CORRELATION + ".json"), intent)
        leases = root / ".rag_index/android-native-device-leases"; leases.mkdir(mode=0o700)
        admission.android_native_fixture.write_private_plan(leases / "lease-archlinux-api35.json", {
            "owner": "android-endpoint", "host": "archlinux", "device": "api35", "correlationId": CORRELATION})
        return intent

    def _runtime_parent(self, root: Path, runtime: str) -> None:
        directory = root / ".rag_index/android-runtime-acceptance"; directory.mkdir(mode=0o700, parents=True)
        admission.android_native_fixture.write_private_plan(directory / ("parent-" + CORRELATION + ".lease"), {
            "parentCorrelationId": CORRELATION, "runtimeCorrelationId": runtime})

    def test_cleanup_blocks_running_or_unknown_runtime_child_before_dispatch(self):
        runtime = "8a22d397-cada-4ead-8731-02bc243cd0b1"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); self._cleanup_intent(root); self._runtime_parent(root, runtime)
            for state, reason in (("running", "blocked_child_running"), ("unknown", "blocked_child_unknown")):
                with self.subTest(state=state), mock.patch.object(admission, "_runtime_child_status", return_value=(state, None)), \
                        mock.patch.object(admission, "_remote") as remote:
                    result = admission.cleanup(root, CORRELATION)
                self.assertEqual(reason, result["reason"])
                remote.assert_not_called()

    def test_terminal_child_cleanup_uses_ephemeral_closing_revision_without_rewriting_parent_intent(self):
        runtime = "8a22d397-cada-4ead-8731-02bc243cd0b1"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); intent = self._cleanup_intent(root); self._runtime_parent(root, runtime)
            cleaned = {"state": "cleaned", "correlationId": CORRELATION,
                       "device": {"uid": "2000", "api": 35, "avd": "vpn-control-api35"},
                       "packageSha256": PACKAGE, "owner": "owner-a", "revision": 4,
                       "caSha256": "a" * 64, "reversePorts": []}
            with mock.patch.object(admission, "_runtime_child_status", return_value=("terminal", 4)), \
                    mock.patch.object(admission, "_remote", return_value=cleaned) as dispatch:
                result = admission.cleanup(root, CORRELATION)
            self.assertEqual("cleaned", result["state"])
            sent = dispatch.call_args.args[1]
            self.assertEqual(4, sent["remote"]["revision"])
            self.assertEqual(3, sent["remote"]["cleanupOriginalRevision"])
            self.assertEqual(3, admission._read_intent(root, CORRELATION)["remote"]["revision"])
            self.assertFalse((root / ".rag_index/android-native-device-leases/lease-archlinux-api35.json").exists())
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); self._cleanup_intent(root); self._runtime_parent(root, runtime)
            with mock.patch.object(admission, "_runtime_child_status", return_value=("terminal", 3)), \
                    mock.patch.object(admission, "_remote") as dispatch:
                result = admission.cleanup(root, CORRELATION)
            self.assertEqual("blocked_child_unknown", result["reason"])
            dispatch.assert_not_called()

    def test_cleanup_worker_accepts_closing_revision_but_keeps_original_journal_binding(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700)
            expected = {"host": "archlinux", "adb": "/bin/adb", "cli": "/tmp/fixture-cli.py", "serial": "emulator-5554",
                        "api": 35, "avd": "vpn-control-api35", "packageSha256": PACKAGE, "owner": "owner-a",
                        "revision": 3, "backupPath": str(root / "routing.json"), "backupSha256": "a" * 64,
                        "campaignId": CAMPAIGN, "leafSha256": LEAF, "caSha256": "b" * 64,
                        "caStoreName": "0123abcd.0", "httpsHostPort": 41001, "socksHostPort": 41002}
            backup = root / "routing.json"; backup.write_bytes(b"routing"); expected["backupSha256"] = hashlib.sha256(b"routing").hexdigest(); backup.chmod(0o600)
            job = root / ("android-endpoint-" + CORRELATION); job.mkdir(mode=0o700)
            for name, value in (("intent.json", expected), ("cleaned.json", {"correlationId": CORRELATION, "caSha256": expected["caSha256"]})):
                path = job / name; path.write_text(json.dumps(value)); path.chmod(0o600)
            lease = root / "android-native-device-api35.lease"
            lease.write_text(json.dumps({"owner": "android-endpoint", "correlationId": CORRELATION, "device": "api35", "host": "archlinux"})); lease.chmod(0o600)
            submitted = {**expected, "revision": 4, "cleanupOriginalRevision": 3}
            def command(argv, **_kwargs):
                if argv[:4] == ["/bin/adb", "-s", "emulator-5554", "shell"]:
                    words = argv[5:]
                    if words == ["id", "-u"]: raw = b"2000\n"
                    elif words == ["getprop", "ro.build.version.sdk"]: raw = b"35\n"
                    elif words[0] == "getprop" and words[1] in {"ro.kernel.qemu.avd_name", "ro.boot.qemu.avd_name"}: raw = b"vpn-control-api35\n"
                    elif words == ["getprop", "ro.product.cpu.abi"]: raw = b"x86_64\n"
                    elif words == ["pm", "path", "com.kardinal.vpncontrol"]: raw = b"package:/data/app/test/base.apk\n"
                    elif words[0] == "sha256sum": raw = (PACKAGE + " /data/app/test/base.apk\n").encode()
                    else: raise AssertionError(words)
                elif argv[:4] == ["/bin/adb", "-s", "emulator-5554", "reverse"]: raw = b""
                elif argv[0] == "/tmp/fixture-cli.py":
                    action = argv[-2:]
                    data = {"runtimeRunning": False, "runtimeObservation": "stopped"} if action[-1:] == ["status"] else {"operations": []}
                    raw = json.dumps({"ok": True, "final": True, "code": "OK", "controllerId": "owner-a", "configurationRevision": 4, "data": data}).encode()
                else: raise AssertionError(argv)
                return SimpleNamespace(returncode=0, stdout=raw, stderr=b"")
            output = io.StringIO()
            with mock.patch("sys.argv", ["remote", "cleanup", str(root), "api35", CORRELATION, json.dumps(submitted)]), \
                    mock.patch("subprocess.run", side_effect=command), contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit):
                    exec(admission._REMOTE, {"__name__": "remote_test", "public_cli_environment": lambda *_: {}})
            receipt = json.loads(output.getvalue())
            self.assertEqual("cleaned", receipt["state"], receipt)
            self.assertEqual(4, receipt["revision"])
            self.assertFalse(lease.exists())
            self.assertEqual(expected, json.loads((job / "intent.json").read_text()))

    def test_runtime_terminal_drift_is_unknown_before_parent_cleanup(self):
        runtime = "8a22d397-cada-4ead-8731-02bc243cd0b1"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700); self._runtime_parent(root, runtime)
            parent_lease_sha = hashlib.sha256((root / ".rag_index/android-runtime-acceptance" /
                                                ("parent-" + CORRELATION + ".lease")).read_bytes()).hexdigest()
            activity = {"schema": 1, "kind": "android-runtime-acceptance", "state": "running",
                        "parentCorrelationId": CORRELATION, "runtimeCorrelationId": runtime, "campaignId": CAMPAIGN,
                        "sourcePackageSha256": PACKAGE, "expectedOwner": "owner-a", "parentLeaseSha256": parent_lease_sha,
                        "endpoint": {"state": "ready", "correlationId": CORRELATION,
                                     "sourcePackageSha256": PACKAGE, "owner": "owner-a"},
                        "fixture": {"campaignId": CAMPAIGN, "deviceUid": "2000", "api": 35, "avd": "vpn-control-api35"}}
            terminal = {"schema": 1, "kind": "android-runtime-acceptance", "state": "stopped",
                        "parentCorrelationId": CORRELATION, "runtimeCorrelationId": runtime, "campaignId": CAMPAIGN,
                        "sourcePackageSha256": PACKAGE, "expectedOwner": "owner-a", "parentLeaseSha256": parent_lease_sha, "closingOwner": "other",
                        "closingRevision": 4, "admittedMode": "vpn-authorized",
                        "restoration": {"settings": True, "source": True, "routing": True, "locationsEmpty": True,
                                        "selectedNull": True, "activeNull": True, "runtimeOff": True}, "terminal": True}
            for suffix, value in ((".json", activity), (".terminal.json", terminal)):
                path = root / ("android-runtime-acceptance-" + runtime + suffix)
                path.write_text(json.dumps(value)); path.chmod(0o600)
            expected = {"parentCorrelationId": CORRELATION, "campaignId": CAMPAIGN, "sourcePackageSha256": PACKAGE,
                        "expectedOwner": "owner-a", "openingRevision": 3, "parentLeaseSha256": parent_lease_sha,
                        "api": 35, "avd": "vpn-control-api35",
                        "adb": "/bin/adb", "cli": "/bin/cli", "serial": "emulator-5554"}
            output = io.StringIO()
            with mock.patch("sys.argv", ["child", str(root), runtime, json.dumps(expected)]), contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit):
                    exec(admission._RUNTIME_CHILD_STATUS, {"__name__": "child_test", "public_cli_environment": lambda *_: {}})
            observed = json.loads(output.getvalue())
            self.assertEqual("unknown", observed["state"])
            self.assertEqual("child_terminal_invalid", observed["reason"])

    def test_runtime_terminal_requires_fresh_stopped_owner_and_revision(self):
        runtime = "8a22d397-cada-4ead-8731-02bc243cd0b1"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700); self._runtime_parent(root, runtime)
            lease_sha = hashlib.sha256((root / ".rag_index/android-runtime-acceptance" /
                                        ("parent-" + CORRELATION + ".lease")).read_bytes()).hexdigest()
            activity = {"schema": 1, "kind": "android-runtime-acceptance", "state": "running",
                        "parentCorrelationId": CORRELATION, "runtimeCorrelationId": runtime, "campaignId": CAMPAIGN,
                        "sourcePackageSha256": PACKAGE, "expectedOwner": "owner-a", "parentLeaseSha256": lease_sha,
                        "endpoint": {"state": "ready", "correlationId": CORRELATION,
                                     "sourcePackageSha256": PACKAGE, "owner": "owner-a"},
                        "fixture": {"campaignId": CAMPAIGN, "deviceUid": "2000", "api": 35, "avd": "vpn-control-api35"}}
            restore = {"settings": True, "source": True, "routing": True, "locationsEmpty": True,
                       "selectedNull": True, "activeNull": True, "runtimeOff": True}
            terminal = {"schema": 1, "kind": "android-runtime-acceptance", "state": "stopped",
                        "parentCorrelationId": CORRELATION, "runtimeCorrelationId": runtime, "campaignId": CAMPAIGN,
                        "sourcePackageSha256": PACKAGE, "expectedOwner": "owner-a", "parentLeaseSha256": lease_sha, "closingOwner": "owner-a",
                        "closingRevision": 4, "admittedMode": "vpn-authorized", "restoration": restore, "terminal": True}
            for suffix, value in ((".json", activity), (".terminal.json", terminal)):
                path = root / ("android-runtime-acceptance-" + runtime + suffix)
                path.write_text(json.dumps(value)); path.chmod(0o600)
            expected = {"parentCorrelationId": CORRELATION, "campaignId": CAMPAIGN, "sourcePackageSha256": PACKAGE,
                        "expectedOwner": "owner-a", "openingRevision": 3, "parentLeaseSha256": lease_sha,
                        "api": 35, "avd": "vpn-control-api35", "adb": "/bin/adb", "cli": "/tmp/fixture-cli.py", "serial": "emulator-5554"}
            fresh = {"ok": True, "final": True, "code": "OK", "controllerId": "owner-a", "configurationRevision": 4,
                     "data": {"runtimeRunning": False, "runtimeObservation": "stopped", "selectedLocationId": None,
                              "activeLocationId": None}}
            for changed in ({"configurationRevision": 3}, {"controllerId": "other"},
                            {"data": {**fresh["data"], "runtimeRunning": True}}):
                with self.subTest(changed=changed), mock.patch("sys.argv", ["child", str(root), runtime, json.dumps(expected)]), \
                        mock.patch("subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=json.dumps({**fresh, **changed}).encode())) as invoke, \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    with self.assertRaises(SystemExit):
                        exec(admission._RUNTIME_CHILD_STATUS, {"__name__": "child_test", "public_cli_environment": lambda *_: {}})
                observed = json.loads(output.getvalue())
                self.assertEqual("unknown", observed["state"])
                self.assertEqual("child_fresh_restoration_invalid", observed["reason"])
                invoke.assert_called_once()
            with mock.patch("sys.argv", ["child", str(root), runtime, json.dumps(expected)]), \
                    mock.patch("subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=json.dumps(fresh).encode())), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                with self.assertRaises(SystemExit):
                    exec(admission._RUNTIME_CHILD_STATUS, {"__name__": "child_test", "public_cli_environment": lambda *_: {}})
            self.assertEqual("terminal", json.loads(output.getvalue())["state"])

    def test_cleanup_shared_lock_observes_child_published_before_dispatch(self):
        runtime = "8a22d397-cada-4ead-8731-02bc243cd0b1"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); self._cleanup_intent(root)
            entered = threading.Event(); release = threading.Event(); result_box: list[dict[str, object]] = []
            def publisher():
                with admission._shared_device_lease(root, "archlinux", "api35"):
                    self._runtime_parent(root, runtime)
                    entered.set(); release.wait(2)
            worker = threading.Thread(target=publisher); worker.start(); self.assertTrue(entered.wait(1))
            def invoke_cleanup():
                result_box.append(admission.cleanup(root, CORRELATION))
            with mock.patch.object(admission, "_runtime_child_status", return_value=("running", None)), \
                    mock.patch.object(admission, "_remote") as remote:
                cleaner = threading.Thread(target=invoke_cleanup); cleaner.start()
                time.sleep(0.05); self.assertTrue(cleaner.is_alive())
                release.set(); worker.join(1); cleaner.join(1)
                remote.assert_not_called()
            self.assertEqual("blocked_child_running", result_box[0]["reason"])

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

    def test_adb_flattening_requires_outer_quoted_readonly_membership_script(self):
        inner = "exec 3</apex/com.android.conscrypt/cacerts; cat /proc/$$/fdinfo/3; printf '%s\\n' __VPN_CONTROL_MOUNTINFO__; /system/bin/cut -d ' ' -f1 /proc/$$/mountinfo"
        outer = "nsenter -t 177 -m -- /system/bin/sh -c " + shlex.quote(inner)

        def parsed(arguments):
            # This is the same flattening boundary as `adb shell`: execute only
            # shell `set --` and `printf`, never the prospective diagnostic.
            source = "set -- " + " ".join(arguments) + "; printf '<%s>\n' \"$@\""
            return subprocess.run(["/bin/sh", "-c", source], check=True, capture_output=True,
                                  text=True).stdout.splitlines()

        old = parsed(["sh", "-c", outer])
        self.assertEqual(["<sh>", "<-c>", "<nsenter>"], old[:3])  # RED: old outer argument is split.
        current = parsed(["sh", "-c", shlex.quote(outer)])
        self.assertEqual(["<sh>", "<-c>", "<" + outer + ">"], current)

    def test_shell_parent_fdinfo_survives_when_child_self_fd3_is_closed(self):
        if not Path("/proc/self/fdinfo").is_dir():
            self.skipTest("requires procfs descriptor view")
        # `/proc/self` resolves in the child used to read it.  This exercises a
        # closing child and proves the parent shell's `/proc/$$` remains the
        # only stable owner of FD3 for the diagnostic script.
        source = "exec 3</; /bin/sh -c 'exec 3>&-; test ! -e /proc/self/fdinfo/3'; test -e /proc/$$/fdinfo/3"
        subprocess.run(["/bin/sh", "-c", source], check=True, capture_output=True)

    def test_readonly_mount_diagnostic_classifies_nsenter_missing_target_without_effect(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700)
            expected = {"host": "archlinux", "adb": "/bin/adb", "cli": "/bin/cli", "serial": "emulator-5554",
                        "api": 35, "avd": "vpn-control-api35", "caSha256": "a" * 64}
            namespace = {"__name__": "remote_test", "public_cli_environment": lambda *_: {}}
            with mock.patch("sys.argv", ["remote", "status", str(root), "api35", CORRELATION, json.dumps(expected)]), \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    exec(admission._REMOTE, namespace)
            job = namespace["job"]; job.mkdir(mode=0o700)
            staging = "/data/local/tmp/vpn-control-endpoint-" + CORRELATION
            generation = {"pid": "177", "startTicks": 123456, "namespace": "mnt:[4026532888]"}
            records = {"stage.json": {"phase": "before_root", "target": "/apex/com.android.conscrypt/cacerts", "staging": staging},
                       "mount-intent.json": {"zygote": generation, "target": "/apex/com.android.conscrypt/cacerts", "staging": staging, "stagingIdentity": "0:755:1:2"},
                       "stage-owned.json": {"staging": staging, "stagingIdentity": "0:755:1:2"}}
            for name, value in records.items():
                path = job / name; path.write_text(json.dumps(value)); path.chmod(0o600)
            ca = job / "ca.pem"; ca.write_bytes(b"ca"); ca.chmod(0o600)
            stat = b"177 (zygote64) S " + b"0 " * 18 + b"123456 0\n"
            membership_output = b"mnt_id:\t42\n__VPN_CONTROL_MOUNTINFO__\n42\n"
            membership_exception = False
            def run(argv, **_kwargs):
                words = argv[5:]
                if words == ["id", "-u"]: return SimpleNamespace(returncode=0, stdout=b"0\n", stderr=b"")
                if words == ["cat", "/proc/177/mountinfo"]: return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
                if words == ["cat", "/proc/177/stat"]: return SimpleNamespace(returncode=0, stdout=stat, stderr=b"")
                if words == ["readlink", "/proc/177/ns/mnt"]: return SimpleNamespace(returncode=0, stdout=b"mnt:[4026532888]\n", stderr=b"")
                if words == ["nsenter", "-t", "177", "-m", "--", "mount", "--help"]: return SimpleNamespace(returncode=1, stdout=b"", stderr=b"nsenter: mount: No such file or directory")
                if words[:2] == ["sh", "-c"]:
                    if membership_exception:
                        raise OSError("diagnostic unavailable")
                    observed_path = staging if staging in words[2] else "/apex/com.android.conscrypt/cacerts"
                    inner = "exec 3<" + observed_path + "; cat /proc/$$/fdinfo/3; printf '%s\\n' __VPN_CONTROL_MOUNTINFO__; /system/bin/cut -d ' ' -f1 /proc/$$/mountinfo"
                    outer = "nsenter -t 177 -m -- /system/bin/sh -c " + shlex.quote(inner)
                    self.assertEqual(words[2], shlex.quote(outer))
                    if membership_output is None:
                        return SimpleNamespace(returncode=1, stdout=b"", stderr=b"transport failed")
                    return SimpleNamespace(returncode=0, stdout=membership_output, stderr=b"")
                if words == ["/system/bin/mount", "--help"] or words == ["nsenter", "-t", "177", "-m", "--", "/system/bin/mount", "--help"]: return SimpleNamespace(returncode=0, stdout=b"--bind\n", stderr=b"")
                if words == ["/system/bin/cat", "/proc/self/status"] or words == ["nsenter", "-t", "177", "-m", "--", "/system/bin/cat", "/proc/self/status"]: return SimpleNamespace(returncode=0, stdout=b"CapEff: 00200000\n", stderr=b"")
                if words == ["/system/bin/getenforce"]: return SimpleNamespace(returncode=0, stdout=b"Enforcing\n", stderr=b"")
                if words == ["/system/bin/cat", "/proc/self/attr/current"]: return SimpleNamespace(returncode=0, stdout=b"u:r:su:s0\n", stderr=b"")
                if words == ["sh", "-c", "command -v nsenter >/dev/null && echo available || echo missing"]: return SimpleNamespace(returncode=0, stdout=b"available\n", stderr=b"")
                if words == ["nsenter", "-t", "177", "-m", "--", "id", "-u"]: return SimpleNamespace(returncode=0, stdout=b"0\n", stderr=b"")
                if words == ["nsenter", "-t", "177", "-m", "--", "/system/bin/id", "-u"]: return SimpleNamespace(returncode=0, stdout=b"0\n", stderr=b"")
                if words == ["nsenter", "-t", "177", "-m", "--", "/system/bin/stat", "-c", "%F:%u:%a", "/apex/com.android.conscrypt/cacerts"]: return SimpleNamespace(returncode=1, stdout=b"", stderr=b"stat: No such file or directory")
                if words == ["nsenter", "-t", "177", "-m", "--", "/system/bin/stat", "-c", "%u:%a:%d:%i", staging]: return SimpleNamespace(returncode=0, stdout=b"0:755:1:2\n", stderr=b"")
                raise AssertionError(words)
            with mock.patch("subprocess.run", side_effect=run) as invoke:
                diagnostic = namespace["partial_diagnostic"]()["mountDiagnostic"]
            self.assertFalse(any("-f" in call.args[0] or "--bind" in call.args[0] and "/system/bin/mount" in call.args[0]
                                 for call in invoke.call_args_list))
            self.assertEqual({"state": "failed", "generation": "stable", "namespaceUid": "root",
                              "target": "unknown", "staging": "unknown", "exit": "nonzero", "errorClass": "not-found",
                              "nsenterBinary": "available", "nsenterId": "ok", "absoluteId": "ok",
                              "failurePhase": "target-stat", "outsideBind": "supported", "insideBind": "supported", "relativeMount": "missing", "targetMountMembership": "member", "targetMountMembershipReason": "ok", "targetMountMembershipBytes": len(membership_output), "targetMountMembershipEntries": 1, "targetMountFdinfoFormat": "valid", "targetMountFdinfoKeyCount": 1, "targetMountFdinfoMntIdCount": 1, "stagingMountMembership": "member", "outsideCapSysAdmin": "present", "insideCapSysAdmin": "present", "selinux": "enforcing", "domain": "su"}, diagnostic)
            with mock.patch("subprocess.run", side_effect=run):
                for membership_output, membership_exception, expected_membership, expected_reason, expected_format in (
                        (b"mnt_id:\t42\n__VPN_CONTROL_MOUNTINFO__\n99\n", False, "foreign", "ok", "valid"),
                        (b"bad fdinfo\n__VPN_CONTROL_MOUNTINFO__\n", False, "unknown", "malformed-fdinfo", "missing"),
                        (b"mnt_id:\t42\n", False, "unknown", "delimiter", "unknown"),
                        (b"mnt_id:\t42\n__VPN_CONTROL_MOUNTINFO__\nnot-an-id\n", False, "unknown", "malformed-mount-ids", "valid"),
                        (b"mnt_id:\t42\n__VPN_CONTROL_MOUNTINFO__\n" + b"1\n" * 257, False, "unknown", "capped-mount-ids", "valid"),
                        (b"\xff", False, "unknown", "encoding", "unknown"),
                        (b"x" * 4097, False, "unknown", "output-size", "unknown"),
                        (None, False, "unknown", "command-nonzero", "unknown"),
                        (b"", True, "unknown", "command-unavailable", "unknown")):
                    with self.subTest(expected_membership=expected_membership, expected_reason=expected_reason):
                        observed = namespace["partial_diagnostic"]()["mountDiagnostic"]
                        self.assertEqual(expected_membership, observed["targetMountMembership"])
                        self.assertEqual(expected_reason, observed["targetMountMembershipReason"])
                        self.assertEqual(expected_format, observed["targetMountFdinfoFormat"])

    def test_status_recovers_persisted_mount_failure_after_lost_start_response(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve(); root.chmod(0o700)
            expected={"host":"archlinux","adb":"/bin/adb","cli":"/bin/cli","serial":"emulator-5554","api":35,"avd":"vpn-control-api35","caSha256":"a"*64}
            job=root/("android-endpoint-"+CORRELATION); job.mkdir(mode=0o700)
            for name,value in (("intent.json",expected),("stage.json",{"phase":"before_root","target":"/apex/com.android.conscrypt/cacerts","staging":"/data/local/tmp/vpn-control-endpoint-"+CORRELATION}),("mount-failure.json",{"phase":"mount","exit":"nonzero","errorClass":"permission"})):
                f=job/name; f.write_text(json.dumps(value)); f.chmod(0o600)
            lease=root/"android-native-device-api35.lease"; lease.write_text(json.dumps({"owner":"android-endpoint","correlationId":CORRELATION,"device":"api35","host":"archlinux"})); lease.chmod(0o600)
            out=io.StringIO(); done=SimpleNamespace(returncode=0,stdout=b"2000\n",stderr=b"")
            with mock.patch("sys.argv",["remote","status",str(root),"api35",CORRELATION,json.dumps(expected)]), mock.patch("subprocess.run",return_value=done), contextlib.redirect_stdout(out):
                with self.assertRaises(SystemExit): exec(admission._REMOTE,{"__name__":"remote_test","public_cli_environment":lambda *_:{}})
            value=json.loads(out.getvalue()); self.assertEqual("partial",value["state"]); self.assertEqual({"phase":"mount","exit":"nonzero","errorClass":"permission"},value["partialDiagnostic"]["mountFailure"])

    def test_status_recovers_future_exact_mount_origin_receipt(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve(); root.chmod(0o700)
            expected={"host":"archlinux","adb":"/bin/adb","cli":"/bin/cli","serial":"emulator-5554","api":35,"avd":"vpn-control-api35","caSha256":"a"*64}
            job=root/("android-endpoint-"+CORRELATION); job.mkdir(mode=0o700)
            future={"phase":"mount","exit":"nonzero","errorClass":"other","errorOrigin":"fstab"}
            for name,value in (("intent.json",expected),("stage.json",{"phase":"before_root","target":"/apex/com.android.conscrypt/cacerts","staging":"/data/local/tmp/vpn-control-endpoint-"+CORRELATION}),("mount-failure.json",future)):
                item=job/name; item.write_text(json.dumps(value)); item.chmod(0o600)
            lease=root/"android-native-device-api35.lease"; lease.write_text(json.dumps({"owner":"android-endpoint","correlationId":CORRELATION,"device":"api35","host":"archlinux"})); lease.chmod(0o600)
            out=io.StringIO(); done=SimpleNamespace(returncode=0,stdout=b"2000\n",stderr=b"")
            with mock.patch("sys.argv",["remote","status",str(root),"api35",CORRELATION,json.dumps(expected)]), mock.patch("subprocess.run",return_value=done), contextlib.redirect_stdout(out):
                with self.assertRaises(SystemExit): exec(admission._REMOTE,{"__name__":"remote_test","public_cli_environment":lambda *_:{}})
            self.assertEqual(future,json.loads(out.getvalue())["partialDiagnostic"]["mountFailure"])

    def test_status_rejects_hardlinked_mount_failure_receipt(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700)
            expected = {"host": "archlinux", "adb": "/bin/adb", "cli": "/bin/cli",
                        "serial": "emulator-5554", "api": 35, "avd": "vpn-control-api35", "caSha256": "a" * 64}
            job = root / ("android-endpoint-" + CORRELATION); job.mkdir(mode=0o700)
            for name, value in (("intent.json", expected), ("stage.json", {"phase": "before_root",
                    "target": "/apex/com.android.conscrypt/cacerts", "staging": "/data/local/tmp/vpn-control-endpoint-" + CORRELATION}),
                    ("mount-failure.json", {"phase": "mount", "exit": "nonzero", "errorClass": "permission"})):
                path = job / name; path.write_text(json.dumps(value)); path.chmod(0o600)
            os.link(job / "mount-failure.json", root / "foreign-hardlink")
            lease = root / "android-native-device-api35.lease"
            lease.write_text(json.dumps({"owner": "android-endpoint", "correlationId": CORRELATION,
                "device": "api35", "host": "archlinux"})); lease.chmod(0o600)
            out = io.StringIO(); done = SimpleNamespace(returncode=0, stdout=b"2000\n", stderr=b"")
            with mock.patch("sys.argv", ["remote", "status", str(root), "api35", CORRELATION, json.dumps(expected)]), \
                    mock.patch("subprocess.run", return_value=done), contextlib.redirect_stdout(out):
                with self.assertRaises(SystemExit):
                    exec(admission._REMOTE, {"__name__": "remote_test", "public_cli_environment": lambda *_: {}})
            value = json.loads(out.getvalue())
            self.assertIsNone(value["partialDiagnostic"]["mountFailure"])

    def test_unknown_mount_failure_projects_only_exact_finite_receipt(self):
        intent={"correlationId":CORRELATION,"remote":{}}
        value={"state":"unknown","reason":"mount_command_failed","phase":"mount","mountFailure":{"phase":"mount","exit":"nonzero","errorClass":"permission","errorOrigin":"other"}}
        self.assertEqual(value["mountFailure"],admission._bound_result(intent,value,"start")["mountFailure"])
        for forged in ({"phase":"mount","exit":["nonzero"],"errorClass":"permission"},{"phase":"mount","exit":"nonzero","errorClass":{"x":"permission"}}):
            self.assertNotIn("mountFailure",admission._bound_result(intent,{**value,"mountFailure":forged},"start"))
        future = {**value, "mountFailure": {**value["mountFailure"], "errorOrigin":"fstab"}}
        self.assertEqual(future["mountFailure"], admission._bound_result(intent, future, "start")["mountFailure"])
        forged_origin = {**future, "mountFailure": {**future["mountFailure"], "errorOrigin":"raw stderr"}}
        self.assertNotIn("mountFailure", admission._bound_result(intent, forged_origin, "start"))

    def test_mount_observed_accepts_actual_filesystem_relative_stage_root(self):
        import ast
        names={'mount_observed','mount_layout'}
        source=ast.Module(body=[node for node in ast.parse(admission._REMOTE).body if isinstance(node,ast.FunctionDef) and node.name in names],type_ignores=[])
        stage='/data/local/tmp/vpn-control-endpoint-'+CORRELATION
        plan={'zygote':{'pid':'177','startTicks':123456,'namespace':'mnt:[4026532888]'},'target':'/system/etc/security/cacerts','staging':stage,'stagingIdentity':'0:755:64800:65543'}
        raw='94 1 253:0 / / ro - ext4 /dev/system ro\n131 94 253:32 / /data rw - ext4 /dev/data rw\n197 94 253:32 '+stage.removeprefix('/data')+' '+plan['target']+' rw - ext4 /dev/data rw\n'
        def unknown(value):raise AssertionError(value)
        namespace={'staging_identity':lambda _:plan['stagingIdentity'],'mount_observation_generation':lambda *_:plan['zygote'],'mount_observation_reader':lambda _:lambda *_:raw,'shell':lambda *_:raw,'unknown':unknown,'os':os,'re':__import__('re'),'pathlib':__import__('pathlib')}
        exec(compile(source,'<mount-layout>','exec'),namespace)
        self.assertTrue(namespace['mount_observed'](plan))

    def test_mount_layout_uses_longest_exact_source_ancestor_and_rejects_foreign_roots(self):
        import ast
        source=ast.Module(body=[node for node in ast.parse(admission._REMOTE).body if isinstance(node,ast.FunctionDef) and node.name=='mount_layout'],type_ignores=[])
        stage='/data/local/tmp/vpn-control-endpoint-'+CORRELATION
        plan={'staging':stage,'target':'/system/etc/security/cacerts','stagingIdentity':'0:755:64800:65543'}
        def unknown(value):raise ValueError(value)
        ns={'unknown':unknown,'re':__import__('re'),'pathlib':__import__('pathlib')};exec(compile(source,'<layout>','exec'),ns)
        base='94 1 253:0 / / ro - ext4 /dev/system ro\n131 94 253:32 / /data rw - ext4 /dev/data rw\n'
        nested='132 131 253:32 /sandbox /data/local/tmp rw - ext4 /dev/data rw\n'
        root='/sandbox/'+stage.rsplit('/',1)[1]
        target='197 94 253:32 '+root+' '+plan['target']+' rw - ext4 /dev/data rw\n'
        layout=ns['mount_layout'](plan,base+nested+target);self.assertEqual(root,layout['root']);self.assertEqual(1,len(layout['owned']))
        prefix='133 131 253:32 /foreign /data/local/tmp-other rw - ext4 /dev/data rw\n'
        self.assertEqual(root,ns['mount_layout'](plan,base+nested+prefix+target)['root'])
        for observed in (target.replace('253:32','253:33'),target.replace(root,'/foreign'),target.replace(root,root+'//deleted'),target.replace('- ext4','- overlay')):
            self.assertEqual([],ns['mount_layout'](plan,base+nested+observed)['owned'])
        for changed in (nested.replace('253:32','253:33'),nested.replace('/sandbox ','/sandbox//deleted '),nested+nested.replace('132 ','133 ')):
            with self.assertRaisesRegex(ValueError,'mount_source_unverified'):ns['mount_layout'](plan,base+changed+target)

    def test_cleanup_never_removes_stage_when_relative_bind_survives_unmount(self):
        import ast
        names={'cleanup_effects','mount_layout'}
        source=ast.Module(body=[node for node in ast.parse(admission._REMOTE).body if isinstance(node,ast.FunctionDef) and node.name in names],type_ignores=[])
        with tempfile.TemporaryDirectory() as raw:
            stage='/data/local/tmp/vpn-control-endpoint-'+CORRELATION
            plan={'zygote':{'pid':'177','startTicks':123456,'namespace':'mnt:[4026532888]'},'target':'/system/etc/security/cacerts','staging':stage,'stagingIdentity':'0:755:64800:65543'}
            mounted='94 1 253:0 / / ro - ext4 /dev/system ro\n131 94 253:32 / /data rw - ext4 /dev/data rw\n197 94 253:32 '+stage.removeprefix('/data')+' '+plan['target']+' rw - ext4 /dev/data rw\n'
            effects=[]
            def shell(*words):
                if words==('id','-u'):return '2000'
                if words[:1]==('cat',):return mounted
                if 'sha256sum' in words:return 'a'*64+'  certificate'
                effects.append(words);return ''
            def unknown(value):raise ValueError(value)
            ns={'validate_mount':lambda p:p,'shell':shell,'guard':lambda *_:None,'routes':lambda:{},'job':Path(raw),'correlation':CORRELATION,
                'record':lambda *_:None,'checkpoint':lambda *_:None,'adb_call':lambda *_a,**_k:None,'identity':lambda *_:None,
                'zygote_identity':lambda _:plan['zygote'],'staging_identity':lambda _:plan['stagingIdentity'],
                'expected':{'caStoreName':'ca.0','caSha256':'a'*64},'unknown':unknown,'unmount_exact':mock.Mock(),
                're':__import__('re'),'pathlib':__import__('pathlib')}
            exec(compile(source,'<cleanup-layout>','exec'),ns)
            with self.assertRaisesRegex(ValueError,'fixture_mount_remaining'):ns['cleanup_effects'](plan)
            ns['unmount_exact'].assert_called_once_with(plan);self.assertEqual([],effects)

    def _shell_mount_observer(self, api=29, drift=None):
        import ast
        plan={'zygote':{'pid':'177','startTicks':123456,'namespace':'mnt:[4026532888]'},
              'target':'/system/etc/security/cacerts' if api==29 else '/apex/com.android.conscrypt/cacerts',
              'staging':'/data/local/tmp/vpn-control-endpoint-'+CORRELATION,'stagingIdentity':'0:755:64800:65543'}
        layout=('131 94 253:32 / /data rw - ext4 /dev/data rw\n197 131 253:32 /local/tmp/vpn-control-endpoint-'+CORRELATION+' '+plan['target']+' rw - ext4 /dev/data rw\n')
        calls=[];helper_reads=0
        def unknown(reason): raise ValueError(reason)
        def shell(*words):
            nonlocal helper_reads
            calls.append(words)
            if words==('id','-u'):return '2000'
            if words==('cat','/proc/177/stat'):return '177 (zygote64) S '+'0 '*18+('123457' if drift=='generation' else '123456')+' 0'
            if words==('readlink','/proc/177/ns/mnt'):raise ValueError('command_failed')  # measured shell exit1, empty output
            if words==('stat','-c','%u:%a:%d:%i',plan['staging']):return '0:755:64800:'+('99' if drift=='stage' else '65543')
            if words==('stat','-c','%u:%g:%a:%d:%i:%F','/system/xbin/su'):
                helper_reads+=1
                return '0:2000:4750:64258:'+('99' if drift=='helper' and helper_reads>1 else '20')+':regular file'
            if words==('sha256sum','/system/xbin/su'):return 'a'*64+'  /system/xbin/su'
            raise AssertionError(words)
        def run(argv,**kwargs):
            words=argv[5:];calls.append(tuple(words))
            self.assertEqual(subprocess.PIPE,kwargs['stderr'])
            if words==['/system/xbin/su','--help']:output=admission._AOSP_SU_HELP
            elif words==['/system/xbin/su','0,0','/system/bin/id','-u']:output='0'
            elif words==['/system/xbin/su','0,0','/system/bin/readlink','/proc/177/ns/mnt']:output='mnt:[99]' if drift=='namespace' else plan['zygote']['namespace']
            elif words==['/system/xbin/su','0,0','/system/bin/cat','/proc/177/mountinfo']:output=layout.replace('/local/tmp/','/foreign/') if drift=='mount' else layout
            else:raise AssertionError(words)
            return SimpleNamespace(returncode=0,stdout=output.encode(),stderr=b'')
        names={'mount_observed','mount_observation_reader','mount_observation_generation','zygote_identity','staging_identity','mount_layout'}
        source=ast.Module(body=[node for node in ast.parse(admission._REMOTE).body if isinstance(node,ast.FunctionDef) and node.name in names],type_ignores=[])
        ns={'shell':shell,'unknown':unknown,'re':__import__('re'),'pathlib':__import__('pathlib'),
            'subprocess':subprocess,'adb':'/bin/adb','serial':'emulator-5554','AOSP_HELP':admission._AOSP_SU_HELP.strip()}
        exec(compile(source,'<actual-mount-observer>','exec'),ns)
        return plan,calls,ns,run

    def test_after_unroot_mount_observer_uses_pinned_root_namespace_reads(self):
        for api in (29,35):
            with self.subTest(api=api):
                plan,calls,ns,run=self._shell_mount_observer(api)
                with mock.patch('subprocess.run',side_effect=run):self.assertTrue(ns['mount_observed'](plan))
                self.assertNotIn(('readlink','/proc/177/ns/mnt'),calls)
                privileged=[x for x in calls if x[:2]==('/system/xbin/su','0,0')]
                self.assertTrue(privileged)
                self.assertTrue(all(x[2:] in {('/system/bin/id','-u'),('/system/bin/readlink','/proc/177/ns/mnt'),('/system/bin/cat','/proc/177/mountinfo')} for x in privileged))

    def test_after_unroot_mount_observer_preserves_generation_stage_and_mount_guards(self):
        for drift,reason in (('generation','zygote_reused'),('namespace','zygote_reused'),('stage','staging_replaced'),('mount','fixture_mount_missing_or_changed'),('helper','mount_observation_principal_unverified')):
            with self.subTest(drift=drift):
                plan,calls,ns,run=self._shell_mount_observer(drift=drift)
                with mock.patch('subprocess.run',side_effect=run),self.assertRaisesRegex(ValueError,reason):ns['mount_observed'](plan)
                self.assertFalse(any(x[0] in {'mount','umount','rm','root','unroot'} for x in calls))

    def test_mount_namespace_reader_rejects_nonread_commands_and_non_aosp_helper(self):
        plan,calls,ns,run=self._shell_mount_observer()
        with mock.patch('subprocess.run',side_effect=run):
            read=ns['mount_observation_reader'](plan)
            for words in (('cat','/proc/99/mountinfo'),('mount','--bind','a','b'),('readlink','/proc/177/ns/net')):
                before=len(calls)
                with self.assertRaisesRegex(ValueError,'mount_observation_principal_unverified'):read(*words)
                self.assertEqual(before,len(calls))
        def foreign(argv,**kwargs):
            if argv[5:]==['/system/xbin/su','--help']:return SimpleNamespace(returncode=0,stdout=b'foreign help',stderr=b'')
            return run(argv,**kwargs)
        with mock.patch('subprocess.run',side_effect=foreign),self.assertRaisesRegex(ValueError,'mount_observation_principal_unverified'):ns['mount_observation_reader'](plan)

    def test_mount_observer_accepts_exact_aosp_help_on_stderr_but_rejects_mixed_streams(self):
        for mixed in (False,True):
            with self.subTest(mixed=mixed):
                plan,calls,ns,run=self._shell_mount_observer()
                def help_on_stderr(argv,**kwargs):
                    if argv[5:]==['/system/xbin/su','--help']:
                        return SimpleNamespace(returncode=0,stdout=b'other' if mixed else b'',stderr=admission._AOSP_SU_HELP.encode())
                    return run(argv,**kwargs)
                with mock.patch('subprocess.run',side_effect=help_on_stderr):
                    if mixed:
                        with self.assertRaisesRegex(ValueError,'mount_observation_principal_unverified'):ns['mount_observed'](plan)
                    else:self.assertTrue(ns['mount_observed'](plan))

    def test_rooted_mount_reader_preserves_direct_reads_without_su(self):
        plan,calls,ns,run=self._shell_mount_observer()
        original=ns['shell']
        def rooted(*words):
            if words==('id','-u'):return '0'
            if words==('readlink','/proc/177/ns/mnt'):return plan['zygote']['namespace']
            return original(*words)
        ns['shell']=rooted
        with mock.patch('subprocess.run',side_effect=AssertionError('root daemon observer should not invoke su')):
            read=ns['mount_observation_reader'](plan)
            self.assertEqual(plan['zygote']['namespace'],read('readlink','/proc/177/ns/mnt'))

    def test_default_rooted_cleanup_guard_reads_public_state_as_shell(self):
        import ast
        names={'command','public','public_argv','guard'}
        source=ast.Module(body=[n for n in ast.parse(admission._REMOTE).body if isinstance(n,ast.FunctionDef) and n.name in names],type_ignores=[])
        expected={'cli':'/bin/cli','owner':'owner-a','revision':3,'backupPath':'/fixture/routing.json','backupSha256':hashlib.sha256(b'backup').hexdigest()}
        adapted=[]
        def authorized(argv,timeout,env):
            adapted.append(argv)
            words=argv[9:] if argv[7:8]==['--controller-id'] else argv[7:]
            data={'runtimeRunning':False,'runtimeObservation':'stopped'} if words==['status'] else {'operations':[]}
            return SimpleNamespace(returncode=0,stdout=json.dumps({'ok':True,'final':True,'code':'OK','controllerId':'owner-a','configurationRevision':3,'data':data}).encode(),stderr=b'')
        def unknown(reason):raise ValueError(reason)
        ns={'expected':expected,'cli':'/bin/cli','serial':'emulator-5554','action':'cleanup','readmission':None,'remaining':None,'diagnostic_actions':set(),
            'shell':lambda *_:'0','identity':mock.Mock(),'installed':mock.Mock(),'environment':{},'root':Path('/fixture'),
            'private':lambda *_:b'backup','os':SimpleNamespace(path=SimpleNamespace(lexists=lambda _:True)),'job':Path('/fixture/job'),'rooted_public_read':authorized,'subprocess':subprocess,'json':json,'hashlib':hashlib,'pathlib':__import__('pathlib'),
            'step':lambda *_:None,'command_phase':lambda *_:'public-status','command_failure':lambda reason,*_:unknown(reason),'unknown':unknown}
        exec(compile(source,'<actual-default-cleanup-guard>','exec'),ns)
        denied=SimpleNamespace(returncode=1,stdout=b'{"ok":false,"code":"PERMISSION_DENIED","final":true}',stderr=b'')
        with mock.patch('subprocess.run',return_value=denied) as direct:
            ns['guard']('0')
        direct.assert_not_called();self.assertEqual(2,len(adapted));ns['identity'].assert_called_once_with('0')
        self.assertTrue(all(x[7:9]==['--controller-id','owner-a'] for x in adapted))

    def test_default_rooted_reader_revalidates_original_journals_and_builds_shell_adapter(self):
        import ast
        names={'rooted_public_read','public_words'}
        source=ast.Module(body=[n for n in ast.parse(admission._REMOTE).body if isinstance(n,ast.FunctionDef) and n.name in names],type_ignores=[])
        for drift in (None,'intent','lease','mount','stage','namespace','reverse'):
            with self.subTest(drift=drift),tempfile.TemporaryDirectory() as raw:
                job=Path(raw);job.chmod(0o700)
                plan={'zygote':{'pid':'177','startTicks':19,'namespace':'mnt:[42]'},'target':'/system/etc/security/cacerts','staging':'/data/local/tmp/fixture','stagingIdentity':'0:755:1:22'}
                expected={'owner':'owner-a','revision':3}
                records={'intent.json':expected,'mount-intent.json':plan,'stage-owned.json':{k:plan[k] for k in ('zygote','staging','stagingIdentity')}}
                if drift in {'intent','mount','stage'}:records[{'intent':'intent.json','mount':'mount-intent.json','stage':'stage-owned.json'}[drift]]={}
                def unknown(reason):raise ValueError(reason)
                ns={'expected':expected,'stored_expected':expected,'job':job,'readmission':None,'remaining':None,'action':'cleanup','api':'29','adb':'/bin/adb','serial':'emulator-5554',
                    'validate_mount':lambda x:plan if x==plan else unknown('mount_intent_invalid'),'private':lambda p,*_:json.dumps(records[p.name]).encode(),'exact_lease_present':lambda:None if drift=='lease' else object(),
                    'identity':mock.Mock(),'installed':mock.Mock(),'routes':lambda:{1:2} if drift=='reverse' else {},'zygote_identity':lambda _:{} if drift=='namespace' else plan['zygote'],
                    'principal_identity':('identity','hash'),'principal_preflight':{},'unknown':unknown,'json':json,'os':os,'sys':sys,'hashlib':hashlib,'tempfile':tempfile,'pathlib':__import__('pathlib'),'stat':stat,'subprocess':subprocess,
                    'ENDPOINT_ADAPTER':admission._ENDPOINT_ADB_ADAPTER,'step':lambda *_:None,'command_phase':lambda *_:'public-status'}
                def preflight(gate):
                    gate();ns['principal_preflight']={'grammar':'aosp-who-command','helperIdentity':'verified','shellUid':'verified','providerAccess':'verified'}
                ns['fixed_principal_preflight']=preflight
                exec(compile(source,'<actual-rooted-reader>','exec'),ns)
                argv=['/bin/cli','--json','--android','--serial','emulator-5554','--timeout-seconds','30','--controller-id','owner-a','status']
                def run(actual,**kwargs):
                    self.assertEqual(argv,actual)
                    adapter=Path(kwargs['env']['PATH'].split(os.pathsep)[0])/'adb'
                    source=adapter.read_text();self.assertIn('"revision": 3',source);self.assertIn('"owner": "owner-a"',source)
                    self.assertIn("'2000,2000'",source)
                    return SimpleNamespace(returncode=0,stdout=b'{}',stderr=b'')
                with mock.patch('subprocess.run',side_effect=run) as dispatch:
                    if drift:
                        with self.assertRaises(ValueError):ns['rooted_public_read'](argv,30,{})
                        dispatch.assert_not_called()
                    else:ns['rooted_public_read'](argv,30,{});dispatch.assert_called_once()

    def test_mount_target_preflight_rejects_measured_deleted_inode_before_mount(self):
        import ast
        source=ast.Module(body=[node for node in ast.parse(admission._REMOTE).body if isinstance(node,ast.FunctionDef) and node.name in ('mount_target_preflight','mount_exact')],type_ignores=[])
        plan={'zygote':{'pid':'177','startTicks':123456,'namespace':'mnt:[4026532888]'},'target':'/system/etc/security/cacerts','staging':'/data/local/tmp/vpn-control-endpoint-'+CORRELATION}
        for observed in ('64800:65542:0:directory','64800:65542:bad:directory','64800:65542:2:symbolic link'):
            with self.subTest(observed=observed):
                reason=[];shell=mock.Mock(return_value=observed)
                def unknown(value):reason.append(value);raise SystemExit()
                namespace={'adb':'/bin/adb','serial':'emulator-5554','zygote_identity':lambda _:plan['zygote'],'shell':shell,'re':__import__('re'),'unknown':unknown,'subprocess':__import__('subprocess')}
                exec(compile(source,'<mount-preflight>','exec'),namespace)
                with mock.patch('subprocess.run',side_effect=AssertionError('mount attempted despite unlinked target')) as run:
                    with self.assertRaises(SystemExit):namespace['mount_exact'](plan)
                self.assertEqual(['mount_target_unlinked_or_unverified'],reason);run.assert_not_called()
                shell.assert_called_once_with('/system/bin/nsenter','-t','177','-m','--','/system/bin/stat','-c','%d:%i:%h:%F','/system/etc/security/cacerts')

    def test_mount_target_preflight_accepts_linked_target_and_rejects_namespace_drift(self):
        import ast
        source=ast.Module(body=[node for node in ast.parse(admission._REMOTE).body if isinstance(node,ast.FunctionDef) and node.name in ('mount_target_preflight','mount_exact')],type_ignores=[])
        plan={'zygote':{'pid':'177','startTicks':123456,'namespace':'mnt:[4026532888]'},'target':'/system/etc/security/cacerts','staging':'/data/local/tmp/vpn-control-endpoint-'+CORRELATION}
        for drift in (False,True):
            with self.subTest(drift=drift):
                identities=[plan['zygote'],{**plan['zygote'],'namespace':'mnt:[99]'} if drift else plan['zygote'],plan['zygote']]
                def unknown(value):raise SystemExit(value)
                namespace={'adb':'/bin/adb','serial':'emulator-5554','zygote_identity':mock.Mock(side_effect=identities),
                    'shell':mock.Mock(return_value='64258:1142:2:directory'),'re':__import__('re'),'unknown':unknown,'subprocess':__import__('subprocess')}
                exec(compile(source,'<mount-preflight>','exec'),namespace)
                with mock.patch('subprocess.run',return_value=SimpleNamespace(returncode=0,stdout=b'',stderr=b'')) as run:
                    if drift:
                        with self.assertRaisesRegex(SystemExit,'zygote_reused_before_mount'):namespace['mount_exact'](plan)
                        run.assert_not_called()
                    else:
                        namespace['mount_exact'](plan);run.assert_called_once()
                        self.assertEqual(['mount','--bind',plan['staging'],plan['target']],run.call_args.args[0][-4:])

    def test_future_mount_failure_classifies_only_finite_origins(self):
        cases = ((b"nsenter: cannot run", "nsenter-launch"),
                 (b"mount: /data/local/tmp/vpn-control-endpoint-" + CORRELATION.encode() + b": failed", "mount-path-pair"),
                 (b"fstab lookup failed", "fstab"),
                 (b"cannot read /proc/filesystems", "proc-filesystems"),
                 (b"opaque kernel failure", "other"),
                 (b"", "unknown"))
        for stderr, origin in cases:
            with self.subTest(origin=origin), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); root.chmod(0o700)
                expected = {"adb":"/bin/adb","cli":"/bin/cli","serial":"emulator-5554","api":35,"avd":"vpn-control-api35"}
                namespace = {"__name__":"remote_test","public_cli_environment":lambda *_:{}}
                with mock.patch("sys.argv", ["remote","status",str(root),"api35",CORRELATION,json.dumps(expected)]), contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(SystemExit): exec(admission._REMOTE, namespace)
                namespace["job"].mkdir(mode=0o700)
                plan = {"zygote":{"pid":"177","startTicks":123456,"namespace":"mnt:[4026532888]"},"target":"/apex/com.android.conscrypt/cacerts","staging":"/data/local/tmp/vpn-control-endpoint-"+CORRELATION}
                namespace["zygote_identity"] = mock.Mock(return_value=plan["zygote"])
                namespace["mount_target_preflight"] = mock.Mock()
                with mock.patch("subprocess.run", return_value=SimpleNamespace(returncode=1,stdout=b"",stderr=stderr)), contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(SystemExit): namespace["mount_exact"](plan)
                receipt = json.loads((namespace["job"] / "mount-failure.json").read_text())
                self.assertEqual({"phase":"mount","exit":"nonzero","errorClass":"other" if origin in {"other","unknown","fstab","proc-filesystems","nsenter-launch","mount-path-pair"} else "other","errorOrigin":origin}, receipt)
                if stderr:
                    self.assertNotIn(stderr.decode("utf-8", "ignore"), json.dumps(receipt))

    def test_mount_wrapper_durably_records_finite_failure_before_unknown(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve(); root.chmod(0o700)
            expected={"adb":"/bin/adb","cli":"/bin/cli","serial":"emulator-5554","api":35,"avd":"vpn-control-api35"}
            ns={"__name__":"remote_test","public_cli_environment":lambda *_:{}}
            with mock.patch("sys.argv",["remote","status",str(root),"api35",CORRELATION,json.dumps(expected)]), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit): exec(admission._REMOTE,ns)
            ns["job"].mkdir(mode=0o700)
            plan={"zygote":{"pid":"177","startTicks":123456,"namespace":"mnt:[4026532888]"},"target":"/apex/com.android.conscrypt/cacerts","staging":"/data/local/tmp/vpn-control-endpoint-"+CORRELATION}
            ns["zygote_identity"]=mock.Mock(return_value=plan["zygote"])
            ns["mount_target_preflight"]=mock.Mock()
            output=io.StringIO()
            with mock.patch("subprocess.run",return_value=SimpleNamespace(returncode=1,stdout=b"",stderr=b"Operation not permitted")) as run, contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit): ns["mount_exact"](plan)
            self.assertEqual({"phase":"mount","exit":"nonzero","errorClass":"permission","errorOrigin":"other"},json.loads((ns["job"] / "mount-failure.json").read_text()))
            self.assertEqual(0o600, (ns["job"] / "mount-failure.json").stat().st_mode & 0o777)
            self.assertEqual({"state":"unknown","reason":"mount_command_failed","correlationId":CORRELATION,"phase":"mount","mountFailure":{"phase":"mount","exit":"nonzero","errorClass":"permission","errorOrigin":"other"}},json.loads(output.getvalue()))
            run.assert_called_once(); ns["zygote_identity"].assert_called_once()

    def test_mount_diagnostic_projects_only_bounded_nsenter_failure_shape(self):
        intent = {"correlationId": CORRELATION, "remote": {}}
        partial = {"uid": "root", "stage": "before-root", "mountPlan": "recorded",
                   "zygoteGeneration": "recorded", "stagingIdentity": "recorded", "mount": "absent",
                   "ca": "present", "commandPhase": "mount", "mountDiagnostic": {
                       "state": "failed", "generation": "stable", "namespaceUid": "unknown",
                       "target": "unknown", "staging": "unknown", "exit": "nonzero", "errorClass": "not-found",
                       "nsenterBinary": "available", "nsenterId": "ok", "absoluteId": "ok", "failurePhase": "target-stat", "outsideBind": "supported", "insideBind": "supported", "relativeMount": "missing", "targetMountMembership": "member", "targetMountMembershipReason": "ok", "targetMountMembershipBytes": 42, "targetMountMembershipEntries": 1, "targetMountFdinfoFormat": "valid", "targetMountFdinfoKeyCount": 1, "targetMountFdinfoMntIdCount": 1, "stagingMountMembership": "member", "outsideCapSysAdmin": "present", "insideCapSysAdmin": "present", "selinux": "enforcing", "domain": "su"}}
        value = {"state": "partial", "reason": "setup_incomplete", "phase": "mount-intent", "partialDiagnostic": partial}
        result = admission._bound_result(intent, value, "status")
        self.assertEqual(partial["mountDiagnostic"], result["mountDiagnostic"])
        self.assertNotIn("mountDiagnostic", admission._bound_result(intent, {**value, "partialDiagnostic": {
            **partial, "mountDiagnostic": {**partial["mountDiagnostic"], "errorClass": "raw stderr"}}}, "status"))
        for forged in ("unbounded", ["member"]):
            self.assertNotIn("mountDiagnostic", admission._bound_result(intent, {**value, "partialDiagnostic": {
                **partial, "mountDiagnostic": {**partial["mountDiagnostic"], "targetMountMembership": forged}}}, "status"))
        for key, forged in (("targetMountMembershipReason", "raw stderr"),
                            ("targetMountMembershipBytes", [1]),
                            ("targetMountMembershipEntries", 258)):
            self.assertNotIn("mountDiagnostic", admission._bound_result(intent, {**value, "partialDiagnostic": {
                **partial, "mountDiagnostic": {**partial["mountDiagnostic"], key: forged}}}, "status"))

    def test_partial_diagnostic_projects_only_finite_field_enums(self):
        remote = {"api": 35, "avd": "vpn-control-api35", "packageSha256": PACKAGE,
                  "owner": "owner-a", "revision": 3, "caSha256": hashlib.sha256(CA).hexdigest()}
        intent = {"correlationId": CORRELATION, "remote": remote}
        partial = {"uid": "root", "stage": "before-root", "mountPlan": "recorded",
                   "zygoteGeneration": "recorded", "stagingIdentity": "recorded", "mount": "present",
                   "ca": "present", "commandPhase": "cleanup-unmount"}
        baseline = {"state": "partial", "reason": "setup_incomplete", "phase": "mount-intent",
                    "partialDiagnostic": partial}
        self.assertEqual(partial, admission._bound_result(intent, baseline, "status")["partialDiagnostic"])
        for key in partial:
            for forged in ("forged-value", ["nested"]):
                with self.subTest(key=key, forged=forged):
                    candidate = {**partial, key: forged}
                    result = admission._bound_result(intent, {**baseline, "partialDiagnostic": candidate}, "status")
                    self.assertNotIn("partialDiagnostic", result)

    def test_opening_readback_requires_exact_x86_64_abi_identity_before_intent(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            opening = {"ok": True, "state": "complete", "result": {
                "package": {"baseSha256": PACKAGE},
                "device": {"uid": "2000", "api": 35, "avd": "vpn-control-api35", "abi": "x86_64"},
                "guard": {"controllerId": "owner-a", "configurationRevision": 3},
                "backup": {"path": "/private/fixture/android-readback-" + BACKUP + "/routing.json",
                           "sha256": BACKUP_HASH}}}
            with self._admitted(root)[0], mock.patch.object(
                    admission.android_admission_readback, "async_collect", return_value=opening):
                result = self._start(root)
            self.assertEqual("unknown", result["state"])
            self.assertTrue(admission._intent_path(root, CORRELATION).exists())
            for changed in (
                    {"uid": "2000", "api": 35, "avd": "vpn-control-api35"},
                    {"uid": "2000", "api": 35, "avd": "vpn-control-api35", "abi": "arm64-v8a"},
                    {"uid": "2000", "api": 35, "avd": "vpn-control-api35", "abi": "x86_64", "extra": True}):
                with self.subTest(device=changed), tempfile.TemporaryDirectory() as rejected_raw:
                    rejected = Path(rejected_raw).resolve()
                    blocked = {**opening, "result": {**opening["result"], "device": changed}}
                    with self._admitted(rejected)[0], mock.patch.object(
                            admission.android_admission_readback, "async_collect", return_value=blocked), \
                            mock.patch.object(admission, "_remote") as remote:
                        with self.assertRaisesRegex(ValueError, "opening readback"):
                            self._start(rejected)
                    self.assertFalse((rejected / ".rag_index/android-endpoint-admission" /
                                      (CORRELATION + ".json")).exists())
                    self.assertFalse((rejected / ".rag_index/android-native-device-leases" /
                                      "lease-archlinux-api35.json").exists())
                    remote.assert_not_called()

    def test_status_missing_local_intent_is_bounded_unknown_without_remote_observation(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with mock.patch.object(admission, "_remote") as remote:
                result = admission.status(root, CORRELATION)
            self.assertEqual({"ok": False, "state": "unknown", "reason": "missing_local_intent",
                              "correlationId": CORRELATION, "replayAllowed": False,
                              "productMutationAllowed": False, "installerTargetAdmitted": False}, result)
            self.assertFalse((root / ".rag_index" / "android-endpoint-admission").exists())
            remote.assert_not_called()

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



class AndroidCleanupReadmissionTest(unittest.TestCase):
    READMISSION = '742b1784-87dd-4fea-9ad3-8df5e8ffbdf3'

    def fixture(self, root):
        root.chmod(0o700)
        rules = {'ignore_rules': True, 'block_quic_udp_443': False,
                 'proxy_packages': [], 'direct_domain_suffixes': []}
        document = {'type': 'vpn_control_routing_rules', 'version': 7,
                    'exported_at': 'opening', 'rules': rules}
        backup = root / 'routing.json'; backup.write_text(json.dumps(document)); backup.chmod(0o600)
        expected = {'host': 'archlinux', 'adb': '/bin/adb', 'cli': '/bin/cli', 'serial': 'emulator-5554',
                    'api': 29, 'avd': 'vpn-control-api29', 'packageSha256': PACKAGE, 'owner': 'old-owner',
                    'revision': 0, 'backupPath': str(backup), 'backupSha256': hashlib.sha256(backup.read_bytes()).hexdigest(),
                    'campaignId': CAMPAIGN, 'leafSha256': LEAF, 'caSha256': 'a' * 64,
                    'caStoreName': '0123abcd.0', 'httpsHostPort': 41001, 'socksHostPort': 41002}
        job = root / ('android-endpoint-' + CORRELATION); job.mkdir(mode=0o700)
        plan = {'zygote': {'pid': '177', 'startTicks': 19, 'namespace': 'mnt:[42]'},
                'target': '/system/etc/security/cacerts', 'staging': '/data/local/tmp/vpn-control-endpoint-' + CORRELATION,
                'stagingIdentity': '0:755:1:22'}
        for name, value in [('intent.json', expected), ('mount-intent.json', plan),
                            ('mount-failure.json', {'phase': 'mount', 'exit': 'nonzero', 'errorClass': 'not-found'}),
                            ('stage-owned.json', {key: plan[key] for key in ('zygote', 'staging', 'stagingIdentity')})]:
            admission.android_native_fixture.write_private_plan(job / name, value)
        admission.android_native_fixture.write_private_plan(root / 'android-native-device-api29.lease',
                {'owner': 'android-endpoint', 'correlationId': CORRELATION, 'device': 'api29', 'host': 'archlinux'})
        state = {'uid': '0', 'owner': 'new-owner', 'revision': 0, 'rules': rules, 'runtime': False,
                 'operations': [], 'namespace': 'mnt:[42]', 'inode': '0:755:1:22', 'effects': [], 'reads': 0}
        def command(argv, **kwargs):
            if argv[0] == '/bin/cli':
                words = _public_words(argv); state['reads'] += 1
                if words == ['status']:
                    data = {'runtimeRunning': state['runtime'], 'runtimeObservation': 'stopped',
                            'selectedLocationId': None, 'activeLocationId': None}
                elif words == ['operations', 'list']: data = {'operations': state['operations']}
                elif words == ['routing', 'show']:
                    data = {'routing': {**document, 'rules': state['rules'], 'exported_at': str(state['reads'])}}
                else: raise AssertionError(words)
                raw = json.dumps({'ok': True, 'final': True, 'code': 'OK', 'controllerId': state['owner'],
                                  'configurationRevision': state['revision'], 'data': data}).encode()
            elif argv[3] == 'shell':
                words = argv[5:]
                if words == ['id', '-u']: raw = state['uid'].encode()
                elif words[:1] == ['getprop']:
                    raw = ('29' if words[1] == 'ro.build.version.sdk' else 'x86_64' if words[1] == 'ro.product.cpu.abi' else 'vpn-control-api29').encode()
                elif words[:2] == ['pm', 'path']: raw = b'package:/data/app/owned/base.apk\n'
                elif words == ['stat', '-c', '%u:%g:%a:%d:%i:%F', '/system/xbin/su']:
                    raw = b'0:2000:4750:64258:4886:regular file'
                elif words == ['sha256sum', '/system/xbin/su']: raw = ('a' * 64 + '  /system/xbin/su').encode()
                elif words == ['/system/xbin/su', '--help']: raw = admission._AOSP_SU_HELP.encode()
                elif words == ['/system/xbin/su', '2000,2000', '/system/bin/id', '-u']: raw = b'2000'
                elif words[:4] == ['/system/xbin/su', '2000,2000', '/system/bin/content', 'call']:
                    return SimpleNamespace(returncode=0, stdout=b'', stderr=b'java.lang.IllegalArgumentException: UNSUPPORTED')
                elif words[:1] == ['sha256sum']: raw = ((state.get('package', PACKAGE) if words[1].endswith('/base.apk') else state.get('ca', 'a' * 64)) + ' ' + words[1]).encode()
                elif words == ['cat', '/proc/177/stat']: raw = ('177 (zygote) ' + ' '.join(['0'] * 19 + ['19'])).encode()
                elif words == ['readlink', '/proc/177/ns/mnt']: raw = state['namespace'].encode()
                elif words == ['stat', '-c', '%u:%a:%d:%i', plan['staging']]: raw = state['inode'].encode()
                elif words[:8] == ['nsenter','-t','177','-m','--','/system/bin/stat','-c','%F']:
                    return SimpleNamespace(returncode=0 if state.get('targetCa',b'absent')!=b'absent' else 1, stdout=b'regular file' if state.get('targetCa',b'absent')!=b'absent' else b'', stderr=b'' if state.get('targetCa',b'absent')!=b'absent' else ("stat: '"+words[8]+"': No such file or directory").encode())
                elif words == ['cat', '/proc/177/mountinfo']: raw = state.get('mountinfo', b'1 0 1:1 / / rw - ext4 /dev/x rw\n2 1 1:1 /unowned/ca /system/etc/security/cacerts rw - ext4 /dev/x rw\n')
                elif words[:2] == ['sh', '-c']:
                    raw = state.get('targetCa', b'absent') if 'sha256sum ' in words[2] or 'nsenter' in words[2] and '[ -e ' in words[2] else (b'absent' if state.get('retired') else b'present') if '[ -e ' in words[2] else state.get('membership', b'mnt_id:\t1\n__VPN_CONTROL_MOUNTINFO__\n1\n')
                elif words[:2] == ['rm', '-r']: state['effects'].append(words); state['retired'] = True; raw = b''
                else: raise AssertionError(words)
            elif argv[3:5] == ['reverse', '--list']: raw = state.get('reverses', b'')
            elif argv[3] in {'root', 'unroot'}:
                state['effects'].append(argv[3]); state['uid'] = '0' if argv[3] == 'root' else '2000'; raw = b''
            elif argv[3] == 'wait-for-device': raw = b''
            else: raise AssertionError(argv)
            return SimpleNamespace(returncode=0, stdout=raw, stderr=b'')
        return expected, state, command

    def execute(self, root, expected, action, command):
        output = io.StringIO()
        with mock.patch('sys.argv', ['remote', action, str(root), 'api29', CORRELATION, json.dumps(expected)]), \
                mock.patch('subprocess.run', side_effect=command), contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit):
                exec(admission._REMOTE, {'public_cli_environment': lambda *_: {}})
        return json.loads(output.getvalue())

    def remaining_fixture(self, root):
        expected,state,base=self.fixture(root);job=root/('android-endpoint-'+CORRELATION)
        plan=json.loads((job/'mount-intent.json').read_bytes())
        (job/'mount-failure.json').unlink()
        expected['caSha256']=hashlib.sha256(CA).hexdigest();state['ca']=expected['caSha256']
        (job/'intent.json').write_text(json.dumps(expected))
        admission.android_native_fixture.write_private_plan(job/'stage.json',{'phase':'before_root','target':plan['target'],'staging':plan['staging']})
        (job/'ca.pem').write_bytes(CA);(job/'ca.pem').chmod(0o600)
        admission.android_native_fixture.write_private_plan(job/'cleanup-intent.json',{'correlationId':CORRELATION,'mount':plan})
        for phase in ('cleanup-reverse-https','cleanup-reverse-socks','cleanup-root','cleanup-unmount'):
            admission.android_native_fixture.write_private_plan(job/('checkpoint-'+phase+'.json'),{'phase':phase})
        state['mountinfo']=b'94 1 1:1 / / rw - ext4 /dev/system rw\n131 94 0:1 / /data rw - ext4 /dev/data rw\n'
        def command(argv,**kwargs):
            words=argv[5:] if argv[3:5]==['shell','-T'] else []
            if words[:1]==['/system/xbin/su'] and words[1:2]==['0,0']:words=words[2:]
            if words[:1]==['/system/bin/nsenter']:words=words[5:]
            if words[:1] and words[0].startswith('/system/bin/'):words=[words[0].removeprefix('/system/bin/'),*words[1:]]
            if words==['id','-u'] and argv[5:7]==['/system/xbin/su','0,0']:return SimpleNamespace(returncode=0,stdout=b'0',stderr=b'')
            if words[:2]==['stat','-c'] and words[2]=='%d:%i:%h:%F':return SimpleNamespace(returncode=0,stdout=b'64258:1142:2:directory',stderr=b'')
            if words[:2]==['stat','-c'] and words[2]=='%u:%g:%a:%d:%i:%h:%s:%Y:%Z:%F':
                if state.get('retired'):
                    return SimpleNamespace(returncode=1,stdout=b'',stderr=("stat: '"+words[-1]+"': No such file or directory").encode())
                output=b'0:0:755:1:22:2:4096:100:100:directory' if words[-1]==plan['staging'] else b'0:0:644:1:23:1:100:100:100:regular file'
                return SimpleNamespace(returncode=0,stdout=output,stderr=b'')
            if words[:2]==['stat','-c'] and words[2]=='%F' and words[-1].startswith(plan['target']+'/'):
                return SimpleNamespace(returncode=1,stdout=b'',stderr=("stat: '"+words[-1]+"': No such file or directory").encode())
            if words and words[0] in {'cat','readlink','sha256sum'} and words!=argv[5:]:
                return base([*argv[:5],*words],**kwargs)
            return base(argv,**kwargs)
        binding={'correlationId':self.READMISSION,'originalIntentSha256':'f'*64}
        return expected,state,command,binding

    def test_remaining_stage_readmission_accepts_actual_partial_cleanup_in_new_mode_only(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();expected,state,command,binding=self.remaining_fixture(root)
            old=self.execute(root,{**expected,'cleanupReadmission':binding},'cleanup-readmit',command)
            self.assertEqual('readmission_phase_invalid',old['reason'])
            result=self.execute(root,{**expected,'cleanupRemaining':binding},'remaining-cleanup-admit',command)
            self.assertEqual('ready',result['state'],result)
            self.assertEqual([],state['effects'])
            self.assertFalse((root/('android-endpoint-'+CORRELATION)/'cleaned.json').exists())

    def remaining_admitted(self, root):
        expected,state,command,binding=self.remaining_fixture(root)
        result=self.execute(root,{**expected,'cleanupRemaining':binding},'remaining-cleanup-admit',command)
        self.assertEqual('ready',result['state'],result)
        return expected,state,command,{**binding,'receipt':result['remaining'],'receiptPin':result['remainingReceiptPin']}

    def test_remaining_stage_effect_only_removes_stage_and_unroots_once_then_collects(self):
        from collections import Counter
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();expected,state,command,binding=self.remaining_admitted(root)
            job=root/('android-endpoint-'+CORRELATION);originals={n:(job/n).read_bytes() for n in ('intent.json','cleanup-intent.json','mount-intent.json')}
            counts=Counter()
            def counted(argv,**kwargs):counts[kwargs.get('timeout')]+=1;return command(argv,**kwargs)
            result=self.execute(root,{**expected,'cleanupRemaining':binding},'remaining-cleanup-once',counted)
            self.assertEqual('cleaned',result['state'],result)
            self.assertEqual([['rm','-r','/data/local/tmp/vpn-control-endpoint-'+CORRELATION],'unroot'],state['effects'])
            self.assertEqual('2000',state['uid']);self.assertTrue(result['originalOutcome']=='unknown');self.assertFalse(result['leaseReleased'])
            again=self.execute(root,{**expected,'cleanupRemaining':binding},'remaining-cleanup-once',command)
            self.assertEqual('remaining_attempt_recorded',again['reason']);self.assertEqual(2,len(state['effects']))
            status=self.execute(root,{**expected,'cleanupRemaining':binding},'remaining-cleanup-status',command);self.assertEqual('cleaned',status['state'],status)
            collected=self.execute(root,{**expected,'cleanupRemaining':binding},'remaining-cleanup-collect',command);self.assertEqual('cleaned',collected['state'],collected);self.assertTrue(collected['leaseReleased'])
            again=self.execute(root,{**expected,'cleanupRemaining':binding},'remaining-cleanup-collect',command);self.assertEqual('cleaned',again['state'],again)
            self.assertEqual(originals,{n:(job/n).read_bytes() for n in originals});self.assertFalse((job/'cleaned.json').exists())
            self.assertFalse((root/'android-native-device-api29.lease').exists())
            self.assertLess(counts[30],2048);self.assertLess(counts[10],2048);self.assertLess(counts[315],32)

    def test_remaining_stage_crash_after_removal_and_uncertain_unroot_never_replay(self):
        for phase in ('after-stage','unroot-unknown'):
            with self.subTest(phase=phase),tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve();expected,state,command,binding=self.remaining_admitted(root)
                def crash(argv,**kwargs):
                    if phase=='unroot-unknown' and argv[3:4]==['unroot']:
                        command(argv,**kwargs);raise subprocess.TimeoutExpired(argv,30)
                    result=command(argv,**kwargs)
                    if phase=='after-stage' and argv[5:7]==['rm','-r']:state['owner']='replaced-owner'
                    return result
                value=self.execute(root,{**expected,'cleanupRemaining':binding},'remaining-cleanup-once',crash)
                self.assertEqual('unknown',value['state'],value)
                self.assertEqual(1 if phase=='after-stage' else 2,len(state['effects']))
                job=root/('android-endpoint-'+CORRELATION)
                self.assertTrue((job/('remaining-stage-'+self.READMISSION+'.attempt.json')).exists())
                self.assertFalse((job/('remaining-stage-'+self.READMISSION+'.terminal.json')).exists())
                retry=self.execute(root,{**expected,'cleanupRemaining':binding},'remaining-cleanup-once',command)
                self.assertEqual('remaining_attempt_recorded',retry['reason']);self.assertEqual(1 if phase=='after-stage' else 2,len(state['effects']))
                observed=self.execute(root,{**expected,'cleanupRemaining':binding},'remaining-cleanup-status',command)
                self.assertEqual('unknown',observed['state']);self.assertTrue((root/'android-native-device-api29.lease').exists())

    def test_remaining_admission_rejects_link_mount_child_and_public_drift(self):
        for phase in ('unlinked','mount-ref','child','owner','rules','runtime'):
            with self.subTest(phase=phase),tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve();expected,state,command,binding=self.remaining_fixture(root)
                if phase=='mount-ref':state['mountinfo']+=('197 131 0:1 /local/tmp/vpn-control-endpoint-'+CORRELATION+' /foreign rw - ext4 /dev/data rw\n').encode()
                elif phase=='child':admission.android_native_fixture.write_private_plan(root/'android-runtime-acceptance-child.json',{'parentCorrelationId':CORRELATION})
                elif phase=='rules':state['rules']={}
                elif phase=='runtime':state['runtime']=True
                def drift(argv,**kwargs):
                    if phase=='unlinked' and argv[3:5]==['shell','-T'] and '%d:%i:%h:%F' in argv:return SimpleNamespace(returncode=0,stdout=b'64258:1142:0:directory',stderr=b'')
                    result=command(argv,**kwargs)
                    if phase=='owner' and argv[0]=='/bin/cli' and state['reads']==1:state['owner']='later-owner'
                    return result
                result=self.execute(root,{**expected,'cleanupRemaining':binding},'remaining-cleanup-admit',drift)
                self.assertEqual('unknown',result['state'],result);self.assertEqual([],state['effects'])

    def test_remaining_effect_rejects_same_byte_private_generation_replacement(self):
        for name in ('intent.json','mount-intent.json','ca.pem','lease','receipt'):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve();expected,state,command,binding=self.remaining_admitted(root);job=root/('android-endpoint-'+CORRELATION)
                path=root/'android-native-device-api29.lease' if name=='lease' else job/('remaining-stage-'+self.READMISSION+'.json') if name=='receipt' else job/name
                content=path.read_bytes();path.rename(path.with_suffix('.historical'));path.write_bytes(content);path.chmod(0o600)
                result=self.execute(root,{**expected,'cleanupRemaining':binding},'remaining-cleanup-once',command)
                self.assertEqual('unknown',result['state'],result);self.assertEqual([],state['effects'])

    def test_remaining_owner_drift_after_unroot_fence_blocks_unroot(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();expected,state,command,binding=self.remaining_admitted(root)
            fence=root/('android-endpoint-'+CORRELATION)/('remaining-stage-'+self.READMISSION+'.unroot.json')
            def drift(argv,**kwargs):
                if fence.exists():state['owner']='later-owner'
                return command(argv,**kwargs)
            result=self.execute(root,{**expected,'cleanupRemaining':binding},'remaining-cleanup-once',drift)
            self.assertEqual('unknown',result['state']);self.assertEqual([['rm','-r','/data/local/tmp/vpn-control-endpoint-'+CORRELATION]],state['effects']);self.assertEqual('0',state['uid'])

    def remaining_local_fixture(self, root):
        expected,state,command,binding=self.remaining_fixture(root)
        intent={'host':'archlinux','device':'api29','correlationId':CORRELATION,'sourceSha':SOURCE,'targetArtifactId':'sha256-'+PACKAGE,'remoteRoot':str(root),'remote':expected}
        admission.android_native_fixture.write_private_plan(admission._intent_path(root,CORRELATION),intent)
        leases=root/'.rag_index/android-native-device-leases';leases.mkdir(mode=0o700)
        admission.android_native_fixture.write_private_plan(leases/'lease-archlinux-api29.json',{'owner':'android-endpoint','correlationId':CORRELATION,'host':'archlinux','device':'api29'})
        config=SimpleNamespace(hosts={'archlinux':SimpleNamespace(android_devices={'api29':{'adb':expected['adb'],'cli':expected['cli'],'serial':expected['serial'],'api':29,'expectedAvd':expected['avd']}})})
        def remote(_root,dispatch,action):return self.execute(root,dispatch['remote'],action,command)
        return intent,state,config,remote

    def test_remaining_local_apis_preserve_unknown_original_and_release_exact_leases(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();intent,state,config,remote=self.remaining_local_fixture(root);original=admission._intent_path(root,CORRELATION).read_bytes()
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote',side_effect=remote):
                result=admission.remaining_cleanup_readmission(root,CORRELATION,self.READMISSION);self.assertEqual('ready',result['state'],result)
                again=admission.remaining_cleanup_readmission(root,CORRELATION,self.READMISSION);self.assertEqual('remaining_already_recorded',again['reason'])
                status=admission.remaining_cleanup_status(root,CORRELATION,self.READMISSION);self.assertEqual('ready',status['state'],status)
                result=admission.remaining_cleanup_once(root,CORRELATION,self.READMISSION);self.assertEqual('cleaned',result['state'],result)
                again=admission.remaining_cleanup_once(root,CORRELATION,self.READMISSION);self.assertEqual('remaining_attempt_recorded',again['reason']);self.assertEqual(2,len(state['effects']))
                result=admission.remaining_cleanup_collect(root,CORRELATION,self.READMISSION);self.assertEqual('cleaned',result['state'],result);self.assertTrue(result['leaseReleased'])
                again=admission.remaining_cleanup_collect(root,CORRELATION,self.READMISSION);self.assertEqual('cleaned',again['state'],again)
                status=admission.remaining_cleanup_status(root,CORRELATION,self.READMISSION);self.assertEqual('cleaned',status['state'],status)
            self.assertEqual(original,admission._intent_path(root,CORRELATION).read_bytes());self.assertFalse((root/'.rag_index/android-native-device-leases/lease-archlinux-api29.json').exists())

    def test_remaining_local_unknown_attempt_and_same_byte_replacement_block_dispatch(self):
        for attack in ('unknown','original','receipt','lease','child'):
            with self.subTest(attack=attack),tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve();intent,state,config,remote=self.remaining_local_fixture(root)
                with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote',side_effect=remote):
                    self.assertEqual('ready',admission.remaining_cleanup_readmission(root,CORRELATION,self.READMISSION)['state'])
                if attack=='child':
                    parent=root/'.rag_index/android-runtime-acceptance';parent.mkdir(mode=0o700)
                    admission.android_native_fixture.write_private_plan(parent/('parent-'+CORRELATION+'.lease'),{'parentCorrelationId':CORRELATION,'correlationId':self.READMISSION})
                if attack=='unknown':
                    with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote',return_value={'state':'unknown','correlationId':CORRELATION}) as dispatch:
                        self.assertEqual('unknown',admission.remaining_cleanup_once(root,CORRELATION,self.READMISSION)['state'])
                        self.assertEqual('remaining_attempt_recorded',admission.remaining_cleanup_once(root,CORRELATION,self.READMISSION)['reason']);self.assertEqual(1,dispatch.call_count)
                elif attack!='child':
                    file=admission._intent_path(root,CORRELATION) if attack=='original' else admission._remaining_path(root,self.READMISSION) if attack=='receipt' else root/'.rag_index/android-native-device-leases/lease-archlinux-api29.json'
                    def replacement(_root,dispatch,action):
                        content=file.read_bytes();file.rename(file.with_suffix('.preserved'));file.write_bytes(content);file.chmod(0o600)
                        return {'state':'unknown','correlationId':CORRELATION}
                    with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote',side_effect=replacement):
                        result=admission.remaining_cleanup_once(root,CORRELATION,self.READMISSION);self.assertEqual('remaining_local_unverified',result['reason'])
                else:
                    with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote') as dispatch:
                        self.assertEqual('unknown',admission.remaining_cleanup_once(root,CORRELATION,self.READMISSION)['state']);dispatch.assert_not_called()
                self.assertEqual([],state['effects'])

    def test_remaining_actual_generated_subprocess_paths_match_scoped_transport_ceilings(self):
        from collections import Counter
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();expected,state,command,binding=self.remaining_fixture(root)
            sequence=('remaining-cleanup-admit','remaining-cleanup-status','remaining-cleanup-once','remaining-cleanup-status','remaining-cleanup-collect','remaining-cleanup-status','remaining-cleanup-collect')
            for action in sequence:
                counts=Counter()
                def counted(argv,**kwargs):counts[kwargs['timeout']]+=1;return command(argv,**kwargs)
                result=self.execute(root,{**expected,'cleanupRemaining':binding},action,counted)
                self.assertIn(result['state'],{'ready','cleaned'},result)
                self.assertIn(dict(counts),admission._REMAINING_COMMAND_BOUNDS[action])
                self.assertGreaterEqual(admission._readmission_transport_seconds(action,{'cleanupRemaining':binding}),sum(seconds*calls for seconds,calls in counts.items())+60)
                if action=='remaining-cleanup-admit':binding={**binding,'receipt':result['remaining'],'receiptPin':result['remainingReceiptPin']}
            self.assertEqual(60,admission._readmission_transport_seconds('status',{'cleanupRemaining':binding}))

    def test_remaining_remote_large_private_receipt_uses_existing_android_cap(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();intent,state,config,remote=self.remaining_local_fixture(root)
            config.hosts['archlinux'].fixture_transfer_root=root
            response={'state':'ready','correlationId':CORRELATION,'remaining':{'metadata':'a'*5000}}
            payload=json.dumps(response).encode();self.assertGreater(len(payload),4096);self.assertLess(len(payload),16384)
            dispatch={**intent,'remote':{**intent['remote'],'cleanupRemaining':{'correlationId':self.READMISSION,'originalIntentSha256':'f'*64}}}
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission.ssh_transport,'connection_host',return_value=SimpleNamespace(password=None)),mock.patch.object(admission.ssh_transport,'build_ssh_argv',return_value=['ssh']),mock.patch.object(admission.android_observation,'_run_probe',return_value=(0,payload)) as observer,mock.patch.object(admission.ssh_transfer,'_bounded_run') as transfer:
                self.assertEqual(response,admission._remote(root,dispatch,'remaining-cleanup-admit'));transfer.assert_not_called()
                self.assertEqual(14890,observer.call_args.args[1]);self.assertEqual(4096,admission.ssh_transfer.MAX_OUTPUT_BYTES);self.assertEqual(16384,admission.android_observation.MAX_OUTPUT_BYTES)
            for failure,outcome in ((RuntimeError('oversized_output'),'output-limit'),(TimeoutError(),'timeout')):
                with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission.ssh_transport,'connection_host',return_value=SimpleNamespace(password=None)),mock.patch.object(admission.ssh_transport,'build_ssh_argv',return_value=['ssh']),mock.patch.object(admission.android_observation,'_run_probe',side_effect=failure):
                    result=admission._remote(root,dispatch,'remaining-cleanup-admit');self.assertEqual('unknown',result['state']);self.assertEqual(outcome,result['transportDiagnostic']['outcome'])

    def test_remaining_other_correlation_cannot_bypass_consumed_recovery(self):
        other='da33b0d7-7aa1-46d5-82a8-c83b2ceded1b'
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();expected,state,command,binding=self.remaining_admitted(root)
            result=self.execute(root,{**expected,'cleanupRemaining':{'correlationId':other,'originalIntentSha256':'f'*64}},'remaining-cleanup-admit',command)
            self.assertEqual('remaining_already_recorded',result['reason']);self.assertEqual([],state['effects'])
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();intent,state,config,remote=self.remaining_local_fixture(root)
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote',return_value={'state':'unknown','correlationId':CORRELATION}) as dispatch:
                self.assertEqual('unknown',admission.remaining_cleanup_readmission(root,CORRELATION,self.READMISSION)['state'])
                self.assertEqual('remaining_already_recorded',admission.remaining_cleanup_readmission(root,CORRELATION,other)['reason']);self.assertEqual(1,dispatch.call_count)

    def test_old_owner_fails_then_fresh_readmission_cleans_without_rewriting_intent(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); expected, state, command = self.fixture(root)
            original = (root / ('android-endpoint-' + CORRELATION) / 'intent.json').read_bytes()
            state['uid'] = '2000'
            denied = self.execute(root, expected, 'cleanup', command)
            self.assertEqual('owner_changed', denied['reason']); self.assertEqual([], state['effects'])
            state['uid'] = '0'
            binding = {'correlationId': self.READMISSION, 'originalIntentSha256': 'f' * 64}
            admitted = self.execute(root, {**expected, 'cleanupReadmission': binding}, 'cleanup-readmit', command)
            self.assertEqual('ready', admitted['state'], admitted)
            self.assertEqual([], state['effects'])
            sent = {**expected, 'owner': 'new-owner', 'cleanupReadmission': {**binding, 'receipt': admitted['readmission']}}
            cleaned = self.execute(root, sent, 'cleanup', command)
            self.assertEqual('cleaned', cleaned['state'], cleaned)
            self.assertEqual(original, (root / ('android-endpoint-' + CORRELATION) / 'intent.json').read_bytes())

    def test_readmission_rejects_foreign_package_rules_runtime_operations_namespace_stage_and_reverse(self):
        variants = [{'package': 'e' * 64}, {'rules': {}}, {'runtime': True},
                    {'operations': [{'final': False}]}, {'namespace': 'mnt:[43]'},
                    {'inode': '0:755:1:99'}, {'reverses': b'host tcp:18080 tcp:41001\n'},
                    {'membership': b'mnt_id:\t2\n__VPN_CONTROL_MOUNTINFO__\n1\n'},
                    {'ca': 'e' * 64}, {'mountinfo': b'invalid\n'}]
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); expected, state, command = self.fixture(root); state.update(variant)
                result = self.execute(root, {**expected, 'cleanupReadmission': {
                    'correlationId': self.READMISSION, 'originalIntentSha256': 'f' * 64}}, 'cleanup-readmit', command)
                self.assertEqual('unknown', result['state']); self.assertEqual([], state['effects'])
                self.assertFalse((root / ('android-endpoint-' + CORRELATION) / ('cleanup-readmission-' + self.READMISSION + '.json')).exists())

    def test_cleanup_readmission_revalidates_each_drift_before_any_effect(self):
        variants = [{'owner': 'third-owner'}, {'revision': 1}, {'package': 'e' * 64},
                    {'runtime': True}, {'operations': [{'final': False}]}, {'namespace': 'mnt:[43]'},
                    {'inode': '0:755:1:99'}, {'rules': {}}, {'ca': 'e' * 64}]
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); expected, state, command = self.fixture(root)
                binding = {'correlationId': self.READMISSION, 'originalIntentSha256': 'f' * 64}
                admitted = self.execute(root, {**expected, 'cleanupReadmission': binding}, 'cleanup-readmit', command)
                state.update(variant)
                result = self.execute(root, {**expected, 'owner': 'new-owner', 'cleanupReadmission': {
                    **binding, 'receipt': admitted['readmission']}}, 'cleanup', command)
                self.assertEqual('unknown', result['state']); self.assertEqual([], state['effects'])

    def test_owner_revision_change_between_reads_rejects_receipt(self):
        for key, changed in [('owner', 'later-owner'), ('revision', 1)]:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); expected, state, command = self.fixture(root)
                def drift(argv, **kwargs):
                    if state['reads'] == 4: state[key] = changed
                    return command(argv, **kwargs)
                result = self.execute(root, {**expected, 'cleanupReadmission': {
                    'correlationId': self.READMISSION, 'originalIntentSha256': 'f' * 64}}, 'cleanup-readmit', drift)
                self.assertEqual('unknown', result['state']); self.assertEqual([], state['effects'])

    def test_remote_receipt_forgery_and_unsafe_files_reject_before_effects(self):
        for attack in ['forged', 'hardlink', 'symlink', 'mode', 'original']:
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); expected, state, command = self.fixture(root)
                binding = {'correlationId': self.READMISSION, 'originalIntentSha256': 'f' * 64}
                admitted = self.execute(root, {**expected, 'cleanupReadmission': binding}, 'cleanup-readmit', command)
                job = root / ('android-endpoint-' + CORRELATION)
                receipt = job / ('cleanup-readmission-' + self.READMISSION + '.json')
                if attack == 'forged': admitted['readmission']['snapshot']['revision'] = 1
                elif attack == 'hardlink': os.link(receipt, job / 'alias.json')
                elif attack == 'symlink':
                    receipt.rename(job / 'original.json'); receipt.symlink_to(job / 'original.json')
                elif attack == 'mode': receipt.chmod(0o644)
                elif attack == 'original': (job / 'intent.json').write_text('{}')
                result = self.execute(root, {**expected, 'owner': 'new-owner', 'cleanupReadmission': {
                    **binding, 'receipt': admitted['readmission']}}, 'cleanup', command)
                self.assertEqual('unknown', result['state']); self.assertEqual([], state['effects'])

    def local_fixture(self, root):
        expected, state, command = self.fixture(root)
        intent = {'host': 'archlinux', 'device': 'api29', 'correlationId': CORRELATION,
                  'sourceSha': SOURCE, 'targetArtifactId': 'sha256-' + PACKAGE,
                  'remoteRoot': str(root), 'remote': expected}
        admission.android_native_fixture.write_private_plan(admission._intent_path(root, CORRELATION), intent)
        leases = root / '.rag_index/android-native-device-leases'; leases.mkdir(mode=0o700)
        admission.android_native_fixture.write_private_plan(leases / 'lease-archlinux-api29.json', {
            'owner': 'android-endpoint', 'correlationId': CORRELATION, 'host': 'archlinux', 'device': 'api29'})
        profile = {'adb': expected['adb'], 'cli': expected['cli'], 'serial': expected['serial'],
                   'api': 29, 'expectedAvd': expected['avd']}
        config = SimpleNamespace(hosts={'archlinux': SimpleNamespace(android_devices={'api29': profile})})
        def remote(_root, dispatch, action): return self.execute(root, dispatch['remote'], action, command)
        remote.command = command
        return intent, state, config, remote

    def test_public_readmission_and_cleanup_preserve_exact_local_original_bytes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); intent, state, config, remote = self.local_fixture(root)
            original = admission._intent_path(root, CORRELATION).read_bytes()
            with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                    mock.patch.object(admission, '_remote', side_effect=remote):
                result = admission.cleanup_readmission(root, CORRELATION, self.READMISSION)
                self.assertEqual('ready', result['state']); self.assertEqual([], state['effects'])
                result = admission.cleanup_readmitted(root, CORRELATION, self.READMISSION)
                self.assertEqual('cleaned', result['state'], result)
            self.assertEqual(original, admission._intent_path(root, CORRELATION).read_bytes())

    def test_runtime_child_rejects_both_local_apis_before_remote_dispatch(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); intent, state, config, remote = self.local_fixture(root)
            with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                    mock.patch.object(admission, '_remote', side_effect=remote):
                admission.cleanup_readmission(root, CORRELATION, self.READMISSION)
            directory = root / '.rag_index/android-runtime-acceptance'; directory.mkdir(mode=0o700)
            admission.android_native_fixture.write_private_plan(directory / ('parent-' + CORRELATION + '.lease'), {
                'parentCorrelationId': CORRELATION, 'runtimeCorrelationId': CAMPAIGN})
            with mock.patch.object(admission, '_remote') as dispatch:
                with self.assertRaisesRegex(ValueError, 'runtime child'):
                    admission.cleanup_readmitted(root, CORRELATION, self.READMISSION)
                with self.assertRaisesRegex(ValueError, 'runtime child'):
                    admission.cleanup_readmission(root, CORRELATION, BACKUP)
            dispatch.assert_not_called(); self.assertEqual([], state['effects'])

    def test_private_snapshot_rejects_same_inode_write_and_path_replacement(self):
        for change in ['write', 'replace']:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); root.chmod(0o700); path = root / 'record.json'
                admission.android_native_fixture.write_private_plan(path, {'a': 1})
                actual_read = os.read
                def mutate(fd, limit):
                    payload = actual_read(fd, limit)
                    if change == 'write': path.write_bytes(payload.replace(b'1', b'2'))
                    else:
                        replacement = root / 'new.json'; replacement.write_bytes(payload); replacement.chmod(0o600)
                        os.replace(replacement, path)
                    return payload
                with mock.patch.object(admission.android_native_fixture_lifecycle, '_read_plan', return_value={'a': 1}), \
                        mock.patch.object(admission.os, 'read', side_effect=mutate):
                    with self.assertRaisesRegex(ValueError, 'record changed'):
                        admission._private_snapshot(path)

    def test_remote_child_and_mounted_or_foreign_overlay_reject_readmission(self):
        for variant in ['child', 'mounted', 'foreign']:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); expected, state, command = self.fixture(root)
                if variant == 'child':
                    admission.android_native_fixture.write_private_plan(root / ('android-runtime-acceptance-' + CAMPAIGN + '.json'),
                                                                       {'parentCorrelationId': CORRELATION})
                else:
                    if variant == 'foreign': state['targetCa'] = b'present'
                    state['mountinfo'] = ('2 1 1:1 ' + ('/data/local/tmp/vpn-control-endpoint-' + CORRELATION if variant == 'mounted' else '/foreign') + ' /system/etc/security/cacerts rw - ext4 /dev/x rw\n').encode()
                result = self.execute(root, {**expected, 'cleanupReadmission': {
                    'correlationId': self.READMISSION, 'originalIntentSha256': 'f' * 64}}, 'cleanup-readmit', command)
                self.assertEqual('unknown', result['state']); self.assertEqual([], state['effects'])

    def test_remote_private_read_rejects_same_inode_change_before_receipt(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); expected, state, command = self.fixture(root)
            path = root / ('android-endpoint-' + CORRELATION) / 'intent.json'
            actual_stat = os.stat
            attacked = False
            def mutate(*args, **kwargs):
                nonlocal attacked
                if args[0] == 'intent.json' and kwargs.get('dir_fd') is not None and not attacked:
                    attacked = True
                    payload = path.read_bytes()
                    path.write_bytes(payload.replace(b'old-owner', b'bad-owner'))
                return actual_stat(*args, **kwargs)
            with mock.patch.object(admission.os, 'stat', side_effect=mutate):
                result = self.execute(root, {**expected, 'cleanupReadmission': {
                    'correlationId': self.READMISSION, 'originalIntentSha256': 'f' * 64}}, 'cleanup-readmit', command)
            self.assertEqual('private_file_changed', result['reason']); self.assertEqual([], state['effects'])

    def test_local_forged_original_binding_and_unsafe_receipt_block_dispatch(self):
        for attack in ['original', 'forged', 'mode', 'hardlink', 'symlink']:
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); intent, state, config, remote = self.local_fixture(root)
                with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                        mock.patch.object(admission, '_remote', side_effect=remote):
                    admission.cleanup_readmission(root, CORRELATION, self.READMISSION)
                receipt = admission._readmission_path(root, self.READMISSION)
                if attack == 'original': admission._intent_path(root, CORRELATION).write_text('{}')
                elif attack == 'forged':
                    value = json.loads(receipt.read_bytes()); value['originalIntentSha256'] = '0' * 64
                    receipt.write_text(json.dumps(value))
                elif attack == 'mode': receipt.chmod(0o644)
                elif attack == 'hardlink': os.link(receipt, receipt.parent / 'alias.json')
                elif attack == 'symlink':
                    receipt.rename(receipt.parent / 'original.json'); receipt.symlink_to(receipt.parent / 'original.json')
                with mock.patch.object(admission, '_remote') as dispatch:
                    with self.assertRaises((ValueError, KeyError, OSError)):
                        admission.cleanup_readmitted(root, CORRELATION, self.READMISSION)
                dispatch.assert_not_called(); self.assertEqual([], state['effects'])


    def test_inter_effect_drift_blocks_unroot_after_owned_stage_retirement(self):
        for changed in [{'owner': 'later-owner'}, {'rules': {}}, {'runtime': True}, {'namespace': 'mnt:[99]'},
                        {'revision': 1}, {'operations': [{'final': False}]}, {'package': 'e' * 64},
                        {'reverses': b'host tcp:18080 tcp:41001\n'}, {'retired': False}]:
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); expected, state, command = self.fixture(root)
                binding = {'correlationId': self.READMISSION, 'originalIntentSha256': 'f' * 64}
                admitted = self.execute(root, {**expected, 'cleanupReadmission': binding}, 'cleanup-readmit', command)
                receipt_bytes = (root / ('android-endpoint-' + CORRELATION) / ('cleanup-readmission-' + self.READMISSION + '.json')).read_bytes()
                def drift(argv, **kwargs):
                    result = command(argv, **kwargs)
                    if argv[3:6] == ['shell', '-T', 'rm']: state.update(changed)
                    return result
                result = self.execute(root, {**expected, 'owner': 'new-owner', 'cleanupReadmission': {
                    **binding, 'receipt': admitted['readmission']}}, 'cleanup', drift)
                self.assertEqual('unknown', result['state'])
                self.assertEqual(1, len(state['effects']))
                self.assertEqual(['rm', '-r'], state['effects'][0][:2])
                self.assertEqual(receipt_bytes, (root / ('android-endpoint-' + CORRELATION) / ('cleanup-readmission-' + self.READMISSION + '.json')).read_bytes())


    def test_checkpoint_drift_blocks_first_cleanup_effect(self):
        for changed in [{'owner': 'later-owner'}, {'rules': {}}, {'runtime': True}, {'namespace': 'mnt:[99]'}]:
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); expected, state, command = self.fixture(root)
                binding = {'correlationId': self.READMISSION, 'originalIntentSha256': 'f' * 64}
                admitted = self.execute(root, {**expected, 'cleanupReadmission': binding}, 'cleanup-readmit', command)
                checkpoint = root / ('android-endpoint-' + CORRELATION) / 'checkpoint-cleanup-stage-remove.json'
                def drift(argv, **kwargs):
                    if checkpoint.exists(): state.update(changed)
                    return command(argv, **kwargs)
                result = self.execute(root, {**expected, 'owner': 'new-owner', 'cleanupReadmission': {
                    **binding, 'receipt': admitted['readmission']}}, 'cleanup', drift)
                self.assertEqual('unknown', result['state']); self.assertEqual([], state['effects'])

    def test_successful_readmitted_cleanup_has_only_owned_stage_remove_and_single_unroot(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); expected, state, command = self.fixture(root)
            binding = {'correlationId': self.READMISSION, 'originalIntentSha256': 'f' * 64}
            admitted = self.execute(root, {**expected, 'cleanupReadmission': binding}, 'cleanup-readmit', command)
            result = self.execute(root, {**expected, 'owner': 'new-owner', 'cleanupReadmission': {
                **binding, 'receipt': admitted['readmission']}}, 'cleanup', command)
            self.assertEqual('cleaned', result['state'], result)
            self.assertEqual([['rm', '-r', '/data/local/tmp/vpn-control-endpoint-' + CORRELATION], 'unroot'], state['effects'])
            self.assertTrue(state['retired']); self.assertEqual('2000', state['uid'])


    def test_readmission_preserves_finite_remote_guard_failure(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); intent, state, config, remote = self.local_fixture(root)
            with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                    mock.patch.object(admission, '_remote', return_value={'state': 'unknown', 'correlationId': CORRELATION,
                                                                      'reason': 'readmission_namespace_foreign'}):
                result = admission.cleanup_readmission(root, CORRELATION, self.READMISSION)
            self.assertEqual('readmission_namespace_foreign', result['reason'])
            self.assertTrue(admission._readmission_path(root, self.READMISSION, '.request.json').exists())
            self.assertFalse(admission._readmission_path(root, self.READMISSION).exists())

    def test_status_original_failed_readmission_observes_guard_without_replay_or_writes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); intent, state, config, remote = self.local_fixture(root)
            state['namespace'] = 'mnt:[99]'
            with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                    mock.patch.object(admission, '_remote', side_effect=remote) as dispatch:
                admission.cleanup_readmission(root, CORRELATION, self.READMISSION)
                before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
                result = admission.cleanup_readmission_status(root, CORRELATION, self.READMISSION)
                after = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            self.assertEqual('readmission_namespace_changed', result['reason'])
            self.assertEqual('cleanup-readmission-status', dispatch.call_args.args[2])
            self.assertEqual(before, after); self.assertEqual([], state['effects'])


    def test_status_receipt_absent_or_present_never_creates_admission_or_effects(self):
        for present in (False, True):
            with self.subTest(present=present), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); intent, state, config, remote = self.local_fixture(root)
                with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                        mock.patch.object(admission, '_remote', side_effect=remote):
                    if present: admission.cleanup_readmission(root, CORRELATION, self.READMISSION)
                    else:
                        digest = admission._private_snapshot(admission._intent_path(root, CORRELATION))[1]
                        admission.android_native_fixture.write_private_plan(admission._readmission_path(root, self.READMISSION, '.request.json'), {
                            'schema': 1, 'endpointCorrelationId': CORRELATION, 'correlationId': self.READMISSION,
                            'originalIntentSha256': digest})
                    before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
                    result = admission.cleanup_readmission_status(root, CORRELATION, self.READMISSION)
                    after = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
                self.assertEqual('partial', result['state']); self.assertFalse(result['ok'])
                self.assertTrue(result['observationOnly']); self.assertTrue(result['freshGuardVerified'])
                self.assertEqual(present, result['receiptPresent'])
                self.assertEqual(before, after); self.assertEqual([], state['effects'])

    def test_status_missing_or_changed_request_blocks_remote_and_has_no_writes(self):
        for variant in ('absent', 'wrong-hash', 'wrong-endpoint'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); intent, state, config, remote = self.local_fixture(root)
                if variant != 'absent':
                    admission.android_native_fixture.write_private_plan(admission._readmission_path(root, self.READMISSION, '.request.json'), {
                        'schema': 1, 'endpointCorrelationId': BACKUP if variant == 'wrong-endpoint' else CORRELATION,
                        'correlationId': self.READMISSION, 'originalIntentSha256': 'f' * 64})
                before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
                with mock.patch.object(admission, '_remote') as dispatch:
                    result = admission.cleanup_readmission_status(root, CORRELATION, self.READMISSION)
                after = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
                dispatch.assert_not_called(); self.assertEqual('unknown', result['state']); self.assertEqual(before, after)

    def test_status_and_submission_do_not_project_foreign_remote_reason(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); intent, state, config, remote = self.local_fixture(root)
            response = {'state': 'unknown', 'correlationId': CORRELATION, 'reason': '/secret transport details'}
            with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                    mock.patch.object(admission, '_remote', return_value=response):
                result = admission.cleanup_readmission(root, CORRELATION, self.READMISSION)
                status = admission.cleanup_readmission_status(root, CORRELATION, self.READMISSION)
            self.assertEqual('cleanup_readmission_unverified', result['reason'])
            self.assertEqual('cleanup_readmission_unverified', status['reason'])
            self.assertNotIn('/secret', json.dumps([result, status])); self.assertEqual([], state['effects'])


    def test_status_self_correlated_request_rejects_without_dispatch_or_writes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); intent, state, config, remote = self.local_fixture(root)
            digest = admission._private_snapshot(admission._intent_path(root, CORRELATION))[1]
            admission.android_native_fixture.write_private_plan(admission._readmission_path(root, CORRELATION, '.request.json'), {
                'schema': 1, 'endpointCorrelationId': CORRELATION, 'correlationId': CORRELATION,
                'originalIntentSha256': digest})
            before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                    mock.patch.object(admission, '_remote', side_effect=remote) as dispatch:
                with self.assertRaisesRegex(ValueError, 'distinct'):
                    admission.cleanup_readmission_status(root, CORRELATION, CORRELATION)
            after = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            dispatch.assert_not_called(); self.assertEqual(before, after); self.assertEqual([], state['effects'])


    def test_ordinary_rooted_cleanup_checks_old_owner_before_unroot(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); expected, state, command = self.fixture(root)
            result = self.execute(root, expected, 'cleanup', command)
            self.assertEqual('owner_changed', result['reason']); self.assertEqual([], state['effects'])
            self.assertEqual('0', state['uid'])

    def test_shell_readmission_proves_namespace_only_after_guarded_root(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); expected, state, command = self.fixture(root); state['uid'] = '2000'
            binding = {'correlationId': self.READMISSION, 'originalIntentSha256': 'f' * 64}
            def namespace_requires_root(argv, **kwargs):
                if state['uid'] == '2000' and (argv[5:] in [['readlink', '/proc/177/ns/mnt'], ['cat', '/proc/177/mountinfo']] or
                        argv[5:7] == ['sh', '-c'] and 'nsenter ' in argv[7]):
                    raise AssertionError('shell cannot prove mount namespace')
                return command(argv, **kwargs)
            admitted = self.execute(root, {**expected, 'cleanupReadmission': binding}, 'cleanup-readmit', namespace_requires_root)
            self.assertEqual('ready', admitted['state'], admitted)
            snapshot = admitted['readmission']['snapshot']
            self.assertEqual('2000', snapshot['uid']); self.assertEqual('unobserved', snapshot['mountObservation'])
            self.assertEqual('unobserved', snapshot['namespaceObservation']); self.assertEqual([], state['effects'])
            result = self.execute(root, {**expected, 'owner': 'new-owner', 'cleanupReadmission': {
                **binding, 'receipt': admitted['readmission']}}, 'cleanup', namespace_requires_root)
            self.assertEqual('cleaned', result['state'], result)
            self.assertEqual(['root', ['rm', '-r', '/data/local/tmp/vpn-control-endpoint-' + CORRELATION], 'unroot'], state['effects'])


    def test_shell_cleanup_post_root_drift_keeps_lease_and_never_deletes_stage(self):
        for changed in [{'owner': 'later-owner'}, {'rules': {}}, {'runtime': True}, {'namespace': 'mnt:[99]'},
                        {'inode': '0:755:1:999'}, {'ca': 'e' * 64}, {'membership': b'mnt_id: 2\n__VPN_CONTROL_MOUNTINFO__\n1\n'},
                        {'mountinfo': b'2 1 1:1 /foreign /system/etc/security/cacerts rw - overlay /dev/x rw\n'}]:
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); intent, state, config, remote = self.local_fixture(root); state['uid'] = '2000'
                with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                        mock.patch.object(admission, '_remote', side_effect=remote):
                    admitted = admission.cleanup_readmission(root, CORRELATION, self.READMISSION)
                self.assertEqual('ready', admitted['state'], admitted)
                original_command = remote.command
                def after_root(argv, **kwargs):
                    result = original_command(argv, **kwargs)
                    if argv[3:4] == ['root']: state.update(changed)
                    return result
                def cleanup_remote(_root, dispatch, action):
                    return self.execute(root, dispatch['remote'], action, after_root)
                with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                        mock.patch.object(admission, '_remote', side_effect=cleanup_remote):
                    result = admission.cleanup_readmitted(root, CORRELATION, self.READMISSION)
                self.assertEqual('unknown', result['state']); self.assertEqual(['root'], state['effects'])
                self.assertTrue((root / '.rag_index/android-native-device-leases/lease-archlinux-api29.json').exists())
                self.assertTrue((root / 'android-native-device-api29.lease').exists())
                self.assertFalse(state.get('retired', False))

    def test_shell_readmission_preserves_prior_unknown_request_and_uses_new_uuid(self):
        old = '3ea08756-5f56-4df9-8fda-7503410ccb37'
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); intent, state, config, remote = self.local_fixture(root); state['uid'] = '2000'
            digest = admission._private_snapshot(admission._intent_path(root, CORRELATION))[1]
            historical = admission._readmission_path(root, old, '.request.json')
            admission.android_native_fixture.write_private_plan(historical, {
                'schema': 1, 'endpointCorrelationId': CORRELATION, 'correlationId': old, 'originalIntentSha256': digest})
            before = historical.read_bytes()
            with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                    mock.patch.object(admission, '_remote', side_effect=remote) as dispatch:
                with self.assertRaises(FileExistsError): admission.cleanup_readmission(root, CORRELATION, old)
                dispatch.assert_not_called()
                result = admission.cleanup_readmission(root, CORRELATION, self.READMISSION)
            self.assertEqual('ready', result['state']); self.assertEqual(before, historical.read_bytes())
            self.assertEqual([], state['effects'])

    def test_shell_admission_requires_recorded_exact_failed_mount_and_public_baseline(self):
        for changed in [{'package': 'e' * 64}, {'rules': {}}, {'runtime': True}, {'operations': [{'final': False}]},
                        {'inode': '0:755:1:999'}, {'ca': 'e' * 64}, {'reverses': b'host tcp:18080 tcp:41001\n'}]:
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); expected, state, command = self.fixture(root); state['uid'] = '2000'; state.update(changed)
                result = self.execute(root, {**expected, 'cleanupReadmission': {
                    'correlationId': self.READMISSION, 'originalIntentSha256': 'f' * 64}}, 'cleanup-readmit', command)
                self.assertEqual('unknown', result['state']); self.assertEqual([], state['effects'])
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); expected, state, command = self.fixture(root); state['uid'] = '2000'
            (root / ('android-endpoint-' + CORRELATION) / 'mount-failure.json').write_text('{}')
            result = self.execute(root, {**expected, 'cleanupReadmission': {
                'correlationId': self.READMISSION, 'originalIntentSha256': 'f' * 64}}, 'cleanup-readmit', command)
            self.assertEqual('readmission_failed_mount_unverified', result['reason']); self.assertEqual([], state['effects'])


    def stage_only_fixture(self, root):
        expected, state, command = self.fixture(root)
        job = root / ('android-endpoint-' + CORRELATION)
        (job / 'mount-intent.json').unlink()
        admission.android_native_fixture.write_private_plan(job / 'stage.json', {
            'phase': 'before_root', 'target': '/system/etc/security/cacerts',
            'staging': '/data/local/tmp/vpn-control-endpoint-' + CORRELATION})
        state['owner'] = expected['owner']
        return expected, state, command

    def test_rooted_stage_only_cleanup_rejects_public_drift_before_stage_remove(self):
        for variant in ('owner', 'runtime', 'operations', 'backup'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); expected, state, command = self.stage_only_fixture(root)
                if variant == 'owner': state['owner'] = 'changed-owner'
                elif variant == 'runtime': state['runtime'] = True
                elif variant == 'operations': state['operations'] = [{'final': False}]
                else: (root / 'routing.json').write_bytes(b'changed')
                result = self.execute(root, expected, 'cleanup', command)
                self.assertEqual('unknown', result['state']); self.assertEqual([], state['effects'])
                self.assertFalse(state.get('retired', False)); self.assertEqual('0', state['uid'])

    def test_rooted_stage_only_cleanup_rechecks_public_drift_before_unroot(self):
        for variant in ('owner', 'runtime', 'operations', 'backup'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); expected, state, command = self.stage_only_fixture(root)
                def drift(argv, **kwargs):
                    result = command(argv, **kwargs)
                    if argv[3:6] == ['shell', '-T', 'rm']:
                        if variant == 'owner': state['owner'] = 'changed-owner'
                        elif variant == 'runtime': state['runtime'] = True
                        elif variant == 'operations': state['operations'] = [{'final': False}]
                        else: (root / 'routing.json').write_bytes(b'changed')
                    return result
                result = self.execute(root, expected, 'cleanup', drift)
                self.assertEqual('unknown', result['state'])
                self.assertEqual([['rm', '-r', '/data/local/tmp/vpn-control-endpoint-' + CORRELATION]], state['effects'])
                self.assertEqual('0', state['uid'])


    def test_target_mount_diagnostic_reports_relationship_without_claiming_stock_or_effects(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); intent, state, config, remote = self.local_fixture(root); state['uid'] = '2000'
            with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                    mock.patch.object(admission, '_remote', side_effect=remote):
                admission.cleanup_readmission(root, CORRELATION, self.READMISSION)
                state['uid'] = '0'
                state['mountinfo'] = ('2 1 1:1 /system/etc/security/cacerts /system/etc/security/cacerts rw - ext4 /dev/secret rw\n' +
                                     '3 2 1:1 /data/local/tmp/vpn-control-endpoint-' + CORRELATION + ' /system/etc/security/cacerts rw - tmpfs hidden rw\n').encode()
                before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
                result = admission.cleanup_mount_diagnostic(root, CORRELATION, self.READMISSION)
                after = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            self.assertEqual('partial', result['state'], result); self.assertTrue(result['observationOnly'])
            diagnostic = result['mountDiagnostic']
            self.assertEqual(2, diagnostic['targetEntryCount']); self.assertFalse(diagnostic['openingTargetMountRecorded'])
            self.assertEqual([{'rootRelation': 'target-exact', 'filesystem': 'ext4'},
                              {'rootRelation': 'stage-exact', 'filesystem': 'tmpfs'}], diagnostic['entries'])
            self.assertEqual('absent', diagnostic['ownCaRelation']); self.assertEqual([], state['effects'])
            self.assertEqual(before, after); self.assertNotIn('/dev/secret', json.dumps(result))


    def test_mount_diagnostic_classifies_ca_and_foreign_filesystem_without_admission(self):
        target_ca = '/system/etc/security/cacerts/0123abcd.0'
        for payload, relation in [(b'absent', 'absent'), (b'other', 'other'),
                                  (('a' * 64 + ' ' + target_ca).encode(), 'owned'),
                                  (('e' * 64 + ' ' + target_ca).encode(), 'foreign')]:
            with self.subTest(relation=relation), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); intent, state, config, remote = self.local_fixture(root); state['uid'] = '2000'
                with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                        mock.patch.object(admission, '_remote', side_effect=remote):
                    admission.cleanup_readmission(root, CORRELATION, self.READMISSION)
                    state['uid'] = '0'; state['targetCa'] = payload
                    state['mountinfo'] = b'2 1 1:1 /unknown /system/etc/security/cacerts rw - foreignfs secret rw\n'
                    result = admission.cleanup_mount_diagnostic(root, CORRELATION, self.READMISSION)
                self.assertEqual('partial', result['state'], result); self.assertFalse(result['ok'])
                self.assertEqual(relation, result['mountDiagnostic']['ownCaRelation'])
                self.assertEqual([{'rootRelation': 'other', 'filesystem': 'other'}], result['mountDiagnostic']['entries'])
                self.assertEqual([], state['effects']); self.assertNotIn('foreignfs', json.dumps(result))

    def test_mount_diagnostic_rejects_hidden_mount_source_drift_and_keeps_receipt(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); intent, state, config, remote = self.local_fixture(root); state['uid'] = '2000'
            with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                    mock.patch.object(admission, '_remote', side_effect=remote):
                admission.cleanup_readmission(root, CORRELATION, self.READMISSION)
            before = admission._readmission_path(root, self.READMISSION).read_bytes()
            state['uid'] = '0'; reads = 0
            def command(argv, **kwargs):
                nonlocal reads
                if argv[5:] == ['cat', '/proc/177/mountinfo']:
                    reads += 1
                    state['mountinfo'] = ('2 1 1:1 /unknown /system/etc/security/cacerts rw - ext4 /secret' + str(reads) + ' rw\n').encode()
                return remote.command(argv, **kwargs)
            def observing(_root, dispatch, action): return self.execute(root, dispatch['remote'], action, command)
            with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                    mock.patch.object(admission, '_remote', side_effect=observing):
                result = admission.cleanup_mount_diagnostic(root, CORRELATION, self.READMISSION)
            self.assertEqual('unknown', result['state']); self.assertEqual('readmission_observation_changed', result['reason'])
            self.assertEqual([], state['effects']); self.assertEqual(before, admission._readmission_path(root, self.READMISSION).read_bytes())

    def test_mount_diagnostic_missing_receipt_or_self_correlation_never_dispatches(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); intent, state, config, remote = self.local_fixture(root)
            before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            with mock.patch.object(admission, '_remote') as dispatch:
                result = admission.cleanup_mount_diagnostic(root, CORRELATION, self.READMISSION)
                with self.assertRaisesRegex(ValueError, 'distinct'):
                    admission.cleanup_mount_diagnostic(root, CORRELATION, CORRELATION)
            self.assertEqual('unknown', result['state']); dispatch.assert_not_called()
            after = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            self.assertEqual(before, after); self.assertEqual([], state['effects'])


    def test_mount_diagnostic_failed_command_reports_exact_finite_step(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); intent, state, config, remote = self.local_fixture(root); state['uid'] = '2000'
            with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                    mock.patch.object(admission, '_remote', side_effect=remote):
                admission.cleanup_readmission(root, CORRELATION, self.READMISSION)
            state['uid'] = '0'
            def command(argv, **kwargs):
                if argv[5:7] == ['sh', '-c'] and 'sha256sum ' in argv[7]:
                    return SimpleNamespace(returncode=1, stdout=b'', stderr=b'nsenter: /secret/path: Permission denied')
                return remote.command(argv, **kwargs)
            def observe(_root, dispatch, action): return self.execute(root, dispatch['remote'], action, command)
            with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                    mock.patch.object(admission, '_remote', side_effect=observe):
                result = admission.cleanup_mount_diagnostic(root, CORRELATION, self.READMISSION)
            self.assertEqual('command_failed', result['reason'])
            self.assertEqual({'phase': 'target-ca', 'outcome': 'nonzero', 'stderrClass': 'permission'}, result['commandDiagnostic'])
            self.assertNotIn('/secret', json.dumps(result)); self.assertEqual([], state['effects'])


    def test_target_ca_command_survives_actual_adb_shell_joining(self):
        with tempfile.TemporaryDirectory() as raw, tempfile.TemporaryDirectory() as shell_raw:
            root = Path(raw).resolve(); intent, state, config, remote = self.local_fixture(root); state['uid'] = '2000'
            with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                    mock.patch.object(admission, '_remote', side_effect=remote):
                admission.cleanup_readmission(root, CORRELATION, self.READMISSION)
            state['uid'] = '0'; runner = subprocess.run; observed = []
            shell_root = Path(shell_raw).resolve()
            nsenter = shell_root / 'nsenter'
            nsenter.write_text('#!/bin/sh\n[ "$#" -eq 7 ] && [ "$1" = -t ] && [ "$2" = 177 ] && [ "$3" = -m ] && [ "$4" = -- ] && [ "$5" = /system/bin/sh ] && [ "$6" = -c ] || exit 71\nshift 6\nexec /bin/sh -c "$1"\n')
            nsenter.chmod(0o700)
            environment = {**os.environ, 'PATH': str(shell_root) + ':' + os.environ.get('PATH', '/usr/bin:/bin')}
            def command(argv, **kwargs):
                if argv[5:7] == ['sh', '-c'] and 'sha256sum ' in argv[7]:
                    # adbd joins remaining argv into one shell command. Execute
                    # that joining boundary with an inert nsenter parser stub.
                    done = runner(['/bin/sh', '-c', ' '.join(argv[5:])], capture_output=True, env=environment, timeout=5)
                    observed.append(done)
                    return done
                return remote.command(argv, **kwargs)
            def observe(_root, dispatch, action): return self.execute(root, dispatch['remote'], action, command)
            with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                    mock.patch.object(admission, '_remote', side_effect=observe):
                result = admission.cleanup_mount_diagnostic(root, CORRELATION, self.READMISSION)
            self.assertEqual('partial', result['state'], result); self.assertEqual(2, len(observed))
            self.assertTrue(all(done.returncode == 0 and done.stdout.strip() == b'absent' for done in observed))
            self.assertEqual([], state['effects'])

    def test_mount_command_phases_and_failure_classification_are_finite(self):
        phases = [(['id', '-u'], 'device-identity'), (['pm', 'path', 'com.kardinal.vpncontrol'], 'device-package'),
                  (['readlink', '/proc/177/ns/mnt'], 'zygote-namespace'),
                  (['cat', '/proc/177/mountinfo'], 'target-mountinfo')]
        for words, phase in phases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); intent, state, config, remote = self.local_fixture(root); state['uid'] = '2000'
                with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                        mock.patch.object(admission, '_remote', side_effect=remote):
                    admission.cleanup_readmission(root, CORRELATION, self.READMISSION)
                state['uid'] = '0'
                def command(argv, **kwargs):
                    if argv[5:] == words: return SimpleNamespace(returncode=1, stdout=b'', stderr=b'/private: No such file')
                    return remote.command(argv, **kwargs)
                def observe(_root, dispatch, action): return self.execute(root, dispatch['remote'], action, command)
                with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                        mock.patch.object(admission, '_remote', side_effect=observe):
                    result = admission.cleanup_mount_diagnostic(root, CORRELATION, self.READMISSION)
                self.assertEqual({'phase': phase, 'outcome': 'nonzero', 'stderrClass': 'not-found'}, result['commandDiagnostic'])
                self.assertNotIn('/private', json.dumps(result)); self.assertEqual([], state['effects'])
        for forged in ({'phase': '/secret', 'outcome': 'nonzero', 'stderrClass': 'none'},
                       {'phase': 'target-ca', 'outcome': 'raw stderr', 'stderrClass': 'none'},
                       {'phase': 'target-ca', 'outcome': 'nonzero', 'stderrClass': 'none', 'raw': 'secret'}):
            self.assertIsNone(admission._bounded_command_diagnostic(forged))


    def test_rooted_public_permission_failure_keeps_finite_json_disposition(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); intent, state, config, remote = self.local_fixture(root); state['uid'] = '2000'
            with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                    mock.patch.object(admission, '_remote', side_effect=remote): admission.cleanup_readmission(root, CORRELATION, self.READMISSION)
            state['uid'] = '0'
            def command(argv, **kwargs):
                if argv[0] == '/bin/cli' and state['uid'] == '0':
                    return SimpleNamespace(returncode=1, stderr=b'', stdout=json.dumps({'schemaVersion': 1,
                        'ok': False, 'code': 'PERMISSION_DENIED', 'final': True, 'message': '/secret context'}).encode())
                return remote.command(argv, **kwargs)
            def observing(_root, dispatch, action): return self.execute(root, dispatch['remote'], action, command)
            with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), \
                    mock.patch.object(admission, '_remote', side_effect=observing):
                result = admission.cleanup_mount_diagnostic(root, CORRELATION, self.READMISSION)
            self.assertEqual({'code': 'PERMISSION_DENIED', 'exitDisposition': 'matched', 'final': True}, result['publicFailure'])
            self.assertNotIn('/secret', json.dumps(result)); self.assertEqual([], state['effects'])

    def test_rooted_principal_probe_is_fixed_read_only_before_public_failure(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); intent, state, config, remote = self.local_fixture(root); state['uid'] = '2000'
            with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), mock.patch.object(admission, '_remote', side_effect=remote):
                admission.cleanup_readmission(root, CORRELATION, self.READMISSION)
            state['uid'] = '0'; calls = []
            def command(argv, **kwargs):
                words = argv[5:] if argv[3:5] == ['shell', '-T'] else []
                if words and ('/system/xbin/su' in words or words[0] == '/system/xbin/su'):
                    calls.append(words)
                    if words == ['stat', '-c', '%u:%g:%a:%d:%i:%F', '/system/xbin/su']: out = b'0:2000:4750:64258:4886:regular file'
                    elif words == ['sha256sum', '/system/xbin/su']: out = ('a' * 64 + '  /system/xbin/su').encode()
                    elif words == ['/system/xbin/su', '--help']: out = b"usage: su [WHO [COMMAND...]]\n\nSwitch to WHO (default 'root') and run the given COMMAND (default sh).\n\nWHO is a comma-separated list of user, group, and supplementary groups\nin that order.\n"
                    elif words == ['/system/xbin/su', '2000,2000', '/system/bin/id', '-u']: out = b'2000'
                    elif words == ['/system/xbin/su', '2000,2000', '/system/bin/content', 'call', '--uri', 'content://com.kardinal.vpncontrol.control', '--method', 'endpoint-read-only-principal-preflight']:
                        return SimpleNamespace(returncode=0, stdout=b'', stderr=b'Error while accessing provider:com.kardinal.vpncontrol.control\njava.lang.IllegalArgumentException: UNSUPPORTED\n\tat android.content.ContentProvider.call(ContentProvider.java:1)\n')
                    else: self.fail('unexpected principal command: ' + repr(words))
                    return SimpleNamespace(returncode=0, stdout=out, stderr=b'')
                if argv[0] == '/bin/cli':
                    return SimpleNamespace(returncode=1, stdout=json.dumps({'schemaVersion': 1, 'ok': False, 'code': 'PERMISSION_DENIED', 'final': True}).encode(), stderr=b'')
                return remote.command(argv, **kwargs)
            def observing(_root, dispatch, action): return self.execute(root, dispatch['remote'], action, command)
            with mock.patch.object(admission.ssh_transport, 'load_config', return_value=config), mock.patch.object(admission, '_remote', side_effect=observing):
                result = admission.cleanup_mount_diagnostic(root, CORRELATION, self.READMISSION)
            self.assertEqual({'grammar': 'aosp-who-command', 'helperIdentity': 'verified', 'shellUid': 'verified', 'providerAccess': 'verified'}, result['principalPreflight'])
            self.assertGreaterEqual(sum(words[-1:] == ['endpoint-read-only-principal-preflight'] for words in calls), 2)
            self.assertEqual([], state['effects']); self.assertEqual('0', state['uid'])

    def test_fixed_root_adapter_preserves_real_joined_content_argv_and_rejects_mutations(self):
        import subprocess
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); log = root / 'log'; su = root / 'su'; adb = root / 'real-adb'; adapter = root / 'adb'
            su.write_text('#!/bin/sh\n[ "$1" = 2000,2000 ] && [ "$2" = /system/bin/content ] || exit 90\nshift 2\n[ "$1" = write ] && cat >/dev/null\nprintf "Result: Bundle[{state=complete}]\\n"\n')
            su.chmod(0o700)
            adb.write_text('#!' + sys.executable + '\nimport json,subprocess,sys\nfrom pathlib import Path\na=sys.argv[1:]; p=sys.stdin.buffer.read()\nwith open('+repr(str(log))+',"a") as f: f.write(json.dumps({"argv":a,"input":p.decode()})+"\\n")\nif a==["devices"]: print("List of devices attached\\nserial-1\\tdevice");sys.exit(0)\nif a[4]=="stat": print("0:2000:4750:64258:4886:regular file");sys.exit(0)\nif a[4]=="sha256sum": print("'+ 'a'*64 + '  /system/xbin/su");sys.exit(0)\na=a[4:]; a[0]='+repr(str(su))+'\nr=subprocess.run(["/bin/sh","-c"," ".join(a)],input=p,check=False);sys.exit(r.returncode)\n')
            adb.chmod(0o700)
            config = {'adb': str(adb), 'serial': 'serial-1', 'owner': 'new-owner', 'revision': 0, 'operation': 'status', 'suIdentity': ['0:2000:4750:64258:4886:regular file', 'a'*64+'  /system/xbin/su']}
            adapter.write_text('#!' + sys.executable + '\nCONFIG=' + repr(json.dumps(config)) + '\n' + admission._ENDPOINT_ADB_ADAPTER); adapter.chmod(0o700)
            prefix = ['-s', 'serial-1', 'shell', '-T', 'content']; identifier = self.READMISSION
            payload = json.dumps({'schemaVersion': 1, 'requestId': CORRELATION, 'controllerId': 'new-owner', 'ifRevision': None,
                'interactive': False, 'asynchronous': False, 'command': {'operation': 'status', 'arguments': {}}}).encode()
            def run(words, data=b''):
                return subprocess.run([str(adapter), *words], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, env={'PATH':os.environ.get('PATH',os.defpath)})
            self.assertEqual(0, run(['devices']).returncode)
            self.assertEqual(0, run(prefix + ['write', '--uri', 'content://com.kardinal.vpncontrol.control/document-uploads/' + identifier + '/0'], payload).returncode)
            seal = identifier + ':' + str(len(payload)) + ':' + hashlib.sha256(payload).hexdigest()
            self.assertEqual(0, run(prefix + ['call', '--uri', 'content://com.kardinal.vpncontrol.control', '--method', 'document-seal', '--arg', seal]).returncode)
            self.assertEqual(0, run(prefix + ['call', '--uri', 'content://com.kardinal.vpncontrol.control', '--method', 'document-submit', '--arg', identifier]).returncode)
            count = len(log.read_text().splitlines())
            for words, data in ((['-s','serial-1','root'],b''), (['-s','foreign','shell','-T','content'],b''),
                    (prefix + ['call','--uri','content://foreign','--method','document-submit','--arg',identifier],b''),
                    (prefix + ['write','--uri','content://com.kardinal.vpncontrol.control/document-uploads/'+CORRELATION+'/0'],payload.replace(b'"status"',b'"off"')),
                    (prefix + ['write','--uri','content://com.kardinal.vpncontrol.control/document-uploads/'+CORRELATION+'/1'],payload),
                    (prefix + ['call','--uri','content://com.kardinal.vpncontrol.control','--method','document-submit','--arg',CORRELATION],b'')):
                self.assertEqual(126, run(words,data).returncode)
            self.assertEqual(count, len(log.read_text().splitlines()))
            records = [json.loads(x) for x in log.read_text().splitlines()]
            forwarded=[x for x in records if x['argv'][4:5]==['/system/xbin/su']]
            self.assertEqual(payload.decode(), forwarded[0]['input'])
            self.assertTrue(all(x['argv'][4:7] == ['/system/xbin/su','2000,2000','/system/bin/content'] for x in forwarded))
            self.assertEqual(3,len(forwarded))
            adb.write_text(adb.read_text().replace('0:2000:4750:64258:4886:regular file','0:0:4750:64258:4886:regular file'))
            self.assertEqual(126,run(prefix + ['call','--uri','content://com.kardinal.vpncontrol.control','--method','document-submit','--arg',identifier]).returncode)
            self.assertEqual(3,sum(json.loads(x)['argv'][4:5]==['/system/xbin/su'] for x in log.read_text().splitlines()))

    def test_rooted_public_reads_require_private_fixed_adapter_environment(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); intent,state,config,remote = self.local_fixture(root); state['uid']='2000'
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config), mock.patch.object(admission,'_remote',side_effect=remote):
                admission.cleanup_readmission(root,CORRELATION,self.READMISSION)
            state['uid']='0'; paths=[]
            def command(argv, **kwargs):
                if argv[0]=='/bin/cli' and state['uid']=='0':
                    directory=Path(kwargs['env']['PATH'].split(os.pathsep)[0]); path=directory/'adb'; paths.append(path)
                    self.assertEqual(0o700, stat.S_IMODE(path.stat().st_mode)); self.assertEqual(0o700,stat.S_IMODE(directory.stat().st_mode))
                    self.assertIn(admission._ENDPOINT_ADB_ADAPTER,path.read_text()); self.assertIn("'operation'",path.read_text())
                return remote.command(argv,**kwargs)
            def observing(_root,dispatch,action): return self.execute(root,dispatch['remote'],action,command)
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config), mock.patch.object(admission,'_remote',side_effect=observing):
                result=admission.cleanup_mount_diagnostic(root,CORRELATION,self.READMISSION)
            self.assertEqual('partial',result['state'],result); self.assertTrue(paths); self.assertTrue(all(not path.exists() for path in paths)); self.assertEqual([],state['effects'])

    def test_finite_public_failure_and_principal_fields_reject_hostile_values(self):
        for value in ({'code':'SECRET','final':True,'exitDisposition':'matched'},
                      {'code':'PERMISSION_DENIED','final':True,'exitDisposition':[]},
                      {'code':'TIMEOUT','final':True,'exitDisposition':'matched'},
                      {'code':'PERMISSION_DENIED','final':True,'exitDisposition':'matched','message':'secret'}):
            self.assertIsNone(admission._bounded_public_failure(value))
        for value in ({'grammar':'aosp-who-command','helperIdentity':'unverified','shellUid':'verified','providerAccess':'verified'},
                      {'grammar':[],'helperIdentity':'verified','shellUid':'verified','providerAccess':'verified'},
                      {'grammar':'unsupported','helperIdentity':'verified','shellUid':'unverified','providerAccess':'verified'}):
            self.assertIsNone(admission._bounded_principal_preflight(value))

    def test_root_principal_capability_drift_fails_before_public_dispatch_or_effects(self):
        for case in ('unsafe-binary','unsupported-help','helper-drift','wrong-uid','provider-denied','stage-drift','namespace-drift'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve(); intent,state,config,remote=self.local_fixture(root); state['uid']='2000'
                with mock.patch.object(admission.ssh_transport,'load_config',return_value=config), mock.patch.object(admission,'_remote',side_effect=remote):
                    admission.cleanup_readmission(root,CORRELATION,self.READMISSION)
                state['uid']='0'; calls=[]; hashes=0
                def command(argv,**kwargs):
                    nonlocal hashes
                    words=argv[5:] if argv[3:5]==['shell','-T'] else []
                    if argv[0]=='/bin/cli': self.fail('unverified capability reached public CLI')
                    if words and '/system/xbin/su' in words:
                        calls.append(words)
                        if case=='unsafe-binary' and words[:1]==['stat']: return SimpleNamespace(returncode=0,stdout=b'2000:777:1:42:regular file',stderr=b'')
                        if words==['sha256sum','/system/xbin/su']:
                            hashes+=1
                            if case=='helper-drift' and hashes>1: return SimpleNamespace(returncode=0,stdout=('b'*64+'  /system/xbin/su').encode(),stderr=b'')
                        if words==['/system/xbin/su','--help']:
                            if case=='unsupported-help': return SimpleNamespace(returncode=0,stdout=b'usage: su -c arbitrary',stderr=b'/secret diagnostic')
                            if case=='stage-drift': state['inode']='0:755:1:99'
                        if words==['/system/xbin/su','2000,2000','/system/bin/id','-u']:
                            if case=='wrong-uid': return SimpleNamespace(returncode=0,stdout=b'0',stderr=b'')
                            if case=='namespace-drift': state['namespace']='mnt:[99]'
                        if case=='provider-denied' and words[-1:]==['endpoint-read-only-principal-preflight']:
                            return SimpleNamespace(returncode=0,stdout=b'',stderr=b'java.lang.SecurityException: PERMISSION_DENIED /secret')
                    return remote.command(argv,**kwargs)
                def observing(_root,dispatch,action): return self.execute(root,dispatch['remote'],action,command)
                with mock.patch.object(admission.ssh_transport,'load_config',return_value=config), mock.patch.object(admission,'_remote',side_effect=observing):
                    result=admission.cleanup_mount_diagnostic(root,CORRELATION,self.READMISSION)
                self.assertEqual('unknown',result['state']); self.assertEqual([],state['effects']); self.assertNotIn('/secret',json.dumps(result))
                if case in {'unsafe-binary','unsupported-help','helper-drift','stage-drift'}:
                    self.assertFalse(any(words[:3]==['/system/xbin/su','2000,2000','/system/bin/id'] for words in calls))
                if case in {'wrong-uid','namespace-drift'}: self.assertFalse(any(words[-1:]==['endpoint-read-only-principal-preflight'] for words in calls))

    def test_fresh_rooted_stage_only_receipt_preserves_unknown_shell_receipt_and_target_mount(self):
        fresh='538c34a8-9f9c-4d0a-b16b-7008c859f44f'
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve(); intent,state,config,remote=self.local_fixture(root); state['uid']='2000'
            original=admission._intent_path(root,CORRELATION).read_bytes()
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config), mock.patch.object(admission,'_remote',side_effect=remote):
                admission.cleanup_readmission(root,CORRELATION,self.READMISSION)
                retained=admission._readmission_path(root,self.READMISSION).read_bytes()
                state['uid']='0'; state['mountinfo']=b'1 0 1:1 / / rw - ext4 /dev/x rw\n2 1 1:1 /unowned/ca /system/etc/security/cacerts rw - ext4 /dev/x rw\n'
                admitted=admission.cleanup_readmission(root,CORRELATION,fresh)
                self.assertEqual('ready',admitted['state'],admitted)
                receipt=admission._readmission_path(root,fresh).read_bytes()
                snapshot=json.loads(receipt)['snapshot']
                self.assertEqual(hashlib.sha256(state['mountinfo'].strip()).hexdigest(),snapshot['unownedTargetMountsSha256'])
                result=admission.cleanup_readmitted(root,CORRELATION,fresh)
            self.assertEqual('cleaned',result['state'],result)
            self.assertEqual([['rm','-r',json.loads(receipt)['snapshot']['mount']['staging']], 'unroot'],state['effects'])
            self.assertEqual(original,admission._intent_path(root,CORRELATION).read_bytes())
            self.assertEqual(retained,admission._readmission_path(root,self.READMISSION).read_bytes())
            self.assertEqual(receipt,admission._readmission_path(root,fresh).read_bytes())
            self.assertIn(b'/unowned/ca',state['mountinfo'])

    def test_stage_only_readmission_rejects_references_overlays_ca_and_unstable_full_mounts(self):
        for case in ('root-reference','root-descendant','mountpoint-reference','mountpoint-descendant','overlay','multiple-targets','target-ca','between-reads'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve(); expected,state,command=self.fixture(root)
                stage='/data/local/tmp/vpn-control-endpoint-'+CORRELATION
                baseline=b'1 0 1:1 / / rw - ext4 /dev/x rw\n2 1 1:1 /unowned/ca /system/etc/security/cacerts rw - ext4 /dev/x rw\n'
                state['mountinfo']=baseline
                if case=='root-reference': state['mountinfo']+=('3 1 1:1 '+stage+' /other rw - ext4 /dev/x rw\n').encode()
                if case=='root-descendant': state['mountinfo']+=('3 1 1:1 '+stage+'/child /other rw - ext4 /dev/x rw\n').encode()
                if case=='mountpoint-reference': state['mountinfo']+=('3 1 1:1 /foreign '+stage+' rw - ext4 /dev/x rw\n').encode()
                if case=='mountpoint-descendant': state['mountinfo']+=('3 1 1:1 /foreign '+stage+'/child rw - ext4 /dev/x rw\n').encode()
                if case=='overlay': state['mountinfo']=baseline.replace(b'- ext4',b'- overlay')
                if case=='multiple-targets': state['mountinfo']+=b'3 1 1:1 /foreign /system/etc/security/cacerts rw - ext4 /dev/x rw\n'
                if case=='target-ca': state['targetCa']=b'present'
                def drift(argv,**kwargs):
                    if case=='between-reads' and state['reads']>=4: state['mountinfo']=baseline.replace(b'/unowned/ca',b'/changed/ca')
                    return command(argv,**kwargs)
                result=self.execute(root,{**expected,'cleanupReadmission':{'correlationId':self.READMISSION,'originalIntentSha256':'f'*64}},'cleanup-readmit',drift)
                self.assertEqual('unknown',result['state'],result); self.assertEqual([],state['effects'])
                self.assertFalse((root/('android-endpoint-'+CORRELATION)/('cleanup-readmission-'+self.READMISSION+'.json')).exists())

    def test_stage_only_full_mount_pin_is_rechecked_before_each_owned_effect(self):
        for phase in ('before-stage','after-stage'):
            for case in ('mount','target-ca','owner','rules','runtime','namespace'):
                with self.subTest(phase=phase,case=case), tempfile.TemporaryDirectory() as raw:
                    root=Path(raw).resolve(); expected,state,command=self.fixture(root)
                    state['mountinfo']=b'1 0 1:1 / / rw - ext4 /dev/x rw\n2 1 1:1 /unowned/ca /system/etc/security/cacerts rw - ext4 /dev/x rw\n'
                    binding={'correlationId':self.READMISSION,'originalIntentSha256':'f'*64}
                    admitted=self.execute(root,{**expected,'cleanupReadmission':binding},'cleanup-readmit',command)
                    self.assertEqual('ready',admitted['state'],admitted)
                    job=root/('android-endpoint-'+CORRELATION); retained=(job/('cleanup-readmission-'+self.READMISSION+'.json')).read_bytes()
                    def change():
                        if case=='mount': state['mountinfo']=state['mountinfo'].replace(b'/unowned/ca',b'/changed/ca')
                        elif case=='target-ca': state['targetCa']=b'present'
                        elif case=='owner': state['owner']='later-owner'
                        elif case=='rules': state['rules']={}
                        elif case=='runtime': state['runtime']=True
                        elif case=='namespace': state['namespace']='mnt:[99]'
                    def drift(argv,**kwargs):
                        if phase=='before-stage' and (job/'checkpoint-cleanup-stage-remove.json').exists(): change()
                        result=command(argv,**kwargs)
                        if phase=='after-stage' and argv[3:6]==['shell','-T','rm']: change()
                        return result
                    result=self.execute(root,{**expected,'owner':'new-owner','cleanupReadmission':{**binding,'receipt':admitted['readmission']}},'cleanup',drift)
                    self.assertEqual('unknown',result['state'],result)
                    self.assertEqual(0 if phase=='before-stage' else 1,len(state['effects'])); self.assertNotIn('unroot',state['effects'])
                    self.assertEqual(retained,(job/('cleanup-readmission-'+self.READMISSION+'.json')).read_bytes()); self.assertTrue((root/'android-native-device-api29.lease').exists())

    def test_rooted_target_absence_requires_exact_missing_stat_not_permission_or_shell_false(self):
        for error in (b'Permission denied', b'nsenter: No such file or directory', b'', b'stat: foreign: No such file or directory'):
            with self.subTest(error=error), tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve(); expected,state,command=self.fixture(root)
                def denied(argv,**kwargs):
                    if argv[5:13]==['nsenter','-t','177','-m','--','/system/bin/stat','-c','%F']:
                        return SimpleNamespace(returncode=1,stdout=b'',stderr=error)
                    return command(argv,**kwargs)
                result=self.execute(root,{**expected,'cleanupReadmission':{'correlationId':self.READMISSION,'originalIntentSha256':'f'*64}},'cleanup-readmit',denied)
                self.assertEqual('readmission_target_ca_unverified',result['reason']); self.assertEqual([],state['effects'])

    def test_rooted_public_prefix_rejects_owner_or_flag_drift_before_principal_reads(self):
        import ast
        definitions = ast.Module(body=[node for node in ast.parse(admission._REMOTE).body
            if isinstance(node, ast.FunctionDef) and node.name in {'public_words', 'command_phase', 'rooted_public_read'}], type_ignores=[])
        for words in (['--controller-id','foreign','status'], ['--controller-id'],
                      ['--controller-id','','status'], ['--controller-id','new-owner\n','status'],
                      ['--other','new-owner','status'], ['--controller-id','new-owner','--other','status']):
            with self.subTest(words=words):
                calls=[]
                def unknown(reason): raise ValueError(reason)
                namespace={'expected':{'cli':'/bin/cli'}, 'api':'29', 'readmission':None, 'remaining':None,
                    'observed_readmission_owner':'new-owner', 'action':'cleanup-readmit', 'unknown':unknown, 'json':json,
                    'job':Path('/inert'), 'private':lambda *_:b'{}', 'validate_mount':lambda _: {},
                    'readmission_principal_preflight':lambda _:calls.append('principal'), 'principal_preflight':{}}
                exec(compile(definitions, '<generated-prefix>', 'exec'), namespace)
                with self.assertRaisesRegex(ValueError, 'readmission_public_invalid'):
                    namespace['rooted_public_read'](['/bin/cli','--json','--android','--serial','serial','--timeout-seconds','30',*words],30,{})
                self.assertEqual([],calls)
        namespace={'expected':{'cli':'/bin/cli'}, 'unknown':unknown}
        exec(compile(definitions, '<generated-prefix>', 'exec'), namespace)
        for words,phase in ((['status'],'public-status'), (['operations','list'],'public-operations'), (['routing','show'],'public-routing')):
            self.assertEqual(phase,namespace['command_phase'](['/bin/cli','--json','--android','--serial','serial','--timeout-seconds','30','--controller-id','new-owner',*words]))

    def test_complete_generated_rooted_snapshot_uses_real_adapter_and_joined_adb(self):
        import subprocess
        runner=subprocess.run
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve(); expected,state,native=self.fixture(root)
            transport=root/'inert-adb'; su=root/'inert-su'; log=root/'transport.log'
            su.write_text('#!/bin/sh\n[ "$1" = 2000,2000 ] && [ "$2" = /system/bin/content ] || exit 90\nshift 2\n[ "$1" = write ] && cat >/dev/null\nprintf "Result: Bundle[{state=complete}]\\n"\n'); su.chmod(0o700)
            transport.write_text('#!'+sys.executable+'\nimport json,subprocess,sys\na=sys.argv[1:];p=sys.stdin.buffer.read()\nwith open('+repr(str(log))+',"a") as f:f.write(json.dumps({"argv":a,"input":p.decode()})+"\\n")\nif a==["devices"]:print("List of devices attached\\nemulator-5554\\tdevice");sys.exit(0)\nif a[4]=="stat":print("0:2000:4750:64258:4886:regular file");sys.exit(0)\nif a[4]=="sha256sum":print("'+'a'*64+'  /system/xbin/su");sys.exit(0)\na=a[4:];a[0]='+repr(str(su))+'\nr=subprocess.run(["/bin/sh","-c"," ".join(a)],input=p,check=False);sys.exit(r.returncode)\n'); transport.chmod(0o700)
            expected['adb']=str(transport)
            job=root/('android-endpoint-'+CORRELATION)
            # Bind the inert transport before the test's immutable original is captured.
            (job/'intent.json').unlink(); admission.android_native_fixture.write_private_plan(job/'intent.json',expected)
            original=(job/'intent.json').read_bytes(); public=[]
            def command(argv,**kwargs):
                if argv[0]!='/bin/cli': return native(argv,**kwargs)
                words=_public_words(argv); owner=argv[8] if argv[7:8]==['--controller-id'] else None
                operation={('status',):'status',('operations','list'):'operations.list',('routing','show'):'routing.show'}[tuple(words)]
                public.append((operation,owner))
                adapter=Path(kwargs['env']['PATH'].split(os.pathsep)[0])/'adb'
                payload=json.dumps({'schemaVersion':1,'requestId':CORRELATION,'controllerId':owner,'ifRevision':None,
                    'interactive':False,'asynchronous':False,'command':{'operation':operation,'arguments':{}}}).encode()
                prefix=['-s','emulator-5554','shell','-T','content']
                seal=self.READMISSION+':'+str(len(payload))+':'+hashlib.sha256(payload).hexdigest()
                for arguments,data in ((['devices'],b''),
                    (prefix+['write','--uri','content://com.kardinal.vpncontrol.control/document-uploads/'+self.READMISSION+'/0'],payload),
                    (prefix+['call','--uri','content://com.kardinal.vpncontrol.control','--method','document-seal','--arg',seal],b''),
                    (prefix+['call','--uri','content://com.kardinal.vpncontrol.control','--method','document-submit','--arg',self.READMISSION],b'')):
                    done=runner([str(adapter),*arguments],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,env={'PATH':os.defpath})
                    self.assertEqual(0,done.returncode,(arguments,done.stderr))
                return native(argv,**kwargs)
            result=self.execute(root,{**expected,'cleanupReadmission':{'correlationId':self.READMISSION,'originalIntentSha256':'f'*64}},'cleanup-readmit',command)
            self.assertEqual('ready',result['state'],result)
            self.assertEqual([('status',None),('operations.list','new-owner'),('routing.show','new-owner'),('status','new-owner'),
                ('status','new-owner'),('operations.list','new-owner'),('routing.show','new-owner'),('status','new-owner')],public)
            uploads=[json.loads(item)['input'] for item in log.read_text().splitlines() if json.loads(item)['argv'][7:8]==['write']]
            self.assertEqual(8,len(uploads)); self.assertEqual([owner for _,owner in public],[json.loads(packet)['controllerId'] for packet in uploads])
            self.assertEqual([],state['effects']); self.assertEqual(original,(job/'intent.json').read_bytes())
            self.assertFalse(list(job.glob('endpoint-read-*')))

    def terminal_fixture(self, root):
        intent,state,config,remote=self.local_fixture(root)
        with mock.patch.object(admission.ssh_transport,'load_config',return_value=config), mock.patch.object(admission,'_remote',side_effect=remote):
            self.assertEqual('ready',admission.cleanup_readmission(root,CORRELATION,self.READMISSION)['state'])
            self.assertEqual('cleaned',admission.cleanup_readmitted(root,CORRELATION,self.READMISSION)['state'])
        effects=list(state['effects'])
        def command(argv,**kwargs):
            words=argv[5:] if argv[3:5]==['shell','-T'] else []
            if words[:2]==['/system/xbin/su','0,0']:
                words=words[2:]
                if words==['/system/bin/id','-u']: return SimpleNamespace(returncode=0,stdout=b'0',stderr=b'')
                if words[:3]==['/system/bin/stat','-c','%F'] and words[3]==intent['remote'].get('staging','/data/local/tmp/vpn-control-endpoint-'+CORRELATION):
                    if state.get('stagePresent'): return SimpleNamespace(returncode=0,stdout=b'directory',stderr=b'')
                    return SimpleNamespace(returncode=1,stdout=b'',stderr=("stat: '"+words[3]+"': No such file or directory").encode())
                words=[words[0].removeprefix('/system/bin/'),*words[1:]]
                if words[:1]==['nsenter'] and words[-1]=='/data/local/tmp/vpn-control-endpoint-'+CORRELATION:
                    if state.get('stagePresent'): return SimpleNamespace(returncode=0,stdout=b'directory',stderr=b'')
                    return SimpleNamespace(returncode=1,stdout=b'',stderr=("stat: '"+words[-1]+"': No such file or directory").encode())
                return remote.command([*argv[:5],*words],**kwargs)
            return remote.command(argv,**kwargs)
        return intent,state,config,command,effects

    def test_receipted_terminal_status_fixes_actual_owner_adjusted_intent_rejection_without_writes(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve(); intent,state,config,command,effects=self.terminal_fixture(root)
            receipt=json.loads(admission._readmission_path(root,self.READMISSION).read_bytes())
            derived={**intent['remote'],'owner':receipt['snapshot']['owner'],'revision':receipt['snapshot']['revision'],
                'cleanupReadmission':{'correlationId':self.READMISSION,'originalIntentSha256':receipt['originalIntentSha256'],'receipt':receipt}}
            rejected=self.execute(root,derived,'status',command)
            self.assertEqual('intent_changed',rejected['reason'])
            before={str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()}
            def remote(_root,dispatch,action): return self.execute(root,dispatch['remote'],action,command)
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config), mock.patch.object(admission,'_remote',side_effect=remote):
                result=admission.cleanup_readmitted_status(root,CORRELATION,self.READMISSION)
            self.assertEqual('cleaned',result['state'],result); self.assertTrue(result['observationOnly'])
            self.assertEqual(before,{str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()})
            self.assertEqual(effects,state['effects']); self.assertEqual('2000',state['uid'])

    def test_receipted_terminal_status_rejects_drift_and_preserves_every_record(self):
        cases=({'owner':'foreign'}, {'revision':1}, {'rules':{}}, {'runtime':True}, {'operations':[{'final':False}]},
               {'namespace':'mnt:[43]'}, {'stagePresent':True}, {'targetCa':b'present'}, {'mountinfo':b'changed'}, {'reverses':b'host tcp:18080 tcp:41001\n'},
               {'case':'remote-lease'}, {'case':'local-lease'}, {'case':'marker'}, {'case':'receipt'}, {'case':'helper'}, {'case':'child'}, {'case':'timeout'})
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve(); intent,state,config,command,effects=self.terminal_fixture(root); state.update(case)
                job=root/('android-endpoint-'+CORRELATION)
                if case.get('case')=='remote-lease': admission.android_native_fixture.write_private_plan(root/'android-native-device-api29.lease',{})
                if case.get('case')=='local-lease': admission.android_native_fixture.write_private_plan(root/'.rag_index/android-native-device-leases/lease-archlinux-api29.json',{})
                if case.get('case')=='marker': (job/'cleaned.json').write_text('{}')
                if case.get('case')=='receipt':
                    path=admission._readmission_path(root,self.READMISSION); receipt=json.loads(path.read_bytes());receipt['originalIntentSha256']='0'*64;path.write_text(json.dumps(receipt))
                if case.get('case')=='child': admission.android_native_fixture.write_private_plan(root/'android-runtime-acceptance-foreign.json',{'parentCorrelationId':CORRELATION})
                before={str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()}
                def checked(argv,**kwargs):
                    if case.get('case')=='helper' and argv[5:]==['stat','-c','%u:%g:%a:%d:%i:%F','/system/xbin/su']:
                        return SimpleNamespace(returncode=0,stdout=b'0:0:4750:64258:4886:regular file',stderr=b'')
                    if case.get('case')=='timeout' and argv[5:7]==['/system/xbin/su','0,0']:
                        import subprocess
                        raise subprocess.TimeoutExpired(argv,10)
                    return command(argv,**kwargs)
                def remote(_root,dispatch,action): return self.execute(root,dispatch['remote'],action,checked)
                with mock.patch.object(admission.ssh_transport,'load_config',return_value=config), mock.patch.object(admission,'_remote',side_effect=remote):
                    result=admission.cleanup_readmitted_status(root,CORRELATION,self.READMISSION)
                self.assertEqual('unknown',result['state'],result); self.assertEqual(effects,state['effects'])
                self.assertEqual(before,{str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()})

    def test_receipted_terminal_status_actual_serial_budget_and_inter_read_drift(self):
        from collections import Counter
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve(); intent,state,config,command,effects=self.terminal_fixture(root); counts=Counter()
            def counted(argv,**kwargs): counts[kwargs['timeout']]+=1;return command(argv,**kwargs)
            def remote(_root,dispatch,action):
                self.assertEqual('cleanup-readmitted-status',action)
                limit=admission._readmission_transport_seconds(action,dispatch['remote'])
                result=self.execute(root,dispatch['remote'],action,counted)
                self.assertEqual(Counter({30:48,10:100,315:2}),counts)
                self.assertGreaterEqual(limit,sum(seconds*calls for seconds,calls in counts.items())+60)
                return result
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config), mock.patch.object(admission,'_remote',side_effect=remote):
                self.assertEqual('cleaned',admission.cleanup_readmitted_status(root,CORRELATION,self.READMISSION)['state'])
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve(); intent,state,config,command,effects=self.terminal_fixture(root); reads=0
            def drift(argv,**kwargs):
                nonlocal reads
                if argv[0]=='/bin/cli':
                    reads+=1
                    if reads==5: state['owner']='foreign'
                return command(argv,**kwargs)
            def remote(_root,dispatch,action): return self.execute(root,dispatch['remote'],action,drift)
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config), mock.patch.object(admission,'_remote',side_effect=remote):
                self.assertEqual('unknown',admission.cleanup_readmitted_status(root,CORRELATION,self.READMISSION)['state'])
            self.assertEqual(effects,state['effects'])

    def test_receipted_terminal_status_missing_records_never_create_journals(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw)
            with mock.patch.object(admission,'_remote') as remote:
                result=admission.cleanup_readmitted_status(root,CORRELATION,self.READMISSION)
            self.assertEqual('unknown',result['state']); remote.assert_not_called()
            self.assertEqual([],list(root.iterdir()))

    def test_receipted_terminal_status_rejects_forged_binding_before_dispatch(self):
        for key,value in (('schema',True), ('originalRevision',False), ('originalIntentSha256','0'*64),
                          ('readmissionCorrelationId',CORRELATION), ('extra','private-untrusted')):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve(); intent,state,config,command,effects=self.terminal_fixture(root)
                path=admission._readmission_path(root,self.READMISSION); receipt=json.loads(path.read_bytes());receipt[key]=value;path.write_text(json.dumps(receipt))
                before={str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()}
                with mock.patch.object(admission.ssh_transport,'load_config',return_value=config), mock.patch.object(admission,'_remote') as remote:
                    result=admission.cleanup_readmitted_status(root,CORRELATION,self.READMISSION)
                self.assertEqual('unknown',result['state']);remote.assert_not_called()
                self.assertEqual(before,{str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()})
                self.assertEqual(effects,state['effects'])
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw)
            with mock.patch.object(admission,'_remote') as remote:
                with self.assertRaises(ValueError): admission.cleanup_readmitted_status(root,CORRELATION,CORRELATION)
            remote.assert_not_called();self.assertEqual([],list(root.iterdir()))

    def test_failed_mount_preserves_original_bounded_command_evidence_before_finite_failure(self):
        import ast
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve(); expected,state,command=self.fixture(root);job=root/('android-endpoint-'+CORRELATION)
            plan=json.loads((job/'mount-intent.json').read_bytes());(job/'mount-failure.json').unlink();response={}
            source=ast.Module(body=[node for node in ast.parse(admission._REMOTE).body if isinstance(node,ast.FunctionDef) and node.name=='mount_exact'],type_ignores=[])
            error=('mount: '+plan['staging']+' on '+plan['target']+': No such file or directory\nprivate-detail').encode()
            def emit(state,reason,**extra): response.update(extra);raise SystemExit()
            namespace={'mount_target_preflight':lambda _:None,'zygote_identity':lambda _:plan['zygote'],'adb':expected['adb'],'serial':expected['serial'],
                'job':job,'base64':__import__('base64'),'hashlib':hashlib,'subprocess':__import__('subprocess'),
                'record':admission.android_native_fixture.write_private_plan,'emit':emit,'unknown':lambda _:self.fail('unexpected unknown')}
            exec(compile(source,'<mount-exact>','exec'),namespace)
            with mock.patch('subprocess.run',return_value=SimpleNamespace(returncode=1,stdout=b'',stderr=error)):
                with self.assertRaises(SystemExit): namespace['mount_exact'](plan)
            evidence=job/'mount-command-evidence.json';self.assertTrue(evidence.is_file())
            trace=json.loads(evidence.read_bytes());self.assertEqual(error,__import__('base64').b64decode(trace['stderr']['base64']))
            self.assertEqual(hashlib.sha256(error).hexdigest(),trace['stderr']['sha256']);self.assertFalse(trace['stderr']['truncated'])
            self.assertEqual(['mount','--bind',plan['staging'],plan['target']],trace['argv'][-4:]);self.assertEqual(0o600,stat.S_IMODE(evidence.stat().st_mode))
            self.assertNotIn('private-detail',json.dumps(response));self.assertEqual('mount-path-pair',response['mountFailure']['errorOrigin'])

    def mount_diagnostic_command(self, state, base):
        def command(argv,**kwargs):
            words=argv[5:] if argv[3:5]==['shell','-T'] else []
            if words[:1]==['/system/bin/sh']:
                if '__VPN_CONTROL_DESCRIPTOR__' in words[-1]:
                    output='/system/etc/security/cacerts (deleted)\n__VPN_CONTROL_DESCRIPTOR__\n1:22:directory\nmnt_id: 1\n'
                elif '/system/bin/awk' in words[-1]:
                    output='1 2 0:1 /private-old-stage /system/etc/security/cacerts rw - ext4 /private-device rw\n'
                else: output='mnt_id: 1\n__VPN_CONTROL_MOUNTINFO__\n1\n'
                return SimpleNamespace(returncode=0,stdout=output.encode(),stderr=b'')
            inner=words[5:] if words[:1]==['/system/bin/nsenter'] else words
            if inner[:1]==['/system/bin/stat']:
                output=b'1:22:0:directory' if '%d:%i:%h:%F' in inner else b'directory:0:755:1:22'
                return SimpleNamespace(returncode=0,stdout=output,stderr=b'')
            if inner==['/system/bin/uname','-r']:
                return SimpleNamespace(returncode=0,stdout=b'4.14.0-test',stderr=b'')
            if inner[:2]==['/system/bin/readlink','-f']:
                path=inner[-1];output='/system/bin/toybox' if path in ('/system/bin/mount','/system/bin/nsenter') else path
                return SimpleNamespace(returncode=0,stdout=output.encode(),stderr=b'')
            if inner==['/system/bin/readlink','/proc/self/ns/mnt']:
                return SimpleNamespace(returncode=0,stdout=state['namespace'].encode(),stderr=b'')
            if inner[:1]==['/system/bin/sha256sum']:
                return SimpleNamespace(returncode=0,stdout=('a'*64+'  '+inner[-1]).encode(),stderr=b'')
            if inner[:1]==['/system/bin/getenforce']:
                return SimpleNamespace(returncode=0,stdout=b'Enforcing',stderr=b'')
            if inner==['/system/bin/cat','/proc/self/attr/current']:
                return SimpleNamespace(returncode=0,stdout=b'u:r:su:s0',stderr=b'')
            if inner[:1]==['/system/bin/cat']:
                return SimpleNamespace(returncode=0,stdout=b'ext4\nproc\n',stderr=b'')
            if inner[:1]==['/system/bin/logcat']:
                return SimpleNamespace(returncode=0,stdout=b'unrelated private log\n',stderr=b'')
            return base(argv,**kwargs)
        return command

    def test_existing_failed_mount_diagnostic_never_retries_mount_or_fabricates_original_stderr(self):
        from collections import Counter
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();intent,state,config,remote=self.local_fixture(root); state['owner']=intent['remote']['owner']; counts=Counter(); calls=[]
            command=self.mount_diagnostic_command(state,remote.command)
            def counted(argv,**kwargs): counts[kwargs['timeout']]+=1; calls.append(argv);return command(argv,**kwargs)
            def observe(_root,dispatch,action): return self.execute(root,dispatch['remote'],action,counted)
            original=admission._intent_path(root,CORRELATION).read_bytes()
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote',side_effect=observe):
                result=admission.mount_failure_diagnostic(root,CORRELATION,self.READMISSION)
            self.assertEqual('partial',result['state'],result);self.assertEqual('unavailable',result['originalCommandEvidence'])
            self.assertEqual('directory',result['mountFailureDiagnostic']['target']['lstat']);self.assertEqual('member',result['mountFailureDiagnostic']['rootMembership'])
            self.assertEqual([],state['effects']);self.assertEqual(original,admission._intent_path(root,CORRELATION).read_bytes())
            self.assertFalse(any('--bind' in argv for argv in calls));self.assertFalse(any(_public_words(argv)==['routing','show'] for argv in calls if argv[0]=='/bin/cli'))
            capture=root/('android-endpoint-'+CORRELATION)/('mount-diagnostic-'+self.READMISSION+'.json')
            self.assertEqual(0o600,stat.S_IMODE(capture.stat().st_mode));self.assertNotIn('unrelated private log',capture.read_text());self.assertFalse((capture.parent/'mount-command-evidence.json').exists())
            self.assertEqual(Counter({30:250,10:82}),counts)
            self.assertGreaterEqual(admission._readmission_transport_seconds('mount-failure-diagnostic',{**intent['remote'],'mountDiagnosticCorrelation':self.READMISSION}),sum(seconds*calls for seconds,calls in counts.items())+60)

    def test_mount_failure_diagnostic_captures_disconnected_target_proof_read_only(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();intent,state,config,remote=self.local_fixture(root);state['owner']=intent['remote']['owner']
            command=self.mount_diagnostic_command(state,remote.command)
            def observe(_root,dispatch,action):return self.execute(root,dispatch['remote'],action,command)
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote',side_effect=observe):
                result=admission.mount_failure_diagnostic(root,CORRELATION,self.READMISSION)
            capture=json.loads((root/('android-endpoint-'+CORRELATION)/('mount-diagnostic-'+self.READMISSION+'.json')).read_bytes())
            labels={item['label'] for item in capture['probes']}
            self.assertTrue({'target-namespace-links','stage-namespace-links','targetDescriptor','targetMountinfo','kernelVersion'}<=labels)
            self.assertEqual([],state['effects']);self.assertEqual('partial',result['state'])
            facts=result['mountFailureDiagnostic']
            self.assertEqual('zero',facts['targetLinkCount']);self.assertEqual('deleted',facts['targetDescriptor'])
            self.assertEqual('exact',facts['targetDescriptorIdentity']);self.assertEqual('one',facts['targetMountCount'])
            self.assertEqual('other',facts['targetMountRoot']);self.assertEqual('readable',facts['kernelVersion'])
            self.assertNotIn('private-old-stage',json.dumps(result));self.assertNotIn('private-device',json.dumps(result))
            for item in capture['probes']:
                if item['label'] in ('targetDescriptor','targetMountinfo'):
                    outer=__import__('shlex').split(item['argv'][-1]);self.assertEqual(1,len(outer))
                    parsed=__import__('shlex').split(outer[0]);self.assertEqual(['/system/bin/nsenter','-t'],parsed[:2])
                    self.assertEqual(['-m','--','/system/bin/sh','-c'],parsed[3:7])
                    if item['label']=='targetMountinfo':
                        inner=__import__('shlex').split(parsed[7]);self.assertEqual('/system/bin/awk',inner[0])
                        self.assertEqual('target=/system/etc/security/cacerts',inner[2])
                        self.assertEqual('$5 == target { if (++n <= 16) print; else exit 1 }',inner[3])
                        self.assertEqual('/proc/self/mountinfo',inner[4])
                        fixture=root/'filtered-mountinfo'
                        foreign='3 2 0:1 /foreign /another-target rw - ext4 /dev/test rw\n'
                        exact='1 2 0:1 /retained /system/etc/security/cacerts rw - ext4 /dev/test rw\n'
                        fixture.write_text(foreign+exact)
                        done=__import__('subprocess').run(['awk',*inner[1:4],str(fixture)],capture_output=True,check=False)
                        self.assertEqual(0,done.returncode);self.assertEqual(exact.encode(),done.stdout)
                        fixture.write_text(exact*17)
                        done=__import__('subprocess').run(['awk',*inner[1:4],str(fixture)],capture_output=True,check=False)
                        self.assertEqual(1,done.returncode);self.assertEqual(exact.encode()*16,done.stdout)

    def test_mount_failure_additional_probe_post_guard_drift_leaves_no_capture(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();intent,state,config,remote=self.local_fixture(root);state['owner']=intent['remote']['owner']
            command=self.mount_diagnostic_command(state,remote.command)
            def observed(argv,**kwargs):
                result=command(argv,**kwargs)
                if argv[-2:]==['/system/bin/uname','-r']:state['owner']='foreign'
                return result
            def observe(_root,dispatch,action):return self.execute(root,dispatch['remote'],action,observed)
            original=admission._intent_path(root,CORRELATION).read_bytes()
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote',side_effect=observe):
                result=admission.mount_failure_diagnostic(root,CORRELATION,self.READMISSION)
            self.assertEqual('unknown',result['state']);self.assertEqual([],state['effects'])
            self.assertEqual(original,admission._intent_path(root,CORRELATION).read_bytes())
            self.assertFalse((root/('android-endpoint-'+CORRELATION)/('mount-diagnostic-'+self.READMISSION+'.json')).exists())

    def test_existing_failed_mount_diagnostic_guard_drift_stops_without_capture_or_effects(self):
        for variant in ({'owner':'foreign'},{'runtime':True},{'operations':[{'final':False}]},{'namespace':'mnt:[99]'},
                        {'inode':'0:755:1:99'},{'package':'e'*64},{'ca':'e'*64}):
            with self.subTest(variant=variant),tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve();intent,state,config,remote=self.local_fixture(root);state['owner']=intent['remote']['owner'];state.update(variant)
                command=self.mount_diagnostic_command(state,remote.command)
                def observe(_root,dispatch,action):return self.execute(root,dispatch['remote'],action,command)
                with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote',side_effect=observe):
                    result=admission.mount_failure_diagnostic(root,CORRELATION,self.READMISSION)
                self.assertEqual('unknown',result['state'],result);self.assertEqual([],state['effects'])
                self.assertFalse((root/('android-endpoint-'+CORRELATION)/('mount-diagnostic-'+self.READMISSION+'.json')).exists())

    def test_mount_failure_diagnostic_keeps_probe_errors_and_only_matching_avc_private(self):
        for case in ('namespace-path','helper','avc'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve();intent,state,config,remote=self.local_fixture(root);state['owner']=intent['remote']['owner']
                command=self.mount_diagnostic_command(state,remote.command)
                def observed(argv,**kwargs):
                    words=argv[5:]
                    if case=='namespace-path' and words[:1]==['/system/bin/nsenter'] and '/system/bin/stat' in words:
                        return SimpleNamespace(returncode=1,stdout=b'',stderr=b'No such file or directory private-path-detail')
                    if case=='helper' and words[:1]==['/system/bin/nsenter'] and '/system/bin/sha256sum' in words:
                        return SimpleNamespace(returncode=1,stdout=b'',stderr=b'private-helper-detail')
                    if case=='avc' and words[:1]==['/system/bin/logcat']:
                        output=('unrelated-private-secret\navc: denied { mounton } comm="mount" name="vpn-control-endpoint-'+CORRELATION+'"\n').encode()
                        return SimpleNamespace(returncode=0,stdout=output,stderr=b'')
                    return command(argv,**kwargs)
                def observe(_root,dispatch,action):return self.execute(root,dispatch['remote'],action,observed)
                with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote',side_effect=observe):
                    result=admission.mount_failure_diagnostic(root,CORRELATION,self.READMISSION)
                self.assertEqual('partial',result['state'],result);self.assertEqual([],state['effects']);self.assertNotIn('private-',json.dumps(result))
                facts=result['mountFailureDiagnostic']
                if case=='namespace-path':self.assertEqual('unavailable',facts['target']['lstat'])
                if case=='helper':self.assertEqual('unavailable',facts['mountHelper']['namespaceIdentity'])
                if case=='avc':self.assertEqual('matching-denial',facts['avc'])
                self.assertEqual('enforcing',facts['selinux']);self.assertEqual('su',facts['domain'])
                capture=json.loads((root/('android-endpoint-'+CORRELATION)/('mount-diagnostic-'+self.READMISSION+'.json')).read_bytes())
                if case=='avc':
                    text=__import__('base64').b64decode(capture['probes'][-1]['stdout']).decode();self.assertIn('avc: denied',text);self.assertNotIn('unrelated-private-secret',text)

    def recovery_fixture(self, root):
        import shlex
        intent,state,config,remote=self.local_fixture(root);intent['remote']['owner']='f6540000-1111-4111-8111-000000000000';state['uid']='0';state['owner']=intent['remote']['owner']
        admission._intent_path(root,CORRELATION).write_text(json.dumps(intent))
        (root/('android-endpoint-'+CORRELATION)/'intent.json').write_text(json.dumps(intent['remote']))
        old_id='d861ec64-e487-4035-afd1-e8dd8400f5c7';new_id='aae27b01-a810-4088-93f2-ff06a036d112'
        old={**intent,'correlationId':old_id,'remote':{**intent['remote'],'owner':'fb632672-ffb5-4d24-a55e-d5d7252e9a74','revision':1}}
        admission.android_native_fixture.write_private_plan(admission._intent_path(root,old_id),old)
        job=root/('android-endpoint-'+CORRELATION);current=json.loads((job/'mount-intent.json').read_bytes());current['stagingIdentity']='0:755:64800:65543';state['inode']=current['stagingIdentity']
        (job/'mount-intent.json').write_text(json.dumps(current));(job/'stage-owned.json').write_text(json.dumps({key:current[key] for key in ('zygote','staging','stagingIdentity')}))
        old_plan={**current,'staging':'/data/local/tmp/vpn-control-endpoint-'+old_id,'stagingIdentity':'0:755:64800:65542'}
        old_job=root/('android-endpoint-'+old_id);old_job.mkdir(mode=0o700)
        for name,value in {'intent.json':old['remote'],'mount-intent.json':old_plan,'stage-owned.json':{key:old_plan[key] for key in ('zygote','staging','stagingIdentity')},'cleanup-intent.json':{'correlationId':old_id,'mount':old_plan},'cleaned.json':{'correlationId':old_id,'caSha256':old['remote']['caSha256']}}.items():
            admission.android_native_fixture.write_private_plan(old_job/name,value)
        base='94 1 253:0 / / ro - ext4 /dev/system ro\n131 94 253:32 / /data rw - ext4 /dev/data rw\n'
        state['mountinfo']=(base+'197 94 253:32 '+old_plan['staging'].removeprefix('/data')+'//deleted '+old_plan['target']+' rw - ext4 /dev/data rw\n').encode()
        state['recovery_unmounted']=False
        def command(argv,**kwargs):
            state.setdefault('timeouts',__import__('collections').Counter())[kwargs['timeout']]+=1
            if state.get('assertRemoteLock'):
                import fcntl
                descriptor=os.open(root/'android-native-device-api29.lock',os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError):fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(descriptor)
            if state.get('postFenceDrift') and (job/('mount-recovery-'+new_id+'.attempt.json')).exists():
                changed=state.pop('postFenceDrift');state.update(changed)
            words=argv[5:] if argv[3:5]==['shell','-T'] else []
            if words==['stat','-c','%u:%g:%a:%d:%i:%F','/system/xbin/su'] and state.get('unsafeSu'):
                return SimpleNamespace(returncode=0,stdout=state['unsafeSu'].encode(),stderr=b'')
            if words==['sha256sum','/system/xbin/su'] and state.get('changedSuHash'):
                state['suHashReads']=state.get('suHashReads',0)+1
                output=('a' if state['suHashReads']==1 else 'f')*64+'  /system/xbin/su'
                return SimpleNamespace(returncode=0,stdout=output.encode(),stderr=b'')
            if words[:1]==['/system/bin/sh']:
                text=words[-1]
                if '__VPN_CONTROL_DESCRIPTOR__' in text:
                    return SimpleNamespace(returncode=0,stdout=(old_plan['target']+' (deleted)\n__VPN_CONTROL_DESCRIPTOR__\n64800:65542:directory\nmnt_id: 197\n').encode(),stderr=b'')
                if 'echo absent' in text:return SimpleNamespace(returncode=0,stdout=b'present' if state.get('historicalStagePresent') else b'absent',stderr=b'')
            if words[:1]==['/system/bin/nsenter']:
                inner=words[5:]
                if inner[:1]==['/system/bin/umount']:
                    state['effects'].append('unmount')
                    if state.get('unmountFailure'):return SimpleNamespace(returncode=1,stdout=b'',stderr=b'private uncertain mount failure')
                    state['mountinfo']=(base+state.get('extraMountinfo','')+state.get('postExtraMountinfo','')).encode();state['recovery_unmounted']=True
                    return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
                if inner[:1]==['/system/bin/stat']:
                    if '%d:%i' in inner:
                        output='64800:65542' if inner[-1]==old_plan['target'] else '64800:65000'
                        return SimpleNamespace(returncode=0,stdout=output.encode(),stderr=b'')
                    if inner[-1]==old_plan['target']:
                        output=state.get('targetIdentity','64258:1142:2:directory' if state['recovery_unmounted'] else '64800:65542:0:directory')
                        return SimpleNamespace(returncode=0,stdout=output.encode(),stderr=b'')
                    return SimpleNamespace(returncode=1,stdout=b'',stderr=('stat: '+inner[-1]+': No such file or directory').encode())
            return remote.command(argv,**kwargs)
        def observe(_root,dispatch,action):return self.execute(root,dispatch['remote'],action,command)
        return intent,state,config,old_id,new_id,observe

    def test_recovery_admission_then_exact_once_unmount_preserves_both_originals_and_lease(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();intent,state,config,old_id,new_id,observe=self.recovery_fixture(root)
            originals=[admission._intent_path(root,x).read_bytes() for x in (CORRELATION,old_id)]
            lease=root/'.rag_index/android-native-device-leases/lease-archlinux-api29.json';lease_bytes=lease.read_bytes()
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote',side_effect=observe):
                result=admission.recovery_readmission(root,CORRELATION,old_id,new_id);self.assertEqual('ready',result['state'],result);self.assertEqual([],state['effects'])
                result=admission.recovery_unmount_once(root,CORRELATION,old_id,new_id);self.assertEqual('partial',result['state'],result);self.assertEqual('recovery_target_restored',result['reason']);self.assertEqual(['unmount'],state['effects'])
                result=admission.recovery_unmount_once(root,CORRELATION,old_id,new_id);self.assertEqual('unknown',result['state']);self.assertEqual(['unmount'],state['effects'])
                result=admission.recovery_status(root,CORRELATION,old_id,new_id);self.assertEqual('partial',result['state'],result)
            self.assertEqual(lease_bytes,lease.read_bytes());self.assertEqual(originals,[admission._intent_path(root,x).read_bytes() for x in (CORRELATION,old_id)])

    def test_recovery_transport_budget_covers_actual_serial_generated_paths(self):
        from collections import Counter
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();intent,state,config,old_id,new_id,observe=self.recovery_fixture(root)
            actions=[(admission.recovery_readmission,'recovery-readmit',Counter({30:508,10:108,315:2})),
                     (admission.recovery_status,'recovery-status',Counter({30:508,10:108,315:2})),
                     (admission.recovery_unmount_once,'recovery-unmount',Counter({30:1222,10:267,315:5})),
                     (admission.recovery_status,'recovery-status',Counter({30:474,10:106,315:2}))]
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote',side_effect=observe):
                for function,action,expected in actions:
                    state['timeouts']=Counter();result=function(root,CORRELATION,old_id,new_id)
                    self.assertIn(result['state'],('ready','partial'),result);self.assertEqual(expected,state['timeouts'])
                    budget=admission._readmission_transport_seconds(action,{**intent['remote'],'cleanupRecovery':{'correlationId':new_id}})
                    self.assertGreaterEqual(budget,sum(seconds*calls for seconds,calls in state['timeouts'].items())+60)

    def test_recovery_near_ceiling_inode_inventory_budget_is_mechanically_covered(self):
        from collections import Counter
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();intent,state,config,old_id,new_id,observe=self.recovery_fixture(root)
            extra=''.join(str(300+i)+' 131 253:32 /unrelated'+str(i)+' /extra'+str(i)+' rw - ext4 /dev/data rw\n' for i in range(126))
            state['extraMountinfo']=extra;state['postExtraMountinfo']='500 131 253:32 /another /post-extra rw - ext4 /dev/data rw\n';state['mountinfo']+=extra.encode()
            actions=[(admission.recovery_readmission,'recovery-readmit',Counter({30:760,10:108,315:2})),
                     (admission.recovery_unmount_once,'recovery-unmount',Counter({30:1854,10:267,315:5})),
                     (admission.recovery_status,'recovery-status',Counter({30:728,10:106,315:2}))]
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote',side_effect=observe):
                for function,action,expected in actions:
                    state['timeouts']=Counter();result=function(root,CORRELATION,old_id,new_id)
                    self.assertIn(result['state'],('ready','partial'),result);self.assertEqual(expected,state['timeouts'])
                    self.assertGreaterEqual(admission._readmission_transport_seconds(action,{'cleanupRecovery':{'correlationId':new_id}}),sum(seconds*calls for seconds,calls in expected.items())+60)

    def test_recovery_unmount_rejects_fresh_drift_and_forged_or_rewritten_protected_proof(self):
        cases=('owner','revision','rules','runtime','operation','namespace','stage','ca','package','mount','historical-rewrite','historical-hardlink','receipt')
        for case in cases:
            with self.subTest(case=case),tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve();intent,state,config,old_id,new_id,observe=self.recovery_fixture(root)
                with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote',side_effect=observe):
                    self.assertEqual('ready',admission.recovery_readmission(root,CORRELATION,old_id,new_id)['state'])
                    if case=='owner':state['owner']='foreign'
                    elif case=='revision':state['revision']=1
                    elif case=='rules':state['rules']={**state['rules'],'ignore_rules':False}
                    elif case=='runtime':state['runtime']=True
                    elif case=='operation':state['operations']=[{'final':False}]
                    elif case=='namespace':state['namespace']='mnt:[99]'
                    elif case=='stage':state['inode']='0:755:64800:99'
                    elif case=='ca':state['ca']='f'*64
                    elif case=='package':state['package']='f'*64
                    elif case=='mount':state['mountinfo']=state['mountinfo'].replace(b'197 94',b'198 94')
                    elif case=='historical-rewrite':
                        path=root/('android-endpoint-'+old_id)/'cleaned.json';before=path.read_bytes();path.write_bytes(before)
                    elif case=='historical-hardlink':
                        path=root/('android-endpoint-'+old_id)/'cleaned.json';os.link(path,root/'foreign-link')
                    elif case=='receipt':
                        path=root/'.rag_index/android-endpoint-admission'/('mount-recovery-'+new_id+'.json');data=json.loads(path.read_bytes());data['snapshot']['native']['targetIdentity']=['64800','99','0','directory'];path.write_text(json.dumps(data))
                    result=admission.recovery_unmount_once(root,CORRELATION,old_id,new_id)
                    self.assertEqual('unknown',result['state'],result);self.assertEqual([],state['effects'])

    def test_uncertain_recovery_preserves_replay_fence_and_status_never_writes_or_retries(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();intent,state,config,old_id,new_id,observe=self.recovery_fixture(root)
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote',side_effect=observe):
                self.assertEqual('ready',admission.recovery_readmission(root,CORRELATION,old_id,new_id)['state']);state['unmountFailure']=True
                result=admission.recovery_unmount_once(root,CORRELATION,old_id,new_id);self.assertEqual('unknown',result['state']);self.assertEqual(['unmount'],state['effects'])
                before={str(path.relative_to(root)):(path.read_bytes(),path.stat().st_mtime_ns) for path in root.rglob('*.json')}
                self.assertEqual('unknown',admission.recovery_status(root,CORRELATION,old_id,new_id)['state'])
                self.assertEqual(before,{str(path.relative_to(root)):(path.read_bytes(),path.stat().st_mtime_ns) for path in root.rglob('*.json')})
                self.assertEqual('unknown',admission.recovery_unmount_once(root,CORRELATION,old_id,new_id)['state']);self.assertEqual(['unmount'],state['effects'])

    def test_recovery_readmission_rejects_foreign_target_source_and_unsafe_principal_without_receipt(self):
        cases=('linked-target','old-stage-present','different-root','source-device','source-root','second-target','current-stage-bind','unsafe-su-mode','unsafe-su-group','su-hash-change','runtime-child','inode-cap')
        for case in cases:
            with self.subTest(case=case),tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve();intent,state,config,old_id,new_id,observe=self.recovery_fixture(root)
                if case=='linked-target':state['targetIdentity']='64800:65542:2:directory'
                elif case=='old-stage-present':state['historicalStagePresent']=True
                elif case=='different-root':state['mountinfo']=state['mountinfo'].replace(old_id.encode(),b'foreign-stage')
                elif case=='source-device':state['mountinfo']=state['mountinfo'].replace(b'131 94 253:32',b'131 94 253:33')
                elif case=='source-root':state['mountinfo']=state['mountinfo'].replace(b'253:32 / /data',b'253:32 /other /data')
                elif case=='second-target':state['mountinfo']+=b'198 94 253:32 /foreign /system/etc/security/cacerts rw - ext4 /dev/data rw\n'
                elif case=='current-stage-bind':state['mountinfo']+=('198 94 253:32 /local/tmp/vpn-control-endpoint-'+CORRELATION+' /foreign rw - ext4 /dev/data rw\n').encode()
                elif case=='unsafe-su-mode':state['unsafeSu']='0:2000:4777:64258:4886:regular file'
                elif case=='unsafe-su-group':state['unsafeSu']='0:0:4750:64258:4886:regular file'
                elif case=='su-hash-change':state['changedSuHash']=True
                elif case=='runtime-child':admission.android_native_fixture.write_private_plan(root/'android-runtime-acceptance-foreign.json',{'parentCorrelationId':old_id})
                elif case=='inode-cap':state['mountinfo']+=''.join(str(300+i)+' 131 253:32 /unrelated'+str(i)+' /extra'+str(i)+' rw - ext4 /dev/data rw\n' for i in range(127)).encode()
                with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote',side_effect=observe):
                    result=admission.recovery_readmission(root,CORRELATION,old_id,new_id)
                self.assertEqual('unknown',result['state'],result);self.assertEqual([],state['effects'])
                self.assertFalse((root/'.rag_index/android-endpoint-admission'/('mount-recovery-'+new_id+'.json')).exists())

    def test_recovery_local_same_byte_rewrite_and_distinct_correlation_validation(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();intent,state,config,old_id,new_id,observe=self.recovery_fixture(root)
            def rewritten(*args):
                value=observe(*args);path=admission._intent_path(root,old_id);before=path.read_bytes();path.write_bytes(before);return value
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote',side_effect=rewritten):
                self.assertEqual('unknown',admission.recovery_readmission(root,CORRELATION,old_id,new_id)['state'])
            self.assertEqual([],state['effects'])
            before={str(path.relative_to(root)):path.read_bytes() for path in root.rglob('*.json')}
            with mock.patch.object(admission,'_remote') as dispatch:
                for function in (admission.recovery_readmission,admission.recovery_unmount_once,admission.recovery_status):
                    with self.assertRaises(ValueError):function(root,CORRELATION,old_id,CORRELATION)
                dispatch.assert_not_called()
            self.assertEqual(before,{str(path.relative_to(root)):path.read_bytes() for path in root.rglob('*.json')})

    def test_recovery_last_guard_after_replay_fence_blocks_drift_before_unmount(self):
        for changed in ({'owner':'foreign'},{'runtime':True},{'rules':{'ignore_rules':False,'block_quic_udp_443':False,'proxy_packages':[],'direct_domain_suffixes':[]}},
                        {'namespace':'mnt:[99]'},{'inode':'0:755:64800:99'}):
            with self.subTest(changed=changed),tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve();intent,state,config,old_id,new_id,observe=self.recovery_fixture(root)
                with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote',side_effect=observe):
                    self.assertEqual('ready',admission.recovery_readmission(root,CORRELATION,old_id,new_id)['state']);state['postFenceDrift']=changed
                    self.assertEqual('unknown',admission.recovery_unmount_once(root,CORRELATION,old_id,new_id)['state'])
                    self.assertEqual([],state['effects'])
                    self.assertTrue((root/('android-endpoint-'+CORRELATION)/('mount-recovery-'+new_id+'.attempt.json')).exists())
                    self.assertEqual('unknown',admission.recovery_unmount_once(root,CORRELATION,old_id,new_id)['state']);self.assertEqual([],state['effects'])

    def test_recovery_local_device_lock_blocks_dispatch_until_competing_action_releases(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();intent,state,config,old_id,new_id,observe=self.recovery_fixture(root)
            entered=threading.Event();finished=threading.Event();results=[]
            def dispatch(*args):entered.set();return observe(*args)
            def invoke():
                try:results.append(admission.recovery_readmission(root,CORRELATION,old_id,new_id))
                finally:finished.set()
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote',side_effect=dispatch):
                with admission._shared_device_lease(root,'archlinux','api29'):
                    worker=threading.Thread(target=invoke);worker.start()
                    blocked=not entered.wait(0.1);alive=worker.is_alive()
                worker.join(2)
            self.assertTrue(blocked,'recovery dispatched while competing device action held local lock');self.assertTrue(alive)
            self.assertTrue(finished.is_set());self.assertEqual('ready',results[0]['state']);self.assertEqual([],state['effects'])

    def test_recovery_remote_device_lock_blocks_proof_and_fence_until_competing_action_releases(self):
        import fcntl
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();intent,state,config,old_id,new_id,observe=self.recovery_fixture(root)
            binding={'correlationId':new_id,'historicalCorrelationId':old_id,'originalIntentSha256':admission._private_snapshot(admission._intent_path(root,CORRELATION))[1],
                     'historicalIntentSha256':admission._private_snapshot(admission._intent_path(root,old_id))[1],'historicalExpected':json.loads(admission._intent_path(root,old_id).read_bytes())['remote']}
            entered=threading.Event();results=[];original_execute=self.execute
            def execute(root,expected,action,command):
                def seen(*args,**kwargs):entered.set();return command(*args,**kwargs)
                return original_execute(root,expected,action,seen)
            self.execute=execute
            descriptor=os.open(root/'android-native-device-api29.lock',os.O_RDWR|os.O_CREAT,0o600);fcntl.flock(descriptor,fcntl.LOCK_EX)
            try:
                worker=threading.Thread(target=lambda:results.append(observe(root,{**intent,'remote':{**intent['remote'],'cleanupRecovery':binding}},'recovery-readmit')));worker.start()
                blocked=not entered.wait(0.1);alive=worker.is_alive()
            finally:fcntl.flock(descriptor,fcntl.LOCK_UN);os.close(descriptor)
            worker.join(2);self.execute=original_execute
            self.assertTrue(blocked,'recovery proof ran while competing host action held remote device lock');self.assertTrue(alive)
            self.assertFalse(worker.is_alive());self.assertEqual('ready',results[0]['state']);self.assertEqual([],state['effects'])

    def test_recovery_locks_cover_every_probe_effect_and_postproof_and_release_on_exit(self):
        import fcntl
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();intent,state,config,old_id,new_id,observe=self.recovery_fixture(root);state['assertRemoteLock']=True
            local=root/'.rag_index/android-native-device-leases/lock-archlinux-api29.json';remote=root/'android-native-device-api29.lock'
            def dispatch(*args):
                descriptor=os.open(local,os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError):fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(descriptor)
                return observe(*args)
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote',side_effect=dispatch):
                for function in (admission.recovery_readmission,admission.recovery_status,admission.recovery_unmount_once,admission.recovery_status):
                    result=function(root,CORRELATION,old_id,new_id);self.assertIn(result['state'],('ready','partial'),result)
                    for path in (local,remote):
                        descriptor=os.open(path,os.O_RDWR)
                        try:fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
                        finally:os.close(descriptor)
            self.assertEqual(['unmount'],state['effects'])

    def test_recovery_status_without_coordinator_lock_creates_no_records(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();intent,state,config,old_id,new_id,observe=self.recovery_fixture(root)
            before={str(path.relative_to(root)):path.read_bytes() for path in root.rglob('*.json')}
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote') as dispatch:
                self.assertEqual('unknown',admission.recovery_status(root,CORRELATION,old_id,new_id)['state']);dispatch.assert_not_called()
            self.assertEqual(before,{str(path.relative_to(root)):path.read_bytes() for path in root.rglob('*.json')})

    def endpoint_nested_transport_fixture(self, root):
        from pathlib import PurePosixPath
        ssh=admission.ssh_transport
        return ssh.SshConfig(root,{'gateway':ssh.SshHost('gateway','gateway.invalid',22,'fixture',root/'key',root/'known'),
            'archlinux':ssh.SshHost('archlinux','unused',22,'fixture',root/'key',root/'known',transport='nested',gateway='gateway',
                                   remote_host_alias='archlinux',fixture_transfer_root=PurePosixPath(str(root)))})

    def test_actual_generated_endpoint_nested_ssh_argv_fits_per_argument_limit(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();intent,state,config,old_id,new_id,observe=self.recovery_fixture(root)
            nested=self.endpoint_nested_transport_fixture(root)
            old=json.loads(admission._intent_path(root,old_id).read_bytes())
            binding={'correlationId':new_id,'historicalCorrelationId':old_id,'originalIntentSha256':'a'*64,'historicalIntentSha256':'b'*64,'historicalExpected':old['remote']}
            def inert(argv,payload,timeout):
                largest=max(len(part.encode()) for part in argv)
                self.assertLess(largest,65536,'actual generated nested SSH argument exceeds safe per-argument bound')
                return 0,json.dumps({'state':'unknown','reason':'inert-test','correlationId':CORRELATION}).encode()
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=nested),mock.patch.object(admission.ssh_transfer,'_bounded_run',side_effect=inert) as runner:
                admission._remote(root,{**intent,'remote':{**intent['remote'],'cleanupRecovery':binding}},'recovery-readmit')
                runner.assert_called_once()
            self.assertEqual([],state['effects'])

    def test_endpoint_compressed_source_executes_exact_bytes_and_preserves_stdin_and_arguments(self):
        source = ''.join('# ' + line + '\n' for line in admission._REMOTE.splitlines()) + (
            "import sys,json,hashlib\nprint(json.dumps({'argv':sys.argv[1:],'stdin':hashlib.sha256(sys.stdin.buffer.read()).hexdigest()}))\n")
        command = admission._endpoint_python_command(source, 'recovery-readmit', 'quoted space; $inert')
        result = subprocess.run([sys.executable, *command[1:]], input=CA, capture_output=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual({'argv':['recovery-readmit','quoted space; $inert'], 'stdin':hashlib.sha256(CA).hexdigest()}, json.loads(result.stdout))
        self.assertLess(max(len(part.encode()) for part in command), 65536)
        with tempfile.TemporaryDirectory() as raw:
            config=self.endpoint_nested_transport_fixture(Path(raw))
            nested=admission.ssh_transport.build_ssh_argv(config,'archlinux',60,command=command)
            inner=shlex.split(nested[-1]);destination=shlex.split(inner[-1])
            self.assertEqual(list(command),destination)
            result=subprocess.run([sys.executable,*destination[1:]],input=CA,capture_output=True,timeout=10)
            self.assertEqual(0,result.returncode,result.stderr)
            self.assertEqual(hashlib.sha256(CA).hexdigest(),json.loads(result.stdout)['stdin'])

    def test_endpoint_compressed_source_rejects_integrity_and_bounds_before_execution(self):
        import base64
        import zlib
        source = "print('must-not-execute')\n"
        command = admission._endpoint_python_command(source)
        wrapper = command[2]
        encoded = base64.b64encode(zlib.compress(source.encode(), 9)).decode()
        bad = [wrapper.replace(hashlib.sha256(source.encode()).hexdigest(), '0'*64),
               wrapper.replace('len(s)!='+str(len(source)), 'len(s)!='+str(len(source)+1)),
               wrapper.replace(encoded, base64.b64encode(zlib.compress(source.encode(),9)+b'trailing').decode()),
               wrapper.replace(encoded, base64.b64encode(zlib.compress((source*100).encode(),9)).decode())]
        for program in bad:
            with self.subTest(program=hashlib.sha256(program.encode()).hexdigest()):
                result=subprocess.run([sys.executable,'-c',program],capture_output=True,timeout=10)
                self.assertNotEqual(0,result.returncode);self.assertEqual(b'',result.stdout)
        for program,arguments in [('',()),('a'*262145,()),(source,('a'*65536,))]:
            with self.assertRaises(ValueError):admission._endpoint_python_command(program,*arguments)

    def test_endpoint_transport_diagnostics_are_finite_and_do_not_infer_remote_argument_size(self):
        import errno
        wrapped=admission.ssh_transfer.SshTransferError('ssh_unavailable')
        wrapped.__cause__=OSError(errno.E2BIG,'private-path-secret')
        cases=[((1,b''),None,('remote-result','nonzero','empty',1)),
               (None,wrapped,('local-spawn','argument-limit','unavailable',None)),
               (None,admission.ssh_transfer.SshTransferError('timeout'),('runner','timeout','unavailable',None)),
               ((0,b'not-json-private-secret'),None,('remote-result','invalid-result','not-json',0)),
               ((0,b'{}'),None,('remote-result','invalid-result','invalid-json',0))]
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();intent,state,config,old_id,new_id,observe=self.recovery_fixture(root)
            config=self.endpoint_nested_transport_fixture(root)
            for result,error,expected in cases:
                with self.subTest(expected=expected),mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission.ssh_transfer,'_bounded_run',return_value=result,side_effect=error):
                    value=admission._remote(root,intent,'recovery-status')
                    diagnostic=dict(zip(('phase','outcome','stdout','exit'),expected))
                    self.assertEqual(diagnostic,value['transportDiagnostic'])
                    self.assertEqual(diagnostic,admission._bound_result(intent,value,'status')['transportDiagnostic'])
                    self.assertNotIn('private',json.dumps(value));self.assertEqual([],state['effects'])
        self.assertEqual({},admission._bounded_endpoint_transport({**diagnostic,'raw':'private'}))
        self.assertEqual({},admission._bounded_endpoint_transport({**diagnostic,'exit':True}))

    def test_recovery_generated_full_receipt_fits_unchanged_transport_and_private_limits(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();intent,state,config,old_id,new_id,observe=self.recovery_fixture(root)
            responses=[]
            def dispatch(*args):
                value=observe(*args);responses.append(value);return value
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote',side_effect=dispatch):
                value=admission.recovery_readmission(root,CORRELATION,old_id,new_id)
            self.assertEqual('ready',value['state'],value)
            body=json.dumps(responses[0],sort_keys=True,separators=(',',':')).encode()
            self.assertLessEqual(len(body)+1,admission.ssh_transfer.MAX_OUTPUT_BYTES)
            receipt=root/('android-endpoint-'+CORRELATION)/('mount-recovery-'+new_id+'.json')
            self.assertLessEqual(receipt.stat().st_size,8192)
            self.assertEqual([],state['effects'])

    def test_recovery_transport_failure_retains_request_and_projects_only_finite_diagnostic(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();intent,state,config,old_id,new_id,observe=self.recovery_fixture(root)
            originals=[admission._intent_path(root,x).read_bytes() for x in (CORRELATION,old_id)]
            diagnostic={'phase':'remote-result','outcome':'nonzero','stdout':'empty','exit':1}
            def failure(_root,dispatch,action):
                return {'state':'unknown','reason':'transport_or_receipt_unknown','correlationId':CORRELATION,
                        'transportDiagnostic':diagnostic,'rawStderr':'private-secret'}
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config),mock.patch.object(admission,'_remote',side_effect=failure) as remote:
                result=admission.recovery_readmission(root,CORRELATION,old_id,new_id)
                self.assertEqual('unknown',result['state']);self.assertEqual(diagnostic,result['transportDiagnostic'])
                self.assertNotIn('private-secret',json.dumps(result));remote.assert_called_once()
                request=root/'.rag_index/android-endpoint-admission'/('mount-recovery-'+new_id+'.request.json')
                retained=request.read_bytes()
                result=admission.recovery_readmission(root,CORRELATION,old_id,new_id)
                self.assertEqual('unknown',result['state']);remote.assert_called_once()
                self.assertEqual(retained,request.read_bytes())
            self.assertFalse((request.parent/('mount-recovery-'+new_id+'.json')).exists())
            self.assertEqual([],state['effects']);self.assertEqual(originals,[admission._intent_path(root,x).read_bytes() for x in (CORRELATION,old_id)])

    def mount_collect_fixture(self, root):
        import base64
        intent,state,config,remote=self.local_fixture(root)
        config.hosts['archlinux'].fixture_transfer_root=root
        job=root/('android-endpoint-'+CORRELATION); raw=(job/'intent.json').read_bytes(); probes=[]
        for i in range(20):
            content=(b'private-native-mount-evidence-'+bytes([65+i]))*100
            probes.append({'label':'probe-'+str(i),'argv':['/system/bin/stat','-c','%F', '/system/etc/security/cacerts'],
                'returncode':0,'stdout':base64.b64encode(content).decode(),'stderr':'',
                'stdoutSha256':hashlib.sha256(content).hexdigest(),'stderrSha256':hashlib.sha256(b'').hexdigest(),'truncated':False})
        capture={'schema':1,'endpointCorrelationId':CORRELATION,'diagnosticCorrelationId':self.READMISSION,
            'originalIntentSha256':hashlib.sha256(raw).hexdigest(),'originalCommandEvidence':'unavailable','probes':probes}
        path=job/('mount-diagnostic-'+self.READMISSION+'.json');admission.android_native_fixture.write_private_plan(path,capture)
        def fetch(argv,timeout):
            output=io.StringIO()
            with mock.patch('sys.argv',['fetch',*argv[-5:]]),contextlib.redirect_stdout(output):exec(admission._MOUNT_DIAGNOSTIC_FETCH,{})
            data=output.getvalue().encode()
            if len(data)>admission.android_observation.MAX_OUTPUT_BYTES:raise RuntimeError('oversized_output')
            return 0,data
        return intent,config,path,fetch

    def test_mount_diagnostic_collect_large_native_capture_under_unchanged_transport_cap(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();intent,config,path,fetch=self.mount_collect_fixture(root);original=path.read_bytes();requests=[]
            self.assertGreater(len(original),16384);self.assertEqual(16384,admission.android_observation.MAX_OUTPUT_BYTES)
            def transport(argv,timeout):requests.append(json.loads(argv[-1]));return fetch(argv,timeout)
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config), \
                 mock.patch.object(admission.ssh_transport,'connection_host',return_value=SimpleNamespace(password=None)), \
                 mock.patch.object(admission.ssh_transport,'build_ssh_argv',side_effect=lambda *args,**kwargs:list(kwargs['command'])), \
                 mock.patch.object(admission.android_observation,'_run_probe',side_effect=transport):
                result=admission.mount_diagnostic_collect(root,CORRELATION,self.READMISSION)
            self.assertEqual('complete',result['state'],result);artifact=Path(result['localPath'])
            self.assertEqual(original,artifact.read_bytes());self.assertEqual(0o600,stat.S_IMODE(artifact.stat().st_mode))
            self.assertGreater(sum(item['mode']=='chunk' for item in requests),2);self.assertEqual(original,path.read_bytes())
            self.assertNotIn('private-native',json.dumps(result));self.assertEqual(16384,admission.android_observation.MAX_OUTPUT_BYTES)

    def test_mount_diagnostic_collect_rejects_drift_partial_or_malformed_chunks_without_completion(self):
        for case in ('same-inode','original-same-byte','intent-replaced','retained-plan','partial','wrong-offset','local-intent','final-census'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve();intent,config,path,fetch=self.mount_collect_fixture(root);metadata_reads=0;changed=False
                def transport(argv,timeout):
                    nonlocal metadata_reads,changed
                    request=json.loads(argv[-1])
                    if request['mode']=='metadata':metadata_reads+=1
                    if not changed and (request['mode']=='chunk' and request['offset']==8192 or case=='final-census' and metadata_reads==2):
                        changed=True
                        if case=='same-inode' or case=='final-census':
                            content=path.read_bytes();path.write_bytes(content.replace(b'probe-0',b'probe-X',1))
                        if case=='original-same-byte':
                            original=path.parent/'intent.json';retained=original.read_bytes();original.write_bytes(retained)
                            self.assertEqual(hashlib.sha256(retained).hexdigest(),hashlib.sha256(original.read_bytes()).hexdigest())
                        if case=='intent-replaced':
                            original=path.parent/'intent.json';temporary=path.parent/'new-intent.json';temporary.write_bytes(original.read_bytes());temporary.chmod(0o600);temporary.replace(original)
                        if case=='retained-plan':
                            plan=path.parent/'mount-intent.json';value=json.loads(plan.read_bytes());value['stagingIdentity']='0:755:1:23';plan.write_text(json.dumps(value))
                        if case=='partial':return 0,b'{"state":"unknown"}'
                        if case=='local-intent':
                            local=admission._intent_path(root,CORRELATION);value=json.loads(local.read_bytes());value['sourceSha']='0'*40;local.write_text(json.dumps(value))
                    code,output=fetch(argv,timeout)
                    if case=='wrong-offset' and request['mode']=='chunk' and request['offset']==8192:
                        value=json.loads(output);value['offset']=0;output=json.dumps(value).encode()
                    return code,output
                with mock.patch.object(admission.ssh_transport,'load_config',return_value=config), \
                     mock.patch.object(admission.ssh_transport,'connection_host',return_value=SimpleNamespace(password=None)), \
                     mock.patch.object(admission.ssh_transport,'build_ssh_argv',side_effect=lambda *args,**kwargs:list(kwargs['command'])), \
                     mock.patch.object(admission.android_observation,'_run_probe',side_effect=transport):
                    result=admission.mount_diagnostic_collect(root,CORRELATION,self.READMISSION)
                self.assertEqual('unknown',result['state'],result)
                directory=admission._intent_path(root,CORRELATION).parent/('mount-diagnostic-'+CORRELATION+'-'+self.READMISSION)
                self.assertFalse((directory/'collected.json').exists());self.assertTrue((directory/'mount-diagnostic.json').exists())
                self.assertEqual(0o600,stat.S_IMODE((directory/'mount-diagnostic.json').stat().st_mode))
                if case=='partial':self.assertEqual(8192,(directory/'mount-diagnostic.json').stat().st_size)

    def test_mount_diagnostic_collect_rejects_unsafe_or_unbound_source_and_never_overwrites(self):
        for case in ('unsafe-mode','hardlink','wrong-binding','existing'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve();intent,config,path,fetch=self.mount_collect_fixture(root)
                directory=admission._intent_path(root,CORRELATION).parent/('mount-diagnostic-'+CORRELATION+'-'+self.READMISSION)
                if case=='unsafe-mode':path.chmod(0o644)
                if case=='hardlink':os.link(path,path.parent/'linked.json')
                if case=='wrong-binding':
                    value=json.loads(path.read_bytes());value['originalIntentSha256']='0'*64;path.write_text(json.dumps(value))
                if case=='existing':
                    directory.mkdir(mode=0o700);(directory/'mount-diagnostic.json').write_bytes(b'preserved partial evidence');(directory/'mount-diagnostic.json').chmod(0o600)
                before={str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()}
                with mock.patch.object(admission.ssh_transport,'load_config',return_value=config), \
                     mock.patch.object(admission.ssh_transport,'connection_host',return_value=SimpleNamespace(password=None)), \
                     mock.patch.object(admission.ssh_transport,'build_ssh_argv',side_effect=lambda *args,**kwargs:list(kwargs['command'])), \
                     mock.patch.object(admission.android_observation,'_run_probe',side_effect=fetch):
                    result=admission.mount_diagnostic_collect(root,CORRELATION,self.READMISSION)
                self.assertEqual('unknown',result['state'],result);self.assertEqual(before,{str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()})
                self.assertFalse((directory/'collected.json').exists())
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw)
            with mock.patch.object(admission.android_observation,'_run_probe') as remote:
                result=admission.mount_diagnostic_collect(root,CORRELATION,self.READMISSION)
                self.assertEqual('unknown',result['state']);remote.assert_not_called();self.assertEqual([],list(root.iterdir()))
                with self.assertRaises(ValueError):admission.mount_diagnostic_collect(root,CORRELATION,CORRELATION)

    def test_rooted_new_owner_discovery_uses_only_fixed_read_adapter_then_pins_receipt(self):
        import ast
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve(); intent,state,config,remote=self.local_fixture(root); seen=[]
            def command(argv,**kwargs):
                if argv[0]=='/bin/cli':
                    environment=kwargs.get('env') or {}; directory=Path(environment.get('PATH','').split(os.pathsep)[0]); adapter=directory/'adb'
                    if not adapter.is_file():
                        return SimpleNamespace(returncode=1,stdout=json.dumps({'schemaVersion':1,'ok':False,'code':'PERMISSION_DENIED','final':True}).encode(),stderr=b'')
                    bootstrap=adapter.read_text().splitlines()[1].removeprefix('CONFIG=')
                    settings=json.loads(ast.literal_eval(bootstrap)); seen.append(settings)
                    self.assertEqual(None if not seen[:-1] else 'new-owner',settings['owner']); self.assertIsNone(settings['revision'])
                    self.assertIn(settings['operation'],{'status','operations.list','routing.show'})
                return remote.command(argv,**kwargs)
            def observing(_root,dispatch,action): return self.execute(root,dispatch['remote'],action,command)
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config), mock.patch.object(admission,'_remote',side_effect=observing):
                result=admission.cleanup_readmission(root,CORRELATION,self.READMISSION)
            self.assertEqual('ready',result['state'],result); self.assertEqual('new-owner',result['owner']); self.assertEqual(8,len(seen)); self.assertEqual([],state['effects'])

    def test_rooted_stage_only_readmission_requires_one_target_entry_before_receipt_or_effects(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve(); expected,state,command=self.fixture(root)
            state['mountinfo']=b'1 0 1:1 / / rw - ext4 /dev/x rw\n'
            result=self.execute(root,{**expected,'cleanupReadmission':{'correlationId':self.READMISSION,'originalIntentSha256':'f'*64}},'cleanup-readmit',command)
            self.assertEqual('unknown',result['state'],result); self.assertEqual([],state['effects'])
            self.assertFalse((root/('android-endpoint-'+CORRELATION)/('cleanup-readmission-'+self.READMISSION+'.json')).exists())

    def test_large_routing_readmission_budget_survives_measured_169_second_read(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve(); expected,state,command=self.fixture(root); routing=[]; other=[]
            def delayed(argv,**kwargs):
                if argv[0]=='/bin/cli':
                    if _public_words(argv)==['routing','show']:
                        routing.append((argv[6],kwargs['timeout']))
                        if int(argv[6])<300 or kwargs['timeout']<315: raise subprocess.TimeoutExpired(argv,169)
                    else: other.append((argv[6],kwargs['timeout']))
                return command(argv,**kwargs)
            result=self.execute(root,{**expected,'cleanupReadmission':{'correlationId':self.READMISSION,'originalIntentSha256':'f'*64}},'cleanup-readmit',delayed)
            self.assertEqual('ready',result['state'],result); self.assertEqual([('300',315)]*2,routing)
            self.assertTrue(all(budget==('30',30) for budget in other)); self.assertEqual([],state['effects'])

    def test_readmission_outer_transport_budget_covers_both_large_snapshots(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve(); config=SimpleNamespace(hosts={'archlinux':SimpleNamespace(fixture_transfer_root=root)})
            intent={'host':'archlinux','remoteRoot':str(root),'device':'api29','correlationId':CORRELATION,'remote':{'cleanupReadmission':{'correlationId':self.READMISSION,'originalIntentSha256':'f'*64}}}
            response={'correlationId':CORRELATION,'state':'ready'}
            def bounded(_argv,_payload,timeout):
                return (0,json.dumps(response).encode()) if timeout>=2*(315+120) else (124,b'')
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config), mock.patch.object(admission.ssh_transport,'connection_host',return_value=SimpleNamespace(password=None)), \
                    mock.patch.object(admission.ssh_transport,'build_ssh_argv',return_value=['inert-ssh']) as build, mock.patch.object(admission.ssh_transfer,'_bounded_run',side_effect=bounded):
                result=admission._remote(root,intent,'cleanup-readmit')
            self.assertEqual('ready',result['state'],result); self.assertEqual(60,build.call_args.args[2])

    def test_readmitted_cleanup_routing_budget_and_post_retirement_timeout_keep_lease(self):
        for fail_after_retirement in (False,True):
            with self.subTest(fail_after_retirement=fail_after_retirement), tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve(); expected,state,command=self.fixture(root); budgets=[]
                binding={'correlationId':self.READMISSION,'originalIntentSha256':'f'*64}
                admitted=self.execute(root,{**expected,'cleanupReadmission':binding},'cleanup-readmit',command)
                job=root/('android-endpoint-'+CORRELATION); receipt=(job/('cleanup-readmission-'+self.READMISSION+'.json')).read_bytes()
                def slow(argv,**kwargs):
                    if argv[0]=='/bin/cli' and _public_words(argv)==['routing','show']:
                        budgets.append((argv[6],kwargs['timeout']))
                        if kwargs['timeout']<169 or fail_after_retirement and state.get('retired'): raise subprocess.TimeoutExpired(argv,315)
                    return command(argv,**kwargs)
                result=self.execute(root,{**expected,'owner':'new-owner','cleanupReadmission':{**binding,'receipt':admitted['readmission']}},'cleanup',slow)
                self.assertTrue(budgets); self.assertTrue(all(x==('300',315) for x in budgets))
                self.assertEqual(receipt,(job/('cleanup-readmission-'+self.READMISSION+'.json')).read_bytes())
                if fail_after_retirement:
                    self.assertEqual('unknown',result['state']); self.assertEqual(1,len(state['effects'])); self.assertNotIn('unroot',state['effects']); self.assertTrue((root/'android-native-device-api29.lease').exists())
                else:
                    self.assertEqual('cleaned',result['state'],result); self.assertEqual(9,len(budgets))

    def test_extended_budget_is_limited_to_exact_readmission_paths(self):
        binding={'cleanupReadmission':{'correlationId':self.READMISSION,'originalIntentSha256':'f'*64}}
        self.assertEqual(15550,admission._readmission_transport_seconds('cleanup-readmit',binding))
        self.assertEqual(15550,admission._readmission_transport_seconds('cleanup-readmission-status',binding))
        self.assertEqual(31430,admission._readmission_transport_seconds('cleanup-mount-diagnostic',binding))
        self.assertEqual(55105,admission._readmission_transport_seconds('cleanup',{'cleanupReadmission':{**binding['cleanupReadmission'],'receipt':{}}}))
        for action in ('start','status','cleanup','cleanup-readmit','cleanup-readmission-status','cleanup-mount-diagnostic'):
            self.assertEqual(60,admission._readmission_transport_seconds(action,{}))
        self.assertEqual(60,admission._readmission_transport_seconds('cleanup',binding))
        self.assertEqual(60,admission._readmission_transport_seconds('status',binding))

    def test_actual_rooted_readmission_all_commands_near_ceiling_fit_outer_deadline(self):
        from collections import Counter
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve(); expected,state,command=self.fixture(root); elapsed=0; observed=Counter()
            binding={'correlationId':self.READMISSION,'originalIntentSha256':'f'*64}
            dispatch={**expected,'cleanupReadmission':binding}
            config=SimpleNamespace(hosts={'archlinux':SimpleNamespace(fixture_transfer_root=root)})
            intent={'host':'archlinux','remoteRoot':str(root),'device':'api29','correlationId':CORRELATION,'remote':dispatch}
            def bounded(_argv,_payload,timeout):
                def near_ceiling(argv,**kwargs):
                    nonlocal elapsed
                    observed[kwargs['timeout']]+=1; elapsed+=kwargs['timeout']-0.001
                    if elapsed>timeout: raise admission.ssh_transfer.SshTransferError('inert outer deadline exceeded')
                    return command(argv,**kwargs)
                result=self.execute(root,dispatch,'cleanup-readmit',near_ceiling)
                return 0,json.dumps(result).encode()
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config), mock.patch.object(admission.ssh_transport,'connection_host',return_value=SimpleNamespace(password=None)), \
                    mock.patch.object(admission.ssh_transport,'build_ssh_argv',return_value=['inert-ssh']), mock.patch.object(admission.ssh_transfer,'_bounded_run',side_effect=bounded):
                result=admission._remote(root,intent,'cleanup-readmit')
            self.assertEqual('ready',result['state'],result); self.assertEqual(Counter({30:460,10:106,315:2}),observed)
            self.assertGreater(elapsed,15400); self.assertEqual([],state['effects'])

    def test_every_generated_readmission_path_command_count_fits_derived_outer_budget(self):
        from collections import Counter
        paths=(('cleanup-readmit','0',{30:460,10:106,315:2}),
               ('cleanup-readmit','2000',{30:54,315:2}),
               ('cleanup-readmission-status','0',{30:460,10:106,315:2}),
               ('cleanup-readmission-status','2000',{30:54,315:2}),
               ('cleanup-mount-diagnostic','0',{30:930,10:221,315:4}),
               ('cleanup','0',{30:1617,10:370,315:9}),
               ('cleanup','2000',{30:1240,10:264,315:10}))
        for action,uid,expected_counts in paths:
            with self.subTest(action=action,uid=uid), tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve(); expected,state,command=self.fixture(root); state['uid']=uid
                binding={'correlationId':self.READMISSION,'originalIntentSha256':'f'*64}
                if action=='cleanup-readmit': dispatch={**expected,'cleanupReadmission':binding}
                else:
                    receipt=self.execute(root,{**expected,'cleanupReadmission':binding},'cleanup-readmit',command)['readmission']
                    dispatch={**expected,'cleanupReadmission':binding if action=='cleanup-readmission-status' else {**binding,'receipt':receipt}}
                    if action=='cleanup': dispatch['owner']='new-owner'
                observed=Counter(); elapsed=0; limit=admission._readmission_transport_seconds(action,dispatch)
                def near_ceiling(argv,**kwargs):
                    nonlocal elapsed
                    observed[kwargs['timeout']]+=1; elapsed+=kwargs['timeout']-0.001
                    if elapsed>limit: raise admission.ssh_transfer.SshTransferError('inert outer deadline exceeded')
                    return command(argv,**kwargs)
                result=self.execute(root,dispatch,action,near_ceiling)
                self.assertEqual('cleaned' if action=='cleanup' else 'ready' if action=='cleanup-readmit' else 'partial',result['state'],result)
                self.assertEqual(Counter(expected_counts),observed)
                self.assertGreaterEqual(limit,sum(timeout*count for timeout,count in observed.items())+60)

    def test_measured_setuid_su_mode_is_admitted_with_stable_owned_identity(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve(); expected,state,command=self.fixture(root)
            def measured(argv,**kwargs):
                if argv[5:]==['stat','-c','%u:%g:%a:%d:%i:%F','/system/xbin/su']:
                    return SimpleNamespace(returncode=0,stdout=b'0:2000:4750:64258:4886:regular file',stderr=b'')
                return command(argv,**kwargs)
            result=self.execute(root,{**expected,'cleanupReadmission':{'correlationId':self.READMISSION,'originalIntentSha256':'f'*64}},'cleanup-readmit',measured)
            self.assertEqual('ready',result['state'],result); self.assertEqual([],state['effects'])

    def test_fixed_su_identity_rejects_alternate_ownership_mode_and_generation_drift(self):
        unsafe=(b'2000:2000:4750:64258:4886:regular file',b'0:0:4750:64258:4886:regular file',
                b'0:1000:4750:64258:4886:regular file',b'0:2000:4752:64258:4886:regular file',
                b'0:2000:4770:64258:4886:regular file',b'0:2000:4777:64258:4886:regular file',
                b'0:2000:755:64258:4886:regular file',b'0:2000:4750:64258:4886:symbolic link')
        for observed in (*unsafe,'gid-drift','inode-drift','device-drift'):
            with self.subTest(observed=observed), tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve(); expected,state,command=self.fixture(root); stats=0; drops=[]
                def altered(argv,**kwargs):
                    nonlocal stats
                    if argv[0]=='/bin/cli': self.fail('unsafe su identity reached public read')
                    words=argv[5:]
                    if words==['stat','-c','%u:%g:%a:%d:%i:%F','/system/xbin/su']:
                        stats+=1
                        if isinstance(observed,bytes): return SimpleNamespace(returncode=0,stdout=observed,stderr=b'')
                        if stats>1:
                            changed={'gid-drift':b'0:0:4750:64258:4886:regular file',
                                     'inode-drift':b'0:2000:4750:64258:9999:regular file',
                                     'device-drift':b'0:2000:4750:99999:4886:regular file'}[observed]
                            return SimpleNamespace(returncode=0,stdout=changed,stderr=b'')
                    if words[:2]==['/system/xbin/su','2000,2000']: drops.append(words)
                    return command(argv,**kwargs)
                result=self.execute(root,{**expected,'cleanupReadmission':{'correlationId':self.READMISSION,'originalIntentSha256':'f'*64}},'cleanup-readmit',altered)
                self.assertEqual('unknown',result['state'],result); self.assertEqual([],state['effects']); self.assertEqual([],drops)

    def test_unreceipted_readmission_status_retains_finite_actual_public_command_failure(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve(); intent,state,config,remote=self.local_fixture(root)
            digest=admission._private_snapshot(admission._intent_path(root,CORRELATION))[1]
            request=admission._readmission_path(root,self.READMISSION,'.request.json')
            admission.android_native_fixture.write_private_plan(request,{'schema':1,'endpointCorrelationId':CORRELATION,'correlationId':self.READMISSION,'originalIntentSha256':digest})
            before={str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()}
            def command(argv,**kwargs):
                if argv[0]=='/bin/cli':
                    return SimpleNamespace(returncode=2,stdout=json.dumps({'schemaVersion':1,'ok':False,'code':'UNAVAILABLE','final':True,'message':'/private/secret context'}).encode(),stderr=b'/private/secret stderr')
                return remote.command(argv,**kwargs)
            def observing(_root,dispatch,action): return self.execute(root,dispatch['remote'],action,command)
            with mock.patch.object(admission.ssh_transport,'load_config',return_value=config), mock.patch.object(admission,'_remote',side_effect=observing):
                result=admission.cleanup_readmission_status(root,CORRELATION,self.READMISSION)
            self.assertEqual('unknown',result['state']); self.assertEqual('command_failed',result['reason'])
            self.assertEqual({'phase':'public-status','outcome':'nonzero','stderrClass':'other'},result['commandDiagnostic'])
            self.assertEqual({'code':'UNAVAILABLE','exitDisposition':'matched','final':True},result['publicFailure'])
            self.assertNotIn('/private',json.dumps(result)); self.assertEqual([],state['effects'])
            self.assertFalse(admission._readmission_path(root,self.READMISSION).exists())
            self.assertEqual(before,{str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()})

    def test_readonly_readmission_failure_phases_are_finite_on_generated_paths(self):
        cases=(('device','device-identity','nonzero','permission'),('package','device-package','nonzero','not-found'),
               ('routing-timeout','public-routing','timeout','none'),('public-encoding','public-status','encoding','none'))
        for action in ('cleanup-readmit','cleanup-readmission-status'):
            for case,phase,outcome,stderr in cases:
                with self.subTest(action=action,case=case), tempfile.TemporaryDirectory() as raw:
                    root=Path(raw).resolve(); expected,state,command=self.fixture(root)
                    def failing(argv,**kwargs):
                        if case=='device' and argv[5:]==['getprop','ro.build.version.sdk']:
                            return SimpleNamespace(returncode=1,stdout=b'',stderr=b'Permission denied /secret device')
                        if case=='package' and argv[5:2+5]==['pm','path']:
                            return SimpleNamespace(returncode=1,stdout=b'',stderr=b'No such file /secret package')
                        if argv[0]=='/bin/cli':
                            if case=='routing-timeout' and _public_words(argv)==['routing','show']: raise subprocess.TimeoutExpired(argv,315)
                            if case=='public-encoding' and _public_words(argv)==['status']: return SimpleNamespace(returncode=0,stdout=b'\xff',stderr=b'')
                        return command(argv,**kwargs)
                    result=self.execute(root,{**expected,'cleanupReadmission':{'correlationId':self.READMISSION,'originalIntentSha256':'f'*64}},action,failing)
                    self.assertEqual('unknown',result['state']); self.assertEqual({'phase':phase,'outcome':outcome,'stderrClass':stderr},result['commandDiagnostic'])
                    self.assertNotIn('/secret',json.dumps(result)); self.assertEqual([],state['effects'])

    def test_readmission_failure_projections_reject_forged_fields_or_wrong_correlation(self):
        for method in ('admission','status'):
            for case in ('hostile','wrong-correlation','valid'):
                with self.subTest(method=method,case=case), tempfile.TemporaryDirectory() as raw:
                    root=Path(raw).resolve(); intent,state,config,remote=self.local_fixture(root)
                    if method=='status':
                        digest=admission._private_snapshot(admission._intent_path(root,CORRELATION))[1]
                        admission.android_native_fixture.write_private_plan(admission._readmission_path(root,self.READMISSION,'.request.json'),{'schema':1,'endpointCorrelationId':CORRELATION,'correlationId':self.READMISSION,'originalIntentSha256':digest})
                    command={'phase':'public-status','outcome':'nonzero','stderrClass':'none'}
                    public={'code':'UNAVAILABLE','exitDisposition':'matched','final':True}
                    if case=='hostile': command['stderr']='secret'; public['message']='secret'
                    value={'state':'unknown','reason':'command_failed','correlationId':self.READMISSION if case=='wrong-correlation' else CORRELATION,'commandDiagnostic':command,'publicFailure':public,'raw':'secret'}
                    with mock.patch.object(admission.ssh_transport,'load_config',return_value=config), mock.patch.object(admission,'_remote',return_value=value):
                        result=(admission.cleanup_readmission if method=='admission' else admission.cleanup_readmission_status)(root,CORRELATION,self.READMISSION)
                    self.assertEqual('unknown',result['state']); self.assertNotIn('secret',json.dumps(result)); self.assertFalse(admission._readmission_path(root,self.READMISSION).exists())
                    if case=='valid': self.assertEqual(command,result['commandDiagnostic']); self.assertEqual(public,result['publicFailure'])
                    else: self.assertNotIn('commandDiagnostic',result); self.assertNotIn('publicFailure',result)

    def test_codec_shaped_initial_status_null_owner_passes_fixed_readonly_adapter(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw); identifier=self.READMISSION; forwarded=[]
            configuration={'adb':'/bin/adb','serial':'serial-1','owner':None,'revision':None,'operation':'status',
                'suIdentity':['0:2000:4750:64258:4886:regular file','a'*64+'  /system/xbin/su']}
            # ControlDocumentCodec emits all seven fields. DesktopAndroidAdbClient
            # keeps controllerId null for STATUS: only mutations bind an owner.
            payload=json.dumps({'schemaVersion':1,'requestId':CORRELATION,'controllerId':None,'ifRevision':None,
                'interactive':False,'asynchronous':False,'command':{'operation':'status','arguments':{}}}).encode()
            def adb(argv,**kwargs):
                if argv[5:]==['stat','-c','%u:%g:%a:%d:%i:%F','/system/xbin/su']: out=b'0:2000:4750:64258:4886:regular file'
                elif argv[5:]==['sha256sum','/system/xbin/su']: out=('a'*64+'  /system/xbin/su').encode()
                else: forwarded.append((argv,kwargs.get('input'))); out=b''
                return SimpleNamespace(returncode=0,stdout=out,stderr=b'')
            with mock.patch('sys.argv',['adb','-s','serial-1','shell','-T','content','write','--uri','content://com.kardinal.vpncontrol.control/document-uploads/'+identifier+'/0']), \
                    mock.patch('sys.stdin',SimpleNamespace(buffer=io.BytesIO(payload))), mock.patch('subprocess.run',side_effect=adb):
                with self.assertRaises(SystemExit) as exited: exec(admission._ENDPOINT_ADB_ADAPTER,{'CONFIG':json.dumps(configuration),'__file__':str(root/'adb')})
            self.assertEqual(0,exited.exception.code); self.assertEqual(1,len(forwarded)); self.assertEqual(payload,forwarded[0][1])

    def test_initial_null_owner_adapter_remains_status_only_and_receipted_reads_pin_owner(self):
        cases=((None,'status',None,'status',True),
               (None,'status','new-owner','status',False),
               (None,'operations.list',None,'operations.list',False),
               (None,'routing.show',None,'routing.show',False),
               (None,'status',None,'off',False),
               ('new-owner','status',None,'status',False),
               ('new-owner','status','foreign-owner','status',False),
               ('new-owner','status','new-owner','status',True))
        for configured,operation,packet_owner,packet_operation,allowed in cases:
            with self.subTest(configured=configured,operation=operation,packet_owner=packet_owner,packet_operation=packet_operation), tempfile.TemporaryDirectory() as raw:
                root=Path(raw); forwarded=[]
                configuration={'adb':'/bin/adb','serial':'serial-1','owner':configured,'revision':None,'operation':operation,
                    'suIdentity':['0:2000:4750:64258:4886:regular file','a'*64+'  /system/xbin/su']}
                payload=json.dumps({'schemaVersion':1,'requestId':CORRELATION,'controllerId':packet_owner,'ifRevision':None,
                    'interactive':False,'asynchronous':False,'command':{'operation':packet_operation,'arguments':{}}}).encode()
                def adb(argv,**kwargs):
                    if argv[5:]==['stat','-c','%u:%g:%a:%d:%i:%F','/system/xbin/su']: out=b'0:2000:4750:64258:4886:regular file'
                    elif argv[5:]==['sha256sum','/system/xbin/su']: out=('a'*64+'  /system/xbin/su').encode()
                    else: forwarded.append(argv); out=b''
                    return SimpleNamespace(returncode=0,stdout=out,stderr=b'')
                with mock.patch('sys.argv',['adb','-s','serial-1','shell','-T','content','write','--uri','content://com.kardinal.vpncontrol.control/document-uploads/'+self.READMISSION+'/0']), \
                        mock.patch('sys.stdin',SimpleNamespace(buffer=io.BytesIO(payload))), mock.patch('subprocess.run',side_effect=adb):
                    with self.assertRaises(SystemExit) as exited: exec(admission._ENDPOINT_ADB_ADAPTER,{'CONFIG':json.dumps(configuration),'__file__':str(root/'adb')})
                self.assertEqual(0 if allowed else 126,exited.exception.code); self.assertEqual(1 if allowed else 0,len(forwarded))


if __name__ == "__main__":
    unittest.main()
