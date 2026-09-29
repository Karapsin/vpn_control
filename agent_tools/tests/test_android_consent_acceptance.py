"""Causal guards for the disposable Android VPN consent-denial scenario."""
from __future__ import annotations

import unittest
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock
from contextlib import ExitStack, redirect_stdout

from agent_tools import android_consent_acceptance as subject


CORRELATION = "b68a93e0-445d-4cf5-8fee-2f5d90065bd3"
OWNER = "e8d73f61-f7bf-4e24-b13a-aff40b1c8e1b"
PACKAGE_SHA = "d" * 64
BACKUP_SHA = "e" * 64
OPERATION_ID = "00000000-0000-4000-8000-000000009999"
DIAGNOSTIC = "[runtime]\nmode=VPN\nvpn_permission_granted=false\nis_vpn_running=false\n"
TITLE = ('<node text="Connection request" resource-id="android:id/alertTitle" '
         'package="com.android.vpndialogs"/>')
CANCEL = ('<node text="Cancel" resource-id="android:id/button2" '
          'package="com.android.vpndialogs" enabled="true" bounds="[10,20][110,80]"/>')
REQUESTOR = ('<node text="VPN Control wants to set up a VPN connection that allows it to monitor network traffic." '
             'resource-id="com.android.vpndialogs:id/warning" package="com.android.vpndialogs"/>')


class _PublicConsentDevice:
    def __init__(self, *, xml: str | None = None, headless_xml: str = "<hierarchy/>",
                 diagnostic: str = DIAGNOSTIC,
                 lose_on: bool = False,
                 noninteractive_code: str = "INTERACTION_REQUIRED",
                 waited_operation: str = OPERATION_ID, wait_ok: bool = False,
                 wait_exit: int = 1):
        self.xml = xml if xml is not None else "<hierarchy>" + TITLE + REQUESTOR + CANCEL + "</hierarchy>"
        self.headless_xml = headless_xml
        self.diagnostic = diagnostic
        self.lose_on = lose_on
        self.noninteractive_code = noninteractive_code
        self.waited_operation = waited_operation
        self.wait_ok = wait_ok
        self.wait_exit = wait_exit
        self.calls: list[list[str]] = []
        self.on_count = 0
        self.noninteractive_count = 0
        self.tap_count = 0
        self.wait_count = 0
        self.ui_dump_count = 0
        self.pre_on_phase = None
        self.job: Path | None = None
        self.adb_path = ""
        self.cli_path = ""
        self.cli_envs: list[dict | None] = []
        self.operation_journal_before_ui = None

    @staticmethod
    def done(value: str, returncode: int = 0):
        return SimpleNamespace(returncode=returncode, stdout=value.encode())

    def run(self, args, **kwargs):
        self.calls.append(args)
        if args[:5] == [self.adb_path, "-s", "emulator-5554", "shell", "-T"]:
            words = args[5:]
            probes = {
                ("id", "-u"): "2000\n",
                ("getprop", "ro.build.version.sdk"): "29\n",
                ("getprop", "ro.kernel.qemu.avd_name"): "owned-api29\n",
                ("getprop", "ro.boot.qemu.avd_name"): "\n",
                ("getprop", "ro.product.cpu.abi"): "x86_64\n",
                ("pm", "path", "com.kardinal.vpncontrol"): "package:/data/app/owned/base.apk\n",
                ("sha256sum", "/data/app/owned/base.apk"):
                    PACKAGE_SHA + "  /data/app/owned/base.apk\n",
            }
            if tuple(words) in probes:
                return self.done(probes[tuple(words)])
            if words[:2] == ["uiautomator", "dump"]:
                self.ui_dump_count += 1
                assert self.job is not None
                record = self.job / "operation.json"
                if record.is_file():
                    self.operation_journal_before_ui = (
                        json.loads(record.read_text()), stat.S_IMODE(record.stat().st_mode))
                return self.done("UI dumped\n")
            if words[0] == "cat":
                return self.done(self.headless_xml if self.ui_dump_count == 1 else self.xml)
            if words[0] == "rm":
                return self.done("")
            if words[:2] == ["input", "tap"]:
                self.tap_count += 1
                if words[2:] != ["60", "50"]:
                    raise AssertionError("wrong Cancel coordinates")
                return self.done("")
            raise AssertionError(f"unexpected shell action: {words!r}")
        if args[:5] != [self.cli_path, "--json", "--android", "--serial", "emulator-5554"] and \
                args[:4] != [self.cli_path, "--android", "--serial", "emulator-5554"]:
            raise AssertionError(f"unexpected public command: {args!r}")
        self.cli_envs.append(kwargs.get("env"))
        if "diagnostics" in args:
            return self.done(self.diagnostic)
        if "status" in args:
            return self.done(json.dumps({"ok": True, "final": True, "code": "OK",
                                         "controllerId": OWNER, "configurationRevision": 2,
                                         "data": {"runtimeRunning": False,
                                                  "runtimeObservation": "stopped"}}))
        if "on" in args:
            if "--interactive" not in args:
                self.noninteractive_count += 1
                return self.done(json.dumps({"ok": False, "final": True,
                                             "code": self.noninteractive_code,
                                             "controllerId": OWNER,
                                             "configurationRevision": 2}), returncode=1)
            self.on_count += 1
            assert self.job is not None
            self.pre_on_phase = json.loads((self.job / "phase.json").read_text())["phase"]
            if self.lose_on:
                raise subprocess.TimeoutExpired(args, 120)
            return self.done(json.dumps({"ok": True, "final": False, "code": "ACCEPTED",
                                         "controllerId": OWNER, "operationId": OPERATION_ID}))
        if "wait" in args:
            self.wait_count += 1
            return self.done(json.dumps({"ok": self.wait_ok, "final": True,
                                         "code": "PERMISSION_DENIED", "controllerId": OWNER,
                                         "operationId": self.waited_operation}), returncode=self.wait_exit)
        raise AssertionError(f"unexpected public command: {args!r}")


def _run_worker(root: Path, device: _PublicConsentDevice) -> dict:
    root.chmod(0o700)
    binary = root / "bin"
    binary.mkdir(mode=0o700)
    adb = binary / "adb"
    adb.write_text("#!/bin/sh\nexit 0\n"); adb.chmod(0o700)
    cli = root / "vpn-control"
    cli.write_text("#!/bin/sh\nexit 0\n"); cli.chmod(0o700)
    device.adb_path = str(adb)
    device.cli_path = str(cli)
    job = root / ("android-document-job-" + CORRELATION)
    job.mkdir(mode=0o700)
    device.job = job
    argv = ["remote-worker", str(adb), str(cli), "emulator-5554", "owned-api29",
            "29", str(root), CORRELATION, PACKAGE_SHA, OWNER, "2"]
    output = io.StringIO()
    with mock.patch.object(sys, "argv", argv), \
            mock.patch.object(subprocess, "run", side_effect=device.run), \
            redirect_stdout(output):
        try:
            exec(subject._REMOTE, {"__name__": "__main__"})
        except SystemExit:
            pass
    return json.loads(output.getvalue())


class AndroidConsentParserTest(unittest.TestCase):
    def test_read_only_preflight_classifies_existing_permission_without_raw_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            adb = root / "adb"
            cli = root / "vpn-control"
            for executable in (adb, cli):
                executable.write_text("#!/bin/sh\nexit 0\n")
                executable.chmod(0o700)
            diagnostic = DIAGNOSTIC.replace("vpn_permission_granted=false", "vpn_permission_granted=true")
            output = io.StringIO()
            with mock.patch.object(sys, "argv", ["preflight", str(adb), str(cli), "emulator-5554"]), \
                    mock.patch.object(subprocess, "run", return_value=SimpleNamespace(
                        returncode=0, stdout=diagnostic.encode())), redirect_stdout(output):
                exec(subject._PREFLIGHT, {"__name__": "__main__"})
            self.assertEqual(json.loads(output.getvalue()), {"ready": False, "code": "permission_granted"})

    def test_read_only_preflight_does_not_call_missing_mode_proxy_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            adb = root / "adb"
            cli = root / "vpn-control"
            for executable in (adb, cli):
                executable.write_text("#!/bin/sh\nexit 0\n")
                executable.chmod(0o700)
            for diagnostic, expected in (
                    (DIAGNOSTIC.replace("mode=VPN\n", ""), "diagnostics_unavailable"),
                    (DIAGNOSTIC.replace("mode=VPN", "mode=PROXY_ONLY"), "mode_not_vpn"),
                    (DIAGNOSTIC.replace("mode=VPN", "mode=garbled"), "diagnostics_unavailable")):
                with self.subTest(diagnostic=diagnostic):
                    output = io.StringIO()
                    with mock.patch.object(sys, "argv", ["preflight", str(adb), str(cli), "emulator-5554"]), \
                            mock.patch.object(subprocess, "run", return_value=SimpleNamespace(
                                returncode=0, stdout=diagnostic.encode())), redirect_stdout(output):
                        exec(subject._PREFLIGHT, {"__name__": "__main__"})
                    self.assertEqual(json.loads(output.getvalue()), {"ready": False, "code": expected})

    def test_diagnostics_require_one_vpn_mode_and_explicit_denied_stopped_state(self) -> None:
        diagnostic = (
            "[runtime]\n"
            "mode=VPN\n"
            "vpn_permission_granted=false\n"
            "is_vpn_running=false\n"
        )
        self.assertTrue(subject._diagnostic_consent_state(diagnostic))
        for changed in (
            diagnostic.replace("mode=VPN", "mode=PROXY_ONLY"),
            diagnostic.replace("vpn_permission_granted=false", "vpn_permission_granted=true"),
            diagnostic.replace("is_vpn_running=false", "is_vpn_running=true"),
            diagnostic.replace("vpn_permission_granted=false\n", ""),
            diagnostic + "mode=VPN\n",
            diagnostic + "vpn_permission_granted=true\n",
            diagnostic + "is_vpn_running=true\n",
            "mode=VPN\nvpn_permission_granted=false\nis_vpn_running=false\n",
            diagnostic + "[runtime]\nmode=VPN\n",
            diagnostic + "[network]\nstate=idle\n[runtime]\nmode=VPN\n"
            "vpn_permission_granted=false\nis_vpn_running=false\n",
        ):
            with self.subTest(changed=changed):
                self.assertFalse(subject._diagnostic_consent_state(changed))

    def test_only_owned_cancel_button_with_valid_bounds_is_admitted(self) -> None:
        title = ('<node text="Connection request" resource-id="android:id/alertTitle" '
                 'package="com.android.vpndialogs"/>')
        node = ('<node index="1" text="Cancel" resource-id="android:id/button2" '
                'package="com.android.vpndialogs" enabled="true" bounds="[10,20][110,80]"/>')
        self.assertEqual(subject._cancel_button("<hierarchy>" + title + REQUESTOR + node + "</hierarchy>"), (60, 50))
        for changed in (
            node.replace('package="com.android.vpndialogs"', 'package="com.example.foreign"'),
            node.replace('resource-id="android:id/button2"', 'resource-id="android:id/button1"'),
            node.replace('text="Cancel"', 'text="OK"'),
            node.replace('enabled="true"', 'enabled="false"'),
            node.replace("[10,20][110,80]", "[110,80][10,20]"),
            node.replace("[10,20][110,80]", "[-10,20][110,80]"),
            node.replace("[10,20][110,80]", "[0,0][0,0]"),
        ):
            with self.subTest(changed=changed):
                self.assertIsNone(subject._cancel_button("<hierarchy>" + title + REQUESTOR + changed + "</hierarchy>"))
        foreign_requestor = REQUESTOR.replace("VPN Control wants", "Another VPN wants")
        self.assertIsNone(subject._cancel_button("<hierarchy>" + title + foreign_requestor + node + "</hierarchy>"))
        self.assertIsNone(subject._cancel_button("<hierarchy>" + title + node + "</hierarchy>"))
        self.assertIsNone(subject._cancel_button("<hierarchy>" + title + REQUESTOR + REQUESTOR + node + "</hierarchy>"))
        self.assertIsNone(subject._cancel_button("<hierarchy>" + title + node))
        self.assertIsNone(subject._cancel_button("<hierarchy>" + title + node + node + "</hierarchy>"))
        self.assertIsNone(subject._cancel_button("<hierarchy>" + title + node +
                                                 '<node package="com.example.foreign"/>' + "</hierarchy>"))


class AndroidConsentWorkerTest(unittest.TestCase):
    def test_noncanonical_accepted_operation_id_rejects_before_prompt(self) -> None:
        class BadIdDevice(_PublicConsentDevice):
            def run(self, args, **kwargs):
                result = super().run(args, **kwargs)
                if "on" in args and result.returncode == 0:
                    value = json.loads(result.stdout)
                    value["operationId"] = "a" * 36
                    return self.done(json.dumps(value))
                return result
        with tempfile.TemporaryDirectory() as tmp:
            device = BadIdDevice()
            result = _run_worker(Path(tmp), device)
            self.assertEqual(result["state"], "unknown")
            self.assertEqual(device.tap_count, 0)
            self.assertIsNone(device.operation_journal_before_ui)

    def test_denial_is_bound_to_exact_operation_and_runtime_stays_off(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            device = _PublicConsentDevice()
            result = _run_worker(Path(tmp), device)
            self.assertEqual(result["state"], "complete")
            self.assertEqual(result["operationId"], OPERATION_ID)
            self.assertTrue(result["consentDenied"])
            self.assertTrue(result["runtimeOff"])
            self.assertTrue(result["permissionStillAbsent"])
            self.assertTrue(result["noninteractiveRejected"])
            self.assertEqual(device.pre_on_phase, "interactive_on_submitted")
            self.assertEqual((device.noninteractive_count, device.on_count,
                              device.tap_count, device.wait_count), (1, 1, 1, 1))
            self.assertFalse(any("off" in call or "cancel" in call for call in device.calls))
            self.assertTrue(device.cli_envs)
            self.assertTrue(all(isinstance(env, dict) and
                                env["PATH"].split(":", 1)[0] == str(Path(tmp).resolve() / "bin")
                                for env in device.cli_envs))

    def test_noninteractive_on_must_reject_before_interactive_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            device = _PublicConsentDevice(noninteractive_code="OK")
            result = _run_worker(Path(tmp), device)
            self.assertEqual(result["state"], "unknown")
            self.assertEqual((device.noninteractive_count, device.on_count,
                              device.tap_count, device.wait_count), (1, 0, 0, 0))

    def test_noninteractive_on_must_not_show_system_vpn_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            device = _PublicConsentDevice(headless_xml="<hierarchy>" + TITLE + REQUESTOR + CANCEL + "</hierarchy>")
            result = _run_worker(Path(tmp), device)
            self.assertEqual(result["state"], "unknown")
            self.assertEqual((device.noninteractive_count, device.on_count,
                              device.tap_count, device.wait_count), (1, 0, 0, 0))

    def test_operation_identity_is_durable_before_observing_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            device = _PublicConsentDevice()
            result = _run_worker(Path(tmp), device)
            self.assertEqual(result["state"], "complete")
            self.assertEqual(device.operation_journal_before_ui,
                             ({"operationId": OPERATION_ID, "controllerId": OWNER}, 0o600))

    def test_foreign_prompt_is_not_tapped_or_waited(self) -> None:
        foreign = "<hierarchy>" + TITLE + CANCEL.replace("com.android.vpndialogs", "com.example.foreign") + "</hierarchy>"
        for xml in (foreign, "<hierarchy>" + TITLE + CANCEL,
                    "<hierarchy>" + TITLE + REQUESTOR.replace("VPN Control wants", "Another VPN wants") + CANCEL + "</hierarchy>",
                    "<hierarchy>" + TITLE + CANCEL + CANCEL + "</hierarchy>"):
            with self.subTest(xml=xml), tempfile.TemporaryDirectory() as tmp:
                device = _PublicConsentDevice(xml=xml)
                result = _run_worker(Path(tmp), device)
                self.assertEqual(result["state"], "unknown")
                self.assertEqual((device.on_count, device.tap_count, device.wait_count), (1, 0, 0))

    def test_lost_on_acknowledgement_is_unknown_and_never_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            device = _PublicConsentDevice(lose_on=True)
            result = _run_worker(Path(tmp), device)
            self.assertEqual(result["state"], "unknown")
            self.assertEqual(device.pre_on_phase, "interactive_on_submitted")
            self.assertEqual((device.on_count, device.tap_count, device.wait_count), (1, 0, 0))

    def test_other_operation_denial_cannot_satisfy_request(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            device = _PublicConsentDevice(waited_operation="00000000-0000-4000-8000-000000008888")
            result = _run_worker(Path(tmp), device)
            self.assertEqual(result["state"], "unknown")
            self.assertEqual((device.on_count, device.tap_count, device.wait_count), (1, 1, 1))

    def test_duplicate_runtime_section_before_on_is_rejected(self) -> None:
        diagnostic = (DIAGNOSTIC + "[network]\nstate=idle\n" + DIAGNOSTIC)
        with tempfile.TemporaryDirectory() as tmp:
            device = _PublicConsentDevice(diagnostic=diagnostic)
            result = _run_worker(Path(tmp), device)
            self.assertEqual(result["state"], "unknown")
            self.assertEqual((device.on_count, device.tap_count, device.wait_count), (0, 0, 0))

    def test_denial_result_cannot_claim_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            device = _PublicConsentDevice(wait_ok=True)
            result = _run_worker(Path(tmp), device)
            self.assertEqual(result["state"], "unknown")
            self.assertEqual((device.on_count, device.tap_count, device.wait_count), (1, 1, 1))

    def test_denial_result_requires_public_exit_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            device = _PublicConsentDevice(wait_exit=0)
            result = _run_worker(Path(tmp), device)
            self.assertEqual(result["state"], "unknown")
            self.assertEqual((device.on_count, device.tap_count, device.wait_count), (1, 1, 1))


class AndroidConsentAdapterTest(unittest.TestCase):
    def test_preflight_returns_bounded_permission_code_without_reserving(self) -> None:
        profile = {"api": 29, "adb": "/approved/adb", "serial": "emulator-5554",
                   "expectedAvd": "owned-api29"}
        config = SimpleNamespace(hosts={"archlinux": SimpleNamespace(
            android_devices={"api29": profile}, fixture_transfer_root=Path("/fixture"))})
        stage = {"ok": True, "state": "published", "sourceSha": "a" * 40,
                 "receipt": {"cliPath": "/fixture/android-cli-stage-" + CORRELATION +
                                        "/tree/bin/vpn-control"}}
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(subject.ssh_transport, "load_config", return_value=config))
            stack.enter_context(mock.patch.object(subject.ssh_transport, "connection_host",
                                                  return_value=SimpleNamespace(password=None)))
            stack.enter_context(mock.patch.object(subject.android_observation, "_profile", return_value=profile))
            stack.enter_context(mock.patch.object(subject.subprocess, "run",
                                                  return_value=SimpleNamespace(stdout="a" * 40 + "\n")))
            stack.enter_context(mock.patch.object(subject.android_cli_stage, "status", return_value=stage))
            stack.enter_context(mock.patch.object(subject.android_observation, "observe",
                                                  return_value={"available": True,
                                                                "ownerConsistency": "consistent"}))
            ssh = stack.enter_context(mock.patch.object(subject.ssh_transport, "build_ssh_argv",
                                                       return_value=["preflight"]))
            stack.enter_context(mock.patch.object(subject.android_observation, "_run_probe",
                                                  return_value=(0, b'{"ready":false,"code":"permission_granted"}')))
            reserve = stack.enter_context(mock.patch.object(subject.android_document_acceptance, "_reserve"))
            result = subject.preflight("/unused", "archlinux", "api29", CORRELATION)
            self.assertEqual(result["state"], "blocked")
            self.assertEqual(result["code"], "permission_granted")
            self.assertEqual(set(result), {"ok", "state", "code", "host", "deviceAlias",
                                           "sourceSha", "productAction"})
            self.assertEqual(ssh.call_args.args[2], 60)
            reserve.assert_not_called()

    def test_preflight_uses_approved_adb_for_packaged_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "bin"
            binary.mkdir()
            adb = binary / "adb"
            adb.write_text("#!/bin/sh\nexit 0\n"); adb.chmod(0o700)
            cli = root / "vpn-control"
            cli.write_text("#!/bin/sh\nexit 0\n"); cli.chmod(0o700)
            device = _PublicConsentDevice()
            device.adb_path = str(adb)
            device.cli_path = str(cli)
            output = io.StringIO()
            with mock.patch.object(sys, "argv", ["preflight", str(adb), str(cli), "emulator-5554"]), \
                    mock.patch.object(subprocess, "run", side_effect=device.run), \
                    redirect_stdout(output):
                exec(subject._PREFLIGHT, {"__name__": "__main__"})
            self.assertEqual(json.loads(output.getvalue()), {"ready": True, "code": "ready"})
            self.assertEqual(len(device.cli_envs), 1)
            self.assertEqual(Path(device.cli_envs[0]["PATH"].split(":", 1)[0]).resolve(),
                             binary.resolve())

    def test_status_rejects_forged_terminal_and_mismatched_operation_journal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            job = root / ("android-document-job-" + CORRELATION)
            job.mkdir(mode=0o700)
            intent = {"fixtureRoot": tmp, "packageSha256": PACKAGE_SHA,
                      "expectedOwner": OWNER, "expectedRevision": 2,
                      "api": 29, "expectedAvd": "owned-api29"}
            identity = {"pid": 1, "startTicks": 1}
            result = {"state": "complete", "sourcePackageSha256": PACKAGE_SHA,
                      "device": {"uid": "2000", "api": 29, "avd": "owned-api29"},
                      "opening": {"owner": OWNER, "revision": 2},
                      "operationId": OPERATION_ID, "consentDenied": True,
                      "runtimeOff": True, "permissionStillAbsent": True}
            for name, value in (("intent.json", intent), ("identity.json", identity),
                                ("operation.json", {"controllerId": OWNER,
                                                    "operationId": "00000000-0000-4000-8000-000000008888"}),
                                ("result.json", {"state": "complete", "result": result})):
                path = job / name
                path.write_text(json.dumps(value)); path.chmod(0o600)
            command = [sys.executable, "-I", "-B", "-c", "exec(" + repr(subject._STATUS) + ")",
                       tmp, CORRELATION, json.dumps(intent, sort_keys=True, separators=(",", ":"))]
            observed = subprocess.run(command, capture_output=True, check=True, timeout=10)
            self.assertEqual(json.loads(observed.stdout)["state"], "unknown")
            self.assertEqual(json.loads(observed.stdout)["reason"], "terminal_binding_invalid")
            record = job / "operation.json"
            record.write_text(json.dumps({"controllerId": OWNER, "operationId": OPERATION_ID}))
            record.chmod(0o600)
            observed = subprocess.run(command, capture_output=True, check=True, timeout=10)
            self.assertEqual(json.loads(observed.stdout)["state"], "complete")

    def test_start_rejects_source_stage_backup_and_granted_permission_before_reserve(self) -> None:
        source_sha = "a" * 40
        profile = {"api": 29, "adb": "/approved/adb", "serial": "emulator-5554",
                   "expectedAvd": "owned-api29"}
        config = SimpleNamespace(hosts={"archlinux": SimpleNamespace(
            android_devices={"api29": profile}, fixture_transfer_root=Path("/fixture"))})
        artifact = {"verification": "verified", "artifact": {"platform": "android",
                    "artifactKind": "native-fixture-apk", "sourceSha": source_sha,
                    "sha256": PACKAGE_SHA}, "location": {"localPath": "/verified.apk"}}
        stage = {"ok": True, "state": "published", "sourceSha": source_sha,
                 "receipt": {"cliPath": "/fixture/android-cli-stage-" + CORRELATION +
                                        "/tree/bin/vpn-control",
                             "manifestSha256": "f" * 64, "desktopJarSha256": "c" * 64}}
        backup = {"ok": True, "state": "complete", "result": {
            "package": {"baseSha256": PACKAGE_SHA},
            "backup": {"sha256": BACKUP_SHA},
            "guard": {"controllerId": OWNER, "configurationRevision": 2},
            "device": {"api": 29}}}
        live = {"ok": True, "result": {"stage": "backup_present", "controllerId": OWNER,
                "configurationRevision": 2, "backup": {"sha256": BACKUP_SHA}}}
        start_args = ("/unused", "archlinux", "api29", CORRELATION,
                      "sha256-" + PACKAGE_SHA, CORRELATION, CORRELATION,
                      BACKUP_SHA, OWNER, 2)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(subject.ssh_transport, "load_config", return_value=config))
            stack.enter_context(mock.patch.object(subject.ssh_transport, "connection_host",
                                                  return_value=SimpleNamespace(password=None)))
            stack.enter_context(mock.patch.object(subject.android_observation, "_profile", return_value=profile))
            stack.enter_context(mock.patch.object(subject.native_artifact_registry, "verify_artifact",
                                                  return_value=artifact))
            stack.enter_context(mock.patch.object(subject.subprocess, "run",
                                                  return_value=SimpleNamespace(stdout=source_sha + "\n")))
            stack.enter_context(mock.patch.object(subject.android_package_install, "_inspect_apk"))
            stack.enter_context(mock.patch.object(subject.android_cli_stage, "status", return_value=stage))
            stack.enter_context(mock.patch.object(subject.android_admission_readback,
                                                  "async_collect", return_value=backup))
            stack.enter_context(mock.patch.object(subject.android_admission_readback,
                                                  "readback_status", return_value=live))
            stack.enter_context(mock.patch.object(subject.android_public_inspect, "inspect",
                                                  return_value={"outcome": "admitted", "result": {
                                                      "runtime": {"running": False}}}))
            def bounded_ssh(_config, _host, timeout_seconds, *, command):
                if not 1 <= timeout_seconds <= 60:
                    raise ValueError("SSH timeout must be between 1 and 60 seconds.")
                self.assertTrue(command)
                return ["preflight"]
            stack.enter_context(mock.patch.object(subject.ssh_transport, "build_ssh_argv",
                                                  side_effect=bounded_ssh))
            probe = stack.enter_context(mock.patch.object(subject.android_observation, "_run_probe",
                                                         return_value=(0, b'{"ready":false}')))
            reserve = stack.enter_context(mock.patch.object(subject.android_document_acceptance,
                                                           "_reserve"))
            artifact["artifact"]["sourceSha"] = "b" * 40
            with self.assertRaisesRegex(ValueError, "current source"):
                subject.start(*start_args)
            artifact["artifact"]["sourceSha"] = source_sha
            stage["sourceSha"] = "b" * 40
            with self.assertRaisesRegex(ValueError, "current source"):
                subject.start(*start_args)
            stage["sourceSha"] = source_sha
            # A synchronous android-admission-readback result has a top-level
            # outcome and cannot stand in for a completed async readback receipt.
            async_shape = dict(backup)
            backup.clear()
            backup.update({"ok": True, "outcome": "admitted", "result": async_shape["result"]})
            with self.assertRaisesRegex(ValueError, "opening backup"):
                subject.start(*start_args)
            backup.clear()
            backup.update(async_shape)
            backup["result"]["backup"]["sha256"] = "d" * 64
            with self.assertRaisesRegex(ValueError, "opening backup"):
                subject.start(*start_args)
            backup["result"]["backup"]["sha256"] = BACKUP_SHA
            with self.assertRaisesRegex(ValueError, "permission is not freshly absent"):
                subject.start(*start_args)
            self.assertEqual(probe.call_count, 1)
            reserve.assert_not_called()

    def test_unknown_collection_retains_device_lease_and_never_replays(self) -> None:
        unknown = {"ok": False, "state": "unknown", "reason": "command_outcome_unknown",
                   "correlationId": CORRELATION, "replayAllowed": False}
        with mock.patch.object(subject, "status", return_value=unknown), \
                mock.patch.object(subject.android_document_acceptance, "_release_device") as release, \
                mock.patch.object(subject.android_observation, "_run_probe") as probe:
            observed = subject.collect("/unused", CORRELATION)
        self.assertEqual(observed, unknown)
        release.assert_not_called()
        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
