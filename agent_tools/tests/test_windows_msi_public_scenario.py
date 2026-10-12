"""Strict read-only Windows MSI protected diagnostic observation."""
from __future__ import annotations

import json
import base64
import contextlib
import io
import hashlib
import gzip
import os
import re
import shutil
import tempfile
import struct
import zipfile
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import windows_msi_public_scenario as scenario


JOB = "9107428f-9c80-4284-9f4e-926350105a59"
SOURCE = "a" * 40


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def fake_pair(root: Path, *, matching_code: bool = True, asset_arch: str = "x86_64",
              asset_platform: str = "windows", jar_name: str = "desktopApp-fixed.jar",
              target_version: str = "2.2.0") -> tuple[dict[str, str], dict[str, object]]:
    package = root / "fixture"; package.mkdir()
    image = package / "packages" / "base" / "vpn-control"; (image / "app" / "native" / "windows-amd64").mkdir(parents=True)
    (image / "vpn-control-cli.exe").write_bytes(b"c" * 5000)
    (image / "app" / "native" / "windows-amd64" / "vpn-control-install-helper.exe").write_bytes(b"helper")
    with zipfile.ZipFile(image / "app" / jar_name, "w") as archive:
        archive.writestr("bin/windows-amd64/sing-box.exe", b"runtime")
    base = package / "packages" / "base" / "vpn-control-2.1.17.msi"; base.write_bytes(b"base")
    target = package / "packages" / "target" / ("vpn-control-" + target_version + ".msi"); target.parent.mkdir()
    target.write_bytes(b"target")
    fingerprint = "b" * 64
    def asset(path: Path, version: str) -> dict[str, object]:
        return {"fileName": path.name, "sha256": _digest(path.read_bytes()), "sizeBytes": path.stat().st_size,
                "architecture": asset_arch, "platform": asset_platform, "displayVersion": version}
    receipt = {"schemaVersion": 1, "testOnly": True, "productionTrustChanged": False,
               "architecture": "x86_64", "nativeOs": "Windows-test", "sourceFingerprint": fingerprint,
               "builds": [
                   {"label": "base", "version": "2.1.17", "codeFingerprint": "c" * 64,
                    "sourceFingerprint": fingerprint, "image": "packages\\base\\vpn-control", "assets": [asset(base, "2.1.17")]},
                   {"label": "target", "version": target_version, "codeFingerprint": "c" * 64 if matching_code else "d" * 64,
                    "sourceFingerprint": fingerprint, "image": "packages\\target\\vpn-control", "assets": [asset(target, target_version)]},
               ]}
    receipt_path = package / "fixture-receipt.json"; receipt_path.write_text(json.dumps(receipt))
    ids = {"fixtureReceiptArtifactId": "sha256-" + _digest(receipt_path.read_bytes()),
           "baseMsiArtifactId": "sha256-" + _digest(base.read_bytes()),
           "targetMsiArtifactId": "sha256-" + _digest(target.read_bytes())}
    locations = {ids["fixtureReceiptArtifactId"]: (receipt_path, "fixture-receipt"),
                 ids["baseMsiArtifactId"]: (base, "desktop-package"),
                 ids["targetMsiArtifactId"]: (target, "desktop-package")}
    def verify(_root: Path, artifact_id: str) -> dict[str, object]:
        path, kind = locations[artifact_id]
        return {"verification": "verified", "artifact": {"platform": "windows", "artifactKind": kind, "sourceSha": SOURCE},
                "location": {"evidenceClass": "local-verified", "localPath": str(path)}}
    return ids, {"verify": verify, "receipt": receipt}


def response(*, job: str = JOB, diagnostic: object = None) -> bytes:
    return json.dumps({"state": "observed", "status": {"version": 1, "jobId": job,
                       "sequence": 3, "phase": "Failed", "code": "RUNTIME_FAILED"},
                       "diagnostic": diagnostic}).encode()


class WindowsMsiPreinstallStatusTest(unittest.TestCase):
    def test_public_intent_write_failure_cannot_claim_or_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); ids, helper = fake_pair(root)
            correlation = "11111111-1111-4111-8111-111111111111"
            args = {"host": "archlinux", "correlationId": correlation, "sourceSha": SOURCE, **ids}
            target = types.SimpleNamespace(fixture_transfer_root=Path("/private/fixture"))
            config = types.SimpleNamespace(hosts={"archlinux": target})
            descriptor = ("windows-cp117", "/private/qga.sock", 589342, 520739,
                          "vpncp117", "S-1-5-21-1-2-3-1002", Path("private"))
            fixture = {"probeReceiptSha256": "e" * 64,
                       "controllerId": "33333333-3333-4333-8333-333333333333",
                       "ownerPid": 4567, "ownerStartedAtUtc": "2026-09-28T10:00:00Z"}
            with (patch.object(scenario.native_artifact_registry, "verify_artifact", side_effect=helper["verify"]),
                  patch.object(scenario.ssh_transport, "load_config", return_value=config),
                  patch.object(scenario.windows_credential_probe_ssh, "_descriptor", return_value=descriptor),
                  patch("agent_tools.windows_msi_base_prepare._require_verified_live_fixture", return_value=correlation),
                  patch("agent_tools.windows_fixture_network_probe.verified_owner_network_receipt",
                        return_value={"originalSid": descriptor[5], **fixture}),
                  patch("agent_tools.windows_msi_target_prepare._verified_network_context", return_value=fixture),
                  patch.object(scenario, "_write_intent", side_effect=OSError("fsync failed")),
                  patch.object(scenario.campaign_lease, "claim_role") as claim,
                  patch.object(scenario.windows_credential_probe_ssh, "_run_ssh") as send):
                with self.assertRaisesRegex(OSError, "fsync failed"):
                    scenario.start(root, args)
                claim.assert_not_called()
                send.assert_not_called()

    def test_remote_duplicate_intent_never_dispatches_second_guest_exec(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700)
            correlation = "11111111-1111-4111-8111-111111111111"
            lease_id = "22222222-2222-4222-8222-222222222222"
            artifact_ids = ["sha256-" + char * 64 for char in "abc"]
            encoded = base64.b64encode(b"x" * 200).decode()
            payload = {"schema": 1, "leaseId": lease_id, "socketPath": "/private/qga.sock", "pid": 589342, "startTicks": 520739,
                       "encodedCommand": encoded, "commandSha256": _digest(b"x" * 200),
                       "sourceSha": SOURCE, "artifactIds": artifact_ids}
            campaign = root / "windows-cp117" / "windows-cp117-campaign"
            campaign.mkdir(parents=True, mode=0o700)
            (root / "windows-cp117").chmod(0o700)
            (campaign / ".environment.lock").write_bytes(b"")
            (campaign / ".environment.lock").chmod(0o600)
            (campaign / "active.json").write_text(json.dumps({"version": 1, "sequence": 3,
                "state": "role-active", "role": "public", "correlationId": correlation,
                "server": "live", "credentials": "ready", "lastEvidenceSha256": "e" * 64,
                "lastOutcome": "succeeded", "identity": {"host": "archlinux",
                "environment": "windows-cp117", "leaseId": lease_id, "operator": "windows-base",
                "sourceSha": SOURCE, "fixtureReceiptArtifactId": artifact_ids[0],
                "baseMsiArtifactId": artifact_ids[1], "targetMsiArtifactId": artifact_ids[2],
                "socketPath": payload["socketPath"], "qemuPid": payload["pid"],
                "startTicks": payload["startTicks"]}}))
            (campaign / "active.json").chmod(0o600)
            raw = json.dumps(payload).encode(); frame = struct.pack(">I", len(raw)) + raw
            dispatches = []

            class FakeSocket:
                def __init__(self, *args, **kwargs): self.data = bytearray()
                def settimeout(self, value): pass
                def connect(self, value): pass
                def close(self): pass
                def sendall(self, value):
                    if value.startswith(b"\xff"):
                        sync = json.loads(value[1:])
                        self.data.extend(b"\xff" + json.dumps({"return": sync["arguments"]["id"]}).encode() + b"\n")
                    else:
                        dispatches.append(json.loads(value)["execute"])
                        self.data.extend(b'{"return":{"pid":1234}}\n')
                def recv(self, size):
                    take = min(size, len(self.data))
                    result = bytes(self.data[:take]); del self.data[:take]
                    return result

            code = scenario._REMOTE_START.replace("or not live(sock,pid,ticks)", "or False")
            def invoke() -> dict[str, object]:
                output = io.StringIO()
                stdin = types.SimpleNamespace(buffer=io.BytesIO(frame))
                with (patch("socket.socket", FakeSocket),
                      patch.object(sys, "argv", ["start", str(root), "windows-cp117", correlation]),
                      patch.object(sys, "stdin", stdin), contextlib.redirect_stdout(output)):
                    exec(code, {"__name__": "__main__"})
                return json.loads(output.getvalue())
            self.assertEqual("submitted", invoke()["state"])
            self.assertEqual("unknown", invoke()["state"])
            self.assertEqual(["guest-exec"], dispatches)
            stage = root / "windows-cp117" / "windows-msi-public" / correlation
            self.assertEqual(0o700, stage.stat().st_mode & 0o777)
            self.assertEqual(0o600, (stage / "binding.json").stat().st_mode & 0o777)

    def test_exact_same_source_pair_admits_and_mismatched_code_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); ids, helper = fake_pair(root)
            with patch.object(scenario.native_artifact_registry, "verify_artifact", side_effect=helper["verify"]):
                pair = scenario._admit_pair(root, SOURCE, ids["fixtureReceiptArtifactId"], ids["baseMsiArtifactId"], ids["targetMsiArtifactId"])
            self.assertEqual("2.2.0", pair["targetVersion"])
            self.assertEqual(_digest(b"target"), pair["targetMsiSha256"])
            self.assertEqual(_digest(b"runtime"), pair["baseRuntimeSha256"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); ids, helper = fake_pair(root, matching_code=False)
            with patch.object(scenario.native_artifact_registry, "verify_artifact", side_effect=helper["verify"]):
                with self.assertRaises(scenario.WindowsMsiPreinstallStatusError):
                    scenario._admit_pair(root, SOURCE, ids["fixtureReceiptArtifactId"], ids["baseMsiArtifactId"], ids["targetMsiArtifactId"])
        for wrong in ({"asset_arch": "arm64"}, {"asset_platform": "linux"}):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); ids, helper = fake_pair(root, **wrong)
                with patch.object(scenario.native_artifact_registry, "verify_artifact", side_effect=helper["verify"]):
                    with self.assertRaises(scenario.WindowsMsiPreinstallStatusError):
                        scenario._admit_pair(root, SOURCE, ids["fixtureReceiptArtifactId"], ids["baseMsiArtifactId"], ids["targetMsiArtifactId"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); ids, helper = fake_pair(root, target_version="2.1.16")
            with patch.object(scenario.native_artifact_registry, "verify_artifact", side_effect=helper["verify"]):
                with self.assertRaises(scenario.WindowsMsiPreinstallStatusError):
                    scenario._admit_pair(root, SOURCE, ids["fixtureReceiptArtifactId"], ids["baseMsiArtifactId"], ids["targetMsiArtifactId"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); ids, helper = fake_pair(root, jar_name="desktopApp-'evil.jar")
            with patch.object(scenario.native_artifact_registry, "verify_artifact", side_effect=helper["verify"]):
                with self.assertRaises(scenario.WindowsMsiPreinstallStatusError):
                    scenario._admit_pair(root, SOURCE, ids["fixtureReceiptArtifactId"], ids["baseMsiArtifactId"], ids["targetMsiArtifactId"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); ids, helper = fake_pair(root)
            helper["receipt"]["builds"][0]["image"] = "..\\unrelated\\vpn-control"
            (root / "fixture" / "fixture-receipt.json").write_text(json.dumps(helper["receipt"]))
            with patch.object(scenario.native_artifact_registry, "verify_artifact", side_effect=helper["verify"]):
                with self.assertRaises(scenario.WindowsMsiPreinstallStatusError):
                    scenario._admit_pair(root, SOURCE, ids["fixtureReceiptArtifactId"], ids["baseMsiArtifactId"], ids["targetMsiArtifactId"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); ids, helper = fake_pair(root)
            image = root / "fixture" / "packages" / "base" / "vpn-control"
            image.rename(image.with_name("real-image"))
            image.symlink_to(image.with_name("real-image"), target_is_directory=True)
            with patch.object(scenario.native_artifact_registry, "verify_artifact", side_effect=helper["verify"]):
                with self.assertRaises(scenario.WindowsMsiPreinstallStatusError):
                    scenario._admit_pair(root, SOURCE, ids["fixtureReceiptArtifactId"], ids["baseMsiArtifactId"], ids["targetMsiArtifactId"])

    def test_lost_submission_response_keeps_intent_and_never_replays(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); ids, helper = fake_pair(root)
            args = {"host": "archlinux", "correlationId": "11111111-1111-4111-8111-111111111111", "sourceSha": SOURCE, **ids}
            target = types.SimpleNamespace(fixture_transfer_root=Path("/private/fixture"))
            config = types.SimpleNamespace(hosts={"archlinux": target})
            descriptor = ("windows-cp117", "/private/qga.sock", 589342, 520739,
                          "vpncp117", "S-1-5-21-2404255130-2183793310-3766671872-1002", Path("private"))
            fixture = {"probeReceiptSha256": "e" * 64,
                       "controllerId": "33333333-3333-4333-8333-333333333333",
                       "ownerPid": 4567, "ownerStartedAtUtc": "2026-09-28T10:00:00Z"}
            with (patch.object(scenario.native_artifact_registry, "verify_artifact", side_effect=helper["verify"]),
                  patch.object(scenario.ssh_transport, "load_config", return_value=config),
                  patch.object(scenario.windows_credential_probe_ssh, "_descriptor", return_value=descriptor),
                  patch.object(scenario, "_require_live_fixture_campaign", return_value=(args["correlationId"], fixture)),
                  patch.object(scenario.campaign_lease, "claim_role", return_value={"state": "role-active"}),
                  patch("agent_tools.windows_msi_base_prepare._verified_claimed_campaign"),
                  patch("agent_tools.windows_msi_target_prepare._verified_network_context", return_value=fixture),
                  patch.object(scenario.windows_credential_probe_ssh, "_run_ssh", return_value=None) as send):
                first = scenario.start(root, args)
                self.assertEqual("unknown", first["state"])
                self.assertFalse(first["replayAllowed"])
                self.assertTrue(scenario._intent_file(root, args["correlationId"]).is_file())
                with self.assertRaises(scenario.WindowsMsiPreinstallStatusError):
                    scenario.start(root, args)
                other = {**args, "correlationId": "22222222-2222-4222-8222-222222222222"}
                with self.assertRaises(scenario.WindowsMsiPreinstallStatusError):
                    scenario.start(root, other)
                send.assert_called_once()

    def test_no_live_campaign_receipt_blocks_before_public_intent_or_guest_request(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); ids, helper = fake_pair(root)
            args = {"host": "archlinux", "correlationId": "11111111-1111-4111-8111-111111111111",
                    "sourceSha": SOURCE, **ids}
            target = types.SimpleNamespace(fixture_transfer_root=Path("/private/fixture"))
            config = types.SimpleNamespace(hosts={"archlinux": target})
            descriptor = ("windows-cp117", "/private/qga.sock", 589342, 520739,
                          "vpncp117", "S-1-5-21-2404255130-2183793310-3766671872-1002", Path("private"))
            with (patch.object(scenario.native_artifact_registry, "verify_artifact", side_effect=helper["verify"]),
                  patch.object(scenario.ssh_transport, "load_config", return_value=config),
                  patch.object(scenario.windows_credential_probe_ssh, "_descriptor", return_value=descriptor),
                  patch.object(scenario.windows_credential_probe_ssh, "_run_ssh") as send):
                with self.assertRaises(ValueError):
                    scenario.start(root, args)
                send.assert_not_called()
                self.assertFalse(scenario._intent_file(root, args["correlationId"]).exists())

    def test_live_server_receipt_verification_does_not_claim_before_intent(self) -> None:
        from agent_tools import windows_msi_base_prepare as base
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(base, "_require_verified_live_fixture", return_value="11111111-1111-4111-8111-111111111111"), \
             patch("agent_tools.windows_fixture_network_probe.verified_owner_network_receipt",
                   return_value={"originalSid": "S-1-5-21-1-2-3-1002",
                                 "controllerId": "33333333-3333-4333-8333-333333333333",
                                 "ownerPid": 123, "ownerStartedAtUtc": "2026-09-28T10:00:00Z"}), \
             patch("agent_tools.windows_msi_target_prepare._verified_network_context", return_value={}), \
             patch.object(scenario.campaign_lease, "claim_role", return_value={"state": "unknown"}):
            descriptor = ("windows-cp117", "/qga.sock", 1, 2, "vpncp117", "S-1-5-21-1-2-3-1002", Path("private"))
            observed = scenario._require_live_fixture_campaign(Path(directory),
                {"correlationId": "22222222-2222-4222-8222-222222222222"}, descriptor, object(), object())
            self.assertEqual(observed[0], "11111111-1111-4111-8111-111111111111")
            scenario.campaign_lease.claim_role.assert_not_called()

    def test_command_size_fails_before_intent_or_qga(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); ids, helper = fake_pair(root, jar_name="desktopApp-" + "a" * 230 + ".jar")
            args = {"host": "archlinux", "correlationId": "11111111-1111-4111-8111-111111111111", "sourceSha": SOURCE, **ids}
            target = types.SimpleNamespace(fixture_transfer_root=Path("/private/fixture"))
            config = types.SimpleNamespace(hosts={"archlinux": target})
            descriptor = ("windows-cp117", "/private/qga.sock", 589342, 520739,
                          "vpncp117", "S-1-5-21-2404255130-2183793310-3766671872-1002", Path("private"))
            with (patch.object(scenario.native_artifact_registry, "verify_artifact", side_effect=helper["verify"]),
                  patch.object(scenario.ssh_transport, "load_config", return_value=config),
                  patch.object(scenario.windows_credential_probe_ssh, "_descriptor", return_value=descriptor),
                  patch.object(scenario, "_bootstrap", return_value="x" * 12000),
                  patch.object(scenario.windows_credential_probe_ssh, "_run_ssh") as send):
                with self.assertRaisesRegex(scenario.WindowsMsiPreinstallStatusError, "bootstrap exceeds"):
                    scenario.start(root, args)
                send.assert_not_called()
                self.assertFalse(scenario._intent_file(root, args["correlationId"]).exists())

    def test_fixed_bootstrap_packs_exact_public_task_with_bounded_command(self) -> None:
        pair = {"targetVersion": "2.2.0", "baseCliSha256": "a" * 64,
                "targetMsiSha256": "b" * 64, "targetMsiSize": 1000,
                "baseAppJarName": "desktopApp-fixed.jar", "baseAppJarSha256": "c" * 64,
                "baseHelperSha256": "d" * 64, "sourceSha": SOURCE}
        command = scenario._bootstrap("11111111-1111-4111-8111-111111111111", pair,
                                      "VPNMSIX64\\vpncp117", "S-1-5-21-1-2-3-1002")
        packed = re.search(r"\$body='([^']+)'", command)
        self.assertIsNotNone(packed)
        wrapper = gzip.decompress(base64.b64decode(packed.group(1))).decode("utf-16le")
        inner = re.search(r"\$packed=\[Convert\]::FromBase64String\('([^']+)'\)", wrapper)
        self.assertIsNotNone(inner)
        raw = gzip.decompress(base64.b64decode(inner.group(1), validate=True))
        task = raw.decode("utf-8", errors="strict")
        self.assertEqual(task, scenario._public_task("11111111-1111-4111-8111-111111111111", pair,
                                                   "S-1-5-21-1-2-3-1002"))
        self.assertIn(hashlib.sha256(raw).hexdigest(), wrapper)
        self.assertIn("$expected=" + str(len(raw)), wrapper)
        self.assertIn(" --async --timeout-seconds 120 updates install", task)
        self.assertIn("operations status $request.operationId", task)
        self.assertLess(len(base64.b64encode(command.encode("utf-16le"))), 30000)

    def test_emitted_task_carrier_argument_cap_without_powershell(self) -> None:
        pair = {"targetVersion": "2.2.0", "baseCliSha256": "a" * 64,
                "targetMsiSha256": "b" * 64, "targetMsiSize": 1000,
                "baseAppJarName": "desktopApp-fixed.jar", "baseAppJarSha256": "c" * 64,
                "baseHelperSha256": "d" * 64, "sourceSha": SOURCE}
        body = "# inert padding\n" * 6000 + "[Console]::Out.WriteLine('SOURCE_EXECUTED')\n"
        with patch.object(scenario, "_public_task", return_value=body):
            command = scenario._bootstrap("11111111-1111-4111-8111-111111111111", pair,
                                          "VPNMSIX64\\vpncp117", "S-1-5-21-1-2-3-1002")
        carriers = re.findall(r"\$body='([^']+)'", command)
        self.assertEqual(len(carriers), 1)
        raw = gzip.decompress(base64.b64decode(carriers[0], validate=True))
        self.assertEqual(raw.decode("utf-16le", errors="strict").encode("utf-16le"), raw)
        register = command.split("$stage='TASK_REGISTER'\n", 1)[1].split("$principal=", 1)[0]
        lines = register.splitlines()
        self.assertEqual(lines[0], "$packed=[Convert]::FromBase64String($body)")
        assignments = [(index, line) for index, line in enumerate(lines) if re.search(r"\$body\s*=", line)]
        actions = [(index, line) for index, line in enumerate(lines) if line.startswith("$action=")]
        self.assertEqual(len(assignments), 1)
        self.assertEqual(len(actions), 1)
        body_index, body_assignment = assignments[0]
        action_index, action_assignment = actions[0]
        self.assertLess(body_index, action_index)
        between = [line for line in lines[body_index + 1:action_index] if line.strip()]
        self.assertIn(between, ([], ["$decompressor.Dispose();$inputStream.Dispose();$outputStream.Dispose()"] ))
        self.assertIn(body_assignment, (
            "$body=[Convert]::ToBase64String($outputStream.ToArray())",
            "$body=[Convert]::ToBase64String($wrapperBytes)",
        ))
        if body_assignment.endswith("($wrapperBytes)"):
            self.assertEqual(lines[:body_index].count(" $wrapperBytes=$outputStream.ToArray()"), 1)
        action = re.fullmatch(r"\$action=New-ScheduledTaskAction -Execute '[^']+' -Argument \('([^']+)'\+\$body\)",
                              action_assignment)
        self.assertIsNotNone(action)
        argument = action.group(1) + base64.b64encode(raw).decode("ascii")
        self.emitted_task_argument_length = len(argument)
        self.emitted_task_argument_sha256 = hashlib.sha256(argument.encode("ascii")).hexdigest()
        self.assertLessEqual(len(argument), 30000)

    def test_fixed_preflight_emitted_carrier_preserves_source_and_command_cap(self) -> None:
        command = scenario._powershell_preflight_script()
        self.preflight_encoded_command_length = len(base64.b64encode(command.encode("utf-16le")))
        self.assertLess(self.preflight_encoded_command_length, 30000)
        carrier = re.search(r"\$packed=\[Convert\]::FromBase64String\('([^']+)'\)", command)
        self.assertIsNotNone(carrier)
        raw = gzip.decompress(base64.b64decode(carrier.group(1), validate=True))
        self.assertIn("$expected=" + str(len(raw)), command)
        self.assertIn(hashlib.sha256(raw).hexdigest(), command)
        probe = raw.decode("utf-8", errors="strict")
        literals = re.search(r"\$bootstrap='((?:[^']|'')*)';\$task='((?:[^']|'')*)'\n", probe)
        self.assertIsNotNone(literals)
        sources = {"bootstrap": literals.group(1).replace("''", "'"),
                   "task": literals.group(2).replace("''", "'")}
        pair = {"targetVersion": "2.2.0", "baseCliSha256": "a" * 64,
                "targetMsiSha256": "b" * 64, "targetMsiSize": 1000,
                "baseAppJarName": "desktopApp-fixed.jar", "baseAppJarSha256": "c" * 64,
                "baseHelperSha256": "d" * 64, "sourceSha": "e" * 40}
        corr = "11111111-1111-4111-8111-111111111111"
        self.assertEqual(sources["bootstrap"], scenario._bootstrap(corr, pair, "VPNMSIX64\\vpncp117", "S-1-5-21-1-2-3-1002"))
        self.assertEqual(sources["task"], scenario._public_task(corr, pair, "S-1-5-21-1-2-3-1002"))
        self.assertIn("Language.Parser]::ParseInput($bootstrap", probe)
        self.assertIn("Language.Parser]::ParseInput($task", probe)

    def test_ps5_preflight_is_fixed_to_owned_guest_and_inert_program(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = types.SimpleNamespace()
            config = types.SimpleNamespace(hosts={"archlinux": target})
            descriptor = ("windows-cp117", "/private/qga.sock", 589342, 520739,
                          "vpncp117", "S-1-5-21-1-2-3-1002", Path("private"))
            with (patch.object(scenario.ssh_transport, "load_config", return_value=config),
                  patch.object(scenario.windows_credential_probe_ssh, "_descriptor", return_value=descriptor),
                  patch.object(scenario.windows_credential_probe_ssh, "_run_ssh",
                               return_value=b'{"state":"passed","checks":["ps5-parse","gzip","utf8-pipeline"]}') as send):
                self.assertEqual("passed", scenario.powershell_preflight(root, {"host": "archlinux"})["state"])
                self.assertEqual(1, send.call_count)
                with self.assertRaises(scenario.WindowsMsiPreinstallStatusError):
                    scenario.powershell_preflight(root, {"host": "other"})
                with self.assertRaises(scenario.WindowsMsiPreinstallStatusError):
                    scenario.powershell_preflight(root, {"host": "archlinux", "script": "updates install"})
            script = scenario._powershell_preflight_script()
            carrier = re.search(r"\$packed=\[Convert\]::FromBase64String\('([^']+)'\)", script)
            self.assertIsNotNone(carrier)
            raw = gzip.decompress(base64.b64decode(carrier.group(1), validate=True))
            self.assertIn(hashlib.sha256(raw).hexdigest(), script)
            script = raw.decode("utf-8", errors="strict")
            literals = re.search(r"\$bootstrap='((?:[^']|'')*)';\$task='((?:[^']|'')*)'\n", script)
            self.assertIsNotNone(literals)
            # These complete source strings are parser inputs, never invoked.
            script = script[:literals.start()] + "$bootstrap='<source>';$task='<source>'\n" + script[literals.end():]
            self.assertIn("[System.Management.Automation.Language.Parser]::ParseInput", script)
            self.assertIn("Set-Content -LiteralPath $leaf -Encoding UTF8", script)
            self.assertNotIn("Start-ScheduledTask", script)
            self.assertNotIn("updates install |", script)

    def test_status_refuses_foreign_original_user_and_false_terminal_claim(self) -> None:
        correlation = "11111111-1111-4111-8111-111111111111"
        intent = {"pair": {"sourceSha": SOURCE, "targetMsiSha256": "c" * 64, "targetVersion": "2.2.0"},
                  "expectedSid": "S-1-5-21-1-2-3-1002"}
        value = {"state": "observed", "dispatchExited": True, "dispatchExitCode": 0, "taskTriggered": True,
                 "requestCode": "ACCEPTED", "requestFinal": False, "requestExit": "0",
                 "taskStage": "OBSERVE", "taskResult": "IN_PROGRESS", "taskCorrelationId": correlation, "taskVersion": 1,
                 "operationId": "33333333-3333-4333-8333-333333333333", "requestId": "44444444-4444-4444-8444-444444444444",
                 "originalSid": "S-1-5-21-1-2-3-9999", "sessionId": 1,
                 "controllerId": correlation, "revision": 0, "targetSha256": "c" * 64,
                 "targetVersion": "2.2.0", "jobId": JOB,
                 "observedOperationId": "33333333-3333-4333-8333-333333333333",
                 "observedControllerId": correlation, "observedJobId": JOB,
                 "observedCode": "ACCEPTED", "observedFinal": False,
                 "protected": {"version": 1, "jobId": JOB, "phase": "Succeeded", "code": "OK", "sequence": 4}}
        self.assertEqual("unknown", scenario._status_result(json.dumps(value).encode(), correlation, intent)["state"])
        value["originalSid"] = intent["expectedSid"]
        terminal = scenario._status_result(json.dumps(value).encode(), correlation, intent)
        self.assertEqual("protected-terminal", terminal["phase"])
        self.assertEqual("verify-installed-target-original-user-return-and-input-cleanup", terminal["nextAction"])
        self.assertEqual(["installed-target", "original-user-return", "input-cleanup"], terminal["remainingVerification"])
        self.assertFalse(terminal["replayAllowed"])
        # A native success receipt supplies no ordinary-owner or cleanup proof.
        with patch.object(scenario, "status", return_value=terminal):
            collected = scenario.collect(Path("."), {})
        self.assertTrue(collected["collected"])
        self.assertFalse(collected["installedVerified"])
        self.assertEqual(terminal["remainingVerification"], collected["remainingVerification"])
        recovered = {**value, "observedControllerId": "55555555-5555-4555-8555-555555555555",
                     "observedOriginControllerId": correlation,
                     "observedOriginRequestId": value["requestId"]}
        self.assertEqual("protected-terminal", scenario._status_result(json.dumps(recovered).encode(), correlation, intent)["phase"])
        recovered["observedOriginRequestId"] = JOB
        self.assertEqual("public-request-observed", scenario._status_result(json.dumps(recovered).encode(), correlation, intent)["phase"])
        conflict = {**value, "journalJobId": "66666666-6666-4666-8666-666666666666"}
        self.assertEqual("unknown", scenario._status_result(json.dumps(conflict).encode(), correlation, intent)["state"])
        for change in ({"requestFinal": True}, {"requestExit": "1"}, {"operationId": None},
                       {"jobId": None}, {"observedOperationId": JOB}, {"observedJobId": None},
                       {"observedCode": "arbitrary"}, {"observedFinal": "false"},
                       {"taskStage": "REQUEST"}, {"requestCode": "ARBITRARY_CODE"}):
            bad = {**value, **change}
            unbound = scenario._status_result(json.dumps(bad).encode(), correlation, intent)
            self.assertEqual("public-request-observed", unbound["phase"])
            self.assertNotIn("remainingVerification", unbound)
        for phase, code in (("Installing", "OK"), ("Failed", "RUNTIME_FAILED"), ("Cancelled", "CANCELLED"), ("Succeeded", "RUNTIME_FAILED")):
            different = {**value, "protected": {**value["protected"], "phase": phase, "code": code}}
            self.assertNotIn("remainingVerification", scenario._status_result(json.dumps(different).encode(), correlation, intent))
        self.assertIn(" --async ", scenario._public_task(correlation, {
            "targetVersion": "2.2.0", "baseCliSha256": "a" * 64,
            "targetMsiSha256": "c" * 64, "targetMsiSize": 1,
        }, intent["expectedSid"]))
        self.assertNotIn("1>", scenario._public_task(correlation, {
            "targetVersion": "2.2.0", "baseCliSha256": "a" * 64,
            "targetMsiSha256": "c" * 64, "targetMsiSize": 1,
        }, intent["expectedSid"]))

    def test_remote_status_rejects_foreign_binding_before_qga(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); corr = "11111111-1111-4111-8111-111111111111"
            stage = root / "windows-cp117" / "windows-msi-public" / corr
            stage.mkdir(parents=True, mode=0o700)
            binding = {"socketPath": "/private/qga.sock", "pid": 589342, "startTicks": 520739,
                       "sourceSha": SOURCE, "artifactIds": ["sha256-" + "a" * 64] * 3,
                       "commandSha256": "b" * 64}
            (stage / "binding.json").write_text(json.dumps(binding))
            output = io.StringIO()
            argv = ["status", str(root), "windows-cp117", corr, "/private/qga.sock", "589342", "520739",
                    "c" * 40, *binding["artifactIds"], binding["commandSha256"]]
            with patch.object(sys, "argv", argv), contextlib.redirect_stdout(output):
                exec(scenario._REMOTE_STATUS, {"__name__": "__main__"})
            self.assertEqual("unknown", json.loads(output.getvalue())["state"])

    def test_remote_status_decodes_powershell_utf16_request_and_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); corr = "11111111-1111-4111-8111-111111111111"
            stage = root / "windows-cp117" / "windows-msi-public" / corr
            stage.mkdir(parents=True, mode=0o700)
            binding = {"socketPath": "/private/qga.sock", "pid": 589342, "startTicks": 520739,
                       "sourceSha": SOURCE, "artifactIds": ["sha256-" + "a" * 64] * 3,
                       "commandSha256": "b" * 64}
            (stage / "binding.json").write_text(json.dumps(binding))
            (stage / "dispatch.json").write_text(json.dumps({"pid": 1234}))
            base = "C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-msi-" + corr + "\\"
            protected_path = "C:\\ProgramData\\vpn-control-install-jobs\\" + JOB + "\\status.json"
            def utf16(value: object) -> bytes:
                return b"\xff\xfe" + json.dumps(value).encode("utf-16le")
            files = {
                base + "task-status.json": utf16({"version": 1, "correlationId": corr, "stage": "OBSERVE", "result": "IN_PROGRESS"}),
                base + "intent.json": utf16({"correlationId": corr, "originalSid": "S-1-5-21-1-2-3-1002", "sessionId": 1,
                    "controllerId": corr, "revision": 0, "targetSha256": "c" * 64, "targetVersion": "2.2.0"}),
                base + "request.json": utf16({"code": "ACCEPTED", "final": False, "operationId": "33333333-3333-4333-8333-333333333333",
                    "requestId": "44444444-4444-4444-8444-444444444444", "data": {}}),
                base + "request.exit": b"0\r\n",
                base + "operation.json": utf16({"operationId": "33333333-3333-4333-8333-333333333333",
                    "controllerId": corr, "jobId": JOB, "code": "ACCEPTED", "final": False}),
                protected_path: utf16({"version": 1, "jobId": JOB, "phase": "Failed", "code": "RUNTIME_FAILED", "sequence": 3}),
            }
            bootstrap = json.dumps({"version": 1, "correlationId": corr, "triggered": True}) + "\n"
            class FakeSocket:
                next_handle = 1
                handles: dict[int, bytes] = {}
                def __init__(self, *args, **kwargs): self.data = bytearray()
                def settimeout(self, value): pass
                def connect(self, value): pass
                def close(self): pass
                def sendall(self, raw):
                    if raw.startswith(b"\xff"):
                        sync = json.loads(raw[1:]); reply = {"return": sync["arguments"]["id"]}
                        self.data.extend(b"\xff" + json.dumps(reply).encode() + b"\n")
                        return
                    request = json.loads(raw); command = request["execute"]; args = request["arguments"]
                    if command == "guest-exec-status":
                        reply = {"return": {"exited": True, "exitcode": 0, "out-data": base64.b64encode(bootstrap.encode()).decode()}}
                    elif command == "guest-file-open":
                        content = files.get(args["path"])
                        if content is None: reply = {"error": {"class": "GenericError"}}
                        else:
                            handle = FakeSocket.next_handle; FakeSocket.next_handle += 1
                            FakeSocket.handles[handle] = content; reply = {"return": handle}
                    elif command == "guest-file-read":
                        content = FakeSocket.handles[args["handle"]]
                        reply = {"return": {"count": len(content), "buf-b64": base64.b64encode(content).decode(), "eof": True}}
                    else: reply = {"return": {}}
                    self.data.extend(json.dumps(reply).encode() + b"\n")
                def recv(self, size):
                    take = min(size, len(self.data)); result = bytes(self.data[:take]); del self.data[:take]
                    return result
            output = io.StringIO()
            argv = ["status", str(root), "windows-cp117", corr, "/private/qga.sock", "589342", "520739",
                    SOURCE, *binding["artifactIds"], binding["commandSha256"]]
            code = scenario._REMOTE_STATUS.replace("if not live(sock,binding['pid'],binding['startTicks']): raise ValueError()", "if False: raise ValueError()")
            with patch("socket.socket", FakeSocket), patch.object(sys, "argv", argv), contextlib.redirect_stdout(output):
                exec(code, {"__name__": "__main__"})
            remote = json.loads(output.getvalue())
            self.assertEqual("0", remote["requestExit"])
            self.assertEqual("ACCEPTED", remote["requestCode"])
            intent = {"pair": {"sourceSha": SOURCE, "targetMsiSha256": "c" * 64, "targetVersion": "2.2.0"},
                      "expectedSid": "S-1-5-21-1-2-3-1002"}
            self.assertEqual("protected-terminal", scenario._status_result(output.getvalue().encode(), corr, intent)["phase"])
            journal_key = json.dumps({"controllerId": corr, "operationId": "33333333-3333-4333-8333-333333333333"},
                                     separators=(",", ":"))
            self.assertEqual("06fe77cd6eab31fd692a3648fed2ed8b7436dc65542efd79f652a340c6950429",
                             _digest(journal_key.encode()))
            journal_path = ("C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\cp166\\state\\.install-correlation-"
                            + _digest(journal_key.encode()) + ".json")
            files.pop(base + "operation.json")
            files[journal_path] = utf16({"version": 1, "controllerId": corr,
                "requestId": "44444444-4444-4444-8444-444444444444",
                "operationId": "33333333-3333-4333-8333-333333333333", "jobId": JOB,
                "workspaceKey": "350953b8f82bd15c413e675b49dd57de2c83b3bce407f68dd352101f0096780c"})
            output = io.StringIO()
            with patch("socket.socket", FakeSocket), patch.object(sys, "argv", argv), contextlib.redirect_stdout(output):
                exec(code, {"__name__": "__main__"})
            journal_remote = json.loads(output.getvalue())
            self.assertEqual(JOB, journal_remote["journalJobId"])
            self.assertEqual("protected-terminal", scenario._status_result(output.getvalue().encode(), corr, intent)["phase"])
            files[journal_path] = utf16({**json.loads(files[journal_path].decode("utf-16")), "requestId": JOB})
            output = io.StringIO()
            with patch("socket.socket", FakeSocket), patch.object(sys, "argv", argv), contextlib.redirect_stdout(output):
                exec(code, {"__name__": "__main__"})
            self.assertEqual("public-request-observed", scenario._status_result(output.getvalue().encode(), corr, intent)["phase"])
            record = json.loads(files[journal_path].decode("utf-16"))
            for bad in ({**record, "workspaceKey": "f" * 64},
                        {**record, "receiptAuthority": "MACOS_USER_LOCAL"}):
                files[journal_path] = utf16(bad)
                output = io.StringIO()
                with patch("socket.socket", FakeSocket), patch.object(sys, "argv", argv), contextlib.redirect_stdout(output):
                    exec(code, {"__name__": "__main__"})
                self.assertEqual("unknown", json.loads(output.getvalue())["state"])

    def test_qga_short_read_without_eof_needs_second_read(self) -> None:
        """Native QGA returned 114 bytes with eof=false for the CP176 status."""
        status = response()
        protected_status = json.dumps(json.loads(status)["status"], separators=(",", ":")).encode()
        replies = iter([
            {"return": 1},
            {"return": {"count": len(protected_status), "buf-b64": base64.b64encode(protected_status).decode(), "eof": False}},
            {"return": {"count": 0, "buf-b64": "", "eof": True}},
            {"return": {}},
            {"error": {"class": "GenericError"}},
        ])

        class FakeSocket:
            def __init__(self, *args, **kwargs): self.data = bytearray()
            def settimeout(self, value): pass
            def connect(self, value): pass
            def close(self): pass
            def sendall(self, raw):
                if raw.startswith(b"\xff"):
                    sync = json.loads(raw[1:])
                    self.data.extend(b"\xff" + json.dumps({"return": sync["arguments"]["id"]}).encode() + b"\n")
                else:
                    command = json.loads(raw)
                    self.data.extend(json.dumps(next(replies)).encode() + b"\n")
            def recv(self, size):
                take = min(size, len(self.data))
                result = bytes(self.data[:take]); del self.data[:take]
                return result

        output = io.StringIO()
        code = scenario._REMOTE_OBSERVE.replace("if not live():", "if False:")
        with (patch("socket.socket", FakeSocket),
              patch.object(sys, "argv", ["observer", "/private/qga.sock", "589342", "520739", JOB]),
              contextlib.redirect_stdout(output)):
            exec(code, {"__name__": "__main__"})
        result = scenario._parse(output.getvalue().encode(), JOB)
        self.assertEqual("observed", result["state"])
        self.assertEqual("Failed", result["phase"])

    def test_exact_job_binds_fixed_diagnostic(self) -> None:
        raw = response(diagnostic={"version": 1, "stage": "EXCLUSIVE_ADMISSION", "kind": "OTHER"})
        self.assertEqual({"stage": "EXCLUSIVE_ADMISSION", "kind": "OTHER"}, scenario._parse(raw, JOB)["diagnostic"])

    def test_mismatched_job_and_unbounded_content_fail_closed(self) -> None:
        other = "11111111-1111-4111-8111-111111111111"
        self.assertEqual("unknown", scenario._parse(response(job=other), JOB)["state"])
        self.assertEqual("unknown", scenario._parse(b"x" * 8193, JOB)["state"])
        self.assertEqual("unknown", scenario._parse(response(diagnostic={"version": 1, "stage": "RAW_PATH", "kind": "OTHER"}), JOB)["state"])
        unsafe = json.loads(response())
        unsafe["status"]["code"] = "C:\\private\\credential"
        self.assertEqual("unknown", scenario._parse(json.dumps(unsafe).encode(), JOB)["state"])

    def test_missing_diagnostic_does_not_infer_admission_cause(self) -> None:
        result = scenario._parse(response(), JOB)
        self.assertEqual("observed", result["state"])
        self.assertEqual("absent-or-unreadable", result["diagnostic"])
        self.assertNotIn("stage", result)

    def test_rejects_noncanonical_job_before_transport(self) -> None:
        with patch.object(scenario.ssh_transport, "load_config") as load:
            with self.assertRaises(scenario.WindowsMsiPreinstallStatusError):
                scenario.preinstall_status(Path("."), "archlinux", JOB.upper())
            load.assert_not_called()

    def test_route_uses_only_configured_guest_and_fixed_program(self) -> None:
        target = types.SimpleNamespace()
        config = types.SimpleNamespace(hosts={"archlinux": target})
        done = subprocess.CompletedProcess([], 0, response(diagnostic={"version": 1, "stage": "INVENTORY", "kind": "WIN32_API"}), b"")
        with (patch.object(scenario.ssh_transport, "load_config", return_value=config),
              patch.object(scenario.windows_credential_probe_ssh, "_descriptor", return_value=("windows-cp117", "/private/qga.sock", 589342, 520739, "account", "sid", Path("private"))),
              patch.object(scenario.ssh_transport, "build_ssh_argv", return_value=["ssh", "fixed-host"]) as argv,
              patch.object(scenario.subprocess, "run", return_value=done)):
            result = scenario.preinstall_status(Path("."), "archlinux", JOB)
        self.assertEqual("observed", result["state"])
        self.assertEqual("INVENTORY", result["diagnostic"]["stage"])
        command = argv.call_args.kwargs["command"]
        self.assertEqual(("/private/qga.sock", "589342", "520739", JOB), command[-4:])
        self.assertNotIn("guest-exec", scenario._REMOTE_OBSERVE)

    def test_rejects_other_windows_environment(self) -> None:
        target = types.SimpleNamespace()
        config = types.SimpleNamespace(hosts={"archlinux": target})
        with (patch.object(scenario.ssh_transport, "load_config", return_value=config),
              patch.object(scenario.windows_credential_probe_ssh, "_descriptor", return_value=("other-guest", "/private/qga.sock", 589342, 520739, "account", "sid", Path("private"))),
              patch.object(scenario.subprocess, "run") as run):
            with self.assertRaises(scenario.WindowsMsiPreinstallStatusError):
                scenario.preinstall_status(Path("."), "archlinux", JOB)
            run.assert_not_called()


_POWERSHELL = os.environ.get("VPN_CONTROL_TEST_PWSH") or shutil.which("pwsh") or shutil.which("powershell")


@unittest.skipUnless(_POWERSHELL, "local PowerShell required for emitted task controls")
class WindowsMsiCompressedTaskTest(unittest.TestCase):
    """Execute only generated carrier bytes and an inert task-action recorder."""

    def run_powershell(self, arguments):
        return subprocess.run([_POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", *arguments],
                              capture_output=True, timeout=15)

    def emitted_argument(self, body):
        pair = {"targetVersion": "2.2.0", "baseCliSha256": "a" * 64,
                "targetMsiSha256": "b" * 64, "targetMsiSize": 1000,
                "baseAppJarName": "desktopApp-fixed.jar", "baseAppJarSha256": "c" * 64,
                "baseHelperSha256": "d" * 64, "sourceSha": SOURCE}
        with patch.object(scenario, "_public_task", return_value=body):
            command = scenario._bootstrap("11111111-1111-4111-8111-111111111111", pair,
                                          "VPNMSIX64\\vpncp117", "S-1-5-21-1-2-3-1002")
        packed = re.search(r"\$body='([^']+)'", command).group(1)
        selected = command.split("$stage='TASK_REGISTER'\n", 1)[1].split("$principal=", 1)[0]
        control = ("$ErrorActionPreference='Stop';$script:ActionCalls=0;"
                   "function New-ScheduledTaskAction {param([string]$Execute,[string]$Argument) "
                   "$script:ActionCalls++;return $Argument};$body='" + packed + "';\n" + selected +
                   "[Console]::Out.WriteLine(([ordered]@{argument=$action;calls=$script:ActionCalls}|ConvertTo-Json -Compress))")
        result = self.run_powershell(["-Command", control])
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        value = json.loads(result.stdout)
        self.assertEqual(value["calls"], 1)
        return value["argument"]

    def invoke_argument(self, argument):
        return subprocess.run([_POWERSHELL, "-NoLogo", *argument.split()],
                              capture_output=True, timeout=15)

    def test_actual_emitted_scheduled_task_argument_stays_below_cap(self):
        body = "# inert padding\n" * 6000 + "[Console]::Out.WriteLine('SOURCE_EXECUTED')\n"
        argument = self.emitted_argument(body)
        self.assertLessEqual(len(argument), 30000)
        result = self.invoke_argument(argument)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stdout.decode().strip(), "SOURCE_EXECUTED")

    def test_actual_emitted_unicode_body_invokes_once(self):
        body = ("[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n"
                "[Console]::Out.WriteLine('SOURCE_EXECUTED:π✓')\n")
        result = self.invoke_argument(self.emitted_argument(body))
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stdout.decode("utf-8").splitlines(), ["SOURCE_EXECUTED:π✓"])

    def test_actual_emitted_tampered_body_refused_before_invocation(self):
        body = "[Console]::Out.WriteLine('SOURCE_EXECUTED')\n# original\n"
        argument = self.emitted_argument(body)
        prefix, encoded = argument.rsplit(" ", 1)
        original = base64.b64decode(encoded, validate=True).decode("utf-16le")
        inner = re.search(r"\$packed=\[Convert\]::FromBase64String\('([^']+)'\)", original)
        variants = (body.replace("original", "tampered"), body[:-1], body + "# extra\n")
        for changed in variants:
            with self.subTest(byteLength=len(changed.encode("utf-8"))):
                if inner:
                    packed = base64.b64encode(gzip.compress(changed.encode("utf-8"), mtime=0)).decode()
                    altered = original.replace(inner.group(1), packed, 1)
                else:
                    self.assertEqual(original, body)
                    altered = changed
                altered_arg = prefix + " " + base64.b64encode(altered.encode("utf-16le")).decode()
                result = self.invoke_argument(altered_arg)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(b"SOURCE_EXECUTED", result.stdout)

    def test_actual_emitted_invalid_utf8_and_parser_fail_before_invocation(self):
        body = "[Console]::Out.WriteLine('SOURCE_EXECUTED')\n"
        argument = self.emitted_argument(body)
        prefix, encoded = argument.rsplit(" ", 1)
        wrapper = base64.b64decode(encoded, validate=True).decode("utf-16le")
        inner = re.search(r"\$packed=\[Convert\]::FromBase64String\('([^']+)'\)", wrapper)
        self.assertIsNotNone(inner)
        for raw in (b"\xff", b"[Console]::Out.WriteLine('SOURCE_EXECUTED')\n}"):
            with self.subTest(raw=raw):
                packed = base64.b64encode(gzip.compress(raw, mtime=0)).decode()
                altered = wrapper.replace(inner.group(1), packed, 1)
                altered = re.sub(r"\$expected=[0-9]+", "$expected=" + str(len(raw)), altered, count=1)
                altered = re.sub(r"\$actual -cne '[0-9a-f]{64}'", "$actual -cne '" + hashlib.sha256(raw).hexdigest() + "'", altered, count=1)
                altered_arg = prefix + " " + base64.b64encode(altered.encode("utf-16le")).decode()
                result = self.invoke_argument(altered_arg)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(b"SOURCE_EXECUTED", result.stdout)


if __name__ == "__main__":
    unittest.main()
