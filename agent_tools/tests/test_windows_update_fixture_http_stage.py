"""Deterministic regressions for the CP117 fixture ZIP HTTP transport."""
from __future__ import annotations

import hashlib
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
from urllib.request import urlopen

from agent_tools import windows_update_fixture_http_stage as http_stage


CORRELATION = "03de8469-bcb2-49e4-a710-a3c4d1db3f64"
SOURCE = "a" * 40
ARTIFACT = "sha256-" + "b" * 64


class FixtureHttpStageTests(unittest.TestCase):
    def request(self):
        return {"host": "archlinux", "correlationId": CORRELATION, "sourceSha": SOURCE,
                "fixtureReceiptArtifactId": ARTIFACT, "baseMsiArtifactId": ARTIFACT,
                "targetMsiArtifactId": ARTIFACT}

    def remote_args(self, directory, digest, length):
        binding = {"correlationId": CORRELATION, "socketPath": "/qga", "pid": 1, "startTicks": 2,
                   "leaseId": "24b6d975-6e5c-4c3c-b85e-c02f4d6d8926", "sourceSha": SOURCE,
                   "sourceFingerprint": "d" * 64, "bundleSha256": digest,
                   "expectedSid": "S-1-5-21-1-2-3-1002", "fixtureReceiptArtifactId": ARTIFACT,
                   "baseMsiArtifactId": ARTIFACT, "targetMsiArtifactId": ARTIFACT}
        return (directory, CORRELATION, digest, str(length),
                base64.b64encode(json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()).decode())

    def test_remote_stage_accepts_exact_bytes_once_and_never_overwrites(self):
        payload = b"fixture-bundle"; digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            args = self.remote_args(directory, digest, len(payload))
            done = subprocess.run([sys.executable, "-c", http_stage._REMOTE_STAGE, *args], input=payload,
                                  capture_output=True, check=False, timeout=10)
            self.assertEqual(0, done.returncode)
            self.assertEqual({"state": "staged", "sha256": digest, "length": len(payload)}, json.loads(done.stdout))
            authority = Path(directory) / "windows-cp117" / "windows-update-fixture-stage" / CORRELATION
            self.assertEqual(digest, json.loads((authority / "binding.json").read_text())["bundleSha256"])
            self.assertFalse((authority / "dispatch.json").exists())
            repeated = subprocess.run([sys.executable, "-c", http_stage._REMOTE_STAGE, *args], input=payload,
                                      capture_output=True, check=False, timeout=10)
            self.assertEqual({"state": "unknown"}, json.loads(repeated.stdout))

    def test_remote_stage_rejects_truncated_and_hash_mismatch_without_success_receipt(self):
        payload = b"fixture-bundle"; digest = hashlib.sha256(payload).hexdigest()
        for sent in (payload[:-1], b"x" * len(payload)):
            with self.subTest(sent=sent), tempfile.TemporaryDirectory() as directory:
                done = subprocess.run([sys.executable, "-c", http_stage._REMOTE_STAGE,
                                       *self.remote_args(directory, digest, len(payload))], input=sent,
                                      capture_output=True, check=False, timeout=10)
                self.assertEqual({"state": "unknown"}, json.loads(done.stdout))
                stage = Path(directory) / "windows-cp117" / "windows-update-fixture-http-stage" / CORRELATION
                self.assertFalse((stage / "binding.json").exists())

    def test_remote_stage_fails_closed_for_symlink_parent(self):
        payload = b"fixture-bundle"; digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory); (root / "windows-cp117").symlink_to(outside, target_is_directory=True)
            done = subprocess.run([sys.executable, "-c", http_stage._REMOTE_STAGE,
                                   *self.remote_args(directory, digest, len(payload))], input=payload,
                                  capture_output=True, check=False, timeout=10)
            self.assertEqual({"state": "unknown"}, json.loads(done.stdout))
            self.assertEqual([], list(Path(outside).iterdir()))

    def test_status_never_creates_a_journal_and_projects_only_exact_remote_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual("unknown", http_stage.status(root, {"correlationId": CORRELATION})["state"])
            self.assertFalse((root / http_stage._GROUP).exists())
        record = {"bundleSha256": "c" * 64, "bundleSize": 7}
        self.assertEqual("staged", http_stage.project_remote_stage(
            b'{"state":"staged","sha256":"' + b"c" * 64 + b'","length":7}', record)["state"])
        self.assertEqual("unknown", http_stage.project_remote_stage(
            b'{"state":"staged","sha256":"' + b"c" * 64 + b'","length":7,"extra":1}', record)["state"])

    def test_workflow_allows_only_frozen_prepare_or_correlation_phase_dispatch(self):
        with mock.patch.object(http_stage, "prepare", return_value={"state":"prepared"}) as prepare:
            self.assertEqual("prepared", http_stage.workflow(Path.cwd(), "prepare", self.request())["state"])
            prepare.assert_called_once_with(Path.cwd(), self.request())
        status = mock.Mock(return_value={"state":"listening"})
        with mock.patch.dict(http_stage._PHASES, {"listener-status": status}):
            self.assertEqual("listening", http_stage.workflow(Path.cwd(), "listener-status", {"correlationId":CORRELATION})["state"])
            status.assert_called_once_with(Path.cwd(), {"correlationId":CORRELATION})
        with self.assertRaises(http_stage.WindowsUpdateFixtureHttpStageError):
            http_stage.workflow(Path.cwd(), "guest-download", {"correlationId":CORRELATION,"port":1})

    def test_prepare_diagnostic_classifies_pre_effect_admission_without_reservation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (mock.patch.object(http_stage.stage.public, "_admit_pair", side_effect=ValueError("bad source")),
                  mock.patch.object(http_stage.base, "_descriptor", side_effect=AssertionError("no VM read after source failure")),
                  mock.patch.object(http_stage.stage, "_reserve", side_effect=AssertionError("must not reserve")),
                  mock.patch.object(http_stage.stage.campaign_lease, "claim_role", side_effect=AssertionError("must not claim"))):
                result = http_stage.prepare_diagnostic(root, self.request())
            self.assertEqual({"state":"diagnosed", "correlationId":CORRELATION, "phase":"source-unadmitted",
                              "preEffect":True, "replayAllowed":False, "nativeActionAllowed":False,
                              "productAction":False}, result)
            self.assertFalse((root / http_stage._GROUP).exists())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); target = object(); descriptor = ("windows-cp117", "/qga", 1, 2, "S-1-5-21-1-2-3-1002")
            campaign = root / http_stage.stage.campaign_lease._DIR; campaign.mkdir(parents=True); campaign.chmod(0o700)
            lease = "24b6d975-6e5c-4c3c-b85e-c02f4d6d8926"
            identity = http_stage.base._campaign_identity({**self.request(), "correlationId": lease}, descriptor)
            with (mock.patch.object(http_stage.stage.public, "_admit_pair", return_value={"sourceFingerprint":"d" * 64}),
                  mock.patch.object(http_stage.base, "_descriptor", return_value=(object(), target, descriptor)),
                  mock.patch.object(http_stage.stage.campaign_lease, "_active", return_value={"identity":identity,"state":"active","role":None,"server":"stopped","credentials":"absent"}),
                  mock.patch.object(http_stage.stage, "_reserve", side_effect=AssertionError("must not reserve"))):
                self.assertEqual("ready-to-reserve", http_stage.workflow(root, "prepare-diagnostic", self.request())["phase"])

    def test_bundle_diagnostic_executes_and_closes_source_bundle_without_reserving(self):
        stream = mock.Mock()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (mock.patch.object(http_stage.stage.public, "_admit_pair", return_value={"sourceFingerprint":"d" * 64}),
                  mock.patch.object(http_stage.stage, "_bundle", return_value=(stream, {"entry":"e" * 64}, 7, "f" * 64)) as bundle,
                  mock.patch.object(http_stage.stage, "_reserve", side_effect=AssertionError("must not reserve")),
                  mock.patch.object(http_stage.stage.campaign_lease, "claim_role", side_effect=AssertionError("must not claim")),
                  mock.patch.object(http_stage.base, "_descriptor", side_effect=AssertionError("must not inspect VM"))):
                self.assertEqual("bundle-ready", http_stage.workflow(root, "bundle-diagnostic", self.request())["phase"])
            bundle.assert_called_once()
            stream.close.assert_called_once()
        with tempfile.TemporaryDirectory() as directory:
            with (mock.patch.object(http_stage.stage.public, "_admit_pair", return_value={"sourceFingerprint":"d" * 64}),
                  mock.patch.object(http_stage.stage, "_bundle", side_effect=ValueError("source module missing"))):
                self.assertEqual("bundle-unbuildable", http_stage.bundle_diagnostic(Path(directory), self.request())["phase"])

    def test_reserve_diagnostic_reports_prior_stage_without_confirming_or_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); target = object(); descriptor = ("windows-cp117", "/qga", 1, 2, "S-1-5-21-1-2-3-1002")
            campaign = root / http_stage.stage.campaign_lease._DIR; campaign.mkdir(parents=True); campaign.chmod(0o700)
            lease = "24b6d975-6e5c-4c3c-b85e-c02f4d6d8926"
            identity = http_stage.base._campaign_identity({**self.request(), "correlationId": lease}, descriptor)
            history = root / http_stage.stage._GROUP; history.mkdir(); history.chmod(0o700)
            old = "00000000-0000-4000-8000-000000000000"; (history / (old + ".json")).write_text("{}")
            with (mock.patch.object(http_stage.base, "_descriptor", return_value=(object(), target, descriptor)),
                  mock.patch.object(http_stage.stage.campaign_lease, "_active", return_value={"identity":identity,"state":"active","role":None,"server":"stopped","credentials":"absent"}),
                  mock.patch.object(http_stage.stage, "_read_intent", return_value={"leaseId":"old"}) as read_intent,
                  mock.patch.object(http_stage.stage, "_closed_stage_history", side_effect=AssertionError("must not contact fixture host")),
                  mock.patch.object(http_stage.stage, "_reserve", side_effect=AssertionError("must not reserve"))):
                result = http_stage.workflow(root, "reserve-diagnostic", self.request())
            self.assertEqual("prior-stage-needs-confirmation", result["phase"])
            read_intent.assert_called_once_with(root.resolve(), old)
            self.assertFalse((root / http_stage._GROUP / CORRELATION).exists())

    def test_prior_stage_confirmation_reports_remote_closure_without_new_reservation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); history = root / http_stage.stage._GROUP; history.mkdir(parents=True); history.chmod(0o700)
            old = "00000000-0000-4000-8000-000000000000"; (history / (old + ".json")).write_text("{}")
            with (mock.patch.object(http_stage.stage, "_read_intent", return_value={"leaseId":"old"}),
                  mock.patch.object(http_stage.stage.public, "_admit_pair", return_value={"sourceFingerprint":"d" * 64}),
                  mock.patch.object(http_stage.base, "_descriptor", return_value=(object(), object(), ("windows-cp117","/qga",1,2,"S-1-5-21-1-2-3-1002"))),
                  mock.patch.object(http_stage.stage, "_require_cross_route_lease", return_value="24b6d975-6e5c-4c3c-b85e-c02f4d6d8926"),
                  mock.patch.object(http_stage.stage, "_closed_stage_history_detail", return_value="confirmed") as confirm,
                  mock.patch.object(http_stage.stage, "_reserve", side_effect=AssertionError("must not reserve"))):
                self.assertEqual("confirmed", http_stage.prior_stage_confirmation(root, self.request())["phase"])
            confirm.assert_called_once_with(root.resolve(), "24b6d975-6e5c-4c3c-b85e-c02f4d6d8926")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); history = root / http_stage.stage._GROUP; history.mkdir(parents=True); history.chmod(0o700)
            old = "00000000-0000-4000-8000-000000000000"; (history / (old + ".json")).write_text("{}")
            with (mock.patch.object(http_stage.stage, "_read_intent", return_value={"leaseId":"old"}),
                  mock.patch.object(http_stage.stage.public, "_admit_pair", return_value={"sourceFingerprint":"d" * 64}),
                  mock.patch.object(http_stage.base, "_descriptor", return_value=(object(), object(), ("windows-cp117","/qga",1,2,"S-1-5-21-1-2-3-1002"))),
                  mock.patch.object(http_stage.stage, "_require_cross_route_lease", return_value="24b6d975-6e5c-4c3c-b85e-c02f4d6d8926"),
                  mock.patch.object(http_stage.stage, "_closed_stage_history_detail", return_value="remote-status-mismatch")):
                self.assertEqual("remote-status-mismatch", http_stage.prior_stage_confirmation(root, self.request())["phase"])

    def test_record_rejects_stale_source_lease_or_vm_before_any_dispatch(self):
        record = {"request": self.request(), "leaseId": "24b6d975-6e5c-4c3c-b85e-c02f4d6d8926",
                  "bundlePath": "/private/bundle.zip", "bundleSha256": "e" * 64, "bundleSize": 7,
                  "routeNonce": "x" * 32, "sourceFingerprint": "d" * 64}
        intent = {"request": self.request(), "leaseId": record["leaseId"], "sourceFingerprint": "d" * 64,
                  "bundleSha256": "e" * 64, "bundleSize": 7, "environment": "windows-cp117",
                  "socketPath": "/qga", "pid": 1, "startTicks": 2, "expectedSid": "S-1-5-21-1-2-3-1002"}
        target = mock.Mock()
        with (mock.patch.object(http_stage, "_read", return_value=record), mock.patch.object(http_stage, "_artifact"),
              mock.patch.object(http_stage.stage.public, "_admit_pair", return_value={"sourceFingerprint":"d" * 64}),
              mock.patch.object(http_stage.base, "_descriptor", return_value=(object(), target, ("windows-cp117","/qga",1,2,"S-1-5-21-1-2-3-1002"))),
              mock.patch.object(http_stage.large_transfer, "read", return_value={"binding": http_stage._large_binding(record, ("windows-cp117","/qga",1,2,"S-1-5-21-1-2-3-1002")), "sha256":"e" * 64, "length":7}),
              mock.patch.object(http_stage.stage, "_read_intent", return_value={**intent,"leaseId":"00000000-0000-4000-8000-000000000000"}),
              mock.patch.object(http_stage.stage, "_require_cross_route_lease", side_effect=AssertionError("must not claim stale intent"))):
            with self.assertRaises(http_stage.WindowsUpdateFixtureHttpStageError):
                http_stage._record(Path.cwd(), CORRELATION)

    def test_stage_start_diagnostic_reaches_host_boundary_for_prepared_claimed_stage_without_dispatch(self):
        record = {"request": self.request(), "leaseId": "24b6d975-6e5c-4c3c-b85e-c02f4d6d8926",
                  "bundlePath": "/private/bundle.zip", "bundleSha256": "e" * 64, "bundleSize": 7,
                  "routeNonce": "x" * 32, "sourceFingerprint": "d" * 64}
        descriptor = ("windows-cp117", "/qga", 1, 2, "S-1-5-21-1-2-3-1002")
        intent = {"request": self.request(), "leaseId": record["leaseId"], "sourceFingerprint": "d" * 64,
                  "bundleSha256": "e" * 64, "bundleSize": 7, "environment": descriptor[0],
                  "socketPath": descriptor[1], "pid": descriptor[2], "startTicks": descriptor[3],
                  "expectedSid": descriptor[4]}
        # Targets loaded from configuration commonly expose this as a string;
        # stage_start itself passes ``str(...)`` to the fixed host program.
        target = mock.Mock(fixture_transfer_root="/fixture")
        core = {"binding": http_stage._large_binding(record, descriptor), "sha256": "e" * 64,
                "length": 7, "phase": "prepared"}
        with (mock.patch.object(http_stage, "_read", return_value=record),
              mock.patch.object(http_stage, "_artifact"),
              mock.patch.object(http_stage.stage.public, "_admit_pair", return_value={"sourceFingerprint": "d" * 64}),
              mock.patch.object(http_stage.base, "_descriptor", return_value=(object(), target, descriptor)),
              mock.patch.object(http_stage.stage, "_read_intent", return_value=intent),
              mock.patch.object(http_stage.large_transfer, "read", return_value=core),
              mock.patch.object(http_stage.base, "_verified_claimed_campaign") as claimed,
              mock.patch.object(http_stage, "_large_advance", side_effect=AssertionError("must not reserve")),
              mock.patch.object(http_stage.base, "_remote", side_effect=AssertionError("must not deliver"))):
            result = http_stage.workflow(Path.cwd(), "stage-start-diagnostic", {"correlationId": CORRELATION})
        self.assertEqual("remote-host-next", result["phase"])
        self.assertTrue(result["preEffect"])
        claimed.assert_called_once()

    def test_stage_start_diagnostic_rejects_a_mismatched_claimed_role_before_dispatch(self):
        record = {"request": self.request(), "leaseId": "24b6d975-6e5c-4c3c-b85e-c02f4d6d8926",
                  "bundlePath": "/private/bundle.zip", "bundleSha256": "e" * 64, "bundleSize": 7,
                  "routeNonce": "x" * 32, "sourceFingerprint": "d" * 64}
        descriptor = ("windows-cp117", "/qga", 1, 2, "S-1-5-21-1-2-3-1002")
        intent = {"request": self.request(), "leaseId": record["leaseId"], "sourceFingerprint": "d" * 64,
                  "bundleSha256": "e" * 64, "bundleSize": 7, "environment": descriptor[0],
                  "socketPath": descriptor[1], "pid": descriptor[2], "startTicks": descriptor[3],
                  "expectedSid": descriptor[4]}
        target = mock.Mock(fixture_transfer_root=Path("/fixture"))
        core = {"binding": http_stage._large_binding(record, descriptor), "sha256": "e" * 64,
                "length": 7, "phase": "prepared"}
        with (mock.patch.object(http_stage, "_read", return_value=record),
              mock.patch.object(http_stage, "_artifact"),
              mock.patch.object(http_stage.stage.public, "_admit_pair", return_value={"sourceFingerprint": "d" * 64}),
              mock.patch.object(http_stage.base, "_descriptor", return_value=(object(), target, descriptor)),
              mock.patch.object(http_stage.stage, "_read_intent", return_value=intent),
              mock.patch.object(http_stage.large_transfer, "read", return_value=core),
              mock.patch.object(http_stage.base, "_verified_claimed_campaign",
                                side_effect=http_stage.base.WindowsMsiBasePrepareError("wrong role")),
              mock.patch.object(http_stage, "_large_advance", side_effect=AssertionError("must not reserve")),
              mock.patch.object(http_stage.base, "_remote", side_effect=AssertionError("must not deliver"))):
            result = http_stage.stage_start_diagnostic(Path.cwd(), {"correlationId": CORRELATION})
        self.assertEqual("campaign-not-claimed", result["phase"])

    def test_repeated_phase_reservation_blocks_effect_before_remote_dispatch(self):
        record = {"request": self.request(), "leaseId": "24b6d975-6e5c-4c3c-b85e-c02f4d6d8926",
                  "bundlePath": "/private/bundle.zip", "bundleSha256": "e" * 64, "bundleSize": 7,
                  "routeNonce": "x" * 32, "sourceFingerprint": "d" * 64}
        target = mock.Mock(fixture_transfer_root=Path("/fixture"))
        descriptor = ("windows-cp117", "/qga", 1, 2, "S-1-5-21-1-2-3-1002")
        with (mock.patch.object(http_stage, "_record", return_value=(Path.cwd(), record, object(), target)),
              mock.patch.object(http_stage.base, "_descriptor", return_value=(object(), target, descriptor)),
              mock.patch.object(http_stage, "host_stage_probe", return_value={"phase": "host-stage-complete", "listenerStartAllowed": True}),
              mock.patch.object(http_stage, "_large_advance", return_value=False),
              mock.patch.object(http_stage.base, "_remote") as remote,
              mock.patch("builtins.open", mock.mock_open(read_data=b"bundle"))):
            self.assertEqual("unknown", http_stage.stage_start(Path.cwd(), {"correlationId":CORRELATION})["state"])
            self.assertEqual("unknown", http_stage.listener_start(Path.cwd(), {"correlationId":CORRELATION})["state"])
            self.assertEqual("unknown", http_stage.guest_create(Path.cwd(), {"correlationId":CORRELATION})["state"])
            remote.assert_not_called()

    def test_guest_create_diagnostic_classifies_absent_leaf_without_create_dispatch(self):
        record = {"request": self.request(), "leaseId": "24b6d975-6e5c-4c3c-b85e-c02f4d6d8926",
                  "bundlePath": "/private/bundle.zip", "bundleSha256": "e" * 64, "bundleSize": 7,
                  "routeNonce": "x" * 32, "sourceFingerprint": "d" * 64}
        descriptor = ("windows-cp117", "/qga", 1, 2, "S-1-5-21-1-2-3-1002")
        config = object()
        with (mock.patch.object(http_stage, "_record", return_value=(Path.cwd(), record, config, object())) as record_read,
              mock.patch.object(http_stage.base, "_descriptor", return_value=(object(), object(), descriptor)),
              mock.patch.object(http_stage.large_transfer, "read", return_value={"phase": "guest-created"}),
              mock.patch.object(http_stage.base, "_remote", return_value=b'{"interpreter":"absent","state":"leaf-absent"}') as remote,
              mock.patch.object(http_stage, "_large_advance", side_effect=AssertionError("must not reserve")),
              mock.patch.object(http_stage, "_qga_action", side_effect=AssertionError("must not create"))):
            result = http_stage.workflow(Path.cwd(), "guest-create-diagnostic", {"correlationId": CORRELATION})
        self.assertEqual({"state": "diagnosed", "correlationId": CORRELATION, "preEffect": True,
                          "replayAllowed": False, "nativeActionAllowed": False, "productAction": False,
                          "phase": "guest-create-not-confirmed-leaf-absent", "interpreter": "absent"}, result)
        record_read.assert_called_once_with(Path.cwd(), CORRELATION)
        self.assertEqual(http_stage._REMOTE_QGA_GUEST_CREATE_DIAGNOSTIC, remote.call_args.args[1])

    def test_guest_create_diagnostic_keeps_interpreter_schema_for_noneligible_or_malformed_observation(self):
        record = {"request": self.request(), "leaseId": "24b6d975-6e5c-4c3c-b85e-c02f4d6d8926",
                  "bundlePath": "/private/bundle.zip", "bundleSha256": "e" * 64, "bundleSize": 7,
                  "routeNonce": "x" * 32, "sourceFingerprint": "d" * 64}
        descriptor = ("windows-cp117", "/qga", 1, 2, "S-1-5-21-1-2-3-1002")
        with mock.patch.object(http_stage, "_record", return_value=(Path.cwd(), record, object(), object())):
            with mock.patch.object(http_stage.large_transfer, "read", return_value={"phase": "listening"}):
                noneligible = http_stage.guest_create_diagnostic(Path.cwd(), {"correlationId": CORRELATION})
        self.assertEqual("not-guest-created", noneligible["phase"])
        self.assertEqual("unknown", noneligible["interpreter"])
        with (mock.patch.object(http_stage, "_record", return_value=(Path.cwd(), record, object(), object())),
              mock.patch.object(http_stage.base, "_descriptor", return_value=(object(), object(), descriptor)),
              mock.patch.object(http_stage.large_transfer, "read", return_value={"phase": "guest-created"}),
              mock.patch.object(http_stage.base, "_remote", return_value=b'{"interpreter":"surprise","state":"leaf-absent"}')):
            malformed = http_stage.guest_create_diagnostic(Path.cwd(), {"correlationId": CORRELATION})
        self.assertEqual("unknown", malformed["phase"])
        self.assertEqual("unknown", malformed["interpreter"])

    def test_guest_create_diagnostic_projects_acl_or_ancestor_construction_failures_without_dispatch(self):
        record = {"request": self.request(), "leaseId": "24b6d975-6e5c-4c3c-b85e-c02f4d6d8926",
                  "bundlePath": "/private/bundle.zip", "bundleSha256": "e" * 64, "bundleSize": 7,
                  "routeNonce": "x" * 32, "sourceFingerprint": "d" * 64}
        descriptor = ("windows-cp117", "/qga", 1, 2, "S-1-5-21-1-2-3-1002")
        for state in ("acl-construction-failed", "ancestor-reparse", "ancestor-type"):
            with (
                self.subTest(state=state),
                mock.patch.object(http_stage, "_record", return_value=(Path.cwd(), record, object(), object())),
                mock.patch.object(http_stage.base, "_descriptor", return_value=(object(), object(), descriptor)),
                mock.patch.object(http_stage.large_transfer, "read", return_value={"phase": "guest-created"}),
                mock.patch.object(http_stage.base, "_remote", return_value=json.dumps({"state": state, "interpreter": "absent"}).encode()),
                mock.patch.object(http_stage, "_large_advance", side_effect=AssertionError("must not reserve")),
                mock.patch.object(http_stage, "_qga_action", side_effect=AssertionError("must not create"))):
                result = http_stage.guest_create_diagnostic(Path.cwd(), {"correlationId": CORRELATION})
            self.assertEqual("guest-create-not-confirmed-" + state, result["phase"])
            self.assertEqual("absent", result["interpreter"])
        script = http_stage._guest_create_diagnostic_script(CORRELATION, descriptor[4], "Write-Output test")
        self.assertIn("DirectorySecurity", script)
        self.assertIn("FileSystemAccessRule", script)
        self.assertIn("ancestor-reparse", script)
        self.assertIn("$item=Get-Item -LiteralPath $current -Force -ErrorAction Stop", script)
        self.assertNotIn("$item=$item.Parent", script)
        self.assertIn("$_.ProcessId -ne $PID", script)
        self.assertNotIn("CommandLine -match", script)

    def test_guest_create_diagnostic_never_projects_absent_when_encoded_create_interpreter_is_live(self):
        record = {"request": self.request(), "leaseId": "24b6d975-6e5c-4c3c-b85e-c02f4d6d8926",
                  "bundlePath": "/private/bundle.zip", "bundleSha256": "e" * 64, "bundleSize": 7,
                  "routeNonce": "x" * 32, "sourceFingerprint": "d" * 64}
        descriptor = ("windows-cp117", "/qga", 1, 2, "S-1-5-21-1-2-3-1002")
        with (mock.patch.object(http_stage, "_record", return_value=(Path.cwd(), record, object(), object())),
              mock.patch.object(http_stage.base, "_descriptor", return_value=(object(), object(), descriptor)),
              mock.patch.object(http_stage.large_transfer, "read", return_value={"phase": "guest-created"}),
              # A QGA child uses -EncodedCommand, so its raw correlation is unavailable to a process census.
              mock.patch.object(http_stage.base, "_remote", return_value=b'{"interpreter":"present","state":"leaf-absent"}')):
            result = http_stage.guest_create_diagnostic(Path.cwd(), {"correlationId": CORRELATION})
        self.assertEqual("present", result["interpreter"])
        self.assertNotEqual("absent", result["interpreter"])

    def test_prepare_freezes_exact_bundle_once_without_guest_or_campaign_mutation(self):
        payload = b"zip-content"; digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = tempfile.TemporaryFile(mode="w+b"); bundle.write(payload); bundle.seek(0)
            pair = {"sourceFingerprint": "d" * 64}
            with (mock.patch.object(http_stage.stage.public, "_admit_pair", return_value=pair),
                  mock.patch.object(http_stage.stage, "_bundle", return_value=(bundle, {}, len(payload), digest)),
                  mock.patch.object(http_stage.base, "_descriptor", return_value=(object(), object(), ("windows-cp117", "/qga", 1, 2, "S-1-5-21-1-2-3-1002"))),
                  mock.patch.object(http_stage.stage, "_require_cross_route_lease", return_value="24b6d975-6e5c-4c3c-b85e-c02f4d6d8926") as lease,
                  mock.patch.object(http_stage.stage.campaign_lease, "claim_role", return_value={"state":"role-active"}),
                  mock.patch.object(http_stage.stage, "_reserve", side_effect=lambda _root, _record, stream: (root / "stage.zip"))):
                (root / "stage.zip").write_bytes(payload)
                result = http_stage.prepare(root, self.request())
                self.assertEqual("prepared", result["state"])
                shared = http_stage.large_transfer.read(root, CORRELATION)
                self.assertEqual("fixture-zip", shared["binding"]["kind"])
                self.assertEqual(digest, shared["sha256"])
                self.assertEqual(payload, (root / "stage.zip").read_bytes())
                self.assertEqual("unknown", http_stage.prepare(root, self.request())["state"])
                self.assertEqual(1, lease.call_count)

    def test_ps5_preflight_rejects_unsafe_here_string_and_is_parser_checkable(self):
        program = http_stage.ps5_preflight_script("$x=1;[Console]::Out.WriteLine($x)")
        self.assertIn("[scriptblock]::Create", program)
        with self.assertRaises(http_stage.WindowsUpdateFixtureHttpStageError):
            http_stage.ps5_preflight_script("'@")

    def test_guest_scripts_are_small_exact_bound_and_preflightable(self):
        script = http_stage.guest_download_script(correlation_id=CORRELATION,
            sid="S-1-5-21-1-2-3-1002", sha256="e" * 64, length=131218059,
            port=4567, path="/" + "x" * 32)
        self.assertIn("$corr='" + CORRELATION + "'", script)
        self.assertIn("$port=4567", script)
        self.assertLess(len(script.encode("utf-16le")), 28000)
        self.assertIn("[scriptblock]::Create", http_stage.ps5_preflight_script(script))
        status = http_stage.guest_status_script(correlation_id=CORRELATION, sha256="e" * 64, length=131218059)
        self.assertIn("hash-mismatch", status)
        self.assertIn("\\download\\bundle.zip", status)
        self.assertIn("Join-Path $root 'download'", http_stage.stage._create_script(CORRELATION, "S-1-5-21-1-2-3-1002"))
        self.assertIn("Move-Item -LiteralPath $incoming -Destination $archive", http_stage.stage._stage_script(
            CORRELATION, "S-1-5-21-1-2-3-1002", {}, "e" * 64))
        with self.assertRaises(http_stage.WindowsUpdateFixtureHttpStageError):
            http_stage.guest_download_script(correlation_id=CORRELATION, sid="wrong", sha256="e" * 64,
                                             length=1, port=1, path="/" + "x" * 32)

    def test_one_use_listener_serves_only_the_exact_bundle(self):
        payload = b"listener-zip"; digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory); bundle = stage / "bundle.zip"; bundle.write_bytes(payload); bundle.chmod(0o600)
            process = subprocess.Popen([sys.executable, "-c", http_stage._HTTP_WORKER, directory], stdin=subprocess.PIPE)
            assert process.stdin is not None
            process.stdin.write(json.dumps({"path": "/" + "a" * 32, "sha256": digest, "length": len(payload)}).encode())
            process.stdin.close()
            for _ in range(100):
                ready = stage / "listener-ready.json"
                if ready.exists(): break
                threading.Event().wait(.01)
            info = json.loads(ready.read_text())
            self.assertEqual(payload, urlopen("http://127.0.0.1:" + str(info["port"]) + "/" + "a" * 32, timeout=5).read())
            self.assertEqual(0, process.wait(timeout=5))
            self.assertEqual({"served": True}, json.loads((stage / "listener-done.json").read_text()))

    def test_lifecycle_wrappers_project_exact_receipts_and_cleanup_needs_terminal_listener(self):
        record = {"request": self.request(), "leaseId": "24b6d975-6e5c-4c3c-b85e-c02f4d6d8926",
                  "bundlePath": "/private/bundle.zip", "bundleSha256": "e" * 64,
                  "bundleSize": 7, "routeNonce": "x" * 32, "sourceFingerprint": "d" * 64}
        target = mock.Mock(fixture_transfer_root=Path("/fixture"))
        with (mock.patch.object(http_stage, "_record", return_value=(Path.cwd(), record, object(), target)),
              mock.patch.object(http_stage.base, "_descriptor", return_value=(object(), target, ("windows-cp117", "/qga", 1, 2, "S-1-5-21-1-2-3-1002"))),
              mock.patch.object(http_stage, "_large_advance", return_value=True),
              mock.patch.object(http_stage.base, "_remote", return_value=b'{"state":"staged","sha256":"' + b"e" * 64 + b'","length":7}') as remote):
            self.assertEqual("staged", http_stage.stage_start(Path.cwd(), {"correlationId": CORRELATION})["state"])
            self.assertEqual(http_stage._REMOTE_STAGE, remote.call_args.args[1])
            self.assertEqual(Path(record["bundlePath"]), remote.call_args.args[3])
        with (mock.patch.object(http_stage, "_record", return_value=(Path.cwd(), record, object(), target)),
              mock.patch.object(http_stage, "host_stage_probe", return_value={"phase": "host-stage-complete", "listenerStartAllowed": True}),
              mock.patch.object(http_stage.base, "_descriptor", return_value=(object(), target, ("windows-cp117", "/qga", 1, 2, "S-1-5-21-1-2-3-1002"))),
              mock.patch.object(http_stage, "_large_advance", return_value=True),
              mock.patch.object(http_stage.base, "_remote", return_value=b'{"state":"listening","port":4567}')):
            self.assertEqual("listening", http_stage.listener_start(Path.cwd(), {"correlationId": CORRELATION})["state"])
        with (mock.patch.object(http_stage, "_record", return_value=(Path.cwd(), record, object(), target)),
              mock.patch.object(http_stage, "listener_status", return_value={"state":"listening"}),
              mock.patch.object(http_stage.base, "_remote") as remote):
            self.assertEqual("unknown", http_stage.cleanup(Path.cwd(), {"correlationId": CORRELATION})["state"])
            remote.assert_not_called()

    def test_host_staged_pre_effect_diagnostic_proves_absence_before_immutable_close(self):
        record = {"request": self.request(), "leaseId": "24b6d975-6e5c-4c3c-b85e-c02f4d6d8926",
                  "bundlePath": "/private/bundle.zip", "bundleSha256": "e" * 64,
                  "bundleSize": 7, "routeNonce": "x" * 32, "sourceFingerprint": "d" * 64}
        target = mock.Mock(fixture_transfer_root="/fixture")
        with (mock.patch.object(http_stage, "_record", return_value=(Path.cwd(), record, object(), target)),
              mock.patch.object(http_stage.large_transfer, "read", return_value={"phase":"host-staged"}),
              mock.patch.object(http_stage.base, "_remote", return_value=b'{"state":"absent"}') as remote,
              mock.patch.object(http_stage.large_transfer, "close_host_staged_pre_effect",
                                return_value={"state":"unknown"}) as close):
            self.assertEqual("host-stage-absent", http_stage.host_staged_pre_effect_diagnostic(
                Path.cwd(), {"correlationId": CORRELATION})["phase"])
            self.assertEqual("unknown", http_stage.host_staged_pre_effect_close(
                Path.cwd(), {"correlationId": CORRELATION})["state"])
        self.assertEqual(http_stage._REMOTE_HOST_STAGE_ABSENT, remote.call_args.args[1])
        close.assert_called_once_with(Path.cwd().resolve(), CORRELATION)

    def test_host_stage_absence_probe_fails_closed_for_unsafe_fixed_ancestors(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory); root.chmod(0o700)
            missing_parent = subprocess.run([sys.executable, "-c", http_stage._REMOTE_HOST_STAGE_ABSENT,
                                              str(root), CORRELATION], capture_output=True, check=False, timeout=10)
            self.assertEqual({"state":"absent"}, json.loads(missing_parent.stdout))
            parent = root / "windows-cp117"; parent.symlink_to(outside, target_is_directory=True)
            unsafe_parent = subprocess.run([sys.executable, "-c", http_stage._REMOTE_HOST_STAGE_ABSENT,
                                             str(root), CORRELATION], capture_output=True, check=False, timeout=10)
            self.assertEqual({"state":"unknown"}, json.loads(unsafe_parent.stdout))
            parent.unlink(); root.chmod(0o755)
            unsafe_mode = subprocess.run([sys.executable, "-c", http_stage._REMOTE_HOST_STAGE_ABSENT,
                                           str(root), CORRELATION], capture_output=True, check=False, timeout=10)
            self.assertEqual({"state":"unknown"}, json.loads(unsafe_mode.stdout))

    def test_host_stage_probe_remote_distinguishes_complete_partial_and_never_writes_fixture(self):
        payload = b"frozen-fixture"; digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.remote_args(directory, digest, len(payload))
            binding = json.loads(base64.b64decode(args[-1]))
            parent = root / "windows-cp117"; http_group = parent / "windows-update-fixture-http-stage"
            authority_group = parent / "windows-update-fixture-stage"
            http_leaf = http_group / CORRELATION; authority_leaf = authority_group / CORRELATION
            for path in (parent, http_group, authority_group, http_leaf, authority_leaf):
                path.mkdir(exist_ok=True); path.chmod(0o700)
            (authority_leaf / "binding.json").write_text(json.dumps(binding, separators=(",", ":")))
            (http_leaf / "binding.json").write_text(json.dumps({"sha256": digest, "length": len(payload)}, separators=(",", ":")))
            (http_leaf / "bundle.zip").write_bytes(payload)
            for path in (authority_leaf / "binding.json", http_leaf / "binding.json", http_leaf / "bundle.zip"):
                path.chmod(0o600)
            def snapshot():
                return {str(path.relative_to(root)): (path.lstat().st_mode, path.read_bytes())
                        for path in root.rglob("*") if path.is_file()}
            before = snapshot()
            complete = subprocess.run([sys.executable, "-c", http_stage._REMOTE_HOST_STAGE_PROBE, *args],
                                      capture_output=True, check=False, timeout=10)
            self.assertEqual({"state": "complete"}, json.loads(complete.stdout))
            self.assertEqual(before, snapshot())
            (authority_leaf / "binding.json").write_text(json.dumps({"correlationId": CORRELATION}))
            (authority_leaf / "binding.json").chmod(0o600)
            partial_before = snapshot()
            partial = subprocess.run([sys.executable, "-c", http_stage._REMOTE_HOST_STAGE_PROBE, *args],
                                     capture_output=True, check=False, timeout=10)
            self.assertEqual({"state": "partial"}, json.loads(partial.stdout))
            self.assertEqual(partial_before, snapshot())
            (authority_leaf / "binding.json").write_text(json.dumps(binding, separators=(",", ":")))
            (authority_leaf / "binding.json").chmod(0o600)
            (http_leaf / "bundle.zip").write_bytes(b"corrupted-fixture")
            (http_leaf / "bundle.zip").chmod(0o600)
            hash_partial_before = snapshot()
            hash_partial = subprocess.run([sys.executable, "-c", http_stage._REMOTE_HOST_STAGE_PROBE, *args],
                                          capture_output=True, check=False, timeout=10)
            self.assertEqual({"state": "partial"}, json.loads(hash_partial.stdout))
            self.assertEqual(hash_partial_before, snapshot())
            # The first probe was complete, then the immutable stage changed.
            # Listener start must recheck in the same host process before it
            # can spawn the one-use worker.
            listener = subprocess.run([sys.executable, "-c", http_stage._REMOTE_LISTENER_START,
                                       directory, CORRELATION, digest, str(len(payload)), "/" + "z" * 32, args[-1]],
                                      capture_output=True, check=False, timeout=10)
            self.assertEqual({"state": "unknown"}, json.loads(listener.stdout))
            self.assertFalse((http_leaf / "listener-ready.json").exists())
            self.assertFalse((http_leaf / "listener-done.json").exists())

    def test_host_stage_probe_only_admits_listener_after_exact_complete_receipt(self):
        record = {"request": self.request(), "leaseId": "24b6d975-6e5c-4c3c-b85e-c02f4d6d8926",
                  "bundlePath": "/private/bundle.zip", "bundleSha256": "e" * 64,
                  "bundleSize": 7, "routeNonce": "x" * 32, "sourceFingerprint": "d" * 64}
        descriptor = ("windows-cp117", "/qga", 1, 2, "S-1-5-21-1-2-3-1002")
        target = mock.Mock(fixture_transfer_root="/fixture")
        core = {"phase": "host-staged", "binding": http_stage._large_binding(record, descriptor),
                "sha256": record["bundleSha256"], "length": record["bundleSize"]}
        with (mock.patch.object(http_stage, "_record", return_value=(Path.cwd(), record, object(), target)),
              mock.patch.object(http_stage.base, "_descriptor", return_value=(object(), target, descriptor)),
              mock.patch.object(http_stage.large_transfer, "read", return_value=core),
              mock.patch.object(http_stage.base, "_remote", side_effect=(b'{"state":"complete"}',
                                                                           b'{"state":"partial"}',
                                                                           b'{"state":"complete","extra":true}')) as remote):
            complete = http_stage.workflow(Path.cwd(), "host-stage-probe", {"correlationId": CORRELATION})
            partial = http_stage.host_stage_probe(Path.cwd(), {"correlationId": CORRELATION})
            malformed = http_stage.host_stage_probe(Path.cwd(), {"correlationId": CORRELATION})
        self.assertEqual("host-stage-complete", complete["phase"])
        self.assertTrue(complete["listenerStartAllowed"])
        self.assertEqual("host-stage-partial", partial["phase"])
        self.assertFalse(partial["listenerStartAllowed"])
        self.assertEqual("unknown", malformed["phase"])
        self.assertFalse(malformed["listenerStartAllowed"])
        self.assertEqual(http_stage._REMOTE_HOST_STAGE_PROBE, remote.call_args_list[0].args[1])

    def test_listener_start_rejects_partial_probe_before_phase_or_remote_spawn(self):
        with (mock.patch.object(http_stage, "host_stage_probe", return_value={"phase": "host-stage-partial", "listenerStartAllowed": False}),
              mock.patch.object(http_stage, "_large_advance") as advance,
              mock.patch.object(http_stage.base, "_remote") as remote):
            result = http_stage.listener_start(Path.cwd(), {"correlationId": CORRELATION})
        self.assertEqual("unknown", result["state"])
        advance.assert_not_called()
        remote.assert_not_called()

    def test_e66_recovery_requires_full_export_and_writes_immutable_import_before_close(self):
        output = '''Traceback (most recent call last):
  File "/tmp/agent_tools/windows_update_fixture_http_stage.py", line 872, in stage_start
    base._remote(
  File "/tmp/agent_tools/windows_msi_base_prepare.py", line 872, in _remote
    with source.open("rb") as stream:
AttributeError: '_io.BufferedReader' object has no attribute 'open'
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_path = root / http_stage._E66_EVIDENCE
            evidence_path.parent.mkdir(parents=True)
            input_path = root / http_stage._E66_INPUT
            input_path.write_text('{"correlationId": "e66d02a7-a40c-41e0-8f8b-674624f98a54", "phase": "stage-start"}')
            input_path.chmod(0o600)
            evidence_path.write_text(json.dumps({"taskId": http_stage._E66_TASK, "turnId": http_stage._E66_TURN,
                "itemId": http_stage._E66_ITEM, "command": http_stage._E66_COMMAND, "exitCode": 1,
                "output": output}, separators=(",", ":")))
            evidence_path.chmod(0o600)
            pinned = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            with mock.patch.object(http_stage, "_E66_TRANSCRIPT_SHA256", pinned):
                transcript = http_stage._e66_transcript(root)
                self.assertTrue(http_stage._e66_import_receipt(root, transcript))
                self.assertTrue(http_stage._e66_imported(root, transcript))
            evidence_path.write_text(json.dumps({"taskId": http_stage._E66_TASK, "turnId": http_stage._E66_TURN,
                "itemId": http_stage._E66_ITEM, "command": http_stage._E66_COMMAND, "exitCode": 1,
                "output": output + "\ntrailing output that still contains every causal token"}))
            evidence_path.chmod(0o600)
            with mock.patch.object(http_stage, "_E66_TRANSCRIPT_SHA256", pinned):
                with self.assertRaises(http_stage.WindowsUpdateFixtureHttpStageError):
                    http_stage._e66_transcript(root)

    def test_e66_recovery_never_records_or_closes_without_the_exact_import(self):
        with (mock.patch.object(http_stage, "_record", return_value=(Path.cwd(), {}, object(), object())),
              mock.patch.object(http_stage.large_transfer, "read", return_value={"phase": "host-staged"}),
              mock.patch.object(http_stage, "_e66_transcript", return_value={"inputSha256": "a" * 64,
                                                                                "commandSha256": "b" * 64,
                                                                                "transcriptSha256": "c" * 64}),
              mock.patch.object(http_stage, "_e66_imported", return_value=False),
              mock.patch.object(http_stage, "_e66_import_receipt", return_value=False),
              mock.patch.object(http_stage.large_transfer, "record_predispatch_failure", create=True) as record,
              mock.patch.object(http_stage, "host_staged_pre_effect_close") as close):
            result = http_stage.e66_pre_effect_recovery(Path.cwd(), {"correlationId": http_stage._E66_CORRELATION})
        self.assertEqual("unknown", result["state"])
        record.assert_not_called()
        close.assert_not_called()

    def test_e66_recovery_records_the_fixed_failure_only_after_import_then_uses_normal_close(self):
        imported = {"inputSha256": "a" * 64, "commandSha256": "b" * 64, "transcriptSha256": "c" * 64}
        host_staged = {"phase": "host-staged"}
        proven = {"phase": "host-staged", "dispatchFailure": http_stage._E66_FAILURE}
        with (mock.patch.object(http_stage, "_record", return_value=(Path.cwd(), {}, object(), object())),
              mock.patch.object(http_stage.large_transfer, "read", side_effect=(host_staged, proven)),
              mock.patch.object(http_stage, "_e66_transcript", return_value=imported),
              mock.patch.object(http_stage, "_e66_imported", return_value=True),
              mock.patch.object(http_stage, "_e66_import_receipt") as write_import,
              mock.patch.object(http_stage, "_fsync_e66_import_directory", return_value=True) as fsync_directory,
              mock.patch.object(http_stage.large_transfer, "record_predispatch_failure", create=True,
                                return_value={"state": "host-staged"}) as record,
              mock.patch.object(http_stage, "host_staged_pre_effect_close", return_value={"state": "aborted"}) as close):
            result = http_stage.e66_pre_effect_recovery(Path.cwd(), {"correlationId": http_stage._E66_CORRELATION})
        self.assertEqual("aborted", result["state"])
        write_import.assert_not_called()
        fsync_directory.assert_called_once_with(Path.cwd())
        record.assert_called_once_with(Path.cwd(), http_stage._E66_CORRELATION)
        close.assert_called_once_with(Path.cwd(), {"correlationId": http_stage._E66_CORRELATION})

    def test_e66_retirement_finishes_only_the_fixed_stage_role_after_durable_evidence(self):
        receipt = {"correlationId": http_stage._E66_CORRELATION, "leaseId": http_stage._E66_LEASE}
        receipt_sha = "e" * 64
        details = (Path.cwd(), {"leaseId": http_stage._E66_LEASE}, object(), object(), object(), receipt, receipt_sha)
        with (mock.patch.object(http_stage, "_e66_retirement_admission", return_value=("ready", details)),
              mock.patch.object(http_stage, "_e66_retirement_receipt", return_value=receipt) as durable,
              mock.patch.object(http_stage.stage.campaign_lease, "finish_role", return_value={"state": "active"}) as finish,
              mock.patch.object(http_stage.large_transfer, "advance") as transfer):
            result = http_stage.e66_retire_aborted_stage(Path.cwd(), {"correlationId": http_stage._E66_CORRELATION})
        self.assertEqual("retired", result["state"])
        durable.assert_called_once_with(Path.cwd(), receipt, create=True)
        finish.assert_called_once_with(Path.cwd(), http_stage._E66_LEASE, "stage", http_stage._E66_CORRELATION,
                                       receipt_sha, "failed-cleaned", details[4])
        transfer.assert_not_called()

    def test_e66_retirement_status_reports_pending_finish_without_reconcile_or_replay(self):
        with (mock.patch.object(http_stage, "_e66_retirement_admission", return_value=("pending-finish", None)) as admission,
              mock.patch.object(http_stage.stage.campaign_lease, "reconcile") as reconcile,
              mock.patch.object(http_stage.stage.campaign_lease, "finish_role") as finish):
            result = http_stage.e66_retire_aborted_stage_status(Path.cwd(), {"correlationId": http_stage._E66_CORRELATION})
        self.assertEqual("pending-finish", result["state"])
        admission.assert_called_once_with(Path.cwd(), reconcile_pending=False)
        reconcile.assert_not_called()
        finish.assert_not_called()

    def test_e66_retirement_status_reports_retired_after_role_finish_without_mutation(self):
        with (mock.patch.object(http_stage, "_e66_retirement_admission", return_value=("retired", ())) as admission,
              mock.patch.object(http_stage.stage.campaign_lease, "reconcile") as reconcile,
              mock.patch.object(http_stage.stage.campaign_lease, "finish_role") as finish,
              mock.patch.object(http_stage.large_transfer, "advance") as advance):
            result = http_stage.e66_retire_aborted_stage_status(Path.cwd(), {"correlationId": http_stage._E66_CORRELATION})
        self.assertEqual("retired", result["state"])
        admission.assert_called_once_with(Path.cwd(), reconcile_pending=False)
        reconcile.assert_not_called()
        finish.assert_not_called()
        advance.assert_not_called()

    def test_http_status_projects_only_the_exact_e66_aborted_core_without_action(self):
        descriptor = ("windows-cp117", "/qga", 1, 2, "S-1-5-21-1-2-3-1002")
        record = {"request": {"correlationId": http_stage._E66_CORRELATION, "sourceSha": "a" * 40,
                               "fixtureReceiptArtifactId": ARTIFACT, "baseMsiArtifactId": ARTIFACT,
                               "targetMsiArtifactId": ARTIFACT}, "leaseId": http_stage._E66_LEASE,
                  "bundlePath": "/private/bundle.zip", "bundleSha256": "e" * 64, "bundleSize": 7,
                  "routeNonce": "x" * 32, "sourceFingerprint": "d" * 64}
        core = {"binding": http_stage._large_binding(record, descriptor), "sha256": "e" * 64, "length": 7,
                "phase": "aborted", "dispatchFailure": http_stage._E66_FAILURE,
                "preEffectClose": {"reason": "source-not-path", "remoteStage": "absent"}}
        with (mock.patch.object(http_stage, "_read", return_value=record),
              mock.patch.object(http_stage, "_artifact"),
              mock.patch.object(http_stage, "_record", return_value=(Path.cwd(), record, object(), object())) as bound_record,
              mock.patch.object(http_stage.base, "_descriptor", return_value=(object(), object(), descriptor)),
              mock.patch.object(http_stage, "_e66_transcript", return_value={"transcriptSha256": "f" * 64}),
              mock.patch.object(http_stage, "_e66_imported", return_value=True),
              mock.patch.object(http_stage.large_transfer, "read", return_value=core),
              mock.patch.object(http_stage.large_transfer, "advance") as advance,
              mock.patch.object(http_stage.base, "_remote") as remote):
            result = http_stage.status(Path.cwd(), {"correlationId": http_stage._E66_CORRELATION})
        self.assertEqual("aborted", result["state"])
        bound_record.assert_called_once_with(Path.cwd(), http_stage._E66_CORRELATION, campaign_mode="stage-or-idle")
        advance.assert_not_called()
        remote.assert_not_called()

    def test_collect_completion_admits_terminal_idle_cleanup_without_reopening_stage_role(self):
        record = {"request": self.request(), "leaseId": "24b6d975-6e5c-4c3c-b85e-c02f4d6d8926",
                  "bundlePath": "/private/bundle.zip", "bundleSha256": "e" * 64,
                  "bundleSize": 7, "routeNonce": "x" * 32, "sourceFingerprint": "d" * 64}
        target = mock.Mock(fixture_transfer_root="/fixture")
        completed = {"value": False}
        def stage_status(_root, _value):
            completed["value"] = True  # stage.status completed the stage role.
            return {"state": "staged-not-server-ready", "correlationId": CORRELATION,
                    "bundleSha256": record["bundleSha256"]}
        def terminal_record(_root, _corr, *, campaign_mode="stage"):
            self.assertTrue(completed["value"])
            self.assertEqual("idle", campaign_mode)
            return Path.cwd(), record, object(), target
        with (mock.patch.object(http_stage, "_read", return_value=record),
              mock.patch.object(http_stage.stage, "status", side_effect=stage_status),
              mock.patch.object(http_stage.base, "_descriptor", return_value=(object(), target, ("windows-cp117", "/qga", 1, 2, "S-1-5-21-1-2-3-1002"))),
              mock.patch.object(http_stage.large_transfer, "read", return_value={"phase": "placed"}),
              mock.patch.object(http_stage, "_record", side_effect=terminal_record),
              mock.patch.object(http_stage, "listener_status", return_value={"state": "served"}),
              mock.patch.object(http_stage, "_large_advance", return_value=True),
              mock.patch.object(http_stage.base, "_remote", return_value=b'{"state":"cleaned"}') as remote):
            self.assertEqual("staged-not-server-ready", http_stage.collect(Path.cwd(), {"correlationId": CORRELATION})["state"])
            self.assertEqual("cleaned", http_stage.cleanup(Path.cwd(), {"correlationId": CORRELATION})["state"])
        self.assertEqual(http_stage._REMOTE_CLEANUP, remote.call_args.args[1])

    def test_qga_programs_compile_and_never_embed_fixture_bytes(self):
        for name in ("_REMOTE_QGA_PS", "_REMOTE_QGA_DOWNLOAD", "_REMOTE_LISTENER_START",
                     "_REMOTE_LISTENER_STATUS", "_REMOTE_CLEANUP", "_REMOTE_QGA_STAGE_EXTRACT"):
            program = getattr(http_stage, name)
            compile(program, name, "exec")
            self.assertNotIn("bundle.zip',os.O_WRONLY", program)
        self.assertIn("save(dispatch,{'pid':child})", http_stage._REMOTE_QGA_STAGE_EXTRACT)
