"""Causal regressions for the fixed CP117 guest-create abort route."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from agent_tools import windows_update_fixture_guest_create_abort as abort


SID = "S-1-5-21-1-2-3-1002"
DESCRIPTOR = ("windows-cp117", "/qga", 17, 29, SID)
ARTIFACT = "sha256-" + "a" * 64


class GuestCreateAbortTests(unittest.TestCase):
    def _record(self):
        return {"leaseId": abort._LEASE, "sourceFingerprint": "b" * 64,
                "bundleSha256": "c" * 64, "bundleSize": 7,
                "request": {"correlationId": abort._CORRELATION, "sourceSha": abort._SOURCE,
                            "fixtureReceiptArtifactId": ARTIFACT, "baseMsiArtifactId": ARTIFACT,
                            "targetMsiArtifactId": ARTIFACT}}

    def _patch_admission_inputs(self, root):
        record = self._record(); config = object(); target = mock.Mock(fixture_transfer_root="/fixture")
        return (record, config, target, (
            mock.patch.object(abort.http, "_record", return_value=(root, record, config, target)),
            mock.patch.object(abort.base, "_descriptor", return_value=(object(), target, DESCRIPTOR)),
            mock.patch.object(abort.http.large_transfer, "read", return_value={"phase": "guest-created"}),
            mock.patch.object(abort, "_host_stage", return_value="complete"),
            mock.patch.object(abort.http, "listener_status", return_value={"state": "stopped"}),
            mock.patch.object(abort, "_guest_absent", return_value=True),
            mock.patch.object(abort, "_campaign", return_value="armed"),
            mock.patch.object(abort, "_marker", return_value="absent"),
        ))

    def test_status_is_read_only_and_requires_absent_guest_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); record, config, target, patches = self._patch_admission_inputs(root)
            patches = list(patches)
            patches[5] = mock.patch.object(abort, "_guest_absent", return_value=False)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], \
                 mock.patch.object(abort, "_receipt", return_value=False) as receipt, \
                 mock.patch.object(abort.base, "_remote", side_effect=AssertionError("status must not clean")):
                result = abort.status(root, {"correlationId": abort._CORRELATION})
            self.assertEqual("guest-create", result["phase"])
            self.assertFalse(result["abortAllowed"])
            receipt.assert_called_once()

    def test_status_refuses_wrong_fixed_source_before_host_or_qga_observation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); record = self._record(); record["request"] = {**record["request"], "sourceSha": "0" * 40}
            with mock.patch.object(abort.http, "_record", return_value=(root, record, object(), object())), \
                 mock.patch.object(abort.base, "_descriptor", return_value=(object(), object(), DESCRIPTOR)), \
                 mock.patch.object(abort, "_host_stage", side_effect=AssertionError("must not query host")), \
                 mock.patch.object(abort, "_guest_absent", side_effect=AssertionError("must not query QGA")):
                result = abort.status(root, {"correlationId": abort._CORRELATION})
            self.assertEqual("binding", result["phase"])

    def test_host_observation_accepts_guest_created_core_and_projects_terminal_host_states(self):
        record = self._record(); target = mock.Mock(fixture_transfer_root="/fixture")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(abort.base, "_remote", return_value=b'{"state":"complete"}') as remote:
                self.assertEqual("complete", abort._host_stage(root, record, DESCRIPTOR, object(), target))
            self.assertIs(remote.call_args.args[1], abort.http._REMOTE_HOST_STAGE_PROBE)
            for raw, expected in ((b'{"state":"absent"}', "absent"), (b'{"state":"partial"}', "partial"),
                                  (b'{"state":"unknown"}', "unknown")):
                with self.subTest(raw=raw), mock.patch.object(abort.base, "_remote", return_value=raw):
                    self.assertEqual(expected, abort._host_stage(root, record, DESCRIPTOR, object(), target))

    def test_guest_state_uses_real_three_argument_diagnostic_builder_within_qga_bound(self):
        create = abort.http.stage._create_script(abort._CORRELATION, SID)
        script = abort.http._guest_create_diagnostic_script(abort._CORRELATION, SID, create)
        self.assertLess(len(base64.b64encode(script.encode("utf-16le"))), 30000)
        with mock.patch.object(abort.base, "_remote", return_value=b'{"state":"leaf-absent","interpreter":"absent"}'):
            self.assertEqual("absent", abort._guest_state(object(), DESCRIPTOR))

    def test_status_proves_retired_without_pre_abort_host_or_stage_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); _record, _config, _target, patches = self._patch_admission_inputs(root)
            with patches[0], patches[1], patches[2], \
                 mock.patch.object(abort, "_receipt", return_value=True), \
                 mock.patch.object(abort, "_marker", return_value="cleaned"), \
                 mock.patch.object(abort, "_campaign", return_value="retired"), \
                 mock.patch.object(abort, "_guest_state", return_value="absent"), \
                 mock.patch.object(abort, "_host_stage", side_effect=AssertionError("retired must not probe removed host leaf")), \
                 mock.patch.object(abort.http, "listener_status", side_effect=AssertionError("retired must not query listener")):
                result = abort.status(root, {"correlationId": abort._CORRELATION})
            self.assertEqual("retired", result["phase"])
            self.assertFalse(result["abortAllowed"])

    def test_retired_status_exposes_guest_interpreter_presence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); _record, _config, _target, patches = self._patch_admission_inputs(root)
            with patches[0], patches[1], patches[2], \
                 mock.patch.object(abort, "_receipt", return_value=True), \
                 mock.patch.object(abort, "_marker", return_value="cleaned"), \
                 mock.patch.object(abort, "_campaign", return_value="retired"), \
                 mock.patch.object(abort, "_guest_state", return_value="interpreter-present"):
                result = abort.status(root, {"correlationId": abort._CORRELATION})
            self.assertEqual("retired-guest-interpreter-present", result["phase"])
            self.assertFalse(result["abortAllowed"])

    def test_retired_binding_loader_requires_frozen_guest_created_binding(self):
        """It bypasses only role admission, never the HTTP/stage binding checks."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = {**self._record(), "bundlePath": str(root / "bundle.zip"),
                      "request": {"host": "archlinux", **self._record()["request"]}}
            target = mock.Mock()
            intent = {"request": record["request"], "leaseId": abort._LEASE,
                      "sourceFingerprint": record["sourceFingerprint"], "bundleSha256": record["bundleSha256"],
                      "bundleSize": record["bundleSize"], "environment": DESCRIPTOR[0], "socketPath": DESCRIPTOR[1],
                      "pid": DESCRIPTOR[2], "startTicks": DESCRIPTOR[3], "expectedSid": DESCRIPTOR[4]}
            core = {"phase": "guest-created", "binding": abort.http._large_binding(record, DESCRIPTOR),
                    "sha256": record["bundleSha256"], "length": record["bundleSize"]}
            with mock.patch.object(abort.http, "_read", return_value=record), \
                 mock.patch.object(abort.http, "_artifact"), \
                 mock.patch.object(abort.base, "_descriptor", return_value=(object(), target, DESCRIPTOR)), \
                 mock.patch.object(abort.http.stage.public, "_admit_pair", return_value={"sourceFingerprint": record["sourceFingerprint"]}), \
                 mock.patch.object(abort.http.stage, "_read_intent", return_value=intent), \
                 mock.patch.object(abort.http.large_transfer, "read", return_value=core):
                self.assertEqual(record, abort._retired_local_binding(root)[1])
            with mock.patch.object(abort.http, "_read", return_value=record), \
                 mock.patch.object(abort.http, "_artifact"), \
                 mock.patch.object(abort.base, "_descriptor", return_value=(object(), target, DESCRIPTOR)), \
                 mock.patch.object(abort.http.stage.public, "_admit_pair", return_value={"sourceFingerprint": record["sourceFingerprint"]}), \
                 mock.patch.object(abort.http.stage, "_read_intent", return_value=intent), \
                 mock.patch.object(abort.http.large_transfer, "read", return_value={**core, "phase": "host-staged"}):
                with self.assertRaises(abort.WindowsUpdateFixtureGuestCreateAbortError):
                    abort._retired_local_binding(root)

    def test_abort_cleans_exact_host_leaf_then_fsyncs_evidence_then_finishes_role(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); record, config, target, patches = self._patch_admission_inputs(root)
            calls = []
            def remote(_config, program, args, _stdin, _timeout):
                calls.append((program, args))
                return json.dumps({"state": "cleaned"}).encode()
            def receipt(_root, evidence, *, create):
                calls.append(("receipt", evidence, create)); return create
            def finish(*args):
                calls.append(("finish", args)); return {"state": "active"}
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], \
                 mock.patch.object(abort.base, "_remote", side_effect=remote), \
                 mock.patch.object(abort, "_receipt", side_effect=receipt), \
                 mock.patch.object(abort.lease, "finish_role", side_effect=finish), \
                 mock.patch.object(abort.base, "_campaign_remote", return_value=object()):
                result = abort.abort(root, {"correlationId": abort._CORRELATION})
            self.assertEqual("retired", result["state"])
            self.assertEqual(("receipt", calls[0][1], False), calls[0])
            self.assertEqual(("receipt", calls[1][1], True), calls[1])
            self.assertIs(calls[2][0], abort._REMOTE_ABORT)
            self.assertEqual("finish", calls[3][0])
            self.assertEqual(abort._CORRELATION, calls[2][1][1])
            self.assertEqual(record["bundleSha256"], calls[2][1][2])

    def test_abort_does_not_write_or_finish_when_host_cleanup_is_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); _record, _config, _target, patches = self._patch_admission_inputs(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], \
                 mock.patch.object(abort.base, "_remote", return_value=b'{"state":"unknown"}'), \
                 mock.patch.object(abort, "_receipt", return_value=True) as receipt, \
                 mock.patch.object(abort.lease, "finish_role", side_effect=AssertionError("must not close")):
                result = abort.abort(root, {"correlationId": abort._CORRELATION})
            self.assertEqual("unknown", result["state"])
            self.assertEqual(2, receipt.call_count)

    def test_fixed_remote_cleanup_rejects_a_served_listener(self):
        self.assertIn("{'served':False}", abort._REMOTE_ABORT)
        self.assertNotIn("{'served':True}", abort._REMOTE_ABORT)

    def test_marker_reconciles_a_lost_cleanup_response_without_repeating_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); record, config, target, patches = self._patch_admission_inputs(root)
            evidence, digest = abort._receipt_value(record, DESCRIPTOR)
            with patches[0], patches[1], patches[2], patches[4], patches[5], patches[6], \
                 mock.patch.object(abort, "_marker", return_value="cleaned"), \
                 mock.patch.object(abort, "_receipt", return_value=True), \
                 mock.patch.object(abort.base, "_remote", return_value=b'{"state":"cleaned"}') as remote, \
                 mock.patch.object(abort.lease, "finish_role", return_value={"state":"active"}) as finish, \
                 mock.patch.object(abort.base, "_campaign_remote", return_value=object()):
                # Reconciliation does not query the removed listener/host leaf.
                result = abort.abort(root, {"correlationId": abort._CORRELATION})
            self.assertEqual("retired", result["state"])
            self.assertEqual(0, remote.call_count)
            finish.assert_called_once()

    def test_remote_two_phase_marker_survives_crash_after_leaf_removal(self):
        """The pending marker is durable before rmtree, so a later cleanup can finalize it."""
        pending = abort._REMOTE_ABORT.index("save(dict(marker_base,state='pending'))")
        removal = abort._REMOTE_ABORT.index("shutil.rmtree(stage)", pending)
        final = abort._REMOTE_ABORT.index("save(dict(marker_base,state='cleaned'))", removal)
        self.assertLess(pending, removal)
        self.assertLess(removal, final)
        self.assertIn("if action=='status':out({'state':'pending'})", abort._REMOTE_ABORT)
        self.assertIn("if os.path.lexists(stage):", abort._REMOTE_ABORT)

    def test_remote_pending_marker_finalizes_after_simulated_post_removal_crash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); parent = root / "windows-cp117"
            group = parent / "windows-update-fixture-http-stage"; authority_group = parent / "windows-update-fixture-stage"
            authority = authority_group / abort._CORRELATION
            for path in (parent, group, authority_group, authority):
                path.mkdir(mode=0o700, parents=True, exist_ok=True); path.chmod(0o700)
            binding = {"correlationId": abort._CORRELATION, "bundleSha256": "c" * 64}
            marker = {"correlationId": abort._CORRELATION,
                      "bindingSha256": hashlib.sha256(json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                      "served": False, "state": "pending"}
            marker_path = group / (abort._CORRELATION + ".guest-create-aborted.json")
            marker_path.write_text(json.dumps(marker)); marker_path.chmod(0o600)
            encoded = base64.b64encode(json.dumps(binding).encode()).decode()
            done = subprocess.run([sys.executable, "-c", abort._REMOTE_ABORT, str(root), abort._CORRELATION,
                                   "c" * 64, "7", encoded, "cleanup"], capture_output=True, text=True, timeout=10)
            self.assertEqual({"state": "cleaned"}, json.loads(done.stdout))
            self.assertEqual("cleaned", json.loads(marker_path.read_text())["state"])

    def test_local_receipt_without_remote_marker_rechecks_then_cleans(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); _record, _config, _target, patches = self._patch_admission_inputs(root)
            remote_results = [b'{"state":"cleaned"}']
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], \
                 mock.patch.object(abort, "_receipt", return_value=True), \
                 mock.patch.object(abort, "_marker", return_value="absent"), \
                 mock.patch.object(abort.base, "_remote", side_effect=remote_results) as remote, \
                 mock.patch.object(abort.lease, "finish_role", return_value={"state":"active"}), \
                 mock.patch.object(abort.base, "_campaign_remote", return_value=object()):
                result = abort.abort(root, {"correlationId": abort._CORRELATION})
            self.assertEqual("retired", result["state"])
            self.assertEqual(["cleanup"], [call.args[2][-1] for call in remote.call_args_list])

    def test_remote_stale_temp_does_not_block_pending_marker_finalization(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); parent = root / "windows-cp117"
            group = parent / "windows-update-fixture-http-stage"; authority_group = parent / "windows-update-fixture-stage"
            for path in (parent, group, authority_group):
                path.mkdir(mode=0o700, parents=True, exist_ok=True); path.chmod(0o700)
            binding = {"correlationId": abort._CORRELATION, "bundleSha256": "c" * 64}
            marker = {"correlationId": abort._CORRELATION,
                      "bindingSha256": hashlib.sha256(json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                      "served": False, "state": "pending"}
            marker_path = group / (abort._CORRELATION + ".guest-create-aborted.json")
            marker_path.write_text(json.dumps(marker)); marker_path.chmod(0o600)
            stale = group / (marker_path.name + ".tmp-stale"); stale.write_text("partial"); stale.chmod(0o600)
            encoded = base64.b64encode(json.dumps(binding).encode()).decode()
            done = subprocess.run([sys.executable, "-c", abort._REMOTE_ABORT, str(root), abort._CORRELATION,
                                   "c" * 64, "7", encoded, "cleanup"], capture_output=True, text=True, timeout=10)
            self.assertEqual({"state": "cleaned"}, json.loads(done.stdout))
            self.assertTrue(stale.exists())

    def test_fixed_request_rejects_a_caller_selected_correlation(self):
        with self.assertRaises(abort.WindowsUpdateFixtureGuestCreateAbortError):
            abort.status(Path.cwd(), {"correlationId": "00000000-0000-4000-8000-000000000000"})

    def test_status_has_finite_gate_when_shared_core_read_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); _record, _config, _target, patches = self._patch_admission_inputs(root)
            with patches[0], patches[1], mock.patch.object(abort.http.large_transfer, "read", side_effect=ValueError("unreadable")):
                result = abort.status(root, {"correlationId": abort._CORRELATION})
            self.assertEqual("retired-shared-core-invalid", result["phase"])

    def test_fallback_loader_cannot_admit_an_armed_campaign(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); record = self._record(); target = mock.Mock()
            with mock.patch.object(abort.http, "_record", side_effect=abort.http.WindowsUpdateFixtureHttpStageError("idle")), \
                 mock.patch.object(abort, "_retired_local_binding", return_value=(root, record, object(), target, DESCRIPTOR)), \
                 mock.patch.object(abort.http.large_transfer, "read", return_value={"phase": "guest-created"}), \
                 mock.patch.object(abort, "_receipt", return_value=True), \
                 mock.patch.object(abort, "_campaign", return_value="armed"), \
                 mock.patch.object(abort, "_guest_absent", side_effect=AssertionError("no QGA census")), \
                 mock.patch.object(abort, "_marker", side_effect=AssertionError("no marker read")), \
                 mock.patch.object(abort.lease, "finish_role", side_effect=AssertionError("no finish")):
                self.assertEqual("retired-campaign-armed", abort.status(root, {"correlationId": abort._CORRELATION})["phase"])
                self.assertEqual("unknown", abort.abort(root, {"correlationId": abort._CORRELATION})["state"])
