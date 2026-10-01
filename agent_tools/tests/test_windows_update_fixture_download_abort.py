"""Regression coverage for the fixed lost-download retirement path."""
from __future__ import annotations

import base64
import json
import hashlib
import fcntl
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest import mock

from agent_tools import windows_update_fixture_download_abort as abort


SID = "S-1-5-21-1-2-3-1002"
DESCRIPTOR = ("windows-cp117", "/qga", 17, 29, SID)
ARTIFACT = "sha256-" + "a" * 64


class DownloadAbortTests(unittest.TestCase):
    def _lease_identity(self):
        return {"host":"archlinux", "environment":"windows-cp117", "leaseId":abort._LEASE,
                "operator":"windows-owner", "sourceSha":abort._SOURCE, "fixtureReceiptArtifactId":ARTIFACT,
                "baseMsiArtifactId":ARTIFACT, "targetMsiArtifactId":ARTIFACT,
                "socketPath":"/qga", "qemuPid":17, "startTicks":29}

    def test_campaign_record_reads_valid_active_and_releases_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); identity = self._lease_identity(); directory = root / abort.lease._DIR
            directory.mkdir(parents=True, mode=0o700)
            active = {"version":1,"identity":identity,"sequence":1,"state":"role-active","role":"stage",
                      "correlationId":abort._CORRELATION,"server":"stopped","credentials":"absent",
                      "lastEvidenceSha256":None,"lastOutcome":None}
            path = directory / "active.json"; path.write_text(json.dumps(active)); path.chmod(0o600)
            with mock.patch.object(abort.base, "_campaign_identity", return_value=identity):
                self.assertEqual(active, abort._campaign_record(root, self._record(), DESCRIPTOR))
            fd = os.open(directory / ".environment.lock", os.O_RDWR)
            try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally: os.close(fd)

    def test_campaign_record_rejects_wrong_identity_and_reads_closed_when_no_active(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); identity = self._lease_identity(); directory = root / abort.lease._DIR
            directory.mkdir(parents=True, mode=0o700)
            closed = {"version":1,"identity":identity,"sequence":1,"state":"closed","role":None,
                      "correlationId":None,"server":"stopped","credentials":"absent",
                      "lastEvidenceSha256":"d" * 64,"lastOutcome":"failed-cleaned"}
            path = directory / (abort._LEASE + ".closed.json"); path.write_text(json.dumps(closed)); path.chmod(0o600)
            with mock.patch.object(abort.base, "_campaign_identity", return_value=identity):
                self.assertEqual(closed, abort._campaign_record(root, self._record(), DESCRIPTOR))
            wrong = dict(identity, sourceSha="0" * 40)
            with mock.patch.object(abort.base, "_campaign_identity", return_value=wrong):
                self.assertIsNone(abort._campaign_record(root, self._record(), DESCRIPTOR))

    def _remote_leaf(self, root: Path, *, bundle: bytes = b"payload", mode: int = 0o600,
                     extra: str | None = None) -> tuple[dict[str, str], Path]:
        corr = abort._CORRELATION; binding = {"correlationId": corr, "bundleSha256": hashlib.sha256(bundle).hexdigest()}
        parent = root / "windows-cp117"; group = parent / "windows-update-fixture-http-stage"; authority = parent / "windows-update-fixture-stage" / corr; stage = group / corr
        for path in (parent, group, authority.parent, authority, stage):
            path.mkdir(parents=True, exist_ok=True); path.chmod(0o700)
        (authority / "binding.json").write_text(json.dumps(binding)); (authority / "binding.json").chmod(0o600)
        (stage / "binding.json").write_text(json.dumps({"sha256": binding["bundleSha256"], "length": len(bundle)})); (stage / "binding.json").chmod(0o600)
        (stage / "listener-done.json").write_text(json.dumps({"served": False})); (stage / "listener-done.json").chmod(0o600)
        (stage / "listener-ready.json").write_text("{}"); (stage / "listener-ready.json").chmod(0o600)
        (stage / "bundle.zip").write_bytes(bundle); (stage / "bundle.zip").chmod(mode)
        if extra is not None:
            (stage / extra).write_text("x"); (stage / extra).chmod(0o600)
        return binding, stage

    def _remote_cleanup(self, root: Path, binding: dict[str, str]) -> dict[str, str]:
        digest = binding["bundleSha256"]
        encoded = base64.b64encode(json.dumps(binding).encode()).decode()
        done = subprocess.run([sys.executable, "-c", abort._REMOTE_ABORT, str(root), abort._CORRELATION,
                               digest, str(7), encoded, "cleanup"], capture_output=True, text=True, timeout=10)
        return json.loads(done.stdout)

    def _record(self):
        return {"leaseId": abort._LEASE, "sourceFingerprint": "b" * 64,
                "bundleSha256": "c" * 64, "bundleSize": 7, "routeNonce": "x" * 32,
                "request": {"correlationId": abort._CORRELATION, "sourceSha": abort._SOURCE,
                            "fixtureReceiptArtifactId": ARTIFACT, "baseMsiArtifactId": ARTIFACT,
                            "targetMsiArtifactId": ARTIFACT}}

    def _admit(self, root):
        record = self._record(); config = object(); target = mock.Mock(fixture_transfer_root="/fixture")
        return record, config, target, (
            mock.patch.object(abort.http, "_record", return_value=(root, record, config, target)),
            mock.patch.object(abort.base, "_descriptor", return_value=(object(), target, DESCRIPTOR)),
            mock.patch.object(abort.http.large_transfer, "read", return_value={"phase": "download-submitted"}),
            mock.patch.object(abort.http, "_listener_forensic", return_value=("stopped", "false", 7)),
            mock.patch.object(abort, "_guest", return_value="empty"),
            mock.patch.object(abort, "_host", return_value="absent"),
        )

    def test_status_is_read_only_when_task_or_runtime_is_present(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); _r, _c, _t, patches = self._admit(root)
            patches = list(patches); patches[4] = mock.patch.object(abort, "_guest", return_value="task-present")
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], \
                 mock.patch.object(abort, "_receipt", return_value=False) as receipt, \
                 mock.patch.object(abort, "_campaign_record", return_value={"state":"role-active", "role":"stage", "correlationId":abort._CORRELATION}):
                result = abort.status(root, {"correlationId": abort._CORRELATION})
            self.assertEqual("guest-task-present", result["phase"])
            self.assertFalse(result["abortAllowed"])
            receipt.assert_called_once()

    def test_full_lease_record_admits_exact_active_stage_to_ready(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); _r, _c, _t, patches = self._admit(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], \
                 mock.patch.object(abort, "_receipt", return_value=False), \
                 mock.patch.object(abort, "_campaign_record", return_value={"state":"role-active", "role":"stage", "correlationId":abort._CORRELATION}):
                result = abort.status(root, {"correlationId": abort._CORRELATION})
            self.assertEqual("ready", result["phase"]); self.assertTrue(result["abortAllowed"])

    def test_full_lease_record_recognizes_exact_terminal_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); record, _c, _t, patches = self._admit(root)
            evidence = {"correlationId": abort._CORRELATION, "leaseId": abort._LEASE, "sourceSha": abort._SOURCE,
                        "bundleSha256": record["bundleSha256"], "sourceFingerprint": record["sourceFingerprint"],
                        "guestGeneration": {"socketPath": DESCRIPTOR[1], "qemuPid": DESCRIPTOR[2], "startTicks": DESCRIPTOR[3]},
                        "listener": "stopped-unserved", "guestLeaf": "retained-empty-created", "task": "absent", "runtimeAndInstaller": "absent"}
            digest = hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            with patches[0], patches[1], patches[2], patches[4], \
                 mock.patch.object(abort, "_receipt", return_value=True), \
                 mock.patch.object(abort, "_host", return_value="cleaned"), \
                 mock.patch.object(abort, "_campaign_record", return_value={"state":"active", "role":None, "lastOutcome":"failed-cleaned", "lastEvidenceSha256": digest}):
                result = abort.status(root, {"correlationId": abort._CORRELATION})
            self.assertEqual("retired", result["phase"])

    def test_wrong_source_blocks_before_listener_or_guest_queries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); record = self._record(); record["request"] = {**record["request"], "sourceSha": "0" * 40}
            with mock.patch.object(abort.http, "_record", return_value=(root, record, object(), object())), \
                 mock.patch.object(abort.base, "_descriptor", return_value=(object(), object(), DESCRIPTOR)), \
                 mock.patch.object(abort.http, "_listener_forensic", side_effect=AssertionError("no host")), \
                 mock.patch.object(abort, "_guest", side_effect=AssertionError("no QGA")):
                result = abort.status(root, {"correlationId": abort._CORRELATION})
            self.assertEqual("binding", result["phase"])

    def test_abort_writes_receipt_before_host_cleanup_then_finishes_stage_role(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); record, config, target, patches = self._admit(root); calls = []
            def receipt(_root, value, *, create): calls.append(("receipt", create)); return True
            def host(*args): calls.append(("host", args[-1])); return "cleaned" if args[-1] == "cleanup" else "absent"
            with patches[0], patches[1], patches[2], patches[3], patches[4], \
                 mock.patch.object(abort, "_receipt", side_effect=receipt), \
                 mock.patch.object(abort, "_host", side_effect=host), \
                 mock.patch.object(abort, "_task_admission", return_value=("cleaned", None)), \
                 mock.patch.object(abort, "_campaign_record", return_value={"state":"role-active", "role":"stage", "correlationId":abort._CORRELATION}), \
                 mock.patch.object(abort.lease, "finish_role", return_value={"state": "active"}) as finish, \
                 mock.patch.object(abort.base, "_campaign_remote", return_value=object()):
                result = abort.abort(root, {"correlationId": abort._CORRELATION})
            self.assertEqual("retired", result["state"])
            self.assertEqual([("receipt", False), ("host", "status"), ("receipt", True), ("host", "cleanup")], calls)
            finish.assert_called_once()

    def test_host_unknown_after_durable_receipt_never_finishes_role(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); _r, _c, _t, patches = self._admit(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4], \
                 mock.patch.object(abort, "_receipt", return_value=True), \
                 mock.patch.object(abort, "_host", side_effect=["absent", "unknown"]), \
                 mock.patch.object(abort, "_task_admission", return_value=("cleaned", None)), \
                 mock.patch.object(abort.lease, "finish_role", side_effect=AssertionError("must not finish")):
                result = abort.abort(root, {"correlationId": abort._CORRELATION})
            self.assertEqual("unknown", result["state"])

    def test_host_marker_is_two_phase_for_response_loss_recovery(self):
        pending = abort._REMOTE_ABORT.index("save(dict(base,state='pending'))")
        removed = abort._REMOTE_ABORT.index("shutil.rmtree(s)", pending)
        cleaned = abort._REMOTE_ABORT.index("save(dict(base,state='cleaned'))", removed)
        self.assertLess(pending, removed); self.assertLess(removed, cleaned)
        self.assertIn("if action=='status':out({'state':'pending'})", abort._REMOTE_ABORT)
        # Recovery after a crash inside rmtree permits only a shrinking subset
        # of the original host leaf; foreign files still fail closed.
        self.assertIn("names<={'bundle.zip','binding.json','listener-ready.json','listener-done.json'}", abort._REMOTE_ABORT)
        self.assertIn("names!={'bundle.zip','binding.json','listener-ready.json','listener-done.json'}", abort._REMOTE_ABORT)

    def test_remote_cleanup_rehashes_exact_bundle_before_removal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); payload = b"payload"; binding, stage = self._remote_leaf(root, bundle=payload)
            # The fixed helper receives actual length; mismatch is tested by
            # modifying bytes while retaining their length.
            (stage / "bundle.zip").write_bytes(b"PAYLOAD")
            self.assertEqual({"state": "unknown"}, self._remote_cleanup(root, binding))
            self.assertTrue(stage.exists())

    def test_remote_cleanup_accepts_a_complete_verified_leaf(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); binding, stage = self._remote_leaf(root)
            self.assertEqual({"state": "cleaned"}, self._remote_cleanup(root, binding))
            self.assertFalse(stage.exists())

    def test_remote_cleanup_rejects_wrong_mode_and_foreign_regular_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); binding, stage = self._remote_leaf(root, mode=0o644)
            self.assertEqual({"state": "unknown"}, self._remote_cleanup(root, binding)); self.assertTrue(stage.exists())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); binding, stage = self._remote_leaf(root, extra="foreign.txt")
            self.assertEqual({"state": "unknown"}, self._remote_cleanup(root, binding)); self.assertTrue(stage.exists())

    def test_pending_marker_recovers_only_a_shrinking_verified_leaf(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); binding, stage = self._remote_leaf(root)
            # Simulate a crash after pending was fsynced and one original file
            # had already been removed by rmtree.
            (stage / "bundle.zip").unlink()
            marker = stage.parent / (abort._CORRELATION + ".download-aborted.json")
            marker.write_text(json.dumps({"correlationId": abort._CORRELATION,
                "bindingSha256": hashlib.sha256(json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                "served": False, "state": "pending"})); marker.chmod(0o600)
            self.assertEqual({"state": "cleaned"}, self._remote_cleanup(root, binding))
            self.assertFalse(stage.exists())

    def test_guest_probe_keeps_leaf_and_requires_exact_empty_tree(self):
        self.assertIn("mcp-update-fixture-", abort._REMOTE_GUEST_EMPTY)
        self.assertIn("empty-created", abort._REMOTE_GUEST_EMPTY)
        self.assertNotIn("Remove-Item", abort._REMOTE_GUEST_EMPTY)
        self.assertIn("'msiexec.exe'", abort._REMOTE_GUEST_EMPTY)
        self.assertIn("'sing-box.exe'", abort._REMOTE_GUEST_EMPTY)
        # DirectoryInfo methods return .NET objects without PSIsContainer;
        # use the CLR type so a valid empty tree cannot be misclassified.
        self.assertIn("-is [IO.DirectoryInfo]", abort._REMOTE_GUEST_EMPTY)
        # Any other PowerShell instance may be the submission bootstrap that
        # has not registered its task yet, so it blocks retirement.
        self.assertIn("$_.ProcessId -ne $PID", abort._REMOTE_GUEST_EMPTY)

    def test_bootstrap_presence_blocks_even_when_task_and_file_are_absent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); _r, _c, _t, patches = self._admit(root)
            patches = list(patches); patches[4] = mock.patch.object(abort, "_guest", return_value="bootstrap-present")
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], \
                 mock.patch.object(abort, "_campaign_record", return_value={"state":"role-active", "role":"stage", "correlationId":abort._CORRELATION}):
                result = abort.status(root, {"correlationId": abort._CORRELATION})
            self.assertEqual("guest-bootstrap-present", result["phase"])
            self.assertFalse(result["abortAllowed"])

    def test_no_action_is_replayable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); _r, _c, _t, patches = self._admit(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], \
                 mock.patch.object(abort, "_receipt", return_value=False), \
                 mock.patch.object(abort, "_campaign_record", return_value={"state":"role-active", "role":"stage", "correlationId":abort._CORRELATION}):
                result = abort.status(root, {"correlationId": abort._CORRELATION})
        self.assertFalse(result["replayAllowed"])
        self.assertFalse(result["nativeActionAllowed"])

    def test_abort_reconciles_lost_finish_response_without_repeating_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); details = (root, self._record(), object(), object(), DESCRIPTOR, {"x": 1}, "d" * 64)
            with mock.patch.object(abort, "_admission", side_effect=[("pending-finish", details), ("retired", details)]), \
                 mock.patch.object(abort, "_task_admission", return_value=("cleaned", None)), \
                 mock.patch.object(abort.lease, "reconcile", return_value={"state": "active"}) as reconcile, \
                 mock.patch.object(abort.base, "_campaign_remote", return_value=object()), \
                 mock.patch.object(abort, "_host", side_effect=AssertionError("cleanup must not replay")):
                result = abort.abort(root, {"correlationId": abort._CORRELATION})
            self.assertEqual("retired", result["state"])
            reconcile.assert_called_once()

    def test_pending_finish_without_exact_receipt_and_clean_marker_never_reconciles(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(abort, "_admission", return_value=("pending-finish-marker", None)), \
                 mock.patch.object(abort, "_task_admission", return_value=("cleaned", None)), \
                 mock.patch.object(abort.lease, "reconcile", side_effect=AssertionError("must not reconcile")):
                result = abort.abort(root, {"correlationId": abort._CORRELATION})
            self.assertEqual("unknown", result["state"])

    def test_task_cleanup_writes_intent_before_exact_qga_unregistration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); record = self._record(); details = (root, record, object(), object(), DESCRIPTOR, {"actionSha256":"d" * 64})
            with mock.patch.object(abort, "_task_admission", return_value=("ready", details)), \
                 mock.patch.object(abort, "_task_receipt", return_value=True) as receipt, \
                 mock.patch.object(abort.base, "_remote", return_value=b'{"state":"cleaned"}') as remote:
                result = abort.task_cleanup(root, {"correlationId": abort._CORRELATION})
            self.assertEqual("cleaned", result["state"]); receipt.assert_called_once()
            self.assertIs(remote.call_args.args[1], abort._REMOTE_TASK_CLEANUP)

    def test_failed_bound_task_present_with_empty_leaf_is_ready_then_dispatches_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); record = self._record(); config = object(); target = mock.Mock()
            diagnostic = {"phase":"task-failed", "download":"absent", "listener":"stopped", "listenerServed":"false"}
            with mock.patch.object(abort.http, "_record", return_value=(root, record, config, target)), \
                 mock.patch.object(abort.base, "_descriptor", return_value=(object(), target, DESCRIPTOR)), \
                 mock.patch.object(abort.http.large_transfer, "read", return_value={"phase":"download-submitted"}), \
                 mock.patch.object(abort.http, "guest_download_diagnostic", return_value=diagnostic), \
                 mock.patch.object(abort, "_guest_task_failed", return_value="failed-task-safe"), \
                 mock.patch.object(abort.http, "_listener_forensic", return_value=("stopped","false",7)), \
                 mock.patch.object(abort.http, "_submitted_download_script", return_value="frozen-submitted-script") as submitted:
                phase, details = abort._task_admission(root)
            self.assertEqual("ready", phase); self.assertIsNotNone(details)
            submitted.assert_called_once()
            self.assertIn("[Convert]::GetTypeCode($rawResult)", abort._REMOTE_TASK_CLEANUP)
            self.assertIn("$taskResult+=4294967296", abort._REMOTE_TASK_CLEANUP)
            self.assertIn("$taskResult -eq 0", abort._REMOTE_TASK_CLEANUP)
            self.assertIn("$result='cleaned'", abort._REMOTE_TASK_CLEANUP)
            self.assertIn("@{state=$result}", abort._REMOTE_TASK_CLEANUP)
            self.assertNotIn("@{state=(if", abort._REMOTE_TASK_CLEANUP)

    def test_task_cleanup_never_dispatches_wrong_or_running_task(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for phase in ("diagnostic-task-running", "diagnostic-unknown", "guest-not-safe"):
                with self.subTest(phase=phase), mock.patch.object(abort, "_task_admission", return_value=(phase, None)), \
                     mock.patch.object(abort.base, "_remote", side_effect=AssertionError("no QGA")):
                    self.assertEqual("unknown", abort.task_cleanup(root, {"correlationId": abort._CORRELATION})["state"])

    def test_fallback_binding_cannot_rearm_stage_role(self):
        # The fallback is solely for a lost finish response or an already
        # retired receipt; it must never make a failed normal admission ready.
        self.assertIn("fallback and not", Path(abort.__file__).read_text())
        self.assertIn('"retired-binding-invalid"', Path(abort.__file__).read_text())
