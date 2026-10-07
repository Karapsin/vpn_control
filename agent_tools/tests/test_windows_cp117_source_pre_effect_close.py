from __future__ import annotations

import tempfile
import base64
import json
import hashlib
import gzip
import re
import contextlib
import io
import os
import stat
import sys
import fcntl
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_tools import windows_cp117_source_pre_effect_close as close


PROOF = {"first": {"task": "absent"}, "second": {"task": "absent"}, "before": {"activeCount": 0}, "after": {"activeCount": 0}, "remoteJournalAbsent": True, "localJournalAbsent": True}
MARKER = {"version": 1, "state": "verified-pre-effect-absence", "correlationId": close._CORRELATION,
          "intentSha256": "a" * 64, "commandSha256": "b" * 64, "pairSha256": "c" * 64,
          "guestGeneration": {"environment": "windows-cp117", "socketPath": "/qga", "qemuPid": 1,
                              "startTicks": 2, "expectedSid": "S-1-5-21-1"}, "proof": PROOF,
          "proofSha256": hashlib.sha256(json.dumps(PROOF, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}


@contextlib.contextmanager
def source67_archive_fixture():
    """Actual private records and validators; replace only remote observations."""
    descriptor = ("windows-cp117", "/qga", 1, 2, "S-1-5-21-1")
    pair = {"sourceFingerprint": "c" * 64, "sourceSha": close.source._SOURCE}
    command = "fixed archived bootstrap"
    intent = {"request": close._exact_request(), "pair": pair, "leaseId": close._CORRELATION,
              "environment": descriptor[0], "socketPath": descriptor[1], "pid": descriptor[2],
              "startTicks": descriptor[3], "expectedSid": descriptor[4],
              "commandSha256": hashlib.sha256(command.encode("utf-16le")).hexdigest()}
    guest = {"state": "observed", "correlationId": close._CORRELATION, "remoteStage": "absent", "mutation": "none",
             "task": "absent", "leaf": "absent", "result": "absent", "correlationPowerShell": "absent",
             "product": "single", "installedVersion": close.source._BASE_VERSION, "installer": "absent"}
    ready = {"installedVersion": close.source._BASE_VERSION, "productCount": 1, "activeCount": 0, "activeProcesses": []}
    with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
        root = Path(directory); parent = root / close.base._LOCAL; parent.mkdir(parents=True, mode=0o700)
        original = close.base._intent_path(root, close._CORRELATION)
        original.write_text(json.dumps(intent, sort_keys=True)); original.chmod(0o600)
        target = type("Target", (), {"fixture_transfer_root": "/private"})()
        stack.enter_context(patch.object(close.base, "_descriptor", return_value=(object(), target, descriptor)))
        stack.enter_context(patch.object(close.base, "_stage_artifact_readonly", return_value=(pair, 1)))
        stack.enter_context(patch.object(close.source, "_new_pair", return_value=pair))
        stack.enter_context(patch.object(close.source, "_replacement_bootstrap", return_value=command))
        stack.enter_context(patch.object(close, "_remote_absent", return_value=True))
        stack.enter_context(patch.object(close, "_guest_absent", return_value=guest))
        stack.enter_context(patch.object(close, "_ready", return_value=ready))
        phase, marker = close._status(root)
        assert phase == "verified-absence"
        path = close._marker(root); path.write_text(json.dumps(marker, sort_keys=True)); path.chmod(0o600)
        yield root, descriptor, intent, marker


class SourcePreEffectCloseTests(unittest.TestCase):
    def test_status_rechecks_descriptor_tuple_not_transport_container(self):
        descriptor = ("windows-cp117", "/qga", 1, 2, "S-1-5-21-1")
        config, target = object(), object()
        intent, pair = {"request": {}}, {"source": "fixed"}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(close.base, "_descriptor", return_value=(config, target, descriptor)), \
                patch.object(close, "_intent", return_value=(intent, pair, "b" * 64)) as admit, \
                patch.object(close, "_local_absent", return_value=True), \
                patch.object(close, "_remote_absent", return_value=True), \
                patch.object(close, "_guest_absent", return_value={"task": "absent"}), \
                patch.object(close, "_ready", return_value={"activeCount": 0}):
            phase, marker = close._status(Path(directory))
        self.assertEqual("verified-absence", phase)
        self.assertEqual(descriptor[2], marker["guestGeneration"]["qemuPid"])
        self.assertEqual(descriptor, admit.call_args.args[1])

    def test_status_preserves_unknown_start_as_current_verified_absence(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(close, "_status", return_value=("verified-absence", MARKER)):
            self.assertEqual({**close._UNKNOWN, "state": "observed", "phase": "verified-absence",
                              "correlationId": close._CORRELATION}, close.status(directory))

    def test_close_writes_only_create_once_marker_after_verified_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / close.base._LOCAL).mkdir(parents=True); (root / close.lease._DIR).mkdir(parents=True); (root / close.lease._DIR).chmod(0o700)
            for path in (root / close.base._LOCAL / ".environment.lock", root / close.lease._DIR / ".environment.lock"):
                path.write_bytes(b""); path.chmod(0o600)
            with patch.object(close, "_status", return_value=("verified-absence", MARKER)):
                result = close.close(root)
            self.assertEqual("closed", result["state"])
            self.assertEqual(MARKER["proofSha256"], result["closureReceiptSha256"])
            with patch.object(close, "_status", return_value=("closed", MARKER)):
                self.assertEqual(result, close.close(root))

    def test_marker_conflict_and_unverified_status_never_close(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / close.base._LOCAL).mkdir(parents=True); (root / close.lease._DIR).mkdir(parents=True); (root / close.lease._DIR).chmod(0o700)
            for path in (root / close.base._LOCAL / ".environment.lock", root / close.lease._DIR / ".environment.lock"):
                path.write_bytes(b""); path.chmod(0o600)
            with patch.object(close, "_status", return_value=("guest-census", None)):
                result = close.close(root)
            self.assertEqual("unknown", result["state"])
            self.assertEqual("guest-census", result["phase"])
            marker = close._marker(root)
            marker.write_text("{}")
            with patch.object(close, "_status", return_value=("verified-absence", MARKER)):
                self.assertEqual("marker-conflict", close.close(root)["phase"])

    def test_fixed_action_rejects_substitution(self):
        with self.assertRaises(ValueError):
            close.workflow(".", "status", {"leaseId": close._CORRELATION})
        self.assertIn("verified-absence", close.PHASES)
        self.assertNotIn("never-dispatched", close.PHASES)

    def test_guest_census_uses_219_embedded_remote_and_rejects_wrong_version(self):
        intent = {"request": close._exact_request(), "pair": {"sourceFingerprint": "a" * 64},
                  "commandSha256": "b" * 64}
        descriptor = ("windows-cp117", "/qga", 1, 2, "S-1-5-21-1")
        target = type("Target", (), {"fixture_transfer_root": "/private"})()
        value = {"state": "observed", "correlationId": close._CORRELATION, "remoteStage": "absent", "mutation": "none",
                 "task": "absent", "leaf": "absent", "result": "absent", "correlationPowerShell": "absent",
                 "product": "single", "installedVersion": "2.1.19", "installer": "absent"}
        with patch.object(close.base, "_remote", return_value=json.dumps(value).encode()) as remote:
            self.assertIsNotNone(close._guest_absent(object(), target, intent, descriptor))
        self.assertEqual(close._NO_EFFECT_REMOTE, remote.call_args.args[1])
        with patch.object(close.base, "_remote", return_value=json.dumps({**value, "installedVersion": "2.1.17"}).encode()):
            self.assertIsNone(close._guest_absent(object(), target, intent, descriptor))
        # The diagnostic must not call this structurally-valid but unsafe
        # census "observed": closure would reject it.
        with patch.object(close.base, "_remote", return_value=json.dumps({**value, "installedVersion": "2.1.17"}).encode()):
            self.assertEqual("unsafe", close._guest_census_phase(object(), target, intent, descriptor))

    def _run_no_effect_remote(self, *, parser_valid=True, census_status=None, mode="status", calls=None):
        """Execute the emitted observer after its QGA prelude with a live fake QGA."""
        body = "import base64,json,os,re,stat,sys,time" + close._NO_EFFECT_REMOTE.split("import time", 1)[1]
        calls = [] if calls is None else calls
        parser_source: list[str] = []
        census_source: list[str] = []
        safe_census = {"version": 1, "phase": "output", "task": "absent", "leaf": "absent",
                       "result": "absent", "correlationPowerShell": "absent", "product": "single",
                       "installedVersion": "2.1.19", "installer": "absent"}

        def call(_sock, command, args):
            calls.append((command, args))
            if command == "guest-exec":
                encoded = args["arg"][-1]
                decoded = base64.b64decode(encoded).decode("utf-16le")
                if len(parser_source) == 0:
                    parser_source.append(decoded)
                    packed = re.search(r"FromBase64String\('([^']+)'\)", decoded).group(1)
                    census_source.append(gzip.decompress(base64.b64decode(packed)).decode("utf-16le"))
                    return {"pid": 1}
                self.assertEqual(census_source[0], decoded)
                return {"pid": 2}
            self.assertEqual("guest-exec-status", command)
            pid = args["pid"]
            if pid == 1:
                payload = {"version": 1, "valid": parser_valid}
            else:
                if census_status is not None:
                    return census_status
                payload = safe_census
            return {"exited": True, "exitcode": 0, "out-truncated": False, "err-truncated": False,
                    "out-data": base64.b64encode(json.dumps(payload).encode()).decode()}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700)
            (root / "windows-cp117").mkdir(); (root / "windows-cp117").chmod(0o700)
            output = io.StringIO()
            argv = ["remote", str(root), "windows-cp117", close._CORRELATION, "/qga", "1", "2",
                    "d" * 64, "e" * 64, "receipt", "base", "target", "f" * 64, "S-1-5-21-1", mode]
            scope = {"live": lambda *_: True, "call": call, "decode": lambda raw: raw.decode("utf-8")}
            with patch.object(sys, "argv", argv), contextlib.redirect_stdout(output):
                try:
                    exec(body, scope)
                except SystemExit:
                    pass
        return calls, parser_source, census_source, output.getvalue()

    def test_no_effect_remote_parses_exact_gzipped_census_before_dispatch(self):
        calls, parser_source, census_source, output = self._run_no_effect_remote()
        self.assertIn("[Management.Automation.Language.Parser]::ParseInput", parser_source[0])
        self.assertEqual(2, len([call for call in calls if call[0] == "guest-exec"]))
        parser_encoded = calls[0][1]["arg"][-1]
        census_encoded = calls[2][1]["arg"][-1]
        self.assertLess(len(parser_encoded), 30000)
        self.assertLess(len(census_encoded), 30000)
        self.assertIn("Get-ScheduledTask", census_source[0])
        self.assertEqual("observed", json.loads(output)["state"])

    def test_no_effect_remote_invalid_ast_result_never_dispatches_census(self):
        calls, parser_source, census_source, output = self._run_no_effect_remote(parser_valid=False)
        self.assertTrue(parser_source)
        self.assertTrue(census_source)
        self.assertEqual(["guest-exec", "guest-exec-status"], [call[0] for call in calls])
        self.assertEqual({"state": "unknown", "correlationId": close._CORRELATION, "phase": "guest-qga-exec"},
                         json.loads(output))

    def _diagnostic_phase_from_emitted_output(self, output: str):
        intent = {"request": close._exact_request(), "pair": {"sourceFingerprint": "e" * 64},
                  "commandSha256": "f" * 64}
        descriptor = ("windows-cp117", "/qga", 1, 2, "S-1-5-21-1")
        target = type("Target", (), {"fixture_transfer_root": "/private"})()
        with patch.object(close.base, "_remote", return_value=output.encode()):
            return close._guest_census_phase(object(), target, intent, descriptor)

    def test_guest_census_diagnostic_preserves_only_emitted_finite_failures(self):
        _calls, _parser, _census, parser_failure = self._run_no_effect_remote(parser_valid=False)
        _calls, _parser, _census, status_failure = self._run_no_effect_remote(
            census_status={"exited": "malformed"})
        _calls, _parser, _census, output_failure = self._run_no_effect_remote(
            census_status={"exited": True, "exitcode": 0, "out-truncated": False, "err-truncated": False,
                           "out-data": base64.b64encode(b"not-json").decode()})
        _calls, _parser, _census, observed = self._run_no_effect_remote()
        self.assertEqual("guest-qga-exec", self._diagnostic_phase_from_emitted_output(parser_failure))
        self.assertEqual("guest-qga-status-exited-malformed", self._diagnostic_phase_from_emitted_output(status_failure))
        self.assertEqual("guest-empty-or-malformed-output", self._diagnostic_phase_from_emitted_output(output_failure))
        self.assertEqual("observed", self._diagnostic_phase_from_emitted_output(observed))
        self.assertIsNone(self._diagnostic_phase_from_emitted_output(json.dumps(
            {"state": "unknown", "correlationId": close._CORRELATION, "phase": "private-data"})))

    def test_diagnose_is_read_only_and_returns_no_remote_census_payload(self):
        descriptor = ("windows-cp117", "/qga", 1, 2, "S-1-5-21-1")
        intent = {"request": close._exact_request(), "pair": {"sourceFingerprint": "e" * 64},
                  "commandSha256": "f" * 64}
        target = type("Target", (), {"fixture_transfer_root": "/private"})()
        remote = {"state": "unknown", "correlationId": close._CORRELATION,
                  "phase": "guest-empty-or-malformed-output"}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(close.base, "_descriptor", return_value=(object(), target, descriptor)), \
                patch.object(close, "_intent", return_value=(intent, intent["pair"], intent["commandSha256"])), \
                patch.object(close.base, "_remote", return_value=json.dumps(remote).encode()) as call:
            result = close.diagnose(directory, {})
        self.assertEqual({**close._UNKNOWN, "state": "unknown", "phase": "guest-census",
                          "guestCensusPhase": "guest-empty-or-malformed-output",
                          "correlationId": close._CORRELATION}, result)
        self.assertEqual(close._NO_EFFECT_REMOTE, call.call_args.args[1])

    def test_no_effect_remote_rejects_every_non_status_mode_before_qga_dispatch(self):
        for mode in ("cleanup", "start", ""):
            with self.subTest(mode=mode):
                calls = []
                with self.assertRaises(ValueError):
                    self._run_no_effect_remote(mode=mode, calls=calls)
                self.assertEqual([], calls)

    def test_embedded_remote_journal_reader_allows_closed_history_and_rejects_unsafe_tree(self):
        body = "import fcntl,json,os,re,stat,sys" + close._REMOTE_JOURNAL.split("import fcntl,json,os,re,stat,sys", 1)[1]
        def run(root):
            output = io.StringIO(); scope = {"live": lambda *_: True}
            with patch.object(sys, "argv", ["remote", root, "windows-cp117", close._CORRELATION, "/qga", "1", "2"]), contextlib.redirect_stdout(output):
                try: exec(body, scope)
                except SystemExit: pass
            return json.loads(output.getvalue())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700)
            parent = root / "windows-cp117"; group = parent / "windows-cp117-campaign"
            group.mkdir(parents=True); parent.chmod(0o700); group.chmod(0o700)
            lock = group / ".environment.lock"; lock.write_bytes(b""); lock.chmod(0o600)
            other = group / "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa.closed.json"; other.write_text("{}"); other.chmod(0o600)
            self.assertEqual({"state": "absent"}, run(str(root)))
            (group / "unsafe.txt").write_text("x")
            self.assertEqual({"state": "unknown"}, run(str(root)))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700)
            os.symlink("missing", root / "windows-cp117")
            self.assertEqual({"state": "unknown"}, run(str(root)))

    def test_held_existing_lock_blocks_marker_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / close.base._LOCAL).mkdir(parents=True); (root / close.lease._DIR).mkdir(parents=True); (root / close.lease._DIR).chmod(0o700)
            locks = [root / close.base._LOCAL / ".environment.lock", root / close.lease._DIR / ".environment.lock"]
            for path in locks: path.write_bytes(b""); path.chmod(0o600)
            fd = os.open(locks[0], os.O_RDWR); fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                with patch.object(close, "_status", return_value=("verified-absence", MARKER)):
                    self.assertEqual("local-journal", close.close(root)["phase"])
            finally: os.close(fd)
            self.assertFalse(close._marker(root).exists())

    def test_active_race_after_last_observation_prevents_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / close.base._LOCAL).mkdir(parents=True); (root / close.lease._DIR).mkdir(parents=True); (root / close.lease._DIR).chmod(0o700)
            for path in (root / close.base._LOCAL / ".environment.lock", root / close.lease._DIR / ".environment.lock"):
                path.write_bytes(b""); path.chmod(0o600)
            def raced(_root, **_kwargs):
                (root / close.lease._DIR / "active.json").write_text("{}")
                return "verified-absence", MARKER
            with patch.object(close, "_status", side_effect=raced):
                self.assertEqual("local-journal", close.close(root)["phase"])
            self.assertFalse(close._marker(root).exists())

    def test_marker_requires_exact_generation_and_proof_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / close.base._LOCAL).mkdir(parents=True)
            marker = close._marker(root); marker.write_text(json.dumps(MARKER)); marker.chmod(0o600)
            wrong = {**MARKER, "guestGeneration": {**MARKER["guestGeneration"], "startTicks": 9}}
            self.assertEqual(MARKER, close._read_marker(marker, MARKER))
            self.assertIsNone(close._read_marker(marker, wrong))

    def test_marker_tampered_preimage_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / close.base._LOCAL).mkdir(parents=True)
            marker = close._marker(root); marker.write_text(json.dumps({**MARKER, "proof": {"tampered": True}})); marker.chmod(0o600)
            self.assertIsNone(close._read_marker(marker))


class Source67ArchiveProofTests(unittest.TestCase):
    def test_archive_proof_validates_private_records_and_hashes_exact_marker(self):
        with source67_archive_fixture() as (root, descriptor, intent, marker):
            original = close.base._intent_path(root, close._CORRELATION)
            before = (original.read_bytes(), close._marker(root).read_bytes())
            proof = close.archive_proof(root, descriptor)
            self.assertEqual("archived", proof["state"])
            self.assertEqual(hashlib.sha256(before[1]).hexdigest(), proof["markerSha256"])
            self.assertEqual(marker["intentSha256"], proof["intentSha256"])
            self.assertTrue(all(proof[k] is False for k in ("replayAllowed", "nativeActionAllowed", "productAction")))
            self.assertEqual(before, (original.read_bytes(), close._marker(root).read_bytes()))

    def test_missing_malformed_hash_type_and_binding_changes_deny_archive(self):
        changes = ({"pairSha256": "0" * 64}, {"intentSha256": "0" * 64}, {"commandSha256": "0" * 64},
                   {"proofSha256": "0" * 64}, {"version": True},
                   {"guestGeneration": {"environment": "windows-cp117", "socketPath": "/qga", "qemuPid": True, "startTicks": 2, "expectedSid": "S-1-5-21-1"}})
        for change in changes:
            with self.subTest(change=change), source67_archive_fixture() as (root, descriptor, _intent, marker):
                close._marker(root).write_text(json.dumps({**marker, **change}))
                self.assertEqual("unknown", close.archive_proof(root, descriptor)["state"])
        for mode in ("missing", "malformed", "unsafe-mode"):
            with self.subTest(mode=mode), source67_archive_fixture() as (root, descriptor, _intent, _marker):
                path = close._marker(root)
                if mode == "missing": path.unlink()
                elif mode == "malformed": path.write_text("{}")
                else: path.chmod(0o644)
                self.assertEqual("unknown", close.archive_proof(root, descriptor)["state"])

    def test_unknown_current_proof_changed_generation_or_original_intent_deny_archive(self):
        with source67_archive_fixture() as (root, descriptor, intent, _marker):
            with patch.object(close, "_guest_absent", return_value=None):
                self.assertEqual("fresh", close.archive_proof(root, descriptor)["phase"])
            with patch.object(close, "status", return_value={**close._UNKNOWN, "state": "observed", "phase": "closed", "correlationId": close._CORRELATION, "replayAllowed": True}):
                self.assertEqual("unknown", close.archive_proof(root, descriptor)["state"])
            other = (*descriptor[:2], 99, *descriptor[3:])
            self.assertEqual("unknown", close.archive_proof(root, other)["state"])
            close.base._intent_path(root, close._CORRELATION).write_text(json.dumps({**intent, "pair": {"sourceFingerprint": "changed"}}))
            self.assertEqual("unknown", close.archive_proof(root, descriptor)["state"])


class Source67LeafRetirementTests(unittest.TestCase):
    def test_leaf_retirement_unknown_consumes_intent_before_single_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binding = {"retirementCorrelationId": close._LEAF_RETIREMENT}
            for parent in (root / close.base._LOCAL, root / close.lease._DIR):
                parent.mkdir(parents=True); parent.chmod(0o700)
                (parent / ".environment.lock").write_bytes(b"")
                (parent / ".environment.lock").chmod(0o600)
            descriptor = ("windows-cp117", "/qga", 1, 2, "S-1-5-21-1")
            def dispatch(*args):
                self.assertTrue(close._leaf_retire_intent(root).exists())
                return None
            with patch.object(close, "_leaf_retire_ready", return_value=(object(), descriptor, binding, {"owned": True}, "ready")), \
                    patch.object(close, "_local_absent", return_value=True), \
                    patch.object(close.base, "_descriptor", return_value=(object(), object(), descriptor)), \
                    patch.object(close, "_leaf_retire_dispatch", side_effect=dispatch) as submitted, \
                    patch.object(close, "leaf_retire_status", return_value={**close._UNKNOWN, "state": "unknown"}):
                self.assertEqual("unknown", close.leaf_retire_start(root, {})["state"])
                self.assertEqual("unknown", close.leaf_retire_start(root, {})["state"])
            self.assertEqual(1, submitted.call_count)

    def test_leaf_retirement_parser_failure_does_not_reserve_or_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for parent in (root / close.base._LOCAL, root / close.lease._DIR):
                parent.mkdir(parents=True); parent.chmod(0o700)
                (parent / ".environment.lock").write_bytes(b"")
                (parent / ".environment.lock").chmod(0o600)
            with patch.object(close, "_leaf_retire_ready", return_value=(None, None, None, None, "parser")), \
                    patch.object(close, "_local_absent", return_value=True), \
                    patch.object(close, "_leaf_retire_dispatch") as submitted:
                self.assertEqual("parser", close.leaf_retire_start(root, {})["phase"])
                self.assertFalse(close._leaf_retire_intent(root).exists())
                submitted.assert_not_called()

    def test_leaf_retirement_fixed_input_rejects_substitution(self):
        for action in (close.leaf_retire_start, close.leaf_retire_status, close.leaf_retire_preflight):
            with self.assertRaises(ValueError): action(".", {"correlationId": close._CORRELATION})

    def _binding_proof(self):
        sid = 'S-1-5-21-2404255130-2183793310-3766671872-1002'
        binding = {'retirementCorrelationId':close._LEAF_RETIREMENT,'sourceCorrelationId':close._CORRELATION,
                   'generation':{'environment':'windows-cp117','socketPath':'/qga','qemuPid':1,'startTicks':2,'expectedSid':sid},
                   'commandSha256':'a'*64,'originalIntentSha256':'b'*64,'pairSha256':'c'*64,
                   'baseMsiSha256':close._LEAF_SHA256,'baseMsiBytes':close._LEAF_SIZE}
        proof = {'bytes':close._LEAF_SIZE,'sha256':close._LEAF_SHA256}
        for key, inheritance in (('root',3),('file',0)):
            flag = 'OICIID' if inheritance else 'ID'
            sddl = 'O:'+sid+'G:S-1-5-21-2404255130-2183793310-3766671872-513D:'
            sddl += '(A;'+flag+';FA;;;SY)(A;'+flag+';FA;;;BA)(A;'+flag+';FA;;;'+sid+')'
            proof[key] = {'identity':'00000001:'+ ('1' if key == 'root' else '2')*16,'owner':sid,'protected':False,
                          'sddl':sddl,'created':'123','written':'124','attributes':16 if key=='root' else 32,
                          'acl':[{'sid':who,'rights':2032127,'type':'Allow','inherited':True,'inheritance':inheritance,'propagation':0}
                                 for who in ('S-1-5-18','S-1-5-32-544',sid)]}
        return binding, proof

    def test_leaf_proof_rejects_wrong_bytes_acl_identity_reparse_and_metadata(self):
        import copy
        binding, proof = self._binding_proof()
        self.assertTrue(close._leaf_proof(proof,binding))
        mutations = [lambda p:p.update(bytes=True),lambda p:p.update(bytes=close._LEAF_SIZE-1),
                     lambda p:p.update(sha256='0'*64),lambda p:p['root'].update(protected=True),
                     lambda p:p['file'].update(attributes=1056),lambda p:p['file'].update(identity='00000002:'+'2'*16),
                     lambda p:p['root'].update(sddl='arbitrary'),lambda p:p['file'].update(owner='S-1-5-18'),
                     lambda p:p['file']['acl'][0].update(inherited=False),lambda p:p['root']['acl'][0].update(rights=1179817),
                     lambda p:p['root']['acl'][1].update(sid='S-1-5-18'),lambda p:p['root']['acl'][0].update(inheritance=0)]
        for change in mutations:
            altered=copy.deepcopy(proof);change(altered)
            self.assertFalse(close._leaf_proof(altered,binding))

    def test_readiness_requires_two_identical_owned_proofs_and_parsed_mutation(self):
        binding, proof = self._binding_proof();descriptor=('windows-cp117','/qga',1,2,binding['generation']['expectedSid'])
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(close.base,'_descriptor',return_value=(object(),object(),descriptor)), \
                patch.object(close,'_leaf_retire_binding',return_value=binding), \
                patch.object(close,'_local_absent',return_value=True), \
                patch.object(close,'_remote_absent',return_value=True), \
                patch.object(close,'_leaf_guest_census',return_value=True), \
                patch.object(close,'_ready',return_value={'activeCount':0}):
            with patch.object(close,'_leaf_parse',return_value=True), patch.object(close,'_leaf_run',side_effect=[proof,proof]):
                self.assertEqual('ready',close._leaf_retire_ready(Path(directory))[-1])
            with patch.object(close,'_leaf_parse',return_value=False), patch.object(close,'_leaf_run') as read:
                self.assertEqual('parser',close._leaf_retire_ready(Path(directory))[-1]);read.assert_not_called()
            with patch.object(close,'_leaf_parse',return_value=True), patch.object(close,'_leaf_run',side_effect=[proof,{**proof,'sha256':'0'*64}]):
                self.assertEqual('recheck',close._leaf_retire_ready(Path(directory))[-1])
            with patch.object(close,'_leaf_parse',side_effect=[True,False]), patch.object(close,'_leaf_run',side_effect=[proof,proof]):
                self.assertEqual('parser',close._leaf_retire_ready(Path(directory))[-1])

    def test_status_tampered_local_preimage_rendered_action_or_generation_never_reads_guest(self):
        binding, proof = self._binding_proof();descriptor=('windows-cp117','/qga',1,2,binding['generation']['expectedSid'])
        intent={'version':1,'binding':binding,'proof':proof,'bindingSha256':close._leaf_sha(binding),
                'proofSha256':close._leaf_sha(proof),'mutationSha256':hashlib.sha256(close._leaf_script(binding,'start',proof).encode()).hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for change in ({'bindingSha256':'0'*64},{'proofSha256':'0'*64},{'mutationSha256':'0'*64},{'version':True}, {'proof':{}}):
                with patch.object(close,'_leaf_retire_record',return_value={**intent,**change}), \
                        patch.object(close.base,'_descriptor',return_value=(object(),object(),descriptor)), \
                        patch.object(close,'_leaf_retire_binding',return_value=binding), \
                        patch.object(close,'_leaf_run') as read:
                    self.assertEqual('unknown',close.leaf_retire_status(root,{})['state']);read.assert_not_called()

    def test_status_missing_or_unknown_terminal_never_retires(self):
        binding, proof = self._binding_proof();descriptor=('windows-cp117','/qga',1,2,binding['generation']['expectedSid'])
        intent={'version':1,'binding':binding,'proof':proof,'bindingSha256':close._leaf_sha(binding),
                'proofSha256':close._leaf_sha(proof),'mutationSha256':hashlib.sha256(close._leaf_script(binding,'start',proof).encode()).hexdigest()}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(close,'_leaf_retire_record',return_value=intent), \
                patch.object(close.base,'_descriptor',return_value=(object(),object(),descriptor)), \
                patch.object(close,'_leaf_retire_binding',return_value=binding), \
                patch.object(close,'_local_absent',return_value=True), \
                patch.object(close,'_remote_absent',return_value=True), \
                patch.object(close,'_ready',return_value={'activeCount':0}), \
                patch.object(close,'_leaf_parse',return_value=True), \
                patch.object(close,'_leaf_guest_census',return_value=True):
            for observed in (None,{}, {'state':'unknown'}, {'state':'terminal','extra':True}):
                with patch.object(close,'_leaf_run',return_value=observed):
                    self.assertEqual('unknown',close.leaf_retire_status(directory,{})['state'])
            with patch.object(close,'_leaf_run',return_value={'state':'terminal'}):
                self.assertEqual('retired',close.leaf_retire_status(directory,{})['state'])
                with patch.object(close,'_leaf_guest_census',return_value=False):
                    self.assertEqual('unknown',close.leaf_retire_status(directory,{})['state'])
                with patch.object(close,'_local_absent',return_value=False):
                    self.assertEqual('unknown',close.leaf_retire_status(directory,{})['state'])

    def test_exact_rendered_sources_fit_transport_and_parser_never_executes_body(self):
        from agent_tools import windows_cp117_c32_retained_task_retire as transport
        binding, proof=self._binding_proof()
        for mode in ('preflight','start','status'):
            source=close._leaf_script(binding,mode,proof)
            wrapper=close._leaf_wrapper(source)
            packed=re.search(r"FromBase64String\('([^']+)'\)",wrapper).group(1)
            self.assertEqual(source,gzip.decompress(base64.b64decode(packed)).decode())
            self.assertLess(len(base64.b64encode(wrapper.encode('utf-16le'))),30000)
            parser=transport._parse_script(source)
            self.assertLess(len(base64.b64encode(close._leaf_wrapper(parser).encode('utf-16le'))),30000)
            parsed=re.search(r"FromBase64String\('([^']+)'\)",parser).group(1)
            self.assertEqual(source,gzip.decompress(base64.b64decode(parsed)).decode())
            self.assertNotIn('[scriptblock]::Create',parser)

    def _execute_remote_dispatch(self, *, active=False, result=None, generation=True):
        from agent_tools import windows_cp117_c32_retained_task_retire as transport
        binding,proof=self._binding_proof();source=close._leaf_script(binding,'start',proof)
        encoded=base64.b64encode(close._leaf_wrapper(source).encode('utf-16le')).decode()
        body='import base64,fcntl,json,os,stat,sys,time'+transport._REMOTE_DISPATCH.split('import base64,fcntl,json,os,stat,sys,time',1)[1]
        calls=[]
        def call(_sock,command,args):
            calls.append((command,args))
            if command=='guest-exec':return {'pid':9}
            self.assertEqual('guest-exec-status',command)
            return result or {'exited':True,'exitcode':0,'out-truncated':False,'err-truncated':False,
                              'out-data':base64.b64encode(b'{"state":"terminal"}').decode()}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o700);parent=root/'windows-cp117';parent.mkdir(mode=0o700)
            group=parent/'windows-cp117-campaign';group.mkdir(mode=0o700)
            (group/'.environment.lock').write_bytes(b'');(group/'.environment.lock').chmod(0o600)
            if active:(group/'active.json').write_text('{}')
            output=io.StringIO()
            with patch.object(sys,'argv',['remote',str(root),'windows-cp117','/qga','1','2',encoded]), contextlib.redirect_stdout(output):
                exec(body,{'live':lambda *_:generation,'call':call,'decode':lambda raw:raw.decode()})
            return calls,json.loads(output.getvalue())

    def test_actual_dispatch_python_checks_lease_generation_and_finite_terminal(self):
        calls,value=self._execute_remote_dispatch()
        self.assertEqual({'state':'observed','receipt':{'state':'terminal'}},value)
        self.assertEqual(1,sum(cmd=='guest-exec' for cmd,_ in calls))
        for kwargs in ({'active':True},{'generation':False}):
            calls,value=self._execute_remote_dispatch(**kwargs)
            self.assertEqual([],calls);self.assertEqual({'state':'unknown'},value)
        for state in ({'exited':True,'exitcode':1}, {'exited':True,'exitcode':0,'out-truncated':True},
                      {'exited':True,'exitcode':0,'out-data':base64.b64encode(b'{"state":"retired"}').decode()},
                      {'exited':True,'exitcode':0,'out-data':base64.b64encode(b' '*1025).decode()}):
            calls,value=self._execute_remote_dispatch(result=state)
            self.assertEqual({'state':'unknown'},value)
            self.assertEqual(1,sum(cmd=='guest-exec' for cmd,_ in calls))

    def test_transport_rejects_oversize_or_extra_terminal_before_success(self):
        descriptor=('windows-cp117','/qga',1,2,'S-1-5-21-1')
        with patch.object(close.base,'_remote',return_value=b'x'*9001):
            self.assertIsNone(close._leaf_run(object(),descriptor,'inert'))
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(close.base,'_descriptor',return_value=(object(),type('T',(),{'fixture_transfer_root':'/private'})(),descriptor)), \
                patch.object(close.base,'_remote',return_value=b'{"state":"observed","receipt":{"state":"terminal"},"extra":true}'):
            self.assertIsNone(close._leaf_retire_dispatch(Path(directory),object(),descriptor,'inert'))
    def test_actual_read_remote_parses_exact_mutation_and_invalid_parse_prevents_reservation(self):
        """Exercise the emitted Python/QGA parser path, not a mocked _leaf_parse.

        Windows AST semantics remain native acceptance. Here fake QGA supplies
        AST rejection and the actual admission state machine must retain no
        local mutation intent and issue no guest mutation command.
        """
        binding,proof=self._binding_proof()
        descriptor=('windows-cp117','/qga',1,2,binding['generation']['expectedSid'])
        parsed_sources=[];executed_sources=[];qga_calls=[];execution_phases=[]
        def remote(_config, program, arguments, _data, _timeout):
            self.assertEqual(close._LEAF_READ_REMOTE,program)
            body='import base64,json,sys,time'+program.split('import time',1)[1]
            response={}
            def call(_socket,command,args):
                qga_calls.append(command)
                if command=='guest-exec':
                    wrapper=base64.b64decode(args['arg'][-1]).decode('utf-16le')
                    packed=re.search(r"FromBase64String\('([^']+)'\)",wrapper).group(1)
                    actual=gzip.decompress(base64.b64decode(packed)).decode()
                    executed_sources.append(actual)
                    if 'Language.Parser]::ParseInput' in actual:
                        # The executed payload only decompresses and parses the
                        # prospective action. Its bytes are never invoked.
                        self.assertNotIn('[scriptblock]::Create',actual)
                        self.assertNotIn('Invoke-Expression',actual)
                        packed_action=re.search(r"FromBase64String\('([^']+)'\)",actual).group(1)
                        action=gzip.decompress(base64.b64decode(packed_action)).decode()
                        parsed_sources.append(action)
                        execution_phases.append('parse-start' if '[IO.Directory]::Move($leaf,$archiveLeaf)' in action else 'parse-preflight')
                        response['payload']={'valid':'[IO.Directory]::Move($leaf,$archiveLeaf)' not in action}
                    else:
                        self.assertEqual(close._leaf_script(binding,'preflight'),actual)
                        execution_phases.append('read-preflight')
                        response['payload']=proof
                    return {'pid':10}
                self.assertEqual('guest-exec-status',command)
                return {'exited':True,'exitcode':0,'out-truncated':False,'err-truncated':False,
                        'out-data':base64.b64encode(json.dumps(response['payload']).encode()).decode()}
            output=io.StringIO()
            with patch.object(sys,'argv',['remote',*arguments]),contextlib.redirect_stdout(output):
                exec(body,{'call':call,'live':lambda *_:True,'decode':lambda raw:raw.decode()})
            return output.getvalue().encode()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for parent in (root/close.base._LOCAL,root/close.lease._DIR):
                parent.mkdir(parents=True);parent.chmod(0o700)
                (parent/'.environment.lock').write_bytes(b'');(parent/'.environment.lock').chmod(0o600)
            with patch.object(close.base,'_descriptor',return_value=(object(),object(),descriptor)), \
                    patch.object(close,'_leaf_retire_binding',return_value=binding), \
                    patch.object(close,'_local_absent',return_value=True), \
                    patch.object(close,'_remote_absent',return_value=True), \
                    patch.object(close,'_leaf_guest_census',return_value=True), \
                    patch.object(close,'_ready',return_value={'activeCount':0}), \
                    patch.object(close.base,'_remote',side_effect=remote), \
                    patch.object(close,'_leaf_retire_dispatch') as dispatch:
                result=close.leaf_retire_start(root,{})
            self.assertEqual({'state':'blocked','phase':'parser',**close._UNKNOWN},result)
            self.assertFalse(close._leaf_retire_intent(root).exists());dispatch.assert_not_called()
        self.assertEqual([close._leaf_script(binding,'preflight'),close._leaf_script(binding,'start',proof)],parsed_sources)
        self.assertEqual(['parse-preflight','read-preflight','read-preflight','parse-start'],execution_phases)
        self.assertEqual(['guest-exec','guest-exec-status']*4,qga_calls)
        self.assertFalse(any('[IO.Directory]::Move($leaf,$archiveLeaf)' in source for source in executed_sources))

    def test_terminal_transport_failure_retains_finite_exit_reason(self):
        # The old status transport collapsed this causal native exit failure to
        # None, leaving an indistinguishable terminal phase.
        descriptor=('windows-cp117','/qga',1,2,'S-1-5-21-1')
        def remote(_config,program,args,_data,_timeout):
            body='import base64,json,sys,time'+program.split('import time',1)[1]
            def call(_sock,command,_args):
                if command=='guest-exec':return {'pid':5}
                return {'exited':True,'exitcode':5,'out-truncated':False,'err-truncated':False,
                        'out-data':base64.b64encode(b'private error').decode()}
            output=io.StringIO()
            with patch.object(sys,'argv',['remote',*args]),contextlib.redirect_stdout(output):
                exec(body,{'call':call,'live':lambda *_:True,'decode':lambda raw:raw.decode()})
            return output.getvalue().encode()
        with patch.object(close.base,'_remote',side_effect=remote):
            run=getattr(close,'_leaf_diag_run',close._leaf_run)
            observed=run(object(),descriptor,'inert read-only diagnostic')
        self.assertEqual({'state':'unknown','phase':'guest-exit','exitCode':5},observed)
    def test_terminal_diagnostic_accepts_only_finite_redacted_protocol(self):
        descriptor=('windows-cp117','/qga',1,2,'S-1-5-21-1')
        values=[({'state':'observed','inventory':{'state':'unknown','phase':'archive-match','guardCode':'ARCHIVE_CHANGED'}},
                 {'state':'unknown','phase':'archive-match','guardCode':'ARCHIVE_CHANGED'}),
                ({'state':'observed','inventory':{'state':'checked','phase':'verified','guardCode':'none'}},
                 {'state':'checked','phase':'verified','guardCode':'none'}),
                ({'state':'observed','inventory':{'state':'unknown','phase':'private path','guardCode':'private error'}},
                 {'state':'unknown','phase':'transport'}),
                ({'state':'unknown','phase':'guest-exit','exitCode':True},{'state':'unknown','phase':'transport'}),
                ({'state':'unknown','phase':'guest-exit','exitCode':5,'stderr':'private'}, {'state':'unknown','phase':'transport'})]
        for wire,expected in values:
            with patch.object(close.base,'_remote',return_value=json.dumps(wire).encode()):
                self.assertEqual(expected,close._leaf_diag_run(object(),descriptor,'inert'))

    def test_diagnostic_preserves_intent_and_distinguishes_terminal_from_failed_followup_census(self):
        binding,proof=self._binding_proof();descriptor=('windows-cp117','/qga',1,2,binding['generation']['expectedSid'])
        intent={'version':1,'binding':binding,'proof':proof,'bindingSha256':close._leaf_sha(binding),
                'proofSha256':close._leaf_sha(proof),'mutationSha256':hashlib.sha256(close._leaf_script(binding,'start',proof).encode()).hexdigest()}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(close,'_leaf_retire_record',return_value=intent), \
                patch.object(close.base,'_descriptor',return_value=(object(),object(),descriptor)), \
                patch.object(close,'_leaf_retire_binding',return_value=binding), \
                patch.object(close,'_local_absent',return_value=True), \
                patch.object(close,'_remote_absent',return_value=True), \
                patch.object(close,'_leaf_parse',return_value=True), \
                patch.object(close,'_ready',return_value={'activeCount':0}), \
                patch.object(close,'_leaf_guest_census',return_value=False), \
                patch.object(close,'_leaf_retire_dispatch') as dispatch, \
                patch.object(close.guards,'secure_write_create') as write:
            with patch.object(close,'_leaf_diag_run',return_value={'state':'checked','phase':'verified','guardCode':'none'}):
                self.assertEqual('guest-census',close.leaf_retire_diagnose(directory,{})['phase'])
            failure={'state':'unknown','phase':'journal-binding','guardCode':'JOURNAL'}
            with patch.object(close,'_leaf_diag_run',return_value=failure):
                result=close.leaf_retire_diagnose(directory,{})
                self.assertEqual(failure,result['terminalDiagnostic']);self.assertEqual('unknown',result['state'])
            dispatch.assert_not_called();write.assert_not_called()

    def test_diagnostic_source_and_transport_cannot_replace_original_action_or_dispatch(self):
        binding,proof=self._binding_proof()
        original=close._leaf_script(binding,'start',proof)
        diagnostic=close._leaf_diagnostic_script(binding,proof)
        self.assertNotIn('[IO.Directory]::Move',diagnostic)
        self.assertNotIn('Write-SecureJsonCreate \'',diagnostic)
        self.assertNotIn('Remove-Item',diagnostic)
        self.assertEqual(original,close._leaf_script(binding,'start',proof))
        self.assertLess(len(base64.b64encode(close._leaf_wrapper(diagnostic).encode('utf-16le'))),30000)
        with self.assertRaises(ValueError):close.leaf_retire_diagnose('.',{'correlationId':close._CORRELATION})

if __name__ == "__main__":
    unittest.main()
