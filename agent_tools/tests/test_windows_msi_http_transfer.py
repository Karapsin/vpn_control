"""Causal transfer-stage and cleanup checks; no Arch or CP117 connection."""

import hashlib
import base64
import gzip
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from urllib.request import urlopen
from types import SimpleNamespace

from agent_tools import windows_msi_http_transfer as transfer


CORRELATION = "2ace6a48-ba60-4705-9200-4ff857f2aba6"
SOURCE = "b" * 40
SID = "S-1-5-21-1-2-3-1002"
TERMINAL = "c" * 64


class TransferTests(unittest.TestCase):
    def request(self, payload: bytes):
        return {"correlationId": CORRELATION, "sourceSha": SOURCE,
                "baseMsiArtifactId": "sha256-" + hashlib.sha256(payload).hexdigest(),
                "environment": "windows-cp117", "socketPath": "/private/cp117/qga.sock",
                "qemuPid": 1234, "startTicks": 5678, "expectedSid": SID}

    def args(self, root: Path, payload: bytes):
        request = self.request(payload)
        return (str(root), request["environment"], CORRELATION, SOURCE,
                request["baseMsiArtifactId"], request["socketPath"],
                str(request["qemuPid"]), str(request["startTicks"]), SID,
                hashlib.sha256(payload).hexdigest(), str(len(payload)))

    def run_remote(self, program: str, args, payload=b""):
        done = subprocess.run([sys.executable, "-c", program, *args], input=payload,
                              capture_output=True, timeout=10, check=False)
        self.assertEqual(done.returncode, 0, done.stderr.decode(errors="replace"))
        return json.loads(done.stdout)

    def test_intent_binds_exact_bytes_and_status_never_creates_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(transfer.status(root, CORRELATION)["state"], "unknown")
            self.assertFalse((root / transfer._DIR).exists())
            payload = b"msi-payload"
            artifact = root / "base.msi"
            artifact.write_bytes(payload)
            first = transfer.prepare(root, self.request(payload), artifact)
            self.assertEqual(first["state"], "prepared")
            shared = transfer.large_transfer.read(root, CORRELATION)
            self.assertEqual("msi", shared["binding"]["kind"])
            self.assertEqual(hashlib.sha256(payload).hexdigest(), shared["sha256"])
            self.assertEqual(transfer.prepare(root, self.request(payload), artifact)["state"], "unknown")
            self.assertFalse(first["replayAllowed"])

    def test_rejects_digest_drift_and_symlink_before_intent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "base.msi"
            artifact.write_bytes(b"wrong")
            with self.assertRaises(transfer.WindowsMsiHttpTransferError):
                transfer.prepare(root, self.request(b"right"), artifact)
            linked = root / "linked.msi"
            linked.symlink_to(artifact)
            with self.assertRaises(transfer.WindowsMsiHttpTransferError):
                transfer.prepare(root, self.request(b"wrong"), linked)

    def test_partial_and_hash_mismatch_are_observed_then_exactly_cleaned(self):
        payload = b"actual-msi-bytes"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.args(root, payload)
            self.assertEqual(self.run_remote(transfer._REMOTE_STAGE, args, payload[:5])["state"], "unknown")
            self.assertEqual(self.run_remote(transfer._REMOTE_STATUS, args)["state"], "partial")
            self.assertEqual(self.run_remote(transfer._REMOTE_CLEANUP, args)["state"], "cleaned")
            self.assertEqual(self.run_remote(transfer._REMOTE_STATUS, args)["state"], "absent")
        with tempfile.TemporaryDirectory() as directory:
            args = self.args(Path(directory), payload)
            self.assertEqual(self.run_remote(transfer._REMOTE_STAGE, args, b"x" * len(payload))["state"], "unknown")
            self.assertEqual(self.run_remote(transfer._REMOTE_STATUS, args)["state"], "hash-mismatch")
            self.assertEqual(self.run_remote(transfer._REMOTE_CLEANUP, args)["state"], "cleaned")

    def test_symlinked_parent_and_foreign_leaf_fail_closed(self):
        payload = b"bounded-msi"
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            (root / "windows-cp117").symlink_to(outside, target_is_directory=True)
            self.assertEqual(self.run_remote(transfer._REMOTE_STAGE, self.args(root, payload), payload)["state"], "unknown")
            self.assertEqual(list(Path(outside).iterdir()), [])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.args(root, payload)
            self.assertEqual(self.run_remote(transfer._REMOTE_STAGE, args, payload)["state"], "staged")
            stage = root / "windows-cp117" / "windows-msi-http-transfer" / CORRELATION
            (stage / "foreign.txt").write_text("retain")
            self.assertEqual(self.run_remote(transfer._REMOTE_CLEANUP, args)["state"], "unknown")
            self.assertTrue((stage / "foreign.txt").exists())

    def test_repeat_does_not_overwrite_first_stage_or_reuse_cleanup(self):
        payload = b"one-use-msi"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.args(root, payload)
            self.assertEqual(self.run_remote(transfer._REMOTE_STAGE, args, payload)["state"], "staged")
            self.assertEqual(self.run_remote(transfer._REMOTE_STAGE, args, payload)["state"], "unknown")
            self.assertEqual(self.run_remote(transfer._REMOTE_STATUS, args)["state"], "staged")
            self.assertEqual(self.run_remote(transfer._REMOTE_CLEANUP, args)["state"], "cleaned")
            self.assertEqual(self.run_remote(transfer._REMOTE_CLEANUP, args)["state"], "unknown")
            self.assertEqual(self.run_remote(transfer._REMOTE_STAGE, args, payload)["state"], "unknown")

    def test_download_phase_marker_blocks_cleanup_and_preserves_bytes(self):
        payload = b"download-phase-msi"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.args(root, payload)
            self.assertEqual(self.run_remote(transfer._REMOTE_STAGE, args, payload)["state"], "staged")
            stage = root / "windows-cp117" / "windows-msi-http-transfer" / CORRELATION
            (stage / "download-intent.json").write_text("{}")
            self.assertEqual(self.run_remote(transfer._REMOTE_CLEANUP, args)["state"], "unknown")
            self.assertEqual((stage / "base.msi").read_bytes(), payload)

    def test_remote_response_schema_and_current_admission_fail_closed(self):
        record = {"sha256": "a" * 64, "length": 4}
        with mock.patch.object(transfer.base, "_remote", return_value=b'{"state":"staged","sha256":"' + b"a" * 64 + b'","length":4,"extra":1}'):
            self.assertEqual(transfer._remote_result(None, "", (), None, {"staged"}, record)["state"], "unknown")
        with mock.patch.object(transfer.base, "_remote", return_value=b'{"state":"staged","sha256":"' + b"a" * 64 + b'","length":4}'):
            self.assertEqual(transfer._remote_result(None, "", (), None, {"staged"}, record)["state"], "staged")
        self.assertEqual(transfer._phase_result(b'{"state":"listening","port":42,"path":"/wrong"}',
                                                 {"listening"}, "/expected")["state"], "unknown")
        self.assertEqual(transfer._guest_result(b'{"state":"downloaded","sha256":"' + b"a" * 64 + b'","length":5}',
                                                {"downloaded"}, record)["state"], "unknown")

    def test_embedded_scripts_compile(self):
        for name in ("_REMOTE_STAGE", "_REMOTE_STATUS", "_REMOTE_CLEANUP", "_REMOTE_LISTEN_START",
                     "_REMOTE_LISTEN_STATUS", "_REMOTE_LISTEN_DIAGNOSTIC", "_REMOTE_LISTEN_STOP",
                     "_REMOTE_GUEST_DOWNLOAD",
                     "_REMOTE_GUEST_STATUS", "_REMOTE_GUEST_DIAGNOSTIC", "_REMOTE_OWNER_CENSUS",
                     "_REMOTE_GUEST_TASK_CLEANUP", "_REMOTE_GUEST_FILE_CLEANUP",
                     "_REMOTE_GUEST_ABORT",
                     "_REMOTE_TERMINAL_CLEANUP", "_REMOTE_TERMINAL_MARK", "_REMOTE_TERMINAL_STATUS",
                     "_REMOTE_ABORT_CLEANUP", "_REMOTE_ABORT_STATUS",
                     "_REMOTE_PRE_BASE_STATUS",
                     "_HTTP_WORKER"):
            compile(getattr(transfer, name), name, "exec")

    def test_fake_qga_task_dispatch_and_abort_programs(self):
        payload = b"fake-qga-msi"
        arguments = ("/private/cp117/qga.sock", "1234", "5678", SID, CORRELATION,
                     "12345", "/" + "x" * 40, hashlib.sha256(payload).hexdigest(), str(len(payload)))
        stub = '''import base64,hashlib,json,re,sys,time
def live(*args):return True
def user_network(pid):return None
def decode(raw):return raw.decode()
def call(sock,command,args):
 if command=='guest-exec':
  script=base64.b64decode(args['arg'][-1]).decode('utf-16le')
  if 'S-1-5-21-1-2-3-1002' not in script:raise ValueError('SID binding missing')
  if 'EXPECTED_ACTION' not in script:raise ValueError('action missing')
  return {'pid':100}
 if command=='guest-exec-status':
  return {'exited':True,'exitcode':0,'out-data':base64.b64encode(b'EXPECTED_OUTPUT').decode()}
 raise ValueError('unexpected QGA command')
'''
        programs = ((transfer._REMOTE_GUEST_DOWNLOAD,
                     transfer.base._QGA + transfer.base._TRANSFER_NETWORK_QEMU_TOPOLOGY,
                     arguments, "Register-ScheduledTask", '{"state":"submitted"}'),
                    (transfer._REMOTE_GUEST_ABORT, transfer.base._QGA,
                     arguments + ("d" * 64,), "Unregister-ScheduledTask", '{"state":"aborted"}'),
                    (transfer._REMOTE_GUEST_TASK_CLEANUP, transfer.base._QGA,
                     arguments + ("d" * 64,), "Unregister-ScheduledTask", '{"state":"task-cleaned"}'),
                    (transfer._REMOTE_GUEST_STATUS, transfer.base._QGA,
                     arguments + ("d" * 64, "after"), "Get-ScheduledTask",
                     '{"state":"ready-for-base","sha256":"' + hashlib.sha256(payload).hexdigest() + '","length":' + str(len(payload)) + '}'),
                    (transfer._REMOTE_GUEST_DIAGNOSTIC, transfer.base._QGA,
                     arguments + ("d" * 64,), "Get-ScheduledTaskInfo",
                     '{"state":"diagnosed","task":"terminal","principal":"exact","action":"exact",'
                     '"sid":"exact","leaf":"absent","reason":"task-terminal-failed",'
                     '"principalUser":"exact-string","principalLogon":"exact","principalRunLevel":"exact",'
                     '"leafAt":"unknown","leafFault":"unknown","leafOwner":"none"}'),
                    (transfer._REMOTE_OWNER_CENSUS, transfer.base._QGA,
                     arguments + ("d" * 64,), "Get-Acl",
                     '{"state":"census","paths":{' + ','.join('"' + name + '":{"kind":"absent","reparse":"unknown","owner":"none"}'
                                                                   for name in ("profile", "appdata", "local", "app-root", "stage", "final", "partial")) + '}}'),
                    (transfer._REMOTE_GUEST_FILE_CLEANUP, transfer.base._QGA,
                     arguments[:5] + arguments[-2:] + (TERMINAL,), "[IO.File]::Delete",
                     '{"state":"file-cleaned"}'))
        for program, prefix, call_args, action, output in programs:
            self.assertTrue(program.startswith(prefix))
            fake = stub.replace("EXPECTED_ACTION", action).replace("EXPECTED_OUTPUT", output) + program[len(prefix):]
            done = subprocess.run([sys.executable, "-c", fake, *call_args],
                                  capture_output=True, timeout=10, check=False)
            self.assertEqual(done.returncode, 0, done.stderr.decode(errors="replace"))
            self.assertEqual(json.loads(done.stdout)["state"], json.loads(output)["state"])

    def test_guest_abort_is_one_use_and_blocks_unknown_or_running(self):
        record = {"correlationId": CORRELATION, "sha256": "a" * 64, "length": 4,
                  "socketPath": "/private/cp117/qga.sock", "qemuPid": 12,
                  "startTicks": 34, "expectedSid": SID}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = root / ".rag_index" / "windows-msi-http-transfer"
            journal.mkdir(parents=True, mode=0o700)
            marker = {"port": 12345, "pathSha256": hashlib.sha256(("/" + "x" * 40).encode()).hexdigest(),
                      "actionArgsSha256": "d" * 64}
            with (mock.patch.object(transfer, "_listener_join", return_value=(object(), record, "/" + "x" * 40)),
                  mock.patch.object(transfer, "_guest_dispatch_marker", return_value=marker),
                  mock.patch.object(transfer, "guest_download_status", return_value={"state": "running"}) as guest,
                  mock.patch.object(transfer, "listener_status", return_value={"state": "stopped"}),
                  mock.patch.object(transfer.base, "_remote", return_value=b'{"state":"aborted"}') as remote):
                self.assertEqual(transfer.guest_abort(root, None, Path("/remote"), CORRELATION)["state"], "unknown")
                guest.return_value = {"state": "unknown"}
                self.assertEqual(transfer.guest_abort(root, None, Path("/remote"), CORRELATION)["state"], "unknown")
                remote.assert_not_called()
                guest.return_value = {"state": "partial"}
                self.assertEqual(transfer.guest_abort(root, None, Path("/remote"), CORRELATION)["state"], "aborted")
                self.assertEqual(transfer.guest_abort(root, None, Path("/remote"), CORRELATION)["state"], "unknown")
                self.assertEqual(remote.call_count, 1)
                self.assertEqual(remote.call_args.args[2][-1], "d" * 64)

    def test_timed_out_listener_requires_explicit_stop_before_guest_abort(self):
        record = {"correlationId": CORRELATION, "sha256": "a" * 64, "length": 4,
                  "socketPath": "/private/cp117/qga.sock", "qemuPid": 12,
                  "startTicks": 34, "expectedSid": SID}
        marker = {"port": 12345, "pathSha256": hashlib.sha256(("/" + "x" * 40).encode()).hexdigest(),
                  "actionArgsSha256": "d" * 64}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = transfer._private_dir(root, True)
            abort_marker = private / (CORRELATION + ".abort.dispatch.json")
            timed_out = {"state": "stopped", "port": 12345, "pathSha256": marker["pathSha256"]}
            with (mock.patch.object(transfer, "_listener_join", return_value=(object(), record, "/" + "x" * 40)),
                  mock.patch.object(transfer, "_guest_dispatch_marker", return_value=marker),
                  mock.patch.object(transfer, "guest_download_status", return_value={"state": "absent"}),
                  mock.patch.object(transfer, "listener_status", return_value=timed_out) as listener,
                  mock.patch.object(transfer.base, "_remote", return_value=b'{"state":"aborted"}') as remote):
                self.assertEqual(transfer.guest_abort(root, None, Path("/remote"), CORRELATION),
                                 transfer._UNKNOWN)
                self.assertFalse(abort_marker.exists())
                remote.assert_not_called()
                listener.return_value = {"state": "stopped"}
                self.assertEqual(transfer.guest_abort(root, None, Path("/remote"), CORRELATION)["state"],
                                 "aborted")
                self.assertTrue(abort_marker.exists())
                self.assertEqual(remote.call_count, 1)

    def test_listener_diagnostic_projects_unknown_without_raw_endpoint(self):
        bounded = {"state": "diagnosed", "binding": "exact", "stageFiles": "allowed",
                   "intent": "exact", "worker": "exited", "ready": "exact",
                   "done": "served", "stopped": "absent", "port": "free",
                   "reason": "served-awaiting-stop"}
        self.assertEqual(transfer._project_listener_diagnostic(json.dumps(bounded).encode())["reason"],
                         "served-awaiting-stop")
        poisoned = dict(bounded, rawPid=1234)
        self.assertEqual(transfer._project_listener_diagnostic(json.dumps(poisoned).encode()),
                         transfer._UNKNOWN)
        poisoned = dict(bounded, port=12345)
        self.assertEqual(transfer._project_listener_diagnostic(json.dumps(poisoned).encode()),
                         transfer._UNKNOWN)

    def test_listener_diagnostic_facade_exposes_only_bounded_fields(self):
        record = {"correlationId": CORRELATION, "artifactPath": "/verified/base.msi"}
        target = SimpleNamespace(fixture_transfer_root="/remote/cp117")
        descriptor = ("windows-cp117", "/private/cp117/qga.sock", 1234, 5678, SID)
        bounded = {"state": "diagnosed", "binding": "exact", "stageFiles": "allowed",
                   "intent": "exact", "worker": "exited", "ready": "exact",
                   "done": "served", "stopped": "absent", "port": "free",
                   "reason": "served-awaiting-stop", "rawPort": 12345, "rawPath": "/secret"}
        with (mock.patch.object(transfer, "_intent", return_value=record),
              mock.patch.object(transfer.base, "_descriptor", return_value=(object(), target, descriptor)),
              mock.patch.object(transfer, "_admit_current"),
              mock.patch.dict(transfer._PHASES, {"listener-diagnostic": mock.Mock(return_value=bounded)})):
            result = transfer.workflow(Path.cwd(), "listener-diagnostic", {"correlationId": CORRELATION})
        self.assertEqual(result["reason"], "served-awaiting-stop")
        self.assertNotIn("rawPort", result)
        self.assertNotIn("rawPath", result)
        self.assertFalse(result["replayAllowed"])

    def test_malformed_ready_makes_status_unknown_but_diagnostic_names_gate(self):
        payload = b"listener-fixture"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.args(root, payload)
            self.assertEqual(self.run_remote(transfer._REMOTE_STAGE, args, payload)["state"], "staged")
            stage = root / "windows-cp117" / "windows-msi-http-transfer" / CORRELATION
            path_sha = "d" * 64
            fixtures = {"download-intent.json": {"pathSha256": path_sha},
                        "worker.json": {"pid": 99999999, "startTicks": "1", "pathSha256": path_sha},
                        "listener-ready.json": {"pid": 99999999, "startTicks": "1", "port": 12345,
                                                "pathSha256": "e" * 64}}
            for name, value in fixtures.items():
                p = stage / name
                p.write_text(json.dumps(value))
                p.chmod(0o600)
            self.assertEqual(self.run_remote(transfer._REMOTE_LISTEN_STATUS, args)["state"], "unknown")
            diagnostic = self.run_remote(transfer._REMOTE_LISTEN_DIAGNOSTIC, args)
            self.assertEqual(diagnostic["worker"], "exited")
            self.assertEqual(diagnostic["ready"], "mismatch")
            self.assertEqual(diagnostic["reason"], "ready-mismatch")
            self.assertNotIn("pid", diagnostic)
            self.assertNotIn("rawPort", diagnostic)

    def test_workflow_rejects_unbounded_phase_fields_before_dispatch(self):
        root = Path("/unused")
        with mock.patch.object(transfer, "_intent") as intent, mock.patch.object(transfer, "ps5_preflight") as ps5:
            for action, value in (("stage-start", {"correlationId": CORRELATION, "path": "/tmp/x"}),
                                  ("stage-start", {"correlationId": "not-uuid"}),
                                  ("guest-diagnostic-detail", {"correlationId": CORRELATION,
                                                               "path": "C:\\Users\\vpncp117"}),
                                  ("other", {"correlationId": CORRELATION}),
                                  ("ps5-preflight", {"host": "other"}),
                                  ("ps5-preflight", {"host": "archlinux", "script": "write"})):
                with self.assertRaises(transfer.WindowsMsiHttpTransferError):
                    transfer.workflow(root, action, value)
            intent.assert_not_called(); ps5.assert_not_called()

    def test_workflow_derives_prepare_and_later_phase_inputs(self):
        request = dict(transfer.base._UNKNOWN_CLOSURE_REQUEST)
        descriptor = ("windows-cp117", "/private/cp117/qga.sock", 1234, 5678, SID)
        target = SimpleNamespace(fixture_transfer_root="/remote/cp117")
        ready = {"state": "ready", "ready": True, "installedVersion": "2.1.17",
                 "productCount": 1, "activeCount": 0, "activeProcesses": []}
        artifact = Path("/verified/base.msi")
        with (mock.patch.object(transfer.base, "_descriptor", return_value=(object(), target, descriptor)),
              mock.patch.object(transfer.base, "_require_reconciled_legacy") as legacy,
              mock.patch.object(transfer.base, "_require_base_route_free") as route_free,
              mock.patch.object(transfer.base, "readiness", return_value=ready),
              mock.patch.object(transfer.base, "_admit", return_value=({}, artifact, 4)),
              mock.patch.object(transfer, "_admit_current"),
              mock.patch.object(transfer, "prepare", return_value={"state": "prepared"}) as prepared):
            self.assertEqual(transfer.workflow(Path.cwd(), "prepare", request)["state"], "prepared")
            binding = prepared.call_args.args[1]
            self.assertEqual(binding["expectedSid"], SID)
            self.assertEqual(prepared.call_args.args[2], artifact)
            legacy.assert_called_once(); route_free.assert_called_once()
        record = {"correlationId": CORRELATION, "artifactPath": str(artifact)}
        with (mock.patch.object(transfer, "_intent", return_value=record),
              mock.patch.object(transfer.base, "_descriptor", return_value=(object(), target, descriptor)),
              mock.patch.object(transfer, "_admit_current"),
              mock.patch.object(transfer, "remote_stage", return_value={"state": "staged"}) as staged):
            self.assertEqual(transfer.workflow(Path.cwd(), "stage-start", {"correlationId": CORRELATION})["state"], "staged")
            self.assertEqual(staged.call_args.args[-1], artifact)

    def test_workflow_redacts_listener_endpoint_and_poisoned_unknown(self):
        record = {"correlationId": CORRELATION, "artifactPath": "/verified/base.msi"}
        target = SimpleNamespace(fixture_transfer_root="/remote/cp117")
        descriptor = ("windows-cp117", "/private/cp117/qga.sock", 1234, 5678, SID)
        start = mock.Mock(return_value={"state": "listening", "port": 23456,
                                        "path": "/one-use-secret", "token": "secret",
                                        "pathSha256": "f" * 64, "sha256": "f" * 64,
                                        "length": 12345})
        status = mock.Mock(return_value={"state": "listening", "port": 23456,
                                         "pathSha256": "f" * 64,
                                         "socketPath": "/private/cp117/qga.sock"})
        with (mock.patch.object(transfer, "_intent", return_value=record),
              mock.patch.object(transfer.base, "_descriptor", return_value=(object(), target, descriptor)),
              mock.patch.object(transfer, "_admit_current"),
              mock.patch.dict(transfer._PHASES, {"listener-start": start, "listener-status": status})):
            for phase in ("listener-start", "listener-status"):
                result = transfer.workflow(Path.cwd(), phase, {"correlationId": CORRELATION})
                self.assertEqual(result, {"state": "listening", "correlationId": CORRELATION,
                                          "replayAllowed": False, "nativeActionAllowed": False,
                                          "productAction": False})
            start.return_value = {"state": "unknown", "path": "/leak", "token": "leak",
                                  "port": 23456, "pathSha256": "f" * 64, "unexpected": "leak"}
            self.assertEqual(transfer.workflow(Path.cwd(), "listener-start",
                                               {"correlationId": CORRELATION}), transfer._UNKNOWN)
            status.return_value = {"state": "listening", "correlationId": "00000000-0000-4000-8000-000000000000",
                                   "port": 23456}
            self.assertEqual(transfer.workflow(Path.cwd(), "listener-status",
                                               {"correlationId": CORRELATION}), transfer._UNKNOWN)

    def test_guest_diagnostic_projects_unknown_without_leaking_raw_output(self):
        raw = {"state": "diagnosed", "task": "terminal", "principal": "exact",
               "action": "exact", "sid": "exact", "leaf": "absent",
               "reason": "task-terminal-failed", "principalUser": "exact-string",
               "principalLogon": "exact", "principalRunLevel": "exact",
               "leafAt": "unknown", "leafFault": "unknown", "leafOwner": "none",
               "rawOutput": "secret"}
        self.assertEqual(transfer._project_guest_diagnostic(json.dumps(raw).encode()), transfer._UNKNOWN)
        raw.pop("rawOutput")
        self.assertEqual(transfer._project_guest_diagnostic(json.dumps(raw).encode())["reason"],
                         "task-terminal-failed")
        raw["reason"] = ["task-terminal-failed"]
        self.assertEqual(transfer._project_guest_diagnostic(json.dumps(raw).encode()), transfer._UNKNOWN)

    def test_guest_diagnostic_reconciles_status_unknown_without_replay(self):
        record = {"correlationId": CORRELATION, "sha256": "a" * 64, "length": 4,
                  "socketPath": "/private/cp117/qga.sock", "qemuPid": 12,
                  "startTicks": 34, "expectedSid": SID}
        marker = {"port": 12345, "pathSha256": hashlib.sha256(("/" + "x" * 40).encode()).hexdigest(),
                  "actionArgsSha256": "d" * 64}
        diagnostic = {"state": "diagnosed", "task": "terminal", "principal": "exact",
                      "action": "exact", "sid": "exact", "leaf": "absent",
                      "reason": "task-terminal-failed", "principalUser": "exact-string",
                      "principalLogon": "exact", "principalRunLevel": "exact",
                      "leafAt": "unknown", "leafFault": "unknown", "leafOwner": "none"}
        with (mock.patch.object(transfer, "_listener_join", return_value=(object(), record, "/" + "x" * 40)),
              mock.patch.object(transfer, "_guest_dispatch_marker", return_value=marker),
              mock.patch.object(transfer.base, "_remote", return_value=json.dumps(diagnostic).encode()) as remote):
            result = transfer.guest_diagnostic(Path.cwd(), None, Path("/remote"), CORRELATION)
        self.assertEqual(result["reason"], "task-terminal-failed")
        self.assertFalse(result["replayAllowed"])
        self.assertEqual(remote.call_count, 1)
        self.assertEqual(remote.call_args.args[1], transfer._REMOTE_GUEST_DIAGNOSTIC)

    def test_guest_status_uses_persisted_action_hash_after_source_edit(self):
        record = {"correlationId": CORRELATION, "sha256": "a" * 64, "length": 4,
                  "socketPath": "/private/cp117/qga.sock", "qemuPid": 12,
                  "startTicks": 34, "expectedSid": SID}
        marker = {"port": 12345, "pathSha256": hashlib.sha256(("/" + "x" * 40).encode()).hexdigest(),
                  "actionArgsSha256": "d" * 64}
        with (mock.patch.object(transfer, "_listener_join", return_value=(object(), record, "/" + "x" * 40)),
              mock.patch.object(transfer, "_guest_dispatch_marker", return_value=marker),
              mock.patch.object(transfer.base, "_remote", return_value=b'{"state":"absent"}') as remote,
              mock.patch.object(transfer, "_GUEST_DOWNLOAD_PS", "edited after dispatch")):
            result = transfer.guest_download_status(Path.cwd(), None, Path("/remote"), CORRELATION)
        self.assertEqual(result["state"], "absent")
        self.assertEqual(remote.call_args.args[2][-2], "d" * 64)

    def test_guest_dispatch_seals_action_hash_before_uncertain_remote_effect(self):
        record = {"correlationId": CORRELATION, "sha256": "a" * 64, "length": 4,
                  "socketPath": "/private/cp117/qga.sock", "qemuPid": 12,
                  "startTicks": 34, "expectedSid": SID, "sourceSha": SOURCE,
                  "baseMsiArtifactId": "sha256-" + "a" * 64}
        path = "/" + "x" * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertIsNotNone(transfer._private_dir(root, True))
            with (mock.patch.object(transfer, "_listener_join", return_value=(object(), record, path)),
                  mock.patch.object(transfer, "listener_status", return_value={"state": "listening", "port": 12345}),
                  mock.patch.object(transfer.base, "_remote", return_value=b'{"state":"unknown"}') as remote):
                self.assertEqual(transfer.guest_download(root, None, Path("/remote"), CORRELATION)["state"],
                                 "unknown")
            marker = transfer._guest_dispatch_marker(root, record, path)
            self.assertEqual(marker["actionArgsSha256"], transfer._action_args_sha(
                transfer._GUEST_DOWNLOAD_PS, SID, CORRELATION, "a" * 64, 4, 12345, path))
            self.assertEqual(marker["sourceSha"], SOURCE)
            self.assertEqual(marker["qemuPid"], 12)
            with mock.patch.object(transfer, "_GUEST_DOWNLOAD_PS", "edited after dispatch"):
                self.assertEqual(transfer._guest_dispatch_marker(root, record, path)["actionArgsSha256"],
                                 marker["actionArgsSha256"])
            remote.assert_called_once()

    def test_legacy_dispatch_recovery_is_pinned_to_one_correlation(self):
        old = transfer._historical_download_script()
        self.assertEqual(hashlib.sha256(old.encode()).hexdigest(), transfer._HISTORICAL_DOWNLOAD_SHA256)
        self.assertNotEqual(old, transfer._GUEST_DOWNLOAD_PS)
        self.assertIsNone(transfer._historical_action_hash("00000000-0000-4000-8000-000000000000",
                                                            SID, "a" * 64, 4, 12345, "/" + "x" * 40))
        record = {"correlationId": transfer._HISTORICAL_CORRELATION, "sha256": "a" * 64,
                  "length": 4, "expectedSid": SID}
        path = "/" + "x" * 40
        old_marker = {"correlationId": transfer._HISTORICAL_CORRELATION, "sha256": "a" * 64,
                      "length": 4, "port": 12345,
                      "pathSha256": hashlib.sha256(path.encode()).hexdigest()}
        with (mock.patch.object(transfer, "_private_dir", return_value=Path("/private")),
              mock.patch.object(transfer, "_read", return_value=old_marker)):
            recovered = transfer._guest_dispatch_marker(Path.cwd(), record, path)
        self.assertEqual(recovered["actionScriptSha256"], transfer._HISTORICAL_DOWNLOAD_SHA256)
        self.assertEqual(recovered["actionArgsSha256"], transfer._historical_action_hash(
            transfer._HISTORICAL_CORRELATION, SID, "a" * 64, 4, 12345, path))

    def test_diagnostic_facade_redacts_poisoned_fields(self):
        diagnosed = {"state": "diagnosed", "task": "terminal", "principal": "exact",
                     "action": "exact", "sid": "exact", "leaf": "absent",
                     "reason": "task-terminal-failed", "principalUser": "exact-string",
                     "principalLogon": "exact", "principalRunLevel": "exact",
                     "leafAt": "unknown", "leafFault": "unknown", "leafOwner": "none",
                     "path": "secret", "rawOutput": "secret"}
        result = transfer._public_result(diagnosed, CORRELATION, "guest-diagnostic")
        self.assertEqual(result["reason"], "task-terminal-failed")
        self.assertNotIn("path", result)
        self.assertNotIn("rawOutput", result)
        self.assertFalse(result["replayAllowed"])

    def test_native_mismatch_detail_projection_has_no_raw_principal_or_path(self):
        diagnosed = {"state": "diagnosed", "task": "terminal", "principal": "mismatch",
                     "action": "exact", "sid": "exact", "leaf": "unsafe",
                     "reason": "principal-mismatch", "principalUser": "same-sid",
                     "principalLogon": "exact", "principalRunLevel": "exact",
                     "leafAt": "app-root", "leafFault": "owner", "leafOwner": "system"}
        result = transfer._public_result(diagnosed, CORRELATION, "guest-diagnostic-detail")
        self.assertEqual(result["principalUser"], "same-sid")
        self.assertEqual(result["leafAt"], "app-root")
        self.assertEqual(result["leafOwner"], "system")
        self.assertFalse(result["replayAllowed"])
        self.assertNotIn("userId", result)
        self.assertNotIn("path", result)
        poisoned = dict(diagnosed, leafAt="C:\\Users\\vpncp117")
        self.assertEqual(transfer._public_result(poisoned, CORRELATION, "guest-diagnostic-detail"),
                         transfer._UNKNOWN)
        record = {"correlationId": CORRELATION, "artifactPath": "/verified/base.msi"}
        target = SimpleNamespace(fixture_transfer_root="/remote/cp117")
        descriptor = ("windows-cp117", "/private/cp117/qga.sock", 1234, 5678, SID)
        mocked = mock.Mock(return_value=dict(diagnosed, rawOutput="secret", path="secret"))
        with (mock.patch.object(transfer, "_intent", return_value=record),
              mock.patch.object(transfer.base, "_descriptor", return_value=(object(), target, descriptor)),
              mock.patch.object(transfer, "_admit_current"),
              mock.patch.dict(transfer._PHASES, {"guest-diagnostic-detail": mocked})):
            exposed = transfer.workflow(Path.cwd(), "guest-diagnostic-detail",
                                        {"correlationId": CORRELATION})
        self.assertEqual(exposed["leafAt"], "app-root")
        self.assertNotIn("rawOutput", exposed)
        self.assertNotIn("path", exposed)
        mocked.assert_called_once()

    def test_owner_census_accepts_only_fixed_categorical_paths(self):
        paths = {name: {"kind": "directory" if name not in {"final", "partial"} else "absent",
                        "reparse": "no" if name not in {"final", "partial"} else "unknown",
                        "owner": "system" if name == "profile" else
                                 ("none" if name in {"final", "partial"} else "expected")}
                 for name in ("profile", "appdata", "local", "app-root", "stage", "final", "partial")}
        accepted = {"state": "census", "paths": paths}
        self.assertEqual(transfer._project_owner_census(json.dumps(accepted).encode())["paths"]["profile"]["owner"],
                         "system")
        poisoned = json.loads(json.dumps(accepted))
        poisoned["paths"]["profile"]["rawPath"] = "C:\\Users\\vpncp117"
        self.assertEqual(transfer._project_owner_census(json.dumps(poisoned).encode()), transfer._UNKNOWN)
        poisoned = json.loads(json.dumps(accepted))
        poisoned["paths"]["app-root"]["owner"] = "S-1-5-18"
        self.assertEqual(transfer._project_owner_census(json.dumps(poisoned).encode()), transfer._UNKNOWN)

    def test_observed_sid_alias_and_system_profile_are_supported_narrowly(self):
        for script in (transfer._GUEST_STATUS_PS, transfer._GUEST_TASK_CLEANUP_PS,
                       transfer._GUEST_ABORT_PS):
            self.assertIn("PrincipalSid", script)
            self.assertNotIn("$task.Principal.UserId -cne", script)
        for script in (transfer._GUEST_DOWNLOAD_PS, transfer._GUEST_STATUS_PS,
                       transfer._GUEST_TASK_CLEANUP_PS, transfer._GUEST_ABORT_PS,
                       transfer._GUEST_FILE_CLEANUP_PS):
            self.assertIn("S-1-5-18", script)
            self.assertIn("$profile $true", script)
            self.assertIn("$local", script)
            self.assertNotIn("$local $true $true", script)
            self.assertNotIn("$appRoot $true $true", script)
            self.assertNotIn("$dir $true $true", script)

    def test_fixed_ps5_preflight_covers_transfer_scripts(self):
        script = transfer._ps5_preflight_script()
        diagnostic = transfer._ps5_preflight_script(diagnostic=True)
        cleanup = transfer._ps5_preflight_script(cleanup=True)
        census = transfer._ps5_preflight_script(census=True)
        self.assertIn("Parser]::ParseInput", script)
        self.assertNotIn("@PACKED@", script)
        self.assertLess(len(base64.b64encode(script.encode("utf-16le"))), 30000)
        self.assertLess(len(base64.b64encode(diagnostic.encode("utf-16le"))), 30000)
        self.assertLess(len(base64.b64encode(cleanup.encode("utf-16le"))), 30000)
        self.assertLess(len(base64.b64encode(census.encode("utf-16le"))), 30000)
        packed = diagnostic.split("foreach($item in @(", 1)[1].split("))", 1)[0]
        self.assertEqual(len(packed.split(",")), 1)
        parsed_body = gzip.decompress(base64.b64decode(packed.strip("'"))).decode("utf-16le")
        self.assertIn("Get-ScheduledTaskInfo", parsed_body)
        self.assertIn("Add-Type -AssemblyName System.Net.Http", transfer._GUEST_DOWNLOAD_PS)
        self.assertLess(transfer._GUEST_DOWNLOAD_PS.index("Add-Type -AssemblyName System.Net.Http"),
                        transfer._GUEST_DOWNLOAD_PS.index("[Net.Http.HttpClientHandler]"))

    def test_ps5_preflight_requires_both_fixed_parser_batches(self):
        descriptor = ("windows-cp117", "/private/qga.sock", 123, 456, SID)
        passed = b'{"state":"passed","checks":["ps5-parse","gzip","utf8-pipeline"]}'
        failed = b'{"state":"failed","checks":["ps5-parse","gzip","utf8-pipeline"]}'
        with (mock.patch.object(transfer.base, "_descriptor", return_value=(object(), object(), descriptor)),
              mock.patch.object(transfer.base, "_remote", side_effect=(passed, failed)) as remote):
            self.assertEqual(transfer.ps5_preflight(Path.cwd()), transfer._UNKNOWN)
            self.assertEqual(remote.call_count, 2)

    def test_terminal_stage_cleanup_requires_stopped_listener_and_guest_cleanup_proof(self):
        payload = b"terminal-stage-msi"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.args(root, payload)
            self.assertEqual(self.run_remote(transfer._REMOTE_STAGE, args, payload)["state"], "staged")
            stage = root / "windows-cp117" / "windows-msi-http-transfer" / CORRELATION
            phase = {"pid": 99999999, "startTicks": "1", "pathSha256": "d" * 64}
            def write(name, value):
                path = stage / name
                path.write_text(json.dumps(value))
                path.chmod(0o600)
            write("download-intent.json", {"pathSha256": phase["pathSha256"]})
            write("worker.json", phase)
            self.assertEqual(self.run_remote(transfer._REMOTE_TERMINAL_CLEANUP,
                                             args + (TERMINAL,))["state"], "unknown")
            write("listener-stopped.json", phase)
            self.assertEqual(self.run_remote(transfer._REMOTE_PRE_BASE_STATUS,
                                             args)["state"], "staged-for-base")
            write("task-cleaned.json", {"terminalReceiptSha256": "f" * 64,
                                        "guestTask": "absent", "guestMsi": "absent"})
            self.assertEqual(self.run_remote(transfer._REMOTE_TERMINAL_CLEANUP,
                                             args + (TERMINAL,))["state"], "unknown")
            write("task-cleaned.json", {"terminalReceiptSha256": TERMINAL,
                                        "guestTask": "absent", "guestMsi": "absent"})
            result = self.run_remote(transfer._REMOTE_TERMINAL_CLEANUP, args + (TERMINAL,))
            self.assertEqual(result, {"state": "cleaned", "terminalReceiptSha256": TERMINAL})
            self.assertEqual(self.run_remote(transfer._REMOTE_TERMINAL_STATUS,
                                             args + (TERMINAL,))["state"], "cleaned")
            self.assertEqual(self.run_remote(transfer._REMOTE_TERMINAL_CLEANUP,
                                             args + (TERMINAL,))["state"], "unknown")
            self.assertEqual(self.run_remote(transfer._REMOTE_STATUS, args)["state"], "absent")

    def test_failed_or_unknown_terminal_phase_does_not_delete_stage(self):
        payload = b"retain-on-unknown"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.args(root, payload)
            self.assertEqual(self.run_remote(transfer._REMOTE_STAGE, args, payload)["state"], "staged")
            stage = root / "windows-cp117" / "windows-msi-http-transfer" / CORRELATION
            (stage / "download-intent.json").write_text("{}")
            self.assertEqual(self.run_remote(transfer._REMOTE_TERMINAL_CLEANUP,
                                             args + (TERMINAL,))["state"], "unknown")
            self.assertEqual((stage / "base.msi").read_bytes(), payload)

    def test_aborted_stage_cleanup_requires_stopped_worker_and_is_one_use(self):
        payload = b"aborted-stage-msi"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.args(root, payload)
            self.assertEqual(self.run_remote(transfer._REMOTE_STAGE, args, payload)["state"], "staged")
            stage = root / "windows-cp117" / "windows-msi-http-transfer" / CORRELATION
            worker = {"pid": 99999999, "startTicks": "1", "pathSha256": "d" * 64}
            for name, value in (("download-intent.json", {"pathSha256": worker["pathSha256"]}),
                                ("worker.json", worker)):
                path = stage / name
                path.write_text(json.dumps(value)); path.chmod(0o600)
            self.assertEqual(self.run_remote(transfer._REMOTE_ABORT_CLEANUP, args)["state"], "unknown")
            stopped = stage / "listener-stopped.json"
            stopped.write_text(json.dumps(worker)); stopped.chmod(0o600)
            self.assertEqual(self.run_remote(transfer._REMOTE_ABORT_STATUS, args)["state"], "present")
            self.assertEqual(self.run_remote(transfer._REMOTE_ABORT_CLEANUP, args)["state"], "aborted-cleaned")
            self.assertEqual(self.run_remote(transfer._REMOTE_ABORT_STATUS, args)["state"], "aborted-cleaned")
            self.assertEqual(self.run_remote(transfer._REMOTE_ABORT_CLEANUP, args)["state"], "unknown")

    def test_terminal_admission_rejects_nonterminal_or_busy_base(self):
        record = {"correlationId": CORRELATION, "sourceSha": SOURCE,
                  "baseMsiArtifactId": "sha256-" + "a" * 64}
        intent = {"leaseId": CORRELATION,
                  "request": {"sourceSha": SOURCE, "baseMsiArtifactId": record["baseMsiArtifactId"]},
                  "pair": {"baseVersion": "2.1.19"}}
        observed = {"state": "terminal", "result": "PASSED", "stage": "READBACK", "exitCode": 0,
                    "sourceSha": SOURCE, "baseArtifactId": record["baseMsiArtifactId"]}
        idle = {"state": "ready", "activeCount": 0, "installedVersion": "2.1.19"}
        with (mock.patch.object(transfer.base, "_private_intent", return_value=intent),
              mock.patch.object(transfer.base, "status", return_value=observed) as status,
              mock.patch.object(transfer.base, "readiness", return_value=idle) as readiness):
            self.assertRegex(transfer._base_terminal(Path("/unused"), record), r"^[0-9a-f]{64}$")
            status.return_value = {**observed, "result": "FAILED"}
            with self.assertRaises(transfer.WindowsMsiHttpTransferError):
                transfer._base_terminal(Path("/unused"), record)
            status.return_value = observed
            readiness.return_value = {**idle, "activeCount": 1}
            with self.assertRaises(transfer.WindowsMsiHttpTransferError):
                transfer._base_terminal(Path("/unused"), record)

    def test_terminal_admission_recovers_consumed_bootstrap_status_from_durable_proof(self):
        record = {"correlationId": CORRELATION, "sourceSha": SOURCE,
                  "baseMsiArtifactId": "sha256-" + "a" * 64}
        intent = {"leaseId": CORRELATION,
                  "request": {"sourceSha": SOURCE, "baseMsiArtifactId": record["baseMsiArtifactId"]},
                  "pair": {"baseVersion": "2.1.19"}}
        terminal = {"state": "terminal", "result": "PASSED", "stage": "READBACK", "exitCode": 0,
                    "sourceSha": SOURCE, "baseArtifactId": record["baseMsiArtifactId"]}
        idle = {"state": "ready", "activeCount": 0, "installedVersion": "2.1.19"}
        with (mock.patch.object(transfer.base, "_private_intent", return_value=intent),
              mock.patch.object(transfer.base, "status", return_value={"state": "unknown"}),
              mock.patch.object(transfer.base, "terminal_reconcile", return_value=terminal) as reconcile,
              mock.patch.object(transfer.base, "readiness", return_value=idle)):
            self.assertRegex(transfer._base_terminal(Path("/unused"), record), r"^[0-9a-f]{64}$")
            reconcile.assert_called_once_with(Path("/unused"), {"correlationId": CORRELATION})
            reconcile.return_value = {**terminal, "baseArtifactId": "sha256-" + "b" * 64}
            with self.assertRaises(transfer.WindowsMsiHttpTransferError):
                transfer._base_terminal(Path("/unused"), record)

    def test_ready_for_base_requires_stopped_listener_verified_guest_and_stage(self):
        record = {"environment": "windows-cp117", "correlationId": CORRELATION,
                  "sourceSha": SOURCE, "baseMsiArtifactId": "sha256-" + "a" * 64,
                  "socketPath": "/private/cp117/qga.sock", "qemuPid": 12,
                  "startTicks": 34, "expectedSid": SID, "sha256": "a" * 64, "length": 4}
        with (mock.patch.object(transfer, "_listener_join", return_value=(object(), record, "/" + "x" * 40)),
              mock.patch.object(transfer, "listener_status", return_value={"state": "stopped"}) as listener,
              mock.patch.object(transfer, "guest_task_status", return_value={"state": "ready-for-base"}) as guest,
              mock.patch.object(transfer, "_remote_result", return_value={"state": "staged-for-base"}) as stage):
            result = transfer.ready_for_base(Path("/unused"), None, Path("/remote"), CORRELATION)
            self.assertEqual(result["state"], "ready-for-base")
            self.assertEqual(result["guestPath"],
                             r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-base-" + CORRELATION + r"\base.msi")
            stage.assert_called_once()
            listener.return_value = {"state": "listening", "port": 3000}
            self.assertEqual(transfer.ready_for_base(Path("/unused"), None, Path("/remote"), CORRELATION)["state"], "unknown")

    @unittest.skipUnless(sys.platform.startswith("linux"), "listener is scoped to the Arch Linux host")
    def test_one_use_listener_serves_exact_staged_bytes(self):
        payload = b"local-loopback-msi"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.args(root, payload)
            self.assertEqual(self.run_remote(transfer._REMOTE_STAGE, args, payload)["state"], "staged")
            path = "/" + "x" * 40
            started = self.run_remote(transfer._REMOTE_LISTEN_START, args,
                                      json.dumps({"path": path}).encode())
            self.assertEqual(started["state"], "listening")
            try:
                self.assertEqual(urlopen(f"http://127.0.0.1:{started['port']}{path}", timeout=5).read(), payload)
                self.assertEqual(self.run_remote(transfer._REMOTE_LISTEN_STATUS, args)["state"], "served")
                self.assertEqual(self.run_remote(transfer._REMOTE_CLEANUP, args)["state"], "unknown")
            finally:
                self.run_remote(transfer._REMOTE_LISTEN_STOP, args)

    @unittest.skipUnless(sys.platform.startswith("linux"), "listener is scoped to the Arch Linux host")
    def test_live_listener_stop_proves_exact_owner_and_frees_port(self):
        payload = b"abort-before-download"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.args(root, payload)
            self.assertEqual(self.run_remote(transfer._REMOTE_STAGE, args, payload)["state"], "staged")
            started = self.run_remote(transfer._REMOTE_LISTEN_START, args,
                                      json.dumps({"path": "/" + "y" * 40}).encode())
            self.assertEqual(started["state"], "listening")
            self.assertEqual(self.run_remote(transfer._REMOTE_LISTEN_STATUS, args)["state"], "listening")
            self.assertEqual(self.run_remote(transfer._REMOTE_LISTEN_STOP, args)["state"], "stopped")
            self.assertEqual(self.run_remote(transfer._REMOTE_LISTEN_STATUS, args)["state"], "stopped")
            self.assertEqual(self.run_remote(transfer._REMOTE_CLEANUP, args)["state"], "unknown")


if __name__ == "__main__":
    unittest.main()
