"""Causal coverage for the fourth fixed CP117 owner quit."""
from __future__ import annotations

import base64
import contextlib
import gzip
import hashlib
import io
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_tools import windows_msi_owner_relaunch_quit as v1
from agent_tools import windows_msi_owner_relaunch_quit_v3 as v3
from agent_tools import windows_msi_owner_relaunch_quit_v4 as v4


class RelaunchQuitV4Test(unittest.TestCase):
    def _admitted(self):
        descriptor = ("windows-cp117", "/qga.sock", 589342, 520739,
                      "S-1-5-21-2404255130-2183793310-3766671872-1002")
        generation = {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}
        return object(), descriptor, "b" * 64, generation, "c" * 64

    def test_causal_owner_command_form_preserves_old_body_and_matches_relaunch_pair(self):
        """RED: v3 used a quoted state path in both branches and exited at phase 14."""
        self.assertIn(v4._OLD_OWNER_FORM, v1._TASK_PS)
        self.assertIn(v4._OLD_OWNER_FORM, v3._TASK_PS)
        self.assertNotIn(v4._OLD_OWNER_FORM, v4._TASK_PS)
        self.assertIn(v4._NEW_OWNER_FORM, v4._TASK_PS)
        self.assertIn("$unquotedArgument='--state-dir '+$state+' serve'", v4._TASK_PS)
        self.assertIn("$unquoted=$cli+' '+$unquotedArgument", v4._TASK_PS)

    def test_generated_guest_program_compiles_before_qga_dispatch(self):
        compile(v4._REMOTE, "generated-v4-relaunch-quit", "exec")
        self.assertIn(v4._TASK, v4._REMOTE)
        self.assertIn(v3._TASK, v4._REMOTE)
        self.assertIn("LastTaskResult -eq 0", v4._REMOTE)
        self.assertLess(len(v4._REMOTE), 30_000)

    def test_generated_start_bootstrap_stays_under_windows_command_limit(self):
        captured = []

        def fake_call(_sock, command, arguments):
            if command == "guest-exec":
                captured.append(arguments)
                return {"pid": 7}
            self.assertEqual(command, "guest-exec-status")
            return {"exited": True, "exitcode": 0, "out-truncated": False,
                    "err-truncated": False,
                    "out-data": base64.b64encode(b'{"version":1,"state":"submitted"}\\n').decode()}

        source = v4._REMOTE.replace(
            "try:\n if mode not in ('start','status','diagnose','bootstrap-diagnostic') or not live(sock,pid,ticks):raise ValueError()",
            "call=FAKE_CALL\ntry:\n if mode not in ('start','status','diagnose','bootstrap-diagnostic'):raise ValueError()")
        sid = "S-1-5-21-2404255130-2183793310-3766671872-1002"
        with mock.patch("sys.argv", ["generated", "/qga.sock", "589342", "520739", sid,
                                      "b" * 64, "start"]), contextlib.redirect_stdout(io.StringIO()):
            exec(compile(source, "generated-v4-relaunch-quit", "exec"), {"FAKE_CALL": fake_call})
        self.assertEqual(len(captured), 1)
        self.assertLess(sum(len(part) + 1 for part in ["powershell.exe", *captured[0]["arg"]]), 30_000)
        wrapper = base64.b64decode(captured[0]["arg"][-1]).decode("utf-16le")
        packed = re.search(r"\$packed='([^']+)'", wrapper).group(1)
        bootstrap = gzip.decompress(base64.b64decode(packed)).decode()
        v3_body = v3._TASK_PS.replace("__SID__", sid).replace("__CLI_HASH__", "b" * 64)
        v3_args = "-NoProfile -NonInteractive -EncodedCommand " + base64.b64encode(v3_body.encode("utf-16le")).decode()
        v3_digest = __import__("hashlib").sha256(v3_args.encode()).hexdigest()
        self.assertIn("-cne '" + v3_digest + "'", bootstrap)
        self.assertNotIn("'+v3_digest+'", bootstrap)

    def test_admission_requires_exact_v3_failed_receipt_and_owner_before_phase(self):
        config, descriptor, cli_hash, generation, evidence = self._admitted()
        v3_record = {"sourceSha": v4.relaunch._SOURCE, "guestGeneration": generation,
                     "evidenceSha256": evidence, "state": "intent"}
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(v4.v3, "_observer", return_value=(config, descriptor, cli_hash, v3_record)), \
                mock.patch.object(v4.v3, "_run", return_value={"version": 1, "state": "failed"}), \
                mock.patch.object(v4.v1, "_admit", return_value=(config, descriptor, cli_hash, generation, evidence)), \
                mock.patch.object(v4.phase_diagnostic, "status", return_value={"state": "diagnosed", "phase": "owner-before", "replayAllowed": False, "nativeActionAllowed": False}):
            self.assertEqual(v4._admit(Path(directory)), (config, descriptor, cli_hash, generation, evidence))

    def test_non_owner_before_diagnosis_blocks_without_writing_or_dispatching(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(v4, "_admit", return_value=None) as admit, \
                mock.patch.object(v4, "_run") as run:
            result = v4.start(directory, {"host": "archlinux"})
        self.assertEqual(result, v4._UNKNOWN)
        admit.assert_called_once()
        run.assert_not_called()

    def test_durable_intent_prevents_replay_after_unknown_start(self):
        config, descriptor, cli_hash, generation, evidence = self._admitted()
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(v4, "_admit", return_value=(config, descriptor, cli_hash, generation, evidence)), \
                mock.patch.object(v4, "_run", return_value={"version": 1, "state": "unknown"}) as run:
            first = v4.start(directory, {"host": "archlinux"})
            second = v4.start(directory, {"host": "archlinux"})
        self.assertEqual(first, v4._UNKNOWN)
        self.assertEqual(second, v4._UNKNOWN)
        self.assertEqual([call.args[-1] for call in run.call_args_list], ["start"])

    def test_success_status_uses_post_effect_binding_not_live_owner_admission(self):
        config, descriptor, cli_hash, generation, _evidence = self._admitted()
        evidence = hashlib.sha256(json.dumps(generation, sort_keys=True).encode()).hexdigest()
        record = {"version": 1, "correlationId": v4._CORRELATION,
                  "idempotencyKey": v4._CORRELATION, "requestSha256": v4._REQUEST_SHA256,
                  "sourceSha": v4.relaunch._SOURCE, "guestGeneration": generation,
                  "evidenceSha256": evidence, "state": "intent"}
        v1_record = dict(record)
        v1_record.update(correlationId=v1._CORRELATION, idempotencyKey=v1._CORRELATION,
                         requestSha256=v1._REQUEST_SHA256)
        v3_record = dict(record)
        v3_record.update(correlationId=v3._CORRELATION, idempotencyKey=v3._CORRELATION,
                         requestSha256=v3._REQUEST_SHA256)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            v4._write(root, record)
            with mock.patch.object(v4.v1, "_observer_bound", return_value=(config, descriptor, cli_hash, v1_record)), \
                    mock.patch.object(v4.v3, "_observer", return_value=(config, descriptor, cli_hash, v3_record)), \
                    mock.patch.object(v4.phase_diagnostic, "_observer", return_value=(config, descriptor, cli_hash)), \
                    mock.patch.object(v4.v3, "_run", return_value={"version": 1, "state": "failed"}), \
                    mock.patch.object(v4.phase_diagnostic, "_run", return_value={"version": 1, "state": "finished", "exitCode": 14}), \
                    mock.patch.object(v4, "_run", return_value={"version": 1, "state": "exited"}), \
                    mock.patch.object(v4.v1, "_admit") as live_admit:
                result = v4.status(root, {"host": "archlinux"})
        self.assertEqual(result, {"state": "exited", "runtimeRunning": False, "ownerExited": True,
                                  "replayAllowed": False, "nativeActionAllowed": False})
        live_admit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
