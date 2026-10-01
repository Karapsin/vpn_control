"""Causal regressions for the CP117 reaped server-abort cleanup successor."""
from __future__ import annotations

import tempfile
import unittest
import contextlib
import io
import json
import os
from pathlib import Path
from unittest import mock

from agent_tools import windows_fixture_server_abort_successor as successor


NEXT = "1a2b3c4d-1111-4222-8333-123456789abc"
REQUEST = {"successorCleanupCorrelationId": NEXT}
GEN = ("windows-cp117", "/qga", 17, 29, "S-1-5-21-1-2-3-1002")
SERVER_REQUEST = {"host":"archlinux", "leaseId":"11111111-1111-4111-8111-111111111111",
                  "stageCorrelationId":"22222222-2222-4222-8222-222222222222",
                  "serverCorrelationId":successor._SERVER, "sourceSha":"a" * 40,
                  "fixtureReceiptArtifactId":"sha256-" + "b" * 64,
                  "baseMsiArtifactId":"sha256-" + "c" * 64,
                  "targetMsiArtifactId":"sha256-" + "d" * 64}


class ServerAbortSuccessorTests(unittest.TestCase):
    def _admitted(self):
        return object(), type("Target", (), {"fixture_transfer_root":"/fixture"})(), GEN, SERVER_REQUEST

    def test_response_loss_persists_once_and_status_never_replays(self):
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(successor, "_admission", return_value=self._admitted()), \
             mock.patch.object(successor, "_observe", return_value=None) as observe:
            self.assertEqual("unknown", successor.start(temporary, REQUEST)["state"])
            self.assertIsNotNone(successor._read(Path(temporary), NEXT))
            self.assertEqual("unknown", successor.start(temporary, REQUEST)["state"])
            self.assertEqual("unknown", successor.status(temporary, REQUEST)["state"])
        self.assertEqual(2, observe.call_count)

    def test_reaped_prior_child_then_exact_terminal_task_receipt_cleans(self):
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(successor, "_admission", return_value=self._admitted()), \
             mock.patch.object(successor.lease, "finish_role", return_value={"state":"active"}), \
             mock.patch.object(successor.lease, "reconcile", return_value={"state":"active"}), \
             mock.patch.object(successor, "_observe", side_effect=[{"state":"submitted"}, {"state":"terminal","exitcode":0}, {"state":"terminal","exitcode":0}]):
            self.assertEqual("submitted", successor.start(temporary, REQUEST)["state"])
            result = successor.status(temporary, REQUEST)
        self.assertEqual("cleaned", result["state"])
        self.assertEqual(64, len(result["cleanupReceiptSha256"]))

    def test_existing_intent_cannot_dispatch_twice_after_response_loss(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = {"version": 1, "request": REQUEST, "serverCorrelationId": successor._SERVER,
                      "priorCleanupCorrelationId": successor._ABORT, "serverRequest": SERVER_REQUEST,
                      "guestGeneration": {"socketPath": GEN[1], "qemuPid": GEN[2], "startTicks": GEN[3]}}
            self.assertEqual("created", successor._reserve(root, record))
            self.assertEqual("existing", successor._reserve(root, record))
            with mock.patch.object(successor, "_admission", return_value=self._admitted()), \
                 mock.patch.object(successor, "_observe", side_effect=AssertionError("must not dispatch")):
                self.assertEqual("unknown", successor.start(root, REQUEST)["state"])

    def test_terminal_is_durable_before_fresh_verify_and_later_status_skips_child_query(self):
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(successor, "_admission", return_value=self._admitted()), \
             mock.patch.object(successor.lease, "finish_role", return_value={"state":"active"}), \
             mock.patch.object(successor, "_completed", return_value=True), \
             mock.patch.object(successor, "_observe", side_effect=[{"state":"submitted"}, {"state":"terminal","exitcode":0}, {"state":"terminal","exitcode":0}, {"state":"terminal","exitcode":0}]) as observe:
            self.assertEqual("submitted", successor.start(temporary, REQUEST)["state"])
            self.assertEqual("cleaned", successor.status(temporary, REQUEST)["state"])
            self.assertEqual({"exitcode": 0}, successor._terminal(Path(temporary), NEXT))
            with mock.patch.object(successor.server, "_read_intent", return_value={"request": SERVER_REQUEST}), \
                 mock.patch.object(successor.server, "_request", return_value=SERVER_REQUEST), \
                 mock.patch.object(successor.base, "_descriptor", return_value=self._admitted()[:3]):
                self.assertEqual("cleaned", successor.status(temporary, REQUEST)["state"])
        self.assertEqual(["start", "status", "verify"], [call.args[5] for call in observe.call_args_list])

    def test_wrong_original_owner_or_live_server_blocks_before_intent(self):
        for error in ("owner", "server"):
            with self.subTest(error=error), tempfile.TemporaryDirectory() as temporary, \
                 mock.patch.object(successor, "_admission", side_effect=successor.WindowsFixtureServerAbortSuccessorError(error)), \
                 mock.patch.object(successor, "_observe") as observe:
                self.assertEqual("unknown", successor.start(temporary, REQUEST)["state"])
                self.assertIsNone(successor._read(Path(temporary), NEXT))
                observe.assert_not_called()

    def test_prior_effect_already_done_does_not_dispatch_successor(self):
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(successor, "_admission", return_value=self._admitted()), \
             mock.patch.object(successor, "_observe", return_value={"state":"blocked", "reason":"server-or-task-not-safe"}) as observe:
            # A read-only response means the old public task is already absent.
            # This successor is intentionally not a replacement cleanup.
            self.assertEqual("unknown", successor.start(temporary, REQUEST)["state"])
        observe.assert_called_once()

    def test_live_qga_or_failed_cleanup_child_never_reports_clean(self):
        for observed in ({"state":"blocked","reason":"prior-child-live"}, {"state":"unknown"}):
            with self.subTest(observed=observed), tempfile.TemporaryDirectory() as temporary, \
                 mock.patch.object(successor, "_admission", return_value=self._admitted()), \
                 mock.patch.object(successor, "_observe", side_effect=[{"state":"submitted"}, observed]):
                successor.start(temporary, REQUEST)
                self.assertEqual("unknown", successor.status(temporary, REQUEST)["state"])

    def test_nonzero_cleanup_child_requires_fresh_absence_proof_before_lease_finish(self):
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(successor, "_admission", return_value=self._admitted()), \
             mock.patch.object(successor.lease, "finish_role", return_value={"state":"active"}) as finish, \
             mock.patch.object(successor, "_observe", side_effect=[
                 {"state":"submitted"}, {"state":"terminal", "exitcode":1},
                 {"state":"terminal", "exitcode":1}]) as observe:
            self.assertEqual("submitted", successor.start(temporary, REQUEST)["state"])
            result = successor.status(temporary, REQUEST)
            self.assertEqual("cleaned", result["state"])
            self.assertEqual({"exitcode": 1}, successor._terminal(Path(temporary), NEXT))
        self.assertEqual(["start", "status", "verify"], [call.args[5] for call in observe.call_args_list])
        finish.assert_called_once()

    def test_same_campaign_restart_requires_exact_cleanup_and_fresh_absence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            correlation = NEXT
            record = {"version": 1, "request": {"successorCleanupCorrelationId": correlation},
                      "serverCorrelationId": successor._SERVER,
                      "priorCleanupCorrelationId": successor._ABORT,
                      "serverRequest": SERVER_REQUEST,
                      "guestGeneration": {"socketPath": GEN[1], "qemuPid": GEN[2],
                                          "startTicks": GEN[3]}}
            successor._reserve(root, record)
            successor._save_terminal(root, correlation, {"exitcode": 1})
            digest = successor._digest(record["request"], GEN, 1)
            campaign = {"state": "active", "role": None, "server": "stopped",
                        "credentials": "ready", "lastOutcome": "failed-cleaned",
                        "lastEvidenceSha256": digest,
                        "identity": {"leaseId": SERVER_REQUEST["leaseId"]}}
            with mock.patch.object(successor.base, "_descriptor", return_value=self._admitted()[:3]), \
                 mock.patch.object(successor.base, "_campaign_identity", return_value=campaign["identity"]), \
                 mock.patch.object(successor.lease, "_locked", side_effect=lambda _root: (root, os.open(root, os.O_RDONLY))), \
                 mock.patch.object(successor.lease, "_active", return_value=campaign), \
                 mock.patch.object(successor.lease, "_remote_confirm", return_value=True), \
                 mock.patch.object(successor.base, "_campaign_remote", return_value=object()), \
                 mock.patch.object(successor, "_observe", return_value={"state":"terminal", "exitcode":1}) as observe:
                self.assertTrue(successor.allows_server_restart(root, successor._SERVER,
                                                                 SERVER_REQUEST["leaseId"], {"request": SERVER_REQUEST}))
                observe.return_value = {"state":"unknown"}
                self.assertFalse(successor.allows_server_restart(root, successor._SERVER,
                                                                  SERVER_REQUEST["leaseId"], {"request": SERVER_REQUEST}))

    def test_server_history_accepts_only_the_verified_same_campaign_successor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / successor.server._GROUP
            directory.mkdir(parents=True)
            (directory / (successor._SERVER + ".json")).write_text("{}")
            with mock.patch.object(successor.server.base, "_descriptor", return_value=self._admitted()[:3]), \
                 mock.patch.object(successor.server.base, "_campaign_remote", return_value=object()), \
                 mock.patch.object(successor.server, "_read_intent", return_value={"request": SERVER_REQUEST}), \
                 mock.patch.object(successor, "allows_server_restart", return_value=True) as allowed:
                successor.server._closed_server_history(root, SERVER_REQUEST["leaseId"])
                allowed.assert_called_once()
            with mock.patch.object(successor.server.base, "_descriptor", return_value=self._admitted()[:3]), \
                 mock.patch.object(successor.server.base, "_campaign_remote", return_value=object()), \
                 mock.patch.object(successor.server, "_read_intent", return_value={"request": SERVER_REQUEST}), \
                 mock.patch.object(successor, "allows_server_restart", return_value=False):
                with self.assertRaises(successor.server.WindowsUpdateFixtureServerError):
                    successor.server._closed_server_history(root, SERVER_REQUEST["leaseId"])

    def test_request_rejects_historical_or_noncanonical_correlations(self):
        for correlation in (successor._SERVER, successor._ABORT, "A" * 36, "not-a-uuid"):
            with self.subTest(correlation=correlation):
                with self.assertRaises(successor.WindowsFixtureServerAbortSuccessorError):
                    successor._request({"successorCleanupCorrelationId": correlation})

    def test_remote_program_uses_only_fixed_server_task_and_durable_private_journal(self):
        self.assertIn("VpnControlMcpFixtureServer-", successor._REMOTE)
        self.assertNotIn("VpnControlMcpFixtureHttp-", successor._REMOTE)
        self.assertIn("ProcessId=", successor._REMOTE)
        self.assertNotIn("guest-exec-status',{'pid':dispatch['pid']}", successor._REMOTE)
        self.assertIn("os.O_EXCL", successor._REMOTE)
        self.assertIn("0o600", successor._REMOTE)
        self.assertIn("os.fsync(parent)", successor._REMOTE)
        compile(successor._REMOTE, "server-abort-successor-qga", "exec")

    def test_fake_qga_status_reads_durable_terminal_without_reaped_child_poll(self):
        """Execute the remote program with its QGA transport made fail loud.

        The successor terminal is the response-loss recovery fact.  If status
        tries to inspect its already-reaped dispatch PID, this fake fails.
        """
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); job = root / "windows-cp117" / "windows-update-fixture-server" / successor._SERVER
            old = job / ("cleanup-" + successor._ABORT); group = job / ("successor-" + NEXT)
            for directory in (old, group): directory.mkdir(parents=True, mode=0o700)
            os.chmod(job, 0o700)
            binding = {"leaseId":"11111111-1111-4111-8111-111111111111", "role":"server-start", "roleCorrelationId":successor._SERVER,
                       "serverCorrelationId":successor._SERVER, "cleanupCorrelationId":successor._ABORT,
                       "socketPath":"/qga", "qemuPid":17, "startTicks":29, "commandSha256":"a" * 64,
                       "verifyCommandSha256":"b" * 64, "dispatchMode":"dispatched"}
            for path, value in ((old / "binding.json", binding), (old / "dispatch.json", {"pid":88}),
                                (group / "binding.json", {"serverCorrelationId":successor._SERVER, "priorCleanupCorrelationId":successor._ABORT, "successorCleanupCorrelationId":NEXT, "socketPath":"/qga", "qemuPid":17, "startTicks":29, "originalSid":GEN[4]}),
                                (group / "terminal.json", {"exitcode":0})):
                path.write_text(json.dumps(value)); os.chmod(path, 0o600)
            source = successor._REMOTE.replace("not live(sock,pid,ticks)", "False")
            old_argv = __import__("sys").argv; __import__("sys").argv = ["qga", str(root), successor._SERVER, successor._ABORT, NEXT, "/qga", "17", "29", GEN[4], "status", r"C:\Python\python.exe", "eA=="]
            try:
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    with self.assertRaises(SystemExit) as exit_result:
                        exec(source, {})
                self.assertEqual(0, exit_result.exception.code)
            finally: __import__("sys").argv = old_argv
        self.assertEqual({"state":"terminal", "exitcode":0}, json.loads(output.getvalue()))

    def test_read_only_journal_diagnostic_reports_terminal_without_qga_child_poll(self):
        with tempfile.TemporaryDirectory() as temporary:
            group = (Path(temporary) / "windows-cp117" / "windows-update-fixture-server"
                     / successor._SERVER / ("successor-" + NEXT))
            group.mkdir(parents=True, mode=0o700)
            for name, value in (("binding.json", {"exact": True}),
                                ("dispatch.json", {"pid": 88}),
                                ("terminal.json", {"exitcode": 0})):
                path = group / name
                path.write_text(json.dumps(value))
                os.chmod(path, 0o600)
            source = successor._REMOTE_JOURNAL_DIAGNOSTIC.replace("not live(sock,pid,ticks)", "False")
            original = __import__("sys").argv
            __import__("sys").argv = ["qga", temporary, successor._SERVER, successor._ABORT,
                                      NEXT, "/qga", "17", "29"]
            try:
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    exec(source, {})
            finally:
                __import__("sys").argv = original
        self.assertEqual({"state": "observed", "binding": "present", "dispatch": "present",
                          "terminal": "present", "terminalResult": "zero", "terminalExitCode": 0},
                         json.loads(output.getvalue()))

    def test_nonzero_cleanup_after_task_absence_accepts_only_fresh_verifier(self):
        """A terminal child may fail after deletion; never replay that child."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job = root / "windows-cp117" / "windows-update-fixture-server" / successor._SERVER
            old = job / ("cleanup-" + successor._ABORT)
            group = job / ("successor-" + NEXT)
            for directory in (old, group): directory.mkdir(parents=True, mode=0o700)
            os.chmod(job, 0o700)
            binding = {"leaseId": SERVER_REQUEST["leaseId"], "role": "server-start",
                       "roleCorrelationId": successor._SERVER, "serverCorrelationId": successor._SERVER,
                       "cleanupCorrelationId": successor._ABORT, "socketPath": "/qga", "qemuPid": 17,
                       "startTicks": 29, "commandSha256": "a" * 64,
                       "verifyCommandSha256": "b" * 64, "dispatchMode": "dispatched"}
            entries = ((old / "binding.json", binding), (old / "dispatch.json", {"pid": 88}),
                       (group / "binding.json", {"serverCorrelationId": successor._SERVER,
                        "priorCleanupCorrelationId": successor._ABORT,
                        "successorCleanupCorrelationId": NEXT, "socketPath": "/qga",
                        "qemuPid": 17, "startTicks": 29, "originalSid": GEN[4]}),
                       (group / "dispatch.json", {"pid": 99}),
                       (group / "terminal.json", {"exitcode": 1}))
            for path, value in entries:
                path.write_text(json.dumps(value)); os.chmod(path, 0o600)
            suffix = successor._REMOTE[len(successor.base._QGA):]
            suffix = suffix.replace("not live(sock,pid,ticks)", "False")
            calls = []
            def fake_call(_socket, command, _args):
                calls.append(command)
                if command == "guest-exec": return {"pid": 117}
                if command == "guest-exec-status": return {"exited": True, "exitcode": 0}
                raise AssertionError(command)
            namespace = {}
            exec(successor.base._QGA, namespace)
            namespace["call"] = fake_call
            original = __import__("sys").argv
            __import__("sys").argv = ["qga", temporary, successor._SERVER, successor._ABORT,
                                      NEXT, "/qga", "17", "29", GEN[4], "verify",
                                      r"C:\Python\python.exe", "eA=="]
            try:
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    with self.assertRaises(SystemExit) as exit_result:
                        exec(suffix, namespace)
                self.assertEqual(0, exit_result.exception.code)
            finally:
                __import__("sys").argv = original
        self.assertEqual({"state": "terminal", "exitcode": 1}, json.loads(output.getvalue()))
        self.assertEqual(["guest-exec", "guest-exec-status"], calls)


if __name__ == "__main__":
    unittest.main()
