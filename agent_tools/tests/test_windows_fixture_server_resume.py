"""Pre-dispatch-only CP117 server resume regressions."""

import json
import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_tools import windows_fixture_server_resume as resume


class ServerResumeTests(unittest.TestCase):
    REQUEST = {"serverCorrelationId": resume._CORRELATION, "leaseId": "e59a7483-4e38-4e7b-b8fa-0d8b2356916a",
               "stageCorrelationId": "e848bed2-5bea-47bc-a85a-6cf17b1fcc6a", "sourceSha": "a" * 40,
               "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
               "baseMsiArtifactId": "sha256-" + "c" * 64,
               "targetMsiArtifactId": "sha256-" + "d" * 64}
    GUEST = ("windows-cp117", "/qga", 17, 29, "S-1-5-21-1-2-3-1002")

    def _admitted(self):
        target = type("Target", (), {"fixture_transfer_root": "/fixture"})()
        return object(), target, self.REQUEST, {"sourceFingerprint": "a" * 64}, self.GUEST, "fixed script", "b" * 64

    def test_unknown_preflight_does_not_write_resume_intent_or_dispatch(self):
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(resume, "_admit", return_value=self._admitted()), \
             mock.patch.object(resume, "_preflight", return_value=False), \
             mock.patch.object(resume.base, "_remote") as remote:
            self.assertEqual("unknown", resume.start(temporary, {"serverCorrelationId": resume._CORRELATION})["state"])
            self.assertIsNone(resume._read_resume_intent(Path(temporary)))
            remote.assert_not_called()

    def test_one_submission_after_durable_preflight_and_no_replay(self):
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(resume, "_admit", return_value=self._admitted()), \
             mock.patch.object(resume, "_preflight", return_value=True), \
             mock.patch.object(resume.base, "_remote", return_value=json.dumps({"state": "submitted", "serverCorrelationId": resume._CORRELATION}).encode()) as remote:
            first = resume.start(temporary, {"serverCorrelationId": resume._CORRELATION})
            self.assertEqual("submitted", first["state"])
            self.assertIsNotNone(resume._read_resume_intent(Path(temporary)))
            self.assertEqual("unknown", resume.start(temporary, {"serverCorrelationId": resume._CORRELATION})["state"])
            remote.assert_called_once()

    def test_request_is_fixed_and_has_no_command_or_path_fields(self):
        for value in ({"serverCorrelationId": "11111111-1111-4111-8111-111111111111"},
                      {"serverCorrelationId": resume._CORRELATION, "command": "other"}):
            with self.assertRaises(resume.WindowsFixtureServerResumeError):
                resume._request(value)

    def test_remote_preflight_checks_absence_before_any_resume_submission(self):
        prefix = resume.base._QGA + resume.lease.remote_role_guard()
        suffix = resume._REMOTE_PRE_DISPATCH[len(prefix):]
        with tempfile.TemporaryDirectory() as temporary:
            group = Path(temporary) / "windows-cp117" / "windows-update-fixture-server"
            group.mkdir(parents=True, mode=0o700)
            os.chmod(group, 0o700)
            def observe(job_present):
                job = group / resume._CORRELATION
                if job_present: job.mkdir()
                calls = []
                namespace = {}
                exec(prefix, namespace)
                namespace["live"] = lambda *_: True
                namespace["require_campaign_role"] = lambda *_: None
                def call(_socket, command, _args):
                    calls.append(command)
                    if command == "guest-exec": return {"pid": 18}
                    if command == "guest-exec-status": return {"exited": True, "exitcode": 0}
                    raise AssertionError(command)
                namespace["call"] = call
                argv = ["qga", temporary, "windows-cp117", self.REQUEST["leaseId"],
                        resume._CORRELATION, "/qga", "17", "29", self.REQUEST["sourceSha"],
                        self.REQUEST["fixtureReceiptArtifactId"], self.REQUEST["baseMsiArtifactId"],
                        self.REQUEST["targetMsiArtifactId"]]
                with mock.patch("sys.argv", argv):
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        with self.assertRaises(SystemExit) if job_present else contextlib.nullcontext():
                            exec(suffix, namespace)
                if job_present: job.rmdir()
                return json.loads(output.getvalue()), calls
            blocked, blocked_calls = observe(True)
            self.assertEqual({"state": "blocked", "phase": "remote-journal"}, blocked)
            self.assertEqual([], blocked_calls)
            ready, ready_calls = observe(False)
            self.assertEqual({"state": "ready", "phase": "guest-absence"}, ready)
            self.assertEqual(["guest-exec", "guest-exec-status"], ready_calls)


if __name__ == "__main__":
    unittest.main()
