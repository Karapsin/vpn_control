"""Causal regressions for the fixed CP117 post-resource server diagnostic."""
from __future__ import annotations

import base64
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_tools import windows_fixture_post_resource_diagnostic as diagnostic


class PostResourceDiagnosticTests(unittest.TestCase):
    def _intent(self):
        return {"request": {"host": "archlinux", "leaseId": "a" * 8 + "-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
                              "stageCorrelationId": "b" * 8 + "-bbbb-4bbb-bbbb-bbbbbbbbbbbb",
                              "serverCorrelationId": diagnostic._CORRELATION, "sourceSha": "c" * 40,
                              "fixtureReceiptArtifactId": "sha256-" + "d" * 64,
                              "baseMsiArtifactId": "sha256-" + "e" * 64,
                              "targetMsiArtifactId": "sha256-" + "f" * 64},
                "socketPath": "/qga", "qemuPid": 41, "startTicks": 42,
                "originalSid": "S-1-5-21-1-2-3-1002",
                "pythonPath": r"C:\Program Files\Python313\python.exe",
                "pythonExeSha256": "1" * 64}

    def _diagnose(self, reply):
        descriptor = ("windows-cp117", "/qga", 41, 42, "S-1-5-21-1-2-3-1002")
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(diagnostic.server, "_read_intent", return_value=self._intent()), \
             mock.patch.object(diagnostic.base, "_descriptor", return_value=(object(), object(), descriptor)), \
             mock.patch.object(diagnostic.stage, "status", return_value={"state": "staged-not-server-ready"}), \
             mock.patch.object(diagnostic.server, "diagnose_status", return_value={
                 "state": "observed", "serverCorrelationId": diagnostic._CORRELATION,
                 "task": "ready", "lastResult": 1, "ready": "absent",
                 "stateContent": "probe-events", "stageAcl": "expected", "stateAcl": "expected",
                 "replayAllowed": False}), \
             mock.patch.object(diagnostic.base, "_remote", return_value=json.dumps(reply).encode()) as remote:
            result = diagnostic.diagnose(directory, dict(diagnostic._EXPECTED_INPUT))
        return result, remote

    def test_successfully_classifies_all_post_resource_gates_without_ready_receipt(self):
        reply = {"state": "observed", "result": {"version": 1,
                 "serverProcessIdentity": "ok", "tlsLoadCertChain": "ok",
                 "certificateDigestRecheck": "ok", "loopbackEphemeralBind": "ok"}}
        result, remote = self._diagnose(reply)
        self.assertEqual({"state": "diagnosed", "serverCorrelationId": diagnostic._CORRELATION,
                          "serverProcessIdentity": "ok", "tlsLoadCertChain": "ok",
                          "certificateDigestRecheck": "ok", "loopbackEphemeralBind": "ok",
                          "replayAllowed": False, "nativeActionAllowed": False,
                          "productAction": False}, result)
        args = remote.call_args.args[2]
        self.assertEqual("1" * 64, args[4])
        self.assertTrue(args[6].endswith(r"\server-cert.pem"))
        self.assertTrue(args[7].endswith(r"\server-key.pem"))

    def test_failed_tls_gate_skips_dependent_digest_and_bind(self):
        reply = {"state": "observed", "result": {"version": 1,
                 "serverProcessIdentity": "ok", "tlsLoadCertChain": "failed",
                 "certificateDigestRecheck": "skipped", "loopbackEphemeralBind": "skipped"}}
        result, _remote = self._diagnose(reply)
        self.assertEqual("failed", result["tlsLoadCertChain"])
        self.assertEqual("skipped", result["certificateDigestRecheck"])
        self.assertEqual("skipped", result["loopbackEphemeralBind"])

    def test_rejects_noncausal_gate_ordering_and_never_marks_replay_allowed(self):
        reply = {"state": "observed", "result": {"version": 1,
                 "serverProcessIdentity": "failed", "tlsLoadCertChain": "ok",
                 "certificateDigestRecheck": "skipped", "loopbackEphemeralBind": "skipped"}}
        result, _remote = self._diagnose(reply)
        self.assertEqual(diagnostic._UNKNOWN, result)

    def test_does_not_execute_except_for_exit_one_after_probe_events_without_ready_file(self):
        descriptor = ("windows-cp117", "/qga", 41, 42, "S-1-5-21-1-2-3-1002")
        wrong_failure = {"state": "observed", "serverCorrelationId": diagnostic._CORRELATION,
                         "task": "ready", "lastResult": 1, "ready": "present",
                         "stateContent": "ready-present", "stageAcl": "expected",
                         "stateAcl": "expected", "replayAllowed": False}
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(diagnostic.server, "_read_intent", return_value=self._intent()), \
             mock.patch.object(diagnostic.base, "_descriptor", return_value=(object(), object(), descriptor)), \
             mock.patch.object(diagnostic.stage, "status", return_value={"state": "staged-not-server-ready"}), \
             mock.patch.object(diagnostic.server, "diagnose_status", return_value=wrong_failure), \
             mock.patch.object(diagnostic.base, "_remote", side_effect=AssertionError("must not execute")):
            self.assertEqual(diagnostic._UNKNOWN, diagnostic.diagnose(directory, dict(diagnostic._EXPECTED_INPUT)))

    def test_guest_program_performs_only_the_post_resource_reads_and_ephemeral_bind(self):
        code = diagnostic._POST_RESOURCE_CODE
        self.assertIn("module.server_process_identity()", code)
        self.assertIn("tls.load_cert_chain(certificate,private_key)", code)
        self.assertLess(code.index("tls.load_cert_chain"), code.index("probe_certificate_sha256(certificate)!=digest"))
        self.assertIn("listener.bind(('127.0.0.1',0))", code)
        self.assertIn("listener.close()", code)
        for forbidden in ("serve(", "write_private_ready_json", "probe_events_path", "mkdir(",
                          "Register-ScheduledTask", "Start-ScheduledTask", "Remove-Item"):
            self.assertNotIn(forbidden, code)

    def test_remote_program_hashes_frozen_python_before_guest_execution_and_suppresses_exception_text(self):
        remote = diagnostic._REMOTE_POST_RESOURCE
        compile(remote, "post-resource-remote", "exec")
        self.assertIn("Get-FileHash -LiteralPath $p -Algorithm SHA256", remote)
        self.assertLess(remote.index("Get-FileHash -LiteralPath $p -Algorithm SHA256"),
                        remote.index("child=call(sock,'guest-exec'"))
        self.assertNotIn("str(error)", remote)
        self.assertNotIn("traceback", remote)

    def test_changed_interpreter_is_classified_before_guest_execution(self):
        with tempfile.NamedTemporaryFile() as frozen:
            frozen.write(b"signed-python-bytes"); frozen.flush()
            calls = []
            source = diagnostic._REMOTE_POST_RESOURCE.replace(
                "phase='binding'\ntry:",
                "phase='binding'\ndef call(sock,command,args):\n calls.append((command,args));return {'pid':7} if command=='guest-exec' else {'exited':True,'exitcode':0,'out-truncated':False,'err-truncated':False,'out-data':base64.b64encode(b'not-the-frozen-hash').decode()}\ntry:").replace(
                    "if not live(sock,pid,ticks):raise ValueError()", "if False:raise ValueError()")
            output = io.StringIO()
            with mock.patch.object(sys, "argv", ["diagnostic", "/qga", "41", "42", frozen.name,
                                                   "0" * 64, r"C:\\stage", r"C:\\cert", r"C:\\key",
                                                   base64.b64encode(diagnostic._POST_RESOURCE_CODE.encode()).decode()]), \
                 contextlib.redirect_stdout(output):
                exec(compile(source, "post-resource-remote", "exec"), {"calls": calls})
        self.assertEqual(["guest-exec", "guest-exec-status"], [call[0] for call in calls])
        self.assertEqual({"state": "diagnosed", "phase": "python-digest"}, json.loads(output.getvalue()))

    def test_only_the_fixed_correlation_and_read_only_actions_are_admitted(self):
        with self.assertRaises(diagnostic.WindowsFixturePostResourceDiagnosticError):
            diagnostic.workflow(Path.cwd(), "start", dict(diagnostic._EXPECTED_INPUT))
        with self.assertRaises(diagnostic.WindowsFixturePostResourceDiagnosticError):
            diagnostic.diagnose(Path.cwd(), {"serverCorrelationId": "00000000-0000-4000-8000-000000000000"})

    def test_probe_events_acl_diagnostic_is_read_only_and_bounds_result(self):
        descriptor = ("windows-cp117", "/qga", 41, 42, "S-1-5-21-1-2-3-1002")
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(diagnostic.server, "_read_intent", return_value=self._intent()), \
             mock.patch.object(diagnostic.base, "_descriptor", return_value=(object(), object(), descriptor)), \
             mock.patch.object(diagnostic.stage, "status", return_value={"state": "staged-not-server-ready"}), \
             mock.patch.object(diagnostic.server, "diagnose_status", return_value={
                 "state": "observed", "serverCorrelationId": diagnostic._CORRELATION,
                 "task": "ready", "lastResult": 1, "ready": "absent",
                 "stateContent": "probe-events", "stageAcl": "expected", "stateAcl": "expected",
                 "replayAllowed": False}), \
             mock.patch.object(diagnostic.base, "_remote", return_value=json.dumps({
                 "state": "observed", "result": {"version": 1, "probeEventsAcl": "mismatch",
                 "aclShape": {"protected": "no", "aceCount": "three", "principals": "exact",
                              "rights": "exact", "inheritance": "exact", "originalSid": "yes",
                              "systemSid": "yes", "adminSid": "yes",
                              "unexpectedPrincipal": "none"},
                 "identity": {"originalSid": "yes", "stageRecipientSid": "yes",
                              "stateRootThirdSid": "yes", "taskPrincipalSid": "yes",
                              "thirdSidNamespace": "same-domain-user", "thirdSidAuthority": "S-1-5"}}}).encode()) as remote:
            result = diagnostic.diagnose_events_acl(directory, dict(diagnostic._EXPECTED_INPUT))
        self.assertEqual("mismatch", result["probeEventsAcl"])
        self.assertEqual({"originalSid": "yes", "stageRecipientSid": "yes",
                          "stateRootThirdSid": "yes", "taskPrincipalSid": "yes",
                          "thirdSidNamespace": "same-domain-user", "thirdSidAuthority": "S-1-5"}, result["identity"])
        self.assertFalse(result["nativeActionAllowed"])
        script = base64.b64decode(remote.call_args.args[2][-1]).decode()
        self.assertIn("establish=False", script)
        self.assertNotIn("Set-Acl", script)

    def test_identity_failure_shape_fails_closed_without_exposing_sid_or_dispatching_mutation(self):
        malformed = {"state": "observed", "result": {"version": 1, "probeEventsAcl": "mismatch",
                     "aclShape": {"protected": "no", "aceCount": "three", "principals": "exact",
                                  "rights": "exact", "inheritance": "exact", "originalSid": "yes",
                                  "systemSid": "yes", "adminSid": "yes", "unexpectedPrincipal": "none"},
                     "identity": {"originalSid": "yes", "stageRecipientSid": "yes",
                                  "stateRootThirdSid": "yes", "taskPrincipalSid": "S-1-5-21-secret",
                                  "thirdSidNamespace": "same-domain-user", "thirdSidAuthority": "S-1-5"}}}
        descriptor = ("windows-cp117", "/qga", 41, 42, "S-1-5-21-1-2-3-1002")
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(diagnostic.server, "_read_intent", return_value=self._intent()), \
             mock.patch.object(diagnostic.base, "_descriptor", return_value=(object(), object(), descriptor)), \
             mock.patch.object(diagnostic.stage, "status", return_value={"state": "staged-not-server-ready"}), \
             mock.patch.object(diagnostic.server, "diagnose_status", return_value={
                 "state": "observed", "serverCorrelationId": diagnostic._CORRELATION,
                 "task": "ready", "lastResult": 1, "ready": "absent", "stateContent": "probe-events",
                 "stageAcl": "expected", "stateAcl": "expected", "replayAllowed": False}), \
             mock.patch.object(diagnostic.base, "_remote", return_value=json.dumps(malformed).encode()) as remote:
            result = diagnostic.diagnose_events_acl(directory, dict(diagnostic._EXPECTED_INPUT))
        self.assertEqual(diagnostic._UNKNOWN, result)
        self.assertEqual(1, remote.call_count)
        self.assertNotIn("secret", str(result))

    def test_acl_identity_program_uses_only_read_only_receipts_and_sanitized_task_translation(self):
        code = diagnostic._PROBE_EVENTS_ACL_CODE
        self.assertEqual(3, code.count("establish=False"))
        self.assertIn("VPNMSIX64\\\\vpncp117", code)
        self.assertIn("Translate([Security.Principal.SecurityIdentifier])", code)
        for forbidden in ("Set-Acl", "Register-ScheduledTask", "Start-ScheduledTask", "Remove-Item", "mkdir("):
            self.assertNotIn(forbidden, code)

    def test_identity_projection_selects_the_sole_non_system_admin_sid_regardless_of_ace_order(self):
        source = diagnostic._PROBE_EVENTS_ACL_CODE.replace("@SID@", json.dumps("S-1-5-21-1-2-3-1002"))
        self.assertNotIn("rules[2]", source)
        namespace = {"__builtins__": __builtins__}
        exec(compile(source.split("try:\n events=", 1)[0], "acl-identity-helpers", "exec"), namespace)
        receipt = {"acl": [
            {"sid": "S-1-5-21-1-2-3-1002"},
            {"sid": "S-1-5-18"},
            {"sid": "S-1-5-32-544"},
        ]}
        self.assertEqual("S-1-5-21-1-2-3-1002", namespace["recipient"](receipt))

    def test_identity_namespace_and_authority_classes_are_bounded_for_well_known_sids(self):
        source = diagnostic._PROBE_EVENTS_ACL_CODE.replace("@SID@", json.dumps("S-1-5-21-1-2-3-1002"))
        namespace = {"__builtins__": __builtins__}
        exec(compile(source.split("try:\n events=", 1)[0], "acl-identity-helpers", "exec"), namespace)
        expected = {
            "S-1-1-0": ("everyone", "S-1-1"),
            "S-1-3-0": ("creator-owner", "S-1-3"),
            "S-1-3-1": ("creator-group", "S-1-3"),
            "S-1-3-4": ("owner-rights", "S-1-3"),
            "S-1-5-12": ("restricted", "S-1-5"),
            "S-1-15-2-1": ("all-application-packages", "S-1-15"),
        }
        for sid, (kind, authority) in expected.items():
            with self.subTest(sid=sid):
                self.assertEqual(kind, namespace["namespace"](sid, "S-1-5-21-1-2-3-1002"))
                self.assertEqual(authority, namespace["authority"](sid))
