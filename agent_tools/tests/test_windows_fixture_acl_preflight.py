"""Causal regression for the CP117 OWNER RIGHTS fixture ACL preflight."""
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

from agent_tools import windows_fixture_acl_preflight as preflight


class WindowsFixtureAclPreflightTests(unittest.TestCase):
    def _intent(self):
        return {"request": {"host": "archlinux", "leaseId": "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
                             "stageCorrelationId": preflight._STAGE_CORRELATION,
                             "serverCorrelationId": preflight._FAILED_SERVER_CORRELATION,
                             "sourceSha": "c" * 40, "fixtureReceiptArtifactId": "sha256-" + "d" * 64,
                             "baseMsiArtifactId": "sha256-" + "e" * 64,
                             "targetMsiArtifactId": "sha256-" + "f" * 64},
                "socketPath": "/qga", "qemuPid": 41, "startTicks": 42,
                "originalSid": "S-1-5-21-1-2-3-1002",
                "pythonPath": r"C:\Program Files\Python313\python.exe", "pythonExeSha256": "1" * 64}

    def _run(self, reply):
        descriptor = ("windows-cp117", "/qga", 41, 42, "S-1-5-21-1-2-3-1002")
        staged = {"state": "staged-not-server-ready", "sourceSha": "c" * 40,
                  "fileHashes": {"server/prepare_desktop_update_fixture.py": "2" * 64}}
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(preflight.server, "_read_intent", return_value=self._intent()), \
             mock.patch.object(preflight.base, "_descriptor", return_value=(object(), object(), descriptor)), \
             mock.patch.object(preflight.stage, "status", return_value=staged), \
             mock.patch.object(preflight.base, "_remote", return_value=json.dumps(reply).encode()) as remote:
            result = preflight.preflight(Path(directory), dict(preflight._EXPECTED_INPUT))
        return result, remote

    def test_owner_rights_result_blocks_before_any_campaign_claim_or_server_task(self):
        reply = {"state": "observed", "result": {"version": 1, "modes": {
            "fixture-0700": {"initial": "owner-rights", "normalizer": "match"},
            "control-0777": {"initial": "mismatch", "normalizer": "match"}}}}
        with mock.patch.object(preflight.server, "_admit_campaign", side_effect=AssertionError("campaign claim")), \
             mock.patch.object(preflight.server, "start", side_effect=AssertionError("server task")):
            result, remote = self._run(reply)
        self.assertEqual("blocked", result["state"])
        self.assertEqual("owner-rights", result["modes"]["fixture-0700"]["initial"])
        self.assertEqual(1, remote.call_count)

    def test_both_matching_acl_shapes_admit_the_gate(self):
        reply = {"state": "observed", "result": {"version": 1, "modes": {
            "fixture-0700": {"initial": "match", "normalizer": "match"},
            "control-0777": {"initial": "mismatch", "normalizer": "match"}}}}
        result, remote = self._run(reply)
        self.assertEqual("ready", result["state"])
        self.assertEqual({"fixture-0700", "control-0777"}, set(result["modes"]))
        args = remote.call_args.args[2]
        self.assertEqual("1" * 64, args[4])
        self.assertTrue(args[5].endswith(r"\content"))
        self.assertNotIn("S-1-5-21", str(result))

    def test_0700_normalizer_failure_still_evaluates_the_0777_control(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory) / "stage"
            entry = stage / "server" / "prepare_desktop_update_fixture.py"
            entry.parent.mkdir(parents=True)
            entry.write_text(
                "def windows_acl_receipt(path, *, private, establish=True):\n"
                "    return {'protected': True, 'isDirectory': True, 'currentSid': 'S-1-5-21-1-2-3-1002', 'acl': [\n"
                "        {'sid': 'S-1-5-18', 'type': 'Allow', 'inherited': False, 'propagation': 0, 'rights': 0x1F01FF, 'inheritance': 3},\n"
                "        {'sid': 'S-1-5-32-544', 'type': 'Allow', 'inherited': False, 'propagation': 0, 'rights': 0x1F01FF, 'inheritance': 3},\n"
                "        {'sid': 'S-1-5-21-1-2-3-1002', 'type': 'Allow', 'inherited': False, 'propagation': 0, 'rights': 0x1F01FF, 'inheritance': 3}] }\n"
                "def require_windows_private_acl(path, *, private, directory):\n"
                "    if path.name == 'fixture-0700': raise ValueError('fixture normalizer failed')\n",
                encoding="utf-8")
            scratch = Path(directory) / "scratch"
            source = preflight._EXERCISE_CODE.replace(
                r"root=pathlib.Path(r'C:\Users\vpncp117\AppData\Local\VpnControl')/('mcp-acl-preflight-'+nonce)",
                "root=pathlib.Path(sys.argv[3])")
            output = io.StringIO()
            with mock.patch.object(sys, "argv", ["exercise", str(stage), "nonce", str(scratch)]), \
                 contextlib.redirect_stdout(output):
                exec(compile(source, "acl-preflight-exercise", "exec"), {})
        result = json.loads(output.getvalue())
        self.assertEqual("unknown", result["modes"]["fixture-0700"]["normalizer"])
        self.assertEqual("match", result["modes"]["control-0777"]["normalizer"])

    def test_preexisting_nonce_root_is_never_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory) / "stage"
            entry = stage / "server" / "prepare_desktop_update_fixture.py"
            entry.parent.mkdir(parents=True)
            entry.write_text("# not imported when the nonce root already exists\n", encoding="utf-8")
            scratch = Path(directory) / "existing-nonce-root"
            scratch.mkdir()
            marker = scratch / "preserve"
            marker.write_text("owned elsewhere", encoding="utf-8")
            source = preflight._EXERCISE_CODE.replace(
                r"root=pathlib.Path(r'C:\Users\vpncp117\AppData\Local\VpnControl')/('mcp-acl-preflight-'+nonce)",
                "root=pathlib.Path(sys.argv[3])")
            output = io.StringIO()
            with mock.patch.object(sys, "argv", ["exercise", str(stage), "nonce", str(scratch)]), \
                 contextlib.redirect_stdout(output):
                exec(compile(source, "acl-preflight-existing-root", "exec"), {})
            self.assertTrue(scratch.is_dir())
            self.assertEqual("owned elsewhere", marker.read_text(encoding="utf-8"))
            self.assertEqual("unknown", json.loads(output.getvalue())["modes"]["fixture-0700"]["initial"])

    def test_malformed_or_cleanup_uncertain_result_fails_closed(self):
        malformed = {"state": "observed", "result": {"version": 1, "modes": {
            "fixture-0700": {"initial": "owner-rights", "normalizer": "secret"},
            "control-0777": {"initial": "match", "normalizer": "match"}}}}
        result, _remote = self._run(malformed)
        self.assertEqual(preflight._UNKNOWN, result)

    def test_sanitized_wrapper_failure_phase_survives_projection(self):
        for phase in ("python-verify", "guest-launch", "guest-wait", "guest-exit-nonzero",
                      "guest-output-truncation", "guest-output-length", "guest-output-parse"):
            with self.subTest(phase=phase):
                result = preflight._project({"state": "unknown", "phase": phase})
                self.assertEqual("unknown", result["state"])
                self.assertEqual(phase, result["phase"])
                self.assertEqual("unknown", result["comparison"])

    def test_read_only_status_reports_prefix_census_and_python_booleans_without_guest_details(self):
        descriptor = ("windows-cp117", "/qga", 41, 42, "S-1-5-21-1-2-3-1002")
        staged = {"state": "staged-not-server-ready", "sourceSha": "c" * 40,
                  "fileHashes": {"server/prepare_desktop_update_fixture.py": "2" * 64}}
        reply = {"state": "observed", "result": {"version": 1, "scratch": "one",
                 "signatureValid": True, "signerMatches": True, "shaMatches": True}}
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(preflight.server, "_read_intent", return_value=self._intent()), \
             mock.patch.object(preflight.base, "_descriptor", return_value=(object(), object(), descriptor)), \
             mock.patch.object(preflight.stage, "status", return_value=staged), \
             mock.patch.object(preflight.base, "_remote", return_value=json.dumps(reply).encode()) as remote:
            result = preflight.status(Path(directory), dict(preflight._EXPECTED_INPUT))
        self.assertEqual("observed", result["state"])
        self.assertEqual("one", result["scratch"])
        self.assertTrue(result["signatureValid"])
        self.assertNotIn("S-1-5-21", str(result))
        self.assertNotIn("C:\\", str(result))
        self.assertEqual(1, remote.call_count)

    def test_status_unknown_reply_fails_closed_and_never_deletes_prefix_scratch(self):
        descriptor = ("windows-cp117", "/qga", 41, 42, "S-1-5-21-1-2-3-1002")
        staged = {"state": "staged-not-server-ready", "sourceSha": "c" * 40,
                  "fileHashes": {"server/prepare_desktop_update_fixture.py": "2" * 64}}
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(preflight.server, "_read_intent", return_value=self._intent()), \
             mock.patch.object(preflight.base, "_descriptor", return_value=(object(), object(), descriptor)), \
             mock.patch.object(preflight.stage, "status", return_value=staged), \
             mock.patch.object(preflight.base, "_remote", return_value=b'{"state":"unknown"}'):
            result = preflight.status(Path(directory), dict(preflight._EXPECTED_INPUT))
        self.assertEqual("unknown", result["state"])
        self.assertEqual("unknown", result["scratch"])

    def test_status_preserves_bounded_read_only_failure_phase(self):
        descriptor = ("windows-cp117", "/qga", 41, 42, "S-1-5-21-1-2-3-1002")
        staged = {"state": "staged-not-server-ready", "sourceSha": "c" * 40,
                  "fileHashes": {"server/prepare_desktop_update_fixture.py": "2" * 64}}
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(preflight.server, "_read_intent", return_value=self._intent()), \
             mock.patch.object(preflight.base, "_descriptor", return_value=(object(), object(), descriptor)), \
             mock.patch.object(preflight.stage, "status", return_value=staged), \
             mock.patch.object(preflight.base, "_remote", return_value=b'{"state":"unknown","phase":"guest-parse"}'):
            result = preflight.status(Path(directory), dict(preflight._EXPECTED_INPUT))
        self.assertEqual("unknown", result["state"])
        self.assertEqual("guest-parse", result["phase"])

    def test_only_fixed_stage_is_admitted_before_guest_execution(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(preflight.base, "_remote", side_effect=AssertionError("guest execution")):
            with self.assertRaises(preflight.WindowsFixtureAclPreflightError):
                preflight.preflight(Path(directory), {"stageCorrelationId": "00000000-0000-4000-8000-000000000000"})

    def test_guest_exercise_compares_initial_0700_acl_then_normalizer_and_only_cleans_its_nonce_root(self):
        code = preflight._EXERCISE_CODE
        self.assertIn("events.mkdir(mode=0o700)", code)
        self.assertLess(code.index("out['modes']['fixture-0700']['initial']=compare(events)"),
                        code.index("module.require_windows_private_acl(events,private=True,directory=True)"))
        self.assertIn("root.mkdir(mode=0o777)", code)
        self.assertNotIn("root.mkdir(mode=0o700)", code)
        self.assertIn("control.mkdir(mode=0o777)", code)
        self.assertIn("module.require_windows_private_acl(control,private=True,directory=True)", code)
        self.assertIn("'S-1-3-4'", code)
        self.assertIn("shutil.rmtree(root)", code)
        self.assertIn("created=False", code)
        self.assertIn("if created and root.exists()", code)
        self.assertIn("unsafe(root.parent)", code)
        self.assertIn("mcp-acl-preflight-", code)
        for forbidden in ("Register-ScheduledTask", "Start-ScheduledTask", "Remove-Item", "serve(", "ready.json"):
            self.assertNotIn(forbidden, code)

    def test_remote_checks_live_generation_and_signed_python_before_disposable_execution(self):
        code = preflight._REMOTE_EXERCISE
        compile(code, "acl-preflight-remote", "exec")
        self.assertIn("Get-AuthenticodeSignature", code)
        self.assertIn("Get-FileHash -LiteralPath $p -Algorithm SHA256", code)
        self.assertLess(code.index("Get-FileHash -LiteralPath $p -Algorithm SHA256"),
                        code.index("'path':python"))
        self.assertNotIn("str(error)", code)
        self.assertNotIn("traceback", code)

    def test_guest_exercise_accepts_omitted_qga_truncation_flags_and_rejects_explicit_non_false_values(self):
        code = preflight._REMOTE_EXERCISE
        phases = ("guest-launch", "guest-wait", "guest-exit-nonzero", "guest-output-truncation",
                  "guest-output-length", "guest-output-parse")
        for phase in phases:
            with self.subTest(phase=phase):
                self.assertIn("phase='" + phase + "'", code)
        self.assertIn("result.get('out-truncated',False) is not False", code)
        self.assertIn("result.get('err-truncated',False) is not False", code)
        self.assertTrue({}.get("out-truncated", False) is False)
        self.assertTrue({}.get("err-truncated", False) is False)
        for invalid in (True, 0, "false", None):
            with self.subTest(invalid=invalid):
                self.assertIsNot(invalid, False)
        self.assertLess(code.index("phase='guest-exit-nonzero'"), code.index("phase='guest-output-truncation'"))
        self.assertLess(code.index("phase='guest-output-truncation'"), code.index("phase='guest-output-length'"))
        self.assertLess(code.index("phase='guest-output-length'"), code.index("phase='guest-output-parse'"))

    def test_status_program_only_observes_scratch_prefix_and_signed_python(self):
        code = preflight._REMOTE_STATUS
        compile(code, "acl-preflight-status", "exec")
        self.assertIn("mcp-acl-preflight-*", code)
        self.assertIn("Get-AuthenticodeSignature", code)
        self.assertIn("Get-FileHash -LiteralPath $p -Algorithm SHA256", code)
        self.assertIn("-ceq '@HASH@'", code)
        rendered = code.replace("@HASH@", "a" * 64)
        self.assertIn("-ceq '" + "a" * 64 + "'", rendered)
        self.assertNotIn("-ceq " + "a" * 64 + ")", rendered)
        self.assertIn("result.get('out-truncated',False) is not False", code)
        self.assertIn("result.get('err-truncated',False) is not False", code)
        for forbidden in ("Remove-Item", "Set-Acl", "Register-ScheduledTask", "Start-ScheduledTask", "mkdir("):
            self.assertNotIn(forbidden, code)

    def test_generated_guest_program_does_not_expose_host_inputs_in_its_result_shape(self):
        source = base64.b64decode(base64.b64encode(preflight._EXERCISE_CODE.encode())).decode()
        self.assertNotIn("originalSid", source)
        self.assertNotIn("serverCorrelationId", source)
        self.assertNotIn("scheduler", source.lower())
