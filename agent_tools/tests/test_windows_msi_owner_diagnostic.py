"""Causal regressions for bounded CP117 owner-census failure diagnosis."""

import base64
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest import TestCase, mock

from agent_tools import windows_msi_owner_census as census
from agent_tools import windows_msi_owner_diagnostic as diagnostic


class OwnerDiagnosticTests(TestCase):
    def test_census_unknown_now_has_a_bounded_state_directory_cause(self):
        """Regression: an ACL proof failure used to collapse into generic unknown."""
        self.assertEqual(census._project(b'{"state":"unknown"}', "a" * 40, "c" * 64)["state"], "unknown")
        result = diagnostic._project(
            b'{"version":1,"state":"diagnosed","phase":"state-directory","detail":"foreign-allow-ace-other"}', "a" * 40)
        self.assertEqual(result["state"], "diagnosed")
        self.assertEqual(result["phase"], "state-directory")
        self.assertFalse(result["nativeActionAllowed"])
        self.assertNotIn("raw", result)

    def test_static_source_and_qga_binding_are_required_before_guest_read(self):
        descriptor = ("windows-cp117", "/private/qga.sock", 100, 200, "S-1-5-21-1-2-3-1002")
        intent = {"environment": descriptor[0], "socketPath": descriptor[1], "pid": 100,
                  "startTicks": 200, "expectedSid": descriptor[4],
                  "request": {"correlationId": diagnostic._CORRELATION, "sourceSha": "a" * 40},
                  "pair": {"sourceSha": "a" * 40, "baseVersion": "2.1.19",
                           "baseCliSha256": "c" * 64}}
        with (mock.patch.object(diagnostic.base, "_private_intent", return_value=intent),
              mock.patch.object(diagnostic.base, "_descriptor", return_value=(object(), SimpleNamespace(), descriptor)),
              mock.patch.object(diagnostic.base, "_stage_artifact_readonly", return_value=(intent["pair"], 1)),
              mock.patch.object(diagnostic.base, "_remote", return_value=b'{"version":1,"state":"diagnosed","phase":"process","detail":"not-applicable"}') as remote):
            result = diagnostic.diagnose(Path.cwd(), {"host": "archlinux"})
            self.assertEqual(result["phase"], "process")
            self.assertEqual(result["sourceSha"], "a" * 40)
            intent["startTicks"] = 201
            self.assertEqual(diagnostic.diagnose(Path.cwd(), {"host": "archlinux"}), diagnostic._UNKNOWN)
            self.assertEqual(remote.call_count, 1)

    def test_guest_program_is_read_only_and_qga_rejects_unbounded_output(self):
        self.assertIn("$phase='state-directory'", diagnostic._DIAGNOSTIC_PS)
        self.assertIn("$detail='foreign-allow-ace-other'", diagnostic._DIAGNOSTIC_PS)
        self.assertIn("$phase='public-status'", diagnostic._DIAGNOSTIC_PS)
        self.assertNotIn("Stop-Process", diagnostic._DIAGNOSTIC_PS)
        self.assertNotIn(" quit ", diagnostic._DIAGNOSTIC_PS)
        compile(diagnostic._REMOTE, "owner-diagnostic-remote", "exec")
        stub = '''import base64,json,sys
def live(*args):return True
def decode(value):return value.decode()
def call(sock,command,args):
 if command=='guest-exec':
  script=base64.b64decode(args['arg'][-1]).decode('utf-16le')
  if "Stop-Process" in script or "$phase='state-directory'" not in script:raise ValueError('unexpected script')
  return {'pid':42}
 if command=='guest-exec-status':return {'exited':True,'exitcode':0,'out-truncated':True,'out-data':''}
 raise ValueError('unexpected QGA action')
'''
        program = stub + diagnostic._REMOTE[len(diagnostic.base._QGA):]
        run = subprocess.run([sys.executable, "-c", program, "/private/qga.sock", "100", "200",
                              "S-1-5-21-1-2-3-1002", "c" * 64], capture_output=True, timeout=10, check=False)
        self.assertEqual(run.returncode, 0, run.stderr.decode(errors="replace"))
        self.assertEqual(json.loads(run.stdout), {"version": 1, "state": "unknown"})

    def test_state_directory_acl_causes_are_bounded_and_mirror_census(self):
        """RED→GREEN: generic state-directory now retains only the failed ACL fact."""
        script = diagnostic._DIAGNOSTIC_PS
        for detail in diagnostic._STATE_DIRECTORY_DETAILS:
            with self.subTest(detail=detail):
                result = diagnostic._project(json.dumps({
                    "version": 1, "state": "diagnosed", "phase": "state-directory", "detail": detail,
                }).encode(), "a" * 40)
                self.assertEqual(result["detail"], detail)
                self.assertNotIn("sid", result)
                self.assertNotIn("path", result)
        self.assertIn("$stateOwner -cne $sid", script)
        self.assertIn("$rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))", script)
        self.assertIn("missing-owner-list-directory", script)
        self.assertIn("missing-owner-create-files", script)
        self.assertIn("foreign-allow-ace-other", script)
        self.assertNotIn("Get-Acl -LiteralPath $state|ConvertTo-Json", script)

    def test_trusted_directory_aces_proceed_and_other_identity_blocks(self):
        """RED→GREEN: SYSTEM/Admin ACEs are normal; another identity is still a boundary."""
        result = diagnostic._project(json.dumps({
            "version": 1, "state": "diagnosed", "phase": "process", "detail": "not-applicable",
        }).encode(), "a" * 40)
        self.assertEqual(result["phase"], "process")
        blocked = diagnostic._project(json.dumps({
            "version": 1, "state": "diagnosed", "phase": "state-directory", "detail": "foreign-allow-ace-other",
        }).encode(), "a" * 40)
        self.assertEqual(blocked["detail"], "foreign-allow-ace-other")
        script = diagnostic._DIAGNOSTIC_PS
        self.assertIn("'S-1-5-18','S-1-5-32-544'", script)
        self.assertIn("$rule.IdentityReference.Value -notin $directoryAllowedSids", script)
        self.assertIn("$rule.IdentityReference.Value -ceq $sid", script)
        self.assertIn("throw 'STATE_ACL'", script)
        self.assertNotIn("foreign-allow-ace-trusted", script.split("$phase='state-files'", 1)[0])

    def test_state_file_causes_are_bounded_per_fixed_file(self):
        """RED→GREEN: each lock/endpoint proof failure keeps only a safe file class."""
        script = diagnostic._DIAGNOSTIC_PS
        self.assertIn("$fileAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])", script)
        self.assertIn("$fileAllowedSids=@($sid,'S-1-5-18','S-1-5-32-544')", script)
        self.assertIn("$rule.IdentityReference.Value -notin $fileAllowedSids", script)
        self.assertIn("$rule.IdentityReference.Value -ceq $sid", script)
        self.assertIn("[Security.AccessControl.FileSystemRights]::ReadData", script)
        self.assertIn("$detail=$fileKind+'-foreign-allow-ace-other'", script)
        self.assertIn("$detail=$fileKind+'-missing-owner-read'", script)
        for detail in diagnostic._STATE_FILE_DETAILS:
            with self.subTest(detail=detail):
                result = diagnostic._project(json.dumps({
                    "version": 1, "state": "diagnosed", "phase": "state-files", "detail": detail,
                }).encode(), "a" * 40)
                self.assertEqual(result["phase"], "state-files")
                self.assertEqual(result["detail"], detail)
                self.assertFalse(result["replayAllowed"])
                self.assertNotIn("path", result)
                self.assertNotIn("Sid", result)

    def test_endpoint_unavailable_keeps_a_safe_process_chain_proof(self):
        """RED→GREEN: a missing endpoint no longer hides the lock-derived owner generation."""
        for detail in diagnostic._ENDPOINT_UNAVAILABLE_DETAILS:
            with self.subTest(detail=detail):
                result = diagnostic._project(json.dumps({
                    "version": 1, "state": "diagnosed", "phase": "endpoint-unavailable", "detail": detail,
                }).encode(), "a" * 40)
                self.assertEqual(result["phase"], "endpoint-unavailable")
                self.assertEqual(result["detail"], detail)
                self.assertNotIn("Pid", result)
                self.assertNotIn("path", result)
        script = diagnostic._DIAGNOSTIC_PS
        self.assertIn("function ProcessChainState", script)
        self.assertIn("return 'exact'", script)
        self.assertIn("return 'absent'", script)
        self.assertIn("return 'invalid'", script)
        self.assertIn("[System.Management.Automation.ErrorCategory]::ObjectNotFound", script)
        self.assertIn("$phase='endpoint-unavailable'", script)

    def test_trusted_file_aces_proceed_and_other_identity_blocks(self):
        """RED→GREEN: reviewed SYSTEM/Admin ACEs pass; an unknown identity remains a boundary."""
        result = diagnostic._project(json.dumps({
            "version": 1, "state": "diagnosed", "phase": "process", "detail": "not-applicable",
        }).encode(), "a" * 40)
        self.assertEqual(result["phase"], "process")
        for detail in ("lock-foreign-allow-ace-other", "endpoint-foreign-allow-ace-other"):
            with self.subTest(detail=detail):
                blocked = diagnostic._project(json.dumps({
                    "version": 1, "state": "diagnosed", "phase": "state-files", "detail": detail,
                }).encode(), "a" * 40)
                self.assertEqual(blocked["detail"], detail)
        script = diagnostic._DIAGNOSTIC_PS
        self.assertIn("'S-1-5-18','S-1-5-32-544'", script)
        self.assertIn("$rule.IdentityReference.Value -notin $fileAllowedSids", script)
        self.assertIn("$rule.IdentityReference.Value -ceq $sid", script)
        self.assertIn("throw 'STATE_ACL'", script)
        self.assertNotIn("foreign-allow-ace-trusted", script)

    def test_parent_child_identity_and_generation_mismatches_remain_process_causes(self):
        """RED→GREEN: the census rejects self-parenting and indistinct generations."""
        script = diagnostic._DIAGNOSTIC_PS
        self.assertIn("$parent.ProcessId -eq $child.ProcessId", script)
        self.assertIn("$parent.CreationDate.ToUniversalTime().ToString('o') -ceq $child.CreationDate.ToUniversalTime().ToString('o')", script)
        for mismatch in ("self-parent", "same-creation-time"):
            with self.subTest(mismatch=mismatch):
                result = diagnostic._project(
                    b'{"version":1,"state":"diagnosed","phase":"process","detail":"not-applicable"}', "a" * 40)
                self.assertEqual(result["phase"], "process")
                self.assertFalse(result["nativeActionAllowed"])

    def test_projection_and_input_reject_poisoned_values(self):
        for raw in (b'{"version":1,"state":"diagnosed","phase":"raw-command","detail":"not-applicable"}',
                    b'{"version":1,"state":"observed","phase":"complete","detail":"not-applicable"}',
                    b'{"version":1,"state":"diagnosed","phase":"complete","detail":"token"}',
                    b'{"version":1,"state":"diagnosed","phase":"state-directory","detail":"S-1-5-18"}'):
            self.assertEqual(diagnostic._project(raw, "a" * 40), diagnostic._UNKNOWN)
        with self.assertRaises(diagnostic.WindowsMsiOwnerDiagnosticError):
            diagnostic.diagnose(Path.cwd(), {"host": "archlinux", "ownerPid": 1})
